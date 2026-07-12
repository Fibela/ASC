"""
SPECTER Agent REST API â€” P13 + P14 (Security Hardening).

Endpoint map:
  POST   /agents/register           â€” Agent self-registration (enrollment token required)
  GET    /agents/                   â€” List agents          (analyst+)
  GET    /agents/probe              â€” [HONEYPOT] Triggers security alert
  GET    /agents/dump               â€” [HONEYPOT] Triggers security alert
  GET    /agents/export             â€” [HONEYPOT] Triggers security alert
  GET    /agents/{id}               â€” Agent detail         (analyst+)
  DELETE /agents/{id}               â€” Deregister agent     (admin only)
  POST   /agents/{id}/events        â€” Ingest telemetry     (rate-limited, agent auth)
  GET    /agents/{id}/commands      â€” Poll for commands    (agent auth)
  POST   /agents/{id}/results       â€” Report cmd result    (canary ping verified)
  POST   /agents/{id}/command       â€” Issue command        (param schema + injection check)
  PATCH  /agents/{id}/threat        â€” Set threat level     (analyst+)
  GET    /agents/{id}/timeline      â€” Event timeline       (analyst+)

P14 Security layers active on this router:
  - Enrollment token verification on registration (HMAC-SHA256, 1-hour window)
  - Honeypot endpoints for reconnaissance detection
  - Sliding-window rate limiter on telemetry ingestion
  - Param schema allowlist + injection check on command issue
  - Canary ping verification on command results
  - Strict signature mode audit logging
  - X-Specter-Guard response header on agent-facing endpoints
"""

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.api.deps import get_analyst_or_admin, get_current_admin, get_current_user
from asc_api.core.audit import log_security_action
from asc_api.core.config import get_settings
from asc_api.core.signing import verify_agent_event
from asc_api.core.specter_security import (
    SprecterRateLimiter,
    check_injection,
    check_suspicious_registration,
    generate_enrollment_token,
    log_honeypot_trigger,
    validate_command_params,
    verify_enrollment_token,
)
from asc_api.core.honeypot import (
    build_probe_decoy,
    build_dump_decoy,
    build_export_decoy,
    canary_store,
    fingerprint_request,
    generate_evidence_report,
    lookup_ip_reputation,
)
from asc_api.db.session import get_db
from asc_api.models.agent import Agent, AgentCommand, AgentEvent
from asc_api.models.honeypot import HoneypotEvidenceReport
from asc_api.models.user import User
from asc_api.services.agent_commander import (
    compute_poll_interval,
    escalate_threat_level,
    deescalate_threat_level,
    get_pending_commands,
    ingest_events,
    issue_command,
    mark_command_delivered,
    record_command_result,
    refresh_agent_status,
)

router = APIRouter(prefix="/agents", tags=["SPECTER Agents"])
settings = get_settings()

# Module-level rate limiter â€” shared across all requests in this process.
# Each agent's key is its UUID, so fresh agents start with an empty bucket.
_event_rate_limiter = SprecterRateLimiter(
    max_requests=settings.SPECTER_MAX_EVENTS_PER_WINDOW,
    window_seconds=settings.SPECTER_RATE_WINDOW_SECONDS,
)

_GUARD_HEADER = "SPECTER-Guard-PremosCorp-v1"

# Valid command types (P35 executors added in P36)
_VALID_COMMAND_TYPES = {
    # P13 originals
    "kill_process", "block_ip", "quarantine_file",
    "isolate", "unisolate", "collect_snapshot", "canary_ping",
    # P35 new executors
    "isolate_endpoint", "log_query", "unblock_ip", "unblock_domain",
}


# â”€â”€ Pydantic schemas â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class AgentRegisterRequest(BaseModel):
    hostname: str
    os_type: str           # windows | linux | macos
    os_version: str
    arch: str              # x86_64 | arm64
    ip_address: str
    public_key: str        # Ed25519 raw public key, base64
    specter_version: str = "1.0.0"
    labels: dict[str, str] = Field(default_factory=dict)
    tenant_id: str | None = None  # populated by the admin who generates the enrollment token


class AgentOut(BaseModel):
    id: str
    hostname: str
    os_type: str
    os_version: str
    arch: str
    ip_address: str
    specter_version: str
    status: str
    threat_level: str
    poll_interval: int
    first_seen: str
    last_seen: str
    labels: dict
    total_events: int

    @classmethod
    def from_orm(cls, a: Agent) -> "AgentOut":
        return cls(
            id=a.id,
            hostname=a.hostname,
            os_type=a.os_type,
            os_version=a.os_version,
            arch=a.arch,
            ip_address=a.ip_address,
            specter_version=a.specter_version,
            status=a.status,
            threat_level=a.threat_level,
            poll_interval=a.poll_interval,
            first_seen=a.first_seen.isoformat(),
            last_seen=a.last_seen.isoformat(),
            labels=a.labels or {},
            total_events=a.total_events or 0,
        )


class EventBatchRequest(BaseModel):
    events: list[dict[str, Any]] = Field(max_length=200)


class CommandResultRequest(BaseModel):
    command_id: str
    success: bool
    result: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


class IssueCommandRequest(BaseModel):
    command_type: str
    params: dict[str, Any] = Field(default_factory=dict)


class SetThreatRequest(BaseModel):
    threat_level: str   # normal | elevated | critical


# â”€â”€ Agent identity header dependency â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

async def _get_agent_by_header(
    x_specter_id: str = Header(..., alias="X-Specter-ID"),
    db: AsyncSession = Depends(get_db),
) -> Agent:
    result = await db.execute(select(Agent).where(Agent.id == x_specter_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Agent not found. Re-register the SPECTER agent.")
    return agent


# â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

async def _get_agent_or_404(agent_id: str, db: AsyncSession, tenant_id: str | None = None) -> Agent:
    query = select(Agent).where(Agent.id == agent_id)
    if tenant_id is not None:
        query = query.where(Agent.tenant_id == tenant_id)
    result = await db.execute(query)
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent


def _cmd_out(cmd: AgentCommand, include_result: bool = False) -> dict:
    out = {
        "id":           cmd.id,
        "agent_id":     cmd.agent_id,
        "command_type": cmd.command_type,
        "params":       cmd.params,
        "signature":    cmd.signature,
        "status":       cmd.status,
        "issued_by":    cmd.issued_by,
        "issued_at":    cmd.issued_at.isoformat(),
        "delivered_at": cmd.delivered_at.isoformat() if cmd.delivered_at else None,
        "completed_at": cmd.completed_at.isoformat() if cmd.completed_at else None,
    }
    if include_result:
        out["result"] = cmd.result
        out["error"]  = cmd.error
    return out


def _guard(response: Response) -> None:
    """Inject the SPECTER-Guard authenticity header into a response."""
    response.headers["X-Specter-Guard"] = _GUARD_HEADER


# â”€â”€ Endpoints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@router.post("/register", summary="SPECTER agent self-registration")
async def register_agent(
    payload: AgentRegisterRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    x_specter_token: str = Header(default="", alias="X-Specter-Token"),
) -> dict:
    """
    Called by a fresh SPECTER agent on first run (or after self-healing re-register).

    P14: Requires a valid enrollment token in X-Specter-Token when
    SPECTER_ENROLLMENT_SECRET is configured. Empty secret = dev mode (skip).
    """
    _guard(response)

    # Barrier: enrollment token
    if not verify_enrollment_token(settings.SPECTER_ENROLLMENT_SECRET, x_specter_token):
        log_security_action(
            "specter_enrollment_token_invalid",
            user_id="agent",
            role="agent",
            resource="agent_registration",
            resource_id=payload.hostname,
            detail=f"invalid or missing enrollment token hostname={payload.hostname}",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing SPECTER enrollment token.",
        )

    # Trap: suspicious registration frequency (non-blocking â€” log only)
    client_ip = request.client.host if request.client else payload.ip_address
    check_suspicious_registration(payload.hostname, client_ip)

    # Idempotent: same hostname â†’ update existing agent record
    existing = await db.execute(
        select(Agent).where(Agent.hostname == payload.hostname)
    )
    agent = existing.scalar_one_or_none()

    if agent:
        agent.ip_address = payload.ip_address
        agent.public_key = payload.public_key
        agent.os_version = payload.os_version
        agent.specter_version = payload.specter_version
        agent.status = "active"
        agent.last_seen = datetime.now(timezone.utc)
        if payload.tenant_id and not agent.tenant_id:
            agent.tenant_id = payload.tenant_id
        await db.commit()
        await db.refresh(agent)
    else:
        agent = Agent(
            id=str(uuid.uuid4()),
            tenant_id=payload.tenant_id,
            hostname=payload.hostname,
            os_type=payload.os_type,
            os_version=payload.os_version,
            arch=payload.arch,
            ip_address=payload.ip_address,
            public_key=payload.public_key,
            specter_version=payload.specter_version,
            labels=payload.labels,
            poll_interval=compute_poll_interval("normal"),
        )
        db.add(agent)
        await db.commit()
        await db.refresh(agent)

    return {
        "agent_id":        agent.id,
        "poll_interval":   agent.poll_interval,
        "threat_level":    agent.threat_level,
        "backend_pub_key": settings.SPECTER_SIGNING_PUBLIC_KEY,
        "ts":              datetime.now(timezone.utc).isoformat(),
    }


@router.get("", summary="List all SPECTER agents")
async def list_agents(
    status_filter: str | None = None,
    threat_filter: str | None = None,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
) -> dict:
    q = (
        select(Agent)
        .where(Agent.tenant_id == current_user.tenant_id)
        .order_by(Agent.last_seen.desc())
        .limit(limit)
    )
    if status_filter:
        q = q.where(Agent.status == status_filter)
    if threat_filter:
        q = q.where(Agent.threat_level == threat_filter)
    result = await db.execute(q)
    agents = result.scalars().all()
    return {
        "agents": [AgentOut.from_orm(a).model_dump() for a in agents],
        "total":  len(agents),
    }


@router.get("/enrollment-token", summary="Get current SPECTER enrollment token (admin)")
async def get_enrollment_token(
    _: User = Depends(get_current_admin),
) -> dict:
    """
    Returns the current SPECTER enrollment token for the authenticated admin.

    The token is HMAC-SHA256(SPECTER_ENROLLMENT_SECRET, window) with a 1-hour rolling
    window.  It is safe to distribute to endpoint operators but expires within ~2 hours.
    Never returns the raw secret â€” only the derived token.

    Security: admin-only.  Analysts cannot retrieve the enrollment token (least privilege).
    """
    import math, time as _time

    if not settings.SPECTER_ENROLLMENT_SECRET:
        return {
            "configured": False,
            "token": None,  # nosec B105 — dict key, not a credential
            "valid_for_seconds": None,
            "note": "SPECTER_ENROLLMENT_SECRET not configured â€” dev mode (open registration)",
        }

    token = generate_enrollment_token(settings.SPECTER_ENROLLMENT_SECRET)
    seconds_remaining = int(3600 - (_time.time() % 3600))

    return {
        "configured": True,
        "token": token,
        "valid_for_seconds": seconds_remaining,
        "note": f"Token expires in {seconds_remaining // 60}m {seconds_remaining % 60}s. Distribute via secure channel only.",
    }


# â”€â”€ Honeypot endpoints (registered before /{agent_id} â€” order matters) â”€â”€â”€â”€â”€â”€â”€â”€
# Legitimate SPECTER agents never call these paths.
# Any access triggers a security audit event indicating reconnaissance.

@router.get("/probe", summary="[HONEYPOT] Reconnaissance detection endpoint", include_in_schema=False)
async def _honeypot_probe(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Advanced honeypot: returns realistic system-status decoy with embedded canary token URL.
    Any access fingerprints the attacker and generates a signed evidence report persisted to DB.
    """
    client_ip = request.client.host if request.client else "unknown"
    headers = dict(request.headers)
    log_honeypot_trigger("/agents/probe", client_ip, headers)

    fp = fingerprint_request(client_ip, headers)
    base_url = str(request.base_url).rstrip("/")
    decoy, token = build_probe_decoy(base_url)

    try:
        ip_rep = await lookup_ip_reputation(client_ip, abuseipdb_key=settings.ABUSEIPDB_API_KEY)
    except Exception:
        ip_rep = {}

    report = generate_evidence_report(
        event_type="honeypot_probe_accessed",
        fingerprint=fp,
        token=token,
        ip_reputation=ip_rep,
        secret_key=settings.SECRET_KEY,
        additional_context={"decoy_type": "system_probe", "canary_label": token.label},
    )
    db.add(HoneypotEvidenceReport(
        report_id=report["report_id"],
        token_id=token.token_id,
        event_type="honeypot_probe_accessed",
        attacker_ip=client_ip,
        severity=report["report"]["incident_summary"]["severity"],
        generated_at=datetime.now(timezone.utc),
        report_json=report["report"],
        signature=report["signature"],
        fingerprint_hash=fp.fingerprint_hash,
    ))
    await db.commit()
    return decoy


@router.get("/dump", summary="[HONEYPOT] Agent dump endpoint", include_in_schema=False)
async def _honeypot_dump(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Advanced honeypot: returns realistic agent inventory decoy with embedded canary token.
    Evidence report persisted to DB (replaces removed in-memory _evidence_reports list).
    """
    client_ip = request.client.host if request.client else "unknown"
    headers = dict(request.headers)
    log_honeypot_trigger("/agents/dump", client_ip, headers)

    fp = fingerprint_request(client_ip, headers)
    base_url = str(request.base_url).rstrip("/")
    decoy, token = build_dump_decoy(base_url)

    try:
        ip_rep = await lookup_ip_reputation(client_ip, abuseipdb_key=settings.ABUSEIPDB_API_KEY)
    except Exception:
        ip_rep = {}

    report = generate_evidence_report(
        event_type="honeypot_dump_accessed",
        fingerprint=fp,
        token=token,
        ip_reputation=ip_rep,
        secret_key=settings.SECRET_KEY,
        additional_context={"decoy_type": "agent_inventory", "canary_label": token.label},
    )
    db.add(HoneypotEvidenceReport(
        report_id=report["report_id"],
        token_id=token.token_id,
        event_type="honeypot_dump_accessed",
        attacker_ip=client_ip,
        severity=report["report"]["incident_summary"]["severity"],
        generated_at=datetime.now(timezone.utc),
        report_json=report["report"],
        signature=report["signature"],
        fingerprint_hash=fp.fingerprint_hash,
    ))
    await db.commit()
    return decoy


@router.get("/export", summary="[HONEYPOT] Agent export endpoint", include_in_schema=False)
async def _honeypot_export(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Advanced honeypot: returns realistic credentials-export decoy with embedded canary token.
    Fake DB credentials reference non-routable internal hostnames â€” completely inert.
    Evidence report persisted to DB (replaces removed in-memory _evidence_reports list).
    """
    client_ip = request.client.host if request.client else "unknown"
    headers = dict(request.headers)
    log_honeypot_trigger("/agents/export", client_ip, headers)

    fp = fingerprint_request(client_ip, headers)
    base_url = str(request.base_url).rstrip("/")
    decoy, token = build_export_decoy(base_url)

    try:
        ip_rep = await lookup_ip_reputation(client_ip, abuseipdb_key=settings.ABUSEIPDB_API_KEY)
    except Exception:
        ip_rep = {}

    report = generate_evidence_report(
        event_type="honeypot_export_accessed",
        fingerprint=fp,
        token=token,
        ip_reputation=ip_rep,
        secret_key=settings.SECRET_KEY,
        additional_context={"decoy_type": "credentials_export", "canary_label": token.label},
    )
    db.add(HoneypotEvidenceReport(
        report_id=report["report_id"],
        token_id=token.token_id,
        event_type="honeypot_export_accessed",
        attacker_ip=client_ip,
        severity=report["report"]["incident_summary"]["severity"],
        generated_at=datetime.now(timezone.utc),
        report_json=report["report"],
        signature=report["signature"],
        fingerprint_hash=fp.fingerprint_hash,
    ))
    await db.commit()
    return decoy


# â”€â”€ Agent-specific endpoints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@router.get("/{agent_id}", summary="SPECTER agent detail")
async def get_agent(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
) -> dict:
    result = await db.execute(
        select(Agent).where(Agent.id == agent_id, Agent.tenant_id == current_user.tenant_id)
    )
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent = await refresh_agent_status(db, agent)
    return AgentOut.from_orm(agent).model_dump()


@router.delete("/{agent_id}", summary="Deregister SPECTER agent (admin only)")
async def deregister_agent(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
) -> dict:
    result = await db.execute(
        select(Agent).where(Agent.id == agent_id, Agent.tenant_id == current_user.tenant_id)
    )
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    await db.delete(agent)
    await db.commit()
    log_security_action(
        "agent_deregister",
        user_id=str(current_user.id),
        role=current_user.role,
        resource="agent",
        resource_id=agent_id,
        detail=f"hostname={agent.hostname}",
    )
    return {"detail": f"Agent {agent.hostname} deregistered."}


@router.post("/{agent_id}/events", summary="Ingest SPECTER telemetry batch")
async def ingest_agent_events(
    agent_id: str,
    payload: EventBatchRequest,
    response: Response,
    agent: Agent = Depends(_get_agent_by_header),
    db: AsyncSession = Depends(get_db),
) -> dict:
    _guard(response)

    if agent.id != agent_id:
        raise HTTPException(status_code=403, detail="Agent ID mismatch.")

    # Filter: rate limiting â€” max events per window per agent
    if not _event_rate_limiter.is_allowed(agent_id):
        log_security_action(
            "specter_rate_limit_exceeded",
            user_id="agent",
            role="agent",
            resource="agent_events",
            resource_id=agent_id,
            detail=f"hostname={agent.hostname} batch_size={len(payload.events)}",
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Telemetry rate limit exceeded. Slow down event submission.",
        )

    accepted, rejected = await ingest_events(db, agent, payload.events)

    # Strict sig mode: if any event was accepted but has invalid sig, emit audit event
    if settings.SPECTER_STRICT_SIGNATURE_MODE and rejected > 0:
        log_security_action(
            "specter_invalid_signatures",
            user_id="agent",
            role="agent",
            resource="agent_events",
            resource_id=agent_id,
            detail=f"hostname={agent.hostname} rejected={rejected}",
        )

    return {
        "accepted": accepted,
        "rejected": rejected,
        "ts":       datetime.now(timezone.utc).isoformat(),
    }


@router.get("/{agent_id}/commands", summary="Poll for pending SPECTER commands")
async def poll_commands(
    agent_id: str,
    response: Response,
    agent: Agent = Depends(_get_agent_by_header),
    db: AsyncSession = Depends(get_db),
) -> dict:
    _guard(response)

    if agent.id != agent_id:
        raise HTTPException(status_code=403, detail="Agent ID mismatch.")

    agent.last_seen = datetime.now(timezone.utc)
    if agent.status == "inactive":
        agent.status = "active"

    cmds = await get_pending_commands(db, agent_id)
    for cmd in cmds:
        await mark_command_delivered(db, cmd)

    return {
        "commands":      [_cmd_out(c) for c in cmds],
        "poll_interval": agent.poll_interval,
        "threat_level":  agent.threat_level,
        "ts":            datetime.now(timezone.utc).isoformat(),
    }


@router.post("/{agent_id}/results", summary="Report SPECTER command result")
async def report_command_result(
    agent_id: str,
    payload: CommandResultRequest,
    response: Response,
    agent: Agent = Depends(_get_agent_by_header),
    db: AsyncSession = Depends(get_db),
) -> dict:
    _guard(response)

    if agent.id != agent_id:
        raise HTTPException(status_code=403, detail="Agent ID mismatch.")

    result_q = await db.execute(
        select(AgentCommand).where(
            AgentCommand.id == payload.command_id,
            AgentCommand.agent_id == agent_id,
        )
    )
    cmd = result_q.scalar_one_or_none()
    if not cmd:
        raise HTTPException(status_code=404, detail="Command not found.")

    cmd = await record_command_result(
        db, cmd,
        success=payload.success,
        result=payload.result,
        error=payload.error,
    )
    return {"command_id": cmd.id, "status": cmd.status}


@router.post("/{agent_id}/command", summary="Issue command to SPECTER agent (admin only)")
async def issue_agent_command(
    agent_id: str,
    payload: IssueCommandRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
) -> dict:
    if payload.command_type not in _VALID_COMMAND_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown command_type. Valid: {sorted(_VALID_COMMAND_TYPES)}",
        )

    # Agent lookup first â€” 404 takes semantic priority over param errors
    result = await db.execute(
        select(Agent).where(Agent.id == agent_id, Agent.tenant_id == current_user.tenant_id)
    )
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    # Filter: param schema validation
    param_errors = validate_command_params(payload.command_type, payload.params)
    if param_errors:
        raise HTTPException(
            status_code=422,
            detail={"message": "Invalid command params", "errors": param_errors},
        )

    # Filter: injection check
    flagged = check_injection(payload.params)
    if flagged:
        log_security_action(
            "specter_injection_attempt",
            user_id=str(current_user.id),
            role=current_user.role,
            resource="agent_command",
            resource_id=agent_id,
            detail=f"command={payload.command_type} flagged_params={flagged}",
        )
        raise HTTPException(
            status_code=422,
            detail=f"Shell injection pattern detected in params: {flagged}",
        )
    cmd = await issue_command(
        db, agent, payload.command_type, payload.params, str(current_user.id),
        tenant_id=current_user.tenant_id,
    )

    log_security_action(
        "agent_command_issued",
        user_id=str(current_user.id),
        role=current_user.role,
        resource="agent",
        resource_id=agent_id,
        detail=f"command={payload.command_type} cmd_id={cmd.id}",
    )
    return _cmd_out(cmd)


@router.patch("/{agent_id}/threat", summary="Set agent threat level (analyst+)")
async def set_threat_level(
    agent_id: str,
    payload: SetThreatRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
) -> dict:
    valid = {"normal", "elevated", "critical"}
    if payload.threat_level not in valid:
        raise HTTPException(status_code=400, detail=f"threat_level must be one of: {sorted(valid)}")

    agent = await _get_agent_or_404(agent_id, db, tenant_id=current_user.tenant_id)
    old_level = agent.threat_level
    agent.threat_level = payload.threat_level
    agent.poll_interval = compute_poll_interval(payload.threat_level)
    await db.commit()

    log_security_action(
        "agent_threat_level_changed",
        user_id=str(current_user.id),
        role=current_user.role,
        resource="agent",
        resource_id=agent_id,
        detail=f"{old_level} â†’ {payload.threat_level} hostname={agent.hostname}",
    )
    return {
        "agent_id":      agent.id,
        "threat_level":  agent.threat_level,
        "poll_interval": agent.poll_interval,
    }


@router.get("/{agent_id}/timeline", summary="Recent events for a SPECTER agent")
async def agent_timeline(
    agent_id: str,
    limit: int = 100,
    anomalies_only: bool = False,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
) -> dict:
    agent = await _get_agent_or_404(agent_id, db, tenant_id=current_user.tenant_id)
    q = (
        select(AgentEvent)
        .where(AgentEvent.agent_id == agent_id)
        .order_by(AgentEvent.ts.desc())
        .limit(min(limit, 500))
    )
    if anomalies_only:
        q = q.where(AgentEvent.is_anomaly == True)  # noqa: E712

    result = await db.execute(q)
    events = result.scalars().all()
    return {
        "agent_id": agent_id,
        "hostname": agent.hostname,
        "events": [
            {
                "id":              e.id,
                "event_type":      e.event_type,
                "severity":        e.severity,
                "is_anomaly":      e.is_anomaly,
                "signature_valid": e.signature_valid,
                "data":            e.data,
                "ts":              e.ts.isoformat(),
                "received_at":     e.received_at.isoformat(),
            }
            for e in events
        ],
        "total": len(events),
    }


@router.get("/{agent_id}/command-history", summary="Command history for a SPECTER agent (analyst+)")
async def agent_command_history(
    agent_id: str,
    limit: int = 20,
    status_filter: str | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
) -> dict:
    """
    Returns the last N commands issued to this agent, including execution results.

    Useful for the analyst command center: poll this endpoint to see when a
    queued command transitions from pending â†’ delivered â†’ completed/failed.

    Results include the full result payload so log_query matches can be
    displayed directly in the UI without a separate fetch.

    Query params:
      limit        â€” max commands to return (default 20, max 100)
      status_filterâ€” optional filter: pending|delivered|completed|failed
    """
    agent = await _get_agent_or_404(agent_id, db, tenant_id=current_user.tenant_id)
    q = (
        select(AgentCommand)
        .where(AgentCommand.agent_id == agent_id)
        .order_by(AgentCommand.issued_at.desc())
        .limit(min(limit, 100))
    )
    if status_filter:
        q = q.where(AgentCommand.status == status_filter)

    result = await db.execute(q)
    cmds = result.scalars().all()
    return {
        "agent_id": agent_id,
        "hostname": agent.hostname,
        "commands": [_cmd_out(c, include_result=True) for c in cmds],
        "total":    len(cmds),
    }
