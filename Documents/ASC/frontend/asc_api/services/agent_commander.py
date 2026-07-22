"""
SPECTER Agent Commander — P13.

Responsible for:
  - Issuing signed commands to SPECTER agents
  - Computing adaptive poll interval based on threat level
  - Updating agent status (active/inactive based on last_seen)
  - Flagging behavioral anomalies in incoming telemetry
"""

import time
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.core.config import get_settings
from asc_api.core.signing import sign_command, verify_agent_event, is_fresh
from asc_api.models.agent import Agent, AgentCommand, AgentEvent

from asc_api.core.logging import get_logger
settings = get_settings()
log = get_logger("asc.agent_commander")

# ── Adaptive poll intervals (seconds) by threat level ─────────────────────────
POLL_INTERVALS: dict[str, int] = {
    "normal":   30,
    "elevated":  5,
    "critical":  1,
}

# ── Threat level → command priority ───────────────────────────────────────────
THREAT_LEVEL_WEIGHT: dict[str, int] = {
    "normal":   0,
    "elevated": 1,
    "critical": 2,
}


# ── Command issuing ────────────────────────────────────────────────────────────

async def issue_command(
    db: AsyncSession,
    agent: Agent,
    command_type: str,
    params: dict[str, Any],
    issued_by: str,
    tenant_id: str | None = None,
) -> AgentCommand:
    """
    Create a signed AgentCommand and persist it.

    The payload that is signed includes all fields that the agent will
    re-compute and verify — preventing parameter tampering in transit.
    """
    cmd_id = str(uuid.uuid4())
    ts = time.time()

    signable = {
        "id":           cmd_id,
        "agent_id":     agent.id,
        "command_type": command_type,
        "params":       params,
        "ts":           ts,
    }

    if not settings.SPECTER_SIGNING_PRIVATE_KEY:
        sig = "unsigned-dev-mode"
    else:
        sig = sign_command(settings.SPECTER_SIGNING_PRIVATE_KEY, signable)

    cmd = AgentCommand(
        id=cmd_id,
        tenant_id=tenant_id or agent.tenant_id,
        agent_id=agent.id,
        command_type=command_type,
        params=params,
        signature=sig,
        status="pending",
        issued_by=issued_by,
    )
    db.add(cmd)
    await db.commit()
    await db.refresh(cmd)
    return cmd


# ── Telemetry ingestion ────────────────────────────────────────────────────────

async def ingest_events(
    db: AsyncSession,
    agent: Agent,
    events: list[dict[str, Any]],
) -> tuple[int, int]:
    """
    Verify and store a batch of telemetry events from a SPECTER agent.

    Returns (accepted_count, rejected_count, accepted_events).
    Rejected = replay (ts fuera de ventana, siempre) o firma inválida
    (SOLO cuando SPECTER_STRICT_SIGNATURE_MODE=True). En modo permisivo los
    eventos con firma inválida se almacenan con signature_valid=False.
    Anomaly detection: marks event as anomaly if event_type not seen
    in the last 500 events for this agent (simple novelty detection).
    """
    if not events:
        return 0, 0, []

    # Load a lightweight set of known event types for this agent (novelty baseline)
    recent_q = await db.execute(
        select(AgentEvent.event_type)
        .where(AgentEvent.agent_id == agent.id)
        .order_by(AgentEvent.received_at.desc())
        .limit(500)
    )
    known_types: set[str] = {r for (r,) in recent_q}

    accepted = rejected = 0
    accepted_events: list[dict[str, Any]] = []
    for raw in events[:settings.SPECTER_MAX_EVENTS_PER_BATCH]:
        sig = raw.pop("signature", "")
        ts_val = raw.get("ts", 0)

        # Replay protection
        if not is_fresh(ts_val):
            rejected += 1
            continue

        # Signature verification
        valid = verify_agent_event(agent.public_key, raw, sig)

        # SECURITY (S103.5): en modo estricto, rechazar eventos con firma Ed25519
        # inválida. Antes se almacenaban con signature_valid=False y se contaban
        # como aceptados, dejando INERTE el control criptográfico (permitía inyectar
        # telemetría spoofeada conociendo solo el ID del agente). El docstring ya
        # prometía este rechazo; ahora el código lo cumple.
        if not valid and settings.SPECTER_STRICT_SIGNATURE_MODE:
            rejected += 1
            continue

        event_type = raw.get("event_type", "unknown")
        is_anomaly = event_type not in known_types
        known_types.add(event_type)

        try:
            event_ts = datetime.fromtimestamp(ts_val, tz=timezone.utc)
        except Exception:
            event_ts = datetime.now(timezone.utc)

        ev = AgentEvent(
            agent_id=agent.id,
            event_type=event_type,
            severity=raw.get("severity", "info"),
            data=raw,
            signature=sig,
            signature_valid=valid,
            is_anomaly=is_anomaly,
            ts=event_ts,
        )
        db.add(ev)
        accepted += 1
        # S106.1 — retener el evento aceptado para el puente de detección
        accepted_events.append({
            "raw": raw,
            "event_id": ev.id,
            "event_type": event_type,
            "severity": str(raw.get("severity", "info")).lower(),
            "is_anomaly": is_anomaly,
        })

    # Update agent heartbeat and event counter
    agent.last_seen = datetime.now(timezone.utc)
    agent.total_events = (agent.total_events or 0) + accepted
    await db.commit()
    return accepted, rejected, accepted_events


# ── S106.1 — Puente de detección: telemetría SPECTER → alertas ────────────────
#
# HALLAZGO S106: ingest_events almacenaba AgentEvent pero NO alimentaba el motor
# de detección. La telemetría del agente moría como registro. Este puente cierra
# el eslabón entrante: eventos aceptados → correlación (mismas reglas) + anomalía/
# severidad → Alert, SIEMPRE scopeada al tenant del agente. Decisión (2026-07-21):
# ambos caminos (correlación + anomalía).

async def detect_from_agent_events(
    db: AsyncSession, agent: Agent, accepted_events: list[dict[str, Any]]
) -> list[str]:
    """
    Corre detección sobre los eventos aceptados de un agente y crea alertas.
    Devuelve la lista de IDs de alertas creadas. Idempotencia por-lote: deduplica
    las alertas de anomalía por (event_type, severity) dentro del batch.
    """
    if not accepted_events:
        return []

    # Import local para evitar ciclo (correlator no debe importar commander).
    from asc_api.models.alert import Alert
    from asc_api.services.correlator import evaluate_correlation_rules, normalize_event

    tid = agent.tenant_id
    host = agent.hostname
    event_ids = [it["event_id"] for it in accepted_events]

    normalized = []
    for it in accepted_events:
        raw = {**it["raw"]}
        raw.setdefault("host", host)
        normalized.append(await normalize_event(raw))

    objs: list[Alert] = []

    # 1) Correlación — MISMAS reglas que el resto del sistema (sin lógica duplicada).
    for ad in await evaluate_correlation_rules(normalized, db):
        objs.append(Alert(
            title=ad["title"],
            description=ad["description"],
            severity=ad["severity"],
            risk_score=ad["risk_score"],
            ttps=ad.get("ttps", []),
            source_events=event_ids,
            affected_hosts=[host] if host else [],
            recommended_actions=[],
            tenant_id=tid,
        ))

    # 2) Anomalía / severidad alta — deduplicado por (event_type, severity) en el lote.
    seen: set = set()
    for it in accepted_events:
        et = it["event_type"]
        sev = it["severity"]
        high = sev in ("high", "critical")
        if not (it["is_anomaly"] or high):
            continue
        key = (et, sev)
        if key in seen:
            continue
        seen.add(key)
        reason = "anomalía de comportamiento (tipo no visto)" if it["is_anomaly"] else f"severidad {sev}"
        objs.append(Alert(
            title=f"Telemetría SPECTER: {et} en {host or 'agente'}",
            description=f"Evento '{et}' del agente {host or agent.id} marcado por {reason}.",
            severity="high" if high else "medium",
            risk_score=0.8 if high else 0.5,
            ttps=[],
            source_events=[it["event_id"]],
            affected_hosts=[host] if host else [],
            recommended_actions=[],
            tenant_id=tid,
        ))

    if not objs:
        return []
    for a in objs:
        db.add(a)
    await db.commit()               # el default de id se aplica en el flush
    created = [a.id for a in objs]  # ids ya poblados tras el commit
    log.info("specter_detection_alerts", agent_id=agent.id, alerts=len(created))
    return created


# ── Status management ──────────────────────────────────────────────────────────

def compute_poll_interval(threat_level: str) -> int:
    """Return the poll interval in seconds for a given threat level."""
    return POLL_INTERVALS.get(threat_level, 30)


def escalate_threat_level(current: str) -> str:
    """Escalate threat level by one step. critical stays critical."""
    order = ["normal", "elevated", "critical"]
    idx = order.index(current) if current in order else 0
    return order[min(idx + 1, len(order) - 1)]


def deescalate_threat_level(current: str) -> str:
    """De-escalate threat level by one step. normal stays normal."""
    order = ["normal", "elevated", "critical"]
    idx = order.index(current) if current in order else 0
    return order[max(idx - 1, 0)]


async def refresh_agent_status(db: AsyncSession, agent: Agent) -> Agent:
    """
    Mark agent inactive if it hasn't been seen in SPECTER_INACTIVE_THRESHOLD_SECONDS.
    Called on GET /agents/{id} so the UI always shows fresh status.
    """
    threshold = settings.SPECTER_INACTIVE_THRESHOLD_SECONDS
    last_seen = agent.last_seen
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)
    elapsed = (datetime.now(timezone.utc) - last_seen).total_seconds()
    if elapsed > threshold and agent.status == "active":
        agent.status = "inactive"
        await db.commit()
    return agent


# ── Command delivery helpers ───────────────────────────────────────────────────

async def get_pending_commands(db: AsyncSession, agent_id: str) -> list[AgentCommand]:
    """Fetch all pending commands for an agent (oldest first)."""
    result = await db.execute(
        select(AgentCommand)
        .where(AgentCommand.agent_id == agent_id, AgentCommand.status == "pending")
        .order_by(AgentCommand.issued_at.asc())
    )
    return list(result.scalars().all())


async def mark_command_delivered(db: AsyncSession, cmd: AgentCommand) -> None:
    cmd.status = "delivered"
    cmd.delivered_at = datetime.now(timezone.utc)
    await db.commit()


async def record_command_result(
    db: AsyncSession,
    cmd: AgentCommand,
    success: bool,
    result: dict[str, Any],
    error: str | None = None,
) -> AgentCommand:
    cmd.status = "completed" if success else "failed"
    cmd.completed_at = datetime.now(timezone.utc)
    cmd.result = result
    cmd.error = error

    # Trap: canary ping — verify the agent's proof-of-private-key response.
    # The agent signs {"nonce": <nonce>} with its Ed25519 private key.
    # We verify with the registered public key to confirm the agent holds the
    # original key (detecting compromised agents running with copied credentials).
    if cmd.command_type == "canary_ping" and success:
        from sqlalchemy import select as _select
        from asc_api.core.audit import log_security_action
        agent_q = await db.execute(_select(Agent).where(Agent.id == cmd.agent_id))
        agent_obj = agent_q.scalar_one_or_none()
        if agent_obj:
            pong = result.get("pong", "")
            nonce = result.get("nonce", "")
            valid = verify_agent_event(agent_obj.public_key, {"nonce": nonce}, pong)
            event = "specter_canary_ping_verified" if valid else "specter_canary_ping_failed"
            log_security_action(
                event,
                user_id="system",
                role="system",
                resource="agent",
                resource_id=cmd.agent_id,
                detail=f"cmd_id={cmd.id} nonce={nonce[:16]}... valid={valid}",
            )

    await db.commit()
    await db.refresh(cmd)
    return cmd
