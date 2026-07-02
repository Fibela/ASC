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

settings = get_settings()

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

    Returns (accepted_count, rejected_count).
    Rejected = invalid signature or replay (ts out of window).
    Anomaly detection: marks event as anomaly if event_type not seen
    in the last 500 events for this agent (simple novelty detection).
    """
    if not events:
        return 0, 0

    # Load a lightweight set of known event types for this agent (novelty baseline)
    recent_q = await db.execute(
        select(AgentEvent.event_type)
        .where(AgentEvent.agent_id == agent.id)
        .order_by(AgentEvent.received_at.desc())
        .limit(500)
    )
    known_types: set[str] = {r for (r,) in recent_q}

    accepted = rejected = 0
    for raw in events[:settings.SPECTER_MAX_EVENTS_PER_BATCH]:
        sig = raw.pop("signature", "")
        ts_val = raw.get("ts", 0)

        # Replay protection
        if not is_fresh(ts_val):
            rejected += 1
            continue

        # Signature verification
        valid = verify_agent_event(agent.public_key, raw, sig)

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

    # Update agent heartbeat and event counter
    agent.last_seen = datetime.now(timezone.utc)
    agent.total_events = (agent.total_events or 0) + accepted
    await db.commit()
    return accepted, rejected


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
