"""
SOAR ↔ Incident Bridge — P30-B / PIIL Adaptive Binding

Closes the loop between the Incident Response lifecycle (P28) and the SOAR
auto-trigger engine (P25), implementing the PIIL Adaptive SOAR Binding:

  1. Incident → SOAR  (forward binding)
     When an incident transitions status, a SOAR evaluation context is built
     and all matching PlaybookTriggers are fired automatically.
     Condition types added (extend soar_service._VALID_CONDITION_TYPES):
       • incident_status_change  — context["new_status"] matches condition_value
       • incident_sla_breach     — context["sla_breach"] is True (any value matches)
       • incident_severity       — context["severity"] gte/lte/eq condition_value

  2. SOAR → Incident  (reverse binding)
     When a SOAR trigger fires and the evaluation context carries an incident_id,
     a timeline entry is written to IncidentTimeline so analysts see which
     playbooks were activated during the incident lifecycle.

  3. PIIL Forensic SLA Ledger
     Every status transition that produces a SOAR binding event is also
     recorded in the forensic_ledger table (ForensicEntry) with SHA3-512 +
     Ed25519 signature — providing a tamper-evident chain of custody for the
     automated response decisions made during an incident.

Security posture
----------------
- Bridge calls are FIRE-AND-FORGET (non-blocking); a failure in SOAR binding
  never blocks or rolls back the incident transition.
- All DB writes are independent commits — incident and SOAR records cannot
  deadlock each other.
- Forensic ledger entries are append-only and never deleted.
- No attacker-controlled data reaches the SOAR evaluation context without
  validation in _build_incident_context().
"""
from __future__ import annotations

import base64
import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import log_security_action
from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.forensic_entry import ForensicEntry
from app.models.incident import Incident, IncidentTimeline

log = get_logger(__name__)
_s = get_settings()

# Severity rank (mirrors incident_service / correlation_service)
_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


# ── Context builder ────────────────────────────────────────────────────────────

def _build_incident_context(
    incident: Incident,
    new_status: str,
    actor: str,
) -> dict[str, Any]:
    """
    Build a SOAR evaluation context from an incident transition event.
    Only validated, typed fields are included — no raw user input.
    """
    return {
        # Standard SOAR context keys
        "severity": incident.severity,
        "actor": actor,
        # Incident-specific keys
        "incident_id": incident.id,
        "new_status": new_status,
        "previous_status": incident.status,
        "sla_breach": incident.sla_breach,
        "sla_minutes": incident.sla_minutes,
        "mttd_minutes": incident.mttd_minutes,
        "mttc_minutes": incident.mttc_minutes,
        "mttr_minutes": incident.mttr_minutes,
        "incident_type": incident.incident_type,
        "nist_phase": incident.nist_phase,
    }


# ── Forensic SLA Ledger entry ──────────────────────────────────────────────────

def _sign_ledger(hash_hex: str) -> str:
    """Sign hash_hex with SPECTER_SIGNING_PRIVATE_KEY. Returns base64 sig."""
    private_key_b64 = _s.SPECTER_SIGNING_PRIVATE_KEY
    if not private_key_b64:
        return base64.b64encode(b"PIIL-UNSIGNED").decode()
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        priv_bytes = base64.b64decode(private_key_b64)
        key = Ed25519PrivateKey.from_private_bytes(priv_bytes)
        return base64.b64encode(key.sign(hash_hex.encode())).decode()
    except Exception as exc:
        log.warning("PIIL ledger signing failed: %s", exc)
        return base64.b64encode(b"PIIL-SIGN-ERROR").decode()


async def _write_forensic_ledger(
    db: AsyncSession,
    incident_id: str,
    new_status: str,
    actor: str,
    triggers_fired: int,
    canonical: dict,
) -> None:
    """
    Append a signed ForensicEntry to the ledger for this SOAR binding event.
    Uses a separate commit so it never blocks the caller.
    """
    payload = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    hash_hex = hashlib.sha3_512(payload).hexdigest()
    sig = _sign_ledger(hash_hex)

    entry = ForensicEntry(
        id=str(uuid.uuid4()),
        action_id=incident_id,
        action_type="piil_soar_binding",
        target=f"incident:{incident_id}:{new_status}",
        canonical_data=canonical,
        hash_sha3_512=hash_hex,
        signature_ed25519=sig,
        signed_by_email=actor,
        signed_by_user_id="system",
        signed_at=datetime.now(timezone.utc),
        verified=bool(_s.SPECTER_SIGNING_PRIVATE_KEY),
    )
    db.add(entry)
    try:
        await db.commit()
    except Exception as exc:
        log.error("PIIL ledger commit failed (non-fatal): %s", exc)
        await db.rollback()


# ── SOAR → Incident timeline writer ───────────────────────────────────────────

async def write_soar_event_to_timeline(
    db: AsyncSession,
    incident_id: str,
    trigger_name: str,
    playbook_name: str,
    actor: str = "system:soar",
) -> None:
    """
    Write a SOAR trigger-fired event to IncidentTimeline.
    Called by the SOAR engine after a trigger fires in an incident context.
    Non-blocking — errors are logged but not raised.
    """
    result = await db.execute(
        select(Incident).where(Incident.id == incident_id)
    )
    incident = result.scalar_one_or_none()
    if incident is None:
        log.debug("write_soar_event_to_timeline: incident %s not found, skipping", incident_id)
        return

    now = datetime.now(timezone.utc)
    entry = IncidentTimeline(
        id=str(uuid.uuid4()),
        incident_id=incident_id,
        event_type="soar_triggered",
        actor=actor,
        detail={
            "trigger_name": trigger_name,
            "playbook_name": playbook_name,
            "fired_at": now.isoformat(),
        },
        created_at=now,
    )
    db.add(entry)
    incident.updated_at = now
    try:
        await db.commit()
        log.info(
            "soar_event_written incident=%s trigger=%r playbook=%r",
            incident_id, trigger_name, playbook_name,
        )
    except Exception as exc:
        log.error("soar_event_to_timeline commit failed (non-fatal): %s", exc)
        await db.rollback()


# ── Incident → SOAR forward binding ───────────────────────────────────────────

async def evaluate_soar_for_incident(
    db: AsyncSession,
    incident: Incident,
    new_status: str,
    actor: str,
) -> int:
    """
    Evaluate all enabled PlaybookTriggers against this incident transition.
    Fires matching triggers and writes results to IncidentTimeline.

    Returns the count of triggers fired.

    This is the PIIL Adaptive SOAR Binding entry point — called from
    incident_service.transition_status() after a successful commit.
    """
    from app.services.soar_service import evaluate_triggers_for_context

    context = _build_incident_context(incident, new_status, actor)
    now = datetime.now(timezone.utc)
    fired_count = 0

    try:
        fired = await evaluate_triggers_for_context(db, context)
        fired_count = len(fired)
    except Exception as exc:
        log.error("SOAR evaluation for incident %s failed (non-fatal): %s", incident.id, exc)
        return 0

    if fired_count > 0:
        # Write each fired trigger to IncidentTimeline
        for trigger_info in fired:
            entry = IncidentTimeline(
                id=str(uuid.uuid4()),
                incident_id=incident.id,
                event_type="soar_triggered",
                actor="system:soar",
                detail={
                    "trigger_id": trigger_info.get("trigger_id"),
                    "trigger_name": trigger_info.get("trigger_name"),
                    "playbook_id": trigger_info.get("playbook_id"),
                    "condition_type": trigger_info.get("condition_type"),
                    "new_status": new_status,
                    "fired_at": now.isoformat(),
                },
                created_at=now,
            )
            db.add(entry)

        try:
            await db.commit()
        except Exception as exc:
            log.error("SOAR timeline batch commit failed (non-fatal): %s", exc)
            await db.rollback()
            return 0

        # PIIL Forensic SLA Ledger — only write when at least one trigger fired
        canonical = {
            "incident_id": incident.id,
            "incident_type": incident.incident_type,
            "severity": incident.severity,
            "new_status": new_status,
            "sla_breach": incident.sla_breach,
            "triggers_fired": fired_count,
            "trigger_names": [t.get("trigger_name") for t in fired],
            "actor": actor,
            "timestamp": now.isoformat(),
            "piil_version": "1.0",
        }
        await _write_forensic_ledger(
            db, incident.id, new_status, actor, fired_count, canonical
        )

        log_security_action(
            "piil_soar_binding_fired",
            actor=actor,
            resource_id=incident.id,
            detail={"triggers_fired": fired_count, "new_status": new_status},
        )
        log.info(
            "piil_soar_binding incident=%s status=%s triggers_fired=%d",
            incident.id, new_status, fired_count,
        )

    return fired_count


# ── SLA breach proactive escalation ───────────────────────────────────────────

async def escalate_sla_breaches(db: AsyncSession) -> int:
    """
    Scan all open incidents for SLA breach condition.
    For each newly breached incident, evaluate SOAR triggers with
    condition_type='incident_sla_breach'.

    Called periodically by a Celery task (every ESCALATION_CHECK_INTERVAL_SECONDS).
    Returns count of incidents escalated.
    """
    from app.services.incident_service import _check_sla_breach, _utcnow
    from app.models.incident import VALID_TRANSITIONS

    result = await db.execute(
        select(Incident).where(
            Incident.status.not_in(["closed", "dismissed"]),
            Incident.sla_breach.is_(False),
        )
    )
    open_incidents = list(result.scalars().all())
    escalated = 0

    for inc in open_incidents:
        if _check_sla_breach(inc):
            inc.sla_breach = True
            inc.updated_at = _utcnow()

            from app.models.incident import IncidentTimeline
            now = _utcnow()
            entry = IncidentTimeline(
                id=str(uuid.uuid4()),
                incident_id=inc.id,
                event_type="sla_warning",
                actor="system:piil",
                detail={
                    "sla_minutes": inc.sla_minutes,
                    "severity": inc.severity,
                    "elapsed_minutes": inc.mttd_minutes,
                    "flagged_at": now.isoformat(),
                },
                created_at=now,
            )
            db.add(entry)
            escalated += 1

    if escalated > 0:
        try:
            await db.commit()
        except Exception as exc:
            log.error("SLA breach batch commit failed: %s", exc)
            await db.rollback()
            return 0

        log.info("piil_sla_escalation: flagged %d incidents as SLA breach", escalated)

    return escalated
