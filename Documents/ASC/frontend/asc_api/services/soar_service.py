"""
SOAR Service — P25-S1

Condition-based playbook auto-triggering engine.

Architecture
------------
A PlaybookTrigger defines a condition (type + operator + value) that, when
satisfied by an evaluation context, fires the associated playbook automatically.

Evaluation contexts are produced by:
  - PCDI adaptive scoring (pcdi_score type)
  - Hunt finding creation/confirmation (finding_severity type)
  - Hunt status/priority changes (hunt_priority type)
  - PANL neutralization action updates (panl_status type)

evaluate_triggers_for_context() is called:
  1. From the PCDI Celery escalation task (after hunt is upgraded to critical)
  2. From PCDI score endpoint (inline, non-blocking)
  3. From PANL approval/completion hooks

Security:
  - Triggers only fire read-only by default; PlaybookContext is built with
    analyst context so playbook actions still respect HitL if required.
  - Trigger execution is logged via log_security_action.
  - trigger_count + last_triggered_at updated atomically on fire.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.core.audit import log_security_action
from asc_api.core.logging import get_logger
from asc_api.core.tenant_context import get_tenant_id
from asc_api.models.soar import PlaybookTrigger

log = get_logger("asc.soar")

# ── Condition evaluation ───────────────────────────────────────────────────────

_VALID_CONDITION_TYPES = frozenset(
    {
        "pcdi_score",
        "finding_severity",
        "hunt_priority",
        "panl_status",
        # P26 PIDS — identity-aware condition types
        "identity_group",  # context["groups"] list contains condition_value
        "iam_event",  # context["iam_action"] matches condition_value (eq/contains)
        # P30 PIIL — incident lifecycle condition types
        "incident_status_change",  # context["new_status"] eq/contains condition_value
        "incident_sla_breach",  # context["sla_breach"] is True (any operator matches)
        "incident_severity",  # context["severity"] gte/lte/eq condition_value
    }
)

_VALID_OPERATORS = frozenset({"gte", "lte", "eq", "contains"})

_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _evaluate_condition(trigger: PlaybookTrigger, context: dict[str, Any]) -> bool:
    """
    Return True if trigger condition is satisfied by the evaluation context.

    Context keys (all optional — missing key → condition not satisfied):
      pcdi_score    : float  — adaptive score 0-100
      severity      : str    — finding severity (info/low/medium/high/critical)
      hunt_priority : str    — hunt priority (low/medium/high/critical)
      panl_status   : str    — PANL action status
    """
    ctype = trigger.condition_type
    op = trigger.condition_operator
    val = trigger.condition_value

    if ctype == "pcdi_score":
        score = context.get("pcdi_score")
        if score is None:
            return False
        threshold = float(val)
        if op == "gte":
            return float(score) >= threshold
        if op == "lte":
            return float(score) <= threshold
        if op == "eq":
            return float(score) == threshold
        return False

    if ctype == "finding_severity":
        severity = context.get("severity", "")
        if op == "eq":
            return severity == val
        if op == "gte":
            return _SEVERITY_ORDER.get(severity, -1) >= _SEVERITY_ORDER.get(val, 999)
        if op == "contains":
            return severity in [v.strip() for v in val.split(",")]
        return False

    if ctype == "hunt_priority":
        priority = context.get("hunt_priority", "")
        if op == "eq":
            return priority == val
        if op == "contains":
            return priority in [v.strip() for v in val.split(",")]
        return False

    if ctype == "panl_status":
        status = context.get("panl_status", "")
        if op == "eq":
            return status == val
        if op == "contains":
            return status in [v.strip() for v in val.split(",")]
        return False

    # P26 — identity_group: context["groups"] is a list of AD group names
    if ctype == "identity_group":
        groups: list = context.get("groups", [])
        if not isinstance(groups, list):
            return False
        if op == "eq":
            return val in groups
        if op == "contains":
            targets = [v.strip() for v in val.split(",")]
            return any(g in groups for g in targets)
        return False

    # P26 — iam_event: context["iam_action"] is a string event name
    if ctype == "iam_event":
        iam_action = context.get("iam_action", "")
        if op == "eq":
            return iam_action == val
        if op == "contains":
            return iam_action in [v.strip() for v in val.split(",")]
        return False

    # P30 PIIL — incident_status_change: context["new_status"] matches condition_value
    if ctype == "incident_status_change":
        new_status = context.get("new_status", "")
        if op == "eq":
            return new_status == val
        if op == "contains":
            return new_status in [v.strip() for v in val.split(",")]
        return False

    # P30 PIIL — incident_sla_breach: fires whenever sla_breach is True
    if ctype == "incident_sla_breach":
        return bool(context.get("sla_breach", False))

    # P30 PIIL — incident_severity: context["severity"] gte/lte/eq condition_value
    if ctype == "incident_severity":
        severity = context.get("severity", "")
        if op == "eq":
            return severity == val
        if op == "gte":
            return _SEVERITY_ORDER.get(severity, -1) >= _SEVERITY_ORDER.get(val, 999)
        if op == "lte":
            return _SEVERITY_ORDER.get(severity, 999) <= _SEVERITY_ORDER.get(val, -1)
        if op == "contains":
            return severity in [v.strip() for v in val.split(",")]
        return False

    return False


# ── Core service functions ─────────────────────────────────────────────────────


async def evaluate_triggers_for_context(
    db: AsyncSession,
    context: dict[str, Any],
    *,
    triggered_by: str = "system",
) -> list[dict]:
    """
    Evaluate all enabled triggers against the provided context dict.

    For each matching trigger, fire the associated playbook automatically.
    Returns a list of fire results (one per matched trigger).

    Context dict example:
      {
        "pcdi_score": 85,
        "severity": "critical",
        "hunt_priority": "critical",
        "hunt_id": "...",
        "finding_id": "...",
      }
    """
    result = await db.execute(select(PlaybookTrigger).where(PlaybookTrigger.enabled.is_(True)))
    # P26: adaptive orchestration — evaluate highest-priority triggers first
    triggers = sorted(result.scalars().all(), key=lambda t: getattr(t, "priority", 5), reverse=True)

    fired: list[dict] = []
    hunt_id_ctx = context.get("hunt_id")

    for trigger in triggers:
        # Scope filter
        if trigger.hunt_id_filter and trigger.hunt_id_filter != hunt_id_ctx:
            continue

        if not _evaluate_condition(trigger, context):
            continue

        # P26: dedup — skip if same playbook awaiting_approval in dedup window
        dedup_mins = getattr(trigger, "dedup_window_minutes", 0) or 0
        if dedup_mins > 0 and await _is_dedup_active(db, trigger, dedup_mins):
            log.info(
                "soar_trigger_dedup_skip",
                trigger_id=trigger.id,
                playbook_id=trigger.playbook_id,
                dedup_window_minutes=dedup_mins,
            )
            continue

        fire_result = await _fire_trigger(db, trigger, context, triggered_by=triggered_by)
        fired.append(fire_result)

    if fired:
        log.info(
            "soar_triggers_fired",
            count=len(fired),
            context_keys=list(context.keys()),
            triggered_by=triggered_by,
        )

    return fired


async def _is_dedup_active(
    db: AsyncSession,
    trigger: PlaybookTrigger,
    dedup_window_minutes: int,
) -> bool:
    """
    Return True if the trigger's playbook has a run in awaiting_approval status
    created within the dedup window.  Prevents duplicate approval queues.
    """
    from datetime import timedelta

    from asc_api.models.playbook_run import PlaybookRun

    cutoff = datetime.now(UTC) - timedelta(minutes=dedup_window_minutes)
    stmt = (
        select(PlaybookRun)
        .where(
            PlaybookRun.playbook_id == trigger.playbook_id,
            PlaybookRun.status == "awaiting_approval",
            PlaybookRun.started_at >= cutoff,
        )
        .limit(1)
    )
    result = await db.execute(stmt)
    return result.scalar_one_or_none() is not None


async def _fire_trigger(
    db: AsyncSession,
    trigger: PlaybookTrigger,
    context: dict[str, Any],
    *,
    triggered_by: str,
) -> dict:
    """
    Execute the playbook associated with a matched trigger.

    Imports trigger_playbook lazily to avoid circular imports.
    Updates trigger metadata (count + timestamp) after firing.
    """
    from asc_api.services.playbook import PlaybookContext, trigger_playbook

    pb_context = PlaybookContext(
        semaphore="red" if context.get("pcdi_score", 0) >= 80 else "yellow",
        risk_score=min(1.0, context.get("pcdi_score", 50) / 100),
        trigger_source="soar_auto",
        host=context.get("affected_host"),
        dst_ip=context.get("indicator_value") if context.get("indicator_type") == "ip" else None,
        # P26: propagate identity context so identity step types can act
        affected_user=context.get("affected_user"),
        affected_domain=context.get("affected_domain", "corp.local"),
        trigger_data={
            "soar_trigger_id": trigger.id,
            "condition_type": trigger.condition_type,
            "condition_value": trigger.condition_value,
            **context,
        },
    )

    run_id = None
    error = None
    try:
        # trigger_playbook signature: (playbook_id, ctx, db, initiated_by) → PlaybookRun
        run = await trigger_playbook(trigger.playbook_id, pb_context, db, triggered_by)
        run_id = run.id
    except Exception as exc:
        error = str(exc)
        log.warning("soar_trigger_fire_error", trigger_id=trigger.id, error=error)

    # Update trigger metadata
    trigger.trigger_count = (trigger.trigger_count or 0) + 1
    trigger.last_triggered_at = datetime.now(UTC)
    trigger.last_triggered_context = str(context)[:500]
    await db.commit()

    log_security_action(
        "soar_trigger_fired",
        user_id=triggered_by,
        role="system",
        resource="playbook_trigger",
        resource_id=trigger.id,
        detail=(
            f"Trigger '{trigger.condition_type} {trigger.condition_operator} {trigger.condition_value}' "
            f"→ playbook {trigger.playbook_id}. "
            f"run_id={run_id}. error={error}"
        ),
        status="ok" if not error else "error",
    )

    return {
        "trigger_id": trigger.id,
        "trigger_name": getattr(trigger, "name", trigger.condition_type),
        "playbook_id": trigger.playbook_id,
        "playbook_name": getattr(trigger, "playbook_name", ""),
        "condition_type": trigger.condition_type,
        "matched": True,
        "run_id": run_id,
        "error": error,
        "fired_at": datetime.now(UTC).isoformat(),
    }


async def create_trigger(
    db: AsyncSession,
    *,
    playbook_id: str,
    playbook_name: str,
    condition_type: str,
    condition_operator: str,
    condition_value: str,
    hunt_id_filter: str | None = None,
    priority: int = 5,
    rate_limit_per_hour: int = 10,
    dedup_window_minutes: int = 0,
    created_by: str,
) -> dict:
    """Create and persist a new PlaybookTrigger."""
    if condition_type not in _VALID_CONDITION_TYPES:
        return {"error": f"Invalid condition_type '{condition_type}'. Valid: {sorted(_VALID_CONDITION_TYPES)}"}
    if condition_operator not in _VALID_OPERATORS:
        return {"error": f"Invalid condition_operator '{condition_operator}'. Valid: {sorted(_VALID_OPERATORS)}"}
    if not (1 <= priority <= 10):
        return {"error": "priority must be between 1 and 10"}

    trigger = PlaybookTrigger(
        id=str(uuid.uuid4()),
        playbook_id=playbook_id,
        playbook_name=playbook_name,
        condition_type=condition_type,
        condition_operator=condition_operator,
        condition_value=condition_value,
        hunt_id_filter=hunt_id_filter,
        priority=priority,
        rate_limit_per_hour=rate_limit_per_hour,
        dedup_window_minutes=dedup_window_minutes,
        enabled=True,
        trigger_count=0,
        created_by=created_by,
        created_at=datetime.now(UTC),
    )
    db.add(trigger)
    await db.commit()
    await db.refresh(trigger)

    log_security_action(
        "soar_trigger_created",
        user_id=created_by,
        role="analyst",
        resource="playbook_trigger",
        resource_id=trigger.id,
        detail=f"{condition_type} {condition_operator} {condition_value} → {playbook_id}",
        status="ok",
    )
    return _trigger_to_dict(trigger)


async def list_triggers(
    db: AsyncSession,
    *,
    playbook_id: str | None = None,
    condition_type: str | None = None,
    enabled_only: bool = False,
) -> list[dict]:
    """List stored triggers, with optional filters."""
    q = select(PlaybookTrigger).order_by(PlaybookTrigger.created_at.desc())
    if playbook_id:
        q = q.where(PlaybookTrigger.playbook_id == playbook_id)
    if condition_type:
        q = q.where(PlaybookTrigger.condition_type == condition_type)
    if enabled_only:
        q = q.where(PlaybookTrigger.enabled.is_(True))
    result = await db.execute(q)
    return [_trigger_to_dict(t) for t in result.scalars().all()]


async def get_trigger(db: AsyncSession, trigger_id: str, tenant_id: str | None = None) -> dict | None:
    stmt = select(PlaybookTrigger).where(PlaybookTrigger.id == trigger_id)
    if tenant_id is not None:  # SECURITY (S103.6): aislamiento cross-tenant
        stmt = stmt.where(PlaybookTrigger.tenant_id == tenant_id)
    result = await db.execute(stmt)
    t = result.scalar_one_or_none()
    return _trigger_to_dict(t) if t else None


async def delete_trigger(db: AsyncSession, trigger_id: str, *, deleted_by: str, tenant_id: str | None = None) -> bool:
    stmt = select(PlaybookTrigger).where(PlaybookTrigger.id == trigger_id)
    if tenant_id is not None:  # SECURITY (S103.6)
        stmt = stmt.where(PlaybookTrigger.tenant_id == tenant_id)
    result = await db.execute(stmt)
    t = result.scalar_one_or_none()
    if not t:
        return False
    await db.delete(t)
    await db.commit()
    log_security_action(
        "soar_trigger_deleted",
        user_id=deleted_by,
        role="analyst",
        resource="playbook_trigger",
        resource_id=trigger_id,
        detail=f"Deleted trigger {trigger_id} ({t.condition_type} → {t.playbook_id})",
        status="ok",
    )
    return True


async def toggle_trigger(
    db: AsyncSession, trigger_id: str, *, enabled: bool, updated_by: str, tenant_id: str | None = None
) -> dict | None:
    stmt = select(PlaybookTrigger).where(PlaybookTrigger.id == trigger_id)
    if tenant_id is not None:  # SECURITY (S103.6)
        stmt = stmt.where(PlaybookTrigger.tenant_id == tenant_id)
    result = await db.execute(stmt)
    t = result.scalar_one_or_none()
    if not t:
        return None
    t.enabled = enabled
    await db.commit()
    return _trigger_to_dict(t)


async def test_trigger(trigger_id: str, context: dict, db: AsyncSession) -> dict:
    """Dry-run evaluation of a single trigger against a provided context (no firing)."""
    _stmt = select(PlaybookTrigger).where(PlaybookTrigger.id == trigger_id)
    _tid = get_tenant_id()  # SECURITY (S103.7): dry-run también aísla
    if _tid is not None:
        _stmt = _stmt.where(PlaybookTrigger.tenant_id == _tid)
    result = await db.execute(_stmt)
    t = result.scalar_one_or_none()
    if not t:
        return {"error": "Trigger not found", "trigger_id": trigger_id}
    matched = _evaluate_condition(t, context)
    return {
        "trigger_id": trigger_id,
        "playbook_id": t.playbook_id,
        "condition_type": t.condition_type,
        "condition_operator": t.condition_operator,
        "condition_value": t.condition_value,
        "context": context,
        "matched": matched,
        "would_fire": matched and t.enabled,
        "note": "Dry-run — no playbook executed.",
    }


def _trigger_to_dict(t: PlaybookTrigger) -> dict:
    return {
        "id": t.id,
        "playbook_id": t.playbook_id,
        "playbook_name": t.playbook_name,
        "condition_type": t.condition_type,
        "condition_operator": t.condition_operator,
        "condition_value": t.condition_value,
        "hunt_id_filter": t.hunt_id_filter,
        # P26 adaptive orchestration fields
        "priority": getattr(t, "priority", 5),
        "rate_limit_per_hour": getattr(t, "rate_limit_per_hour", 10),
        "dedup_window_minutes": getattr(t, "dedup_window_minutes", 0),
        "enabled": t.enabled,
        "trigger_count": t.trigger_count,
        "last_triggered_at": t.last_triggered_at.isoformat() if t.last_triggered_at else None,
        "last_triggered_context": t.last_triggered_context,
        "created_by": t.created_by,
        "created_at": t.created_at.isoformat() if t.created_at else None,
    }


# ── ScheduledReport CRUD ───────────────────────────────────────────────────────

_VALID_FREQUENCIES = frozenset({"daily", "weekly"})
_VALID_FORMATS = frozenset({"json", "pdf"})


async def create_scheduled_report(
    db: AsyncSession,
    *,
    hunt_id: str,
    hunt_name: str | None,
    recipient_email: str,
    frequency: str,
    format: str,
    created_by: str,
) -> dict:
    """Create and persist a new ScheduledReport."""
    from asc_api.models.soar import ScheduledReport

    if frequency not in _VALID_FREQUENCIES:
        return {"error": f"Invalid frequency '{frequency}'. Valid: {sorted(_VALID_FREQUENCIES)}"}
    if format not in _VALID_FORMATS:
        return {"error": f"Invalid format '{format}'. Valid: {sorted(_VALID_FORMATS)}"}

    sr = ScheduledReport(
        id=str(uuid.uuid4()),
        hunt_id=hunt_id,
        hunt_name=hunt_name,
        recipient_email=recipient_email,
        frequency=frequency,
        format=format,
        enabled=True,
        send_count=0,
        created_by=created_by,
        created_at=datetime.now(UTC),
    )
    db.add(sr)
    await db.commit()
    await db.refresh(sr)
    log_security_action(
        "scheduled_report_created",
        user_id=created_by,
        role="analyst",
        resource="scheduled_report",
        resource_id=sr.id,
        detail=f"Hunt {hunt_id} → {recipient_email} ({frequency}/{format})",
        status="ok",
    )
    return _report_to_dict(sr)


async def list_scheduled_reports(
    db: AsyncSession,
    *,
    hunt_id: str | None = None,
    enabled_only: bool = False,
) -> list[dict]:
    from asc_api.models.soar import ScheduledReport

    q = select(ScheduledReport).order_by(ScheduledReport.created_at.desc())
    if hunt_id:
        q = q.where(ScheduledReport.hunt_id == hunt_id)
    if enabled_only:
        q = q.where(ScheduledReport.enabled.is_(True))
    result = await db.execute(q)
    return [_report_to_dict(r) for r in result.scalars().all()]


async def get_scheduled_report(db: AsyncSession, report_id: str) -> dict | None:
    from asc_api.models.soar import ScheduledReport

    _stmt = select(ScheduledReport).where(ScheduledReport.id == report_id)
    _tid = get_tenant_id()  # SECURITY (S103.7)
    if _tid is not None:
        _stmt = _stmt.where(ScheduledReport.tenant_id == _tid)
    result = await db.execute(_stmt)
    r = result.scalar_one_or_none()
    return _report_to_dict(r) if r else None


async def delete_scheduled_report(db: AsyncSession, report_id: str, *, deleted_by: str) -> bool:
    from asc_api.models.soar import ScheduledReport

    _stmt = select(ScheduledReport).where(ScheduledReport.id == report_id)
    _tid = get_tenant_id()  # SECURITY (S103.7)
    if _tid is not None:
        _stmt = _stmt.where(ScheduledReport.tenant_id == _tid)
    result = await db.execute(_stmt)
    r = result.scalar_one_or_none()
    if not r:
        return False
    await db.delete(r)
    await db.commit()
    log_security_action(
        "scheduled_report_deleted",
        user_id=deleted_by,
        role="analyst",
        resource="scheduled_report",
        resource_id=report_id,
        detail=f"Deleted scheduled report {report_id}",
        status="ok",
    )
    return True


async def toggle_scheduled_report(db: AsyncSession, report_id: str, *, enabled: bool, updated_by: str) -> dict | None:
    from asc_api.models.soar import ScheduledReport

    _stmt = select(ScheduledReport).where(ScheduledReport.id == report_id)
    _tid = get_tenant_id()  # SECURITY (S103.7)
    if _tid is not None:
        _stmt = _stmt.where(ScheduledReport.tenant_id == _tid)
    result = await db.execute(_stmt)
    r = result.scalar_one_or_none()
    if not r:
        return None
    r.enabled = enabled
    await db.commit()
    return _report_to_dict(r)


async def deliver_scheduled_report(db: AsyncSession, report_id: str) -> dict:
    """
    Generate and deliver a single scheduled report immediately.

    P26 PIDS extension:
      - Includes identity action timeline for the hunt
      - Signs the full report payload with SHA3-512 + Ed25519
        using PIDS_SIGNING_PRIVATE_KEY / SPECTER_SIGNING_PRIVATE_KEY
      - Returns forensic_hash and signature in the response

    Email delivery via Resend (RESEND_API_KEY required); logs only when key absent.
    """
    import hashlib
    import json

    from asc_api.models.hunt import Hunt, HuntFinding
    from asc_api.models.soar import ScheduledReport
    from asc_api.services.pids_service import _sign_hash, get_identity_timeline

    _stmt = select(ScheduledReport).where(ScheduledReport.id == report_id)
    _tid = get_tenant_id()  # SECURITY (S103.7)
    if _tid is not None:
        _stmt = _stmt.where(ScheduledReport.tenant_id == _tid)
    result = await db.execute(_stmt)
    r = result.scalar_one_or_none()
    if not r:
        return {"error": "ScheduledReport not found", "report_id": report_id}

    # Load hunt + findings
    hunt_result = await db.execute(select(Hunt).where(Hunt.id == r.hunt_id))
    hunt = hunt_result.scalar_one_or_none()

    findings_result = await db.execute(select(HuntFinding).where(HuntFinding.hunt_id == r.hunt_id))
    findings = findings_result.scalars().all()

    # Load PIDS identity timeline
    identity_timeline = await get_identity_timeline(db, r.hunt_id)

    now_ts = datetime.now(UTC).isoformat()
    summary = {
        "hunt_id": r.hunt_id,
        "hunt_name": hunt.name if hunt else r.hunt_name,
        "hunt_status": hunt.status if hunt else "unknown",
        "hunt_priority": hunt.priority if hunt else "unknown",
        "total_findings": len(findings),
        "confirmed": sum(1 for f in findings if f.is_confirmed),
        "false_positives": sum(1 for f in findings if f.is_false_positive),
        "critical_findings": sum(1 for f in findings if f.severity == "critical"),
        "high_findings": sum(1 for f in findings if f.severity == "high"),
        "report_format": r.format,
        "generated_at": now_ts,
        # P26 PIDS
        "identity_timeline": identity_timeline,
        "identity_action_count": len(identity_timeline),
        "identity_actions_successful": sum(1 for a in identity_timeline if a.get("success")),
    }

    # P26: forensic signing of the full report payload
    canonical_payload = json.dumps(
        {"report_id": report_id, "report": summary},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    forensic_hash = hashlib.sha3_512(canonical_payload).hexdigest()
    forensic_signature = _sign_hash(forensic_hash)

    error = None
    try:
        await _send_report(r.recipient_email, summary, format=r.format)
    except Exception as exc:
        error = str(exc)
        log.warning("scheduled_report_send_error", report_id=report_id, error=error)

    r.last_sent_at = datetime.now(UTC)
    r.send_count = (r.send_count or 0) + 1
    r.last_error = error
    await db.commit()

    log_security_action(
        "scheduled_report_delivered",
        user_id="celery",
        role="system",
        resource="scheduled_report",
        resource_id=report_id,
        detail=(
            f"Delivered to {r.recipient_email} (send_count={r.send_count}). "
            f"identity_actions={len(identity_timeline)}. "
            f"forensic_hash_prefix={forensic_hash[:16]}. error={error}"
        ),
        status="ok" if not error else "error",
    )
    return {
        "report_id": report_id,
        "summary": summary,
        "forensic_hash": forensic_hash,
        "forensic_signature": forensic_signature,
        "error": error,
    }


async def _send_report(recipient_email: str, summary: dict, *, format: str) -> None:
    """
    Deliver a scheduled report via Resend when RESEND_API_KEY is set.
    Falls back to log-only when the key is absent (dev / self-hosted).
    Raises RuntimeError on Resend API failure so the caller can record it.
    """
    from asc_api.core.config import get_settings

    _cfg = get_settings()
    api_key = _cfg.RESEND_API_KEY

    if not api_key:
        log.info(
            "scheduled_report_send_skipped",
            reason="no_resend_api_key",
            recipient=recipient_email,
            hunt_id=summary.get("hunt_id"),
            format=format,
            total_findings=summary.get("total_findings"),
        )
        return

    hunt_name = summary.get("hunt_name", "Unknown Hunt")
    total = summary.get("total_findings", 0)
    confirmed = summary.get("confirmed", 0)
    critical = summary.get("critical_findings", 0)
    high = summary.get("high_findings", 0)
    fp = summary.get("false_positives", 0)
    ia_count = summary.get("identity_action_count", 0)
    ia_ok = summary.get("identity_actions_successful", 0)
    gen_at = summary.get("generated_at", "")

    text_body = (
        f"ASC PremosCorp — Scheduled Report\n\n"
        f"Hunt:     {hunt_name}\n"
        f"Status:   {summary.get('hunt_status', 'unknown')}\n"
        f"Priority: {summary.get('hunt_priority', 'unknown')}\n"
        f"Generated: {gen_at}\n\n"
        f"Findings Summary\n"
        f"  Total:            {total}\n"
        f"  Confirmed:        {confirmed}\n"
        f"  Critical:         {critical}\n"
        f"  High:             {high}\n"
        f"  False positives:  {fp}\n\n"
        f"Identity Actions: {ia_count} ({ia_ok} successful)\n"
        f"Report format: {format}\n"
    )

    html_body = (
        "<div style='font-family:sans-serif;color:#1a1a2e;max-width:600px'>"
        "<h2 style='color:#0d1b2a'>ASC PremosCorp — Scheduled Report</h2>"
        f"<p><strong>Hunt:</strong> {hunt_name}</p>"
        f"<p><strong>Status:</strong> {summary.get('hunt_status', 'unknown')} &nbsp;|&nbsp; "
        f"<strong>Priority:</strong> {summary.get('hunt_priority', 'unknown')}</p>"
        f"<p><strong>Generated:</strong> {gen_at}</p>"
        "<h3>Findings Summary</h3>"
        "<table border='1' cellpadding='8' cellspacing='0' style='border-collapse:collapse'>"
        "<tr style='background:#f0f4f8'><th>Metric</th><th>Count</th></tr>"
        f"<tr><td>Total</td><td>{total}</td></tr>"
        f"<tr><td>Confirmed</td><td>{confirmed}</td></tr>"
        f"<tr><td>Critical</td><td>{critical}</td></tr>"
        f"<tr><td>High</td><td>{high}</td></tr>"
        f"<tr><td>False Positives</td><td>{fp}</td></tr>"
        "</table>"
        f"<p><strong>Identity Actions:</strong> {ia_count} ({ia_ok} successful)</p>"
        f"<p><em>Report format: {format}</em></p>"
        "<hr style='border:none;border-top:1px solid #e0e0e0;margin:24px 0'>"
        "<p style='color:#888;font-size:12px'>ASC PremosCorp · Calidad sobre Comodidad</p>"
        "</div>"
    )

    import httpx

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "from": _cfg.RESEND_FROM_EMAIL,
                "to": [recipient_email],
                "subject": f"[ASC] Hunt Report: {hunt_name} — {total} findings",
                "text": text_body,
                "html": html_body,
            },
        )

    if resp.status_code not in (200, 201):
        raise RuntimeError(f"Resend error {resp.status_code}: {resp.text[:200]}")

    log.info(
        "scheduled_report_sent",
        recipient=recipient_email,
        hunt_id=summary.get("hunt_id"),
        format=format,
        total_findings=total,
        resend_id=resp.json().get("id"),
    )


def _report_to_dict(r) -> dict:
    return {
        "id": r.id,
        "hunt_id": r.hunt_id,
        "hunt_name": r.hunt_name,
        "recipient_email": r.recipient_email,
        "frequency": r.frequency,
        "format": r.format,
        "enabled": r.enabled,
        "last_sent_at": r.last_sent_at.isoformat() if r.last_sent_at else None,
        "send_count": r.send_count,
        "last_error": r.last_error,
        "created_by": r.created_by,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }
