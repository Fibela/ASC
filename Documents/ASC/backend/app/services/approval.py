"""
Human-in-the-Loop Approval Service — P16 + PANL

State machine:
  pending_approval → (partial_approval if multi-sig) → approved → executing → completed | failed
                   → rejected     (any analyst, any time while pending)
                   → escalated    (timeout expired without decision)

PANL integrations (P16 pre-P16.3):
  - Behavioral throttle: blocks suspicious action sprees before creating the action
  - Adaptive severity: upgrades severity based on real-time threat context
  - Multi-signature: CRITICAL → 2 distinct analyst approvals; HIGH → 1
  - Dynamic rollback: create_rollback_action() reverses destructive completed actions
  - Push notifications: every state change publishes an SSE event via notification_bus

Security invariants:
  - approved_by != initiated_by  (self-approval forbidden, HTTP 403)
  - No duplicate approvals: same analyst cannot sign twice on the same action
  - Only CRITICAL/HIGH severity + always-require types trigger approval gate
  - Escalation is lazy: triggered on list/get; no Celery needed
  - rollback_available is set automatically on successful execution of reversible actions
  - Double rollback prevented: rollback_of chain is one level deep
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import log_security_action
from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.notifications import notification_bus
from app.core.signing import (
    decrypt_analyst_private_key,
    sign_approval,
)
from app.core.panl import (
    AdaptiveContext,
    adapt_severity,
    check_behavioral_throttle,
    required_approvals_for,
)
from app.models.neutralization import NeutralizationAction
from app.models.user import User
from app.services.neutralizer import execute_action
from app.services.pfn import create_forensic_entry
from app.services.specter_bridge import dispatch as specter_dispatch

log = get_logger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

TIMEOUT_BY_SEVERITY: dict[str, int] = {
    "critical": 15,
    "high":     30,
    "medium":   60,
    "low":      120,
}

# These action types always require human approval regardless of severity
ALWAYS_REQUIRE_APPROVAL: frozenset[str] = frozenset({
    "isolate_endpoint",
    "disable_account",
})

# Severities that route through the approval gate
APPROVAL_SEVERITIES: frozenset[str] = frozenset({"critical", "high"})

# Actions whose effects can be reversed by PANL dynamic rollback
REVERSIBLE_ACTIONS: frozenset[str] = frozenset({
    "isolate_endpoint",
    "block_ip",
    "block_domain",
    "quarantine_file",
})

# Maps each reversible action_type → its inverse action_type
ROLLBACK_MAP: dict[str, str] = {
    "isolate_endpoint": "unisolate_endpoint",
    "block_ip":         "unblock_ip",
    "block_domain":     "unblock_domain",
    "quarantine_file":  "restore_file",
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def needs_approval(action_type: str, severity: str) -> bool:
    """Return True if this action/severity combination must pass through HitL."""
    return action_type in ALWAYS_REQUIRE_APPROVAL or severity.lower() in APPROVAL_SEVERITIES


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _expires_at(severity: str) -> datetime:
    minutes = TIMEOUT_BY_SEVERITY.get(severity.lower(), 30)
    return _now() + timedelta(minutes=minutes)


# ── Core state machine ────────────────────────────────────────────────────────

async def request_action(
    db: AsyncSession,
    *,
    action_type: str,
    target: str,
    target_type: str,
    params: dict[str, Any],
    severity: str,
    initiated_by: str,
    alert_id: str | None = None,
    automated: bool = False,
    adaptive_context: AdaptiveContext | None = None,
) -> NeutralizationAction:
    """
    Create a NeutralizationAction and route it through the PANL gate.

    PANL pipeline (in order):
      1. BehavioralThrottle — block if same user is spamming the same action_type
      2. AdaptiveSeverity   — upgrade severity based on threat context
      3. MultiSigPolicy     — set required_approvals (1 or 2)
      4. HitL gate          — pending_approval if requires, else execute immediately
      5. Notification       — publish pending_approval_created event to SSE bus
    """
    import uuid

    # 1. Behavioral throttle (skipped for automated/system actions)
    if not automated:
        check_behavioral_throttle(initiated_by, action_type)

    # 2. Adaptive severity
    context = adaptive_context or AdaptiveContext()
    original_severity = severity
    severity = adapt_severity(severity, context)
    severity_adapted = severity != original_severity

    # 3. Multi-sig policy
    requires = needs_approval(action_type, severity)
    timeout_min = TIMEOUT_BY_SEVERITY.get(severity.lower(), 30)
    req_approvals = required_approvals_for(severity, action_type) if requires else 0

    action = NeutralizationAction(
        id=str(uuid.uuid4()),
        alert_id=alert_id,
        action_type=action_type,
        severity=severity,
        original_severity=original_severity if severity_adapted else None,
        severity_adapted=severity_adapted,
        target=target,
        target_type=target_type,
        params=params,
        automated=automated,
        initiated_by=initiated_by,
        approval_required=requires,
        timeout_minutes=timeout_min,
        expires_at=_expires_at(severity) if requires else None,
        status="pending_approval" if requires else "executing",
        required_approvals=req_approvals,
        approvals_log=[],
        rollback_available=False,
    )
    db.add(action)
    await db.commit()
    await db.refresh(action)

    log_security_action(
        "neutralize_request",
        user_id=initiated_by,
        role="system",
        resource="neutralization",
        resource_id=action.id,
        detail=(
            f"action_type={action_type} target={target} "
            f"severity={severity} approval_required={requires} "
            f"required_approvals={req_approvals} severity_adapted={severity_adapted}"
        ),
        status="pending" if requires else "auto_execute",
    )

    # 5. SSE notification
    if requires:
        asyncio.ensure_future(
            notification_bus.publish(
                "pending_approval_created",
                {
                    "action_id":    action.id,
                    "action_type":  action_type,
                    "severity":     severity,
                    "target":       target,
                    "initiated_by": initiated_by,
                    "expires_at":   action.expires_at.isoformat() if action.expires_at else None,
                    "required_approvals": req_approvals,
                },
            )
        )
    else:
        action = await _execute_immediately(db, action)

    return action


async def approve_action(
    db: AsyncSession,
    *,
    action_id: str,
    approved_by: str,
) -> NeutralizationAction:
    """
    Record an analyst's approval signature.

    - Self-approval and duplicate-approver are rejected.
    - For CRITICAL actions (required_approvals=2): first approval stays pending,
      second approval triggers execution (PANL multi-signature).
    - For HIGH/other (required_approvals=1): immediate execution.

    Returns the action in its updated state.  If multi-sig is still incomplete
    the state remains 'pending_approval' with approvals_log populated.
    """
    action = await _get_or_raise(db, action_id)

    if action.status != "pending_approval":
        raise ValueError(f"Cannot approve action in state '{action.status}'")

    # Self-approval guard
    if action.initiated_by == approved_by:
        raise ValueError("Self-approval is forbidden: approved_by must differ from initiated_by")

    # Duplicate-approver guard (PANL multi-sig)
    existing_approvers = {a["approved_by"] for a in (action.approvals_log or [])}
    if approved_by in existing_approvers:
        raise ValueError(
            f"Analyst {approved_by!r} has already signed this action. "
            "Multi-signature requires two *distinct* analysts."
        )

    _check_not_expired(action)

    # Record this approval — attempt cryptographic signing with analyst's private key
    now = _now()
    approved_at_iso = now.isoformat()
    log_entry: dict = {"approved_by": approved_by, "approved_at": approved_at_iso}

    try:
        settings = get_settings()
        analyst_result = await db.execute(select(User).where(User.email == approved_by))
        analyst = analyst_result.scalar_one_or_none()
        if analyst and analyst.signing_private_key_enc and analyst.signing_public_key:
            priv_b64 = decrypt_analyst_private_key(
                analyst.signing_private_key_enc, settings.SECRET_KEY
            )
            log_entry["signature"] = sign_approval(
                priv_b64, action_id, approved_by, approved_at_iso
            )
            log_entry["public_key"] = analyst.signing_public_key
    except Exception as exc:
        # Signing failure is non-fatal — audit trail degrades gracefully.
        # The approval is still recorded; the signature field is absent.
        log.warning("approval_signing_failed", analyst=approved_by, error=str(exc))

    action.approvals_log = list(action.approvals_log or []) + [log_entry]

    required = getattr(action, "required_approvals", 1) or 1
    approvals_received = len(action.approvals_log)

    if approvals_received >= required:
        # ── Full approval achieved — execute ──────────────────────────────────
        action.approved_by = approved_by
        action.approved_at = now
        action.status = "approved"
        await db.commit()
        await db.refresh(action)

        log_security_action(
            "neutralize_approve",
            user_id=approved_by,
            role="system",
            resource="neutralization",
            resource_id=action.id,
            detail=(
                f"action_type={action.action_type} target={action.target} "
                f"approvals={approvals_received}/{required} — executing"
            ),
            status="ok",
        )

        asyncio.ensure_future(
            notification_bus.publish(
                "action_approved",
                {
                    "action_id":   action.id,
                    "action_type": action.action_type,
                    "approved_by": approved_by,
                    "approvals":   approvals_received,
                    "required":    required,
                },
            )
        )

        action = await _execute_immediately(db, action)

    else:
        # ── Partial approval — stay pending, await more signatures ────────────
        await db.commit()
        await db.refresh(action)

        log_security_action(
            "neutralize_partial_approve",
            user_id=approved_by,
            role="system",
            resource="neutralization",
            resource_id=action.id,
            detail=(
                f"action_type={action.action_type} "
                f"approvals={approvals_received}/{required} — awaiting more signatures"
            ),
            status="partial",
        )

        asyncio.ensure_future(
            notification_bus.publish(
                "action_partial_approved",
                {
                    "action_id":   action.id,
                    "action_type": action.action_type,
                    "approved_by": approved_by,
                    "approvals":   approvals_received,
                    "required":    required,
                    "note": (
                        f"CRITICAL action requires {required} signatures. "
                        f"{required - approvals_received} more needed."
                    ),
                },
            )
        )

    return action


async def reject_action(
    db: AsyncSession,
    *,
    action_id: str,
    rejected_by: str,
    reason: str,
) -> NeutralizationAction:
    """
    Reject a pending_approval action with a mandatory written reason.

    Any analyst can reject — including those who already partially approved.
    Rejection is immediate and irreversible (no rollback of a rejection).
    """
    action = await _get_or_raise(db, action_id)

    if action.status != "pending_approval":
        raise ValueError(f"Cannot reject action in state '{action.status}'")

    if not reason or not reason.strip():
        raise ValueError("rejection_reason is required")

    action.rejected_by = rejected_by
    action.rejected_at = _now()
    action.rejection_reason = reason.strip()
    action.status = "rejected"
    await db.commit()
    await db.refresh(action)

    log_security_action(
        "neutralize_reject",
        user_id=rejected_by,
        role="system",
        resource="neutralization",
        resource_id=action.id,
        detail=f"reason={reason[:120]}",
        status="ok",
    )

    asyncio.ensure_future(
        notification_bus.publish(
            "action_rejected",
            {
                "action_id":   action.id,
                "action_type": action.action_type,
                "rejected_by": rejected_by,
                "reason":      reason.strip()[:200],
            },
        )
    )

    return action


async def escalate_expired(db: AsyncSession) -> list[str]:
    """
    Lazy escalation: find all pending_approval actions past their expires_at
    and mark them escalated.  Returns list of escalated action IDs.
    Called automatically on list/get; no Celery needed.
    """
    now = _now()
    result = await db.execute(
        select(NeutralizationAction).where(
            NeutralizationAction.status == "pending_approval",
            NeutralizationAction.expires_at <= now,
        )
    )
    expired = result.scalars().all()
    escalated_ids: list[str] = []

    for action in expired:
        action.status = "escalated"
        action.escalated_at = now
        action.escalation_reason = (
            f"No decision within {action.timeout_minutes} minutes — auto-escalated"
        )
        escalated_ids.append(action.id)
        log_security_action(
            "neutralize_escalate",
            user_id="system",
            role="system",
            resource="neutralization",
            resource_id=action.id,
            detail=f"timeout={action.timeout_minutes}min action_type={action.action_type}",
            status="escalated",
        )
        asyncio.ensure_future(
            notification_bus.publish(
                "action_escalated",
                {
                    "action_id":    action.id,
                    "action_type":  action.action_type,
                    "timeout_min":  action.timeout_minutes,
                    "initiated_by": action.initiated_by,
                },
            )
        )

    if escalated_ids:
        await db.commit()

    return escalated_ids


async def get_pending(db: AsyncSession) -> list[NeutralizationAction]:
    """Return all currently pending_approval actions (after escalating expired ones)."""
    await escalate_expired(db)
    result = await db.execute(
        select(NeutralizationAction)
        .where(NeutralizationAction.status == "pending_approval")
        .order_by(NeutralizationAction.created_at)
    )
    return list(result.scalars().all())


# ── Rollback ──────────────────────────────────────────────────────────────────

async def create_rollback_action(
    db: AsyncSession,
    *,
    original_action_id: str,
    initiated_by: str,
) -> NeutralizationAction:
    """
    PANL Dynamic Rollback — reverse a completed destructive action.

    Creates a new NeutralizationAction of the inverse type.  The rollback
    goes through the normal HitL gate so destructive reversals (e.g. unisolate
    of a compromised endpoint) still require approval.

    Forensic links maintained:
      rollback_action.rollback_of   = original_action.id
      original_action.rollback_action_id = rollback_action.id

    Guards:
      - original must be "completed" with rollback_available=True
      - action_type must be in ROLLBACK_MAP
      - double rollback is prevented (rollback_action_id already set)
      - cannot rollback a rollback (is_rollback=True chain guard)
    """
    original = await _get_or_raise(db, original_action_id)

    if original.status != "completed":
        raise ValueError(
            f"Cannot rollback action in state '{original.status}' — must be 'completed'"
        )
    if not original.rollback_available:
        raise ValueError(
            f"Action {original_action_id!r} is not marked rollback_available. "
            "Only successfully executed reversible actions support rollback."
        )
    if getattr(original, "is_rollback", False):
        raise ValueError("Cannot rollback a rollback — chain limited to one level.")
    if original.rollback_action_id:
        raise ValueError(
            f"A rollback for action {original_action_id!r} already exists: "
            f"{original.rollback_action_id}"
        )
    if original.action_type not in ROLLBACK_MAP:
        raise ValueError(
            f"Action type '{original.action_type}' is not reversible. "
            f"Reversible types: {sorted(ROLLBACK_MAP)}"
        )

    inverse_type = ROLLBACK_MAP[original.action_type]

    # Rollback uses same params as original (the inverse command will interpret them)
    rollback = await request_action(
        db,
        action_type=inverse_type,
        target=original.target,
        target_type=original.target_type,
        params=original.params,
        severity=original.severity,  # same severity gate as original
        initiated_by=initiated_by,
        alert_id=original.alert_id,
        automated=False,  # forensic rollback always has a human owner
    )

    # Stamp forensic links (db.refresh already populated rollback from request_action)
    rollback.is_rollback = True
    rollback.rollback_of = original.id
    original.rollback_action_id = rollback.id
    original.rollback_available = False  # prevent double-rollback

    await db.commit()
    await db.refresh(rollback)

    log_security_action(
        "neutralize_rollback_requested",
        user_id=initiated_by,
        role="system",
        resource="neutralization",
        resource_id=rollback.id,
        detail=(
            f"rollback_of={original.id} original_action_type={original.action_type} "
            f"inverse_action_type={inverse_type} target={original.target}"
        ),
        status="pending",
    )

    asyncio.ensure_future(
        notification_bus.publish(
            "rollback_requested",
            {
                "rollback_action_id":   rollback.id,
                "original_action_id":   original.id,
                "original_action_type": original.action_type,
                "inverse_action_type":  inverse_type,
                "target":               original.target,
                "initiated_by":         initiated_by,
            },
        )
    )

    return rollback


# ── Internal helpers ──────────────────────────────────────────────────────────

async def _get_or_raise(db: AsyncSession, action_id: str) -> NeutralizationAction:
    result = await db.execute(
        select(NeutralizationAction).where(NeutralizationAction.id == action_id)
    )
    action = result.scalar_one_or_none()
    if not action:
        raise ValueError(f"NeutralizationAction {action_id!r} not found")
    return action


def _check_not_expired(action: NeutralizationAction) -> None:
    if action.expires_at and _now() > action.expires_at:
        raise ValueError(
            f"Action {action.id} has expired (expires_at={action.expires_at.isoformat()})"
        )


async def _execute_immediately(
    db: AsyncSession, action: NeutralizationAction
) -> NeutralizationAction:
    """
    Execute via the SPECTER bridge (P16.2).

    Priority:
      1. specter_bridge.dispatch() — routes to SPECTER agent or broadcast.
      2. If the bridge raises unexpectedly, falls back to neutralizer.py simulation.

    Post-execution:
      - Sets rollback_available=True for reversible actions on success.
      - Publishes action_completed / action_failed SSE event.
    """
    action.status = "executing"
    await db.commit()

    issued_by = action.approved_by or action.initiated_by or "system"

    try:
        result = await specter_dispatch(
            db,
            action_type=action.action_type,
            target=action.target,
            target_type=action.target_type,
            params=action.params,
            issued_by=issued_by,
        )
    except Exception as bridge_exc:
        log.error("specter_bridge_exception", error=str(bridge_exc), action_id=action.id)
        result = await execute_action(action.action_type, action.params)

    action.status = "completed" if result.success else "failed"
    action.result = result.details
    action.error_message = None if result.success else result.message
    action.executed_at = _now()

    # PANL: mark reversible actions available for dynamic rollback
    if (
        result.success
        and action.action_type in REVERSIBLE_ACTIONS
        and not getattr(action, "is_rollback", False)
    ):
        action.rollback_available = True

    await db.commit()
    await db.refresh(action)

    # PFN — generate forensic ledger entry for every successful execution.
    # Wrapped in try/except so a PFN failure never aborts the neutralization result.
    if result.success and action.approved_by:
        try:
            approver_result = await db.execute(
                select(User).where(User.email == action.approved_by)
            )
            approver = approver_result.scalar_one_or_none()
            if approver and isinstance(approver, User):
                await create_forensic_entry(db, action, approver)
        except Exception as pfn_exc:
            log.warning("pfn_hook_error", action_id=action.id, error=str(pfn_exc))

    log_security_action(
        "neutralize_execute",
        user_id=issued_by,
        role="system",
        resource="neutralization",
        resource_id=action.id,
        detail=(
            f"action_type={action.action_type} "
            f"dispatch_mode={result.details.get('dispatch_mode', 'unknown')} "
            f"success={result.success} rollback_available={action.rollback_available}"
        ),
        status="ok" if result.success else "error",
    )

    asyncio.ensure_future(
        notification_bus.publish(
            "action_completed" if result.success else "action_failed",
            {
                "action_id":          action.id,
                "action_type":        action.action_type,
                "status":             action.status,
                "rollback_available": action.rollback_available,
                "dispatch_mode":      result.details.get("dispatch_mode", "unknown"),
            },
        )
    )

    return action
