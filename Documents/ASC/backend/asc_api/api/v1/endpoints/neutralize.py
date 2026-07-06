"""
Neutralization API â€” P16 + PANL

Security layers applied at the endpoint level:
  RequestRateLimit    â€” max 20 POST /neutralize/ per user per minute (PANL)
  BehavioralThrottle  â€” max 10 same-action_type per user per minute (in approval.py)
  HitL gate           â€” CRITICAL/HIGH â†’ pending_approval (in approval.py)
  Multi-signature     â€” CRITICAL â†’ 2 distinct analyst approvals (in approval.py)
  Self-approval block â€” 403 Forbidden if approved_by == initiated_by
  Rollback guard      â€” only completed, rollback_available actions can be reversed
"""
from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from asc_api.models.agent import AgentCommand

from asc_api.db.session import get_db
from asc_api.models.neutralization import NeutralizationAction
from asc_api.models.user import User
from asc_api.services.neutralizer import RECOMMENDED_ACTIONS
from asc_api.services.approval import (
    request_action,
    approve_action,
    reject_action,
    get_pending,
    escalate_expired,
    create_rollback_action,
)
from asc_api.api.deps import get_analyst_or_admin, get_current_admin
from asc_api.core.audit import log_security_action
from asc_api.core.panl import request_rate_limiter
from pydantic import BaseModel, field_validator

router = APIRouter(prefix="/neutralize", tags=["Neutralization"])

# â”€â”€ Per-user request rate limiter (PANL) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


async def _rate_limited_user(
    current_user: User = Depends(get_analyst_or_admin),
) -> User:
    """Dependency: enforce max 20 POST /neutralize/ per user per minute."""
    if not request_rate_limiter.is_allowed(current_user.email):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Rate limit exceeded: max {request_rate_limiter.MAX_REQUESTS} "
                f"neutralize requests per {request_rate_limiter.WINDOW_SECONDS}s. "
                "Slow down or contact your supervisor."
            ),
        )
    return current_user


# â”€â”€ Request schemas â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class NeutralizeRequest(BaseModel):
    action_type: str
    target: str
    target_type: str
    severity: str = "high"
    params: dict = {}
    alert_id: str | None = None
    automated: bool = False
    # PANL adaptive context â€” optional; set by alert automation or analyst override
    adaptive_context: dict = {}

    @field_validator("severity")
    @classmethod
    def valid_severity(cls, v: str) -> str:
        allowed = {"critical", "high", "medium", "low"}
        if v.lower() not in allowed:
            raise ValueError(f"severity must be one of {sorted(allowed)}")
        return v.lower()

    @field_validator("action_type")
    @classmethod
    def valid_action_type(cls, v: str) -> str:
        allowed = {
            "isolate_endpoint", "block_ip", "block_domain",
            "kill_process", "quarantine_file", "remove_persistence", "disable_account",
        }
        if v not in allowed:
            raise ValueError(f"action_type must be one of {sorted(allowed)}")
        return v


class ApproveRequest(BaseModel):
    pass  # approved_by comes from JWT


class RejectRequest(BaseModel):
    reason: str

    @field_validator("reason")
    @classmethod
    def reason_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("reason must not be empty")
        return v.strip()


# â”€â”€ Serialization helper â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _serialize(a: NeutralizationAction) -> dict:
    return {
        "id":                  a.id,
        "action_type":         a.action_type,
        "severity":            a.severity,
        "original_severity":   getattr(a, "original_severity", None),
        "severity_adapted":    getattr(a, "severity_adapted", False),
        "target":              a.target,
        "target_type":         a.target_type,
        "status":              a.status,
        "automated":           a.automated,
        "alert_id":            a.alert_id,
        "initiated_by":        a.initiated_by,
        "approval_required":   a.approval_required,
        "required_approvals":  getattr(a, "required_approvals", 1),
        "approvals_received":  len(getattr(a, "approvals_log", None) or []),
        "approvals_log":       getattr(a, "approvals_log", []) or [],
        "timeout_minutes":     a.timeout_minutes,
        "expires_at":          a.expires_at.isoformat() if a.expires_at else None,
        "approved_by":         a.approved_by,
        "approved_at":         a.approved_at.isoformat() if a.approved_at else None,
        "rejected_by":         a.rejected_by,
        "rejected_at":         a.rejected_at.isoformat() if a.rejected_at else None,
        "rejection_reason":    a.rejection_reason,
        "escalated_at":        a.escalated_at.isoformat() if a.escalated_at else None,
        "escalation_reason":   a.escalation_reason,
        "result":              a.result,
        "error_message":       a.error_message,
        "rollback_available":  a.rollback_available,
        "is_rollback":         getattr(a, "is_rollback", False),
        "rollback_of":         getattr(a, "rollback_of", None),
        "rollback_action_id":  getattr(a, "rollback_action_id", None),
        "created_at":          a.created_at.isoformat(),
        "executed_at":         a.executed_at.isoformat() if a.executed_at else None,
    }


# â”€â”€ Endpoints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@router.post("", summary="Request a neutralization action (PANL + HitL gate)")
async def neutralize(
    payload: NeutralizeRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(_rate_limited_user),
):
    """
    Submit a neutralization action through the PANL pipeline:
    1. Rate limit check (20 req/min per user)
    2. Behavioral throttle (10 same-action-type/min per user)
    3. Adaptive severity upgrade (context-aware)
    4. HitL gate: CRITICAL/HIGH â†’ pending_approval; MEDIUM/LOW â†’ execute
    5. Multi-signature: CRITICAL requires 2 distinct analyst approvals
    6. SSE notification published to connected analyst browsers
    """
    from asc_api.core.panl import AdaptiveContext
    try:
        ctx = AdaptiveContext.from_dict(payload.adaptive_context) if payload.adaptive_context else None
        action = await request_action(
            db,
            action_type=payload.action_type,
            target=payload.target,
            target_type=payload.target_type,
            params=payload.params,
            severity=payload.severity,
            initiated_by=current_user.email,
            alert_id=payload.alert_id,
            automated=payload.automated,
            adaptive_context=ctx,
        )
    except ValueError as e:
        msg = str(e)
        if "throttle" in msg.lower() or "too many" in msg.lower():
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=msg)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)

    return _serialize(action)


@router.get("/pending", summary="List actions awaiting approval (auto-escalates expired)")
async def list_pending(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
):
    """Returns all pending_approval actions. Expired ones are escalated first."""
    actions = await get_pending(db)
    return {"total": len(actions), "actions": [_serialize(a) for a in actions]}


@router.post("/{action_id}/approve", summary="Approve a pending neutralization action")
async def approve(
    action_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
):
    """
    Record this analyst's approval signature.
    - Self-approval â†’ 403 Forbidden
    - Duplicate approval by same analyst â†’ 400
    - Expired action â†’ 409 Conflict
    - CRITICAL (multi-sig): first approval stays pending, second triggers execution
    - HIGH/other: immediate execution on approval
    """
    tenant_check = await db.execute(
        select(NeutralizationAction).where(
            NeutralizationAction.id == action_id,
            NeutralizationAction.tenant_id == current_user.tenant_id,
        )
    )
    if not tenant_check.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Action not found")
    try:
        action = await approve_action(db, action_id=action_id, approved_by=current_user.email)
    except ValueError as e:
        msg = str(e)
        if "Self-approval" in msg:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=msg)
        if "expired" in msg:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=msg)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)

    return _serialize(action)


@router.post("/{action_id}/reject", summary="Reject a pending neutralization action")
async def reject(
    action_id: str,
    payload: RejectRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
):
    """Reject a pending_approval action with a mandatory written reason."""
    tenant_check = await db.execute(
        select(NeutralizationAction).where(
            NeutralizationAction.id == action_id,
            NeutralizationAction.tenant_id == current_user.tenant_id,
        )
    )
    if not tenant_check.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Action not found")
    try:
        action = await reject_action(
            db,
            action_id=action_id,
            rejected_by=current_user.email,
            reason=payload.reason,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    return _serialize(action)


@router.post("/{action_id}/rollback", summary="Request a PANL dynamic rollback of a completed action")
async def rollback(
    action_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
):
    """
    Initiate a forensic rollback for a completed, reversible action.

    Reversible types: isolate_endpoint, block_ip, block_domain, quarantine_file.
    The rollback itself goes through the HitL gate at the same severity level
    as the original action â€” CRITICAL rollbacks require dual-analyst sign-off.

    Forensic links:
      rollback_action.rollback_of   = original_action.id
      original_action.rollback_action_id = rollback_action.id
    """
    tenant_check = await db.execute(
        select(NeutralizationAction).where(
            NeutralizationAction.id == action_id,
            NeutralizationAction.tenant_id == current_user.tenant_id,
        )
    )
    if not tenant_check.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Action not found")
    try:
        rollback_action = await create_rollback_action(
            db,
            original_action_id=action_id,
            initiated_by=current_user.email,
        )
    except ValueError as e:
        msg = str(e)
        if "not found" in msg:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=msg)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)

    log_security_action(
        "neutralize_rollback_initiated",
        user_id=current_user.email,
        resource="neutralization",
        resource_id=rollback_action.id,
        detail=f"rollback_of={action_id}",
        status="pending",
    )

    return _serialize(rollback_action)


@router.get("/recommended/{severity}", summary="Get recommended actions for a threat severity")
async def recommended_actions(
    severity: str,
    current_user: User = Depends(get_analyst_or_admin),
):
    actions = RECOMMENDED_ACTIONS.get(severity.lower())
    if not actions:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown severity: {severity}. Use: critical, high, medium, low",
        )
    return {"severity": severity, "recommended_actions": actions}


@router.get("/history", summary="List past neutralization actions")
async def action_history(
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
):
    await escalate_expired(db)
    result = await db.execute(
        select(NeutralizationAction)
        .where(NeutralizationAction.tenant_id == current_user.tenant_id)
        .order_by(desc(NeutralizationAction.created_at))
        .limit(min(limit, 1000))
    )
    actions = result.scalars().all()
    return {"total": len(actions), "actions": [_serialize(a) for a in actions]}


# NOTE: /{action_id} is registered AFTER all literal paths (/pending, /history,
# /recommended/{severity}) so FastAPI never confuses a literal segment for an ID.
@router.get("/{action_id}", summary="Get a single neutralization action (auto-escalates if expired)")
async def get_action(
    action_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
):
    """Fetch one action by ID. Lazy-escalates it if it has expired."""
    await escalate_expired(db)
    result = await db.execute(
        select(NeutralizationAction).where(
            NeutralizationAction.id == action_id,
            NeutralizationAction.tenant_id == current_user.tenant_id,
        )
    )
    action = result.scalar_one_or_none()
    if not action:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Action not found")
    return _serialize(action)


@router.get("/{action_id}/commands", summary="List SPECTER commands issued for a neutralization action")
async def get_action_commands(
    action_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
):
    """
    Returns the AgentCommands queued to SPECTER agents as part of this action.
    Only populated when dispatch_mode is 'specter' or 'broadcast'.
    """
    action_result = await db.execute(
        select(NeutralizationAction).where(
            NeutralizationAction.id == action_id,
            NeutralizationAction.tenant_id == current_user.tenant_id,
        )
    )
    action = action_result.scalar_one_or_none()
    if not action:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Action not found")

    command_ids: list[str] = action.result.get("commands_issued", []) if action.result else []
    if not command_ids:
        return {
            "action_id":     action_id,
            "dispatch_mode": action.result.get("dispatch_mode", "simulation") if action.result else "simulation",
            "commands":      [],
        }

    cmd_result = await db.execute(
        select(AgentCommand).where(AgentCommand.id.in_(command_ids))
    )
    cmds = cmd_result.scalars().all()

    return {
        "action_id":     action_id,
        "dispatch_mode": action.result.get("dispatch_mode", "unknown") if action.result else "unknown",
        "commands": [
            {
                "id":           c.id,
                "agent_id":     c.agent_id,
                "command_type": c.command_type,
                "params":       c.params,
                "status":       c.status,
                "issued_by":    c.issued_by,
                "issued_at":    c.issued_at.isoformat(),
                "delivered_at": c.delivered_at.isoformat() if c.delivered_at else None,
                "completed_at": c.completed_at.isoformat() if c.completed_at else None,
                "result":       c.result,
                "error":        c.error,
            }
            for c in cmds
        ],
    }
