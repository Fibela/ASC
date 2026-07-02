"""
PIDS Endpoints — P26

REST API for Premos Identity-Driven SOAR (PIDS).

Endpoints:
  GET    /pids/actions                  List identity actions (filterable)
  GET    /pids/actions/{action_id}      Single identity action + forensic token
  POST   /pids/actions/{action_id}/verify  Re-verify the forensic hash and signature
  GET    /pids/timeline/{hunt_id}       Chronological identity timeline for a hunt
  GET    /pids/summary                  Global or hunt-scoped PIDS statistics
  GET    /pids/summary/{hunt_id}        Hunt-scoped PIDS statistics
  POST   /pids/actions                  Manually create an identity action

Security: all endpoints require analyst or admin role.
Rate-limiting: writes 10/min, reads 60/min.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.api.deps import get_analyst_or_admin
from asc_api.core.rate_limit import limiter
from asc_api.core.logging import get_logger
from asc_api.db.session import get_db
from asc_api.models.user import User
from asc_api.services import pids_service

log = get_logger(__name__)
router = APIRouter(prefix="/pids", tags=["PIDS"])

# ── Request schemas ────────────────────────────────────────────────────────────

class CreateIdentityActionRequest(BaseModel):
    action_type: str = Field(
        ...,
        description="disable_account | enable_account | force_password_reset | quarantine_account | enrich_user",
    )
    username: str = Field(..., min_length=1, max_length=256)
    domain: str = Field("corp.local", max_length=256)
    reason: str = Field(..., min_length=1, max_length=1000)
    hunt_id: str | None = Field(None, description="Link to a hunt UUID")
    finding_id: str | None = Field(None, description="Link to a finding UUID")
    trigger_id: str | None = Field(None, description="Link to a SOAR trigger UUID")
    playbook_run_id: str | None = Field(None, description="Link to a playbook run UUID")
    success: bool = Field(False)
    result_detail: str | None = Field(None, max_length=2000)


# ── Endpoints ──────────────────────────────────────────────────────────────────

@router.get("/actions", summary="List identity actions")
@limiter.limit("60/minute")
async def list_actions(
    request: Request,
    username: str | None = Query(None, description="Filter by AD username"),
    action_type: str | None = Query(None, description="Filter by action type"),
    hunt_id: str | None = Query(None, description="Filter by hunt UUID"),
    success: bool | None = Query(None, description="Filter by success status"),
    limit: int = Query(100, ge=1, le=500),
    current_user: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    actions = await pids_service.list_identity_actions(
        db,
        username=username,
        action_type=action_type,
        hunt_id=hunt_id,
        success=success,
        limit=limit,
    )
    return {"count": len(actions), "actions": actions}


@router.post("/actions", status_code=status.HTTP_201_CREATED, summary="Manually create an identity action")
@limiter.limit("10/minute")
async def create_action(
    request: Request,
    body: CreateIdentityActionRequest,
    current_user: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    try:
        action = await pids_service.create_identity_action(
            db,
            action_type=body.action_type,
            username=body.username,
            domain=body.domain,
            reason=body.reason,
            hunt_id=body.hunt_id,
            finding_id=body.finding_id,
            trigger_id=body.trigger_id,
            playbook_run_id=body.playbook_run_id,
            success=body.success,
            result_detail=body.result_detail,
            initiated_by=current_user.email,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
    return pids_service._action_to_dict(action)


@router.get("/actions/{action_id}", summary="Get a single identity action with forensic token")
@limiter.limit("60/minute")
async def get_action(
    request: Request,
    action_id: str,
    current_user: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    action = await pids_service.get_identity_action(db, action_id)
    if not action:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Identity action not found")
    return action


@router.post(
    "/actions/{action_id}/verify",
    summary="Re-verify the forensic hash and Ed25519 signature of an identity action",
)
@limiter.limit("20/minute")
async def verify_action(
    request: Request,
    action_id: str,
    current_user: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    result = await pids_service.verify_identity_action(db, action_id)
    if result.get("error") == "IdentityAction not found":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Identity action not found")
    return result


@router.get("/timeline/{hunt_id}", summary="Chronological identity action timeline for a hunt")
@limiter.limit("60/minute")
async def identity_timeline(
    request: Request,
    hunt_id: str,
    current_user: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    timeline = await pids_service.get_identity_timeline(db, hunt_id)
    return {
        "hunt_id": hunt_id,
        "count": len(timeline),
        "timeline": timeline,
    }


@router.get("/summary", summary="Global PIDS statistics")
@limiter.limit("60/minute")
async def pids_summary_global(
    request: Request,
    current_user: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    return await pids_service.get_pids_summary(db, hunt_id=None)


@router.get("/summary/{hunt_id}", summary="PIDS statistics scoped to a hunt")
@limiter.limit("60/minute")
async def pids_summary_hunt(
    request: Request,
    hunt_id: str,
    current_user: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    return await pids_service.get_pids_summary(db, hunt_id=hunt_id)
