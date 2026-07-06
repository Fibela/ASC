"""
SOAR Endpoints — P25-S1

REST API for SOAR playbook trigger management and evaluation.

Endpoints:
  GET    /soar/triggers                     List all triggers (filterable)
  POST   /soar/triggers                     Create a new trigger
  GET    /soar/triggers/{trigger_id}        Single trigger detail
  DELETE /soar/triggers/{trigger_id}        Delete a trigger
  PATCH  /soar/triggers/{trigger_id}/toggle Enable or disable a trigger
  POST   /soar/triggers/{trigger_id}/test   Dry-run condition evaluation (no firing)
  POST   /soar/evaluate                     Evaluate a context dict against all triggers

Security: all endpoints require analyst or admin role.
Rate-limiting: creation/evaluation 10/minute, reads 60/minute.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.api.deps import get_analyst_or_admin
from asc_api.core.rate_limit import limiter
from asc_api.core.logging import get_logger
from asc_api.db.session import get_db
from asc_api.models.user import User
from asc_api.services import soar_service

log = get_logger(__name__)
router = APIRouter(prefix="/soar", tags=["SOAR"])

# ── Request schemas ────────────────────────────────────────────────────────────

class CreateTriggerRequest(BaseModel):
    playbook_id: str = Field(..., pattern=r"^PB-\d{3}$", description="e.g. PB-005")
    playbook_name: str = Field(..., min_length=1, max_length=256)
    condition_type: str = Field(
        ...,
        description="pcdi_score | finding_severity | hunt_priority | panl_status | identity_group | iam_event",
    )
    condition_operator: str = Field(
        ...,
        description="gte | lte | eq | contains",
    )
    condition_value: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="'80' for score, 'critical' for severity, 'Admins' for identity_group",
    )
    hunt_id_filter: str | None = Field(
        None,
        description="Restrict trigger to a specific hunt UUID. Omit to apply globally.",
    )
    # P26 adaptive orchestration
    priority: int = Field(
        5,
        ge=1,
        le=10,
        description="Evaluation priority 1-10 (10=highest). Higher-priority triggers fire first.",
    )
    rate_limit_per_hour: int = Field(
        10,
        ge=0,
        le=1000,
        description="Maximum fires per hour per trigger (0 = unlimited).",
    )
    dedup_window_minutes: int = Field(
        0,
        ge=0,
        le=1440,
        description="Skip if same playbook is awaiting_approval within this window (0 = no dedup).",
    )


class ToggleTriggerRequest(BaseModel):
    enabled: bool


class EvaluateContextRequest(BaseModel):
    context: dict = Field(
        ...,
        description=(
            "Evaluation context. Keys: pcdi_score (float), severity (str), "
            "hunt_priority (str), panl_status (str), hunt_id (str), "
            "affected_host (str), indicator_value (str), indicator_type (str)"
        ),
    )
    dry_run: bool = Field(
        True,
        description="If True, no playbooks are executed. Set False to actually fire matching triggers.",
    )


class TestTriggerRequest(BaseModel):
    context: dict = Field(..., description="Test context to evaluate against this single trigger.")


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/triggers", summary="List SOAR playbook triggers")
@limiter.limit("60/minute")
async def list_triggers(
    request: Request,
    playbook_id: str | None = Query(None, description="Filter by playbook ID"),
    condition_type: str | None = Query(None, description="Filter by condition type"),
    enabled_only: bool = Query(False, description="Return only enabled triggers"),
    current_user: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    triggers = await soar_service.list_triggers(
        db,
        playbook_id=playbook_id,
        condition_type=condition_type,
        enabled_only=enabled_only,
    )
    return {"count": len(triggers), "triggers": triggers}


@router.post("/triggers", status_code=status.HTTP_201_CREATED, summary="Create a SOAR playbook trigger")
@limiter.limit("10/minute")
async def create_trigger(
    request: Request,
    body: CreateTriggerRequest,
    current_user: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    result = await soar_service.create_trigger(
        db,
        playbook_id=body.playbook_id,
        playbook_name=body.playbook_name,
        condition_type=body.condition_type,
        condition_operator=body.condition_operator,
        condition_value=body.condition_value,
        hunt_id_filter=body.hunt_id_filter,
        priority=body.priority,
        rate_limit_per_hour=body.rate_limit_per_hour,
        dedup_window_minutes=body.dedup_window_minutes,
        created_by=current_user.email,
    )
    if "error" in result:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=result["error"])
    return result


@router.get("/triggers/{trigger_id}", summary="Get a single SOAR trigger")
@limiter.limit("60/minute")
async def get_trigger(
    request: Request,
    trigger_id: str,
    current_user: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    t = await soar_service.get_trigger(db, trigger_id)
    if not t:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Trigger not found")
    return t


@router.delete("/triggers/{trigger_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Delete a SOAR trigger")
@limiter.limit("10/minute")
async def delete_trigger(
    request: Request,
    trigger_id: str,
    current_user: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> None:
    deleted = await soar_service.delete_trigger(db, trigger_id, deleted_by=current_user.email)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Trigger not found")


@router.patch("/triggers/{trigger_id}/toggle", summary="Enable or disable a SOAR trigger")
@limiter.limit("20/minute")
async def toggle_trigger(
    request: Request,
    trigger_id: str,
    body: ToggleTriggerRequest,
    current_user: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    result = await soar_service.toggle_trigger(
        db, trigger_id, enabled=body.enabled, updated_by=current_user.email
    )
    if not result:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Trigger not found")
    return result


@router.post("/triggers/{trigger_id}/test", summary="Dry-run a trigger against a test context (no playbook execution)")
@limiter.limit("20/minute")
async def test_trigger(
    request: Request,
    trigger_id: str,
    body: TestTriggerRequest,
    current_user: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    result = await soar_service.test_trigger(trigger_id, body.context, db)
    if "error" in result and result["error"] == "Trigger not found":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Trigger not found")
    return result


@router.post("/evaluate", summary="Evaluate a context against all enabled triggers")
@limiter.limit("10/minute")
async def evaluate_context(
    request: Request,
    body: EvaluateContextRequest,
    current_user: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    if body.dry_run:
        # Dry-run: evaluate conditions without firing
        from sqlalchemy import select as sa_select
        from asc_api.models.soar import PlaybookTrigger
        from asc_api.services.soar_service import _evaluate_condition

        result = await db.execute(
            sa_select(PlaybookTrigger).where(
                PlaybookTrigger.enabled.is_(True),
                PlaybookTrigger.tenant_id == current_user.tenant_id,
            )
        )
        triggers = list(result.scalars().all())
        hunt_id_ctx = body.context.get("hunt_id")
        matches = []
        for t in triggers:
            if t.hunt_id_filter and t.hunt_id_filter != hunt_id_ctx:
                continue
            matched = _evaluate_condition(t, body.context)
            if matched:
                matches.append({
                    "trigger_id": t.id,
                    "playbook_id": t.playbook_id,
                    "condition_type": t.condition_type,
                    "condition_operator": t.condition_operator,
                    "condition_value": t.condition_value,
                    "would_fire": True,
                })
        return {
            "dry_run": True,
            "context": body.context,
            "matched_count": len(matches),
            "matches": matches,
        }

    # Live evaluation — actually fire matching triggers
    fired = await soar_service.evaluate_triggers_for_context(
        db,
        body.context,
        triggered_by=current_user.email,
    )
    return {
        "dry_run": False,
        "context": body.context,
        "fired_count": len(fired),
        "fired": fired,
    }


# ── Scheduled Reports ─────────────────────────────────────────────────────────

class CreateScheduledReportRequest(BaseModel):
    hunt_id: str = Field(..., description="UUID of the hunt to report on")
    hunt_name: str | None = Field(None, max_length=256)
    recipient_email: str = Field(..., description="Delivery address")
    frequency: str = Field("daily", description="daily | weekly")
    format: str = Field("json", description="json | pdf")


class ToggleReportRequest(BaseModel):
    enabled: bool


@router.get("/reports", summary="List scheduled reports")
@limiter.limit("60/minute")
async def list_scheduled_reports(
    request: Request,
    hunt_id: str | None = Query(None),
    enabled_only: bool = Query(False),
    current_user: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    reports = await soar_service.list_scheduled_reports(db, hunt_id=hunt_id, enabled_only=enabled_only)
    return {"count": len(reports), "reports": reports}


@router.post("/reports", status_code=status.HTTP_201_CREATED, summary="Create a scheduled report")
@limiter.limit("10/minute")
async def create_scheduled_report(
    request: Request,
    body: CreateScheduledReportRequest,
    current_user: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    result = await soar_service.create_scheduled_report(
        db,
        hunt_id=body.hunt_id,
        hunt_name=body.hunt_name,
        recipient_email=body.recipient_email,
        frequency=body.frequency,
        format=body.format,
        created_by=current_user.email,
    )
    if "error" in result:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=result["error"])
    return result


@router.get("/reports/{report_id}", summary="Get a scheduled report")
@limiter.limit("60/minute")
async def get_scheduled_report(
    request: Request,
    report_id: str,
    current_user: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    r = await soar_service.get_scheduled_report(db, report_id)
    if not r:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scheduled report not found")
    return r


@router.delete("/reports/{report_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Delete a scheduled report")
@limiter.limit("10/minute")
async def delete_scheduled_report(
    request: Request,
    report_id: str,
    current_user: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> None:
    deleted = await soar_service.delete_scheduled_report(db, report_id, deleted_by=current_user.email)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scheduled report not found")


@router.patch("/reports/{report_id}/toggle", summary="Enable or disable a scheduled report")
@limiter.limit("20/minute")
async def toggle_scheduled_report(
    request: Request,
    report_id: str,
    body: ToggleReportRequest,
    current_user: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    result = await soar_service.toggle_scheduled_report(
        db, report_id, enabled=body.enabled, updated_by=current_user.email
    )
    if not result:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scheduled report not found")
    return result


@router.post("/reports/{report_id}/deliver", summary="Immediately deliver a scheduled report (on-demand)")
@limiter.limit("5/minute")
async def deliver_report_now(
    request: Request,
    report_id: str,
    current_user: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    result = await soar_service.deliver_scheduled_report(db, report_id)
    if "error" in result and result["error"] == "ScheduledReport not found":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scheduled report not found")
    return result
