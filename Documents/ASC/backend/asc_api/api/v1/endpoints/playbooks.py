"""
Playbooks Engine â€” REST endpoints.

Endpoints:
  GET  /playbooks/                       Catalog of available playbooks
  POST /playbooks/trigger                Manually trigger a specific playbook
  POST /playbooks/auto-trigger           Auto-select and trigger based on context
  GET  /playbooks/runs                   List execution history (paged)
  GET  /playbooks/runs/{run_id}          Single run detail
  POST /playbooks/runs/{run_id}/approve  HitL approval â€” resume paused run
  POST /playbooks/runs/{run_id}/abort    Abort a pending/awaiting run
"""

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.api.deps import get_analyst_or_admin, get_current_user
from asc_api.core.audit import log_security_action
from asc_api.core.logging import get_logger
from asc_api.db.session import get_db
from asc_api.models.playbook_run import PlaybookRun
from asc_api.models.user import User
from asc_api.services.playbook import (
    PlaybookContext,
    abort_playbook_run,
    approve_playbook_run,
    auto_trigger,
    get_playbook_catalog,
    trigger_playbook,
)

log = get_logger(__name__)
router = APIRouter(prefix="/playbooks", tags=["Playbooks"])


# â”€â”€â”€ Request schemas â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TriggerRequest(BaseModel):
    playbook_id: str = Field(..., pattern=r"^PB-\d{3}$", description="e.g. PB-001")
    semaphore: str = Field(..., pattern=r"^(green|yellow|red)$")
    risk_score: float = Field(0.0, ge=0.0, le=1.0)
    host: str | None = None
    dst_ip: str | None = None
    dst_domain: str | None = None
    process_name: str | None = None
    ttps: list[str] = Field(default_factory=list)
    trigger_data: dict[str, Any] = Field(default_factory=dict)


class AutoTriggerRequest(BaseModel):
    semaphore: str = Field(..., pattern=r"^(green|yellow|red)$")
    risk_score: float = Field(..., ge=0.0, le=1.0)
    trigger_source: str = Field("manual", pattern=r"^(manual|auto_detection|auto_fingerprint)$")
    host: str | None = None
    dst_ip: str | None = None
    dst_domain: str | None = None
    process_name: str | None = None
    ttps: list[str] = Field(default_factory=list)
    trigger_data: dict[str, Any] = Field(default_factory=dict)
    fingerprint_confidence: float | None = Field(None, ge=0.0, le=1.0)
    fingerprint_triggers: list[str] = Field(default_factory=list)


class ApproveRequest(BaseModel):
    approval_token: str = Field(..., min_length=36, max_length=36, description="UUID token from awaiting_approval run")


# â”€â”€â”€ Response helper â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _run_to_dict(run: PlaybookRun) -> dict:
    return {
        "id":                run.id,
        "playbook_id":       run.playbook_id,
        "playbook_name":     run.playbook_name,
        "trigger_source":    run.trigger_source,
        "semaphore":         run.semaphore,
        "risk_score":        run.risk_score,
        "status":            run.status,
        "steps_log":         run.steps_log,
        "alert_id":          run.alert_id,
        "approval_token":    run.approval_token,
        "approved_by":       run.approved_by,
        "approved_at":       run.approved_at.isoformat() if run.approved_at else None,
        "initiated_by":      run.initiated_by,
        "started_at":        run.started_at.isoformat() if run.started_at else None,
        "completed_at":      run.completed_at.isoformat() if run.completed_at else None,
        "error":             run.error,
    }


# â”€â”€â”€ Endpoints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@router.get("", summary="Catalog of available playbooks")
async def list_playbooks(
    _: User = Depends(get_current_user),
) -> list[dict]:
    return get_playbook_catalog()


@router.post("/trigger", status_code=status.HTTP_201_CREATED, summary="Manually trigger a specific playbook")
async def trigger_manual(
    body: TriggerRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
) -> dict:
    ctx = PlaybookContext(
        semaphore=body.semaphore,
        risk_score=body.risk_score,
        trigger_source="manual",
        trigger_data=body.trigger_data,
        host=body.host,
        dst_ip=body.dst_ip,
        dst_domain=body.dst_domain,
        process_name=body.process_name,
        ttps=body.ttps,
    )
    try:
        run = await trigger_playbook(body.playbook_id, ctx, db, initiated_by=str(current_user.id))
        await db.commit()
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        await db.rollback()
        log.error("playbook_trigger_error", error=str(exc))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Playbook execution error")

    log.info("playbook_manual_trigger", run_id=run.id, playbook=body.playbook_id, user=str(current_user.id))
    log_security_action(
        "playbook_trigger",
        user_id=str(current_user.id),
        role=current_user.role,
        resource="playbook",
        resource_id=body.playbook_id,
        detail=f"run_id={run.id} semaphore={body.semaphore}",
    )
    return _run_to_dict(run)


@router.post("/auto-trigger", status_code=status.HTTP_201_CREATED, summary="Auto-select and trigger playbook from context")
async def trigger_auto(
    body: AutoTriggerRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
) -> dict:
    ctx = PlaybookContext(
        semaphore=body.semaphore,
        risk_score=body.risk_score,
        trigger_source=body.trigger_source,
        trigger_data=body.trigger_data,
        host=body.host,
        dst_ip=body.dst_ip,
        dst_domain=body.dst_domain,
        process_name=body.process_name,
        ttps=body.ttps,
        fingerprint_confidence=body.fingerprint_confidence,
        fingerprint_triggers=body.fingerprint_triggers,
    )
    try:
        run = await auto_trigger(ctx, db, initiated_by=str(current_user.id))
        await db.commit()
    except Exception as exc:
        await db.rollback()
        log.error("playbook_auto_trigger_error", error=str(exc))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Auto-trigger failed")

    log.info("playbook_auto_trigger", run_id=run.id, playbook=run.playbook_id, user=str(current_user.id))
    return _run_to_dict(run)


@router.get("/runs", summary="List playbook execution history")
async def list_runs(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    status_filter: str | None = Query(None, alias="status"),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> dict:
    q = select(PlaybookRun).order_by(PlaybookRun.started_at.desc()).offset(offset).limit(limit)
    if status_filter:
        q = q.where(PlaybookRun.status == status_filter)

    result = await db.execute(q)
    runs = result.scalars().all()
    return {
        "total": len(runs),
        "offset": offset,
        "limit": limit,
        "runs": [_run_to_dict(r) for r in runs],
    }


@router.get("/runs/{run_id}", summary="Get details of a single playbook run")
async def get_run(
    run_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> dict:
    result = await db.execute(select(PlaybookRun).where(PlaybookRun.id == run_id))
    run = result.scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Playbook run not found")
    return _run_to_dict(run)


@router.post("/runs/{run_id}/approve", summary="Approve HitL checkpoint and resume playbook")
async def approve_run(
    run_id: str,
    body: ApproveRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
) -> dict:
    result = await db.execute(select(PlaybookRun).where(PlaybookRun.id == run_id))
    run = result.scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Playbook run not found")

    if run.status != "awaiting_approval":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Run is not awaiting approval (current status: {run.status})",
        )

    if run.approval_token != body.approval_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid approval token",
        )

    try:
        run = await approve_playbook_run(run, approved_by=str(current_user.id), db=db)
        await db.commit()
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        await db.rollback()
        log.error("playbook_approve_error", run_id=run_id, error=str(exc))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Resume failed")

    log.info("playbook_approved_api", run_id=run.id, approved_by=str(current_user.id))
    log_security_action(
        "playbook_approve",
        user_id=str(current_user.id),
        role=current_user.role,
        resource="playbook",
        resource_id=run_id,
        detail=f"playbook={run.playbook_id}",
    )
    return _run_to_dict(run)


@router.post("/runs/{run_id}/abort", summary="Abort a pending or awaiting playbook run")
async def abort_run(
    run_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
) -> dict:
    result = await db.execute(select(PlaybookRun).where(PlaybookRun.id == run_id))
    run = result.scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Playbook run not found")

    try:
        run = await abort_playbook_run(run, aborted_by=str(current_user.id), db=db)
        await db.commit()
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    except Exception as exc:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Abort failed")

    log.info("playbook_aborted_api", run_id=run.id, aborted_by=str(current_user.id))
    log_security_action(
        "playbook_abort",
        user_id=str(current_user.id),
        role=current_user.role,
        resource="playbook",
        resource_id=run_id,
        detail=f"playbook={run.playbook_id}",
    )
    return _run_to_dict(run)
