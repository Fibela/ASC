"""
Alerts endpoint â€” P21-F2: rate limiting added.
"""
from fastapi import APIRouter, HTTPException, Depends, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func
from datetime import datetime, timezone

from asc_api.db.session import get_db
from asc_api.models.alert import Alert
from asc_api.models.user import User
from asc_api.api.deps import get_current_user, get_analyst_or_admin
from asc_api.core.rate_limit import limiter
from asc_api.core.config import get_settings
from pydantic import BaseModel

router = APIRouter(prefix="/alerts", tags=["Alerts"])
settings = get_settings()


class AlertUpdate(BaseModel):
    status: str | None = None
    analyst_notes: str | None = None
    assigned_to: str | None = None
    false_positive: bool | None = None


@router.get("", summary="List alerts")
@limiter.limit(settings.RATE_LIMIT_ALERTS)
async def list_alerts(
    request: Request,
    limit: int = Query(50, le=500),
    offset: int = Query(0),
    severity: str | None = Query(None),
    status: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    q = select(Alert).order_by(desc(Alert.detected_at)).offset(offset).limit(limit)
    if severity:
        q = q.where(Alert.severity == severity)
    if status:
        q = q.where(Alert.status == status)
    result = await db.execute(q)
    alerts = result.scalars().all()
    return [_alert_to_dict(a) for a in alerts]


@router.get("/stats/summary", summary="Alert statistics for dashboard")
@limiter.limit(settings.RATE_LIMIT_ALERTS)
async def alert_stats(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    total = (await db.execute(select(func.count()).select_from(Alert))).scalar()
    open_count = (await db.execute(select(func.count()).select_from(Alert).where(Alert.status == "open"))).scalar()
    critical = (await db.execute(select(func.count()).select_from(Alert).where(Alert.severity == "critical"))).scalar()
    high = (await db.execute(select(func.count()).select_from(Alert).where(Alert.severity == "high"))).scalar()
    fp = (await db.execute(select(func.count()).select_from(Alert).where(Alert.false_positive == True))).scalar()
    fp_rate = round(fp / total, 4) if total else 0.0

    return {
        "total": total,
        "open": open_count,
        "critical": critical,
        "high": high,
        "false_positive_rate": fp_rate,
        "by_severity": {"critical": critical, "high": high},
    }


@router.get("/{alert_id}", summary="Get alert detail")
@limiter.limit(settings.RATE_LIMIT_ALERTS)
async def get_alert(
    request: Request,
    alert_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _alert_to_dict(alert)


@router.patch("/{alert_id}", summary="Update alert status / assign analyst")
@limiter.limit("60/minute")
async def update_alert(
    request: Request,
    alert_id: str,
    payload: AlertUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    if payload.status:
        alert.status = payload.status
        if payload.status in ("resolved", "false_positive") and not alert.resolved_at:
            alert.resolved_at = datetime.now(timezone.utc)
        if payload.status == "investigating" and not alert.acknowledged_at:
            alert.acknowledged_at = datetime.now(timezone.utc)
    if payload.analyst_notes is not None:
        alert.analyst_notes = payload.analyst_notes
    if payload.assigned_to is not None:
        alert.assigned_to = payload.assigned_to
    if payload.false_positive is not None:
        alert.false_positive = payload.false_positive

    await db.commit()
    return _alert_to_dict(alert)


def _alert_to_dict(a: Alert) -> dict:
    return {
        "id":                a.id,
        "title":             a.title,
        "description":       a.description,
        "severity":          a.severity,
        "status":            a.status,
        "risk_score":        a.risk_score,
        "ttps":              a.ttps,
        "affected_hosts":    a.affected_hosts,
        "recommended_actions": a.recommended_actions,
        "analyst_notes":     a.analyst_notes,
        "assigned_to":       a.assigned_to,
        "false_positive":    a.false_positive,
        "detected_at":       a.detected_at.isoformat() if a.detected_at else None,
        "acknowledged_at":   a.acknowledged_at.isoformat() if a.acknowledged_at else None,
        "resolved_at":       a.resolved_at.isoformat() if a.resolved_at else None,
    }
