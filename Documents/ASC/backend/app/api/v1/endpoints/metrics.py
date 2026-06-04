from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from datetime import datetime, timezone, timedelta

from app.db.session import get_db
from app.models.event import Event
from app.models.alert import Alert
from app.models.metric import SocMetric
from app.services.correlator import get_ioc_coverage

router = APIRouter(prefix="/metrics", tags=["SOC Metrics"])


@router.get("/soc", summary="Real-time SOC KPIs: MTTD, MTTR, FP rate, IoC coverage")
async def get_soc_metrics(
    hours: int = Query(24, description="Lookback window in hours"),
    db: AsyncSession = Depends(get_db),
):
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    # Event count
    total_events = (await db.execute(
        select(func.count()).select_from(Event).where(Event.timestamp >= since)
    )).scalar() or 0

    # Alert counts
    total_alerts = (await db.execute(
        select(func.count()).select_from(Alert).where(Alert.detected_at >= since)
    )).scalar() or 0

    critical = (await db.execute(
        select(func.count()).select_from(Alert).where(Alert.detected_at >= since, Alert.severity == "critical")
    )).scalar() or 0

    high = (await db.execute(
        select(func.count()).select_from(Alert).where(Alert.detected_at >= since, Alert.severity == "high")
    )).scalar() or 0

    medium = (await db.execute(
        select(func.count()).select_from(Alert).where(Alert.detected_at >= since, Alert.severity == "medium")
    )).scalar() or 0

    low = (await db.execute(
        select(func.count()).select_from(Alert).where(Alert.detected_at >= since, Alert.severity == "low")
    )).scalar() or 0

    # False positives
    fp_count = (await db.execute(
        select(func.count()).select_from(Alert).where(Alert.detected_at >= since, Alert.false_positive == True)
    )).scalar() or 0
    fp_rate = round(fp_count / total_alerts, 4) if total_alerts else 0.0

    # MTTD: avg time from event to alert (approximation)
    resolved_alerts = (await db.execute(
        select(Alert).where(Alert.resolved_at != None, Alert.detected_at >= since)
    )).scalars().all()

    mttd_seconds = None
    mttr_seconds = None
    if resolved_alerts:
        mttr_values = [(a.resolved_at - a.detected_at).total_seconds() for a in resolved_alerts if a.resolved_at and a.detected_at]
        mttr_seconds = round(sum(mttr_values) / len(mttr_values), 1) if mttr_values else None

    ioc_coverage = await get_ioc_coverage(db)

    # Risk posture
    if critical > 0:
        posture = "CRITICAL"
    elif high > 3:
        posture = "HIGH"
    elif high > 0 or medium > 5:
        posture = "ELEVATED"
    else:
        posture = "NORMAL"

    return {
        "period_hours":       hours,
        "total_events":       total_events,
        "total_alerts":       total_alerts,
        "false_positive_rate": fp_rate,
        "ioc_coverage":       ioc_coverage,
        "mttd_seconds":       mttd_seconds,
        "mttr_seconds":       mttr_seconds,
        "mttd_minutes":       round(mttd_seconds / 60, 1) if mttd_seconds else None,
        "mttr_minutes":       round(mttr_seconds / 60, 1) if mttr_seconds else None,
        "risk_posture":       posture,
        "by_severity": {
            "critical": critical,
            "high":     high,
            "medium":   medium,
            "low":      low,
        },
    }


@router.get("/timeline", summary="Event/alert counts over time (for charts)")
async def get_timeline(
    hours: int = Query(24),
    bucket_minutes: int = Query(60),
    db: AsyncSession = Depends(get_db),
):
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    result = await db.execute(
        select(Alert.detected_at, Alert.severity).where(Alert.detected_at >= since).order_by(Alert.detected_at)
    )
    alerts = result.all()

    buckets: dict[str, dict] = {}
    for detected_at, severity in alerts:
        key = detected_at.strftime(f"%Y-%m-%dT%H:{'00' if bucket_minutes >= 60 else detected_at.strftime('%M')}:00Z")
        if key not in buckets:
            buckets[key] = {"timestamp": key, "critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
        buckets[key][severity] = buckets[key].get(severity, 0) + 1
        buckets[key]["total"] += 1

    return sorted(buckets.values(), key=lambda x: x["timestamp"])
