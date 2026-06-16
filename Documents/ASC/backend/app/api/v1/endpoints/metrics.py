from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from datetime import datetime, timezone, timedelta

from app.db.session import get_db
from app.models.event import Event
from app.models.alert import Alert
from app.models.metric import SocMetric
from app.models.user import User
from app.services.correlator import get_ioc_coverage
from app.services.metrics import (
    calculate_mttd, calculate_mtta, calculate_mttr, calculate_mttr_respond,
    breakdown_by_severity, status_funnel, daily_mttr_trend, build_soc_summary,
)
from app.api.deps import get_current_user

router = APIRouter(prefix="/metrics", tags=["SOC Metrics"])


def _risk_posture(critical: int, high: int, medium: int) -> str:
    if critical > 0:
        return "CRITICAL"
    if high > 3:
        return "HIGH"
    if high > 0 or medium > 5:
        return "ELEVATED"
    return "NORMAL"


async def _fetch_alerts(db: AsyncSession, since: datetime) -> list[Alert]:
    """Fetch all alerts in window, loaded into memory for pure-function calculations."""
    result = await db.execute(
        select(Alert).where(Alert.detected_at >= since)
    )
    return list(result.scalars().all())


@router.get("/public", summary="Estado operacional del SOC — sin autenticación")
async def public_metrics():
    """
    Public health endpoint for premoscorp.com marketing portal.
    Returns ONLY operational status — no internal KPIs, no timing data,
    no coverage metrics that could provide adversarial intelligence.
    """
    return {
        "status":     "operational",
        "uptime":     True,
        "as_of":      datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


@router.get("/soc", summary="Real-time SOC KPIs: MTTD, MTTA, MTTR, FP rate, IoC coverage")
async def get_soc_metrics(
    hours: int = Query(24, description="Lookback window in hours", ge=1, le=8760),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    since  = datetime.now(timezone.utc) - timedelta(hours=hours)
    alerts = await _fetch_alerts(db, since)

    total_events = (await db.execute(
        select(func.count()).select_from(Event).where(Event.timestamp >= since)
    )).scalar() or 0

    total_alerts = len(alerts)
    critical = sum(1 for a in alerts if a.severity == "critical")
    high     = sum(1 for a in alerts if a.severity == "high")
    medium   = sum(1 for a in alerts if a.severity == "medium")
    low      = sum(1 for a in alerts if a.severity == "low")
    fp_count = sum(1 for a in alerts if a.false_positive)
    fp_rate  = round(fp_count / total_alerts, 4) if total_alerts else 0.0

    ioc_coverage = await get_ioc_coverage(db)
    summary      = build_soc_summary(alerts)
    funnel       = status_funnel(alerts)

    return {
        "period_hours":        hours,
        "total_events":        total_events,
        "total_alerts":        total_alerts,
        "false_positive_rate": fp_rate,
        "ioc_coverage":        ioc_coverage,
        # MTTD — meaningful only when alerts have threat_start_at populated
        "mttd_seconds":        summary["mttd_seconds"],
        "mttd_minutes":        summary["mttd_minutes"],
        # MTTA — time from alert creation to first analyst acknowledgment
        "mtta_seconds":        summary["mtta_seconds"],
        "mtta_minutes":        summary["mtta_minutes"],
        # MTTR — total time from detection to resolution
        "mttr_seconds":        summary["mttr_seconds"],
        "mttr_minutes":        summary["mttr_minutes"],
        "risk_posture":        _risk_posture(critical, high, medium),
        "by_severity": {
            "critical": critical, "high": high, "medium": medium, "low": low,
        },
        "by_status": funnel,
    }


@router.get("/performance", summary="Full MTTD/MTTA/MTTR with percentiles, SLA compliance and daily trend")
async def get_performance_metrics(
    hours: int = Query(168, description="Lookback window in hours (default 7d)", ge=1, le=8760),
    trend_days: int = Query(7, description="Days for daily MTTR trend", ge=1, le=90),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    since  = datetime.now(timezone.utc) - timedelta(hours=hours)
    alerts = await _fetch_alerts(db, since)

    mttd         = calculate_mttd(alerts)
    mtta         = calculate_mtta(alerts)
    mttr         = calculate_mttr(alerts)
    mttr_respond = calculate_mttr_respond(alerts)

    return {
        "period_hours":  hours,
        "total_alerts":  len(alerts),
        # Full stat blocks with percentiles + SLA
        "mttd":          mttd,
        "mtta":          mtta,
        "mttr":          mttr,
        "mttr_respond":  mttr_respond,
        # MTTR broken down per severity
        "by_severity": {
            "mttd": breakdown_by_severity(alerts, calculate_mttd),
            "mtta": breakdown_by_severity(alerts, calculate_mtta),
            "mttr": breakdown_by_severity(alerts, calculate_mttr),
        },
        # Alert lifecycle pipeline
        "status_funnel": status_funnel(alerts),
        # Day-by-day MTTR trend for charts
        "daily_trend":   daily_mttr_trend(alerts, days=trend_days),
    }


@router.get("/timeline", summary="Event/alert counts over time (for charts)")
async def get_timeline(
    hours: int = Query(24),
    bucket_minutes: int = Query(60),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    since  = datetime.now(timezone.utc) - timedelta(hours=hours)
    result = await db.execute(
        select(Alert.detected_at, Alert.severity)
        .where(Alert.detected_at >= since)
        .order_by(Alert.detected_at)
    )
    alerts = result.all()

    buckets: dict[str, dict] = {}
    for detected_at, severity in alerts:
        key = detected_at.strftime(
            f"%Y-%m-%dT%H:{'00' if bucket_minutes >= 60 else detected_at.strftime('%M')}:00Z"
        )
        if key not in buckets:
            buckets[key] = {"timestamp": key, "critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
        buckets[key][severity] = buckets[key].get(severity, 0) + 1
        buckets[key]["total"] += 1

    return sorted(buckets.values(), key=lambda x: x["timestamp"])
