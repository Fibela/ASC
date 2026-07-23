import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query
from fastapi.responses import HTMLResponse, Response
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.api.deps import get_current_user
from asc_api.db.session import get_db
from asc_api.models.alert import Alert
from asc_api.models.event import Event
from asc_api.models.user import User
from asc_api.services.reporter import generate_html_report, generate_pdf_report

router = APIRouter(prefix="/reports", tags=["Reports"])


def _tc(model, tenant_id):
    """S105.2 — scope de tenant (None -> IS NULL, reporte global legacy)."""
    return model.tenant_id.is_(None) if tenant_id is None else model.tenant_id == tenant_id


async def _build_report_data(
    db: AsyncSession, hours: int, analyst: str = "System", tenant_id: str | None = None
) -> dict:
    since = datetime.now(UTC) - timedelta(hours=hours)

    alerts_result = await db.execute(
        select(Alert).where(_tc(Alert, tenant_id), Alert.detected_at >= since).order_by(desc(Alert.detected_at))
    )
    alerts = alerts_result.scalars().all()

    # Real event count for the period
    events_result = await db.execute(
        select(func.count()).select_from(Event).where(_tc(Event, tenant_id), Event.timestamp >= since)
    )
    total_events = events_result.scalar_one() or 0

    total = len(alerts)
    critical = sum(1 for a in alerts if a.severity == "critical")
    fp = sum(1 for a in alerts if a.false_positive)
    fp_rate = round(fp / total, 4) if total else 0.0

    resolved = [a for a in alerts if a.resolved_at and a.detected_at]
    mttr = None
    if resolved:
        mttr_secs = [(a.resolved_at - a.detected_at).total_seconds() for a in resolved]
        mttr = round(sum(mttr_secs) / len(mttr_secs) / 60, 1)

    # MTTD = avg(detected_at - threat_start_at) for alerts that have threat_start_at
    detectable = [a for a in alerts if a.threat_start_at and a.detected_at]
    mttd = None
    if detectable:
        mttd_secs = [(a.detected_at - a.threat_start_at).total_seconds() for a in detectable]
        mttd = round(sum(mttd_secs) / len(mttd_secs) / 60, 1)

    posture = "CRITICAL" if critical > 0 else ("HIGH" if total > 10 else "NORMAL")

    return {
        "report_id": str(uuid.uuid4())[:8].upper(),
        "analyst": analyst,
        "period": f"Last {hours}h",
        "summary": {
            "total_alerts": total,
            "critical_count": critical,
            "risk_posture": posture,
            "total_events": total_events,
        },
        "metrics": {
            "total_alerts": total,
            "total_events": total_events,
            "true_positives": total - fp,
            "fp_rate": fp_rate,
            "mttr_minutes": mttr,
            "mttd_minutes": mttd,
            "ioc_coverage": 0.0,
            "endpoint_coverage": 0.0,
        },
        "alerts": [
            {
                "title": a.title,
                "severity": a.severity,
                "risk_score": a.risk_score,
                "status": a.status,
                "detected_at": a.detected_at.isoformat() if a.detected_at else "",
            }
            for a in alerts
        ],
    }


@router.get("/pdf", summary="Download PDF security report with PremosCorp branding")
async def download_pdf(
    hours: int = Query(24),
    analyst: str = Query("System"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    data = await _build_report_data(db, hours, analyst, tenant_id=current_user.tenant_id)
    pdf_bytes = generate_pdf_report(data)
    if not pdf_bytes:
        from fastapi import HTTPException

        raise HTTPException(status_code=500, detail="PDF generation failed — install reportlab")
    filename = f"ASC_Report_{datetime.now(UTC).strftime('%Y%m%d_%H%M')}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/html", response_class=HTMLResponse, summary="View HTML security report")
async def view_html(
    hours: int = Query(24),
    analyst: str = Query("System"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    data = await _build_report_data(db, hours, analyst, tenant_id=current_user.tenant_id)
    return generate_html_report(data)
