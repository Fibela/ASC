from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response, HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func
from datetime import datetime, timezone, timedelta
import uuid

from app.db.session import get_db
from app.models.alert import Alert
from app.models.user import User
from app.services.reporter import generate_pdf_report, generate_html_report
from app.api.deps import get_current_user

router = APIRouter(prefix="/reports", tags=["Reports"])


async def _build_report_data(db: AsyncSession, hours: int, analyst: str = "System") -> dict:
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    alerts_result = await db.execute(
        select(Alert).where(Alert.detected_at >= since).order_by(desc(Alert.detected_at))
    )
    alerts = alerts_result.scalars().all()

    total = len(alerts)
    critical = sum(1 for a in alerts if a.severity == "critical")
    fp = sum(1 for a in alerts if a.false_positive)
    fp_rate = round(fp / total, 4) if total else 0.0

    resolved = [a for a in alerts if a.resolved_at and a.detected_at]
    mttr = None
    if resolved:
        mttr_secs = [(a.resolved_at - a.detected_at).total_seconds() for a in resolved]
        mttr = round(sum(mttr_secs) / len(mttr_secs) / 60, 1)

    posture = "CRITICAL" if critical > 0 else ("HIGH" if total > 10 else "NORMAL")

    return {
        "report_id": str(uuid.uuid4())[:8].upper(),
        "analyst":   analyst,
        "period":    f"Last {hours}h",
        "summary": {
            "total_alerts":   total,
            "critical_count": critical,
            "risk_posture":   posture,
            "total_events":   total * 5,  # placeholder ratio
        },
        "metrics": {
            "total_alerts":     total,
            "total_events":     total * 5,
            "true_positives":   total - fp,
            "fp_rate":          fp_rate,
            "mttr_minutes":     mttr,
            "mttd_minutes":     None,
            "ioc_coverage":     0.0,
            "endpoint_coverage": 0.0,
        },
        "alerts": [
            {
                "title":       a.title,
                "severity":    a.severity,
                "risk_score":  a.risk_score,
                "status":      a.status,
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
    data = await _build_report_data(db, hours, analyst)
    pdf_bytes = generate_pdf_report(data)
    if not pdf_bytes:
        from fastapi import HTTPException
        raise HTTPException(status_code=500, detail="PDF generation failed — install reportlab")
    filename = f"ASC_Report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M')}.pdf"
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
    data = await _build_report_data(db, hours, analyst)
    return generate_html_report(data)
