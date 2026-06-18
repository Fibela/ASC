"""
Executive Reporting Endpoints — P29-B / PIIL

PIIL Executive Authenticity: every generated report is sealed with
SHA3-512 + Ed25519 (Premos backend key), making reports verifiable
offline without access to ASC — differentiating from generic dashboard exports.

Endpoints
---------
  GET    /reports/executive/summary          Counts by type, last generated
  GET    /reports/executive                  List reports (filterable, paginated)
  POST   /reports/executive/generate         Generate + seal new report (admin)
  GET    /reports/executive/{id}             Full report with canonical payload
  POST   /reports/executive/{id}/verify      Re-verify hash + Ed25519 signature
  DELETE /reports/executive/{id}             Delete report (admin only)

Security: analyst+ for reads; generate/delete require admin role.
Rate-limiting: reads 60/min, writes/generate 10/min.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_analyst_or_admin, get_current_admin
from app.core.rate_limit import limiter
from app.core.logging import get_logger
from app.db.session import get_db
from app.models.executive_report import REPORT_TYPES, REPORT_PERIODS
from app.models.user import User
from app.services import reporting_service

log = get_logger(__name__)
router = APIRouter(prefix="/reports/executive", tags=["Executive Reports / PIIL"])


# ── Request schemas ───────────────────────────────────────────────────────────

class GenerateReportRequest(BaseModel):
    report_type: str = Field("full_executive")
    period: str = Field("custom")
    period_start: datetime = Field(...)
    period_end: datetime = Field(...)
    title: str | None = Field(None, max_length=512)

    @field_validator("report_type")
    @classmethod
    def validate_type(cls, v: str) -> str:
        if v not in REPORT_TYPES:
            raise ValueError(f"report_type must be one of {sorted(REPORT_TYPES)}")
        return v

    @field_validator("period")
    @classmethod
    def validate_period(cls, v: str) -> str:
        if v not in REPORT_PERIODS:
            raise ValueError(f"period must be one of {sorted(REPORT_PERIODS)}")
        return v

    @field_validator("period_end")
    @classmethod
    def validate_range(cls, v: datetime, info: any) -> datetime:
        start = info.data.get("period_start")
        if start and v <= start:
            raise ValueError("period_end must be after period_start")
        return v


# ── Serializers ───────────────────────────────────────────────────────────────

def _report_summary(r: any) -> dict:
    return {
        "id": r.id,
        "report_type": r.report_type,
        "period": r.period,
        "title": r.title,
        "generated_by": r.generated_by,
        "period_start": r.period_start.isoformat() if r.period_start else None,
        "period_end": r.period_end.isoformat() if r.period_end else None,
        "total_incidents": r.total_incidents,
        "closed_incidents": r.closed_incidents,
        "sla_breach_count": r.sla_breach_count,
        "campaign_count": r.campaign_count,
        "avg_mttd_minutes": r.avg_mttd_minutes,
        "avg_mttc_minutes": r.avg_mttc_minutes,
        "avg_mttr_minutes": r.avg_mttr_minutes,
        "hash_sha3_512": r.hash_sha3_512,
        "signature_ed25519": r.signature_ed25519,
        "pubkey_fingerprint": r.pubkey_fingerprint,
        "signature_valid": r.signature_valid,
        "last_verified_at": r.last_verified_at.isoformat() if r.last_verified_at else None,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }


def _report_full(r: any) -> dict:
    d = _report_summary(r)
    d["canonical_data"] = r.canonical_data
    return d


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/summary", summary="Resumen del módulo de reportes ejecutivos")
@limiter.limit("60/minute")
async def report_summary(
    request: Request,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_analyst_or_admin),
) -> dict:
    return await reporting_service.get_reporting_summary(db)


@router.get("", summary="Listar reportes ejecutivos (filtrable, paginado)")
@limiter.limit("60/minute")
async def list_reports(
    request: Request,
    report_type: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_analyst_or_admin),
) -> dict:
    if report_type and report_type not in REPORT_TYPES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"report_type must be one of {sorted(REPORT_TYPES)}",
        )
    reports = await reporting_service.list_reports(
        db, report_type=report_type, limit=limit, offset=offset
    )
    return {
        "items": [_report_summary(r) for r in reports],
        "count": len(reports),
        "limit": limit,
        "offset": offset,
    }


@router.post(
    "/generate",
    status_code=status.HTTP_201_CREATED,
    summary="Generar y sellar nuevo reporte ejecutivo (PIIL)",
)
@limiter.limit("10/minute")
async def generate_report(
    request: Request,
    body: GenerateReportRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
) -> dict:
    try:
        report = await reporting_service.generate_report(
            db,
            report_type=body.report_type,
            period=body.period,
            period_start=body.period_start,
            period_end=body.period_end,
            generated_by=current_user.email,
            title=body.title,
        )
    except ValueError as exc:
        msg = str(exc)
        http_status = (
            status.HTTP_503_SERVICE_UNAVAILABLE
            if "SPECTER_SIGNING_PRIVATE_KEY" in msg
            else status.HTTP_422_UNPROCESSABLE_ENTITY
        )
        raise HTTPException(status_code=http_status, detail=msg)
    return _report_full(report)


@router.get("/{report_id}", summary="Detalle completo de un reporte con payload canónico")
@limiter.limit("60/minute")
async def get_report(
    request: Request,
    report_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_analyst_or_admin),
) -> dict:
    report = await reporting_service.get_report(db, report_id)
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    return _report_full(report)


@router.post("/{report_id}/verify", summary="Re-verificar hash + firma Ed25519 (PIIL)")
@limiter.limit("30/minute")
async def verify_report(
    request: Request,
    report_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_analyst_or_admin),
) -> dict:
    try:
        return await reporting_service.verify_report(db, report_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.delete(
    "/{report_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Eliminar reporte ejecutivo (admin)",
)
@limiter.limit("10/minute")
async def delete_report(
    request: Request,
    report_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_admin),
):
    report = await reporting_service.get_report(db, report_id)
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    await db.delete(report)
    await db.commit()
    log.info("executive_report_deleted id=%s", report_id)
