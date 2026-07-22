"""
Vercel Cron Job endpoints — replace Celery Beat background tasks.

Vercel invokes these GET endpoints on the schedule defined in vercel.json.
Authorization: each endpoint verifies the CRON_SECRET env var matches the
Bearer token Vercel sends automatically (set CRON_SECRET in Vercel Dashboard).

Schedules (vercel.json):
  /api/v1/cron/heartbeat            — every 1 min  (lightweight liveness pulse)
  /api/v1/cron/correlation-sweep    — every 15 min
  /api/v1/cron/escalation           — every 5 min
  /api/v1/cron/sla-check            — every 10 min
  /api/v1/cron/pcdi-scan            — every 5 min
  /api/v1/cron/scheduled-reports    — hourly
"""
from __future__ import annotations

from fastapi import APIRouter, Header, HTTPException, status

from asc_api.core.config import get_settings
from asc_api.core.heartbeat import emit_heartbeat
from asc_api.core.logging import get_logger

log = get_logger("asc.cron")

router = APIRouter(prefix="/cron", tags=["Cron Jobs"])


def _verify(authorization: str | None) -> None:
    settings = get_settings()
    if not settings.CRON_SECRET:
        if not settings.DEBUG:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="CRON_SECRET not configured — set it in Vercel Dashboard",
            )
        return
    if authorization != f"Bearer {settings.CRON_SECRET}":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid cron secret")


@router.get("/heartbeat", summary="Lightweight liveness pulse — every 1 min")
async def cron_heartbeat(authorization: str | None = Header(None)) -> dict:
    """Dedicated 1-minute heartbeat. No business logic — just emits to platform_heartbeats.
    Primary signal for /health/platform staleness detection."""
    _verify(authorization)
    await emit_heartbeat("cron-heartbeat")
    return {"job": "heartbeat", "status": "ok"}


@router.get("/correlation-sweep")
async def cron_correlation_sweep(authorization: str | None = Header(None)) -> dict:
    _verify(authorization)
    job = "cron-correlation-sweep"
    try:
        from asc_api.tasks.correlation_sweep import _async_sweep
        await _async_sweep()
        await emit_heartbeat(job)
        return {"job": "correlation-sweep", "status": "ok"}
    except Exception as exc:
        log.error("cron_correlation_sweep_error", exc_info=exc)
        await emit_heartbeat(job, status="error", detail=str(exc))
        return {"job": "correlation-sweep", "status": "error", "detail": str(exc)}


@router.get("/escalation")
async def cron_escalation(authorization: str | None = Header(None)) -> dict:
    _verify(authorization)
    job = "cron-escalation"
    try:
        from asc_api.tasks.escalation import _run
        result = await _run()
        await emit_heartbeat(job)
        return {"job": "escalation", "status": "ok", **result}
    except Exception as exc:
        log.error("cron_escalation_error", exc_info=exc)
        await emit_heartbeat(job, status="error", detail=str(exc))
        return {"job": "escalation", "status": "error", "detail": str(exc)}


@router.get("/sla-check")
async def cron_sla_check(authorization: str | None = Header(None)) -> dict:
    _verify(authorization)
    job = "cron-sla-check"
    try:
        from asc_api.tasks.sla_escalation import _run
        result = await _run()
        await emit_heartbeat(job)
        return {"job": "sla-check", "status": "ok", **result}
    except Exception as exc:
        log.error("cron_sla_check_error", exc_info=exc)
        await emit_heartbeat(job, status="error", detail=str(exc))
        return {"job": "sla-check", "status": "error", "detail": str(exc)}


@router.get("/pcdi-scan")
async def cron_pcdi_scan(authorization: str | None = Header(None)) -> dict:
    _verify(authorization)
    job = "cron-pcdi-scan"
    try:
        from asc_api.tasks.pcdi_escalation import _run
        result = await _run()
        await emit_heartbeat(job)
        return {"job": "pcdi-scan", "status": "ok", **result}
    except Exception as exc:
        log.error("cron_pcdi_scan_error", exc_info=exc)
        await emit_heartbeat(job, status="error", detail=str(exc))
        return {"job": "pcdi-scan", "status": "error", "detail": str(exc)}


@router.get("/scheduled-reports")
async def cron_scheduled_reports(authorization: str | None = Header(None)) -> dict:
    _verify(authorization)
    job = "cron-scheduled-reports"
    try:
        from asc_api.tasks.scheduled_reports import _run
        result = await _run()
        await emit_heartbeat(job)
        return {"job": "scheduled-reports", "status": "ok", **result}
    except Exception as exc:
        log.error("cron_scheduled_reports_error", exc_info=exc)
        await emit_heartbeat(job, status="error", detail=str(exc))
        return {"job": "scheduled-reports", "status": "error", "detail": str(exc)}
