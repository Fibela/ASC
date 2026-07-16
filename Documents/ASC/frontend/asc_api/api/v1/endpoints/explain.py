"""
Endpoint de explicación adaptativa de alertas (S102).

POST /api/v1/alerts/{alert_id}/explain
  - Auth: get_current_user (mismo JWT que el resto del API).
  - Aislamiento de tenant: la alerta debe pertenecer al tenant del usuario.
  - Perfil: se toma del tenant en DB (hogar/pyme/enterprise). Sin selector
    de cliente: el perfil es un hecho del cliente, no una preferencia por alerta.
  - Respuesta: SSE (text/event-stream), la explicación llega token a token.
  - El módulo EXPLICA y RECOMIENDA; nunca decide ni ejecuta.
"""
from __future__ import annotations

import json

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.api.deps import get_current_user
from asc_api.core.logging import get_logger
from asc_api.core.rate_limit import limiter
from asc_api.core.config import get_settings
from asc_api.db.session import get_db
from asc_api.models.alert import Alert
from asc_api.models.tenant import Tenant
from asc_api.models.user import User
from asc_api.services.explainer import (
    ExplainerDisabled,
    stream_explanation,
)

router = APIRouter(prefix="/alerts", tags=["Alerts"])
settings = get_settings()
log = get_logger("asc.explain")


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


@router.post("/{alert_id}/explain", summary="Explicación adaptativa de una alerta (SSE)")
@limiter.limit(settings.RATE_LIMIT_ALERTS)
async def explain_alert(
    request: Request,
    alert_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # ── Aislamiento de tenant: la alerta debe ser del tenant del usuario ──
    result = await db.execute(
        select(Alert).where(
            Alert.id == alert_id, Alert.tenant_id == current_user.tenant_id
        )
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    # ── Perfil del tenant (fuente de la adaptación) ──
    profile = "pyme"
    if current_user.tenant_id:
        t = await db.execute(
            select(Tenant.profile).where(Tenant.id == current_user.tenant_id)
        )
        profile = t.scalar_one_or_none() or "pyme"

    # ── Falla temprana y honesta si el módulo no está configurado ──
    if not settings.ANTHROPIC_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Explainer no configurado (falta ANTHROPIC_API_KEY en el entorno).",
        )

    alert_data = {
        "id": alert.id,
        "title": alert.title,
        "description": alert.description,
        "severity": alert.severity,
        "risk_score": alert.risk_score,
        "status": alert.status,
        "affected_hosts": alert.affected_hosts,
        "ttps": alert.ttps,
        "matched_iocs": alert.matched_iocs,
        "recommended_actions": alert.recommended_actions,
    }

    async def event_source():
        yield _sse("meta", {"alert_id": alert.id, "profile": profile})
        try:
            async for piece in stream_explanation(alert_data, profile):
                yield _sse("delta", {"text": piece})
            yield _sse("done", {"alert_id": alert.id})
        except ExplainerDisabled:
            yield _sse("error", {"detail": "Explainer no configurado."})
        except httpx.HTTPStatusError as exc:
            log.error("explain_upstream_error", alert_id=alert.id, status=exc.response.status_code)
            yield _sse("error", {"detail": "Servicio de explicación no disponible (upstream)."})
        except httpx.TimeoutException:
            log.error("explain_timeout", alert_id=alert.id)
            yield _sse("error", {"detail": "La explicación excedió el tiempo límite."})
        except Exception as exc:  # noqa: BLE001 — se reporta, no se simula
            log.error("explain_unexpected", alert_id=alert.id, error=str(exc))
            yield _sse("error", {"detail": "Error inesperado generando la explicación."})

    return StreamingResponse(
        event_source(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
