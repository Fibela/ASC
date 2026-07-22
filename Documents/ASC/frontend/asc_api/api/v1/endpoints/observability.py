"""
ASC Observability Endpoints — P39

GET /api/v1/observability/metrics   — Prometheus text format (analyst+ JWT OR scrape token)
GET /api/v1/observability/summary   — JSON snapshot for the frontend status page (analyst+)

Security model:
  • JWT analyst+  — standard portal access
  • METRICS_SCRAPE_TOKEN  — static bearer token for Prometheus scraper (no user login needed)
  If METRICS_SCRAPE_TOKEN is not set, the scrape token path is disabled and only JWT works.

Prometheus scrape config example:
  scrape_configs:
    - job_name: asc_backend
      bearer_token: <METRICS_SCRAPE_TOKEN>
      metrics_path: /api/v1/observability/metrics
      static_configs:
        - targets: ['asc.premoscorp.com']
"""
import time
from datetime import datetime, timezone, timedelta

import psutil
import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.api.deps import get_analyst_or_admin
from asc_api.core.config import get_settings
import hmac

from asc_api.core.metrics_registry import (
    AGENTS_GAUGE,
    ALERTS_GAUGE,
    CONTENT_TYPE_LATEST,
    EVENTS_GAUGE,
    PROCESS_CPU_GAUGE,
    PROCESS_MEMORY_BYTES,
    REGISTRY,
    generate_latest,
)
from asc_api.db.session import get_db
from asc_api.models.agent import Agent
from asc_api.models.alert import Alert
from asc_api.models.event import Event
from asc_api.models.user import User

router = APIRouter(prefix="/observability", tags=["Observability"])
settings = get_settings()
log = structlog.get_logger("asc.observability")

_proc = psutil.Process()


# ── Auth helper ───────────────────────────────────────────────────────────────

def _check_scrape_token(request: Request) -> bool:
    """Return True if a valid static scrape token is present in Authorization header."""
    scrape_token = getattr(settings, "METRICS_SCRAPE_TOKEN", None)
    if not scrape_token:
        return False
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return hmac.compare_digest(auth[7:], scrape_token)
    return False


# ── Gauge refresh helpers ─────────────────────────────────────────────────────

async def _refresh_gauges(db: AsyncSession) -> None:
    """Snapshot DB counts into Prometheus gauges (called before each scrape)."""
    try:
        alert_count = (await db.execute(select(func.count()).select_from(Alert))).scalar() or 0
        ALERTS_GAUGE.set(alert_count)

        event_count = (await db.execute(select(func.count()).select_from(Event))).scalar() or 0
        EVENTS_GAUGE.set(event_count)

        five_min_ago = datetime.now(timezone.utc) - timedelta(minutes=5)
        active_agents = (await db.execute(
            select(func.count()).select_from(Agent).where(Agent.last_seen >= five_min_ago)
        )).scalar() or 0
        AGENTS_GAUGE.set(active_agents)

        PROCESS_CPU_GAUGE.set(_proc.cpu_percent(interval=None))
        PROCESS_MEMORY_BYTES.set(_proc.memory_info().rss)

    except Exception as exc:
        log.warning("gauge_refresh_failed", error=str(exc))


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get(
    "/metrics",
    summary="Prometheus metrics scrape endpoint (analyst+ JWT or METRICS_SCRAPE_TOKEN)",
    response_class=PlainTextResponse,
)
async def prometheus_metrics(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Exposes ASC backend metrics in Prometheus text format (version 0.0.4).

    Authentication: analyst+ JWT **or** static Bearer token (METRICS_SCRAPE_TOKEN env var).
    If neither is provided, returns 401.
    """
    # Accept either JWT (analyst+) or static scrape token
    has_token = _check_scrape_token(request)
    if not has_token:
        # Fall through to JWT validation
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Authentication required")
        try:
            from asc_api.core.security import decode_token_payload
            payload = decode_token_payload(auth_header[7:])
            user_id = payload.get("sub")
            if not user_id:
                raise HTTPException(status_code=401, detail="Invalid token")
            user_result = await db.execute(
                select(User).where(User.id == user_id)
            )
            user = user_result.scalar_one_or_none()
            if not user or user.role not in ("analyst", "admin"):
                raise HTTPException(status_code=403, detail="Analyst or admin role required")
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid token")

    await _refresh_gauges(db)
    output = generate_latest(REGISTRY)
    return PlainTextResponse(content=output.decode("utf-8"), media_type=CONTENT_TYPE_LATEST)


@router.get(
    "/summary",
    summary="JSON observability snapshot for the ASC portal status page (analyst+)",
)
async def observability_summary(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_analyst_or_admin),
):
    """
    Returns a JSON snapshot of key system metrics for the frontend status page.
    Includes DB counts, active agents, process CPU/memory, and Prometheus metric state.
    """
    await _refresh_gauges(db)

    mem = _proc.memory_info()
    cpu = _proc.cpu_percent(interval=None)

    # DB connectivity check
    try:
        await db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False

    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "process": {
            "cpu_percent":   round(cpu, 1),
            "memory_rss_mb": round(mem.rss / 1_048_576, 1),
            "memory_vms_mb": round(mem.vms / 1_048_576, 1),
            "pid":           _proc.pid,
        },
        "database": {
            "ok":           db_ok,
            "alerts_total": int(ALERTS_GAUGE._value.get()),
            "events_total": int(EVENTS_GAUGE._value.get()),
        },
        "agents": {
            "active_last_5min": int(AGENTS_GAUGE._value.get()),
        },
        "prometheus": {
            "metrics_endpoint": "/api/v1/observability/metrics",
            "scrape_token_configured": bool(getattr(settings, "METRICS_SCRAPE_TOKEN", None)),
        },
    }
