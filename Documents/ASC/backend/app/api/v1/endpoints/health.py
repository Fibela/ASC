"""
Health & Observability endpoints — Priority 12 / P21-F3.

GET /api/v1/health/liveness   — Is the process alive?          (no auth, used by Docker / LB)
GET /api/v1/health/readiness  — Is it ready to serve traffic?  (no auth, DB ping)
GET /api/v1/health/system     — Version, uptime, environment   (requires JWT — internal use)
GET /api/v1/health/adapters   — Live probe every configured adapter (analyst+) [P21-F3]
"""

import asyncio
import time
from datetime import datetime, timezone

import psutil
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.api.deps import get_current_user, get_analyst_or_admin
from asc_api.core.config import get_settings
from asc_api.db.session import get_db
from asc_api.models.user import User

_proc = psutil.Process()

router = APIRouter(prefix="/health", tags=["Health & Observability"])

_STARTUP_TIME: float = time.time()
settings = get_settings()


# ── Pure helper (tested independently) ────────────────────────────────────────

def format_uptime(seconds: int) -> str:
    """Human-readable uptime string.  e.g. 1d 3h 5m 2s"""
    d, rem = divmod(int(seconds), 86_400)
    h, rem = divmod(rem, 3_600)
    m, s   = divmod(rem, 60)
    parts: list[str] = []
    if d: parts.append(f"{d}d")
    if h: parts.append(f"{h}h")
    if m: parts.append(f"{m}m")
    parts.append(f"{s}s")
    return " ".join(parts)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/liveness", summary="Liveness — is the process running?")
async def liveness():
    """
    Simple alive-check with no dependencies.
    Docker / load-balancers should hit this endpoint for container health.
    """
    return {
        "status": "alive",
        "ts": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/readiness", summary="Readiness — database + Redis connectivity check")
async def readiness(db: AsyncSession = Depends(get_db)):
    """
    Verifies that the service can reach the database and (if configured) Redis.
    Returns 'ready' when all checks pass, 'degraded' otherwise.
    HTTP status is always 200 — callers inspect the 'status' field.
    """
    try:
        await db.execute(text("SELECT 1"))
        db_ok, db_msg = True, "ok"
    except Exception as exc:
        db_ok, db_msg = False, str(exc)

    redis_ok, redis_msg = True, "not_configured"
    if settings.REDIS_URL:
        try:
            import redis.asyncio as aioredis  # type: ignore[import]
            r = aioredis.from_url(settings.REDIS_URL, socket_connect_timeout=2)
            await r.ping()
            await r.aclose()
            redis_ok, redis_msg = True, "ok"
        except Exception as exc:
            redis_ok, redis_msg = False, type(exc).__name__

    all_ok = db_ok and redis_ok
    return {
        "status": "ready" if all_ok else "degraded",
        "checks": {
            "database": {"ok": db_ok, "detail": db_msg},
            "redis": {"ok": redis_ok, "detail": redis_msg},
        },
        "ts": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/system", summary="System info — version, uptime, environment + CPU/mem (JWT required)")
async def system_info(_: User = Depends(get_current_user)):
    """
    Returns build, runtime, and process resource metadata.
    Requires authentication — environment and resource details must not be exposed publicly.
    """
    uptime_s = time.time() - _STARTUP_TIME
    mem = _proc.memory_info()
    cpu = _proc.cpu_percent(interval=None)  # non-blocking; first call always returns 0.0

    return {
        "app":            settings.APP_NAME,
        "version":        settings.APP_VERSION,
        "environment":    "development" if settings.DEBUG else "production",
        "uptime_seconds": round(uptime_s),
        "uptime_human":   format_uptime(int(uptime_s)),
        "process": {
            "pid":            _proc.pid,
            "cpu_percent":    round(cpu, 1),
            "memory_rss_mb":  round(mem.rss / 1_048_576, 1),
            "memory_vms_mb":  round(mem.vms / 1_048_576, 1),
        },
        "ts":             datetime.now(timezone.utc).isoformat(),
    }


@router.get("/adapters", summary="Live probe all configured adapters (analyst+) — P21-F3")
async def adapter_health(_: User = Depends(get_analyst_or_admin)):
    """
    Probes every configured ASC adapter (ELK, Wazuh, TheHive, PaloAlto/Fortinet, AD).
    Returns a per-adapter status: configured | reachable | unreachable | not_configured.

    Each probe is run with a 5-second timeout and executed in parallel.
    Only adapters whose `is_configured()` returns True are probed — unconfigured adapters
    are returned with status "not_configured" so operators know what to set up.
    Requires analyst or admin JWT — adapter details must not leak publicly.
    """
    from asc_api.adapters import ADAPTERS

    async def _probe(name: str, adapter_cls) -> dict:
        adapter = adapter_cls()
        if not adapter.is_configured():
            return {"adapter": name, "status": "not_configured", "detail": "Required env vars not set"}
        try:
            result = await asyncio.wait_for(adapter.test_connection(), timeout=5.0)
            return {
                "adapter": name,
                "status": "reachable" if result.get("success") else "unreachable",
                "detail": result.get("error") or result.get("message") or "ok",
            }
        except asyncio.TimeoutError:
            return {"adapter": name, "status": "unreachable", "detail": "Timeout after 5s"}
        except Exception as exc:
            return {"adapter": name, "status": "unreachable", "detail": str(exc)}

    probes = await asyncio.gather(*[
        _probe(name, cls) for name, cls in ADAPTERS.items()
    ])

    results = list(probes)
    configured_count = sum(1 for r in results if r["status"] != "not_configured")
    reachable_count  = sum(1 for r in results if r["status"] == "reachable")

    return {
        "total_adapters":     len(results),
        "configured":         configured_count,
        "reachable":          reachable_count,
        "unreachable":        configured_count - reachable_count,
        "adapters":           results,
        "ts":                 datetime.now(timezone.utc).isoformat(),
    }
