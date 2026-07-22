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

    # Deriva de esquema (S103.8): modelos ORM vs columnas reales de la DB.
    # Cierra el modo de fallo del incidente I-3 (columna faltante + SELECT 1 verde).
    schema_missing: list[str] = []
    if db_ok:
        try:
            from asc_api.core.schema_check import missing_model_columns
            schema_missing = await missing_model_columns(db)
        except Exception as exc:  # el chequeo nunca debe tumbar readiness
            schema_missing = [f"check_error:{type(exc).__name__}"]
    schema_ok = not schema_missing

    all_ok = db_ok and redis_ok and schema_ok
    return {
        "status": "ready" if all_ok else "degraded",
        "checks": {
            "database": {"ok": db_ok, "detail": db_msg},
            "schema": {"ok": schema_ok, "missing": schema_missing[:20]},
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


# ── Platform heartbeat monitoring (S108-Ops.1) ────────────────────────────────
#
# Lee platform_heartbeats (escrita por los crons de Vercel y el watchdog externo
# de Supabase) y reporta frescura por-job. Rompe el límite "Vercel no se monitorea
# a sí mismo": el watchdog escribe desde AWS (infra independiente).
#
# Umbrales = intervalo del job + margen. Público expone SOLO el resumen (evita
# revelar la cadencia operativa a un atacante); el detalle por-job va con auth.

_STALE_AFTER: dict[str, int] = {
    "cron-heartbeat":          180,   # */1  → 3 min (si se agenda)
    "cron-escalation":         720,   # */5  → 12 min
    "cron-pcdi-scan":          720,   # */5  → 12 min
    "cron-sla-check":         1320,   # */10 → 22 min
    "cron-correlation-sweep": 1800,   # */15 → 30 min
    "cron-scheduled-reports": 5400,   # 0 *  → 90 min
    "watchdog-supabase":       360,   # */2  → 6 min (señal externa)
}
_DEFAULT_STALE = 900  # jobs no listados → 15 min


async def _load_platform_jobs(db: AsyncSession) -> list[dict] | None:
    """Devuelve el estado por-job, o None si la tabla no existe (degradación honesta)."""
    now = datetime.now(timezone.utc)
    try:
        rows = (await db.execute(text(
            "SELECT id, last_seen_at, last_status, consecutive_failures, detail "
            "FROM platform_heartbeats"
        ))).mappings().all()
    except Exception:
        return None  # tabla ausente (migración pendiente) o error → 'unknown'
    jobs: list[dict] = []
    for r in rows:
        last = r["last_seen_at"]
        if isinstance(last, str):                      # SQLite/aiosqlite devuelve texto
            try:
                last = datetime.fromisoformat(last)
            except ValueError:
                last = None
        if last is not None and last.tzinfo is None:   # Postgres puede venir naive
            last = last.replace(tzinfo=timezone.utc)
        age = (now - last).total_seconds() if last else None
        threshold = _STALE_AFTER.get(r["id"], _DEFAULT_STALE)
        jobs.append({
            "id": r["id"],
            "last_seen_at": last.isoformat() if last else None,
            "age_seconds": round(age) if age is not None else None,
            "threshold_seconds": threshold,
            "stale": (age is None) or (age > threshold),
            "last_status": r["last_status"],
            "consecutive_failures": r["consecutive_failures"],
            "detail": r["detail"],
        })
    return jobs


def _overall_platform_status(jobs: list[dict] | None) -> str:
    if not jobs:                      # None (tabla ausente) o vacío
        return "unknown"
    stale = any(j["stale"] for j in jobs)
    errored = any(j["last_status"] != "ok" for j in jobs)
    return "operational" if not (stale or errored) else "degraded"


@router.get("/platform", summary="Resumen público de salud de plataforma (frescura de latidos)")
async def platform_health(db: AsyncSession = Depends(get_db)):
    """Público: solo resumen (status + conteos). Sin nombres/timing por-job."""
    jobs = await _load_platform_jobs(db)
    return {
        "status": _overall_platform_status(jobs),   # operational | degraded | unknown
        "jobs_total": len(jobs) if jobs else 0,
        "jobs_stale": sum(1 for j in (jobs or []) if j["stale"]),
        "ts": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/platform/detail", summary="Detalle de latidos por-job (analyst+)")
async def platform_health_detail(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_analyst_or_admin),
):
    """Con auth: detalle por-job (nombres, edad, fallos, umbral)."""
    from asc_api.services.reachability import assess_distributed_reachability
    jobs = await _load_platform_jobs(db)
    try:
        distributed = await assess_distributed_reachability(db)
    except Exception:
        distributed = {"classification": "unknown"}
    return {
        "status": _overall_platform_status(jobs),
        "jobs": jobs or [],
        "distributed": distributed,   # Capa 3: red SPECTER como monitor distribuido
        "ts": datetime.now(timezone.utc).isoformat(),
    }


# ── Página de estado PÚBLICA (S108.3 — sin auth) ──────────────────────────────
#
# Un cliente debe poder ver "¿ASC está arriba?" SIN loguearse (justo cuando está
# caído no podría entrar). Página HTML autocontenida que lee readiness + platform.

def _status_badge(state: str) -> tuple[str, str]:
    return {
        "operational": ("Operativo", "#3ECF8E"),
        "degraded":    ("Degradado", "#F2860A"),
        "down":        ("Caído",     "#8B1E1E"),
        "unknown":     ("Sin datos", "#9CA3AF"),
    }.get(state, ("Sin datos", "#9CA3AF"))


@router.get("/status", summary="Página de estado PÚBLICA (HTML, sin auth)")
async def public_status_page(db: AsyncSession = Depends(get_db)):
    from fastapi.responses import HTMLResponse

    # API: si respondemos, está arriba.
    api_ok = True
    # DB: ping simple.
    try:
        await db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False
    # Monitoreo: frescura de latidos.
    try:
        jobs = await _load_platform_jobs(db)
    except Exception:
        jobs = None
    mon_state = _overall_platform_status(jobs)

    # Estado global = lo peor de los componentes.
    if not db_ok:
        overall = "down"
    elif mon_state in ("degraded", "unknown") or not api_ok:
        overall = "degraded" if api_ok and db_ok else "down"
    else:
        overall = "operational"

    o_label, o_color = _status_badge(overall)
    comps = [
        ("API", "operational" if api_ok else "down"),
        ("Base de datos", "operational" if db_ok else "down"),
        ("Monitoreo", mon_state),
    ]
    rows = ""
    for name, st in comps:
        lbl, col = _status_badge(st)
        rows += (
            f'<div class="row"><span>{name}</span>'
            f'<span class="pill" style="color:{col};border-color:{col}">{lbl}</span></div>'
        )

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    html = f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="60">
<title>Estado — ASC PremosCorp</title>
<style>
  body{{background:#0A0A0A;color:#EAEAEA;font-family:Inter,system-ui,sans-serif;margin:0;padding:48px 16px}}
  .card{{max-width:560px;margin:0 auto;background:#111;border:1px solid #222;border-radius:16px;padding:32px}}
  .brand{{color:#E85D04;font-weight:800;letter-spacing:.5px}}
  h1{{font-size:22px;margin:8px 0 4px}}
  .sub{{color:#9CA3AF;font-size:13px;margin-bottom:24px}}
  .banner{{display:flex;align-items:center;gap:12px;background:#0d0d0d;border:1px solid {o_color};
           border-radius:12px;padding:16px 20px;margin-bottom:24px}}
  .dot{{width:12px;height:12px;border-radius:50%;background:{o_color}}}
  .banner b{{color:{o_color};font-size:18px}}
  .row{{display:flex;justify-content:space-between;align-items:center;padding:12px 4px;border-top:1px solid #1c1c1c}}
  .pill{{border:1px solid;border-radius:999px;padding:3px 12px;font-size:12px}}
  .foot{{color:#6b7280;font-size:12px;margin-top:24px;text-align:center}}
</style></head><body>
<div class="card">
  <div class="brand">PremosCorp · ASC</div>
  <h1>Estado del servicio</h1>
  <div class="sub">Analizador de Seguridad Cibernética</div>
  <div class="banner"><span class="dot"></span><b>{o_label}</b></div>
  {rows}
  <div class="foot">Actualizado: {now} · se refresca cada 60 s</div>
</div></body></html>"""
    return HTMLResponse(content=html)
