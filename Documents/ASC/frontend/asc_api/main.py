from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from asc_api.api.v1.router import api_router
from asc_api.core.api_key_rate_limit import api_key_limiter
from asc_api.core.config import get_settings
from asc_api.core.logging import configure_logging, get_logger
from asc_api.core.middleware import (
    ApiKeyRateLimitMiddleware,
    BodySizeLimitMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
)
from asc_api.core.notifications import notification_bus
from asc_api.core.rate_limit import limiter
from asc_api.core.startup_checks import run_startup_checks
from asc_api.core.tenant_middleware import TenantMiddleware
from asc_api.db.session import engine

settings = get_settings()
log = get_logger("asc.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging(debug=settings.DEBUG)
    log.info("asc_startup", app=settings.APP_NAME, version=settings.APP_VERSION, debug=settings.DEBUG)

    # Validate configuration before accepting traffic
    run_startup_checks(settings)

    # S103.8 — Chequeo de deriva de esquema al ARRANCAR: si un modelo referencia
    # una columna que la DB no tiene (migración pendiente), lo logueamos CLARO en
    # los logs de deploy en vez de tirar un 500 opaco por cada request (raíz del
    # incidente I-3). No aborta el arranque: liveness sigue arriba y readiness
    # reporta la deriva; el deploy-gate la caza. Nunca tumba el startup por sí mismo.
    try:
        from asc_api.core.schema_check import missing_model_columns
        from asc_api.db.session import AsyncSessionLocal

        async with AsyncSessionLocal() as _schema_db:
            _drift = await missing_model_columns(_schema_db)
        if _drift:
            log.error(
                "schema_drift_detected",
                missing_columns=_drift[:30],
                hint="Correr migraciones pendientes en Supabase (ver INCIDENTE I-3 en AUDIT_LOG).",
            )
        else:
            log.info("schema_check_passed")
    except Exception as _schema_exc:  # nunca abortar el arranque por el chequeo
        log.warning("schema_check_skipped", reason=type(_schema_exc).__name__)

    # Schema creation is managed by Alembic migrations (run once via `alembic upgrade head`).
    # On Vercel serverless, create_all on every cold start wastes a connection and adds
    # latency. The tables already exist in production — skip create_all entirely.

    # Notification bus: connect to Redis if configured, fall back to local mode
    bus_mode = await notification_bus.connect(settings.REDIS_URL)
    log.info("notification_bus_ready", mode=bus_mode)

    # P41 — API key rate limiter: connect to Redis (falls back to memory on failure)
    rl_mode = await api_key_limiter.connect(settings.REDIS_URL)
    log.info("api_key_rate_limiter_ready", mode=rl_mode)

    yield

    await notification_bus.disconnect()
    log.info("asc_shutdown", app=settings.APP_NAME)
    await engine.dispose()


# Hide API docs in production — exposing OpenAPI schema aids attackers
_docs_url = "/docs" if settings.DEBUG else None
_redoc_url = "/redoc" if settings.DEBUG else None
_openapi_url = "/openapi.json" if settings.DEBUG else None

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    redirect_slashes=False,
    description="""
## ASC PremosCorp — Advanced Security Center API

Motor de detección, análisis y neutralización de amenazas cibernéticas.

### Módulos
- **Analysis** — Análisis de artefactos, dominios e IPs
- **Events** — Ingesta y normalización de logs (SIEM)
- **Alerts** — Gestión de alertas y correlación
- **IoCs** — Base de indicadores de compromiso
- **Metrics** — KPIs SOC: MTTD, MTTR, cobertura
- **Neutralization** — Respuesta automatizada a incidentes
- **Reports** — Reportes PDF/HTML con branding PremosCorp
- **Adapters** — Integración SIEM/EDR/SOAR (ELK, Wazuh, TheHive)
- **Health** — Liveness, readiness y métricas de sistema
    """,
    docs_url=_docs_url,
    redoc_url=_redoc_url,
    openapi_url=_openapi_url,
    lifespan=lifespan,
)

# ── Rate limiter state ────────────────────────────────────────────────────────
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── Middleware stack (last added = outermost = runs first) ────────────────────
# Order (outermost → innermost):
#   ApiKeyRateLimit → SecurityHeaders → BodySizeLimit → CORS → Tenant → RequestContext → GZip → route
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(RequestContextMiddleware)
# P51 — tenant resolution runs after CORS (preflight passes through) and before routes
app.add_middleware(TenantMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS + settings.CORS_ORIGINS_EXTRA,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.REQUEST_MAX_BODY_BYTES)
app.add_middleware(SecurityHeadersMiddleware, debug=settings.DEBUG)
# P41 — API key rate limiting (outermost for X-API-Key path so it runs first)
app.add_middleware(
    ApiKeyRateLimitMiddleware,
    limit_per_minute=settings.RATE_LIMIT_API_KEY_PER_MINUTE,
    limit_per_hour=settings.RATE_LIMIT_API_KEY_PER_HOUR,
)

app.include_router(api_router)


# ── Root liveness (Docker / nginx healthcheck — no auth) ─────────────────────
@app.get("/health", tags=["Health"])
async def health():
    return {"status": "ok", "app": settings.APP_NAME, "version": settings.APP_VERSION}


# ── Structured 500 handler — no stack-trace leakage to clients ───────────────
@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    log.exception(
        "unhandled_exception",
        path=str(request.url.path),
        method=request.method,
        error_type=type(exc).__name__,
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error. Contact your administrator."},
    )
