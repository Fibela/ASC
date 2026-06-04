from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

from app.core.config import get_settings
from app.core.logging import configure_logging
from app.db.session import engine
from app.db.base import Base
from app.api.v1.router import api_router

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging(debug=settings.DEBUG)
    # Create tables on startup (use Alembic migrations in production)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    await engine.dispose()


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
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
    """,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)


@app.get("/health", tags=["Health"])
async def health():
    return {"status": "ok", "app": settings.APP_NAME, "version": settings.APP_VERSION}
