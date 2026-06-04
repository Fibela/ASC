from fastapi import APIRouter
from app.api.v1.endpoints import analyze, events, alerts, iocs, metrics, neutralize, reports

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(analyze.router)
api_router.include_router(events.router)
api_router.include_router(alerts.router)
api_router.include_router(iocs.router)
api_router.include_router(metrics.router)
api_router.include_router(neutralize.router)
api_router.include_router(reports.router)
