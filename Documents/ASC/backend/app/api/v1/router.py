from fastapi import APIRouter
from app.api.v1.endpoints import (
    auth, analyze, events, alerts, iocs, metrics,
    neutralize, reports, detection, playbooks, adapters, health, agents, honeypot,
    notifications, iam, forensic, ops_dashboard, threat_intel, threat_hunting, pcdi,
    soar, pids, correlation, incidents, executive_reports, observability, api_keys,
    webhooks, tenants, onboarding, billing, adapter_registry, auth_sso,
)

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(auth.router)
api_router.include_router(analyze.router)
api_router.include_router(events.router)
api_router.include_router(alerts.router)
api_router.include_router(iocs.router)
api_router.include_router(metrics.router)
api_router.include_router(neutralize.router)
api_router.include_router(reports.router)
api_router.include_router(detection.router)
api_router.include_router(playbooks.router)
api_router.include_router(adapters.router)
api_router.include_router(health.router)
api_router.include_router(agents.router)
api_router.include_router(honeypot.router)
api_router.include_router(notifications.router)
api_router.include_router(iam.router)
api_router.include_router(forensic.router)
api_router.include_router(ops_dashboard.router)
api_router.include_router(threat_intel.router)
api_router.include_router(threat_hunting.router)
api_router.include_router(pcdi.router)
api_router.include_router(soar.router)
api_router.include_router(pids.router)
api_router.include_router(correlation.router)
api_router.include_router(incidents.router)
api_router.include_router(executive_reports.router)
api_router.include_router(observability.router)
api_router.include_router(api_keys.router)
api_router.include_router(webhooks.router)
api_router.include_router(tenants.router)
api_router.include_router(onboarding.router)
api_router.include_router(billing.router)
api_router.include_router(adapter_registry.router)
api_router.include_router(auth_sso.router)
