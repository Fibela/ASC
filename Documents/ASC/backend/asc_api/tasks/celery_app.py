"""
ASC Celery Application — P16.3 deudas técnicas

Broker and backend: Redis when REDIS_URL is configured; memory:// otherwise.

REDIS_URL empty (Fase 1 — Supabase free tier, no Redis):
  Celery is defined but no worker/beat process runs. All periodic tasks
  (escalation, SLA checks, scheduled reports, correlation sweep) are
  inactive. The rest of the backend (API, SPECTER, SOAR, playbooks, SSE
  local mode) functions normally without Redis.

REDIS_URL set (Fase 2 — Docker Compose or Upstash):
  Full Celery with Beat scheduler active.
  Starting the worker:
    celery -A app.tasks.celery_app worker --loglevel=info
  Starting beat:
    celery -A app.tasks.celery_app beat --loglevel=info
  Combined (dev only):
    celery -A app.tasks.celery_app worker --beat --loglevel=info

Docker Compose: see docker-compose.yml celery-worker + celery-beat services.
See docs/deployment-guide.md for the Fase 1 → Fase 2 migration plan.
"""

import logging

from celery import Celery

from asc_api.core.config import get_settings

settings = get_settings()

# Graceful degradation: use in-memory broker when Redis is not configured.
# memory:// is single-process only — no external worker needed, but tasks
# will NOT execute unless a worker loop is started in the same process.
# This is intentional for Fase 1 (Supabase/Vercel/Render, no Redis).
_broker = settings.REDIS_URL or "memory://"
_backend = settings.REDIS_URL or "cache+memory://"

if not settings.REDIS_URL:
    logging.getLogger("asc.celery").warning(
        "REDIS_URL not set — Celery running in no-op mode. "
        "Periodic tasks (escalation, SLA, reports, correlation) are inactive. "
        "Set REDIS_URL (Upstash free tier or Docker Redis) to activate."
    )

celery_app = Celery(
    "asc",
    broker=_broker,
    backend=_backend,
    include=[
        "app.tasks.escalation",
        "app.tasks.pcdi_escalation",  # PCDI-driven critical findings escalation (P24+)
        "app.tasks.scheduled_reports",  # SOAR scheduled report delivery (P25)
        "app.tasks.correlation_sweep",  # Cross-domain correlation engine sweep (P27)
        "app.tasks.sla_escalation",  # PIIL SLA breach proactive escalation (P30)
    ],
)

_PCDI_INTERVAL = getattr(settings, "PCDI_ESCALATION_INTERVAL_SECONDS", 300)
_SLA_INTERVAL = getattr(settings, "SLA_ESCALATION_CHECK_INTERVAL_SECONDS", 120)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    worker_prefetch_multiplier=1,  # one task at a time per worker (safe for async DB)
    task_acks_late=True,  # ack after task completes — no lost tasks on crash
    task_reject_on_worker_lost=True,
    beat_schedule={
        "proactive-escalation": {
            "task": "asc.escalation.check_expired_actions",
            "schedule": settings.ESCALATION_CHECK_INTERVAL_SECONDS,
            "options": {"expires": settings.ESCALATION_CHECK_INTERVAL_SECONDS * 2},
        },
        "pcdi-critical-findings": {
            "task": "asc.pcdi_escalation.check_critical_findings",
            "schedule": _PCDI_INTERVAL,
            "options": {"expires": _PCDI_INTERVAL * 2},
        },
        "soar-scheduled-reports": {
            "task": "asc.scheduled_reports.deliver_due_reports",
            "schedule": 3600,  # every hour
            "options": {"expires": 7200},
        },
        "correlation-sweep": {
            "task": "asc.correlation_sweep.run_sweep",
            "schedule": getattr(settings, "CORRELATION_SWEEP_INTERVAL_SECONDS", 900),
            "options": {"expires": 1800},
        },
        "sla-breach-escalation": {
            "task": "asc.sla_escalation.check_sla_breaches",
            "schedule": _SLA_INTERVAL,
            "options": {"expires": _SLA_INTERVAL * 2},
        },
    },
)
