"""
ASC Celery Task — SLA Breach Escalation (P30-CELERY)

Periodically scans open incidents for SLA violations and fires SOAR
triggers where condition_type='incident_sla_breach' via the PIIL bridge.

Schedule: every SLA_ESCALATION_CHECK_INTERVAL_SECONDS (default 120s).
"""

import asyncio

from asc_api.db.session import AsyncSessionLocal
from asc_api.services.soar_incident_bridge import escalate_sla_breaches
from asc_api.tasks.celery_app import celery_app


async def _run() -> dict:
    async with AsyncSessionLocal() as db:
        escalated = await escalate_sla_breaches(db)
    return {"sla_escalated": escalated}


@celery_app.task(
    name="asc.sla_escalation.check_sla_breaches",
    bind=True,
    max_retries=3,
    default_retry_delay=30,
)
def check_sla_breaches(self) -> dict:
    try:
        return asyncio.run(_run())
    except Exception as exc:
        raise self.retry(exc=exc)
