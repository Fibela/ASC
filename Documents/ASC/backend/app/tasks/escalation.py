"""
Proactive Escalation Task — P16.3 deuda técnica

Runs every ESCALATION_CHECK_INTERVAL_SECONDS (default: 60s) via Celery Beat.
Finds all pending_approval NeutralizationActions whose expires_at has passed
and transitions them to 'escalated' — proactively, without waiting for an
analyst to open the dashboard.

This complements the existing lazy escalation in approval.escalate_expired()
(called on list/get endpoints). The Celery task ensures actions escalate even
if no analyst is actively polling the API.

SSE events are published via direct Redis publish so all connected FastAPI
workers receive the notification, regardless of which worker runs the task.
In local mode (no Redis), the DB update still happens — SSE is best-effort.
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

from asc_api.core.config import get_settings
from asc_api.core.logging import get_logger
from asc_api.core.notifications import NOTIFICATION_CHANNEL
from asc_api.db.session import AsyncSessionLocal
from asc_api.services.approval import escalate_expired
from asc_api.tasks.celery_app import celery_app

log = get_logger("asc.tasks.escalation")


async def _run() -> dict:
    """Core async logic: escalate expired actions and publish SSE events."""
    settings = get_settings()
    escalated_ids: list[str] = []

    async with AsyncSessionLocal() as db:
        escalated_ids = await escalate_expired(db)

    if not escalated_ids:
        return {"escalated": 0}

    # Publish SSE to Redis so connected FastAPI workers notify analysts
    if settings.REDIS_URL:
        try:
            import redis.asyncio as aioredis  # type: ignore[import]
            r = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
            for action_id in escalated_ids:
                payload = json.dumps({
                    "event_type": "action_escalated",
                    "payload":    {"action_id": action_id, "source": "celery_beat"},
                    "timestamp":  datetime.now(timezone.utc).isoformat(),
                })
                await r.publish(NOTIFICATION_CHANNEL, payload)
            await r.aclose()
        except Exception as exc:
            log.warning("escalation_redis_publish_failed", exc_info=exc)

    log.info("proactive_escalation_complete", escalated=len(escalated_ids))
    return {"escalated": len(escalated_ids), "action_ids": escalated_ids}


@celery_app.task(
    name="asc.escalation.check_expired_actions",
    bind=True,
    max_retries=3,
    default_retry_delay=30,
)
def check_expired_actions(self) -> dict:
    """
    Celery task: proactively escalate expired pending_approval actions.

    Uses asyncio.run() to execute async DB logic within the synchronous
    Celery worker context.  Each invocation opens its own DB session so
    there are no connection pool conflicts with the FastAPI event loop.
    """
    try:
        return asyncio.run(_run())
    except Exception as exc:
        log.error("escalation_task_error", exc_info=exc)
        raise self.retry(exc=exc)
