"""
Celery task — P27-B Correlation Engine sweep.

Runs on a configurable beat schedule (default: every 15 minutes).
Creates an async DB session, calls run_correlation_sweep(), and logs the result.

Task name: asc.correlation_sweep.run_sweep
"""
from __future__ import annotations

import asyncio

from asc_api.tasks.celery_app import celery_app
from asc_api.core.logging import get_logger

log = get_logger(__name__)


@celery_app.task(name="asc.correlation_sweep.run_sweep", bind=True, max_retries=2)
def run_sweep(self):  # type: ignore[override]
    """Periodic correlation sweep — groups cross-domain signals into clusters."""
    try:
        asyncio.run(_async_sweep())
    except Exception as exc:
        log.exception("correlation_sweep task failed: %s", exc)
        raise self.retry(exc=exc, countdown=60)


async def _async_sweep() -> None:
    from asc_api.db.session import AsyncSessionLocal
    from asc_api.services.correlation_service import run_correlation_sweep

    async with AsyncSessionLocal() as db:
        stats = await run_correlation_sweep(db)
        log.info("correlation_sweep completed: %s", stats)
