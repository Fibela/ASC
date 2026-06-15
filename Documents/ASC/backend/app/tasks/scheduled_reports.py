"""
Scheduled Reports Celery Task — P25-S2

Runs every hour via Celery Beat.
Delivers due ScheduledReport entries (daily → >24h since last send, weekly → >7d).

Design:
  - Self-contained: opens its own AsyncSession, no shared state.
  - Best-effort delivery: failed sends are logged + last_error stored; task continues.
  - Non-fatal: exceptions per-report are caught; the full batch still completes.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from app.core.logging import get_logger
from app.db.session import AsyncSessionLocal
from app.tasks.celery_app import celery_app

log = get_logger("asc.tasks.scheduled_reports")

_DAILY_INTERVAL  = timedelta(hours=24)
_WEEKLY_INTERVAL = timedelta(days=7)


def _is_due(last_sent_at: datetime | None, frequency: str) -> bool:
    if last_sent_at is None:
        return True
    now = datetime.now(timezone.utc)
    if last_sent_at.tzinfo is None:
        last_sent_at = last_sent_at.replace(tzinfo=timezone.utc)
    interval = _DAILY_INTERVAL if frequency == "daily" else _WEEKLY_INTERVAL
    return (now - last_sent_at) >= interval


async def _run() -> dict:
    from sqlalchemy import select
    from app.models.soar import ScheduledReport
    from app.services.soar_service import deliver_scheduled_report

    sent = 0
    skipped = 0
    errors = 0

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(ScheduledReport).where(ScheduledReport.enabled.is_(True))
        )
        reports = list(result.scalars().all())

        for r in reports:
            if not _is_due(r.last_sent_at, r.frequency):
                skipped += 1
                continue
            try:
                outcome = await deliver_scheduled_report(db, r.id)
                if outcome.get("error"):
                    errors += 1
                    log.warning(
                        "scheduled_report_error",
                        report_id=r.id,
                        recipient=r.recipient_email,
                        error=outcome["error"],
                    )
                else:
                    sent += 1
                    log.info(
                        "scheduled_report_sent",
                        report_id=r.id,
                        recipient=r.recipient_email,
                        frequency=r.frequency,
                    )
            except Exception as exc:  # noqa: BLE001
                errors += 1
                log.error("scheduled_report_task_error", report_id=r.id, exc=str(exc))

    log.info(
        "scheduled_reports_complete",
        total=len(reports),
        sent=sent,
        skipped=skipped,
        errors=errors,
    )
    return {"total": len(reports), "sent": sent, "skipped": skipped, "errors": errors}


@celery_app.task(
    name="asc.scheduled_reports.deliver_due_reports",
    bind=True,
    max_retries=1,
    default_retry_delay=300,
)
def deliver_due_reports(self) -> dict:
    """
    Celery task: scan all enabled ScheduledReports, deliver those that are due.
    Runs every hour via Celery Beat (configured in celery_app.beat_schedule).
    """
    try:
        return asyncio.run(_run())
    except Exception as exc:
        log.error("scheduled_reports_task_error", exc_info=exc)
        raise self.retry(exc=exc)
