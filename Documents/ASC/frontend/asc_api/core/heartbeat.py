"""
Platform heartbeat emitter.

Each Vercel Cron endpoint calls emit_heartbeat(job_id) after completing its work.
The Supabase watchdog Edge Function also writes via this same table using
job_id='watchdog-supabase', providing an external independent signal.

Staleness thresholds: see STALE_AFTER in health.py /platform endpoint.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import text

from asc_api.core.logging import get_logger
from asc_api.db.session import AsyncSessionLocal

log = get_logger("asc.heartbeat")

_UPSERT = text("""
    INSERT INTO platform_heartbeats
        (id, last_seen_at, last_status, consecutive_failures, detail)
    VALUES
        (:id, :ts, :status, 0, :detail)
    ON CONFLICT (id) DO UPDATE SET
        last_seen_at          = :ts,
        last_status           = :status,
        consecutive_failures  = CASE
            WHEN :status = 'ok' THEN 0
            ELSE platform_heartbeats.consecutive_failures + 1
        END,
        detail = :detail
""")


async def emit_heartbeat(
    job_id: str,
    status: str = "ok",
    detail: str | None = None,
) -> None:
    """Write or refresh a heartbeat row. Never raises — a monitoring failure
    must not cascade into the cron job that triggered it."""
    try:
        async with AsyncSessionLocal() as db:
            await db.execute(
                _UPSERT,
                {
                    "id": job_id,
                    "ts": datetime.now(timezone.utc),
                    "status": status,
                    "detail": detail,
                },
            )
            await db.commit()
    except Exception as exc:
        log.warning("heartbeat_emit_failed", job_id=job_id, exc_info=exc)
