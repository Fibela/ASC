"""
PCDI Critical-Findings Escalation Task — P24 Post-Sprint

Runs every PCDI_ESCALATION_INTERVAL_SECONDS (default 300s = 5 min) via Celery Beat.

For each active hunt with unscored or low-scored findings that have indicator values,
recomputes the PCDI adaptive score. When score >= PCDI_CRITICAL_THRESHOLD (80):

  1. Upgrades the hunt priority to 'critical' (if not already critical).
  2. Logs a structured security event via log_security_action.
  3. Publishes an SSE notification so connected analysts are alerted immediately.

This converts PCDI adaptive scoring from a purely lazy (analyst-triggered) flow
into a proactive Celery-backed monitoring loop for critical threats.

Design principles:
  - Scoring is READ-ONLY on production data; only hunt.priority may be upgraded.
  - Self-contained: each invocation opens its own DB session.
  - Non-fatal: scoring failures are logged and skipped, not retried infinitely.
  - SSE publication is best-effort (Redis unavailable → skip, DB update still happens).
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from asc_api.core.logging import get_logger
from asc_api.db.session import AsyncSessionLocal
from asc_api.tasks.celery_app import celery_app

log = get_logger("asc.tasks.pcdi_escalation")

PCDI_CRITICAL_THRESHOLD = 80


async def _run() -> dict:
    """Core async logic: score unreviewed high-risk findings, escalate critical hunts."""
    from sqlalchemy import select

    from asc_api.core.audit import log_security_action
    from asc_api.core.notifications import notification_bus
    from asc_api.models.hunt import Hunt, HuntFinding
    from asc_api.services.pcdi_service import compute_adaptive_score

    escalated_hunts: list[str] = []
    scored_findings = 0

    async with AsyncSessionLocal() as db:
        # Load active hunts
        hunts_result = await db.execute(select(Hunt).where(Hunt.status == "active"))
        active_hunts = hunts_result.scalars().all()

        for hunt in active_hunts:
            # Load findings with observable indicators not yet confirmed/FP
            findings_result = await db.execute(
                select(HuntFinding).where(
                    HuntFinding.hunt_id == hunt.id,
                    HuntFinding.is_confirmed.is_(False),
                    HuntFinding.is_false_positive.is_(False),
                    HuntFinding.indicator_value.is_not(None),
                )
            )
            findings = findings_result.scalars().all()

            max_score = 0
            for finding in findings:
                try:
                    score_result = await compute_adaptive_score(db, finding.id)
                    if "error" in score_result:
                        continue
                    score = score_result.get("adaptive_score", 0)
                    if score > max_score:
                        max_score = score
                    scored_findings += 1
                except Exception as exc:
                    log.warning(
                        "pcdi_escalation_score_error",
                        finding_id=finding.id,
                        exc=str(exc),
                    )

            # Escalate hunt priority if max_score hits critical threshold
            if max_score >= PCDI_CRITICAL_THRESHOLD and hunt.priority != "critical":
                old_priority = hunt.priority
                hunt.priority = "critical"
                await db.commit()
                escalated_hunts.append(hunt.id)

                log_security_action(
                    "pcdi_auto_escalation",
                    user_id="celery",
                    role="system",
                    resource="hunt",
                    resource_id=hunt.id,
                    detail=(
                        f"PCDI max_score={max_score} >= {PCDI_CRITICAL_THRESHOLD}. "
                        f"Hunt priority upgraded: {old_priority} → critical. "
                        f"Findings scored: {len(findings)}"
                    ),
                    status="ok",
                )
                log.warning(
                    "pcdi_hunt_escalated",
                    hunt_id=hunt.id,
                    hunt_name=hunt.name,
                    max_score=max_score,
                    old_priority=old_priority,
                )

                # SSE notification (best-effort)
                try:
                    asyncio.ensure_future(
                        notification_bus.publish(
                            "pcdi_hunt_escalated",
                            {
                                "hunt_id": hunt.id,
                                "hunt_name": hunt.name,
                                "max_pcdi_score": max_score,
                                "old_priority": old_priority,
                                "new_priority": "critical",
                                "ts": datetime.now(UTC).isoformat(),
                            },
                        )
                    )
                except Exception as exc:
                    log.debug("pcdi_escalation_sse_skipped", exc=str(exc))

    log.info(
        "pcdi_escalation_complete",
        active_hunts_checked=len(active_hunts),
        findings_scored=scored_findings,
        hunts_escalated=len(escalated_hunts),
    )
    return {
        "active_hunts_checked": len(active_hunts),
        "findings_scored": scored_findings,
        "hunts_escalated": len(escalated_hunts),
        "escalated_hunt_ids": escalated_hunts,
    }


@celery_app.task(
    name="asc.pcdi_escalation.check_critical_findings",
    bind=True,
    max_retries=2,
    default_retry_delay=60,
)
def check_critical_findings(self) -> dict:
    """
    Celery task: proactively score PCDI findings and escalate critical hunts.

    Complements the lazy (analyst-triggered) PCDI scoring in the API.
    Runs every PCDI_ESCALATION_INTERVAL_SECONDS via Celery Beat.
    """
    try:
        return asyncio.run(_run())
    except Exception as exc:
        log.error("pcdi_escalation_task_error", exc_info=exc)
        raise self.retry(exc=exc)
