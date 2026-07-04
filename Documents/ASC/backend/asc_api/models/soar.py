"""
SOAR — P25 Data Models

PlaybookTrigger: condition-based auto-trigger for playbooks.
  Evaluated on every PCDI escalation, finding creation, and PANL action.

ScheduledReport: recurring hunt report delivery.
  Celery Beat sends PDF/JSON reports on daily/weekly cadence.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from asc_api.db.base import Base


class PlaybookTrigger(Base):
    """
    Condition-based SOAR trigger: when condition is met, auto-fire a playbook.

    Condition types:
      pcdi_score       — adaptive_score >= threshold (float 0-100)
      finding_severity — finding.severity in values (e.g. "critical,high")
      hunt_priority    — hunt.priority == value
      panl_status      — neutralization action reaches status

    Operators: gte, lte, eq, contains (type-dependent)
    """
    __tablename__ = "playbook_triggers"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    playbook_id: Mapped[str] = mapped_column(String(20), nullable=False)
    playbook_name: Mapped[str] = mapped_column(String(256), nullable=False, default="")

    # Condition spec
    condition_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # pcdi_score | finding_severity | hunt_priority | panl_status
    condition_operator: Mapped[str] = mapped_column(
        String(20), nullable=False, default="gte"
    )  # gte | lte | eq | contains
    condition_value: Mapped[str] = mapped_column(
        String(256), nullable=False
    )  # "80" for score, "critical" for severity, etc.

    # Scope
    hunt_id_filter: Mapped[str | None] = mapped_column(
        String(36), nullable=True
    )  # None = apply to all hunts

    # Adaptive orchestration — P26
    priority: Mapped[int] = mapped_column(
        Integer, nullable=False, default=5
    )  # 1 (lowest) – 10 (highest); triggers evaluated highest-first
    rate_limit_per_hour: Mapped[int] = mapped_column(
        Integer, nullable=False, default=10
    )  # max fires per hour (0 = unlimited)
    dedup_window_minutes: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )  # skip if same playbook awaiting_approval in last N min (0 = no dedup)

    # State
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    trigger_count: Mapped[int] = mapped_column(Integer, default=0)
    last_triggered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_triggered_context: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Audit
    created_by: Mapped[str] = mapped_column(String(256), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        Index("ix_pt_playbook_id", "playbook_id"),
        Index("ix_pt_condition_type", "condition_type"),
        Index("ix_pt_enabled", "enabled"),
    )


class ScheduledReport(Base):
    """
    Recurring hunt report delivery via Celery Beat.

    Generates a PCDI-signed summary PDF/JSON for a hunt and delivers
    it to the specified email address on the configured cadence.
    """
    __tablename__ = "scheduled_reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    hunt_id: Mapped[str] = mapped_column(String(36), nullable=False)
    hunt_name: Mapped[str | None] = mapped_column(String(256), nullable=True)

    # Delivery
    recipient_email: Mapped[str] = mapped_column(String(256), nullable=False)
    frequency: Mapped[str] = mapped_column(
        String(20), nullable=False, default="daily"
    )  # daily | weekly
    format: Mapped[str] = mapped_column(
        String(10), nullable=False, default="json"
    )  # json | pdf (pdf requires weasyprint)

    # State
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    send_count: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Audit
    created_by: Mapped[str] = mapped_column(String(256), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        Index("ix_sr_hunt_id", "hunt_id"),
        Index("ix_sr_enabled", "enabled"),
        Index("ix_sr_frequency", "frequency"),
    )
