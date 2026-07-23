import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from asc_api.db.base import Base


class PlaybookRun(Base):
    """Execution record for a single playbook invocation."""

    __tablename__ = "playbook_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # Playbook identity
    playbook_id: Mapped[str] = mapped_column(String(20), nullable=False)  # PB-001…PB-004
    playbook_name: Mapped[str] = mapped_column(String(256), nullable=False)

    # What triggered this run
    trigger_source: Mapped[str] = mapped_column(
        String(30), nullable=False
    )  # manual | auto_detection | auto_fingerprint
    trigger_data: Mapped[dict] = mapped_column(JSON, default=dict)  # raw event / fingerprint payload

    # Risk context
    semaphore: Mapped[str] = mapped_column(String(10), nullable=False)  # green | yellow | red
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    # Execution state
    status: Mapped[str] = mapped_column(
        String(30), nullable=False, default="pending"
    )  # pending | running | awaiting_approval | completed | failed | aborted
    steps_log: Mapped[list] = mapped_column(JSON, default=list)  # [{step_id, name, status, result, ts}]
    next_step_index: Mapped[int] = mapped_column(Integer, default=0)  # resume pointer after HitL

    # Linked artefacts
    alert_id: Mapped[str | None] = mapped_column(String(36), nullable=True)  # Alert created by this run

    # Human-in-the-Loop
    approval_token: Mapped[str | None] = mapped_column(String(36), nullable=True)
    approved_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Lifecycle
    initiated_by: Mapped[str] = mapped_column(String(36), nullable=False)  # user_id or "system"
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    error: Mapped[str | None] = mapped_column(Text, nullable=True)
