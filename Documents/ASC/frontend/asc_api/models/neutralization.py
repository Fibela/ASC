import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, Text, JSON, Boolean, Integer
from sqlalchemy.orm import Mapped, mapped_column
from asc_api.db.base import Base


class NeutralizationAction(Base):
    __tablename__ = "neutralization_actions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    alert_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    action_type: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default="medium")
    # isolate_endpoint, block_ip, block_domain, kill_process,
    # delete_file, remove_persistence, disable_account, quarantine_file
    # rollback types: unisolate_endpoint, unblock_ip, unblock_domain, restore_file

    target: Mapped[str] = mapped_column(String(512), nullable=False)
    target_type: Mapped[str] = mapped_column(String(50), nullable=False)
    params: Mapped[dict] = mapped_column(JSON, default=dict)

    # ── Execution state ───────────────────────────────────────────────────────
    # pending_approval → approved → executing → completed / failed
    #                 → rejected
    #                 → escalated  (timeout expired without decision)
    status: Mapped[str] = mapped_column(String(30), default="pending_approval")

    automated: Mapped[bool] = mapped_column(Boolean, default=False)
    initiated_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    rollback_available: Mapped[bool] = mapped_column(Boolean, default=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # ── Human-in-the-Loop fields (P16.1) ─────────────────────────────────────
    approval_required: Mapped[bool] = mapped_column(Boolean, default=True)
    timeout_minutes: Mapped[int] = mapped_column(Integer, default=30)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    approved_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    rejected_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    rejected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rejection_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    escalated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    escalation_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ── PANL — Multi-signature approval (P16 pre-P16.3) ──────────────────────
    # required_approvals: 1 for HIGH, 2 for CRITICAL (Ed25519-authenticated via JWT)
    required_approvals: Mapped[int] = mapped_column(Integer, default=1)
    # approvals_log: [{approved_by: str, approved_at: ISO-str}]
    approvals_log: Mapped[list] = mapped_column(JSON, default=list)

    # ── PANL — Rollback tracking ──────────────────────────────────────────────
    # is_rollback: True when this action reverses a previous destructive action
    is_rollback: Mapped[bool] = mapped_column(Boolean, default=False)
    # rollback_of: ID of the original action this reverses (forensic link)
    rollback_of: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    # rollback_action_id: ID of the rollback that was created for this action
    rollback_action_id: Mapped[str | None] = mapped_column(String(36), nullable=True)

    # ── PANL — Adaptive severity audit trail ─────────────────────────────────
    # original_severity: severity as submitted by the analyst (before PANL upgrade)
    original_severity: Mapped[str | None] = mapped_column(String(20), nullable=True)
    # severity_adapted: True if PANL upgraded the severity above what was requested
    severity_adapted: Mapped[bool] = mapped_column(Boolean, default=False)
