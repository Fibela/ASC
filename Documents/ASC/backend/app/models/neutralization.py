import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, Text, JSON, Boolean
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base


class NeutralizationAction(Base):
    __tablename__ = "neutralization_actions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    alert_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    action_type: Mapped[str] = mapped_column(String(50), nullable=False)
    # isolate_endpoint, block_ip, block_domain, kill_process,
    # delete_file, remove_persistence, disable_account, quarantine_file

    target: Mapped[str] = mapped_column(String(512), nullable=False)     # IP, hostname, process name, file path, etc.
    target_type: Mapped[str] = mapped_column(String(50), nullable=False) # endpoint, ip, domain, process, file, account
    status: Mapped[str] = mapped_column(String(30), default="pending")   # pending, executing, success, failed, rolled_back
    automated: Mapped[bool] = mapped_column(Boolean, default=False)      # auto-triggered vs analyst-initiated
    initiated_by: Mapped[str | None] = mapped_column(String(36), nullable=True)  # user_id or "system"
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    rollback_available: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
