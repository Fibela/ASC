import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, Float, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)          # low, medium, high, critical
    status: Mapped[str] = mapped_column(String(30), default="open")            # open, investigating, contained, resolved, false_positive
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    source_events: Mapped[list] = mapped_column(JSON, default=list)            # list of event IDs
    matched_iocs: Mapped[list] = mapped_column(JSON, default=list)             # list of IoC IDs
    affected_hosts: Mapped[list] = mapped_column(JSON, default=list)
    ttps: Mapped[list] = mapped_column(JSON, default=list)                     # MITRE ATT&CK
    recommended_actions: Mapped[list] = mapped_column(JSON, default=list)
    analyst_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    assigned_to: Mapped[str | None] = mapped_column(String(36), nullable=True) # user_id
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    false_positive: Mapped[bool] = mapped_column(default=False)
