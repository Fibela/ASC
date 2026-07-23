import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, DateTime, Float, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from asc_api.db.base import Base


class Event(Base):
    __tablename__ = "events"
    __table_args__ = (
        Index("ix_events_source_timestamp", "source", "timestamp"),
        Index("ix_events_severity", "severity"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True)
    source: Mapped[str] = mapped_column(String(100), nullable=False)  # syslog, winlog, netflow, edr
    category: Mapped[str] = mapped_column(String(100), nullable=False)  # process, network, registry, file
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    severity: Mapped[str] = mapped_column(String(20), default="low")  # low, medium, high, critical
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    raw_log: Mapped[str | None] = mapped_column(Text, nullable=True)
    normalized: Mapped[dict] = mapped_column(JSON, default=dict)  # normalized ECS fields
    tags: Mapped[list] = mapped_column(JSON, default=list)
    correlated: Mapped[bool] = mapped_column(default=False)
    alert_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    # P47 Multi-tenancy — NULL = single-tenant / default deployment
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
