import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, Float, Integer, JSON
from sqlalchemy.orm import Mapped, mapped_column
from asc_api.db.base import Base


class SocMetric(Base):
    """SOC KPI snapshot stored periodically (hourly/daily)."""
    __tablename__ = "soc_metrics"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    period: Mapped[str] = mapped_column(String(10), nullable=False)     # hourly, daily, weekly
    period_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    period_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # Detection metrics
    total_events: Mapped[int] = mapped_column(Integer, default=0)
    total_alerts: Mapped[int] = mapped_column(Integer, default=0)
    true_positives: Mapped[int] = mapped_column(Integer, default=0)
    false_positives: Mapped[int] = mapped_column(Integer, default=0)
    false_positive_rate: Mapped[float] = mapped_column(Float, default=0.0)

    # Time metrics (seconds)
    mttd: Mapped[float | None] = mapped_column(Float, nullable=True)    # Mean Time To Detect
    mttr: Mapped[float | None] = mapped_column(Float, nullable=True)    # Mean Time To Respond
    mttc: Mapped[float | None] = mapped_column(Float, nullable=True)    # Mean Time To Contain

    # Coverage
    ioc_coverage: Mapped[float] = mapped_column(Float, default=0.0)     # % IoCs with hits
    endpoint_coverage: Mapped[float] = mapped_column(Float, default=0.0)

    # Severity breakdown
    by_severity: Mapped[dict] = mapped_column(JSON, default=dict)       # {critical:N, high:N, ...}
    by_category: Mapped[dict] = mapped_column(JSON, default=dict)
    top_iocs: Mapped[list] = mapped_column(JSON, default=list)

    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
