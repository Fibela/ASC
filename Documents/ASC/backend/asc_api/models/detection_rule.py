import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, Text, JSON, Boolean, Float
from sqlalchemy.orm import Mapped, mapped_column
from asc_api.db.base import Base


class DetectionRule(Base):
    """Catalog of ASC detection rules — persists rule metadata, evaluated by the detection engine."""
    __tablename__ = "detection_rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    rule_id: Mapped[str] = mapped_column(String(20), unique=True, nullable=False, index=True)  # DET-001 …
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    mitre_ttp: Mapped[str] = mapped_column(String(50), nullable=False)        # e.g. T1036.005
    severity: Mapped[str] = mapped_column(String(30), nullable=False)         # critical | high | medium | low | critical/high
    description: Mapped[str] = mapped_column(Text, nullable=False)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    risk_score_default: Mapped[float] = mapped_column(Float, default=0.5)     # baseline risk for catalog display
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
