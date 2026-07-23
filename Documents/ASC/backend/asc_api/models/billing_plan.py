import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from asc_api.db.base import Base


class BillingPlan(Base):
    """Product catalog for ASC subscription plans — replaces the hardcoded _PLANS list."""

    __tablename__ = "billing_plans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    slug: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)  # free | pro | enterprise
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    tagline: Mapped[str] = mapped_column(Text, nullable=True)
    cta: Mapped[str] = mapped_column(String(100), nullable=True)
    price_usd: Mapped[int | None] = mapped_column(Integer, nullable=True)  # None = contact sales
    price_usd_annual: Mapped[int | None] = mapped_column(Integer, nullable=True)
    billing_period: Mapped[str] = mapped_column(String(20), default="month")
    highlight: Mapped[bool] = mapped_column(Boolean, default=False)  # show as "recommended"
    # Entitlements stored as JSON so they can be extended without schema changes
    features: Mapped[dict] = mapped_column(JSON, default=dict)
    features_list: Mapped[list] = mapped_column(JSON, default=list)
    sort_order: Mapped[int] = mapped_column(Integer, default=0)  # display order
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )
