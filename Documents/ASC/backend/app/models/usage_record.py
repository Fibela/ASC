"""
P55 — UsageRecord model.
Snapshots monthly resource usage per tenant for billing/metering purposes.

Each record captures how many units of a resource type exist for a tenant
in a given billing period (YYYY-MM). Records are idempotent — re-running
the snapshot for the same period + resource_type + tenant_id overwrites.

resource_type values: users, alerts, api_keys, webhooks, incidents
period format: YYYY-MM (e.g. "2026-06")
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Integer, DateTime, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base


class UsageRecord(Base):
    __tablename__ = "usage_records"
    __table_args__ = (
        UniqueConstraint("tenant_id", "period", "resource_type",
                         name="uq_usage_tenant_period_resource"),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    # Billing period in YYYY-MM format (e.g. "2026-06")
    period: Mapped[str] = mapped_column(String(7), nullable=False)
    # Resource being metered: users | alerts | api_keys | webhooks | incidents
    resource_type: Mapped[str] = mapped_column(String(50), nullable=False)
    count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
