"""
P47 — Multi-tenancy Foundation.

Tenant model for commercial SaaS deployment (FASE 5).
Each Tenant represents an organization using ASC PremosCorp as a service.

Design decisions:
- tenant_id added to data models as nullable (non-breaking migration).
  NULL tenant_id = "default" / single-tenant mode (PremosCorp own deployment).
- slug: URL-safe identifier used in routing (e.g., asc.premoscorp.com/t/acme-corp/).
- plan: free | pro | enterprise — governs feature flags and rate limits.
- All user-generated data is isolated by tenant_id at the query layer.
  Enforcement deferred to FASE 5 API middleware.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Boolean, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from asc_api.db.base import Base


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)
    plan: Mapped[str] = mapped_column(String(50), default="free")  # free | pro | enterprise
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    # Contact for billing / support
    contact_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Max active users allowed under this plan (None = unlimited)
    max_users: Mapped[int | None] = mapped_column(nullable=True)
    # Max API keys per user under this plan
    max_api_keys_per_user: Mapped[int | None] = mapped_column(nullable=True)

    # ── P55 Billing / Stripe ──────────────────────────────────────────────────
    # Stripe customer ID (e.g. cus_XXXXXXXXXXXXXXXXXX). NULL = not yet in Stripe.
    stripe_customer_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Active Stripe subscription ID (sub_XXXXXXXXXXXXXXXXXX). NULL = free/no sub.
    stripe_subscription_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # ── P60 Stripe Checkout Auto-Provisioning ─────────────────────────────────
    # Checkout session ID used for idempotency (cs_XXXXXXXXXXXXXXXXXX).
    # Prevents duplicate provisioning if Stripe fires the event more than once.
    stripe_checkout_session_id: Mapped[str | None] = mapped_column(
        String(255), nullable=True, unique=True
    )
