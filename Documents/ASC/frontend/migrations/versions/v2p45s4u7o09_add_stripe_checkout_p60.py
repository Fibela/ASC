"""add_stripe_checkout_p60

Revision ID: v2p45s4u7o09
Revises: u1o34r3t6n08
Create Date: 2026-06-15

P60 — Stripe → ASC Tenant Auto-Provisioning.
Adds stripe_checkout_session_id to tenants for idempotency: prevents
duplicate provisioning if Stripe fires checkout.session.completed twice.
"""
from alembic import op
import sqlalchemy as sa

revision = "v2p45s4u7o09"
down_revision = "u1o34r3t6n08"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "tenants",
        sa.Column("stripe_checkout_session_id", sa.String(255), nullable=True),
    )
    op.create_index(
        "ix_tenants_stripe_checkout_session_id",
        "tenants",
        ["stripe_checkout_session_id"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ix_tenants_stripe_checkout_session_id", table_name="tenants")
    op.drop_column("tenants", "stripe_checkout_session_id")
