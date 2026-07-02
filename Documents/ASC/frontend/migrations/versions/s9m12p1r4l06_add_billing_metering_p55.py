"""add_billing_metering_p55

P55 — Billing and Metering.

Changes:
  1. Adds Stripe ID columns to the tenants table (nullable — populated when
     a tenant subscribes via the Stripe integration).
  2. Creates the usage_records table for monthly resource metering snapshots.

Revision ID: s9m12p1r4l06
Revises: r8l01o0q3k05
Create Date: 2026-06-14
"""
from alembic import op
import sqlalchemy as sa

revision = "s9m12p1r4l06"
down_revision = "r8l01o0q3k05"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Stripe fields on tenants
    op.add_column(
        "tenants",
        sa.Column("stripe_customer_id", sa.String(64), nullable=True),
    )
    op.add_column(
        "tenants",
        sa.Column("stripe_subscription_id", sa.String(64), nullable=True),
    )
    op.create_index("ix_tenants_stripe_customer_id", "tenants", ["stripe_customer_id"])

    # 2. usage_records table
    op.create_table(
        "usage_records",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("period", sa.String(7), nullable=False),           # YYYY-MM
        sa.Column("resource_type", sa.String(50), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "recorded_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id", "period", "resource_type",
            name="uq_usage_tenant_period_resource",
        ),
    )
    op.create_index("ix_usage_records_tenant_id", "usage_records", ["tenant_id"])
    op.create_index("ix_usage_records_period", "usage_records", ["period"])


def downgrade() -> None:
    op.drop_index("ix_usage_records_period", table_name="usage_records")
    op.drop_index("ix_usage_records_tenant_id", table_name="usage_records")
    op.drop_table("usage_records")
    op.drop_index("ix_tenants_stripe_customer_id", table_name="tenants")
    op.drop_column("tenants", "stripe_subscription_id")
    op.drop_column("tenants", "stripe_customer_id")
