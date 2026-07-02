"""add_multi_tenancy_p47

P47 — Multi-tenancy Foundation.

Creates the `tenants` table and adds nullable `tenant_id` column to all
key data tables. NULL tenant_id = single-tenant / default PremosCorp mode.

Design:
- Non-breaking: all new columns are nullable with no default constraints.
- Existing rows retain NULL tenant_id (treated as "default tenant").
- Tenant isolation enforcement deferred to FASE 5 middleware.

Tables with tenant_id added:
  users, alerts, events, api_keys, webhooks, incidents

Revision ID: p6j79m8o1i93
Revises: n4h58k6m9g71
Create Date: 2026-06-14
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = "p6j79m8o1i93"
down_revision = "n4h58k6m9g71"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Create tenants table
    op.create_table(
        "tenants",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(100), nullable=False),
        sa.Column("plan", sa.String(50), nullable=False, server_default="free"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column("contact_email", sa.String(255), nullable=True),
        sa.Column("max_users", sa.Integer(), nullable=True),
        sa.Column("max_api_keys_per_user", sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("slug", name="uq_tenants_slug"),
    )
    op.create_index("ix_tenants_slug", "tenants", ["slug"], unique=True)
    op.create_index("ix_tenants_is_active", "tenants", ["is_active"])

    # 2. Add tenant_id to users
    op.add_column("users", sa.Column("tenant_id", sa.String(36), nullable=True))
    op.create_index("ix_users_tenant_id", "users", ["tenant_id"])

    # 3. Add tenant_id to alerts
    op.add_column("alerts", sa.Column("tenant_id", sa.String(36), nullable=True))
    op.create_index("ix_alerts_tenant_id", "alerts", ["tenant_id"])

    # 4. Add tenant_id to events
    op.add_column("events", sa.Column("tenant_id", sa.String(36), nullable=True))
    op.create_index("ix_events_tenant_id", "events", ["tenant_id"])

    # 5. Add tenant_id to api_keys
    op.add_column("api_keys", sa.Column("tenant_id", sa.String(36), nullable=True))
    op.create_index("ix_api_keys_tenant_id", "api_keys", ["tenant_id"])

    # 6. Add tenant_id to webhooks
    op.add_column("webhooks", sa.Column("tenant_id", sa.String(36), nullable=True))
    op.create_index("ix_webhooks_tenant_id", "webhooks", ["tenant_id"])

    # 7. Add tenant_id to incidents
    op.add_column("incidents", sa.Column("tenant_id", sa.String(36), nullable=True))
    op.create_index("ix_incidents_tenant_id", "incidents", ["tenant_id"])


def downgrade() -> None:
    # Remove tenant_id from data tables (reverse order)
    op.drop_index("ix_incidents_tenant_id", table_name="incidents")
    op.drop_column("incidents", "tenant_id")

    op.drop_index("ix_webhooks_tenant_id", table_name="webhooks")
    op.drop_column("webhooks", "tenant_id")

    op.drop_index("ix_api_keys_tenant_id", table_name="api_keys")
    op.drop_column("api_keys", "tenant_id")

    op.drop_index("ix_events_tenant_id", table_name="events")
    op.drop_column("events", "tenant_id")

    op.drop_index("ix_alerts_tenant_id", table_name="alerts")
    op.drop_column("alerts", "tenant_id")

    op.drop_index("ix_users_tenant_id", table_name="users")
    op.drop_column("users", "tenant_id")

    # Drop tenants table
    op.drop_index("ix_tenants_is_active", table_name="tenants")
    op.drop_index("ix_tenants_slug", table_name="tenants")
    op.drop_table("tenants")
