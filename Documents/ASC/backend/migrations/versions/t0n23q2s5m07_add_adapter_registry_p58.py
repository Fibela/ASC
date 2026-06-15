"""add_adapter_registry_p58

Revision ID: t0n23q2s5m07
Revises: s9m12p1r4l06
Create Date: 2026-06-15

P58 — Tenant Adapter Registry: per-tenant EDR/firewall/identity/SIEM/SOAR configs.
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = "t0n23q2s5m07"
down_revision = "s9m12p1r4l06"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "tenant_adapter_configs",
        sa.Column("id",                    sa.String(36),  primary_key=True),
        sa.Column("tenant_id",             sa.String(36),  nullable=False),
        sa.Column("adapter_type",          sa.String(50),  nullable=False),
        sa.Column("provider",              sa.String(50),  nullable=False, server_default="none"),
        sa.Column("is_enabled",            sa.Boolean(),   nullable=False, server_default=sa.true()),
        sa.Column("host",                  sa.String(512), nullable=True),
        sa.Column("settings_json",         sa.JSON(),      nullable=True),
        sa.Column("credential_encrypted",  sa.Text(),      nullable=True),
        sa.Column("credential_hint",       sa.String(8),   nullable=True),
        sa.Column("created_at",            sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at",            sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "adapter_type", name="uq_tenant_adapter_type"),
    )
    op.create_index("ix_tenant_adapter_configs_tenant_id",
                    "tenant_adapter_configs", ["tenant_id"])
    op.create_index("ix_tenant_adapter_configs_adapter_type",
                    "tenant_adapter_configs", ["adapter_type"])


def downgrade() -> None:
    op.drop_index("ix_tenant_adapter_configs_adapter_type",
                  table_name="tenant_adapter_configs")
    op.drop_index("ix_tenant_adapter_configs_tenant_id",
                  table_name="tenant_adapter_configs")
    op.drop_table("tenant_adapter_configs")
