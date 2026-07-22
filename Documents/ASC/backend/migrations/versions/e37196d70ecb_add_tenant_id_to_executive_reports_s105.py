"""S105.2 — add tenant_id to executive_reports (aislamiento por tenant)

Revision ID: e37196d70ecb
Revises: f9edec8a6897
Create Date: 2026-07-21

Aísla los reportes ejecutivos por tenant. NULL = reporte global (modo single-tenant
legacy), consistente con apply_tenant_filter. Idempotente vía IF NOT EXISTS en el SQL
manual de Supabase (migrations_s105_executive_tenant.sql).
"""
from alembic import op
import sqlalchemy as sa

revision = "e37196d70ecb"
down_revision = "f9edec8a6897"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "executive_reports",
        sa.Column("tenant_id", sa.String(length=36), nullable=True),
    )
    op.create_index(
        "ix_executive_reports_tenant_id", "executive_reports", ["tenant_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_executive_reports_tenant_id", table_name="executive_reports")
    op.drop_column("executive_reports", "tenant_id")
