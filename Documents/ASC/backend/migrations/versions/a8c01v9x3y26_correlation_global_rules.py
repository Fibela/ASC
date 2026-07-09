"""correlation_global_rules — tenant-scoped rule isolation + unique constraint fix

Revision ID: a8c01v9x3y26
Revises: a7b90v8w2x25
Create Date: 2026-07-07

P-16 fix: correlation_rules.name had a GLOBAL unique constraint, which:
  1. Prevented multi-tenant deployments from having a rule named the same as
     one of the 4 built-in global rules (R001-R004).
  2. Let tenant A block tenant B from creating "My Rule" by naming theirs first.

Changes:
  - Drop old UNIQUE(name) constraint (correlation_rules_name_key)
  - Add partial unique index for global rules: UNIQUE(name) WHERE tenant_id IS NULL
  - Add partial unique index for tenant rules: UNIQUE(name, tenant_id) WHERE tenant_id IS NOT NULL

The 4 existing seed rows (R001-R004) keep tenant_id=NULL (global / shared).
No data migration required — only uniqueness semantics change.

Downgrade restores the old global UNIQUE(name) constraint. Note: if tenants have
created rules with the same name before downgrading, the restore will fail — run
the downgrade only on a clean DB or after de-duplicating names.
"""
import sqlalchemy as sa
from alembic import op


revision = "a8c01v9x3y26"
down_revision = "a7b90v8w2x25"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Drop the old global unique constraint on name
    with op.batch_alter_table("correlation_rules") as batch_op:
        try:
            batch_op.drop_constraint("correlation_rules_name_key", type_="unique")
        except Exception:
            pass  # already dropped or named differently — safe to continue

    # Partial unique index: global rules (NULL tenant) → name must be unique among globals
    op.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_cr_global_name "
        "ON correlation_rules(name) WHERE tenant_id IS NULL"
    )
    # Partial unique index: tenant rules → (name, tenant_id) unique within each tenant
    op.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_cr_tenant_name "
        "ON correlation_rules(name, tenant_id) WHERE tenant_id IS NOT NULL"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS uq_cr_global_name")
    op.execute("DROP INDEX IF EXISTS uq_cr_tenant_name")
    with op.batch_alter_table("correlation_rules") as batch_op:
        batch_op.create_unique_constraint("correlation_rules_name_key", ["name"])
