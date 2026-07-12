"""artifact_tenant_isolation — add tenant_id + submitted_by index to artifacts

Revision ID: a7b90v8w2x25
Revises: z6t89u7x1s14
Create Date: 2026-07-06

SEC-6 fix: the artifacts table was missing a tenant_id column, allowing any
authenticated user to retrieve artifacts uploaded by users of other tenants
via GET /analyze/artifact/{id}.

Changes:
  - artifacts.tenant_id VARCHAR(36) NULL  (existing rows left NULL — single-tenant
    legacy data; multi-tenant callers will see only their own artifacts)
  - ix_artifacts_tenant_id index for O(log n) scoped lookups
  - ix_artifacts_submitted_by index (submitted_by already existed as a column
    but lacked an index; added here as a companion perf fix)

Downgrade drops both indexes and the tenant_id column.  The submitted_by index
downgrade is left as a no-op because the column pre-dates this migration and
its index is safe to leave.
"""
import sqlalchemy as sa
from alembic import op

revision = "a7b90v8w2x25"
down_revision = "z6t89u7x1s14"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # IF NOT EXISTS guards: column/indexes may already exist if schema was partially
    # applied via SQL script before this migration was stamped in alembic_version.
    conn = op.get_bind()
    conn.execute(sa.text(
        "ALTER TABLE artifacts ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(36)"
    ))
    conn.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_artifacts_tenant_id ON artifacts(tenant_id)"
    ))
    conn.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_artifacts_submitted_by ON artifacts(submitted_by)"
    ))


def downgrade() -> None:
    op.drop_index("ix_artifacts_tenant_id", table_name="artifacts")
    op.drop_column("artifacts", "tenant_id")
    # submitted_by index is safe to leave; drop only if re-running upgrade from scratch
    try:
        op.drop_index("ix_artifacts_submitted_by", table_name="artifacts")
    except Exception:
        pass
