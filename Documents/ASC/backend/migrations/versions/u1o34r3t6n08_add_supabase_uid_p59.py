"""add_supabase_uid_p59

Revision ID: u1o34r3t6n08
Revises: t0n23q2s5m07
Create Date: 2026-06-15

P59 — SSO Bridge: Supabase → ASC JWT Exchange.
Adds supabase_uid to users for linking Supabase identities to ASC accounts.
"""
from alembic import op
import sqlalchemy as sa

revision = "u1o34r3t6n08"
down_revision = "t0n23q2s5m07"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("supabase_uid", sa.String(36), nullable=True),
    )
    op.create_index("ix_users_supabase_uid", "users", ["supabase_uid"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_users_supabase_uid", table_name="users")
    op.drop_column("users", "supabase_uid")
