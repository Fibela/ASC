"""add_webhooks_p42

P42 — Webhook Support.
Creates the `webhooks` table for storing registered webhook endpoints.

Revision ID: n4h58k6m9g71
Revises: m3g47j5l8f60
Create Date: 2026-06-14
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = "n4h58k6m9g71"
down_revision = "m3g47j5l8f60"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "webhooks",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("url", sa.String(length=2048), nullable=False),
        sa.Column("secret", sa.String(length=64), nullable=False),
        sa.Column("events", sa.JSON(), nullable=True),
        sa.Column("description", sa.String(length=500), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("user_id", sa.String(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column("last_triggered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failure_count", sa.Integer(), nullable=False, server_default="0"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_webhooks_user_id", "webhooks", ["user_id"])
    op.create_index("ix_webhooks_is_active", "webhooks", ["is_active"])


def downgrade() -> None:
    op.drop_index("ix_webhooks_is_active", table_name="webhooks")
    op.drop_index("ix_webhooks_user_id", table_name="webhooks")
    op.drop_table("webhooks")
