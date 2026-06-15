"""add pcdi signed reports p24

Revision ID: d4f92b1a8e36
Revises: c3e04a5b9c27
Create Date: 2026-06-11

Tables: pcdi_signed_reports
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "d4f92b1a8e36"
down_revision = "c3e04a5b9c27"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "pcdi_signed_reports",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("hunt_id", sa.String(36), nullable=False),
        sa.Column("hunt_name", sa.String(256), nullable=True),
        sa.Column("canonical_data", sa.JSON(), nullable=False),
        sa.Column("hash_sha3_512", sa.String(128), nullable=False),
        sa.Column("signature_ed25519", sa.Text(), nullable=False),
        sa.Column("signed_by_email", sa.String(256), nullable=False),
        sa.Column("signed_by_user_id", sa.String(36), nullable=True),
        sa.Column(
            "signed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("verified", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("last_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("pcdi_version", sa.String(10), nullable=False, server_default="1"),
        sa.Column("adaptive_score", sa.Integer(), nullable=True),
    )
    op.create_index("ix_pcdi_hunt_id", "pcdi_signed_reports", ["hunt_id"])
    op.create_index("ix_pcdi_signed_by", "pcdi_signed_reports", ["signed_by_email"])
    op.create_index("ix_pcdi_signed_at", "pcdi_signed_reports", ["signed_at"])


def downgrade() -> None:
    op.drop_index("ix_pcdi_signed_at", table_name="pcdi_signed_reports")
    op.drop_index("ix_pcdi_signed_by", table_name="pcdi_signed_reports")
    op.drop_index("ix_pcdi_hunt_id", table_name="pcdi_signed_reports")
    op.drop_table("pcdi_signed_reports")
