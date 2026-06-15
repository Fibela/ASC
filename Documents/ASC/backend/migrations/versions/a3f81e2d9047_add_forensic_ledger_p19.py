"""add_forensic_ledger_p19

Revision ID: a3f81e2d9047
Revises: 6f4219e1c240
Create Date: 2026-06-10

Premos Forensic Neutralization (PFN) — P19.3
Adds forensic_ledger table: cryptographic proof ledger for every
successfully executed neutralization action.
"""
from __future__ import annotations
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "a3f81e2d9047"
down_revision: Union[str, Sequence[str], None] = "6f4219e1c240"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "forensic_ledger",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("action_id", sa.String(36), nullable=False),
        sa.Column("action_type", sa.String(50), nullable=False),
        sa.Column("target", sa.String(512), nullable=False),
        sa.Column("canonical_data", sa.JSON(), nullable=False),
        sa.Column("hash_sha3_512", sa.String(128), nullable=False),
        sa.Column("signature_ed25519", sa.Text(), nullable=False),
        sa.Column("signed_by_email", sa.String(256), nullable=False),
        sa.Column("signed_by_user_id", sa.String(36), nullable=False),
        sa.Column("signed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verified", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("last_verified_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_forensic_ledger_action_id",
        "forensic_ledger",
        ["action_id"],
    )
    op.create_index(
        "ix_forensic_ledger_signed_by_user_id",
        "forensic_ledger",
        ["signed_by_user_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_forensic_ledger_signed_by_user_id", table_name="forensic_ledger")
    op.drop_index("ix_forensic_ledger_action_id", table_name="forensic_ledger")
    op.drop_table("forensic_ledger")
