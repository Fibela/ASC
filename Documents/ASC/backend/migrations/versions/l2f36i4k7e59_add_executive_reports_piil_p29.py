"""add_executive_reports_piil_p29

Revision ID: l2f36i4k7e59
Revises: k1e25h3j6d48
Create Date: 2026-06-12 00:00:00.000000

P29-B — Executive Reporting + PIIL: adds executive_reports table with
SHA3-512 hash + Ed25519 signature seal (Premos Incident Intelligence Layer).
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "l2f36i4k7e59"
down_revision = "k1e25h3j6d48"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "executive_reports",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("report_type", sa.String(30), nullable=False),
        sa.Column("period", sa.String(20), nullable=False, server_default="custom"),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("generated_by", sa.String(256), nullable=False),
        sa.Column("period_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("period_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("total_incidents", sa.Integer, nullable=False, server_default="0"),
        sa.Column("closed_incidents", sa.Integer, nullable=False, server_default="0"),
        sa.Column("sla_breach_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("campaign_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("avg_mttd_minutes", sa.Float, nullable=True),
        sa.Column("avg_mttc_minutes", sa.Float, nullable=True),
        sa.Column("avg_mttr_minutes", sa.Float, nullable=True),
        sa.Column("canonical_data", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("hash_sha3_512", sa.String(128), nullable=False),
        sa.Column("signature_ed25519", sa.Text, nullable=False),
        sa.Column("pubkey_fingerprint", sa.String(32), nullable=False, server_default=""),
        sa.Column("signature_valid", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("last_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )
    op.create_index("ix_er_report_type", "executive_reports", ["report_type"])
    op.create_index("ix_er_period_start", "executive_reports", ["period_start"])
    op.create_index("ix_er_generated_by", "executive_reports", ["generated_by"])
    op.create_index("ix_er_created_at", "executive_reports", ["created_at"])


def downgrade() -> None:
    op.drop_table("executive_reports")
