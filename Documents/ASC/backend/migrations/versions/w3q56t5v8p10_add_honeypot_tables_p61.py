"""add_honeypot_tables_p61

Revision ID: w3q56t5v8p10
Revises: v2p45s4u7o09
Create Date: 2026-06-18

P61 — Honeypot evidence persistence.
Canary tokens and forensic evidence reports were stored in-memory and lost
on every restart/redeploy. This migration adds persistent DB tables.
"""
from alembic import op
import sqlalchemy as sa

revision = "w3q56t5v8p10"
down_revision = "v2p45s4u7o09"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "honeypot_tokens",
        sa.Column("token_id",   sa.String(64),  primary_key=True),
        sa.Column("endpoint",   sa.String(256), nullable=False),
        sa.Column("label",      sa.String(256), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
    )
    op.create_index("ix_honeypot_tokens_created_at", "honeypot_tokens", ["created_at"])

    op.create_table(
        "honeypot_token_accesses",
        sa.Column("id",               sa.String(36),  primary_key=True),
        sa.Column("token_id",         sa.String(64),
                  sa.ForeignKey("honeypot_tokens.token_id", ondelete="CASCADE"), nullable=False),
        sa.Column("ts",               sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.Column("client_ip",        sa.String(64),  nullable=False),
        sa.Column("user_agent",       sa.String(512), nullable=False, server_default=""),
        sa.Column("referer",          sa.String(512), nullable=False, server_default=""),
        sa.Column("headers_snapshot", sa.JSON,        nullable=False, server_default="{}"),
    )
    op.create_index("ix_honeypot_accesses_token_id", "honeypot_token_accesses", ["token_id"])
    op.create_index("ix_honeypot_accesses_ts",       "honeypot_token_accesses", ["ts"])

    op.create_table(
        "honeypot_evidence_reports",
        sa.Column("report_id",        sa.String(36),  primary_key=True),
        sa.Column("token_id",         sa.String(64),
                  sa.ForeignKey("honeypot_tokens.token_id", ondelete="SET NULL"), nullable=True),
        sa.Column("event_type",       sa.String(100), nullable=False),
        sa.Column("attacker_ip",      sa.String(64),  nullable=False),
        sa.Column("severity",         sa.String(20),  nullable=False, server_default="medium"),
        sa.Column("generated_at",     sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.Column("report_json",      sa.JSON,        nullable=False),
        sa.Column("signature",        sa.Text,        nullable=False),
        sa.Column("fingerprint_hash", sa.String(64),  nullable=False, server_default=""),
    )
    op.create_index("ix_honeypot_evidence_generated_at", "honeypot_evidence_reports", ["generated_at"])
    op.create_index("ix_honeypot_evidence_attacker_ip",  "honeypot_evidence_reports", ["attacker_ip"])


def downgrade() -> None:
    op.drop_table("honeypot_evidence_reports")
    op.drop_table("honeypot_token_accesses")
    op.drop_table("honeypot_tokens")
