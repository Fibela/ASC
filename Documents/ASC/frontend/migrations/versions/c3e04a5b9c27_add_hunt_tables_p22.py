"""add hunt tables p22

Revision ID: c3e04a5b9c27
Revises: b1c92e3f7a05
Create Date: 2026-06-11

Tables: hunt_sessions, hunt_findings, hunt_queries
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "c3e04a5b9c27"
down_revision = "b1c92e3f7a05"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── hunt_sessions ────────────────────────────────────────────────────────
    op.create_table(
        "hunt_sessions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("hypothesis", sa.Text, nullable=True),
        sa.Column("status", sa.String(30), nullable=False, server_default="draft"),
        sa.Column("mitre_technique", sa.String(20), nullable=True),
        sa.Column("mitre_tactic", sa.String(100), nullable=True),
        sa.Column("scope", sa.String(50), nullable=False, server_default="all"),
        sa.Column("priority", sa.String(20), nullable=False, server_default="medium"),
        sa.Column("created_by", sa.String(256), nullable=False),
        sa.Column("assigned_to", sa.String(256), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("conclusion", sa.Text, nullable=True),
        sa.Column("findings_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("true_positive_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("tags", sa.JSON, nullable=False, server_default="[]"),
    )
    op.create_index("ix_hunt_status", "hunt_sessions", ["status"])
    op.create_index("ix_hunt_priority", "hunt_sessions", ["priority"])
    op.create_index("ix_hunt_created_by", "hunt_sessions", ["created_by"])
    op.create_index("ix_hunt_mitre", "hunt_sessions", ["mitre_technique"])

    # ── hunt_findings ────────────────────────────────────────────────────────
    op.create_table(
        "hunt_findings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("hunt_id", sa.String(36),
                  sa.ForeignKey("hunt_sessions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("severity", sa.String(20), nullable=False, server_default="medium"),
        sa.Column("indicator_value", sa.String(1024), nullable=True),
        sa.Column("indicator_type", sa.String(50), nullable=True),
        sa.Column("affected_host", sa.String(256), nullable=True),
        sa.Column("affected_user", sa.String(256), nullable=True),
        sa.Column("data_source", sa.String(100), nullable=True),
        sa.Column("mitre_technique", sa.String(20), nullable=True),
        sa.Column("mitre_tactic", sa.String(100), nullable=True),
        sa.Column("evidence", sa.JSON, nullable=True),
        sa.Column("is_confirmed", sa.Boolean, nullable=False, server_default="0"),
        sa.Column("is_false_positive", sa.Boolean, nullable=False, server_default="0"),
        sa.Column("analyst_notes", sa.Text, nullable=True),
        sa.Column("created_by", sa.String(256), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_hf_hunt_id", "hunt_findings", ["hunt_id"])
    op.create_index("ix_hf_severity", "hunt_findings", ["severity"])
    op.create_index("ix_hf_confirmed", "hunt_findings", ["is_confirmed"])

    # ── hunt_queries ─────────────────────────────────────────────────────────
    op.create_table(
        "hunt_queries",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("hunt_id", sa.String(36),
                  sa.ForeignKey("hunt_sessions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("query_text", sa.Text, nullable=False),
        sa.Column("data_source", sa.String(100), nullable=False, server_default="elk"),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("last_executed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_result_count", sa.Integer, nullable=True),
        sa.Column("last_execution_ms", sa.Integer, nullable=True),
        sa.Column("created_by", sa.String(256), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_hq_hunt_id", "hunt_queries", ["hunt_id"])
    op.create_index("ix_hq_data_source", "hunt_queries", ["data_source"])


def downgrade() -> None:
    op.drop_table("hunt_queries")
    op.drop_table("hunt_findings")
    op.drop_table("hunt_sessions")
