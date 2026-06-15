"""initial_schema_p16

Revision ID: 6f4219e1c240
Revises:
Create Date: 2026-06-10

Initial full schema migration for ASC PremosCorp through P16.3.
Captures all tables from Base.metadata baseline.

P16.3 additions included here:
  users: failed_login_attempts, locked_until, force_password_reset,
         signing_public_key, signing_private_key_enc
  revoked_tokens: new table for JWT JTI blacklist
"""
from __future__ import annotations
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "6f4219e1c240"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── users ─────────────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("email", sa.String(), nullable=False),
        sa.Column("full_name", sa.String(), nullable=True),
        sa.Column("hashed_password", sa.String(), nullable=False),
        sa.Column("role", sa.String(), nullable=False, server_default="analyst"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("last_login", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=True),
        sa.Column("failed_login_attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("force_password_reset", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("signing_public_key", sa.String(length=64), nullable=True),
        sa.Column("signing_private_key_enc", sa.String(length=512), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_users_email"), "users", ["email"], unique=True)

    # ── revoked_tokens (P16.3 JWT blacklist) ──────────────────────────────────
    op.create_table(
        "revoked_tokens",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("jti", sa.String(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.Column("revoked_by", sa.String(), nullable=True),
        sa.Column("reason", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("jti"),
    )
    op.create_index(op.f("ix_revoked_tokens_jti"), "revoked_tokens", ["jti"], unique=True)
    op.create_index(op.f("ix_revoked_tokens_expires_at"), "revoked_tokens", ["expires_at"])

    # ── events ────────────────────────────────────────────────────────────────
    op.create_table(
        "events",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("source", sa.String(), nullable=True),
        sa.Column("event_type", sa.String(), nullable=True),
        sa.Column("severity", sa.String(), nullable=True),
        sa.Column("raw_log", sa.Text(), nullable=True),
        sa.Column("parsed_data", sa.JSON(), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=True),
        sa.Column("processed", sa.Boolean(), server_default=sa.false(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_events_timestamp"), "events", ["timestamp"])
    op.create_index(op.f("ix_events_source"), "events", ["source"])

    # ── iocs ──────────────────────────────────────────────────────────────────
    op.create_table(
        "iocs",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("ioc_type", sa.String(), nullable=False),
        sa.Column("value", sa.String(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("source", sa.String(), nullable=True),
        sa.Column("tags", sa.JSON(), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("active", sa.Boolean(), server_default=sa.true(), nullable=True),
        sa.Column("metadata_", sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_iocs_value"), "iocs", ["value"])
    op.create_index(op.f("ix_iocs_ioc_type"), "iocs", ["ioc_type"])

    # ── alerts ────────────────────────────────────────────────────────────────
    op.create_table(
        "alerts",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("title", sa.String(), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(), nullable=True),
        sa.Column("status", sa.String(), server_default="open", nullable=True),
        sa.Column("source", sa.String(), nullable=True),
        sa.Column("ioc_matches", sa.JSON(), nullable=True),
        sa.Column("raw_data", sa.JSON(), nullable=True),
        sa.Column("assigned_to", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_alerts_severity"), "alerts", ["severity"])
    op.create_index(op.f("ix_alerts_status"), "alerts", ["status"])
    op.create_index(op.f("ix_alerts_created_at"), "alerts", ["created_at"])

    # ── soc_metrics ───────────────────────────────────────────────────────────
    op.create_table(
        "soc_metrics",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("metric_type", sa.String(), nullable=True),
        sa.Column("value", sa.Float(), nullable=True),
        sa.Column("unit", sa.String(), nullable=True),
        sa.Column("period_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("period_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metadata_", sa.JSON(), nullable=True),
        sa.Column("recorded_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )

    # ── artifacts ─────────────────────────────────────────────────────────────
    op.create_table(
        "artifacts",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("filename", sa.String(), nullable=True),
        sa.Column("file_type", sa.String(), nullable=True),
        sa.Column("file_size", sa.Integer(), nullable=True),
        sa.Column("md5", sa.String(), nullable=True),
        sa.Column("sha256", sa.String(), nullable=True),
        sa.Column("analysis_result", sa.JSON(), nullable=True),
        sa.Column("threat_level", sa.String(), nullable=True),
        sa.Column("uploaded_by", sa.String(), nullable=True),
        sa.Column("uploaded_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_artifacts_sha256"), "artifacts", ["sha256"])

    # ── neutralization_actions ────────────────────────────────────────────────
    op.create_table(
        "neutralization_actions",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("action_type", sa.String(), nullable=False),
        sa.Column("target", sa.String(), nullable=False),
        sa.Column("parameters", sa.JSON(), nullable=True),
        sa.Column("status", sa.String(), server_default="pending_approval", nullable=False),
        sa.Column("requested_by", sa.String(), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.Column("approved_by", sa.String(), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("result", sa.JSON(), nullable=True),
        sa.Column("approvals_log", sa.JSON(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("required_approvals", sa.Integer(), server_default="1", nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_neutralization_actions_status"), "neutralization_actions", ["status"])
    op.create_index(
        op.f("ix_neutralization_actions_requested_at"), "neutralization_actions", ["requested_at"]
    )

    # ── playbook_runs ─────────────────────────────────────────────────────────
    op.create_table(
        "playbook_runs",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("playbook_id", sa.String(), nullable=False),
        sa.Column("playbook_name", sa.String(), nullable=True),
        sa.Column("triggered_by", sa.String(), nullable=True),
        sa.Column("status", sa.String(), server_default="running", nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("steps_log", sa.JSON(), nullable=True),
        sa.Column("result", sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )

    # ── agents ────────────────────────────────────────────────────────────────
    op.create_table(
        "agents",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("hostname", sa.String(), nullable=False),
        sa.Column("ip_address", sa.String(), nullable=True),
        sa.Column("os_type", sa.String(), nullable=True),
        sa.Column("arch", sa.String(), nullable=True),
        sa.Column("version", sa.String(), nullable=True),
        sa.Column("public_key", sa.Text(), nullable=True),
        sa.Column("status", sa.String(), server_default="inactive", nullable=False),
        sa.Column("threat_level", sa.String(), server_default="normal", nullable=False),
        sa.Column("poll_interval", sa.Integer(), server_default="30", nullable=False),
        sa.Column("registered_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metadata_", sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_agents_hostname"), "agents", ["hostname"], unique=True)
    op.create_index(op.f("ix_agents_status"), "agents", ["status"])

    # ── agent_events ──────────────────────────────────────────────────────────
    op.create_table(
        "agent_events",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("agent_id", sa.String(), nullable=False),
        sa.Column("event_type", sa.String(), nullable=False),
        sa.Column("data", sa.JSON(), nullable=True),
        sa.Column("severity", sa.String(), server_default="info", nullable=False),
        sa.Column("anomaly_score", sa.Float(), server_default="0.0", nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_agent_events_agent_id"), "agent_events", ["agent_id"])
    op.create_index(op.f("ix_agent_events_ts"), "agent_events", ["ts"])

    # ── agent_commands ────────────────────────────────────────────────────────
    op.create_table(
        "agent_commands",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("agent_id", sa.String(), nullable=False),
        sa.Column("command_type", sa.String(), nullable=False),
        sa.Column("params", sa.JSON(), nullable=True),
        sa.Column("status", sa.String(), server_default="pending", nullable=False),
        sa.Column("issued_by", sa.String(), nullable=True),
        sa.Column("issued_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.Column("result", sa.JSON(), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("signature", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_agent_commands_agent_id"), "agent_commands", ["agent_id"])
    op.create_index(op.f("ix_agent_commands_status"), "agent_commands", ["status"])


def downgrade() -> None:
    op.drop_table("agent_commands")
    op.drop_table("agent_events")
    op.drop_table("agents")
    op.drop_table("playbook_runs")
    op.drop_table("neutralization_actions")
    op.drop_table("artifacts")
    op.drop_table("soc_metrics")
    op.drop_table("alerts")
    op.drop_table("iocs")
    op.drop_table("events")
    op.drop_table("revoked_tokens")
    op.drop_table("users")
