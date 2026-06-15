"""add_correlation_engine_p27

Revision ID: j9d14g2b5c37
Revises: h8c05e3f0a16
Create Date: 2026-06-12 00:00:00.000000

P27-B — Correlation Engine: adds correlation_rules, correlation_clusters,
and correlation_signals tables and seeds 4 built-in pivot rules.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text

revision = "j9d14g2b5c37"
down_revision = "h8c05e3f0a16"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── correlation_rules ────────────────────────────────────────────────────
    op.create_table(
        "correlation_rules",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(256), nullable=False, unique=True),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("pivot_type", sa.String(50), nullable=False),
        sa.Column("min_signals", sa.Integer, nullable=False, server_default="2"),
        sa.Column("time_window_minutes", sa.Integer, nullable=False, server_default="60"),
        sa.Column("severity_threshold", sa.String(20), nullable=False, server_default="low"),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )
    op.create_index("ix_cr_pivot_type", "correlation_rules", ["pivot_type"])
    op.create_index("ix_cr_enabled", "correlation_rules", ["enabled"])

    # ── correlation_clusters ─────────────────────────────────────────────────
    op.create_table(
        "correlation_clusters",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("rule_id", sa.String(36),
                  sa.ForeignKey("correlation_rules.id", ondelete="CASCADE"), nullable=False),
        sa.Column("cluster_key", sa.String(512), nullable=False),
        sa.Column("cluster_type", sa.String(50), nullable=False),
        sa.Column("signal_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("severity", sa.String(20), nullable=False, server_default="low"),
        sa.Column("confidence_score", sa.Float, nullable=False, server_default="0.0"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("status", sa.String(30), nullable=False, server_default="active"),
        sa.Column("is_campaign", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("campaign_name", sa.String(256), nullable=True),
        sa.Column("distinct_signal_domains", sa.Integer, nullable=False, server_default="0"),
        sa.Column("analyst_notes", sa.Text, nullable=True),
        sa.Column("assigned_to", sa.String(256), nullable=True),
        sa.Column("forensic_hash", sa.String(128), nullable=True),
        sa.Column("meta", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )
    op.create_index("ix_cc_rule_id", "correlation_clusters", ["rule_id"])
    op.create_index("ix_cc_cluster_key", "correlation_clusters", ["cluster_key"])
    op.create_index("ix_cc_status", "correlation_clusters", ["status"])
    op.create_index("ix_cc_is_campaign", "correlation_clusters", ["is_campaign"])
    op.create_index("ix_cc_last_seen", "correlation_clusters", ["last_seen"])
    op.create_index("ix_cc_severity", "correlation_clusters", ["severity"])

    # ── correlation_signals ──────────────────────────────────────────────────
    op.create_table(
        "correlation_signals",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("cluster_id", sa.String(36),
                  sa.ForeignKey("correlation_clusters.id", ondelete="CASCADE"), nullable=False),
        sa.Column("signal_type", sa.String(50), nullable=False),
        sa.Column("signal_id", sa.String(36), nullable=False),
        sa.Column("pivot_value", sa.String(512), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False, server_default="low"),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("meta", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )
    op.create_index("ix_cs_cluster_id", "correlation_signals", ["cluster_id"])
    op.create_index("ix_cs_signal_type", "correlation_signals", ["signal_type"])
    op.create_index("ix_cs_signal_id", "correlation_signals", ["signal_id"])
    op.create_index("ix_cs_pivot_value", "correlation_signals", ["pivot_value"])
    op.create_index("ix_cs_timestamp", "correlation_signals", ["timestamp"])

    # ── Seed built-in rules ──────────────────────────────────────────────────
    conn = op.get_bind()
    import uuid as _uuid
    from datetime import datetime, timezone as _tz
    now = datetime.now(_tz.utc).isoformat()

    rules = [
        {
            "id": str(_uuid.uuid4()),
            "name": "R001 — Host Lateral Movement",
            "description": "Clusters signals sharing a host pivot to detect lateral movement campaigns.",
            "pivot_type": "host_pivot",
            "min_signals": 3,
            "time_window_minutes": 60,
            "severity_threshold": "medium",
            "enabled": True,
            "created_at": now,
            "updated_at": now,
        },
        {
            "id": str(_uuid.uuid4()),
            "name": "R002 — Identity Compromise",
            "description": "Groups identity-related signals to detect account takeover or credential abuse.",
            "pivot_type": "identity_pivot",
            "min_signals": 2,
            "time_window_minutes": 120,
            "severity_threshold": "medium",
            "enabled": True,
            "created_at": now,
            "updated_at": now,
        },
        {
            "id": str(_uuid.uuid4()),
            "name": "R003 — C2 IP Activity",
            "description": "Detects repeated contact with a suspicious IP across events, TI hits, and neutralizations.",
            "pivot_type": "ip_pivot",
            "min_signals": 2,
            "time_window_minutes": 60,
            "severity_threshold": "high",
            "enabled": True,
            "created_at": now,
            "updated_at": now,
        },
        {
            "id": str(_uuid.uuid4()),
            "name": "R004 — Malicious Domain Cluster",
            "description": "Groups domain-related signals to identify phishing or malware distribution infrastructure.",
            "pivot_type": "domain_pivot",
            "min_signals": 2,
            "time_window_minutes": 60,
            "severity_threshold": "medium",
            "enabled": True,
            "created_at": now,
            "updated_at": now,
        },
    ]
    for r in rules:
        conn.execute(
            text(
                "INSERT INTO correlation_rules "
                "(id, name, description, pivot_type, min_signals, time_window_minutes, "
                " severity_threshold, enabled, created_at, updated_at) "
                "VALUES (:id, :name, :description, :pivot_type, :min_signals, "
                ":time_window_minutes, :severity_threshold, :enabled, :created_at, :updated_at)"
            ),
            r,
        )


def downgrade() -> None:
    op.drop_table("correlation_signals")
    op.drop_table("correlation_clusters")
    op.drop_table("correlation_rules")
