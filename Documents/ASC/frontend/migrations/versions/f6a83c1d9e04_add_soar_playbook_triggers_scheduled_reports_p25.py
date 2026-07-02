"""add soar playbook_triggers scheduled_reports p25

Revision ID: f6a83c1d9e04
Revises: d4f92b1a8e36
Create Date: 2026-06-11

Tables: playbook_triggers, scheduled_reports
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "f6a83c1d9e04"
down_revision = "d4f92b1a8e36"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "playbook_triggers",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("playbook_id", sa.String(20), nullable=False),
        sa.Column("playbook_name", sa.String(256), nullable=False, server_default=""),
        sa.Column("condition_type", sa.String(50), nullable=False),
        sa.Column("condition_operator", sa.String(20), nullable=False, server_default="gte"),
        sa.Column("condition_value", sa.String(256), nullable=False),
        sa.Column("hunt_id_filter", sa.String(36), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("trigger_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_triggered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_triggered_context", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(256), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_pt_playbook_id", "playbook_triggers", ["playbook_id"])
    op.create_index("ix_pt_condition_type", "playbook_triggers", ["condition_type"])
    op.create_index("ix_pt_enabled", "playbook_triggers", ["enabled"])

    op.create_table(
        "scheduled_reports",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("hunt_id", sa.String(36), nullable=False),
        sa.Column("hunt_name", sa.String(256), nullable=True),
        sa.Column("recipient_email", sa.String(256), nullable=False),
        sa.Column("frequency", sa.String(20), nullable=False, server_default="daily"),
        sa.Column("format", sa.String(10), nullable=False, server_default="json"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("last_sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("send_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(256), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_sr_hunt_id", "scheduled_reports", ["hunt_id"])
    op.create_index("ix_sr_enabled", "scheduled_reports", ["enabled"])
    op.create_index("ix_sr_frequency", "scheduled_reports", ["frequency"])


def downgrade() -> None:
    op.drop_index("ix_sr_frequency", "scheduled_reports")
    op.drop_index("ix_sr_enabled", "scheduled_reports")
    op.drop_index("ix_sr_hunt_id", "scheduled_reports")
    op.drop_table("scheduled_reports")

    op.drop_index("ix_pt_enabled", "playbook_triggers")
    op.drop_index("ix_pt_condition_type", "playbook_triggers")
    op.drop_index("ix_pt_playbook_id", "playbook_triggers")
    op.drop_table("playbook_triggers")
