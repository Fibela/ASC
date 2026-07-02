"""add identity_actions table and extend playbook_triggers for PIDS P26

Revision ID: h8c05e3f0a16
Revises: f6a83c1d9e04
Create Date: 2026-06-12 00:00:00.000000

Changes:
  - New table: identity_actions (PIDS forensic IAM action log)
  - Alter table: playbook_triggers — add priority, rate_limit_per_hour, dedup_window_minutes
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "h8c05e3f0a16"
down_revision = "f6a83c1d9e04"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── identity_actions ──────────────────────────────────────────────────────
    op.create_table(
        "identity_actions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("action_type", sa.String(50), nullable=False),
        sa.Column("username", sa.String(256), nullable=False),
        sa.Column("domain", sa.String(256), nullable=False, server_default="corp.local"),
        sa.Column("reason", sa.Text(), nullable=False),
        # Context linkage
        sa.Column("hunt_id", sa.String(36), nullable=True),
        sa.Column("finding_id", sa.String(36), nullable=True),
        sa.Column("trigger_id", sa.String(36), nullable=True),
        sa.Column("playbook_run_id", sa.String(36), nullable=True),
        # Result
        sa.Column("success", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("result_detail", sa.Text(), nullable=True),
        # Forensic token
        sa.Column("hash_sha3_512", sa.String(128), nullable=True),
        sa.Column("signature_ed25519", sa.Text(), nullable=True),
        sa.Column("signed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("signed_by_email", sa.String(256), nullable=False, server_default="soar_auto"),
        # Audit
        sa.Column("initiated_by", sa.String(256), nullable=False),
        sa.Column(
            "executed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index("ix_ia_username", "identity_actions", ["username"])
    op.create_index("ix_ia_action_type", "identity_actions", ["action_type"])
    op.create_index("ix_ia_hunt_id", "identity_actions", ["hunt_id"])
    op.create_index("ix_ia_executed_at", "identity_actions", ["executed_at"])
    op.create_index("ix_ia_success", "identity_actions", ["success"])

    # ── playbook_triggers — add adaptive orchestration columns ─────────────────
    op.add_column(
        "playbook_triggers",
        sa.Column("priority", sa.Integer(), nullable=False, server_default="5"),
    )
    op.add_column(
        "playbook_triggers",
        sa.Column("rate_limit_per_hour", sa.Integer(), nullable=False, server_default="10"),
    )
    op.add_column(
        "playbook_triggers",
        sa.Column("dedup_window_minutes", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("playbook_triggers", "dedup_window_minutes")
    op.drop_column("playbook_triggers", "rate_limit_per_hour")
    op.drop_column("playbook_triggers", "priority")

    op.drop_index("ix_ia_success", table_name="identity_actions")
    op.drop_index("ix_ia_executed_at", table_name="identity_actions")
    op.drop_index("ix_ia_hunt_id", table_name="identity_actions")
    op.drop_index("ix_ia_action_type", table_name="identity_actions")
    op.drop_index("ix_ia_username", table_name="identity_actions")
    op.drop_table("identity_actions")
