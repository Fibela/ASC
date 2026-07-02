"""add_threat_intel_indicators_p21

Revision ID: b1c92e3f7a05
Revises: a3f81e2d9047
Create Date: 2026-06-11

P21-F1: PremosCorp Threat Intelligence local indicator database.
Stores the authoritative TI corpus used for alert/IoC enrichment.
"""
from alembic import op
import sqlalchemy as sa

revision = "b1c92e3f7a05"
down_revision = "a3f81e2d9047"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "threat_intel_indicators",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("indicator_type", sa.String(50), nullable=False),
        sa.Column("value", sa.String(1024), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False, server_default="medium"),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0.5"),
        sa.Column("threat_actor", sa.String(200), nullable=True),
        sa.Column("malware_family", sa.String(200), nullable=True),
        sa.Column("campaign", sa.String(200), nullable=True),
        sa.Column("ttps", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("tags", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("source", sa.String(200), nullable=False, server_default="internal"),
        sa.Column("source_reference", sa.Text(), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("hit_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_hit_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.String(256), nullable=False, server_default="system"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_ti_value", "threat_intel_indicators", ["value"])
    op.create_index("ix_ti_type_value", "threat_intel_indicators", ["indicator_type", "value"])
    op.create_index("ix_ti_active", "threat_intel_indicators", ["active"])
    op.create_index("ix_ti_severity", "threat_intel_indicators", ["severity"])


def downgrade() -> None:
    op.drop_index("ix_ti_severity", "threat_intel_indicators")
    op.drop_index("ix_ti_active", "threat_intel_indicators")
    op.drop_index("ix_ti_type_value", "threat_intel_indicators")
    op.drop_index("ix_ti_value", "threat_intel_indicators")
    op.drop_table("threat_intel_indicators")
