"""add_incident_response_p28

Revision ID: k1e25h3j6d48
Revises: j9d14g2b5c37
Create Date: 2026-06-12 00:00:00.000000

P28-B — Incident Response Management: adds incidents, incident_links, and
incident_timeline tables implementing the NIST 800-61 lifecycle.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "k1e25h3j6d48"
down_revision = "j9d14g2b5c37"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── incidents ────────────────────────────────────────────────────────────
    op.create_table(
        "incidents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("incident_type", sa.String(50), nullable=False, server_default="other"),
        sa.Column("status", sa.String(30), nullable=False, server_default="detected"),
        sa.Column("nist_phase", sa.String(50), nullable=False, server_default="detection_analysis"),
        sa.Column("severity", sa.String(20), nullable=False, server_default="medium"),
        sa.Column("risk_score", sa.Float, nullable=False, server_default="0.0"),
        sa.Column("created_by", sa.String(256), nullable=False),
        sa.Column("assigned_to", sa.String(256), nullable=True),
        sa.Column("mitre_tactics", sa.JSON, nullable=False, server_default="[]"),
        sa.Column("mitre_techniques", sa.JSON, nullable=False, server_default="[]"),
        sa.Column("tags", sa.JSON, nullable=False, server_default="[]"),
        sa.Column("executive_summary", sa.Text, nullable=True),
        sa.Column("lessons_learned", sa.Text, nullable=True),
        sa.Column("root_cause", sa.Text, nullable=True),
        sa.Column("false_positive", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("sla_minutes", sa.Integer, nullable=False, server_default="240"),
        sa.Column("sla_breach", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("triaged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("contained_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("eradicated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("recovered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("mttd_minutes", sa.Integer, nullable=True),
        sa.Column("mttc_minutes", sa.Integer, nullable=True),
        sa.Column("mttr_minutes", sa.Integer, nullable=True),
        sa.Column("forensic_hash", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )
    op.create_index("ix_inc_status", "incidents", ["status"])
    op.create_index("ix_inc_severity", "incidents", ["severity"])
    op.create_index("ix_inc_incident_type", "incidents", ["incident_type"])
    op.create_index("ix_inc_assigned_to", "incidents", ["assigned_to"])
    op.create_index("ix_inc_created_at", "incidents", ["created_at"])
    op.create_index("ix_inc_sla_breach", "incidents", ["sla_breach"])

    # ── incident_links ────────────────────────────────────────────────────────
    op.create_table(
        "incident_links",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("incident_id", sa.String(36),
                  sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("entity_type", sa.String(50), nullable=False),
        sa.Column("entity_id", sa.String(36), nullable=False),
        sa.Column("notes", sa.Text, nullable=True),
        sa.Column("added_by", sa.String(256), nullable=False, server_default="system"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )
    op.create_index("ix_il_incident_id", "incident_links", ["incident_id"])
    op.create_index("ix_il_entity_type", "incident_links", ["entity_type"])
    op.create_index("ix_il_entity_id", "incident_links", ["entity_id"])

    # ── incident_timeline ─────────────────────────────────────────────────────
    op.create_table(
        "incident_timeline",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("incident_id", sa.String(36),
                  sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("event_type", sa.String(50), nullable=False),
        sa.Column("actor", sa.String(256), nullable=False, server_default="system"),
        sa.Column("detail", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )
    op.create_index("ix_it_incident_id", "incident_timeline", ["incident_id"])
    op.create_index("ix_it_event_type", "incident_timeline", ["event_type"])
    op.create_index("ix_it_created_at", "incident_timeline", ["created_at"])


def downgrade() -> None:
    op.drop_table("incident_timeline")
    op.drop_table("incident_links")
    op.drop_table("incidents")
