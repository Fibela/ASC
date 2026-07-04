"""tenant_isolation — add tenant_id to ops models

Revision ID: z6t89u7x1s14
Revises: y5s78t5v0r13
Create Date: 2026-07-04

Security fix: adds tenant_id (nullable, VARCHAR 36) to every table that participates
in the Operational Dashboard and related SOC pillars but was missing multi-tenant
isolation.  NULL means "pre-migration row — not yet claimed by a tenant."

Tables affected:
  agents, agent_commands
  neutralization_actions
  iocs, threat_intel_indicators
  hunt_sessions, hunt_findings, hunt_queries
  pcdi_signed_reports
  playbook_triggers, scheduled_reports
  identity_actions
  correlation_rules, correlation_clusters, correlation_signals

After deploying this migration, re-register SPECTER agents (they will receive a
tenant_id from the registration token) and re-create any IOC/hunt data.
Existing production rows remain readable but will be excluded from tenant-scoped
queries until back-filled.

Also adds compound indexes on (tenant_id, status|type|…) for the new columns —
these are the indexes that were incorrectly included in y5s78t5v0r13.
"""
import sqlalchemy as sa
from alembic import op

revision = "z6t89u7x1s14"
down_revision = "y5s78t5v0r13"
branch_labels = None
depends_on = None

# Tables that need a tenant_id column added
_TABLES = [
    "agents",
    "agent_commands",
    "neutralization_actions",
    "iocs",
    "threat_intel_indicators",
    "hunt_sessions",
    "hunt_findings",
    "hunt_queries",
    "pcdi_signed_reports",
    "playbook_triggers",
    "scheduled_reports",
    "identity_actions",
    "correlation_rules",
    "correlation_clusters",
    "correlation_signals",
]

# Compound indexes to add after the columns exist
_INDEXES = [
    ("ix_agents_tenant_status",        "agents",                   ["tenant_id", "status"]),
    ("ix_agent_cmds_tenant_status",    "agent_commands",           ["tenant_id", "status"]),
    ("ix_neutralize_tenant_status",    "neutralization_actions",   ["tenant_id", "status"]),
    ("ix_iocs_tenant_type",            "iocs",                     ["tenant_id", "ioc_type"]),
    ("ix_iocs_tenant_active",          "iocs",                     ["tenant_id", "active"]),
    ("ix_ti_tenant_severity",          "threat_intel_indicators",  ["tenant_id", "severity"]),
    ("ix_hunts_tenant_status",         "hunt_sessions",            ["tenant_id", "status"]),
    ("ix_hunt_findings_tenant_sev",    "hunt_findings",            ["tenant_id", "severity"]),
    ("ix_pcdi_tenant_signed",          "pcdi_signed_reports",      ["tenant_id", "signed_at"]),
    ("ix_playbook_tenant_enabled",     "playbook_triggers",        ["tenant_id", "enabled"]),
    ("ix_identity_tenant_executed",    "identity_actions",         ["tenant_id", "executed_at"]),
]


def upgrade() -> None:
    for table in _TABLES:
        op.add_column(table, sa.Column("tenant_id", sa.String(36), nullable=True))
        op.create_index(f"ix_{table}_tenant_id", table, ["tenant_id"])

    for name, table, columns in _INDEXES:
        op.create_index(name, table, columns)


def downgrade() -> None:
    for name, table, _ in reversed(_INDEXES):
        op.drop_index(name, table_name=table)

    for table in reversed(_TABLES):
        op.drop_index(f"ix_{table}_tenant_id", table_name=table)
        op.drop_column(table, "tenant_id")
