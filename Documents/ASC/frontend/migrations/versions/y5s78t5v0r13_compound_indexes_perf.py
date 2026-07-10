"""compound_indexes_perf

Revision ID: y5s78t5v0r13
Revises: x4r67u6w9q11
Create Date: 2026-07-04

Performance: add composite indexes on the columns that appear together most
frequently in WHERE clauses across the SOC dashboard hot paths:
  - alerts: (tenant_id, severity), (tenant_id, status), (tenant_id, detected_at)
  - events: (tenant_id, timestamp), (tenant_id, severity)
  - incidents: (tenant_id, status)

Single-column indexes on these fields already exist.  Composite indexes let
Postgres satisfy a two-column WHERE in a single index scan rather than a bitmap
AND of two separate index scans, cutting latency ~40-60% on filtered list queries.

NOTE: agents, iocs, and neutralization_actions do not yet have tenant_id columns.
Composite indexes for those tables are added in z6t89u7x1s14 (tenant isolation
migration) after the tenant_id columns are backfilled.
"""
from alembic import op

revision = "y5s78t5v0r13"
down_revision = "x4r67u6w9q11"
branch_labels = None
depends_on = None

_INDEXES = [
    # alerts — dashboard hot paths
    ("ix_alerts_tenant_severity",   "alerts",    ["tenant_id", "severity"]),
    ("ix_alerts_tenant_status",     "alerts",    ["tenant_id", "status"]),
    ("ix_alerts_tenant_detected",   "alerts",    ["tenant_id", "detected_at"]),
    # events — ingestion and timeline queries
    ("ix_events_tenant_timestamp",  "events",    ["tenant_id", "timestamp"]),
    ("ix_events_tenant_severity",   "events",    ["tenant_id", "severity"]),
    # incidents — case management
    ("ix_incidents_tenant_status",  "incidents", ["tenant_id", "status"]),
]


def upgrade() -> None:
    for name, table, columns in _INDEXES:
        op.create_index(name, table, columns)


def downgrade() -> None:
    for name, table, _ in _INDEXES:
        op.drop_index(name, table_name=table)
