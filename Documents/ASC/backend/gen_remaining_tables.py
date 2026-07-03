"""
FASE 0.4 — Generate PostgreSQL DDL for remaining 23 tables.
These were never in the initial Alembic migration or were added after.
Output: migrations_asc_remaining_tables.sql
"""
import sys, os
sys.path.insert(0, os.path.abspath("."))
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"

from sqlalchemy import create_engine, inspect
from sqlalchemy.dialects import postgresql

# Import all models
from asc_api.models import (
    alert, event, ioc, metric, artifact, neutralization,
    agent, playbook_run, revoked_token, forensic_entry,
    threat_intel, hunt, pcdi, identity_action, soar,
    correlation, executive_report, api_key, webhook,
    incident, usage_record, tenant_adapter_config, user, tenant
)
from asc_api.models.alert import Base

engine = create_engine("sqlite:///:memory:")
Base.metadata.create_all(engine)
insp = inspect(engine)

# Already patched in migrations_asc_schema_patch.sql
ALREADY_PATCHED = {
    "agents", "agent_events", "agent_commands",
    "alerts", "events", "iocs", "soc_metrics",
    "artifacts", "neutralization_actions", "playbook_runs",
}

# FK-safe creation order (parents before children)
# users → api_keys, webhooks
# correlation_rules → correlation_clusters → correlation_signals
# hunt_sessions → hunt_findings, hunt_queries
# incidents → incident_links, incident_timeline
FK_SAFE_ORDER = [
    "tenants",
    "users",
    "revoked_tokens",
    "api_keys",
    "webhooks",
    "correlation_rules",
    "correlation_clusters",
    "correlation_signals",
    "executive_reports",
    "forensic_ledger",
    "hunt_sessions",
    "hunt_findings",
    "hunt_queries",
    "identity_actions",
    "incidents",
    "incident_links",
    "incident_timeline",
    "pcdi_signed_reports",
    "playbook_triggers",
    "scheduled_reports",
    "tenant_adapter_configs",
    "threat_intel_indicators",
    "usage_records",
]

all_remaining = set(insp.get_table_names()) - ALREADY_PATCHED
REMAINING = [t for t in FK_SAFE_ORDER if t in all_remaining]
# Append any that might be missing from the order list
for t in sorted(all_remaining):
    if t not in REMAINING:
        REMAINING.append(t)

# Type mapping from SQLite type strings to PostgreSQL
def sqlite_to_pg(col_type: str, col_name: str) -> str:
    t = col_type.upper()
    if t in ("VARCHAR", "TEXT", "CLOB"):
        return "TEXT"
    if "VARCHAR" in t:
        n = t.replace("VARCHAR(", "").replace(")", "")
        return f"VARCHAR({n})"
    if t in ("INTEGER", "INT"):
        return "INTEGER"
    if t in ("BIGINT",):
        return "BIGINT"
    if t in ("FLOAT", "REAL", "NUMERIC"):
        return "FLOAT"
    if t in ("BOOLEAN", "BOOL"):
        return "BOOLEAN"
    if t in ("DATETIME",):
        return "TIMESTAMP WITH TIME ZONE"
    if t in ("JSON",):
        return "JSON"
    return t

lines = []
lines.append("-- =============================================================================")
lines.append("-- ASC PremosCorp -- Remaining Tables (FASE 0.4)")
lines.append("-- Creates 23 tables not in initial migration schema patch.")
lines.append("-- Safe to re-run: CREATE TABLE IF NOT EXISTS + ADD COLUMN IF NOT EXISTS")
lines.append("-- Target: Supabase SQL Editor (project ref: kqxwtayzqujlddviskwl)")
lines.append("-- =============================================================================")
lines.append("")
lines.append("BEGIN;")
lines.append("")

for tname in REMAINING:
    cols = insp.get_columns(tname)
    pk_cols = insp.get_pk_constraint(tname).get("constrained_columns", [])
    fks = insp.get_foreign_keys(tname)
    unique = insp.get_unique_constraints(tname)
    indexes = insp.get_indexes(tname)

    lines.append(f"-- {'-' * 74}")
    lines.append(f"-- {tname}")
    lines.append(f"CREATE TABLE IF NOT EXISTS {tname} (")

    col_defs = []
    for col in cols:
        pg_type = sqlite_to_pg(str(col["type"]), col["name"])
        nullable = "" if col["nullable"] else " NOT NULL"
        default = ""
        if col["default"] is not None:
            d = str(col["default"])
            # SQLite stores defaults differently; convert common ones
            if d.upper() in ("TRUE", "1"):
                default = " DEFAULT true"
            elif d.upper() in ("FALSE", "0"):
                default = " DEFAULT false"
            elif d == "now()":
                default = " DEFAULT now()"
            elif d.startswith("'") or d.isdigit() or d.startswith("0."):
                default = f" DEFAULT {d}"
        col_defs.append(f"    {col['name']:<30} {pg_type}{default}{nullable}")

    # Add PK constraint
    if pk_cols:
        col_defs.append(f"    CONSTRAINT pk_{tname} PRIMARY KEY ({', '.join(pk_cols)})")

    # Add FK constraints
    for fk in fks:
        ref_cols = ", ".join(fk["referred_columns"])
        local_cols = ", ".join(fk["constrained_columns"])
        ref_table = fk["referred_table"]
        fk_name = f"fk_{tname}_{'_'.join(fk['constrained_columns'])}_{ref_table}"
        col_defs.append(
            f"    CONSTRAINT {fk_name} FOREIGN KEY({local_cols}) "
            f"REFERENCES {ref_table} ({ref_cols})"
        )

    lines.append(",\n".join(col_defs))
    lines.append(");")

    # Unique constraints
    for u in unique:
        u_name = u.get("name") or f"uq_{tname}_{'_'.join(u['column_names'])}"
        cols_str = ", ".join(u["column_names"])
        lines.append(
            f"CREATE UNIQUE INDEX IF NOT EXISTS {u_name} ON {tname} ({cols_str});"
        )

    # Regular indexes (non-PK, non-unique)
    for idx in indexes:
        if idx.get("unique"):
            continue  # already handled above
        idx_name = idx.get("name") or f"ix_{tname}_{'_'.join(idx['column_names'])}"
        cols_str = ", ".join(idx["column_names"])
        lines.append(
            f"CREATE INDEX IF NOT EXISTS {idx_name} ON {tname} ({cols_str});"
        )

    lines.append("")

lines.append("COMMIT;")
lines.append("")
lines.append("-- =============================================================================")
lines.append(f"-- END -- {len(REMAINING)} remaining tables created/verified")
lines.append("-- =============================================================================")

sql = "\n".join(lines)
out = "migrations_asc_remaining_tables.sql"
with open(out, "w", encoding="utf-8") as f:
    f.write(sql)

print(f"Generated {out}")
print(f"Tables: {len(REMAINING)}")
for t in REMAINING:
    print(f"  - {t}")
