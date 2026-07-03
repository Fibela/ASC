"""
FASE 0.4 — Schema Integrity Check
Generates a SQL query to compare SQLAlchemy model column definitions
against the actual Supabase database. Run the output in Supabase SQL Editor.
"""
import sys, os
sys.path.insert(0, os.path.abspath("."))

# Use in-memory SQLite so we don't need a real Postgres connection
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase

engine = create_engine("sqlite:///:memory:")

# Import all models to register them with Base.metadata
from asc_api.models import (
    alert, event, ioc, metric, artifact, neutralization,
    agent, playbook_run, revoked_token, forensic_entry,
    threat_intel, hunt, pcdi, identity_action, soar,
    correlation, executive_report, api_key, webhook,
    incident, usage_record, tenant_adapter_config, user, tenant
)

# Get base from any model
from asc_api.models.alert import Base

# Create all tables in SQLite
Base.metadata.create_all(engine)

# Inspect SQLite schema
insp = inspect(engine)
table_names = sorted(insp.get_table_names())

print("-- FASE 0.4 Schema Integrity Check")
print("-- Run this in Supabase SQL Editor to see actual vs expected columns")
print("-- Tables defined in SQLAlchemy models:", len(table_names))
print()

# Generate model column map
model_columns = {}
for tname in table_names:
    cols = insp.get_columns(tname)
    model_columns[tname] = {c["name"]: str(c["type"]) for c in cols}

# Print expected tables
print("-- Expected tables from SQLAlchemy models:")
for t in table_names:
    print(f"--   {t}")
print()

# Generate Supabase query
print("SELECT")
print("  table_name,")
print("  column_name,")
print("  data_type,")
print("  is_nullable,")
print("  column_default")
print("FROM information_schema.columns")
print("WHERE table_schema = 'public'")
print("  AND table_name IN (")
for i, t in enumerate(table_names):
    comma = "," if i < len(table_names) - 1 else ""
    print(f"    '{t}'{comma}")
print(")")
print("ORDER BY table_name, ordinal_position;")
print()
print("-- Also check for tables in DB but NOT in models:")
print("SELECT table_name FROM information_schema.tables")
print("WHERE table_schema = 'public'")
print("  AND table_type = 'BASE TABLE'")
print("  AND table_name NOT IN (")
for i, t in enumerate(table_names + ["alembic_version"]):
    comma = "," if i < len(table_names) else ""
    print(f"    '{t}'{comma}")
print(");")

# Save expected column map for comparison
import json
os.makedirs("reports", exist_ok=True)
with open("reports/schema_expected_fase04.json", "w") as f:
    json.dump(model_columns, f, indent=2)
print()
print("-- Expected schema saved to reports/schema_expected_fase04.json")
print(f"-- Total: {len(table_names)} tables, {sum(len(v) for v in model_columns.values())} columns")
