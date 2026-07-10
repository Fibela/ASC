"""enable_rls_all_tables_s6

Revision ID: x4r67u6w9q11
Revises: w3q56t5v8p10
Create Date: 2026-07-03

Session 6 security hardening: 34/37 tables had RLS disabled, exposing all
rows to any request using the Supabase anon key via PostgREST. This migration
enables RLS on every application table and revokes direct SELECT/INSERT/UPDATE/
DELETE from the anon and authenticated roles so PostgREST returns 401 for
unauthenticated access. The application connects as the postgres superuser and
is unaffected — superusers bypass RLS by design.
"""
from alembic import op
from sqlalchemy import text

revision = "x4r67u6w9q11"
down_revision = "w3q56t5v8p10"
branch_labels = None
depends_on = None

# All application tables that must have RLS enforced.
# Tables intentionally excluded: none (all app tables need protection).
_TABLES = [
    "agent_commands",
    "agent_events",
    "agents",
    "alerts",
    "api_keys",
    "artifacts",
    "correlation_clusters",
    "correlation_rules",
    "correlation_signals",
    "events",
    "executive_reports",
    "forensic_ledger",
    "honeypot_evidence_reports",
    "honeypot_token_accesses",
    "honeypot_tokens",
    "hunt_findings",
    "hunt_queries",
    "hunt_sessions",
    "identity_actions",
    "incident_links",
    "incident_timeline",
    "incidents",
    "iocs",
    "neutralization_actions",
    "pcdi_signed_reports",
    "playbook_runs",
    "playbook_triggers",
    "revoked_tokens",
    "scheduled_reports",
    "soc_metrics",
    "tenant_adapter_configs",
    "tenants",
    "threat_intel_indicators",
    "usage_records",
    "users",
    "webhooks",
]


def upgrade() -> None:
    conn = op.get_bind()
    for table in _TABLES:
        # Enable RLS (no-op if already enabled — safe to re-run)
        conn.execute(
            text(f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY;")
        )
        # Force RLS even for table owner (superuser is still exempt)
        conn.execute(
            text(f"ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY;")
        )
        # Revoke all direct access from PostgREST roles
        conn.execute(
            text(
                f"REVOKE ALL ON public.{table} FROM anon, authenticated;"
            )
        )


def downgrade() -> None:
    conn = op.get_bind()
    for table in _TABLES:
        # Re-grant default PostgREST privileges (restores pre-hardening state)
        conn.execute(
            text(
                f"GRANT SELECT, INSERT, UPDATE, DELETE ON public.{table} "
                f"TO anon, authenticated;"
            )
        )
        conn.execute(
            text(
                f"ALTER TABLE public.{table} NO FORCE ROW LEVEL SECURITY;"
            )
        )
        conn.execute(
            text(
                f"ALTER TABLE public.{table} DISABLE ROW LEVEL SECURITY;"
            )
        )
