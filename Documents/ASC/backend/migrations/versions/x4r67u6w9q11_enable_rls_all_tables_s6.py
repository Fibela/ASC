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

revision = "x4r67u6w9q11"
down_revision = "w3q56t5v8p10"
branch_labels = None
depends_on = None

# All application tables that must have RLS enforced.
# Tables intentionally excluded: none (all app tables need protection).
_TABLES = [
    "users",
    "tenants",
    "alerts",
    "events",
    "iocs",
    "neutralization_actions",
    "playbooks",
    "playbook_steps",
    "api_keys",
    "webhooks",
    "webhook_deliveries",
    "agents",
    "agent_commands",
    "threat_intel_indicators",
    "hunt_sessions",
    "hunt_matches",
    "forensic_ledger",
    "pcdi_reports",
    "correlation_rules",
    "correlation_events",
    "incidents",
    "incident_notes",
    "executive_reports",
    "identity_actions",
    "pids_registry",
    "soar_playbooks",
    "soar_triggers",
    "scheduled_reports",
    "onboarding_checklist",
    "usage_records",
    "adapter_registry",
    "stripe_checkouts",
    "honeypot_tokens",
    "honeypot_evidence",
]


def upgrade() -> None:
    conn = op.get_bind()
    for table in _TABLES:
        # Enable RLS (no-op if already enabled — safe to re-run)
        conn.execute(
            op.inline_literal(f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY;")
        )
        # Force RLS even for table owner (superuser is still exempt)
        conn.execute(
            op.inline_literal(f"ALTER TABLE public.{table} FORCE ROW LEVEL SECURITY;")
        )
        # Revoke all direct access from PostgREST roles
        conn.execute(
            op.inline_literal(
                f"REVOKE ALL ON public.{table} FROM anon, authenticated;"
            )
        )


def downgrade() -> None:
    conn = op.get_bind()
    for table in _TABLES:
        # Re-grant default PostgREST privileges (restores pre-hardening state)
        conn.execute(
            op.inline_literal(
                f"GRANT SELECT, INSERT, UPDATE, DELETE ON public.{table} "
                f"TO anon, authenticated;"
            )
        )
        conn.execute(
            op.inline_literal(
                f"ALTER TABLE public.{table} NO FORCE ROW LEVEL SECURITY;"
            )
        )
        conn.execute(
            op.inline_literal(
                f"ALTER TABLE public.{table} DISABLE ROW LEVEL SECURITY;"
            )
        )
