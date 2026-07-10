-- ============================================================
-- ASC PremosCorp — Migraciones de producción pendientes
-- Desde: w3q56t5v8p10 (honeypot_tables_p61)
-- Hasta: a8c01v9x3y26 (correlation_global_rules)
--
-- Ejecutar en: Supabase Dashboard → SQL Editor
-- Proyecto: kqxwtayzqujlddviskwl (ASC DB)
--
-- Las 5 migraciones incluidas:
--   x4r67u6w9q11 — RLS en todas las tablas
--   y5s78t5v0r13 — Índices compuestos de performance
--   z6t89u7x1s14 — tenant_id en tablas de ops (nullable)
--   a7b90v8w2x25 — tenant_id en artifacts
--   a8c01v9x3y26 — Índices parciales únicos en correlation_rules
-- ============================================================

BEGIN;

-- ── x4r67u6w9q11: RLS en todas las tablas ─────────────────────────────────────

ALTER TABLE public.agent_commands ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.agent_commands FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.agent_commands FROM anon, authenticated;

ALTER TABLE public.agent_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.agent_events FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.agent_events FROM anon, authenticated;

ALTER TABLE public.agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.agents FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.agents FROM anon, authenticated;

ALTER TABLE public.alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.alerts FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.alerts FROM anon, authenticated;

ALTER TABLE public.api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.api_keys FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.api_keys FROM anon, authenticated;

ALTER TABLE public.artifacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.artifacts FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.artifacts FROM anon, authenticated;

ALTER TABLE public.correlation_clusters ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.correlation_clusters FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.correlation_clusters FROM anon, authenticated;

ALTER TABLE public.correlation_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.correlation_rules FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.correlation_rules FROM anon, authenticated;

ALTER TABLE public.correlation_signals ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.correlation_signals FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.correlation_signals FROM anon, authenticated;

ALTER TABLE public.events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.events FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.events FROM anon, authenticated;

ALTER TABLE public.executive_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.executive_reports FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.executive_reports FROM anon, authenticated;

ALTER TABLE public.forensic_ledger ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.forensic_ledger FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.forensic_ledger FROM anon, authenticated;

ALTER TABLE public.honeypot_evidence_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.honeypot_evidence_reports FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.honeypot_evidence_reports FROM anon, authenticated;

ALTER TABLE public.honeypot_token_accesses ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.honeypot_token_accesses FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.honeypot_token_accesses FROM anon, authenticated;

ALTER TABLE public.honeypot_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.honeypot_tokens FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.honeypot_tokens FROM anon, authenticated;

ALTER TABLE public.hunt_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.hunt_findings FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.hunt_findings FROM anon, authenticated;

ALTER TABLE public.hunt_queries ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.hunt_queries FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.hunt_queries FROM anon, authenticated;

ALTER TABLE public.hunt_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.hunt_sessions FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.hunt_sessions FROM anon, authenticated;

ALTER TABLE public.identity_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.identity_actions FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.identity_actions FROM anon, authenticated;

ALTER TABLE public.incident_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.incident_links FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.incident_links FROM anon, authenticated;

ALTER TABLE public.incident_timeline ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.incident_timeline FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.incident_timeline FROM anon, authenticated;

ALTER TABLE public.incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.incidents FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.incidents FROM anon, authenticated;

ALTER TABLE public.iocs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.iocs FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.iocs FROM anon, authenticated;

ALTER TABLE public.neutralization_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.neutralization_actions FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.neutralization_actions FROM anon, authenticated;

ALTER TABLE public.pcdi_signed_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.pcdi_signed_reports FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.pcdi_signed_reports FROM anon, authenticated;

ALTER TABLE public.playbook_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.playbook_runs FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.playbook_runs FROM anon, authenticated;

ALTER TABLE public.playbook_triggers ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.playbook_triggers FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.playbook_triggers FROM anon, authenticated;

ALTER TABLE public.revoked_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.revoked_tokens FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.revoked_tokens FROM anon, authenticated;

ALTER TABLE public.scheduled_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scheduled_reports FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.scheduled_reports FROM anon, authenticated;

ALTER TABLE public.soc_metrics ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.soc_metrics FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.soc_metrics FROM anon, authenticated;

ALTER TABLE public.tenant_adapter_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_adapter_configs FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.tenant_adapter_configs FROM anon, authenticated;

ALTER TABLE public.tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.tenants FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.tenants FROM anon, authenticated;

ALTER TABLE public.threat_intel_indicators ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.threat_intel_indicators FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.threat_intel_indicators FROM anon, authenticated;

ALTER TABLE public.usage_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.usage_records FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.usage_records FROM anon, authenticated;

ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.users FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.users FROM anon, authenticated;

ALTER TABLE public.webhooks ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.webhooks FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.webhooks FROM anon, authenticated;

UPDATE alembic_version SET version_num='x4r67u6w9q11' WHERE alembic_version.version_num = 'w3q56t5v8p10';

-- ── y5s78t5v0r13: Índices compuestos de performance ───────────────────────────

CREATE INDEX IF NOT EXISTS ix_alerts_tenant_severity ON alerts (tenant_id, severity);
CREATE INDEX IF NOT EXISTS ix_alerts_tenant_status ON alerts (tenant_id, status);
CREATE INDEX IF NOT EXISTS ix_alerts_tenant_detected ON alerts (tenant_id, detected_at);
CREATE INDEX IF NOT EXISTS ix_events_tenant_timestamp ON events (tenant_id, timestamp);
CREATE INDEX IF NOT EXISTS ix_events_tenant_severity ON events (tenant_id, severity);
CREATE INDEX IF NOT EXISTS ix_incidents_tenant_status ON incidents (tenant_id, status);

UPDATE alembic_version SET version_num='y5s78t5v0r13' WHERE alembic_version.version_num = 'x4r67u6w9q11';

-- ── z6t89u7x1s14: tenant_id nullable en tablas de operaciones ─────────────────

ALTER TABLE agents ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(36);
CREATE INDEX IF NOT EXISTS ix_agents_tenant_id ON agents (tenant_id);

ALTER TABLE agent_commands ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(36);
CREATE INDEX IF NOT EXISTS ix_agent_commands_tenant_id ON agent_commands (tenant_id);

ALTER TABLE neutralization_actions ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(36);
CREATE INDEX IF NOT EXISTS ix_neutralization_actions_tenant_id ON neutralization_actions (tenant_id);

ALTER TABLE iocs ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(36);
CREATE INDEX IF NOT EXISTS ix_iocs_tenant_id ON iocs (tenant_id);

ALTER TABLE threat_intel_indicators ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(36);
CREATE INDEX IF NOT EXISTS ix_threat_intel_indicators_tenant_id ON threat_intel_indicators (tenant_id);

ALTER TABLE hunt_sessions ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(36);
CREATE INDEX IF NOT EXISTS ix_hunt_sessions_tenant_id ON hunt_sessions (tenant_id);

ALTER TABLE hunt_findings ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(36);
CREATE INDEX IF NOT EXISTS ix_hunt_findings_tenant_id ON hunt_findings (tenant_id);

ALTER TABLE hunt_queries ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(36);
CREATE INDEX IF NOT EXISTS ix_hunt_queries_tenant_id ON hunt_queries (tenant_id);

ALTER TABLE pcdi_signed_reports ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(36);
CREATE INDEX IF NOT EXISTS ix_pcdi_signed_reports_tenant_id ON pcdi_signed_reports (tenant_id);

ALTER TABLE playbook_triggers ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(36);
CREATE INDEX IF NOT EXISTS ix_playbook_triggers_tenant_id ON playbook_triggers (tenant_id);

ALTER TABLE scheduled_reports ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(36);
CREATE INDEX IF NOT EXISTS ix_scheduled_reports_tenant_id ON scheduled_reports (tenant_id);

ALTER TABLE identity_actions ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(36);
CREATE INDEX IF NOT EXISTS ix_identity_actions_tenant_id ON identity_actions (tenant_id);

ALTER TABLE correlation_rules ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(36);
CREATE INDEX IF NOT EXISTS ix_correlation_rules_tenant_id ON correlation_rules (tenant_id);

ALTER TABLE correlation_clusters ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(36);
CREATE INDEX IF NOT EXISTS ix_correlation_clusters_tenant_id ON correlation_clusters (tenant_id);

ALTER TABLE correlation_signals ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(36);
CREATE INDEX IF NOT EXISTS ix_correlation_signals_tenant_id ON correlation_signals (tenant_id);

CREATE INDEX IF NOT EXISTS ix_agents_tenant_status ON agents (tenant_id, status);
CREATE INDEX IF NOT EXISTS ix_agent_cmds_tenant_status ON agent_commands (tenant_id, status);
CREATE INDEX IF NOT EXISTS ix_neutralize_tenant_status ON neutralization_actions (tenant_id, status);
CREATE INDEX IF NOT EXISTS ix_iocs_tenant_type ON iocs (tenant_id, ioc_type);
CREATE INDEX IF NOT EXISTS ix_iocs_tenant_active ON iocs (tenant_id, active);
CREATE INDEX IF NOT EXISTS ix_ti_tenant_severity ON threat_intel_indicators (tenant_id, severity);
CREATE INDEX IF NOT EXISTS ix_hunts_tenant_status ON hunt_sessions (tenant_id, status);
CREATE INDEX IF NOT EXISTS ix_hunt_findings_tenant_sev ON hunt_findings (tenant_id, severity);
CREATE INDEX IF NOT EXISTS ix_pcdi_tenant_signed ON pcdi_signed_reports (tenant_id, signed_at);
CREATE INDEX IF NOT EXISTS ix_playbook_tenant_enabled ON playbook_triggers (tenant_id, enabled);
CREATE INDEX IF NOT EXISTS ix_identity_tenant_executed ON identity_actions (tenant_id, executed_at);

UPDATE alembic_version SET version_num='z6t89u7x1s14' WHERE alembic_version.version_num = 'y5s78t5v0r13';

-- ── a7b90v8w2x25: tenant_id en artifacts ──────────────────────────────────────

ALTER TABLE artifacts ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(36);
CREATE INDEX IF NOT EXISTS ix_artifacts_tenant_id ON artifacts (tenant_id);
CREATE INDEX IF NOT EXISTS ix_artifacts_submitted_by ON artifacts (submitted_by);

UPDATE alembic_version SET version_num='a7b90v8w2x25' WHERE alembic_version.version_num = 'z6t89u7x1s14';

-- ── a8c01v9x3y26: índices parciales únicos en correlation_rules ───────────────

-- Eliminar la constraint global (nombre puede variar — ignorar si ya no existe)
DO $$
BEGIN
  ALTER TABLE correlation_rules DROP CONSTRAINT correlation_rules_name_key;
EXCEPTION WHEN undefined_object OR others THEN
  NULL; -- ya fue eliminada o nunca existió
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS uq_cr_global_name
  ON correlation_rules(name) WHERE tenant_id IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_cr_tenant_name
  ON correlation_rules(name, tenant_id) WHERE tenant_id IS NOT NULL;

UPDATE alembic_version SET version_num='a8c01v9x3y26' WHERE alembic_version.version_num = 'a7b90v8w2x25';

COMMIT;
