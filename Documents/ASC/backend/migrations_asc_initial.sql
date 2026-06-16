-- =============================================================================
-- ASC PremosCorp — Initial Schema (idempotente, safe to re-run)
-- Target: Supabase SQL Editor (project ref: kqxwtayzqujlddviskwl)
--
-- Todos los CREATE usan IF NOT EXISTS.
-- ALTER TABLE usa ADD COLUMN IF NOT EXISTS.
-- alembic_version se fija una sola vez al final.
-- =============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS alembic_version (
    version_num VARCHAR(32) NOT NULL,
    CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)
);

-- ── initial_schema_p16 ───────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS users (
    id VARCHAR NOT NULL,
    email VARCHAR NOT NULL,
    full_name VARCHAR,
    hashed_password VARCHAR NOT NULL,
    role VARCHAR DEFAULT 'analyst' NOT NULL,
    is_active BOOLEAN DEFAULT true NOT NULL,
    last_login TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    failed_login_attempts INTEGER DEFAULT 0 NOT NULL,
    locked_until TIMESTAMP WITH TIME ZONE,
    force_password_reset BOOLEAN DEFAULT false NOT NULL,
    signing_public_key VARCHAR(64),
    signing_private_key_enc VARCHAR(512),
    CONSTRAINT pk_users PRIMARY KEY (id)
);
CREATE UNIQUE INDEX IF NOT EXISTS ix_users_email ON users (email);

CREATE TABLE IF NOT EXISTS revoked_tokens (
    id VARCHAR NOT NULL,
    jti VARCHAR NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    revoked_by VARCHAR,
    reason VARCHAR,
    CONSTRAINT pk_revoked_tokens PRIMARY KEY (id),
    CONSTRAINT uq_revoked_tokens_jti UNIQUE (jti)
);
CREATE UNIQUE INDEX IF NOT EXISTS ix_revoked_tokens_jti ON revoked_tokens (jti);
CREATE INDEX IF NOT EXISTS ix_revoked_tokens_expires_at ON revoked_tokens (expires_at);

CREATE TABLE IF NOT EXISTS events (
    id VARCHAR NOT NULL,
    source VARCHAR,
    event_type VARCHAR,
    severity VARCHAR,
    raw_log TEXT,
    parsed_data JSON,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT now(),
    processed BOOLEAN DEFAULT false,
    CONSTRAINT pk_events PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS ix_events_timestamp ON events (timestamp);
CREATE INDEX IF NOT EXISTS ix_events_source ON events (source);

CREATE TABLE IF NOT EXISTS iocs (
    id VARCHAR NOT NULL,
    ioc_type VARCHAR NOT NULL,
    value VARCHAR NOT NULL,
    confidence FLOAT,
    source VARCHAR,
    tags JSON,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT now(),
    last_seen TIMESTAMP WITH TIME ZONE,
    active BOOLEAN DEFAULT true,
    metadata_ JSON,
    CONSTRAINT pk_iocs PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS ix_iocs_value ON iocs (value);
CREATE INDEX IF NOT EXISTS ix_iocs_ioc_type ON iocs (ioc_type);

CREATE TABLE IF NOT EXISTS alerts (
    id VARCHAR NOT NULL,
    title VARCHAR,
    description TEXT,
    severity VARCHAR,
    status VARCHAR DEFAULT 'open',
    source VARCHAR,
    ioc_matches JSON,
    raw_data JSON,
    assigned_to VARCHAR,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE,
    resolved_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT pk_alerts PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS ix_alerts_severity ON alerts (severity);
CREATE INDEX IF NOT EXISTS ix_alerts_status ON alerts (status);
CREATE INDEX IF NOT EXISTS ix_alerts_created_at ON alerts (created_at);

CREATE TABLE IF NOT EXISTS soc_metrics (
    id VARCHAR NOT NULL,
    metric_type VARCHAR,
    value FLOAT,
    unit VARCHAR,
    period_start TIMESTAMP WITH TIME ZONE,
    period_end TIMESTAMP WITH TIME ZONE,
    metadata_ JSON,
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    CONSTRAINT pk_soc_metrics PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS artifacts (
    id VARCHAR NOT NULL,
    filename VARCHAR,
    file_type VARCHAR,
    file_size INTEGER,
    md5 VARCHAR,
    sha256 VARCHAR,
    analysis_result JSON,
    threat_level VARCHAR,
    uploaded_by VARCHAR,
    uploaded_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    CONSTRAINT pk_artifacts PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS ix_artifacts_sha256 ON artifacts (sha256);

CREATE TABLE IF NOT EXISTS neutralization_actions (
    id VARCHAR NOT NULL,
    action_type VARCHAR NOT NULL,
    target VARCHAR NOT NULL,
    parameters JSON,
    status VARCHAR DEFAULT 'pending_approval' NOT NULL,
    requested_by VARCHAR NOT NULL,
    requested_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    approved_by VARCHAR,
    approved_at TIMESTAMP WITH TIME ZONE,
    executed_at TIMESTAMP WITH TIME ZONE,
    result JSON,
    approvals_log JSON,
    expires_at TIMESTAMP WITH TIME ZONE,
    required_approvals INTEGER DEFAULT 1 NOT NULL,
    CONSTRAINT pk_neutralization_actions PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS ix_neutralization_actions_status ON neutralization_actions (status);
CREATE INDEX IF NOT EXISTS ix_neutralization_actions_requested_at ON neutralization_actions (requested_at);

CREATE TABLE IF NOT EXISTS playbook_runs (
    id VARCHAR NOT NULL,
    playbook_id VARCHAR NOT NULL,
    playbook_name VARCHAR,
    triggered_by VARCHAR,
    status VARCHAR DEFAULT 'running',
    started_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    completed_at TIMESTAMP WITH TIME ZONE,
    steps_log JSON,
    result JSON,
    CONSTRAINT pk_playbook_runs PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS agents (
    id VARCHAR NOT NULL,
    hostname VARCHAR NOT NULL,
    ip_address VARCHAR,
    os_type VARCHAR,
    arch VARCHAR,
    version VARCHAR,
    public_key TEXT,
    status VARCHAR DEFAULT 'inactive' NOT NULL,
    threat_level VARCHAR DEFAULT 'normal' NOT NULL,
    poll_interval INTEGER DEFAULT 30 NOT NULL,
    registered_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    last_seen TIMESTAMP WITH TIME ZONE,
    metadata_ JSON,
    CONSTRAINT pk_agents PRIMARY KEY (id)
);
CREATE UNIQUE INDEX IF NOT EXISTS ix_agents_hostname ON agents (hostname);
CREATE INDEX IF NOT EXISTS ix_agents_status ON agents (status);

CREATE TABLE IF NOT EXISTS agent_events (
    id VARCHAR NOT NULL,
    agent_id VARCHAR NOT NULL,
    event_type VARCHAR NOT NULL,
    data JSON,
    severity VARCHAR DEFAULT 'info' NOT NULL,
    anomaly_score FLOAT DEFAULT 0.0 NOT NULL,
    ts TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    CONSTRAINT pk_agent_events PRIMARY KEY (id),
    CONSTRAINT fk_agent_events_agent_id_agents FOREIGN KEY(agent_id) REFERENCES agents (id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS ix_agent_events_agent_id ON agent_events (agent_id);
CREATE INDEX IF NOT EXISTS ix_agent_events_ts ON agent_events (ts);

CREATE TABLE IF NOT EXISTS agent_commands (
    id VARCHAR NOT NULL,
    agent_id VARCHAR NOT NULL,
    command_type VARCHAR NOT NULL,
    params JSON,
    status VARCHAR DEFAULT 'pending' NOT NULL,
    issued_by VARCHAR,
    issued_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    result JSON,
    completed_at TIMESTAMP WITH TIME ZONE,
    signature TEXT,
    CONSTRAINT pk_agent_commands PRIMARY KEY (id),
    CONSTRAINT fk_agent_commands_agent_id_agents FOREIGN KEY(agent_id) REFERENCES agents (id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS ix_agent_commands_agent_id ON agent_commands (agent_id);
CREATE INDEX IF NOT EXISTS ix_agent_commands_status ON agent_commands (status);

-- ── add_forensic_ledger_p19 ──────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS forensic_ledger (
    id VARCHAR(36) NOT NULL,
    action_id VARCHAR(36) NOT NULL,
    action_type VARCHAR(50) NOT NULL,
    target VARCHAR(512) NOT NULL,
    canonical_data JSON NOT NULL,
    hash_sha3_512 VARCHAR(128) NOT NULL,
    signature_ed25519 TEXT NOT NULL,
    signed_by_email VARCHAR(256) NOT NULL,
    signed_by_user_id VARCHAR(36) NOT NULL,
    signed_at TIMESTAMP WITH TIME ZONE,
    verified BOOLEAN DEFAULT false NOT NULL,
    last_verified_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT pk_forensic_ledger PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS ix_forensic_ledger_action_id ON forensic_ledger (action_id);
CREATE INDEX IF NOT EXISTS ix_forensic_ledger_signed_by_user_id ON forensic_ledger (signed_by_user_id);

-- ── add_threat_intel_indicators_p21 ─────────────────────────────────────────

CREATE TABLE IF NOT EXISTS threat_intel_indicators (
    id VARCHAR(36) NOT NULL,
    indicator_type VARCHAR(50) NOT NULL,
    value VARCHAR(1024) NOT NULL,
    severity VARCHAR(20) DEFAULT 'medium' NOT NULL,
    confidence FLOAT DEFAULT 0.5 NOT NULL,
    threat_actor VARCHAR(200),
    malware_family VARCHAR(200),
    campaign VARCHAR(200),
    ttps JSON DEFAULT '[]' NOT NULL,
    tags JSON DEFAULT '[]' NOT NULL,
    source VARCHAR(200) DEFAULT 'internal' NOT NULL,
    source_reference TEXT,
    description TEXT,
    first_seen TIMESTAMP WITH TIME ZONE NOT NULL,
    last_seen TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE,
    active BOOLEAN DEFAULT true NOT NULL,
    hit_count INTEGER DEFAULT 0 NOT NULL,
    last_hit_at TIMESTAMP WITH TIME ZONE,
    created_by VARCHAR(256) DEFAULT 'system' NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT pk_threat_intel_indicators PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS ix_ti_value ON threat_intel_indicators (value);
CREATE INDEX IF NOT EXISTS ix_ti_type_value ON threat_intel_indicators (indicator_type, value);
CREATE INDEX IF NOT EXISTS ix_ti_active ON threat_intel_indicators (active);
CREATE INDEX IF NOT EXISTS ix_ti_severity ON threat_intel_indicators (severity);

-- ── add hunt tables p22 ──────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS hunt_sessions (
    id VARCHAR(36) NOT NULL,
    name VARCHAR(256) NOT NULL,
    description TEXT,
    hypothesis TEXT,
    status VARCHAR(30) DEFAULT 'draft' NOT NULL,
    mitre_technique VARCHAR(20),
    mitre_tactic VARCHAR(100),
    scope VARCHAR(50) DEFAULT 'all' NOT NULL,
    priority VARCHAR(20) DEFAULT 'medium' NOT NULL,
    created_by VARCHAR(256) NOT NULL,
    assigned_to VARCHAR(256),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    conclusion TEXT,
    findings_count INTEGER DEFAULT 0 NOT NULL,
    true_positive_count INTEGER DEFAULT 0 NOT NULL,
    tags JSON DEFAULT '[]' NOT NULL,
    CONSTRAINT pk_hunt_sessions PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS ix_hunt_status ON hunt_sessions (status);
CREATE INDEX IF NOT EXISTS ix_hunt_priority ON hunt_sessions (priority);
CREATE INDEX IF NOT EXISTS ix_hunt_created_by ON hunt_sessions (created_by);
CREATE INDEX IF NOT EXISTS ix_hunt_mitre ON hunt_sessions (mitre_technique);

CREATE TABLE IF NOT EXISTS hunt_findings (
    id VARCHAR(36) NOT NULL,
    hunt_id VARCHAR(36) NOT NULL,
    title VARCHAR(512) NOT NULL,
    description TEXT,
    severity VARCHAR(20) DEFAULT 'medium' NOT NULL,
    indicator_value VARCHAR(1024),
    indicator_type VARCHAR(50),
    affected_host VARCHAR(256),
    affected_user VARCHAR(256),
    data_source VARCHAR(100),
    mitre_technique VARCHAR(20),
    mitre_tactic VARCHAR(100),
    evidence JSON,
    is_confirmed BOOLEAN DEFAULT false NOT NULL,
    is_false_positive BOOLEAN DEFAULT false NOT NULL,
    analyst_notes TEXT,
    created_by VARCHAR(256) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT pk_hunt_findings PRIMARY KEY (id),
    CONSTRAINT fk_hunt_findings_hunt_id_hunt_sessions FOREIGN KEY(hunt_id) REFERENCES hunt_sessions (id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS ix_hf_hunt_id ON hunt_findings (hunt_id);
CREATE INDEX IF NOT EXISTS ix_hf_severity ON hunt_findings (severity);
CREATE INDEX IF NOT EXISTS ix_hf_confirmed ON hunt_findings (is_confirmed);

CREATE TABLE IF NOT EXISTS hunt_queries (
    id VARCHAR(36) NOT NULL,
    hunt_id VARCHAR(36) NOT NULL,
    name VARCHAR(256) NOT NULL,
    query_text TEXT NOT NULL,
    data_source VARCHAR(100) DEFAULT 'elk' NOT NULL,
    description TEXT,
    last_executed_at TIMESTAMP WITH TIME ZONE,
    last_result_count INTEGER,
    last_execution_ms INTEGER,
    created_by VARCHAR(256) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT pk_hunt_queries PRIMARY KEY (id),
    CONSTRAINT fk_hunt_queries_hunt_id_hunt_sessions FOREIGN KEY(hunt_id) REFERENCES hunt_sessions (id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS ix_hq_hunt_id ON hunt_queries (hunt_id);
CREATE INDEX IF NOT EXISTS ix_hq_data_source ON hunt_queries (data_source);

-- ── add_pcdi_signed_reports_p24 ──────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS pcdi_signed_reports (
    id VARCHAR(36) NOT NULL,
    hunt_id VARCHAR(36) NOT NULL,
    hunt_name VARCHAR(256),
    canonical_data JSON NOT NULL,
    hash_sha3_512 VARCHAR(128) NOT NULL,
    signature_ed25519 TEXT NOT NULL,
    signed_by_email VARCHAR(256) NOT NULL,
    signed_by_user_id VARCHAR(36),
    signed_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    verified BOOLEAN DEFAULT false NOT NULL,
    last_verified_at TIMESTAMP WITH TIME ZONE,
    pcdi_version VARCHAR(10) DEFAULT '1' NOT NULL,
    adaptive_score INTEGER,
    CONSTRAINT pk_pcdi_signed_reports PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS ix_pcdi_hunt_id ON pcdi_signed_reports (hunt_id);
CREATE INDEX IF NOT EXISTS ix_pcdi_signed_by ON pcdi_signed_reports (signed_by_email);
CREATE INDEX IF NOT EXISTS ix_pcdi_signed_at ON pcdi_signed_reports (signed_at);

-- ── add_soar_playbook_triggers_scheduled_reports_p25 ────────────────────────

CREATE TABLE IF NOT EXISTS playbook_triggers (
    id VARCHAR(36) NOT NULL,
    playbook_id VARCHAR(20) NOT NULL,
    playbook_name VARCHAR(256) DEFAULT '' NOT NULL,
    condition_type VARCHAR(50) NOT NULL,
    condition_operator VARCHAR(20) DEFAULT 'gte' NOT NULL,
    condition_value VARCHAR(256) NOT NULL,
    hunt_id_filter VARCHAR(36),
    enabled BOOLEAN DEFAULT true NOT NULL,
    trigger_count INTEGER DEFAULT 0 NOT NULL,
    last_triggered_at TIMESTAMP WITH TIME ZONE,
    last_triggered_context TEXT,
    created_by VARCHAR(256) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    priority INTEGER DEFAULT 5 NOT NULL,
    rate_limit_per_hour INTEGER DEFAULT 10 NOT NULL,
    dedup_window_minutes INTEGER DEFAULT 0 NOT NULL,
    CONSTRAINT pk_playbook_triggers PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS ix_pt_playbook_id ON playbook_triggers (playbook_id);
CREATE INDEX IF NOT EXISTS ix_pt_condition_type ON playbook_triggers (condition_type);
CREATE INDEX IF NOT EXISTS ix_pt_enabled ON playbook_triggers (enabled);

CREATE TABLE IF NOT EXISTS scheduled_reports (
    id VARCHAR(36) NOT NULL,
    hunt_id VARCHAR(36) NOT NULL,
    hunt_name VARCHAR(256),
    recipient_email VARCHAR(256) NOT NULL,
    frequency VARCHAR(20) DEFAULT 'daily' NOT NULL,
    format VARCHAR(10) DEFAULT 'json' NOT NULL,
    enabled BOOLEAN DEFAULT true NOT NULL,
    last_sent_at TIMESTAMP WITH TIME ZONE,
    send_count INTEGER DEFAULT 0 NOT NULL,
    last_error TEXT,
    created_by VARCHAR(256) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT pk_scheduled_reports PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS ix_sr_hunt_id ON scheduled_reports (hunt_id);
CREATE INDEX IF NOT EXISTS ix_sr_enabled ON scheduled_reports (enabled);
CREATE INDEX IF NOT EXISTS ix_sr_frequency ON scheduled_reports (frequency);

-- ── add_identity_actions_p26 ─────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS identity_actions (
    id VARCHAR(36) NOT NULL,
    action_type VARCHAR(50) NOT NULL,
    username VARCHAR(256) NOT NULL,
    domain VARCHAR(256) DEFAULT 'corp.local' NOT NULL,
    reason TEXT NOT NULL,
    hunt_id VARCHAR(36),
    finding_id VARCHAR(36),
    trigger_id VARCHAR(36),
    playbook_run_id VARCHAR(36),
    success BOOLEAN DEFAULT false NOT NULL,
    result_detail TEXT,
    hash_sha3_512 VARCHAR(128),
    signature_ed25519 TEXT,
    signed_at TIMESTAMP WITH TIME ZONE,
    signed_by_email VARCHAR(256) DEFAULT 'soar_auto' NOT NULL,
    initiated_by VARCHAR(256) NOT NULL,
    executed_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    CONSTRAINT pk_identity_actions PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS ix_ia_username ON identity_actions (username);
CREATE INDEX IF NOT EXISTS ix_ia_action_type ON identity_actions (action_type);
CREATE INDEX IF NOT EXISTS ix_ia_hunt_id ON identity_actions (hunt_id);
CREATE INDEX IF NOT EXISTS ix_ia_executed_at ON identity_actions (executed_at);
CREATE INDEX IF NOT EXISTS ix_ia_success ON identity_actions (success);

-- ── add_correlation_engine_p27 ───────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS correlation_rules (
    id VARCHAR(36) NOT NULL,
    name VARCHAR(256) NOT NULL,
    description TEXT,
    pivot_type VARCHAR(50) NOT NULL,
    min_signals INTEGER DEFAULT 2 NOT NULL,
    time_window_minutes INTEGER DEFAULT 60 NOT NULL,
    severity_threshold VARCHAR(20) DEFAULT 'low' NOT NULL,
    enabled BOOLEAN DEFAULT true NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    CONSTRAINT pk_correlation_rules PRIMARY KEY (id),
    CONSTRAINT uq_correlation_rules_name UNIQUE (name)
);
CREATE INDEX IF NOT EXISTS ix_cr_pivot_type ON correlation_rules (pivot_type);
CREATE INDEX IF NOT EXISTS ix_cr_enabled ON correlation_rules (enabled);

CREATE TABLE IF NOT EXISTS correlation_clusters (
    id VARCHAR(36) NOT NULL,
    rule_id VARCHAR(36) NOT NULL,
    cluster_key VARCHAR(512) NOT NULL,
    cluster_type VARCHAR(50) NOT NULL,
    signal_count INTEGER DEFAULT 0 NOT NULL,
    severity VARCHAR(20) DEFAULT 'low' NOT NULL,
    confidence_score FLOAT DEFAULT 0.0 NOT NULL,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    status VARCHAR(30) DEFAULT 'active' NOT NULL,
    is_campaign BOOLEAN DEFAULT false NOT NULL,
    campaign_name VARCHAR(256),
    distinct_signal_domains INTEGER DEFAULT 0 NOT NULL,
    analyst_notes TEXT,
    assigned_to VARCHAR(256),
    forensic_hash VARCHAR(128),
    meta JSON DEFAULT '{}' NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    CONSTRAINT pk_correlation_clusters PRIMARY KEY (id),
    CONSTRAINT fk_correlation_clusters_rule_id_correlation_rules FOREIGN KEY(rule_id) REFERENCES correlation_rules (id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS ix_cc_rule_id ON correlation_clusters (rule_id);
CREATE INDEX IF NOT EXISTS ix_cc_cluster_key ON correlation_clusters (cluster_key);
CREATE INDEX IF NOT EXISTS ix_cc_status ON correlation_clusters (status);
CREATE INDEX IF NOT EXISTS ix_cc_is_campaign ON correlation_clusters (is_campaign);
CREATE INDEX IF NOT EXISTS ix_cc_last_seen ON correlation_clusters (last_seen);
CREATE INDEX IF NOT EXISTS ix_cc_severity ON correlation_clusters (severity);

CREATE TABLE IF NOT EXISTS correlation_signals (
    id VARCHAR(36) NOT NULL,
    cluster_id VARCHAR(36) NOT NULL,
    signal_type VARCHAR(50) NOT NULL,
    signal_id VARCHAR(36) NOT NULL,
    pivot_value VARCHAR(512) NOT NULL,
    severity VARCHAR(20) DEFAULT 'low' NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    meta JSON DEFAULT '{}' NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    CONSTRAINT pk_correlation_signals PRIMARY KEY (id),
    CONSTRAINT fk_correlation_signals_cluster_id_correlation_clusters FOREIGN KEY(cluster_id) REFERENCES correlation_clusters (id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS ix_cs_cluster_id ON correlation_signals (cluster_id);
CREATE INDEX IF NOT EXISTS ix_cs_signal_type ON correlation_signals (signal_type);
CREATE INDEX IF NOT EXISTS ix_cs_signal_id ON correlation_signals (signal_id);
CREATE INDEX IF NOT EXISTS ix_cs_pivot_value ON correlation_signals (pivot_value);
CREATE INDEX IF NOT EXISTS ix_cs_timestamp ON correlation_signals (timestamp);

-- ── add_incident_response_p28 ────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS incidents (
    id VARCHAR(36) NOT NULL,
    title VARCHAR(512) NOT NULL,
    description TEXT,
    incident_type VARCHAR(50) DEFAULT 'other' NOT NULL,
    status VARCHAR(30) DEFAULT 'detected' NOT NULL,
    nist_phase VARCHAR(50) DEFAULT 'detection_analysis' NOT NULL,
    severity VARCHAR(20) DEFAULT 'medium' NOT NULL,
    risk_score FLOAT DEFAULT 0.0 NOT NULL,
    created_by VARCHAR(256) NOT NULL,
    assigned_to VARCHAR(256),
    mitre_tactics JSON DEFAULT '[]' NOT NULL,
    mitre_techniques JSON DEFAULT '[]' NOT NULL,
    tags JSON DEFAULT '[]' NOT NULL,
    executive_summary TEXT,
    lessons_learned TEXT,
    root_cause TEXT,
    false_positive BOOLEAN DEFAULT false NOT NULL,
    sla_minutes INTEGER DEFAULT 240 NOT NULL,
    sla_breach BOOLEAN DEFAULT false NOT NULL,
    detected_at TIMESTAMP WITH TIME ZONE,
    triaged_at TIMESTAMP WITH TIME ZONE,
    contained_at TIMESTAMP WITH TIME ZONE,
    eradicated_at TIMESTAMP WITH TIME ZONE,
    recovered_at TIMESTAMP WITH TIME ZONE,
    closed_at TIMESTAMP WITH TIME ZONE,
    mttd_minutes INTEGER,
    mttc_minutes INTEGER,
    mttr_minutes INTEGER,
    forensic_hash VARCHAR(128),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    CONSTRAINT pk_incidents PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS ix_inc_status ON incidents (status);
CREATE INDEX IF NOT EXISTS ix_inc_severity ON incidents (severity);
CREATE INDEX IF NOT EXISTS ix_inc_incident_type ON incidents (incident_type);
CREATE INDEX IF NOT EXISTS ix_inc_assigned_to ON incidents (assigned_to);
CREATE INDEX IF NOT EXISTS ix_inc_created_at ON incidents (created_at);
CREATE INDEX IF NOT EXISTS ix_inc_sla_breach ON incidents (sla_breach);

CREATE TABLE IF NOT EXISTS incident_links (
    id VARCHAR(36) NOT NULL,
    incident_id VARCHAR(36) NOT NULL,
    entity_type VARCHAR(50) NOT NULL,
    entity_id VARCHAR(36) NOT NULL,
    notes TEXT,
    added_by VARCHAR(256) DEFAULT 'system' NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    CONSTRAINT pk_incident_links PRIMARY KEY (id),
    CONSTRAINT fk_incident_links_incident_id_incidents FOREIGN KEY(incident_id) REFERENCES incidents (id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS ix_il_incident_id ON incident_links (incident_id);
CREATE INDEX IF NOT EXISTS ix_il_entity_type ON incident_links (entity_type);
CREATE INDEX IF NOT EXISTS ix_il_entity_id ON incident_links (entity_id);

CREATE TABLE IF NOT EXISTS incident_timeline (
    id VARCHAR(36) NOT NULL,
    incident_id VARCHAR(36) NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    actor VARCHAR(256) DEFAULT 'system' NOT NULL,
    detail JSON DEFAULT '{}' NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    CONSTRAINT pk_incident_timeline PRIMARY KEY (id),
    CONSTRAINT fk_incident_timeline_incident_id_incidents FOREIGN KEY(incident_id) REFERENCES incidents (id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS ix_it_incident_id ON incident_timeline (incident_id);
CREATE INDEX IF NOT EXISTS ix_it_event_type ON incident_timeline (event_type);
CREATE INDEX IF NOT EXISTS ix_it_created_at ON incident_timeline (created_at);

-- ── add_executive_reports_p29 ────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS executive_reports (
    id VARCHAR(36) NOT NULL,
    report_type VARCHAR(30) NOT NULL,
    period VARCHAR(20) DEFAULT 'custom' NOT NULL,
    title VARCHAR(512) NOT NULL,
    generated_by VARCHAR(256) NOT NULL,
    period_start TIMESTAMP WITH TIME ZONE NOT NULL,
    period_end TIMESTAMP WITH TIME ZONE NOT NULL,
    total_incidents INTEGER DEFAULT 0 NOT NULL,
    closed_incidents INTEGER DEFAULT 0 NOT NULL,
    sla_breach_count INTEGER DEFAULT 0 NOT NULL,
    campaign_count INTEGER DEFAULT 0 NOT NULL,
    avg_mttd_minutes FLOAT,
    avg_mttc_minutes FLOAT,
    avg_mttr_minutes FLOAT,
    canonical_data JSON DEFAULT '{}' NOT NULL,
    hash_sha3_512 VARCHAR(128) NOT NULL,
    signature_ed25519 TEXT NOT NULL,
    pubkey_fingerprint VARCHAR(32) DEFAULT '' NOT NULL,
    signature_valid BOOLEAN DEFAULT false NOT NULL,
    last_verified_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    CONSTRAINT pk_executive_reports PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS ix_er_report_type ON executive_reports (report_type);
CREATE INDEX IF NOT EXISTS ix_er_period_start ON executive_reports (period_start);
CREATE INDEX IF NOT EXISTS ix_er_generated_by ON executive_reports (generated_by);
CREATE INDEX IF NOT EXISTS ix_er_created_at ON executive_reports (created_at);

-- ── add_api_keys_p40 ─────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS api_keys (
    id VARCHAR(36) NOT NULL,
    name VARCHAR(100) NOT NULL,
    key_prefix VARCHAR(8) NOT NULL,
    key_hash VARCHAR(64) NOT NULL,
    user_id VARCHAR(36) NOT NULL,
    scopes JSON DEFAULT '[]' NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    CONSTRAINT pk_api_keys PRIMARY KEY (id),
    CONSTRAINT uq_api_keys_key_hash UNIQUE (key_hash),
    CONSTRAINT fk_api_keys_user_id_users FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS ix_api_keys_key_prefix ON api_keys (key_prefix);
CREATE INDEX IF NOT EXISTS ix_api_keys_key_hash ON api_keys (key_hash);
CREATE INDEX IF NOT EXISTS ix_api_keys_user_id ON api_keys (user_id);

-- ── add_webhooks_p42 ─────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS webhooks (
    id VARCHAR NOT NULL,
    url VARCHAR(2048) NOT NULL,
    secret VARCHAR(64) NOT NULL,
    events JSON,
    description VARCHAR(500),
    is_active BOOLEAN DEFAULT true NOT NULL,
    user_id VARCHAR NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    last_triggered_at TIMESTAMP WITH TIME ZONE,
    failure_count INTEGER DEFAULT 0 NOT NULL,
    CONSTRAINT pk_webhooks PRIMARY KEY (id),
    CONSTRAINT fk_webhooks_user_id_users FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS ix_webhooks_user_id ON webhooks (user_id);
CREATE INDEX IF NOT EXISTS ix_webhooks_is_active ON webhooks (is_active);

-- ── add_multi_tenancy_p47 ────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS tenants (
    id VARCHAR(36) NOT NULL,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) NOT NULL,
    plan VARCHAR(50) DEFAULT 'free' NOT NULL,
    is_active BOOLEAN DEFAULT true NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    contact_email VARCHAR(255),
    max_users INTEGER,
    max_api_keys_per_user INTEGER,
    CONSTRAINT pk_tenants PRIMARY KEY (id),
    CONSTRAINT uq_tenants_slug UNIQUE (slug)
);
CREATE UNIQUE INDEX IF NOT EXISTS ix_tenants_slug ON tenants (slug);
CREATE INDEX IF NOT EXISTS ix_tenants_is_active ON tenants (is_active);

ALTER TABLE users      ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(36);
CREATE INDEX IF NOT EXISTS ix_users_tenant_id ON users (tenant_id);

ALTER TABLE alerts     ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(36);
CREATE INDEX IF NOT EXISTS ix_alerts_tenant_id ON alerts (tenant_id);

ALTER TABLE events     ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(36);
CREATE INDEX IF NOT EXISTS ix_events_tenant_id ON events (tenant_id);

ALTER TABLE api_keys   ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(36);
CREATE INDEX IF NOT EXISTS ix_api_keys_tenant_id ON api_keys (tenant_id);

ALTER TABLE webhooks   ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(36);
CREATE INDEX IF NOT EXISTS ix_webhooks_tenant_id ON webhooks (tenant_id);

ALTER TABLE incidents  ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(36);
CREATE INDEX IF NOT EXISTS ix_incidents_tenant_id ON incidents (tenant_id);

-- ── add_onboarding_p53 ───────────────────────────────────────────────────────

ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT true NOT NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verification_token VARCHAR(64);
CREATE INDEX IF NOT EXISTS ix_users_email_verification_token ON users (email_verification_token);
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verification_expires_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS onboarding_step VARCHAR(50) DEFAULT 'completed' NOT NULL;

-- ── add_billing_metering_p55 ─────────────────────────────────────────────────

ALTER TABLE tenants ADD COLUMN IF NOT EXISTS stripe_customer_id VARCHAR(64);
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS stripe_subscription_id VARCHAR(64);
CREATE INDEX IF NOT EXISTS ix_tenants_stripe_customer_id ON tenants (stripe_customer_id);

CREATE TABLE IF NOT EXISTS usage_records (
    id VARCHAR(36) NOT NULL,
    tenant_id VARCHAR(36) NOT NULL,
    period VARCHAR(7) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    count INTEGER DEFAULT 0 NOT NULL,
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    CONSTRAINT pk_usage_records PRIMARY KEY (id),
    CONSTRAINT uq_usage_tenant_period_resource UNIQUE (tenant_id, period, resource_type)
);
CREATE INDEX IF NOT EXISTS ix_usage_records_tenant_id ON usage_records (tenant_id);
CREATE INDEX IF NOT EXISTS ix_usage_records_period ON usage_records (period);

-- ── add_adapter_registry_p58 ─────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS tenant_adapter_configs (
    id VARCHAR(36) NOT NULL,
    tenant_id VARCHAR(36) NOT NULL,
    adapter_type VARCHAR(50) NOT NULL,
    provider VARCHAR(50) DEFAULT 'none' NOT NULL,
    is_enabled BOOLEAN DEFAULT true NOT NULL,
    host VARCHAR(512),
    settings_json JSON,
    credential_encrypted TEXT,
    credential_hint VARCHAR(8),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT pk_tenant_adapter_configs PRIMARY KEY (id),
    CONSTRAINT uq_tenant_adapter_type UNIQUE (tenant_id, adapter_type)
);
CREATE INDEX IF NOT EXISTS ix_tenant_adapter_configs_tenant_id ON tenant_adapter_configs (tenant_id);
CREATE INDEX IF NOT EXISTS ix_tenant_adapter_configs_adapter_type ON tenant_adapter_configs (adapter_type);

-- ── add_supabase_uid_p59 ─────────────────────────────────────────────────────

ALTER TABLE users ADD COLUMN IF NOT EXISTS supabase_uid VARCHAR(36);
CREATE UNIQUE INDEX IF NOT EXISTS ix_users_supabase_uid ON users (supabase_uid);

-- ── add_stripe_checkout_p60 ──────────────────────────────────────────────────

ALTER TABLE tenants ADD COLUMN IF NOT EXISTS stripe_checkout_session_id VARCHAR(255);
CREATE UNIQUE INDEX IF NOT EXISTS ix_tenants_stripe_checkout_session_id ON tenants (stripe_checkout_session_id);

-- =============================================================================
-- Fijar versión final de Alembic (reemplaza cualquier valor previo)
-- =============================================================================
DELETE FROM alembic_version;
INSERT INTO alembic_version (version_num) VALUES ('v2p45s4u7o09');

COMMIT;
