-- =============================================================================
-- ASC PremosCorp -- Remaining Tables (FASE 0.4)
-- Creates 23 tables not in initial migration schema patch.
-- Safe to re-run: CREATE TABLE IF NOT EXISTS + ADD COLUMN IF NOT EXISTS
-- Target: Supabase SQL Editor (project ref: kqxwtayzqujlddviskwl)
-- =============================================================================

BEGIN;

-- --------------------------------------------------------------------------
-- tenants
CREATE TABLE IF NOT EXISTS tenants (
    id                             VARCHAR(36) NOT NULL,
    name                           VARCHAR(255) NOT NULL,
    slug                           VARCHAR(100) NOT NULL,
    plan                           VARCHAR(50) NOT NULL,
    is_active                      BOOLEAN NOT NULL,
    created_at                     TIMESTAMP WITH TIME ZONE NOT NULL,
    contact_email                  VARCHAR(255),
    max_users                      INTEGER,
    max_api_keys_per_user          INTEGER,
    stripe_customer_id             VARCHAR(64),
    stripe_subscription_id         VARCHAR(64),
    stripe_checkout_session_id     VARCHAR(255),
    CONSTRAINT pk_tenants PRIMARY KEY (id)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_tenants_stripe_checkout_session_id ON tenants (stripe_checkout_session_id);

-- --------------------------------------------------------------------------
-- users
CREATE TABLE IF NOT EXISTS users (
    id                             VARCHAR(36) NOT NULL,
    email                          VARCHAR(255) NOT NULL,
    full_name                      VARCHAR(255) NOT NULL,
    hashed_password                VARCHAR(255) NOT NULL,
    role                           VARCHAR(50) NOT NULL,
    is_active                      BOOLEAN NOT NULL,
    created_at                     TIMESTAMP WITH TIME ZONE NOT NULL,
    last_login                     TIMESTAMP WITH TIME ZONE,
    failed_login_attempts          INTEGER NOT NULL,
    locked_until                   TIMESTAMP WITH TIME ZONE,
    force_password_reset           BOOLEAN NOT NULL,
    signing_public_key             VARCHAR(64),
    signing_private_key_enc        VARCHAR(512),
    tenant_id                      VARCHAR(36),
    email_verified                 BOOLEAN NOT NULL,
    email_verification_token       VARCHAR(64),
    email_verification_expires_at  TIMESTAMP WITH TIME ZONE,
    onboarding_step                VARCHAR(50) NOT NULL,
    supabase_uid                   VARCHAR(36),
    CONSTRAINT pk_users PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS ix_users_tenant_id ON users (tenant_id);

-- --------------------------------------------------------------------------
-- revoked_tokens
CREATE TABLE IF NOT EXISTS revoked_tokens (
    id                             VARCHAR(36) NOT NULL,
    jti                            VARCHAR(36) NOT NULL,
    expires_at                     TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at                     TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_by                     VARCHAR(255),
    reason                         VARCHAR(100),
    CONSTRAINT pk_revoked_tokens PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS ix_revoked_tokens_expires_at ON revoked_tokens (expires_at);

-- --------------------------------------------------------------------------
-- api_keys
CREATE TABLE IF NOT EXISTS api_keys (
    id                             VARCHAR(36) NOT NULL,
    name                           VARCHAR(100) NOT NULL,
    key_prefix                     VARCHAR(8) NOT NULL,
    key_hash                       VARCHAR(64) NOT NULL,
    user_id                        VARCHAR(36) NOT NULL,
    scopes                         JSON NOT NULL,
    expires_at                     TIMESTAMP WITH TIME ZONE,
    last_used_at                   TIMESTAMP WITH TIME ZONE,
    is_active                      BOOLEAN NOT NULL,
    created_at                     TIMESTAMP WITH TIME ZONE NOT NULL,
    tenant_id                      VARCHAR(36),
    CONSTRAINT pk_api_keys PRIMARY KEY (id),
    CONSTRAINT fk_api_keys_user_id_users FOREIGN KEY(user_id) REFERENCES users (id)
);
CREATE INDEX IF NOT EXISTS ix_api_keys_key_prefix ON api_keys (key_prefix);
CREATE INDEX IF NOT EXISTS ix_api_keys_tenant_id ON api_keys (tenant_id);
CREATE INDEX IF NOT EXISTS ix_api_keys_user_id ON api_keys (user_id);

-- --------------------------------------------------------------------------
-- webhooks
CREATE TABLE IF NOT EXISTS webhooks (
    id                             TEXT NOT NULL,
    url                            VARCHAR(2048) NOT NULL,
    secret                         VARCHAR(64) NOT NULL,
    events                         JSON NOT NULL,
    description                    VARCHAR(500),
    is_active                      BOOLEAN NOT NULL,
    user_id                        TEXT NOT NULL,
    created_at                     TIMESTAMP WITH TIME ZONE NOT NULL,
    last_triggered_at              TIMESTAMP WITH TIME ZONE,
    failure_count                  INTEGER NOT NULL,
    tenant_id                      VARCHAR(36),
    CONSTRAINT pk_webhooks PRIMARY KEY (id),
    CONSTRAINT fk_webhooks_user_id_users FOREIGN KEY(user_id) REFERENCES users (id)
);
CREATE INDEX IF NOT EXISTS ix_webhooks_tenant_id ON webhooks (tenant_id);
CREATE INDEX IF NOT EXISTS ix_webhooks_user_id ON webhooks (user_id);

-- --------------------------------------------------------------------------
-- correlation_rules
CREATE TABLE IF NOT EXISTS correlation_rules (
    id                             VARCHAR(36) NOT NULL,
    name                           VARCHAR(256) NOT NULL,
    description                    TEXT,
    pivot_type                     VARCHAR(50) NOT NULL,
    min_signals                    INTEGER NOT NULL,
    time_window_minutes            INTEGER NOT NULL,
    severity_threshold             VARCHAR(20) NOT NULL,
    enabled                        BOOLEAN NOT NULL,
    created_at                     TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at                     TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT pk_correlation_rules PRIMARY KEY (id)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_correlation_rules_name ON correlation_rules (name);
CREATE INDEX IF NOT EXISTS ix_cr_enabled ON correlation_rules (enabled);
CREATE INDEX IF NOT EXISTS ix_cr_pivot_type ON correlation_rules (pivot_type);

-- --------------------------------------------------------------------------
-- correlation_clusters
CREATE TABLE IF NOT EXISTS correlation_clusters (
    id                             VARCHAR(36) NOT NULL,
    rule_id                        VARCHAR(36) NOT NULL,
    cluster_key                    VARCHAR(512) NOT NULL,
    cluster_type                   VARCHAR(50) NOT NULL,
    signal_count                   INTEGER NOT NULL,
    severity                       VARCHAR(20) NOT NULL,
    confidence_score               FLOAT NOT NULL,
    first_seen                     TIMESTAMP WITH TIME ZONE NOT NULL,
    last_seen                      TIMESTAMP WITH TIME ZONE NOT NULL,
    status                         VARCHAR(30) NOT NULL,
    is_campaign                    BOOLEAN NOT NULL,
    campaign_name                  VARCHAR(256),
    distinct_signal_domains        INTEGER NOT NULL,
    analyst_notes                  TEXT,
    assigned_to                    VARCHAR(256),
    forensic_hash                  VARCHAR(128),
    meta                           JSON NOT NULL,
    created_at                     TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at                     TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT pk_correlation_clusters PRIMARY KEY (id),
    CONSTRAINT fk_correlation_clusters_rule_id_correlation_rules FOREIGN KEY(rule_id) REFERENCES correlation_rules (id)
);
CREATE INDEX IF NOT EXISTS ix_cc_cluster_key ON correlation_clusters (cluster_key);
CREATE INDEX IF NOT EXISTS ix_cc_is_campaign ON correlation_clusters (is_campaign);
CREATE INDEX IF NOT EXISTS ix_cc_last_seen ON correlation_clusters (last_seen);
CREATE INDEX IF NOT EXISTS ix_cc_rule_id ON correlation_clusters (rule_id);
CREATE INDEX IF NOT EXISTS ix_cc_severity ON correlation_clusters (severity);
CREATE INDEX IF NOT EXISTS ix_cc_status ON correlation_clusters (status);

-- --------------------------------------------------------------------------
-- correlation_signals
CREATE TABLE IF NOT EXISTS correlation_signals (
    id                             VARCHAR(36) NOT NULL,
    cluster_id                     VARCHAR(36) NOT NULL,
    signal_type                    VARCHAR(50) NOT NULL,
    signal_id                      VARCHAR(36) NOT NULL,
    pivot_value                    VARCHAR(512) NOT NULL,
    severity                       VARCHAR(20) NOT NULL,
    timestamp                      TIMESTAMP WITH TIME ZONE NOT NULL,
    meta                           JSON NOT NULL,
    created_at                     TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT pk_correlation_signals PRIMARY KEY (id),
    CONSTRAINT fk_correlation_signals_cluster_id_correlation_clusters FOREIGN KEY(cluster_id) REFERENCES correlation_clusters (id)
);
CREATE INDEX IF NOT EXISTS ix_cs_cluster_id ON correlation_signals (cluster_id);
CREATE INDEX IF NOT EXISTS ix_cs_pivot_value ON correlation_signals (pivot_value);
CREATE INDEX IF NOT EXISTS ix_cs_signal_id ON correlation_signals (signal_id);
CREATE INDEX IF NOT EXISTS ix_cs_signal_type ON correlation_signals (signal_type);
CREATE INDEX IF NOT EXISTS ix_cs_timestamp ON correlation_signals (timestamp);

-- --------------------------------------------------------------------------
-- executive_reports
CREATE TABLE IF NOT EXISTS executive_reports (
    id                             VARCHAR(36) NOT NULL,
    report_type                    VARCHAR(30) NOT NULL,
    period                         VARCHAR(20) NOT NULL,
    title                          VARCHAR(512) NOT NULL,
    generated_by                   VARCHAR(256) NOT NULL,
    period_start                   TIMESTAMP WITH TIME ZONE NOT NULL,
    period_end                     TIMESTAMP WITH TIME ZONE NOT NULL,
    total_incidents                INTEGER NOT NULL,
    closed_incidents               INTEGER NOT NULL,
    sla_breach_count               INTEGER NOT NULL,
    campaign_count                 INTEGER NOT NULL,
    avg_mttd_minutes               FLOAT,
    avg_mttc_minutes               FLOAT,
    avg_mttr_minutes               FLOAT,
    canonical_data                 JSON NOT NULL,
    hash_sha3_512                  VARCHAR(128) NOT NULL,
    signature_ed25519              TEXT NOT NULL,
    pubkey_fingerprint             VARCHAR(32) NOT NULL,
    signature_valid                BOOLEAN NOT NULL,
    last_verified_at               TIMESTAMP WITH TIME ZONE,
    created_at                     TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT pk_executive_reports PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS ix_executive_reports_report_type ON executive_reports (report_type);

-- --------------------------------------------------------------------------
-- forensic_ledger
CREATE TABLE IF NOT EXISTS forensic_ledger (
    id                             VARCHAR(36) NOT NULL,
    action_id                      VARCHAR(36) NOT NULL,
    action_type                    VARCHAR(50) NOT NULL,
    target                         VARCHAR(512) NOT NULL,
    canonical_data                 JSON NOT NULL,
    hash_sha3_512                  VARCHAR(128) NOT NULL,
    signature_ed25519              TEXT NOT NULL,
    signed_by_email                VARCHAR(256) NOT NULL,
    signed_by_user_id              VARCHAR(36) NOT NULL,
    signed_at                      TIMESTAMP WITH TIME ZONE NOT NULL,
    verified                       BOOLEAN NOT NULL,
    last_verified_at               TIMESTAMP WITH TIME ZONE,
    CONSTRAINT pk_forensic_ledger PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS ix_forensic_ledger_action_id ON forensic_ledger (action_id);
CREATE INDEX IF NOT EXISTS ix_forensic_ledger_signed_by_user_id ON forensic_ledger (signed_by_user_id);

-- --------------------------------------------------------------------------
-- hunt_sessions
CREATE TABLE IF NOT EXISTS hunt_sessions (
    id                             VARCHAR(36) NOT NULL,
    name                           VARCHAR(256) NOT NULL,
    description                    TEXT,
    hypothesis                     TEXT,
    status                         VARCHAR(30) NOT NULL,
    mitre_technique                VARCHAR(20),
    mitre_tactic                   VARCHAR(100),
    scope                          VARCHAR(50) NOT NULL,
    priority                       VARCHAR(20) NOT NULL,
    created_by                     VARCHAR(256) NOT NULL,
    assigned_to                    VARCHAR(256),
    created_at                     TIMESTAMP WITH TIME ZONE NOT NULL,
    started_at                     TIMESTAMP WITH TIME ZONE,
    completed_at                   TIMESTAMP WITH TIME ZONE,
    updated_at                     TIMESTAMP WITH TIME ZONE NOT NULL,
    conclusion                     TEXT,
    findings_count                 INTEGER NOT NULL,
    true_positive_count            INTEGER NOT NULL,
    tags                           JSON NOT NULL,
    CONSTRAINT pk_hunt_sessions PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS ix_hunt_created_by ON hunt_sessions (created_by);
CREATE INDEX IF NOT EXISTS ix_hunt_mitre ON hunt_sessions (mitre_technique);
CREATE INDEX IF NOT EXISTS ix_hunt_priority ON hunt_sessions (priority);
CREATE INDEX IF NOT EXISTS ix_hunt_status ON hunt_sessions (status);

-- --------------------------------------------------------------------------
-- hunt_findings
CREATE TABLE IF NOT EXISTS hunt_findings (
    id                             VARCHAR(36) NOT NULL,
    hunt_id                        VARCHAR(36) NOT NULL,
    title                          VARCHAR(512) NOT NULL,
    description                    TEXT,
    severity                       VARCHAR(20) NOT NULL,
    indicator_value                VARCHAR(1024),
    indicator_type                 VARCHAR(50),
    affected_host                  VARCHAR(256),
    affected_user                  VARCHAR(256),
    data_source                    VARCHAR(100),
    mitre_technique                VARCHAR(20),
    mitre_tactic                   VARCHAR(100),
    evidence                       JSON,
    is_confirmed                   BOOLEAN NOT NULL,
    is_false_positive              BOOLEAN NOT NULL,
    analyst_notes                  TEXT,
    created_by                     VARCHAR(256) NOT NULL,
    created_at                     TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at                     TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT pk_hunt_findings PRIMARY KEY (id),
    CONSTRAINT fk_hunt_findings_hunt_id_hunt_sessions FOREIGN KEY(hunt_id) REFERENCES hunt_sessions (id)
);
CREATE INDEX IF NOT EXISTS ix_hf_confirmed ON hunt_findings (is_confirmed);
CREATE INDEX IF NOT EXISTS ix_hf_hunt_id ON hunt_findings (hunt_id);
CREATE INDEX IF NOT EXISTS ix_hf_severity ON hunt_findings (severity);

-- --------------------------------------------------------------------------
-- hunt_queries
CREATE TABLE IF NOT EXISTS hunt_queries (
    id                             VARCHAR(36) NOT NULL,
    hunt_id                        VARCHAR(36) NOT NULL,
    name                           VARCHAR(256) NOT NULL,
    query_text                     TEXT NOT NULL,
    data_source                    VARCHAR(100) NOT NULL,
    description                    TEXT,
    last_executed_at               TIMESTAMP WITH TIME ZONE,
    last_result_count              INTEGER,
    last_execution_ms              INTEGER,
    created_by                     VARCHAR(256) NOT NULL,
    created_at                     TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT pk_hunt_queries PRIMARY KEY (id),
    CONSTRAINT fk_hunt_queries_hunt_id_hunt_sessions FOREIGN KEY(hunt_id) REFERENCES hunt_sessions (id)
);
CREATE INDEX IF NOT EXISTS ix_hq_data_source ON hunt_queries (data_source);
CREATE INDEX IF NOT EXISTS ix_hq_hunt_id ON hunt_queries (hunt_id);

-- --------------------------------------------------------------------------
-- identity_actions
CREATE TABLE IF NOT EXISTS identity_actions (
    id                             VARCHAR(36) NOT NULL,
    action_type                    VARCHAR(50) NOT NULL,
    username                       VARCHAR(256) NOT NULL,
    domain                         VARCHAR(256) NOT NULL,
    reason                         TEXT NOT NULL,
    hunt_id                        VARCHAR(36),
    finding_id                     VARCHAR(36),
    trigger_id                     VARCHAR(36),
    playbook_run_id                VARCHAR(36),
    success                        BOOLEAN NOT NULL,
    result_detail                  TEXT,
    hash_sha3_512                  VARCHAR(128),
    signature_ed25519              TEXT,
    signed_at                      TIMESTAMP WITH TIME ZONE,
    signed_by_email                VARCHAR(256) NOT NULL,
    initiated_by                   VARCHAR(256) NOT NULL,
    executed_at                    TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT pk_identity_actions PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS ix_ia_action_type ON identity_actions (action_type);
CREATE INDEX IF NOT EXISTS ix_ia_executed_at ON identity_actions (executed_at);
CREATE INDEX IF NOT EXISTS ix_ia_hunt_id ON identity_actions (hunt_id);
CREATE INDEX IF NOT EXISTS ix_ia_success ON identity_actions (success);
CREATE INDEX IF NOT EXISTS ix_ia_username ON identity_actions (username);

-- --------------------------------------------------------------------------
-- incidents
CREATE TABLE IF NOT EXISTS incidents (
    id                             VARCHAR(36) NOT NULL,
    title                          VARCHAR(512) NOT NULL,
    description                    TEXT,
    incident_type                  VARCHAR(50) NOT NULL,
    status                         VARCHAR(30) NOT NULL,
    nist_phase                     VARCHAR(50) NOT NULL,
    severity                       VARCHAR(20) NOT NULL,
    risk_score                     FLOAT NOT NULL,
    created_by                     VARCHAR(256) NOT NULL,
    assigned_to                    VARCHAR(256),
    mitre_tactics                  JSON NOT NULL,
    mitre_techniques               JSON NOT NULL,
    tags                           JSON NOT NULL,
    executive_summary              TEXT,
    lessons_learned                TEXT,
    root_cause                     TEXT,
    false_positive                 BOOLEAN NOT NULL,
    sla_minutes                    INTEGER NOT NULL,
    sla_breach                     BOOLEAN NOT NULL,
    detected_at                    TIMESTAMP WITH TIME ZONE,
    triaged_at                     TIMESTAMP WITH TIME ZONE,
    contained_at                   TIMESTAMP WITH TIME ZONE,
    eradicated_at                  TIMESTAMP WITH TIME ZONE,
    recovered_at                   TIMESTAMP WITH TIME ZONE,
    closed_at                      TIMESTAMP WITH TIME ZONE,
    mttd_minutes                   INTEGER,
    mttc_minutes                   INTEGER,
    mttr_minutes                   INTEGER,
    forensic_hash                  VARCHAR(128),
    created_at                     TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at                     TIMESTAMP WITH TIME ZONE NOT NULL,
    tenant_id                      VARCHAR(36),
    CONSTRAINT pk_incidents PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS ix_inc_assigned_to ON incidents (assigned_to);
CREATE INDEX IF NOT EXISTS ix_inc_created_at ON incidents (created_at);
CREATE INDEX IF NOT EXISTS ix_inc_incident_type ON incidents (incident_type);
CREATE INDEX IF NOT EXISTS ix_inc_severity ON incidents (severity);
CREATE INDEX IF NOT EXISTS ix_inc_sla_breach ON incidents (sla_breach);
CREATE INDEX IF NOT EXISTS ix_inc_status ON incidents (status);
CREATE INDEX IF NOT EXISTS ix_incidents_tenant_id ON incidents (tenant_id);

-- --------------------------------------------------------------------------
-- incident_links
CREATE TABLE IF NOT EXISTS incident_links (
    id                             VARCHAR(36) NOT NULL,
    incident_id                    VARCHAR(36) NOT NULL,
    entity_type                    VARCHAR(50) NOT NULL,
    entity_id                      VARCHAR(36) NOT NULL,
    notes                          TEXT,
    added_by                       VARCHAR(256) NOT NULL,
    created_at                     TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT pk_incident_links PRIMARY KEY (id),
    CONSTRAINT fk_incident_links_incident_id_incidents FOREIGN KEY(incident_id) REFERENCES incidents (id)
);
CREATE INDEX IF NOT EXISTS ix_il_entity_id ON incident_links (entity_id);
CREATE INDEX IF NOT EXISTS ix_il_entity_type ON incident_links (entity_type);
CREATE INDEX IF NOT EXISTS ix_il_incident_id ON incident_links (incident_id);

-- --------------------------------------------------------------------------
-- incident_timeline
CREATE TABLE IF NOT EXISTS incident_timeline (
    id                             VARCHAR(36) NOT NULL,
    incident_id                    VARCHAR(36) NOT NULL,
    event_type                     VARCHAR(50) NOT NULL,
    actor                          VARCHAR(256) NOT NULL,
    detail                         JSON NOT NULL,
    created_at                     TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT pk_incident_timeline PRIMARY KEY (id),
    CONSTRAINT fk_incident_timeline_incident_id_incidents FOREIGN KEY(incident_id) REFERENCES incidents (id)
);
CREATE INDEX IF NOT EXISTS ix_it_created_at ON incident_timeline (created_at);
CREATE INDEX IF NOT EXISTS ix_it_event_type ON incident_timeline (event_type);
CREATE INDEX IF NOT EXISTS ix_it_incident_id ON incident_timeline (incident_id);

-- --------------------------------------------------------------------------
-- pcdi_signed_reports
CREATE TABLE IF NOT EXISTS pcdi_signed_reports (
    id                             VARCHAR(36) NOT NULL,
    hunt_id                        VARCHAR(36) NOT NULL,
    hunt_name                      VARCHAR(256),
    canonical_data                 JSON NOT NULL,
    hash_sha3_512                  VARCHAR(128) NOT NULL,
    signature_ed25519              TEXT NOT NULL,
    signed_by_email                VARCHAR(256) NOT NULL,
    signed_by_user_id              VARCHAR(36),
    signed_at                      TIMESTAMP WITH TIME ZONE NOT NULL,
    verified                       BOOLEAN NOT NULL,
    last_verified_at               TIMESTAMP WITH TIME ZONE,
    pcdi_version                   VARCHAR(10) NOT NULL,
    adaptive_score                 INTEGER,
    CONSTRAINT pk_pcdi_signed_reports PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS ix_pcdi_hunt_id ON pcdi_signed_reports (hunt_id);
CREATE INDEX IF NOT EXISTS ix_pcdi_signed_at ON pcdi_signed_reports (signed_at);
CREATE INDEX IF NOT EXISTS ix_pcdi_signed_by ON pcdi_signed_reports (signed_by_email);
CREATE INDEX IF NOT EXISTS ix_pcdi_signed_reports_hunt_id ON pcdi_signed_reports (hunt_id);

-- --------------------------------------------------------------------------
-- playbook_triggers
CREATE TABLE IF NOT EXISTS playbook_triggers (
    id                             VARCHAR(36) NOT NULL,
    playbook_id                    VARCHAR(20) NOT NULL,
    playbook_name                  VARCHAR(256) NOT NULL,
    condition_type                 VARCHAR(50) NOT NULL,
    condition_operator             VARCHAR(20) NOT NULL,
    condition_value                VARCHAR(256) NOT NULL,
    hunt_id_filter                 VARCHAR(36),
    priority                       INTEGER NOT NULL,
    rate_limit_per_hour            INTEGER NOT NULL,
    dedup_window_minutes           INTEGER NOT NULL,
    enabled                        BOOLEAN NOT NULL,
    trigger_count                  INTEGER NOT NULL,
    last_triggered_at              TIMESTAMP WITH TIME ZONE,
    last_triggered_context         TEXT,
    created_by                     VARCHAR(256) NOT NULL,
    created_at                     TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT pk_playbook_triggers PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS ix_pt_condition_type ON playbook_triggers (condition_type);
CREATE INDEX IF NOT EXISTS ix_pt_enabled ON playbook_triggers (enabled);
CREATE INDEX IF NOT EXISTS ix_pt_playbook_id ON playbook_triggers (playbook_id);

-- --------------------------------------------------------------------------
-- scheduled_reports
CREATE TABLE IF NOT EXISTS scheduled_reports (
    id                             VARCHAR(36) NOT NULL,
    hunt_id                        VARCHAR(36) NOT NULL,
    hunt_name                      VARCHAR(256),
    recipient_email                VARCHAR(256) NOT NULL,
    frequency                      VARCHAR(20) NOT NULL,
    format                         VARCHAR(10) NOT NULL,
    enabled                        BOOLEAN NOT NULL,
    last_sent_at                   TIMESTAMP WITH TIME ZONE,
    send_count                     INTEGER NOT NULL,
    last_error                     TEXT,
    created_by                     VARCHAR(256) NOT NULL,
    created_at                     TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT pk_scheduled_reports PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS ix_sr_enabled ON scheduled_reports (enabled);
CREATE INDEX IF NOT EXISTS ix_sr_frequency ON scheduled_reports (frequency);
CREATE INDEX IF NOT EXISTS ix_sr_hunt_id ON scheduled_reports (hunt_id);

-- --------------------------------------------------------------------------
-- tenant_adapter_configs
CREATE TABLE IF NOT EXISTS tenant_adapter_configs (
    id                             VARCHAR(36) NOT NULL,
    tenant_id                      VARCHAR(36) NOT NULL,
    adapter_type                   VARCHAR(50) NOT NULL,
    provider                       VARCHAR(50) NOT NULL,
    is_enabled                     BOOLEAN NOT NULL,
    host                           VARCHAR(512),
    settings_json                  JSON,
    credential_encrypted           TEXT,
    credential_hint                VARCHAR(8),
    created_at                     TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at                     TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT pk_tenant_adapter_configs PRIMARY KEY (id)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_tenant_adapter_type ON tenant_adapter_configs (tenant_id, adapter_type);
CREATE INDEX IF NOT EXISTS ix_tenant_adapter_configs_tenant_id ON tenant_adapter_configs (tenant_id);

-- --------------------------------------------------------------------------
-- threat_intel_indicators
CREATE TABLE IF NOT EXISTS threat_intel_indicators (
    id                             VARCHAR(36) NOT NULL,
    indicator_type                 VARCHAR(50) NOT NULL,
    value                          VARCHAR(1024) NOT NULL,
    severity                       VARCHAR(20) NOT NULL,
    confidence                     FLOAT NOT NULL,
    threat_actor                   VARCHAR(200),
    malware_family                 VARCHAR(200),
    campaign                       VARCHAR(200),
    ttps                           JSON NOT NULL,
    tags                           JSON NOT NULL,
    source                         VARCHAR(200) NOT NULL,
    source_reference               TEXT,
    description                    TEXT,
    first_seen                     TIMESTAMP WITH TIME ZONE NOT NULL,
    last_seen                      TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at                     TIMESTAMP WITH TIME ZONE,
    active                         BOOLEAN NOT NULL,
    hit_count                      INTEGER NOT NULL,
    last_hit_at                    TIMESTAMP WITH TIME ZONE,
    created_by                     VARCHAR(256) NOT NULL,
    updated_at                     TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT pk_threat_intel_indicators PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS ix_ti_active ON threat_intel_indicators (active);
CREATE INDEX IF NOT EXISTS ix_ti_severity ON threat_intel_indicators (severity);
CREATE INDEX IF NOT EXISTS ix_ti_type_value ON threat_intel_indicators (indicator_type, value);
CREATE INDEX IF NOT EXISTS ix_ti_value ON threat_intel_indicators (value);

-- --------------------------------------------------------------------------
-- usage_records
CREATE TABLE IF NOT EXISTS usage_records (
    id                             VARCHAR(36) NOT NULL,
    tenant_id                      VARCHAR(36) NOT NULL,
    period                         VARCHAR(7) NOT NULL,
    resource_type                  VARCHAR(50) NOT NULL,
    count                          INTEGER NOT NULL,
    recorded_at                    TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT pk_usage_records PRIMARY KEY (id)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_usage_tenant_period_resource ON usage_records (tenant_id, period, resource_type);
CREATE INDEX IF NOT EXISTS ix_usage_records_tenant_id ON usage_records (tenant_id);

COMMIT;

-- =============================================================================
-- END -- 23 remaining tables created/verified
-- =============================================================================