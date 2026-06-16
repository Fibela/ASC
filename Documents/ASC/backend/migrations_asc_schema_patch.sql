-- =============================================================================
-- ASC PremosCorp — Schema Patch (corrige drift entre modelos y migración inicial)
-- Target: Supabase SQL Editor (project ref: kqxwtayzqujlddviskwl)
--
-- Recrea 8 tablas cuyos esquemas difieren de los modelos SQLAlchemy actuales.
-- Todas están vacías — DROP + CREATE es seguro.
-- =============================================================================

BEGIN;

-- Eliminar en orden correcto (FK primero)
DROP TABLE IF EXISTS agent_commands;
DROP TABLE IF EXISTS agent_events;
DROP TABLE IF EXISTS agents;
DROP TABLE IF EXISTS alerts;
DROP TABLE IF EXISTS events;
DROP TABLE IF EXISTS iocs;
DROP TABLE IF EXISTS soc_metrics;
DROP TABLE IF EXISTS artifacts;
DROP TABLE IF EXISTS neutralization_actions;
DROP TABLE IF EXISTS playbook_runs;

-- ── alerts ───────────────────────────────────────────────────────────────────
CREATE TABLE alerts (
    id                  VARCHAR(36)              NOT NULL,
    title               VARCHAR(512)             NOT NULL,
    description         TEXT                     NOT NULL,
    severity            VARCHAR(20)              NOT NULL,
    status              VARCHAR(30)              DEFAULT 'open' NOT NULL,
    risk_score          FLOAT                    DEFAULT 0.0 NOT NULL,
    source_events       JSON                     DEFAULT '[]' NOT NULL,
    matched_iocs        JSON                     DEFAULT '[]' NOT NULL,
    affected_hosts      JSON                     DEFAULT '[]' NOT NULL,
    ttps                JSON                     DEFAULT '[]' NOT NULL,
    recommended_actions JSON                     DEFAULT '[]' NOT NULL,
    analyst_notes       TEXT,
    assigned_to         VARCHAR(36),
    threat_start_at     TIMESTAMP WITH TIME ZONE,
    detected_at         TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    acknowledged_at     TIMESTAMP WITH TIME ZONE,
    resolved_at         TIMESTAMP WITH TIME ZONE,
    false_positive      BOOLEAN                  DEFAULT false NOT NULL,
    tenant_id           VARCHAR(36),
    CONSTRAINT pk_alerts PRIMARY KEY (id)
);
CREATE INDEX ix_alerts_severity    ON alerts (severity);
CREATE INDEX ix_alerts_status      ON alerts (status);
CREATE INDEX ix_alerts_detected_at ON alerts (detected_at);
CREATE INDEX ix_alerts_tenant_id   ON alerts (tenant_id);

-- ── events ───────────────────────────────────────────────────────────────────
CREATE TABLE events (
    id          VARCHAR(36)              NOT NULL,
    timestamp   TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    source      VARCHAR(100)             NOT NULL,
    category    VARCHAR(100)             NOT NULL,
    action      VARCHAR(255)             NOT NULL,
    host        VARCHAR(255)             NOT NULL,
    user_agent  VARCHAR(255),
    severity    VARCHAR(20)              DEFAULT 'low' NOT NULL,
    risk_score  FLOAT                    DEFAULT 0.0 NOT NULL,
    raw_log     TEXT,
    normalized  JSON                     DEFAULT '{}' NOT NULL,
    tags        JSON                     DEFAULT '[]' NOT NULL,
    correlated  BOOLEAN                  DEFAULT false NOT NULL,
    alert_id    VARCHAR(36),
    tenant_id   VARCHAR(36),
    CONSTRAINT pk_events PRIMARY KEY (id)
);
CREATE INDEX ix_events_timestamp           ON events (timestamp);
CREATE INDEX ix_events_source              ON events (source);
CREATE INDEX ix_events_severity            ON events (severity);
CREATE INDEX ix_events_tenant_id           ON events (tenant_id);
CREATE INDEX ix_events_source_timestamp    ON events (source, timestamp);

-- ── iocs ─────────────────────────────────────────────────────────────────────
CREATE TABLE iocs (
    id           VARCHAR(36)              NOT NULL,
    value        VARCHAR(512)             NOT NULL,
    ioc_type     VARCHAR(50)              NOT NULL,
    threat_type  VARCHAR(100),
    confidence   FLOAT                    DEFAULT 0.5 NOT NULL,
    severity     VARCHAR(20)              DEFAULT 'medium' NOT NULL,
    source       VARCHAR(100)             DEFAULT 'internal' NOT NULL,
    description  TEXT,
    tags         JSON                     DEFAULT '[]' NOT NULL,
    ttps         JSON                     DEFAULT '[]' NOT NULL,
    first_seen   TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    last_seen    TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    active       BOOLEAN                  DEFAULT true NOT NULL,
    hit_count    INTEGER                  DEFAULT 0 NOT NULL,
    CONSTRAINT pk_iocs PRIMARY KEY (id)
);
CREATE INDEX ix_iocs_value    ON iocs (value);
CREATE INDEX ix_iocs_ioc_type ON iocs (ioc_type);
CREATE INDEX ix_iocs_active   ON iocs (active);

-- ── soc_metrics ──────────────────────────────────────────────────────────────
CREATE TABLE soc_metrics (
    id                  VARCHAR(36)              NOT NULL,
    period              VARCHAR(10)              NOT NULL,
    period_start        TIMESTAMP WITH TIME ZONE NOT NULL,
    period_end          TIMESTAMP WITH TIME ZONE NOT NULL,
    total_events        INTEGER                  DEFAULT 0 NOT NULL,
    total_alerts        INTEGER                  DEFAULT 0 NOT NULL,
    true_positives      INTEGER                  DEFAULT 0 NOT NULL,
    false_positives     INTEGER                  DEFAULT 0 NOT NULL,
    false_positive_rate FLOAT                    DEFAULT 0.0 NOT NULL,
    mttd                FLOAT,
    mttr                FLOAT,
    mttc                FLOAT,
    ioc_coverage        FLOAT                    DEFAULT 0.0 NOT NULL,
    endpoint_coverage   FLOAT                    DEFAULT 0.0 NOT NULL,
    by_severity         JSON                     DEFAULT '{}' NOT NULL,
    by_category         JSON                     DEFAULT '{}' NOT NULL,
    top_iocs            JSON                     DEFAULT '[]' NOT NULL,
    computed_at         TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    CONSTRAINT pk_soc_metrics PRIMARY KEY (id)
);
CREATE INDEX ix_soc_metrics_period_start ON soc_metrics (period_start);

-- ── artifacts ────────────────────────────────────────────────────────────────
CREATE TABLE artifacts (
    id              VARCHAR(36)              NOT NULL,
    filename        VARCHAR(512)             NOT NULL,
    file_type       VARCHAR(100),
    size_bytes      BIGINT,
    md5             VARCHAR(32),
    sha1            VARCHAR(40),
    sha256          VARCHAR(64),
    analysis_status VARCHAR(30)              DEFAULT 'pending' NOT NULL,
    risk_score      FLOAT                    DEFAULT 0.0 NOT NULL,
    verdict         VARCHAR(30),
    analysis_result JSON                     DEFAULT '{}' NOT NULL,
    matched_iocs    JSON                     DEFAULT '[]' NOT NULL,
    yara_matches    JSON                     DEFAULT '[]' NOT NULL,
    vt_result       JSON,
    submitted_by    VARCHAR(36),
    submitted_at    TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    analyzed_at     TIMESTAMP WITH TIME ZONE,
    CONSTRAINT pk_artifacts PRIMARY KEY (id)
);
CREATE INDEX ix_artifacts_sha256 ON artifacts (sha256);
CREATE INDEX ix_artifacts_status ON artifacts (analysis_status);

-- ── neutralization_actions ───────────────────────────────────────────────────
CREATE TABLE neutralization_actions (
    id                  VARCHAR(36)              NOT NULL,
    alert_id            VARCHAR(36),
    action_type         VARCHAR(50)              NOT NULL,
    severity            VARCHAR(20)              DEFAULT 'medium' NOT NULL,
    target              VARCHAR(512)             NOT NULL,
    target_type         VARCHAR(50)              DEFAULT 'host' NOT NULL,
    params              JSON                     DEFAULT '{}' NOT NULL,
    status              VARCHAR(30)              DEFAULT 'pending_approval' NOT NULL,
    automated           BOOLEAN                  DEFAULT false NOT NULL,
    initiated_by        VARCHAR(256),
    result              JSON                     DEFAULT '{}' NOT NULL,
    error_message       TEXT,
    rollback_available  BOOLEAN                  DEFAULT false NOT NULL,
    created_at          TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    executed_at         TIMESTAMP WITH TIME ZONE,
    approval_required   BOOLEAN                  DEFAULT true NOT NULL,
    timeout_minutes     INTEGER                  DEFAULT 60 NOT NULL,
    expires_at          TIMESTAMP WITH TIME ZONE,
    approved_by         VARCHAR(256),
    approved_at         TIMESTAMP WITH TIME ZONE,
    rejected_by         VARCHAR(256),
    rejected_at         TIMESTAMP WITH TIME ZONE,
    rejection_reason    TEXT,
    escalated_at        TIMESTAMP WITH TIME ZONE,
    escalation_reason   TEXT,
    required_approvals  INTEGER                  DEFAULT 1 NOT NULL,
    approvals_log       JSON                     DEFAULT '[]' NOT NULL,
    is_rollback         BOOLEAN                  DEFAULT false NOT NULL,
    rollback_of         VARCHAR(36),
    rollback_action_id  VARCHAR(36),
    original_severity   VARCHAR(20),
    severity_adapted    BOOLEAN                  DEFAULT false NOT NULL,
    CONSTRAINT pk_neutralization_actions PRIMARY KEY (id)
);
CREATE INDEX ix_neutralization_actions_status       ON neutralization_actions (status);
CREATE INDEX ix_neutralization_actions_created_at   ON neutralization_actions (created_at);
CREATE INDEX ix_neutralization_actions_alert_id     ON neutralization_actions (alert_id);

-- ── playbook_runs ─────────────────────────────────────────────────────────────
CREATE TABLE playbook_runs (
    id                VARCHAR(36)              NOT NULL,
    playbook_id       VARCHAR(20)              NOT NULL,
    playbook_name     VARCHAR(256)             NOT NULL,
    trigger_source    VARCHAR(30)              DEFAULT 'manual' NOT NULL,
    trigger_data      JSON                     DEFAULT '{}' NOT NULL,
    semaphore         VARCHAR(10)              DEFAULT 'GREEN' NOT NULL,
    risk_score        FLOAT                    DEFAULT 0.0 NOT NULL,
    status            VARCHAR(30)              DEFAULT 'running' NOT NULL,
    steps_log         JSON                     DEFAULT '[]' NOT NULL,
    next_step_index   INTEGER                  DEFAULT 0 NOT NULL,
    alert_id          VARCHAR(36),
    approval_token    VARCHAR(36),
    approved_by       VARCHAR(36),
    approved_at       TIMESTAMP WITH TIME ZONE,
    initiated_by      VARCHAR(36)              NOT NULL,
    started_at        TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    completed_at      TIMESTAMP WITH TIME ZONE,
    error             TEXT,
    CONSTRAINT pk_playbook_runs PRIMARY KEY (id)
);
CREATE INDEX ix_playbook_runs_status     ON playbook_runs (status);
CREATE INDEX ix_playbook_runs_started_at ON playbook_runs (started_at);

-- ── agents ───────────────────────────────────────────────────────────────────
CREATE TABLE agents (
    id               VARCHAR(36)              NOT NULL,
    hostname         VARCHAR(255)             NOT NULL,
    os_type          VARCHAR(20)              DEFAULT 'unknown' NOT NULL,
    os_version       VARCHAR(128)             DEFAULT '' NOT NULL,
    arch             VARCHAR(16)              DEFAULT 'x64' NOT NULL,
    ip_address       VARCHAR(45)              DEFAULT '0.0.0.0' NOT NULL,
    public_key       TEXT                     NOT NULL,
    specter_version  VARCHAR(20)              DEFAULT '1.0.0' NOT NULL,
    status           VARCHAR(20)              DEFAULT 'inactive' NOT NULL,
    threat_level     VARCHAR(20)              DEFAULT 'normal' NOT NULL,
    poll_interval    INTEGER                  DEFAULT 30 NOT NULL,
    first_seen       TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    last_seen        TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    labels           JSON                     DEFAULT '{}' NOT NULL,
    total_events     INTEGER                  DEFAULT 0 NOT NULL,
    CONSTRAINT pk_agents PRIMARY KEY (id)
);
CREATE UNIQUE INDEX ix_agents_hostname ON agents (hostname);
CREATE INDEX ix_agents_status         ON agents (status);
CREATE INDEX ix_agents_threat_level   ON agents (threat_level);

-- ── agent_events ─────────────────────────────────────────────────────────────
CREATE TABLE agent_events (
    id               VARCHAR(36)              NOT NULL,
    agent_id         VARCHAR(36)              NOT NULL,
    event_type       VARCHAR(40)              NOT NULL,
    severity         VARCHAR(20)              DEFAULT 'info' NOT NULL,
    data             JSON                     DEFAULT '{}' NOT NULL,
    signature        TEXT                     DEFAULT '' NOT NULL,
    signature_valid  BOOLEAN                  DEFAULT false NOT NULL,
    is_anomaly       BOOLEAN                  DEFAULT false NOT NULL,
    ts               TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    received_at      TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    CONSTRAINT pk_agent_events PRIMARY KEY (id),
    CONSTRAINT fk_agent_events_agent_id_agents FOREIGN KEY(agent_id) REFERENCES agents (id) ON DELETE CASCADE
);
CREATE INDEX ix_agent_events_agent_id  ON agent_events (agent_id);
CREATE INDEX ix_agent_events_ts        ON agent_events (ts);
CREATE INDEX ix_agent_events_is_anomaly ON agent_events (is_anomaly);

-- ── agent_commands ───────────────────────────────────────────────────────────
CREATE TABLE agent_commands (
    id            VARCHAR(36)              NOT NULL,
    agent_id      VARCHAR(36)              NOT NULL,
    command_type  VARCHAR(40)              NOT NULL,
    params        JSON                     DEFAULT '{}' NOT NULL,
    signature     TEXT                     DEFAULT '' NOT NULL,
    status        VARCHAR(20)              DEFAULT 'pending' NOT NULL,
    issued_by     VARCHAR(36)              NOT NULL,
    issued_at     TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    delivered_at  TIMESTAMP WITH TIME ZONE,
    completed_at  TIMESTAMP WITH TIME ZONE,
    result        JSON,
    error         VARCHAR(512),
    CONSTRAINT pk_agent_commands PRIMARY KEY (id),
    CONSTRAINT fk_agent_commands_agent_id_agents FOREIGN KEY(agent_id) REFERENCES agents (id) ON DELETE CASCADE
);
CREATE INDEX ix_agent_commands_agent_id ON agent_commands (agent_id);
CREATE INDEX ix_agent_commands_status   ON agent_commands (status);

-- =============================================================================
-- END — 10 tablas recreadas con esquema correcto
-- =============================================================================

COMMIT;
