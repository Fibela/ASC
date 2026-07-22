-- S108-Ops.1 — tabla de latidos de plataforma (monitoreo continuo).
-- Correr en el SQL Editor de Supabase. Idempotente. Sin esta tabla, emit_heartbeat
-- falla en silencio (los crons no dejan rastro) y /health/platform reporta 'unknown'.
CREATE TABLE IF NOT EXISTS platform_heartbeats (
    id                    VARCHAR(64) PRIMARY KEY,
    last_seen_at          TIMESTAMPTZ NOT NULL,
    last_status           VARCHAR(16) NOT NULL DEFAULT 'ok',
    consecutive_failures  INTEGER     NOT NULL DEFAULT 0,
    detail                TEXT
);
