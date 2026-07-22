-- S105.2 — aislamiento por tenant de reportes ejecutivos.
-- Correr en Supabase SQL Editor ANTES de desplegar el código S105.2.
-- Idempotente: seguro re-ejecutar. (Lección incidente I-3: migración ANTES del deploy.)
ALTER TABLE executive_reports ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(36);
CREATE INDEX IF NOT EXISTS ix_executive_reports_tenant_id ON executive_reports (tenant_id);
