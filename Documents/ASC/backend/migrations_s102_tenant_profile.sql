-- ============================================================================
-- ASC · Migración S102 — tenants.profile (explicación adaptativa)
-- Head: c9d12f0e5b67  ->  f309a0115906
-- Ejecutar en Supabase → SQL Editor → New query → pegar → Run.
-- CORRER ESTO ANTES del push (la columna la referencia el ORM).
-- Idempotente: seguro de re-ejecutar; no falla si ya se aplicó.
-- ============================================================================
BEGIN;

-- 1. Columna profile (retrocompatible: server_default 'pyme')
ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS profile VARCHAR(20) NOT NULL DEFAULT 'pyme';

-- 2. Guardia de dominio a nivel DB (idempotente vía DO block)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'ck_tenants_profile_valid'
    ) THEN
        ALTER TABLE tenants
            ADD CONSTRAINT ck_tenants_profile_valid
            CHECK (profile IN ('hogar', 'pyme', 'enterprise'));
    END IF;
END $$;

-- 3. Avanzar el puntero de Alembic (solo si estamos en el head previo)
UPDATE alembic_version
    SET version_num = 'f309a0115906'
    WHERE version_num = 'c9d12f0e5b67';

COMMIT;

-- Verificación (correr aparte tras el COMMIT):
--   SELECT version_num FROM alembic_version;          -- => f309a0115906
--   SELECT DISTINCT profile FROM tenants;             -- => pyme (default)
