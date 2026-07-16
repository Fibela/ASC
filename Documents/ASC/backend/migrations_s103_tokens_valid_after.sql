-- ============================================================================
-- ASC · Migración S103.3 — users.tokens_valid_after (invalidación de sesión)
-- Head: f309a0115906  ->  f9edec8a6897
-- Ejecutar en Supabase → SQL Editor ANTES del push (la columna la lee el ORM).
-- Idempotente.
-- ============================================================================
BEGIN;
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS tokens_valid_after TIMESTAMPTZ NULL;
UPDATE alembic_version
    SET version_num = 'f9edec8a6897'
    WHERE version_num = 'f309a0115906';
COMMIT;
-- Verificar:  SELECT version_num FROM alembic_version;  -- => f9edec8a6897
