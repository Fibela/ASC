# Roadmap — Threat Intel estratificado en 3 capas

**Estado:** DISEÑO APROBADO, NO IMPLEMENTADO. Se activa cuando exista un 2.º tenant
que solicite compartir intel. Hoy el sistema corre el modelo de **2 capas** (ver más
abajo), que cierra la fuga real sin migración.

**Fecha decisión:** 2026-07-21. Fundador solo, cero tenants externos → construir las 3
capas ahora sería resolver un problema que nadie tiene (YAGNI). Se documenta para no
perder el diseño.

## Modelo de 3 capas (objetivo futuro)

```
CAPA 0 — GLOBAL (platform-wide, inmutable, solo lectura)
  Fuentes: AbuseIPDB, VirusTotal, OTX, feeds OSINT.
  tenant_id = NULL, sharing_group_id = NULL.
  Confidencialidad: TLP:WHITE / TLP:CLEAR.

CAPA 1 — SHARED (opt-in entre tenants)
  Ej.: grupo ISAC sectorial; clientes del mismo giro que acuerdan compartir.
  sharing_group_id = <grupo>; visible a los tenants MIEMBROS del grupo.
  Confidencialidad: TLP:GREEN.

CAPA 2 — PRIVATE (estrictamente por tenant)
  IOCs de incidentes propios, threat hunting propio, intel contratada exclusiva.
  tenant_id = <uuid>; nunca cruza la frontera del tenant.
  Confidencialidad: TLP:AMBER / TLP:RED.
```

## Qué falta para implementarla (cuando toque)

1. **Esquema** (migración manual en Supabase ANTES del deploy — lección I-3):
   - `threat_intel_indicators.sharing_group_id  VARCHAR(36) NULL` + índice.
   - `threat_intel_indicators.tlp VARCHAR(12) NOT NULL DEFAULT 'white'`
     con `CHECK (tlp IN ('white','green','amber','red'))`.
   - Tabla `threat_sharing_group_members (id, tenant_id, sharing_group_id, created_at)`
     con UNIQUE(tenant_id, sharing_group_id).
2. **Servicio** `threat_intel.py`: ampliar `_visible(tenant_id, groups)` a
   `or_(global, propio, sharing_group_id IN groups)`; helper
   `_tenant_sharing_groups(db, tenant_id)`.
3. **Endpoints de administración de grupos** (alta/baja de miembros, crear grupo) —
   admin/platform. Enforcement de TLP en la respuesta.
4. **Tests**: visibilidad por capa, opt-in, que un no-miembro NO ve la CAPA 1.
5. **Guardia AST**: ya vigila `ThreatIntelIndicator` (corregido en S105.1).

## Modelo VIGENTE (2 capas, implementado en S105.1)

- CAPA 0 GLOBAL: `tenant_id IS NULL` — corpus compartido visible a todos.
- CAPA 2 PRIVADA: `tenant_id = <uuid>` — solo el tenant dueño lee/edita.
- Lectura: `or_(tenant_id IS NULL, tenant_id == mío)` (`_visible`).
- Escritura/idempotencia: scope exacto del que escribe (`_own_scope`).
- Sin columnas nuevas → sin migración → sin riesgo de deriva de esquema.
- Probado en `backend/tests/test_s105_ti_isolation.py` (8 tests).
