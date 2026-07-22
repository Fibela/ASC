# Runbook de Operaciones — ASC (PremosCorp)

> Operación honesta para un equipo pequeño (hoy, fundador-solo). No hay SOC 24/7. Este runbook
> define cómo vigilar, diagnosticar y recuperar la plataforma ASC. **Versión:** 0.1 · [FECHA]

## 1. Arquitectura operativa (lo que hay que vigilar)

- **Frontend + backend:** Vercel (proyecto `asc-mono`, Next.js + FastAPI serverless).
- **Datos:** Supabase (PostgreSQL).
- **Fuente de eventos:** agentes SPECTER (poll-based).
- **Correo:** Resend. **Pagos:** Stripe. **Explicación adaptativa:** Anthropic.

## 2. Endpoints de salud (verificados)

| Endpoint | Auth | Qué dice |
|----------|------|----------|
| `GET /api/v1/health/liveness` | ninguna | el proceso responde |
| `GET /api/v1/health/readiness` | ninguna | **DB + esquema (deriva) + Redis**; `status: ready` si todo OK |
| `GET /api/v1/health/system` | JWT | versión, uptime, CPU/mem |
| `GET /api/v1/health/adapters` | analyst+ | sonda en vivo de adaptadores configurados |
| `GET /api/v1/observability/metrics` | analyst+ JWT **o** `METRICS_SCRAPE_TOKEN` | métricas Prometheus |
| `GET /api/v1/observability/summary` | analyst+ | snapshot JSON para la página de status |

**Chequeo rápido de salud (una línea):**
```bash
curl -s https://asc.premoscorp.com/api/v1/health/readiness | jq
# Esperado: {"status":"ready","checks":{"database":{"ok":true},"schema":{"ok":true,"missing":[]},...}}
```
Si `schema.ok` es `false` con columnas en `missing` → hay una **migración pendiente**
(correrla en Supabase ANTES de que el deploy la necesite; ver incidente I-3).

## 3. Monitoreo continuo — EL GAP CRÍTICO

**Hoy nadie vigila prod entre despliegues.** El `deploy-smoke` solo corre en cada push. Si
ASC se cae de madrugada, no salta ninguna alerta. Prioridades para cerrarlo:

1. **Monitor externo de uptime (recomendado, producción):** dar de alta un chequeo cada 1–5
   min sobre `/api/v1/health/readiness` en un servicio externo (UptimeRobot / Better Uptime /
   monitoreo nativo de Vercel), con alerta a correo/Telegram. Es independiente de la
   plataforma, así que detecta caídas totales. **Acción pendiente del fundador.**
2. **Stopgap inmediato:** tarea programada (Cowork) que sondea readiness y avisa si no está
   `ready`. Cubre el hueco mientras se configura el monitor externo (ver §7).
3. **Prometheus/Grafana (opcional):** el endpoint `/observability/metrics` ya existe; se puede
   scrapear con `METRICS_SCRAPE_TOKEN` desde un Grafana Cloud gratuito para dashboards+alertas.

## 4. Error tracking — GAP

No hay Sentry/Datadog: los errores solo viven en los logs de Vercel (efímeros, sin alerta de
picos). El backend usa `structlog` (JSON en prod), lo cual ayuda, pero no sustituye un
agregador. **Recomendado:** integrar Sentry (SDK + `SENTRY_DSN` en Vercel) para captura y
alerta de excepciones. *(roadmap)*

## 5. Recuperación / rollback

- **Rollback de deploy (Vercel):** cada deploy de producción es candidato a rollback
  (`isRollbackCandidate`). Desde el dashboard de Vercel → Deployments → "Instant Rollback" al
  último deploy `READY` bueno. Recuperación en segundos, sin tocar la DB.
- **Deriva de esquema (I-3):** si readiness reporta `schema_drift`, correr el SQL de migración
  pendiente en Supabase; readiness vuelve a `ready` sin re-deploy.
- **DB (Supabase):** verificar estado en el panel de Supabase; restaurar desde respaldo si
  aplica. [Definir política de respaldos y RTO/RPO.]

## 6. Respuesta a incidentes de la plataforma (no del cliente)

1. **Detectar:** alerta del monitor o reporte. 2. **Confirmar:** `curl` a readiness + revisar
   deploy en Vercel. 3. **Contener:** rollback si un deploy reciente lo causó. 4. **Corregir:**
   fix + push (CI verde) o SQL de migración. 5. **Verificar:** readiness `ready` + smoke.
   6. **Registrar:** anotar en `docs/AUDIT_LOG.md` (como I-3).

## 7. Tarea programada de salud (stopgap) — ver §3

Configurada vía Cowork: sondea `readiness` en intervalo definido y avisa al fundador si el
estado ≠ `ready` o el HTTP ≠ 200. **No reemplaza** un monitor externo (depende de Cowork
activo), pero cubre el hueco de inmediato.

## 8. Pendientes para "operación vendible"

- [ ] Monitor externo de uptime con alerta (P0 real).
- [ ] Error tracking (Sentry).
- [ ] Página de **status PÚBLICA** (hoy `/status` exige login; un cliente no puede verla si
      está caído). Exponer una variante pública con liveness+readiness (sin datos sensibles).
- [ ] Política de respaldos, RTO/RPO y SLA formal.
- [ ] Hardening menor: `METRICS_SCRAPE_TOKEN` comparado con `compare_digest` (tiempo constante).

---
*PremosCorp — "Cree en tu ambición." La honestidad operativa también es producto.*

---

## S108.1 — Monitoreo de plataforma IMPLEMENTADO (3 capas PremosCorp, sin vendors)

Arquitectura aprobada: sin monitores externos de terceros; se usa Supabase (AWS) como
watchdog independiente de Vercel.

**Hallazgo previo:** el scaffolding (heartbeat + tabla + hooks en los crons) estaba **sin
commitear** y la migración creaba un **segundo head de Alembic** (encadenaba a `z6t89u7x1s14`).
Corregido: encadenada al head real `e37196d70ecb`; head único restaurado.

### Capa 1 — Heartbeats (en la DB)
Los 5 crons de Vercel ya llaman `emit_heartbeat(job)` al terminar (ok/error). El endpoint
**`GET /api/v1/health/platform`** (NUEVO) lee `platform_heartbeats` y reporta frescura:
- **Público:** solo resumen (`operational|degraded|unknown` + conteos). No expone nombres ni
  cadencia por-job (anti-inteligencia).
- **`/platform/detail` (analyst+):** detalle por-job (edad, umbral, fallos).
- Degradación honesta: si la tabla no existe → `unknown`, nunca 500.

**Decisión de eficiencia:** el cron dedicado de 1 min queda **fuera de `vercel.json`** (endpoint
`/cron/heartbeat` disponible pero no agendado). El watchdog a 2 min + los latidos por-job cubren
la señal; se puede activar después si se quiere sub-2-min.

### Capa 2 — Watchdog externo (Supabase Edge Function)
`supabase/functions/asc-watchdog/index.ts`: corre en AWS (independiente de Vercel), pinguea
**`/health/readiness`** (no liveness — así detecta también caída de DB) cada 2 min, escribe el
latido `watchdog-supabase`, y **alerta por Resend** si no está `ready`.

### Despliegue (orden correcto)
1. **Tabla:** correr `backend/migrations_s108_platform_heartbeats.sql` en Supabase SQL Editor
   (sin ella, la Capa 1 no deja rastro).
2. **Edge Function:** `supabase functions deploy asc-watchdog` + secrets:
   `supabase secrets set RESEND_API_KEY=... WATCHDOG_ALERT_EMAIL=... SUPABASE_SERVICE_ROLE_KEY=...`
3. **Programar:** habilitar extensiones `pg_cron` + `pg_net`, correr `supabase/watchdog_setup.sql`
   (reemplazar `<PROJECT_REF>` y `<SERVICE_ROLE_KEY>`).
4. **Verificar:** `curl https://asc.premoscorp.com/api/v1/health/platform` → tras unos minutos,
   `status: operational` con el latido `watchdog-supabase` fresco.

### Capa 3 — Red SPECTER como monitor distribuido (IMPLEMENTADO)
Cada agente es un punto de observación desde una red independiente. Cuando un agente pierde
y recupera contacto con ASC, reporta el hueco vía la telemetría FIRMADA existente
(`event_type='specter.connectivity_gap'`) — **sin migración ni infra nueva**. El backend
(`services/reachability.py`) agrega los reportes de la ventana reciente:
- **0 agentes → none**; **1 agente → localized** (problema de red de ese cliente);
- **≥2 agentes/redes → global** (probable caída de ASC).

Es RETROSPECTIVO (da radio de impacto tras el hecho: "¿fue ASC o la red del cliente?"); la
alerta EN VIVO la da el watchdog (Capa 2). Se expone en `GET /health/platform/detail` (analyst+)
bajo `distributed`. Los eventos `specter.*` se EXCLUYEN del bridge de alertas (no ensucian).
