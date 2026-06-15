# ASC PremosCorp — Go-Live Runbook (72h Observation)
> Versión 1.0 | Fecha: 2026-06-15 | P57-TD5

Este runbook cubre la ventana de observación de 72h post go-live en producción.
Ejecutar **solo después** de que el staging deploy haya pasado todos los criterios
de aceptación del staging-deploy-runbook.md.

---

## Pre go-live checklist

- [ ] Staging deploy completado exitosamente (ver staging-deploy-runbook.md)
- [ ] 48h de staging sin errores críticos en logs
- [ ] Load test completado: p95 < 500ms con 100 usuarios concurrentes
- [ ] Backup de DB Supabase tomado
- [ ] Equipo en standby (2 ingenieros disponibles para incidentes)
- [ ] Ventana de mantenimiento comunicada a usuarios (si aplica)
- [ ] DNS/CNAME apuntando a dominio de producción configurado

---

## Endpoints de monitoreo (bookmarks obligatorios)

| Endpoint | Propósito | Auth |
|----------|-----------|------|
| `GET /health` | Estado del servicio | Ninguna |
| `GET /health/liveness` | Liveness probe | Ninguna |
| `GET /health/system` | CPU, memoria, PID | JWT analyst+ |
| `GET /api/v1/observability/summary` | Métricas JSON | JWT analyst+ |
| `GET /api/v1/observability/metrics` | Prometheus text | `METRICS_SCRAPE_TOKEN` o JWT |

---

## Fase 0h — Deploy a producción

```bash
# Solo si el branch main = staging validado
git checkout main
git pull origin main
git push origin main  # auto-deploy vía GitHub Actions → Render → Vercel

# Monitorear logs de Render en tiempo real
render logs asc-backend --tail

# Señales de startup exitoso (en logs):
# INFO: "startup_checks_passed" production=True
# INFO: "Application startup complete."
# INFO: Uvicorn running on http://0.0.0.0:PORT
```

---

## Tabla de observación 72h

Completar cada revisión y marcar ✅ / ❌:

| Hora | Health | Error Rate | p95 Latency | Memoria | Notas |
|------|--------|------------|-------------|---------|-------|
| 0h   | | | | | Go-live |
| 1h   | | | | | |
| 2h   | | | | | |
| 4h   | | | | | |
| 8h   | | | | | |
| 12h  | | | | | |
| 24h  | | | | | Primer día completo |
| 36h  | | | | | |
| 48h  | | | | | Segundo día completo |
| 60h  | | | | | |
| 72h  | | | | | CIERRE ventana observación |

---

## Checks de monitoreo (ejecutar en cada revisión)

```bash
PROD_URL="https://asc-backend.onrender.com"  # cambiar a dominio producción
TOKEN="<analyst_jwt>"

# 1. Health check básico
curl -sf "$PROD_URL/health" | python -m json.tool
# Verde: status=ok | Rojo: 5xx o timeout

# 2. System metrics
curl -sf -H "Authorization: Bearer $TOKEN" \
  "$PROD_URL/health/system" | python -m json.tool
# Verde: cpu < 80%, memory_rss_mb < 512
# Rojo: cpu > 90% sostenido o memory leak (crecimiento lineal)

# 3. Summary SOC
curl -sf -H "Authorization: Bearer $TOKEN" \
  "$PROD_URL/api/v1/observability/summary" | python -m json.tool
# Verificar: active_agents, pending_alerts, active_incidents en rango normal

# 4. Latencia de endpoints críticos
time curl -sf -H "Authorization: Bearer $TOKEN" \
  "$PROD_URL/api/v1/alerts/" -o /dev/null
# Verde: < 500ms | Amarillo: 500-1000ms | Rojo: > 1000ms

time curl -sf -H "Authorization: Bearer $TOKEN" \
  "$PROD_URL/api/v1/events/" -o /dev/null

# 5. Error rate en logs (últimas 100 líneas)
render logs asc-backend --tail 100 | grep -c "ERROR\|CRITICAL\|500"
# Verde: 0 | Amarillo: 1-5 | Rojo: >5
```

---

## Umbrales de alerta

### CRÍTICO (acción inmediata — escalar en < 15 min)
- `/health` retorna 5xx o no responde en 30s
- Error rate > 10% en cualquier endpoint
- Memory RSS > 800MB (posible OOM)
- Cualquier error `startup_check_failed` en logs
- SQL connection pool exhausted
- SECRET_KEY o DATABASE_URL faltantes

### ALTO (investigar en < 1h)
- p95 latencia > 1000ms sostenida
- Error rate 5-10%
- Memory leak sostenido (>10MB/hora)
- Celery tasks acumuladas sin procesar
- Rate limiting excedido por usuario legítimo

### MEDIO (investigar en < 4h)
- p95 latencia 500-1000ms
- Error rate 1-5%
- Agents SPECTER sin heartbeat > 5 min
- Webhook delivery failures > 20%

---

## Procedimientos de escalación

### P1 — Servicio caído

```bash
# 1. Verificar estado Render
render services list

# 2. Si el servicio está down, restart
render restart asc-backend

# 3. Si el restart no ayuda, revisar logs de crash
render logs asc-backend --since 1h

# 4. Rollback si el crash es post-deploy
render rollback asc-backend

# 5. Notificar al equipo (Slack #asc-incidents)
```

### P2 — DB connection pool exhausted

```bash
# Sintoma en logs: "asyncpg: too many connections"
# Solución: Supabase tiene max 100 conexiones en plan free

# 1. Verificar conexiones activas en Supabase SQL Editor:
SELECT count(*) FROM pg_stat_activity WHERE state = 'active';

# 2. Matar conexiones idle si es necesario:
SELECT pg_terminate_backend(pid) FROM pg_stat_activity
WHERE state = 'idle' AND query_start < now() - interval '10 minutes';

# 3. Considerar migrar a Supabase Pro (500 conexiones) si el tráfico lo justifica
```

### P3 — Rate limiting falso positivo

```bash
# Síntoma: usuario legítimo recibe 429
# Verificar qué clave está siendo limitada

# Revisar headers de respuesta
curl -I -H "X-API-Key: <key>" "$PROD_URL/api/v1/alerts/"
# X-RateLimit-Remaining-Minute: 0  ← límite alcanzado

# Reset manual (solo admin):
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$PROD_URL/api/v1/api-keys/<key_id>/rate-limit-reset"
```

---

## Logs de observación (llenar durante 72h)

```
HORA 0h:
- Health: OK/FAIL
- Sistema: CPU=__% RAM=__MB
- Notas:

HORA 1h:
- Health: OK/FAIL
- Sistema: CPU=__% RAM=__MB
- Notas:

[... continuar cada intervalo ...]

HORA 72h — CIERRE:
- Health: OK/FAIL
- Sistema: CPU=__% RAM=__MB
- Incidentes totales: __
- SLO cumplido (99.9% uptime): SI/NO
- Decisión: GO-LIVE CONFIRMADO / REQUEIRE ACCIÓN
```

---

## Criterios de cierre (72h exitosas)

- [ ] 0 incidentes P1
- [ ] SLO ≥ 99.9% uptime (máximo 4.32 min de downtime en 72h)
- [ ] p95 latencia < 500ms en todos los endpoints críticos
- [ ] 0 errores de seguridad (auth bypass, data leak, CORS fail)
- [ ] Celery tasks procesadas sin acumulación
- [ ] Logs sin errores CRITICAL o HIGH no manejados
- [ ] Memory RSS estable (sin leak mayor a 5MB/hora)

Al cumplir todos los criterios: **PRODUCCIÓN CONFIRMADA** — actualizar ROADMAP.md.

---

## Contactos de emergencia

| Rol | Responsabilidad | Tiempo respuesta |
|-----|-----------------|-----------------|
| Backend Lead | DB, API, migraciones | < 15 min P1 |
| DevOps / SRE | Infra, Render, Vercel | < 15 min P1 |
| Security Engineer | Auth bypass, data leak | < 30 min P1 |
