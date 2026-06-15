# ASC PremosCorp — Staging Deploy Runbook
> Versión 1.0 | Fecha: 2026-06-15 | P57-TD2

Este runbook cubre el proceso completo de deploy a staging (Render + Vercel + Supabase)
antes del go-live en producción. Ejecutar en orden estricto.

---

## Pre-requisitos

| Herramienta | Versión mínima | Verificación |
|-------------|----------------|-------------|
| Python | 3.11+ | `python --version` |
| Node.js | 18+ | `node --version` |
| Git | 2.40+ | `git --version` |
| Render CLI | latest | `render --version` |
| Vercel CLI | latest | `vercel --version` |

---

## FASE 0 — Validación pre-deploy (local)

### 0.1 Suite de tests completa

```bash
cd backend
python -m pytest tests/ -x --tb=short -q
# Requisito: 0 failed, coverage >= 85%
```

### 0.2 Escaneo de seguridad

```bash
# Análisis estático Python
python -m bandit -r app/ -ll -f txt
# Esperado: "No issues identified."

# Dependencias vulnerables
python -m pip_audit -r requirements.txt --format=columns
# Esperado: "No known vulnerabilities found"

# Safety check
python -m safety scan --output screen
# Esperado: 0 vulnerabilities

# Secretos hardcodeados (busca fuera de nosec/tests)
grep -rEn "(password|secret|api_key)\s*=\s*['\"][^'\"]{8,}" app/ \
  --include="*.py" | grep -v "#.*nosec" | grep -v "changeme\|your_\|example\|REPLACE"
# Esperado: 0 resultados

# Verificar que .env no está en git
git ls-files | grep -E "^\.env$" && echo "ALERTA: .env en git" || echo ".env OK"
```

### 0.3 Variables de entorno requeridas (checklist)

Antes del deploy, confirmar que las siguientes variables están configuradas
en el Render Dashboard (Settings → Environment):

**OBLIGATORIAS (sync:false — sin estas el backend no arranca):**
- [ ] `SECRET_KEY` — mínimo 32 chars, generado con `secrets.token_hex(32)`
- [ ] `DATABASE_URL` — Supabase connection string (Session mode, puerto 5432)
  - Formato: `postgresql+asyncpg://postgres.[ref]:[pass]@aws-0-*.pooler.supabase.com:5432/postgres`
- [ ] `CORS_ORIGINS` — JSON array: `["https://asc-premoscorp.vercel.app","https://asc.premoscorp.com"]`

**OPCIONALES (vacío = feature desactivado):**
- [ ] `REDIS_URL` — Upstash URL para Celery; vacío = modo no-op
- [ ] `METRICS_SCRAPE_TOKEN` — token Prometheus; vacío = requiere JWT analista
- [ ] `STRIPE_SECRET_KEY` — `sk_live_…`; vacío = billing desactivado
- [ ] `STRIPE_WEBHOOK_SECRET` — `whsec_…`; vacío = validación webhook skip
- [ ] `SPECTER_SIGNING_PRIVATE_KEY` — clave Ed25519 base64; vacío = firma desactivada
- [ ] `SPECTER_SIGNING_PUBLIC_KEY` — clave pública Ed25519 base64

**Vercel (frontend — configurar en Vercel Dashboard → Settings → Environment Variables):**
- [ ] `NEXT_PUBLIC_API_URL` — URL del backend Render: `https://asc-backend.onrender.com`

---

## FASE 1 — Migraciones de base de datos

```bash
# En Supabase SQL Editor o desde máquina con acceso directo a la DB:
# 1. Verificar cabeza actual de migraciones
alembic current
# Esperado: <revision_id> (head)

# 2. Aplicar migraciones pendientes
alembic upgrade head
# Esperado: 15 migraciones aplicadas (cabeza: s9m12p1r4l06)

# 3. Verificar estructura de tablas críticas
# En Supabase SQL Editor:
SELECT table_name FROM information_schema.tables
WHERE table_schema = 'public'
ORDER BY table_name;
# Esperado: tenants, users, alerts, events, iocs, api_keys, webhooks,
#           usage_records, incidents, forensic_entries, neutralization_requests,
#           threat_clusters, correlation_campaigns, hunt_sessions...

# 4. Verificar columnas nuevas P53-P55 en users/tenants
SELECT column_name FROM information_schema.columns
WHERE table_name = 'users' AND column_name IN
  ('email_verified','email_verification_token','email_verification_expires_at','onboarding_step');
# Esperado: 4 filas

SELECT column_name FROM information_schema.columns
WHERE table_name = 'tenants' AND column_name IN
  ('stripe_customer_id','stripe_subscription_id');
# Esperado: 2 filas

SELECT table_name FROM information_schema.tables
WHERE table_name = 'usage_records';
# Esperado: 1 fila
```

---

## FASE 2 — Deploy Backend (Render)

```bash
# Opción A — Auto-deploy (recomendado)
# Push a main → Render detecta render.yaml → deploy automático
git push origin main

# Opción B — Deploy manual via CLI
render deploy --yaml render.yaml --service asc-backend

# Monitorear logs (esperar "Application startup complete")
render logs asc-backend --tail
```

### Verificación post-deploy backend

```bash
BACKEND_URL="https://asc-backend.onrender.com"

# Health check
curl -sf "$BACKEND_URL/health" | python -m json.tool
# Esperado: {"status":"ok","version":"..."}

# Startup checks (no debe haber RuntimeError)
curl -sf "$BACKEND_URL/health/liveness"
# Esperado: {"status":"alive"}

# Versión de migraciones (via /health/detailed si disponible)
curl -sf "$BACKEND_URL/health/detailed" | python -m json.tool

# CORS: origen legítimo debe pasar
curl -H "Origin: https://asc-premoscorp.vercel.app" \
     -H "Access-Control-Request-Method: GET" \
     -X OPTIONS "$BACKEND_URL/api/v1/metrics/public" -I
# Esperado: Access-Control-Allow-Origin: https://asc-premoscorp.vercel.app

# CORS: origen malicioso debe ser rechazado
curl -H "Origin: https://evil.com" -I "$BACKEND_URL/api/v1/metrics/public"
# Esperado: sin Access-Control-Allow-Origin header

# Endpoint público (no requiere auth)
curl -sf "$BACKEND_URL/api/v1/metrics/public" | python -m json.tool
# Esperado: JSON con métricas

# Endpoint protegido sin token (debe dar 401)
curl -sf "$BACKEND_URL/api/v1/events/" && echo "FALLO: debe dar 401" || echo "OK: 401 correcto"
```

---

## FASE 3 — Deploy Frontend (Vercel)

```bash
# Opción A — Auto-deploy
# Push a main → Vercel detecta next.config.js → deploy automático

# Opción B — Deploy manual
cd frontend
vercel --prod

# Configurar variable de entorno si no está
vercel env add NEXT_PUBLIC_API_URL production
# Valor: https://asc-backend.onrender.com
```

### Verificación post-deploy frontend

```bash
FRONTEND_URL="https://asc-premoscorp.vercel.app"

# Security headers
curl -I "$FRONTEND_URL" | grep -E "(X-Frame|X-Content|Content-Security|Strict-Transport|X-XSS)"
# Esperado: X-Frame-Options: DENY, X-Content-Type-Options: nosniff, CSP presente

# HSTS
curl -I "$FRONTEND_URL" | grep "Strict-Transport-Security"
# Esperado: max-age=31536000; includeSubDomains; preload

# Login page accessible
curl -sf "$FRONTEND_URL/login" -o /dev/null -w "%{http_code}"
# Esperado: 200

# Dashboard redirige a login sin token (client-side guard)
curl -sf "$FRONTEND_URL/dashboard" -o /dev/null -w "%{http_code}"
# Esperado: 200 (SSR), el redirect es client-side via useAuthGuard
```

---

## FASE 4 — Test funcional end-to-end (staging)

```bash
# Bootstrap primer admin
curl -X POST "$BACKEND_URL/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@premoscorp.com","password":"Staging$ecure123!","full_name":"Admin Staging"}'
# Esperado: {"access_token":"...","token_type":"bearer"}

# Login
TOKEN=$(curl -sX POST "$BACKEND_URL/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@premoscorp.com","password":"Staging$ecure123!"}' \
  | python -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Verificar /me
curl -sf -H "Authorization: Bearer $TOKEN" "$BACKEND_URL/api/v1/auth/me"
# Esperado: {"email":"admin@premoscorp.com","role":"admin",...}

# Crear API Key
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "$BACKEND_URL/api/v1/api-keys/" \
  -d '{"name":"Staging Test Key","scopes":["read"]}'
# Esperado: 201 con raw_key (mostrar SOLO una vez)

# Webhook test
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "$BACKEND_URL/api/v1/webhooks/" \
  -d '{"url":"https://webhook.site/test","events":["test"],"description":"Staging test"}'
# Esperado: 201 con secret (mostrar SOLO una vez)
```

---

## Criterios de aceptación para avanzar a go-live

- [ ] `/health` responde `{"status":"ok"}` en menos de 2s
- [ ] `/health/liveness` responde `{"status":"alive"}` en menos de 1s
- [ ] 0 errores de startup en logs de Render (SECRET_KEY, CORS, DB)
- [ ] Migraciones aplicadas correctamente (15 migraciones, cabeza s9m12p1r4l06)
- [ ] CORS rechaza `evil.com`, acepta `asc-premoscorp.vercel.app`
- [ ] Frontend carga con todos los security headers
- [ ] Login, crear API Key y Webhook funcionan correctamente
- [ ] Suite pytest completa: 0 failed, coverage ≥85%
- [ ] Bandit: 0 issues H/M
- [ ] pip-audit: 0 CVEs

---

## Rollback procedure

```bash
# Si el deploy falla y el servicio no levanta:
# 1. En Render Dashboard → asc-backend → Deploys → revert al deploy anterior
# 2. O desde CLI:
render rollback asc-backend

# Si las migraciones rompen la DB (ejecutar ANTES del upgrade):
# Tomar snapshot de Supabase: Dashboard → Database → Backups → Create backup now
alembic downgrade -1  # revertir última migración
alembic downgrade base  # revertir todo (nuclear — solo en emergencia)
```
