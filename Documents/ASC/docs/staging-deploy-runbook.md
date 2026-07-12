# ASC PremosCorp — Staging Deploy Runbook
> Versión 2.0 | Actualizado: 2026-07-12 | S98 — render.yaml v2.0 (88 env vars), 26 migraciones, head c9d12f0e5b67

Este runbook cubre el proceso completo de deploy a staging (Render + Vercel + Supabase)
antes del go-live en producción. Ejecutar en orden estricto.

---

## Contexto de arquitectura

| Capa | Servicio | URL |
|------|----------|-----|
| Backend | Render (`asc-backend`) | `https://asc-backend.onrender.com` |
| Frontend | Vercel (`asc-mono`, team `alfa-premos-projects`) | `https://asc.premoscorp.com` |
| DB | Supabase (PostgreSQL 16, pooler pgbouncer) | `aws-1-us-east-1.pooler.supabase.com:6543` |
| CI/CD | GitHub Actions | `.github/workflows/deploy.yml` |

**No hay proxy entre frontend y backend.** El frontend llama directamente al backend via `NEXT_PUBLIC_API_URL`.

---

## Pre-requisitos

| Herramienta | Versión mínima | Verificación |
|-------------|----------------|-------------|
| Python | 3.12+ | `python --version` |
| Node.js | 18+ | `node --version` |
| Git | 2.40+ | `git --version` |
| Vercel CLI | latest | `vercel --version` |
| gh CLI | latest | `gh --version` |

---

## FASE 0 — Validación pre-deploy (local)

### 0.1 Suite de tests completa

```bash
cd backend
python -m pytest tests/ -x --tb=short -q
# Requisito: 0 failed, coverage >= 85%
# Estado actual (S98): 4930 passed, 0 failed, 14 skipped, 85.37% cov ✅
```

### 0.2 Escaneo de seguridad

```bash
# Análisis estático Python (ruta correcta: asc_api/, no app/)
python -m bandit -r asc_api/ -ll -f txt
# Esperado: 0 HIGH, 0 MEDIUM; 2 LOW aceptables (nosec B105/B106 — false positives)

# Dependencias vulnerables
python -m pip_audit -r requirements.txt --format=columns
# Esperado: "No known vulnerabilities found" ✅ (verificado S98)

# Safety check
python -m safety scan --output screen
# Esperado: 0 vulnerabilities

# Secretos hardcodeados (busca fuera de nosec/tests)
grep -rEn "(password|secret|api_key|token)\s*=\s*['\"][^'\"]{8,}" asc_api/ \
  --include="*.py" | grep -v "#.*nosec" | grep -v "changeme\|your_\|example\|REPLACE"
# Esperado: 0 resultados ✅

# Verificar que .env no está en git
git ls-files | grep -E "^\.env$" && echo "ALERTA: .env en git" || echo ".env OK"
# Esperado: ".env OK" ✅
```

### 0.3 Variables de entorno requeridas

**En Render Dashboard** (Settings → Environment → Set from render.yaml):

> render.yaml v2.0 (S98) declara 88 env vars. Las marcadas `sync: false` deben
> tener valor real en el Dashboard de Render antes del deploy.

**OBLIGATORIAS — backend no arranca sin estas:**
- [ ] `SECRET_KEY` — mínimo 32 chars: `python -c "import secrets; print(secrets.token_hex(32))"`
- [ ] `DATABASE_URL` — `postgresql+asyncpg://postgres.[ref]:[pass]@aws-1-us-east-1.pooler.supabase.com:6543/postgres`
- [ ] `SUPABASE_JWT_SECRET` — JWT secret de Supabase Dashboard → Settings → API

**OPCIONALES IMPORTANTES:**
- [ ] `STRIPE_SECRET_KEY` — `sk_live_...`; vacío = billing desactivado (usar para staging)
- [ ] `STRIPE_WEBHOOK_SECRET` — `whsec_...`; vacío = validación webhook skip
- [ ] `RESEND_API_KEY` — `re_...` para envío de emails de verificación
- [ ] `SUPABASE_URL` — `https://[ref].supabase.co`
- [ ] `SUPABASE_ANON_KEY` — anon key de Supabase
- [ ] `SUPABASE_SERVICE_KEY` — service_role key de Supabase

**En GitHub Secrets** (`https://github.com/Fibela/ASC/settings/secrets/actions`):
- [ ] `CI_LEDGER_SECRET` — secret para el job `premos-ledger` en p49-security-gates.yml
  ```bash
  # Generar:
  python -c "import secrets; print(secrets.token_hex(32))"
  # Agregar:
  gh secret set CI_LEDGER_SECRET
  ```
- [ ] `RENDER_API_KEY` — API key de Render para el job `deploy-backend`
- [ ] `RENDER_BACKEND_SERVICE_ID` — Variable (no secret): ID del servicio Render

**En Vercel** (ya configurado, pero verificar):
- [ ] `NEXT_PUBLIC_API_URL` → `https://asc-backend.onrender.com` ✅ (ya configurado)

---

## FASE 1 — Migraciones de base de datos

```bash
cd backend

# 1. Verificar cabeza actual de migraciones en DB
alembic current
# Esperado: alguna revisión anterior (puede estar desactualizada)

# 2. Verificar que el head local es correcto
alembic heads
# Esperado: c9d12f0e5b67 (head) — 26 migraciones totales

# 3. Mostrar migraciones pendientes
alembic history --indicate-current
# Ver cuántas faltan desde el estado actual de la DB

# 4. TOMAR BACKUP ANTES DE MIGRAR (Supabase → Database → Backups → Create backup now)
# IMPORTANTE: Siempre hacer backup antes de upgrade en DB real

# 5. Aplicar migraciones pendientes
alembic upgrade head
# Esperado: migrations aplicadas sin error, head final: c9d12f0e5b67

# 6. Verificar estructura de tablas críticas (en Supabase SQL Editor)
# SELECT table_name FROM information_schema.tables
# WHERE table_schema = 'public' ORDER BY table_name;
# Tablas esperadas incluyen: tenants, users, alerts, events, iocs, api_keys,
#   webhooks, usage_records, incidents, forensic_entries, neutralization_requests,
#   threat_clusters, correlation_campaigns, hunt_sessions,
#   detection_rules, billing_plans (P58 — migración b3c4d5e6f7a8)

# 7. Verificar columnas P53-P55 (onboarding + billing)
# SELECT column_name FROM information_schema.columns
# WHERE table_name = 'users'
#   AND column_name IN ('email_verified','email_verification_token',
#                       'email_verification_expires_at','onboarding_step');
# Esperado: 4 filas

# SELECT column_name FROM information_schema.columns
# WHERE table_name = 'tenants'
#   AND column_name IN ('stripe_customer_id','stripe_subscription_id');
# Esperado: 2 filas
```

---

## FASE 2 — Deploy Backend (Render)

```bash
# Opción A — Auto-deploy (recomendado)
# Push a main → Render detecta render.yaml → deploy automático
git push origin main

# Opción B — Deploy manual vía Render Dashboard
# Dashboard → asc-backend → Manual Deploy → Deploy latest commit

# Monitorear logs en Render Dashboard (esperar "Application startup complete")
# o via API:
curl -s "https://api.render.com/v1/services/${RENDER_SERVICE_ID}/deploys?limit=1" \
  -H "Authorization: Bearer ${RENDER_API_KEY}" | python -m json.tool
```

### Verificación post-deploy backend

```bash
BACKEND_URL="https://asc-backend.onrender.com"

# Health check (puede tardar 30-60s en levantar el servicio free tier)
curl -sf "$BACKEND_URL/health" | python -m json.tool
# Esperado: {"status":"ok","version":"..."}

# Liveness check
curl -sf "$BACKEND_URL/health/liveness"
# Esperado: {"status":"alive"}

# CORS: origen legítimo debe pasar
curl -H "Origin: https://asc.premoscorp.com" \
     -H "Access-Control-Request-Method: GET" \
     -X OPTIONS "$BACKEND_URL/api/v1/metrics/public" -I 2>&1 | grep -i "access-control"
# Esperado: access-control-allow-origin: https://asc.premoscorp.com

# CORS: www.premoscorp.com debe pasar (CORS_ORIGINS_EXTRA)
curl -H "Origin: https://www.premoscorp.com" \
     -H "Access-Control-Request-Method: GET" \
     -X OPTIONS "$BACKEND_URL/api/v1/metrics/public" -I 2>&1 | grep -i "access-control"
# Esperado: access-control-allow-origin: https://www.premoscorp.com

# CORS: origen malicioso debe ser rechazado
curl -H "Origin: https://evil.com" -I "$BACKEND_URL/api/v1/metrics/public" 2>&1 | grep -i "access-control"
# Esperado: sin Access-Control-Allow-Origin header

# Endpoint protegido sin token (debe dar 401)
HTTP=$(curl -s -o /dev/null -w "%{http_code}" "$BACKEND_URL/api/v1/events/")
[ "$HTTP" = "401" ] && echo "✅ 401 correcto" || echo "❌ FALLO: esperado 401, recibido $HTTP"

# Endpoint público sin auth
curl -sf "$BACKEND_URL/api/v1/metrics/public" | python -m json.tool
# Esperado: JSON con métricas
```

---

## FASE 3 — Deploy Frontend (Vercel)

```bash
# Opción A — Auto-deploy
# Push a main → Vercel detecta cambios en frontend/ → deploy automático

# Opción B — Deploy manual
cd frontend
vercel --prod
```

### Verificación post-deploy frontend

```bash
FRONTEND_URL="https://asc.premoscorp.com"

# Security headers
curl -I "$FRONTEND_URL" 2>&1 | grep -E "(x-frame|x-content|content-security|strict-transport|x-xss)" -i
# Esperado: X-Frame-Options: DENY, X-Content-Type-Options: nosniff, CSP, HSTS

# HSTS con preload
curl -I "$FRONTEND_URL" 2>&1 | grep -i "strict-transport"
# Esperado: max-age=31536000; includeSubDomains; preload

# Login accesible
HTTP=$(curl -s -o /dev/null -w "%{http_code}" "$FRONTEND_URL/login")
echo "Login HTTP: $HTTP (esperado: 200)"

# API conectada (desde el browser, revisar Network tab en /login)
```

---

## FASE 4 — Test funcional E2E (staging)

```bash
BACKEND_URL="https://asc-backend.onrender.com"

# 1. Registrar primer admin
curl -X POST "$BACKEND_URL/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin-staging@premoscorp.com","password":"Staging$ecure123!","full_name":"Admin Staging"}'
# Esperado: {"access_token":"...","token_type":"bearer"}

# 2. Login
TOKEN=$(curl -s -X POST "$BACKEND_URL/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin-staging@premoscorp.com","password":"Staging$ecure123!"}' \
  | python -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

echo "Token obtenido: ${TOKEN:0:20}..."

# 3. Verificar /me
curl -sf -H "Authorization: Bearer $TOKEN" "$BACKEND_URL/api/v1/auth/me" | python -m json.tool
# Esperado: {"email":"admin-staging@premoscorp.com","role":"admin",...}

# 4. Crear API Key
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "$BACKEND_URL/api/v1/api-keys/" \
  -d '{"name":"Staging Test Key","scopes":["read"]}'
# Esperado: 201 con raw_key (mostrar SOLO una vez — no loguear)

# 5. Crear Webhook de prueba
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "$BACKEND_URL/api/v1/webhooks/" \
  -d '{"url":"https://webhook.site/test","events":["test"],"description":"Staging test"}'
# Esperado: 201 con secret

# 6. Crear alerta de prueba
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "$BACKEND_URL/api/v1/alerts/" \
  -d '{"title":"Staging Test Alert","severity":"low","source":"e2e-test"}'
# Esperado: 201

# 7. Métricas públicas
curl -sf "$BACKEND_URL/api/v1/metrics/public" | python -m json.tool
# Esperado: JSON con métricas (puede mostrar 0s en staging limpio)
```

---

## Criterios de aceptación para avanzar a go-live

- [ ] `/health` responde `{"status":"ok"}` en menos de 2s
- [ ] `/health/liveness` responde `{"status":"alive"}` en menos de 1s
- [ ] 0 errores de startup en logs de Render (SECRET_KEY, CORS, DB)
- [ ] 26 migraciones aplicadas correctamente (cabeza: `c9d12f0e5b67`)
- [ ] CORS rechaza `evil.com`, acepta `asc.premoscorp.com` y `www.premoscorp.com`
- [ ] Frontend carga con todos los security headers en `asc.premoscorp.com`
- [ ] Login, crear API Key y Webhook funcionan E2E
- [ ] Suite pytest local: 0 failed, coverage ≥ 85% ✅ (4930/4930, 85.37%)
- [ ] Bandit: 0 HIGH/MEDIUM ✅ (2 LOW nosec legítimos)
- [ ] pip-audit: 0 CVEs ✅

---

## GitHub Secrets requeridos (configuración manual)

```bash
# Instalar gh CLI si no está disponible:
# https://cli.github.com/manual/installation

# Autenticar (una vez):
gh auth login

# Configurar secrets:
gh secret set CI_LEDGER_SECRET --repo Fibela/ASC
# (pegar el valor generado con: python -c "import secrets; print(secrets.token_hex(32))")

gh secret set RENDER_API_KEY --repo Fibela/ASC
# (obtener de Render Dashboard → Account → API Keys)

# Variables (no secrets):
gh variable set RENDER_BACKEND_SERVICE_ID --repo Fibela/ASC --body "srv-XXXXXXXX"
# (obtener de Render Dashboard → asc-backend → Settings → Service ID)
```

---

## Rollback procedure

```bash
# Si el deploy falla y el servicio no levanta:
# En Render Dashboard → asc-backend → Deploys → seleccionar deploy anterior → Rollback

# Si las migraciones rompen la DB:
# 1. PRIMERO: restaurar backup de Supabase (Dashboard → Database → Backups)
# 2. Si necesario revertir última migración:
alembic downgrade -1
# 3. Nuclear (solo emergencia):
alembic downgrade base
```

---

## Observación post go-live (72h)

Ver `docs/go-live-runbook.md` para el proceso de observación con umbrales P1/P2/P3.
