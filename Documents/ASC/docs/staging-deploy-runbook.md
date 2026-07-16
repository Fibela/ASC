# ASC PremosCorp — Staging Deploy Runbook
> Versión 3.0 | Actualizado: 2026-07-14 | S100 — Vercel-only mono-deploy, 26 migraciones, head c9d12f0e5b67

Este runbook cubre el proceso completo de deploy a staging (Vercel + Supabase).
**No se usa Render.com.** Todo corre en Vercel: frontend Next.js + backend FastAPI (serverless).
Ejecutar en orden estricto.

---

## Contexto de arquitectura

| Capa | Servicio | URL |
|------|----------|-----|
| Frontend + Backend | Vercel (`asc-mono`, team `alfa-premos-projects`) | `https://asc.premoscorp.com` |
| DB | Supabase (PostgreSQL 16, pooler pgbouncer) | `aws-1-us-east-1.pooler.supabase.com:6543` |
| Cron Jobs | Vercel Cron (5 jobs definidos en `vercel.json`) | `/api/v1/cron/...` |
| CI/CD | GitHub Actions | `.github/workflows/deploy.yml` |

**Arquitectura mono-deploy:** Next.js + FastAPI corren juntos en el mismo proyecto Vercel `asc-mono`.
El frontend hace llamadas a `/api/v1/...` (ruta relativa). Vercel reescribe `/api/:path*` → `api/index.py`
que importa la app FastAPI como ASGI serverless.

**REGLA — fuente única del API (Session 101):** `backend/asc_api` es la única fuente de verdad.
`frontend/asc_api` (lo que Vercel sirve realmente) es un **espejo generado — nunca se edita a mano**.
Editar solo la copia backend fue la causa de dos bugs reales: el fix CORS de S99 y los endpoints de
cron de S100 nunca llegaron a la copia desplegada.

```bash
node scripts/sync-asc-api.mjs           # propagar cambios backend → frontend
node scripts/sync-asc-api.mjs --check   # verificar integridad (exit 1 si diverge)
pytest backend/tests/test_asc_api_sync.py   # mismo gate, dentro de la suite
```

El `prebuild` de `frontend/package.json` re-ejecuta el sync en cada build donde el monorepo sea
visible. Todo cambio al API se hace en `backend/asc_api` y se propaga con el sync **antes** de commitear.

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
# Estado actual (S100): 4930+ passed, 0 failed, 85.37% cov ✅
```

### 0.2 Escaneo de seguridad

```bash
# Análisis estático Python
python -m bandit -r asc_api/ -ll -f txt
# Esperado: 0 HIGH, 0 MEDIUM, 0 LOW (nosec B105/B106 son falsos positivos anotados)

# Dependencias vulnerables
python -m pip_audit -r requirements.txt --format=columns
# Esperado: "No known vulnerabilities found" ✅

# Safety check
python -m safety scan --output screen

# Secretos hardcodeados
grep -rEn "(password|secret|api_key|token)\s*=\s*['\"][^'\"]{8,}" asc_api/ \
  --include="*.py" | grep -v "#.*nosec" | grep -v "changeme\|your_\|example\|REPLACE"
# Esperado: 0 resultados ✅

# Verificar que .env no está en git
git ls-files | grep -E "^\.env$" && echo "ALERTA: .env en git" || echo ".env OK"
```

### 0.3 Variables de entorno requeridas

**En Vercel Dashboard** (`https://vercel.com/alfa-premos-projects/asc-mono/settings/environment-variables`):

**OBLIGATORIAS — backend no arranca sin estas:**
- [ ] `SECRET_KEY` — mínimo 32 chars: `python -c "import secrets; print(secrets.token_hex(32))"`
- [ ] `DATABASE_URL` — `postgresql+asyncpg://postgres.[ref]:[pass]@aws-1-us-east-1.pooler.supabase.com:6543/postgres`
- [ ] `SUPABASE_JWT_SECRET` — JWT secret de Supabase Dashboard → Settings → API
- [ ] `CORS_ORIGINS` — `["https://asc.premoscorp.com","https://premoscorp.com"]`
- [ ] `DEBUG` — `false`
- [ ] `CRON_SECRET` — `python -c "import secrets; print(secrets.token_hex(32))"`

**OPCIONALES IMPORTANTES:**
- [ ] `STRIPE_SECRET_KEY` — `sk_live_...`; vacío = billing desactivado (OK para staging)
- [ ] `STRIPE_WEBHOOK_SECRET` — `whsec_...`; vacío = validación webhook skip
- [ ] `RESEND_API_KEY` — `re_...` para envío de emails de verificación
- [ ] `SUPABASE_URL` — `https://[ref].supabase.co`
- [ ] `SUPABASE_ANON_KEY` — anon key de Supabase
- [ ] `SUPABASE_SERVICE_KEY` — service_role key de Supabase
- [ ] `CORS_ORIGINS_EXTRA` — `"https://www.premoscorp.com"` (si se necesita subdomain www)

**En GitHub Secrets** (`https://github.com/Fibela/ASC/settings/secrets/actions`):
- [ ] `VERCEL_TOKEN` — Vercel Dashboard → Settings → Tokens (para deploy.yml job explícito)

---

## FASE 1 — Migraciones de base de datos

```bash
cd backend

# 1. Verificar cabeza actual de migraciones en DB
alembic current

# 2. Verificar que el head local es correcto
alembic heads
# Esperado: c9d12f0e5b67 (head) — 26 migraciones totales

# 3. TOMAR BACKUP ANTES DE MIGRAR (Supabase → Database → Backups → Create backup now)

# 4. Aplicar migraciones pendientes (idempotentes — seguros de re-ejecutar)
alembic upgrade head
# Esperado: migrations aplicadas sin error, head final: c9d12f0e5b67

# 5. Verificar tablas críticas (en Supabase SQL Editor)
# SELECT table_name FROM information_schema.tables
# WHERE table_schema = 'public' ORDER BY table_name;
```

---

## FASE 2 — Deploy (Vercel)

```bash
# Opción A — Auto-deploy (recomendado)
# Push a main → GitHub Actions ci-check pasa → Vercel detecta cambios → deploy automático
git push origin main

# Opción B — Deploy manual vía Vercel CLI
cd frontend
vercel --prod

# Opción C — Deploy manual vía GitHub Actions
# GitHub → Actions → Deploy — ASC PremosCorp → Run workflow → main
```

### Verificación post-deploy

```bash
FRONTEND_URL="https://asc.premoscorp.com"

# Security headers
curl -I "$FRONTEND_URL" 2>&1 | grep -Ei "(x-frame|x-content|content-security|strict-transport)"
# Esperado: X-Frame-Options: DENY, X-Content-Type-Options: nosniff, CSP, HSTS

# Backend UP
curl -sf "$FRONTEND_URL/api/v1/health/liveness" | python -m json.tool
# Esperado: {"status":"alive","ts":"..."}

# Backend readiness (DB conectado)
curl -sf "$FRONTEND_URL/api/v1/health/readiness" | python -m json.tool
# Esperado: {"status":"ready","checks":{"database":{"ok":true},...}}

# CORS: origen legítimo
curl -H "Origin: https://asc.premoscorp.com" \
     -H "Access-Control-Request-Method: GET" \
     -X OPTIONS "$FRONTEND_URL/api/v1/metrics/public" -I 2>&1 | grep -i "access-control"
# Esperado: access-control-allow-origin: https://asc.premoscorp.com

# CORS: www subdomain (CORS_ORIGINS_EXTRA)
curl -H "Origin: https://www.premoscorp.com" \
     -H "Access-Control-Request-Method: GET" \
     -X OPTIONS "$FRONTEND_URL/api/v1/metrics/public" -I 2>&1 | grep -i "access-control"
# Esperado: access-control-allow-origin: https://www.premoscorp.com

# CORS: origen malicioso debe ser rechazado
curl -H "Origin: https://evil.com" -I "$FRONTEND_URL/api/v1/metrics/public" 2>&1 | grep -i "access-control"
# Esperado: sin Access-Control-Allow-Origin header

# Endpoint protegido sin token (debe dar 401)
HTTP=$(curl -s -o /dev/null -w "%{http_code}" "$FRONTEND_URL/api/v1/events")
[ "$HTTP" = "401" ] && echo "✅ 401 correcto" || echo "❌ FALLO: esperado 401, recibido $HTTP"

# Endpoint público sin auth
curl -sf "$FRONTEND_URL/api/v1/metrics/public" | python -m json.tool
# Esperado: JSON con métricas
```

---

## FASE 3 — Verificación de Cron Jobs

```bash
FRONTEND_URL="https://asc.premoscorp.com"

# En Vercel Dashboard → asc-mono → Settings → Cron Jobs
# deben aparecer los 5 jobs definidos en vercel.json:
# - /api/v1/cron/correlation-sweep  (*/15 * * * *)
# - /api/v1/cron/escalation         (*/5 * * * *)
# - /api/v1/cron/sla-check          (*/10 * * * *)
# - /api/v1/cron/pcdi-scan          (*/5 * * * *)
# - /api/v1/cron/scheduled-reports  (0 * * * *)

# Test manual de un cron (requiere CRON_SECRET):
CRON_SECRET="<valor de Vercel Dashboard>"
curl -H "Authorization: Bearer $CRON_SECRET" \
     -sf "$FRONTEND_URL/api/v1/cron/correlation-sweep"
# Esperado: {"job":"correlation-sweep","status":"ok"}

# Sin secret → debe rechazar
curl -sf "$FRONTEND_URL/api/v1/cron/correlation-sweep"
# Esperado: 403 con "CRON_SECRET not configured" o "Invalid cron secret"
```

---

## FASE 4 — Test funcional E2E (staging)

```bash
FRONTEND_URL="https://asc.premoscorp.com"

# 1. Registrar primer admin
curl -X POST "$FRONTEND_URL/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin-staging@premoscorp.com","password":"Staging$ecure123!","full_name":"Admin Staging"}'
# Esperado: {"access_token":"...","token_type":"bearer"}

# 2. Login
TOKEN=$(curl -s -X POST "$FRONTEND_URL/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin-staging@premoscorp.com","password":"Staging$ecure123!"}' \
  | python -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

echo "Token: ${TOKEN:0:20}..."

# 3. Verificar /me
curl -sf -H "Authorization: Bearer $TOKEN" "$FRONTEND_URL/api/v1/auth/me" | python -m json.tool

# 4. Crear API Key
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "$FRONTEND_URL/api/v1/api-keys/" \
  -d '{"name":"Staging Test Key","scopes":["read"]}'
# Esperado: 201 con raw_key

# 5. Crear alerta de prueba
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "$FRONTEND_URL/api/v1/alerts/" \
  -d '{"title":"Staging Test Alert","severity":"low","source":"e2e-test"}'
# Esperado: 201
```

---

## Criterios de aceptación

- [ ] `/api/v1/health/liveness` responde `{"status":"alive"}` en menos de 2s
- [ ] `/api/v1/health/readiness` responde `{"status":"ready",...}`
- [ ] 0 errores de startup en logs de Vercel (SECRET_KEY, CORS, DB)
- [ ] 26 migraciones aplicadas correctamente (cabeza: `c9d12f0e5b67`)
- [ ] CORS rechaza `evil.com`, acepta `asc.premoscorp.com` y `www.premoscorp.com`
- [ ] Security headers presentes en `asc.premoscorp.com`
- [ ] Login, crear API Key y Webhook funcionan E2E
- [ ] Cron jobs visibles en Vercel Dashboard (5 jobs)
- [ ] Suite pytest local: 0 failed, coverage ≥ 85% ✅
- [ ] Bandit: 0 HIGH/MEDIUM ✅

---

## GitHub Secrets requeridos (configuración manual)

```bash
# Autenticar:
gh auth login

# Configurar secrets:
gh secret set VERCEL_TOKEN --repo Fibela/ASC
# (obtener de Vercel Dashboard → Settings → Tokens)

gh secret set CI_LEDGER_SECRET --repo Fibela/ASC
# (generar: python -c "import secrets; print(secrets.token_hex(32))")
```

---

## Rollback procedure

```bash
# Si el deploy tiene bug:
# Vercel Dashboard → asc-mono → Deployments → seleccionar deployment anterior → Promote to Production

# Si las migraciones rompen la DB:
# 1. PRIMERO: restaurar backup de Supabase (Dashboard → Database → Backups)
# 2. Revertir última migración:
alembic downgrade -1
# 3. Nuclear (solo emergencia):
alembic downgrade base
```

---

## Nota sobre rutas de health (Vercel vs Docker)

| Contexto | Ruta health | Notas |
|----------|-------------|-------|
| Vercel (producción) | `/api/v1/health/liveness` | FastAPI corre bajo `/api/...` |
| Docker / local | `/health` | FastAPI corre en raíz, `@app.get("/health")` |
| Vercel readiness | `/api/v1/health/readiness` | Incluye DB ping |

Ver `docs/go-live-runbook.md` para el proceso de observación post go-live.
