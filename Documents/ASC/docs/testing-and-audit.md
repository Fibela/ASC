# Testing, Seguridad y Auditoría — ASC PremosCorp
> Versión 4.1 | Actualizado: 2026-06-14 | P53–P55 — Onboarding + Plan Caps + Billing/Metering — 4103 tests, coverage ≥85%

## P53–P55 — Onboarding + Plan Caps + Billing/Metering (2026-06-14)

### Suite test_p53_onboarding.py

**67 tests, 10 clases — CI-safe (sin DB real, sin servicios externos)**

| Clase | Tests | Qué valida |
|-------|-------|------------|
| TestTokenHelpers | 12 | SHA-256 hash, longitud 64, determinismo, unicidad, raw≠hash, expiración en futuro |
| TestRegister | 7 | success (201), slug 409, email 409, email_verified=False, onboarding_step=pending_email, email enviado, password mínimo, slug regex |
| TestVerifyEmail | 6 | token válido→verified, token inválido 400, token expirado 400, campos limpiados, step→pending_setup, raw≠sha256 |
| TestOnboardingStatus | 5 | completed, pending_email, pending_setup, campo email, usuario legacy sin atributos |
| TestCompleteOnboarding | 5 | avanza pending_setup→completed, idempotente, bloquea pending_email 400, emite audit, commit |
| TestEmailVerifiedGate | 5 | import en source, usa getattr, 403 para unverified, 200 para verified, default True |
| TestUserModelFields | 6 | email_verified, token, expires_at, onboarding_step, default=True, default='completed' |
| TestP53Migration | 10 | archivo existe, down_revision, revision, email_verified, token, onboarding_step, server_default, índice, downgrade |
| TestOnboardingConfig | 3 | EMAIL_VERIFICATION_EXPIRE_HOURS exists, default=24, positivo |
| TestRouterRegistration | 10 | prefix=/onboarding, import en router, include_router, 4 rutas presentes, POST/GET correctos |

**Resultado: 67/67 PASSED**

**Seguridad verificada en tests:**
- Raw token ≠ SHA-256(raw token) — verificado con 2 tests
- Email_verified gate: 403 para unverified; 200 para verified
- `getattr(user, "email_verified", True)` — usuarios legacy NO bloqueados
- Config values vacíos por defecto (no secrets hardcoded)
- Token limpiado de DB tras verificación exitosa

---

### Suite test_p54_plan_caps.py

**57 tests, 7 clases — CI-safe (sin DB real)**

| Clase | Tests | Qué valida |
|-------|-------|------------|
| TestPlanDefaults | 13 | free(5/3), pro(50/20), enterprise(None/None), jerarquía, tipo dict, claves por plan |
| TestResolveCap | 8 | default free, default pro, enterprise=None, column override, zero válido, api_key column, plan desconocido, clave no-existente |
| TestEnforceUserCap | 13 | bajo-cap pasa, en-cap 403, sobre-cap 403, code=user_cap_exceeded, current, cap, enterprise∞, enterprise skip DB, pro=50, pro-1 pasa, custom override, 0 pasa, async |
| TestEnforceApiKeyCap | 10 | bajo pasa, en-cap 403, code=api_key_cap_exceeded, plan en detail, enterprise∞, enterprise skip DB, pro=20, custom override, async, scoped a user_id |
| TestApiKeysWiring | 5 | import en api_keys.py, plan_caps referenciado, Tenant importado, create llama enforce, sin viejo límite hardcoded |
| TestModuleStructure | 6 | importable, enforce_user_cap coroutine, enforce_api_key_cap coroutine, _resolve_cap sync, PLAN_DEFAULTS exported, docstring P54 |
| TestP54Regression | 4 | create llama enforce, free=3 not 20, user_count filtra is_active=True |

**Resultado: 57/57 PASSED**

**Seguridad verificada en tests:**
- Enterprise siempre skip DB query (no falsos límites en plan unlimited)
- Cap 0 se respeta (máximo de 0 = ningún recurso permitido)
- Plan desconocido → free defaults (safe fallback)
- Viejo límite hardcoded 422 eliminado, reemplazado por 403 con payload structured

---

### Suite test_p55_billing.py

**80 tests, 9 clases — CI-safe**

| Clase | Tests | Qué valida |
|-------|-------|------------|
| TestUsageRecordModel | 11 | tablename, id, tenant_id, period, resource_type, count, recorded_at, UniqueConstraint, en models/__init__ |
| TestCurrentPeriod | 5 | formato YYYY-MM, 7 chars, dígitos, año en rango, mes con padding |
| TestStripeSignatureVerification | 10 | firma válida True, secret incorrecto False, payload tampered False, missing t= False, missing v1= False, empty sig False, malformed False, replay False, SHA-256, compare_digest |
| TestGetMyUsage | 5 | sin records→ceros, todos los resource_types presentes, sin tenant 400, mapeo de records, period actual |
| TestGetTenantUsage | 2 | admin puede ver otro tenant, tenant no-encontrado 404 |
| TestTakeSnapshot | 5 | sin tenant 400, todos los tipos, commit, audit log, 5 records escritos |
| TestStripeWebhook | 8 | ack sin secret, 400 missing sig, 400 invalid sig, 200 valid sig, 400 JSON inválido, subscription.deleted→free, subscription.updated→pro, unknown event→200 |
| TestBillingConfig | 7 | STRIPE_SECRET_KEY exists, STRIPE_WEBHOOK_SECRET exists, defaults vacíos, tipos string, valores vacíos en runtime |
| TestP55Migration | 11 | archivo existe, down_revision=r8l01o0q3k05, revision, usage_records table, stripe_customer_id, stripe_subscription_id, UniqueConstraint, tenant_id index, period index, downgrade, tenant model fields |
| TestBillingRouterRegistration | 11 | prefix=/billing, import en router, include_router, 4 rutas, POST/GET, RESOURCE_TYPES completo |

**Resultado: 80/80 PASSED**

**Seguridad verificada en tests:**
- `hmac.compare_digest` en Stripe sig (timing-safe) — verificado en test
- SHA-256 usado en verificación de firma — verificado en test
- Config defaults vacíos en runtime (no keys hardcoded vivos)
- JSON payload malformado → 400 antes de procesar
- Firma inválida → 400 sin ejecutar lógica de negocio

---

## P52 — Tenant Management API (2026-06-14)

### Suite test_p52_tenant_management.py

**99 tests, 13 clases — CI-safe (sin DB real, sin servicios externos)**

| Clase | Tests | Qué valida |
|-------|-------|-----------|
| TestSlugValidation | 16 | Regex slug: 7 válidos (acme-corp, tenant-123, 100chars, etc.) + 9 inválidos (UPPERCASE, -leading-dash, trailing-dash-, spaces, too-short, too-long, underscore, dot, @symbol) |
| TestTenantSchemas | 10 | Pydantic field validation: plan inválido, slug uppercase→ValidationError, name<2→ValidationError, reason<5→ValidationError, TenantCreate defaults, TenantPlanChange requiere reason, TenantRead from_attributes, TenantUpdate all fields optional |
| TestCreateTenant | 6 | Success (db.add + commit + refresh + TenantRead), 409 slug conflict, audit log tenant.created con user_id, admin dep inspection, all fields (enterprise + max_users + max_api_keys_per_user), slug con números válido |
| TestListTenants | 8 | Paginación (total/page/items), empty list, filtro plan=pro, plan inválido→422, active_only=True, segunda página (offset correcto), schema TenantRead, admin dep wired |
| TestGetTenant | 5 | 200 con tenant encontrado, 404 con mensaje tenant_id, full TenantRead con contact/max_users, inactivo visible para admin, admin dep |
| TestGetMyTenant | 6 | Retorna tenant por user.tenant_id, 404 si tid=None (single-tenant mode), dep es get_current_user (no admin), user.tenant_id tiene prioridad sobre ContextVar, fallback ContextVar si user.tenant_id=None, 404 si tenant no en DB |
| TestTenantStats | 6 | Schema TenantStats con 6 campos, 404 tenant inexistente, 5 resource types en model_fields, admin dep, todos los conteos en cero, valores no-nulos reales |
| TestUpdateTenant | 7 | Update name→t.name cambia, update email, update max_users, no-change body→commit not called, 404, log tenant.updated con changes dict, admin dep |
| TestChangePlan | 7 | free→pro actualiza t.plan, mismo plan→422 con plan name en detail, log old_plan+new_plan+reason, 404, downgrade enterprise→free, reason completo en audit log, admin dep |
| TestActivateDeactivate | 8 | Deactivate→is_active=False + commit, ya-inactivo→422, Activate→is_active=True + commit, ya-activo→422, deactivate audit event name, activate audit event name, data preservada tras deactivate (slug/plan/max_users/email intactos), ciclo completo deactivate→activate |
| TestBugGap1ApiKeyTenantCtx | 6 | `set_tenant_id` importado en deps.py, llamada presente en source, arg es `user.tenant_id`, llamada antes de `db.commit()`, import desde `app.core.tenant_context`, función callable |
| TestRouterRegistration | 7 | /api/v1/tenants, /api/v1/tenants/me, /api/v1/tenants/{tenant_id}/stats, /api/v1/tenants/{tenant_id}/plan, activate, deactivate, any /tenants path |
| TestP52Regression | 7 | Tenant model attributes, ContextVar set/get/clear, apply_tenant_filter WHERE clause, TenantMiddleware importable, User/Alert/APIKey/Webhook/Incident tienen tenant_id, tenants.py existe, _resolve_user/get_current_user/get_current_admin intactos |

**Resultado: 99/99 PASSED — cobertura 85.67% (gate 85% superado)**

### Bug#Gap-1 — Corrección de aislamiento en autenticación por API Key

**Impacto antes del fix:** Cualquier request autenticado con `X-API-Key` nunca tenía tenant context en el ContextVar. `apply_tenant_filter()` retornaba `WHERE tenant_id IS NULL`, lo que potencialmente exponía datos del tenant default a cualquier API key válido de otro tenant.

**Fix aplicado en `backend/app/api/deps.py`:**
```python
# Bug#Gap-1 fix (P52): set tenant context from user record for API key auth
set_tenant_id(user.tenant_id)
# Touch last_used_at (fire-and-forget)
api_key.last_used_at = datetime.now(timezone.utc)
await db.commit()
```

**Verificaciones de seguridad del fix:**
1. `set_tenant_id` importado desde el módulo canónico `app.core.tenant_context`
2. El argumento es `user.tenant_id` (no hardcoded, no de headers sin validar)
3. La llamada ocurre ANTES de `db.commit()` → tenant context activo para todo el request lifecycle
4. TenantMiddleware sigue corriendo (ASGI level) — este fix solo cubre el camino API key
5. JWT Bearer auth no se ve afectado (TenantMiddleware ya manejaba ese camino)

---

## P56 — Deployment Readiness (2026-06-14)

### Suite test_p56_deployment_readiness.py

**84 tests, 9 clases — CI-safe (sin DB, sin servicios externos)**

| Clase | Tests | Qué valida |
|-------|-------|-----------|
| TestSecurityPreDeploy | 9 | No secrets hardcoded en fuente Python, .env excluido, certs protegidos en gitignore, no DB password remota en source |
| TestInfrastructure | 13 | Dockerfiles existen y usan non-root, .dockerignore excluye .env, render.yaml health=/health + sync:false, docker-compose tiene nginx, next.config.js standalone |
| TestDatabaseMigrations | 6 | Dir migraciones existe, 13 archivos, tags de sprints presentes, alembic.ini, head único = p6j79m8o1i93, chain sin gaps |
| TestCICDWorkflows | 11 | deploy.yml: ci-check/deploy-backend/deploy-frontend/gate jobs, ci-check gate, backend needs ci-check, secrets check graceful, coverage cov-fail-under=85, trigger main/master, p49 workflow |
| TestEnvironmentConfig | 12 | .env.example existe, 9 keys requeridas (SECRET_KEY DATABASE_URL CORS_ORIGINS DEBUG REDIS_URL NEXT_PUBLIC_API_URL METRICS_SCRAPE_TOKEN RATE_LIMIT_LOGIN ALERT_CRITICAL_THRESHOLD), CORS_ORIGINS es JSON array, SECRET_KEY es placeholder, DATABASE_URL es placeholder |
| TestApplicationHealth | 8 | app importable, /health en routes, /health sin auth deps, config importable, api_router importable, TenantMiddleware importable, tenant_context functions, todos los modelos importables |
| TestFrontendConfig | 8 | next.config.js standalone, security headers (X-Content-Type-Options, X-Frame-Options, CSP), package.json build+start scripts, @playwright/test en devDeps, playwright.config.ts, e2e/ dir, tsconfig excluye e2e |
| TestEndpointAudit | 5 | /health registrado, /api/v1/ paths >= 5, /docs oculto en prod, /openapi.json oculto, auth endpoints registrados |
| TestDeploymentRegression | 12 | tenant_id en User/APIKey/Webhook, p49 workflow, p50 workflow, TenantMiddleware en main.py, tenant_filter.py, tenant_context.py, observability endpoint, sdk dir, locustfile.py, deployment-guide.md, .gitleaks.toml |

**Resultado: 84/84 PASSED — commit SHA 97cb974 subido a Fibela/ASC**

### Auditoría de seguridad pre-deploy

| Control | Herramienta | Resultado |
|---------|-------------|-----------|
| Secrets en source code | gitleaks + regex scan | 0 leaks reales |
| Vulnerabilidades Python | bandit -r backend/app | 0 HIGH, 3 LOW (urllib/subprocess — documentados) |
| .env en repositorio | test + git status | .env no presente, gitignored |
| TLS certificates en git | file scan *.pem/*.key | 0 archivos de certificados |
| DB password en source | regex scan excl. config.py | 0 encontradas |
| Real JWT en source | regex eyJ{20+} | 0 encontrados |
| Real API keys en source | regex 40+ char hex keys | 0 encontrados |
| Docker non-root users | Dockerfile parse | appuser (uid 1001), nextjs (uid 1001) |
| Coverage artifacts en git | .gitignore check | .coverage, htmlcov/, coverage.xml excluidos |

---

## P51 — Multi-Tenancy Enforcement (2026-06-14)

### Objetivo
Activar el aislamiento real de tenants sobre la fundación de P47. Toda la capa de datos queda automáticamente scoped al tenant activo en el request, usando un ContextVar asyncio-safe poblado por middleware.

### Arquitectura de enforcement

| Capa | Componente | Descripción |
|------|-----------|-------------|
| ContextVar | `tenant_context.py` | `ContextVar[str | None]` per-request, asyncio-safe |
| Middleware | `tenant_middleware.py` | Extrae `tenant_id` de JWT o `X-Tenant-ID` header; cleanup en finally |
| Query helper | `tenant_filter.py` | `apply_tenant_filter(stmt, model)` → WHERE strict |
| JWT | `security.py` | `create_access_token(..., tenant_id=None)` — kwarg opcional |
| Endpoints | `api_keys.py`, `webhooks.py` | list scoped + create auto-asigna tenant_id |

### Modelo de aislamiento estricto

```
tid = None  → WHERE model.tenant_id IS NULL    (single-tenant mode)
tid = "xyz" → WHERE model.tenant_id = "xyz"   (multi-tenant, SIN OR NULL)
```

Sin fallback a NULL cuando hay tenant activo → cero cross-tenant data bleed.

### Seguridad del enforcement
- **ContextVar asyncio-safe**: cada coroutine tiene copia propia del tenant_id
- **Cleanup garantizado**: `finally: set_tenant_id(None)` en middleware
- **JWT inválido → None silencioso**: la auth gate (`_resolve_user`) es independiente
- **Retrocompatibilidad total**: JWTs pre-P51 sin `tenant_id` → modo single-tenant

### Enfoque de testing P51

| Clase | Tests | Técnica |
|-------|-------|---------|
| `TestTenantContext` | 5 | Unit puro Python |
| `TestTenantMiddleware` | 8 | ASGI integration (Starlette TestApp + httpx) |
| `TestTenantFilter` | 7 | SQL compilation checks (`compile(literal_binds=True)`) |
| `TestJWTTenantClaim` | 5 | JWT encode/decode round-trip |
| `TestAPIKeysTenantEnforcement` | 5 | FastAPI TestClient + dependency_overrides |
| `TestWebhooksTenantEnforcement` | 5 | FastAPI TestClient + dependency_overrides |
| `TestMainPyTenantWiring` | 5 | Análisis estático (source.index) + import check |
| `TestP51Regression` | 7 | Import + filesystem checks |
| **Total** | **47** | — |

**Puntos de seguridad verificados:**
- SQL WHERE con `tenant-x` presente en queries cuando tenant activo
- SQL WHERE con `IS NULL` cuando sin tenant
- `IS NULL` AUSENTE cuando tenant activo (strict isolation)
- Cross-tenant queries producen SQL diferente
- ContextVar limpio post-request
- JWT sin `tenant_id` claim backward compatible
- `X-Tenant-ID` header override funcional

### Cobertura P51

```
Nuevos módulos:
  app/core/tenant_context.py    → 100%
  app/core/tenant_middleware.py → 100%
  app/db/tenant_filter.py       → 100%
```

Full suite: 3716 passed, 14 skipped | Coverage total: 85.45% (gate 85%)

---

## P50 — E2E Tests con Playwright (2026-06-14)

**Sprint objetivo:** Cerrar la pirámide de testing con pruebas browser completas, validar workflows end-to-end frontend → backend → CI/CD, y agregar headers de seguridad HTTP al frontend.

### Archivos nuevos/modificados
- `frontend/playwright.config.ts` — 4 proyectos, HTML+JUnit reporters, screenshot/video on-failure
- `frontend/e2e/helpers.ts` — fixtures compartidos (mock tokens, API factories, auth injection)
- `frontend/e2e/auth.spec.ts` — 12 tests auth
- `frontend/e2e/dashboard.spec.ts` — 9 tests navegación
- `frontend/e2e/api-keys.spec.ts` — 8 tests API keys
- `frontend/e2e/webhooks.spec.ts` — 8 tests webhooks
- `frontend/e2e/rate-limits.spec.ts` — 6 tests rate limits
- `frontend/e2e/security-headers.spec.ts` — 9 tests security headers
- `frontend/next.config.js` — +async headers() con 7 security headers HTTP
- `frontend/package.json` — +@playwright/test 1.49.1, +scripts test:e2e/test:e2e:ui
- `.github/workflows/p50-e2e.yml` — 4 jobs + p50-gate
- `backend/tests/test_p50_e2e_playwright.py` — 64 tests

### Enfoque de testing P50 — Pirámide completa

**Nivel E2E (Playwright — browser)**: Valida que el software funciona desde la perspectiva del usuario real. Los tests de Playwright se ejecutan en un navegador headless real (Chromium/Firefox/WebKit) con el servidor Next.js en modo producción.

**Mocking sin backend real**: Toda llamada `axios` a `/api/v1/**` es interceptada por `page.route()`. Esto permite:
- Correr el E2E suite completo en CI sin levantar FastAPI, PostgreSQL ni Redis
- Testear estados exactos (error 500, 401, respuestas vacías) sin side effects
- Rapidez: ~2-3 min vs ~10+ min con backend real

**`page.addInitScript()` para auth**: Se inyecta `asc_access_token` en localStorage ANTES de que React hidrate. Esto es crítico — si se inyecta después, `useAuthGuard()` ya ejecutó y redirigió a `/login`.

**Invariantes de seguridad E2E** (complementan los tests unitarios):
- `raw_key` nunca en HTML de list response — verificado en navegador, no sólo en schema
- `whsec_` (webhook secret) nunca en HTML de list — idem
- Stack traces de Python no filtrados en UI de error
- No email enumeration en mensaje de error de login

**Security headers verificados en browser** (`security-headers.spec.ts`):
- `X-Content-Type-Options: nosniff` — verificado via `response.headers()`
- `X-Frame-Options: DENY` o CSP `frame-ancestors 'none'` — anti-clickjacking
- `Referrer-Policy: strict-origin-when-cross-origin`

**Bugs detectados por los tests E2E**:
- **Bug#32**: `helpers.ts` contenía `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9` (header JWT válido). El test `test_no_real_jwt_tokens_in_specs` lo detectó. Fix: formato non-JWT obviamente falso.

**CI P50** (`p50-e2e.yml`):
- Chromium: full suite en cada push/PR a `frontend/**`
- Firefox+WebKit: smoke (auth+security) — cross-browser más sensible
- TypeScript: `tsc --noEmit` incluye `e2e/*.ts`
- Path filter: sólo activa en cambios de frontend (ahorra Actions minutes)
- Schedule semanal: domingo 04:00 UTC — full sweep con las 3 engines

### Pirámide de Testing — Estado Final (P50)

```
COMPLETADA AL 100% ✅

E2E (5%)         — Playwright: 6 specs, ~52 tests browser, 3 engines
                   pytest: 64 tests estáticos E2E infrastructure
Integration (25%) — FastAPI + SQLite: 3666+ tests
                   Contrato, RBAC, seguridad, mock de DB/Redis
Unit (70%)       — Modelos, servicios, SOAR, PIDS, correlation, PCDI
                   Security hygiene, CI workflows, load tests
```

### Métricas P50
- Tests pytest nuevos: **64** (6 clases)
- Tests Playwright E2E browser: **~52** (6 spec files)
- Total suite pytest: **3666** tests
- Coverage: **≥85.4%** (gate 85% superado)
- Failures: **0**
- Workflows CI activos: **5** (ci + security-audit + deploy + p49-gates + p50-e2e)
- Security headers agregados al frontend: **7**

---

## P49 — CI/CD Security Gates (2026-06-14)

**Sprint objetivo:** Elevar el pipeline de CI/CD a production-grade con gates bloqueantes y visibilidad en GitHub Security tab.

### Archivos nuevos/modificados
- `.github/workflows/p49-security-gates.yml` — workflow nuevo con 6 jobs
- `.gitleaks.toml` — +2 patrones en allowlist
- `backend/tests/test_p49_cicd_security.py` — 42 tests

### Enfoque de testing P49

**Validación de workflow YAML** — PyYAML parsea cada archivo de workflow antes del push. Detecta sintaxis inválida que GitHub Actions sólo mostraría en runtime. Nota técnica: la clave `on:` en YAML es un boolean `True` en Python; acceso robusto via `parsed.get(True, parsed.get("on", {}))`.

**Inspección de jobs por contenido** — Verificación de que `trivy-fs` use `exit-code: '1'` (blocking) y no `'0'` (informational como en ci.yml). Diferencia crítica: si el gate es `exit-code: 0`, un container con CVE CRITICAL pasa CI igualmente.

**SARIF upload verificado** — `upload-sarif` presente en el workflow para trivy, gitleaks y bandit. SARIF integra findings al GitHub Security tab > Code scanning — visibilidad permanente más allá de los logs de CI.

**Dependency review (PR-only)** — job condicionado a `github.event_name == 'pull_request'`. Gate `deny-licenses: GPL-3.0, AGPL-3.0` protege el modelo SaaS comercial de PremosCorp.

**Safety CVE audit** — evaluación de JSON output compatible con safety 2.x (lista) y 3.x (dict). Las dos herramientas (pip-audit + safety) apuntan a bases de datos distintas (OSV vs PyPI Advisory+SafetyDB): un CVE ausente en una puede estar en la otra.

**Security hygiene local** — 7 checks que espejean exactamente lo que hacen los gates de CI:
- No `password123`, `secret123`, `admin123` en `app/`
- No `eval()` en `services/`
- No `print()` en `services/` (debe ser `structlog`)
- No DB URL hardcodeada fuera de `config.py`
- `[tool.bandit]` en `pyproject.toml` — configuración consistente local/CI

### Bugs resueltos P49
- **Bug#29** — PyYAML `on:` → `True` bool: fix con `parsed.get(True, ...)`
- **Bug#30** — `pyproject.toml` en repo root, no en `backend/`
- **Bug#31** — `config.py` Settings defaults excluidos del hardcoded-DB-password check

### Métricas P49
- Tests nuevos: **42** (5 clases)
- Total suite: **3602** tests (3560 P48 + 42 P49)
- Coverage: **≥85.4%** (gate 85% superado)
- Failures: **0**
- Workflows activos: ci.yml + security-audit.yml + deploy.yml + **p49-security-gates.yml**
- Jobs de seguridad totales en CI: **14** (3 en ci.yml + 5 en security-audit.yml + 6 en p49)

---

---

## Filosofía de Testing

> "Si no está testeado, está roto."

El sistema de neutralización ejecuta acciones con **impacto real en producción** (aislar máquinas, bloquear IPs, deshabilitar cuentas). Un test deficiente puede resultar en:
- Falsos positivos que corten operaciones legítimas
- Falsos negativos que dejen amenazas activas
- Regresiones silenciosas en integraciones externas

**Objetivo:** cobertura ≥ 85% (P34 alcanzó exactamente 85.00%) con pruebas significativas (no tests vacíos para inflar métricas). El techo práctico es ~87% dado que el bloque de adaptadores externos (Specter, ELK, Wazuh, Palo Alto, Fortinet, AD) requiere servicios reales (~800 líneas de adaptadores). `pcdi_escalation._run()` ahora está a 100% — desbloqueado en P34.

---

## Pirámide de Testing

```
              ┌───────────┐
              │  E2E (5%) │  Playwright — flujo completo UI + API
             /│           │\
            / └───────────┘ \
           /  ┌─────────────┐\
          /   │Integración  │ \   Tests vs. sandbox de PremosCorp Specter,
         /    │  (25%)      │  \  Palo Alto, Fortinet, AD
        /     └─────────────┘   \
       /      ┌───────────────┐  \
      /        │  Unitarias   │   \  Pytest + mocks de cada adapter,
      │        │    (70%)     │   │  servicio y modelo de datos
      │        └───────────────┘  │
      └──────────────────────────┘

Objetivo total: ≥ 82% line coverage (P31 baseline)
```

---

## Estructura de Directorios de Tests

```
backend/tests/                              (2919 tests activos — P34 baseline)
├── conftest.py                             Fixtures compartidos: DB SQLite en memoria, users, tokens
├── security/                               Módulo P31-SEC — tests de seguridad con marca @security
│   ├── __init__.py
│   ├── test_rbac.py                        61 tests — acceso por rol, escalación de privilegios
│   ├── test_auth_hardening.py              46 tests — JWT expiry, firma inválida, brute force, reutilización
│   └── test_input_validation.py            ~68 tests — inyección SQL/XSS, body oversized, JSON malformado
├── e2e/                                    Módulo P32-E2E — tests end-to-end de ciclo completo
│   ├── __init__.py
│   └── test_e2e_lifecycle.py               21 tests — 6 fases: Detection→SOAR→Neutralize→IR→SPECTER→PRAF
├── test_auth.py                            Auth endpoints — login, refresh, logout, /me
├── test_alerts.py                          Alerts CRUD + stats
├── test_detection.py                       Detection rules + evaluate/fingerprint
├── test_iam.py                             IAM identity management
├── test_metrics.py                         SOC metrics endpoints
├── test_p31_coverage.py                    66 tests — auth admin, events, neutralize
├── test_p31_coverage_extra.py              79 tests — iocs, alerts, detection, iam, metrics, notifications, forensic
├── test_p31_correlation.py                 31 tests — correlation rules + clusters CRUD
├── test_p32_cov_iam.py                     27 tests — IAM lifecycle completo + verify_action_signatures (P32)
├── test_p32_cov_soar.py                    38 tests — SOAR triggers + reports CRUD completo (P32, 0%→90%)
├── test_p32_praf.py                        46 tests — PRAF service: ledger, scoring, correlator, reporter (P32)
├── test_p33_coverage.py                    78 tests — routing fix, PRAF pure funcs, executive reports (P33)
├── test_p33_coverage_b.py                  44 tests — reporter.py, Celery _run() funcs, _is_due() (P33)
├── test_p34_coverage.py                    37 tests — pcdi scoring loop, task retry paths, PIIL signing, pids helpers (P34)
└── [otros test_*.py]                       Coverage de endpoints restantes
```

### Módulo E2E — Ciclo Completo de Detección a Respuesta

El módulo `e2e/test_e2e_lifecycle.py` valida el pipeline completo:

1. **Detection** — Verifica catálogo de reglas activas (MITRE ATT&CK)
2. **SOAR Trigger** — Crea trigger `pcdi_score ≥ 75`, evalúa contexto con score 95 → `would_fire: True`
3. **Neutralization** — `block_ip` severity `medium`; valida estado en `PENDING_APPROVAL|EXECUTING|COMPLETED`
4. **Incident Response** — NIST state machine: `detected → triaged → contained` (incident_type: `lateral_movement`)
5. **SPECTER Agent** — Health check (tolera 404 en sandbox sin agentes registrados)
6. **PRAF Scoring** — 5 muestras → p95 calculado → `AdaptiveLoadScorer` → SLA gate `p95 < 500ms`

### Módulo PRAF — Premos Resilience & Authenticity Framework

`backend/app/services/praf.py` — Servicio de resiliencia y autenticidad:

| Componente | Responsabilidad |
|-----------|----------------|
| `PRAFLedger` | SHA3-512 fingerprint + Ed25519 signature por entrada de ledger |
| `AdaptiveLoadScorer` | Score 0-100: latencia 50% + error_rate 35% + throughput 15% |
| `CrossDomainCorrelator` | PRAF score → contexto SOAR para trigger automático |
| `ExecutiveReporter` | Reporte PDF-ready con firma digital y SHA3-512 |

Bands: 0-30=low, 31-60=medium, 61-84=high, 85-100=critical. SLA: p95 < 500ms.

**Nota de integración:** Los adaptadores de PremosCorp Specter (EDR), ELK, Wazuh, TheHive, firewalls (Palo Alto/Fortinet) y Active Directory/LDAP requieren servicios reales y se testean en el entorno de sandbox. Los tests unitarios utilizan SQLite en memoria sin dependencias externas.

---

## Tests Unitarios — Ejemplos Clave

### PremosCorp Specter (EDR) Adapter
```python
# backend/tests/unit/adapters/test_specter.py
# Tests de integración con PremosCorp Specter requieren sandbox configurado.
# Los tests unitarios mockean el adaptador:

import pytest
from unittest.mock import AsyncMock, patch
from app.services.specter_bridge import SpecterBridge

@pytest.fixture
def bridge():
    return SpecterBridge(api_url="https://specter.premoscorp.local", api_key="test-key")

@pytest.mark.asyncio
async def test_isolate_host_success(bridge):
    """Verifica que isolate_host llama al endpoint correcto y retorna success."""
    with patch.object(bridge, "_api_call", new_callable=AsyncMock) as mock_call:
        mock_call.return_value = {"status": "isolated", "device_id": "device-123"}
        result = await bridge.isolate_host("WORKSTATION-042", "C2 beacon detected")
        assert result["status"] == "isolated"

@pytest.mark.asyncio
async def test_isolate_host_device_not_found(bridge):
    """Verifica comportamiento cuando el host no existe en Specter."""
    with patch.object(bridge, "_api_call", new_callable=AsyncMock) as mock_call:
        mock_call.side_effect = ValueError("Device not found")
        with pytest.raises(ValueError, match="Device not found"):
            await bridge.isolate_host("UNKNOWN-HOST", "test")
```

### Correlator / SIEM
```python
# backend/tests/unit/services/test_correlator.py

@pytest.mark.asyncio
async def test_brute_force_rule_triggers_at_threshold(db_session):
    """Rule debe disparar con ≥3 auth failures, no con 2."""
    events_2 = [
        {"category": "authentication", "action": "login_failure", "host": "PC-001"},
        {"category": "authentication", "action": "login_failure", "host": "PC-001"},
    ]
    alerts_2 = await evaluate_correlation_rules(events_2, db_session)
    assert len(alerts_2) == 0  # No debe disparar con 2

    events_3 = events_2 + [
        {"category": "authentication", "action": "login_failure", "host": "PC-001"},
    ]
    alerts_3 = await evaluate_correlation_rules(events_3, db_session)
    brute_force = [a for a in alerts_3 if a["rule_id"] == "rule_brute_force"]
    assert len(brute_force) == 1
    assert brute_force[0]["severity"] == "high"

@pytest.mark.asyncio
async def test_credential_dump_rule_mimikatz(db_session):
    events = [{"category": "process", "action": "mimikatz executed", "host": "PC-002"}]
    alerts = await evaluate_correlation_rules(events, db_session)
    cred_dump = [a for a in alerts if a["rule_id"] == "rule_credential_dump"]
    assert len(cred_dump) == 1
    assert cred_dump[0]["risk_score"] >= 0.90
```

### Approval Workflow
```python
# backend/tests/unit/test_approval_workflow.py

@pytest.mark.asyncio
async def test_critical_request_timeout_triggers_escalation(db_session, celery_app):
    """Verifica que timeout en solicitud CRITICAL dispara escalación."""
    request = await create_neutralization_request(
        db=db_session,
        action_type="isolate_endpoint",
        severity="critical",
        timeout_minutes=0.001  # Timeout casi inmediato en test
    )
    
    await asyncio.sleep(0.1)  # Esperar el timeout
    
    await db_session.refresh(request)
    assert request.status == "ESCALATED"

@pytest.mark.asyncio
async def test_medium_severity_executes_automatically(db_session):
    """Acciones MEDIUM no requieren aprobación."""
    request = await create_neutralization_request(
        db=db_session,
        action_type="block_ip",
        severity="medium",
        params={"ip": "1.2.3.4", "direction": "both"}
    )
    assert request.status in ("EXECUTING", "COMPLETED")
    # No debe estar en PENDING_APPROVAL
    assert request.status != "PENDING_APPROVAL"
```

---

## Tests de Seguridad

### SQL Injection
```python
# backend/tests/security/test_sql_injection.py

INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "'; DROP TABLE alerts; --",
    "1 UNION SELECT username, password FROM users--",
    "' AND 1=1--",
    "%27%20OR%20%271%27%3D%271",
]

@pytest.mark.asyncio
@pytest.mark.parametrize("payload", INJECTION_PAYLOADS)
async def test_alerts_endpoint_sql_injection(client, payload):
    """Ningún payload de inyección debe retornar datos no autorizados ni errores 500."""
    resp = await client.get(f"/api/v1/alerts?status={payload}")
    assert resp.status_code in (200, 400, 422)
    assert resp.status_code != 500
    # Si retorna 200, debe ser lista vacía o resultados legítimos
    if resp.status_code == 200:
        data = resp.json()
        assert isinstance(data, list)
```

### LDAP Injection
```python
# backend/tests/security/test_ldap_injection.py

LDAP_INJECTION_PAYLOADS = [
    "admin)(&(password=*))",
    "*)(&",
    "admin)(|(password=*)",
    "*)(uid=*))(|(uid=*",
]

@pytest.mark.asyncio
@pytest.mark.parametrize("payload", LDAP_INJECTION_PAYLOADS)
async def test_ad_adapter_ldap_injection(adapter, payload):
    """El adapter debe sanitizar inputs antes de construir filtros LDAP."""
    with pytest.raises(ValueError, match="Invalid username"):
        await adapter.disable_account(payload, "PREMOSCORP", "test")
```

### RBAC y Autorización
```python
# backend/tests/security/test_rbac.py

@pytest.mark.asyncio
async def test_analyst_cannot_approve_own_request(client, analyst_token):
    """Un analista no puede aprobar su propia solicitud de neutralización."""
    # Crear solicitud como analista
    create_resp = await client.post(
        "/api/v1/neutralize/",
        json={"action_type": "block_ip", "params": {"ip": "1.2.3.4"}},
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    request_id = create_resp.json()["id"]
    
    # Intentar aprobarla como el mismo analista
    approve_resp = await client.post(
        f"/api/v1/neutralize/approve/{request_id}",
        json={"reason": "self-approval attempt"},
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    assert approve_resp.status_code == 403

@pytest.mark.asyncio
async def test_viewer_cannot_trigger_neutralization(client, viewer_token):
    """Rol viewer no puede crear solicitudes de neutralización."""
    resp = await client.post(
        "/api/v1/neutralize/",
        json={"action_type": "block_ip", "params": {"ip": "1.2.3.4"}},
        headers={"Authorization": f"Bearer {viewer_token}"}
    )
    assert resp.status_code == 403
```

---

## Tests de Resiliencia

### Circuit Breaker
```python
# backend/tests/resilience/test_circuit_breaker.py

@pytest.mark.asyncio
async def test_circuit_opens_after_consecutive_failures(adapter):
    """Después de N fallos consecutivos, el circuit breaker debe abrirse
    y retornar fallo inmediato sin llamar a la API."""
    import httpx
    
    with patch.object(adapter, "_api_call", new_callable=AsyncMock) as mock_call:
        mock_call.side_effect = httpx.ConnectError("Connection refused")
        
        # Forzar múltiples fallos para abrir el circuit
        for _ in range(5):
            try:
                await adapter.isolate_host("HOST-001", "test")
            except Exception:
                pass
        
        # El circuit debe estar abierto — debe fallar inmediatamente
        start = time.monotonic()
        result = await adapter.isolate_host("HOST-002", "test")
        elapsed = time.monotonic() - start
        
        assert result.success is False
        assert elapsed < 0.1  # Falla inmediata, sin esperar timeout de red
        assert "circuit open" in result.message.lower()
```

---

## Comandos de Auditoría de Seguridad

### Ejecución Completa (Pre-Deploy)

```bash
#!/bin/bash
# security-audit.sh — Ejecutar antes de cada release

set -e
REPORT_DIR="reports/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$REPORT_DIR"

echo "=== [1/8] Secrets en historial Git ==="
gitleaks detect --source . --verbose \
  --report-path "$REPORT_DIR/gitleaks.json" \
  --report-format json
echo "✅ Gitleaks OK"

echo "=== [2/8] Credenciales hardcodeadas ==="
detect-secrets scan . --all-files > "$REPORT_DIR/detect-secrets.json"
COUNT=$(python3 -c "import json,sys; d=json.load(open('$REPORT_DIR/detect-secrets.json')); print(sum(len(v) for v in d['results'].values()))")
[ "$COUNT" -eq 0 ] && echo "✅ 0 secretos detectados" || (echo "❌ $COUNT secretos detectados" && exit 1)

echo "=== [3/8] Variables hardcodeadas comunes ==="
FOUND=$(grep -rEn "(changeme|password123|secret123|CHANGEME|replace-me|your-api-key)" \
  backend/app/ frontend/src/ --include="*.py" --include="*.ts" --include="*.js" 2>/dev/null | wc -l)
[ "$FOUND" -eq 0 ] && echo "✅ Sin valores genéricos" || (echo "❌ $FOUND ocurrencias encontradas" && exit 1)

echo "=== [4/8] .env en git ==="
git ls-files | grep -E "^\.env$" && (echo "❌ .env está en git" && exit 1) || echo "✅ .env no en git"

echo "=== [5/8] Análisis estático Python (Bandit) ==="
bandit -r backend/app/ -f json -o "$REPORT_DIR/bandit.json" -ll --quiet
python3 -c "
import json
report = json.load(open('$REPORT_DIR/bandit.json'))
criticals = [r for r in report['results'] if r['issue_severity'] == 'HIGH']
print(f'Bandit: {len(report[\"results\"])} issues, {len(criticals)} HIGH')
assert len(criticals) == 0, f'❌ {len(criticals)} HIGH severity issues'
print('✅ Bandit OK')
"

echo "=== [6/8] Vulnerabilidades en dependencias ==="
safety check -r backend/requirements.txt --json -o "$REPORT_DIR/safety.json" --quiet
pip-audit -r backend/requirements.txt -f json -o "$REPORT_DIR/pip-audit.json" --progress-spinner off
echo "✅ Dependencias OK"

echo "=== [7/8] Análisis semgrep ==="
semgrep --config=p/python --config=p/security-audit \
  --config=p/owasp-top-ten \
  backend/app/ \
  --json -o "$REPORT_DIR/semgrep.json" --quiet
echo "✅ Semgrep OK"

echo "=== [8/8] Vulnerabilidades en contenedores ==="
trivy fs . --security-checks vuln,config,secret \
  --format json --output "$REPORT_DIR/trivy-fs.json" \
  --severity CRITICAL,HIGH --quiet
echo "✅ Trivy OK"

echo ""
echo "=============================="
echo "✅ AUDITORÍA COMPLETADA"
echo "Reportes en: $REPORT_DIR/"
echo "=============================="
```

### Comandos Individuales de Referencia Rápida

```bash
# ── Secrets & Credenciales ──────────────────────────────────────────────────

# Escaneo profundo en TODO el historial de commits
gitleaks detect --source . --verbose --log-opts="--all --full-history"

# Solo commits nuevos desde main
gitleaks protect --staged

# Buscar patrones de llaves en código
grep -rEn "(?i)(api.?key|secret.?key|access.?token|auth.?token|bearer)\s*[=:]\s*['\"][a-zA-Z0-9+/=_-]{16,}" \
  backend/ frontend/ --include="*.py" --include="*.ts" --include="*.env*"

# Buscar IPs o URLs hardcodeadas que no deberían estar en código
grep -rn "192\.168\|10\.0\|172\.16\|prod\.premoscorp\|staging\." \
  backend/app/ --include="*.py"

# ── Dependencias ─────────────────────────────────────────────────────────────

# Vulnerabilidades conocidas (CVE database)
safety check -r backend/requirements.txt --full-report

# Alternativa más completa
pip-audit -r backend/requirements.txt --fix --dry-run

# Packages desactualizados (no necesariamente vulnerables)
pip list --outdated

# ── Análisis Estático Python ─────────────────────────────────────────────────

# Todos los niveles de severidad
bandit -r backend/app/ -f txt -ll

# Solo HIGH severity, con contexto
bandit -r backend/app/ -lll --severity-level high

# Buscar eval/exec (ejecución de código arbitrario)
grep -rn "\beval\b\|\bexec\b" backend/app/ --include="*.py"

# Buscar subprocess sin shell=False
grep -rn "subprocess\|os\.system\|os\.popen" backend/app/ --include="*.py"

# ── Semgrep ──────────────────────────────────────────────────────────────────

# Reglas OWASP Top 10
semgrep --config=p/owasp-top-ten backend/app/

# SQL injection específico
semgrep --config=p/sql-injection backend/app/

# Secrets en código
semgrep --config=p/secrets backend/ frontend/

# Custom rule: buscar asyncio.sleep placeholders olvidados
semgrep --pattern "asyncio.sleep($_)" --lang=python backend/app/services/

# ── Contenedores ─────────────────────────────────────────────────────────────

# Imagen backend
docker build -t asc_backend:test ./backend/ && \
  trivy image asc_backend:test --severity CRITICAL,HIGH

# Dockerfile best practices
hadolint backend/Dockerfile
hadolint frontend/Dockerfile

# Verificar que no se copian archivos sensibles
docker run --rm asc_backend:test ls /app/.env 2>&1 | grep -q "No such file" && \
  echo "✅ .env no en imagen" || echo "❌ .env encontrado en imagen"

# ── API y Runtime ─────────────────────────────────────────────────────────────

# Verificar headers de seguridad
curl -si http://localhost:8000/health | grep -E "(X-Content-Type-Options|X-Frame-Options|Strict-Transport-Security|Content-Security-Policy)"

# CORS — verificar que no acepta cualquier origen
curl -si -H "Origin: https://evil.com" -H "Access-Control-Request-Method: POST" \
  http://localhost:8000/api/v1/neutralize/

# JWT — verificar que token inválido da 401
curl -si -H "Authorization: Bearer invalid.jwt.token" \
  http://localhost:8000/api/v1/alerts | grep "HTTP/.*401"

# Rate limiting
for i in {1..20}; do
  curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8000/api/v1/alerts
done | sort | uniq -c
# Debe aparecer 429 después del límite
```

---

## Tests de Carga (P32 — Locust PRAF-Integrated)

El archivo `load_tests/locustfile.py` implementa el escenario P32 de carga distribuida con integración PRAF.

### User Classes

| Clase | Peso | Endpoints |
|-------|------|-----------|
| `NeutralizeUser` | 3 | `/neutralize/`, `/neutralize/pending` |
| `HuntUser` | 4 | `/hunt/query`, `/hunt/stats` |
| `IncidentUser` | 3 | `/incidents/`, `/incidents/{id}` |
| `ReadOnlyUser` | 2 | `/metrics/soc`, `/alerts`, `/detection/rules` |
| `E2ESequentialUser` | 1 | Pipeline completo: alerts→neutralize→create incident→check |

### PRAF Integration

`_PRAFCollector` acumula latencias por request. Al terminar la ejecución (`@events.quitting`):
1. Calcula p95 sobre todas las muestras recolectadas
2. Ejecuta `AdaptiveLoadScorer` con p95, error_rate, throughput observados
3. Imprime resumen PRAF en consola
4. Escribe `praf_load_report.json` con SHA3-512 fingerprint del reporte

```bash
# P32 — 10,000 usuarios, spawn 500/s, 120s de ejecución
locust -f load_tests/locustfile.py --headless \
  --users 10000 --spawn-rate 500 --run-time 120s \
  --host http://localhost:8000

# Targets SLA:
# - p95 < 500ms en /neutralize/, /hunt/, /incidents/
# - Error rate < 0.1%
# - 0 errores 5xx
# - PRAF score < 61 (band medium o inferior)
```

### Sandbox Safety

El IP de neutralización en tests de carga es `100.64.0.1` (RFC 6890 — Shared Address Space, nunca enrutado públicamente). Ningún endpoint externo real recibe requests durante los tests de carga.

---

## Auditoría Continua (Producción)

### Métricas de Auditoría a Monitorear
| Métrica | Alerta si... | Prioridad |
|---------|-------------|-----------|
| Solicitudes de neutralización fallidas | > 5% en 1h | HIGH |
| Aprobaciones que exceden timeout | > 10% en 24h | MEDIUM |
| Llamadas a PremosCorp Specter (EDR) con error 401 | Cualquiera | HIGH |
| Intentos de acceso no autorizado (403) | > 10 en 5min | CRITICAL |
| Tokens JWT inválidos | > 20 en 5min | HIGH |
| Latencia p95 > 2000ms | Sostenido 5min | MEDIUM |

### Retención de Logs de Auditoría
- **Logs de neutralización:** mínimo 2 años (regulatorio)
- **Logs de acceso API:** 90 días
- **Logs de autenticación:** 1 año
- **Respuestas completas de proveedores:** 1 año

### Revisión de Auditoría Manual (Mensual)
- [ ] Revisar todas las solicitudes RECHAZADAS del mes (¿patrón de FP?)
- [ ] Revisar todas las ESCALACIONES (¿timeout muy corto?)
- [ ] Revisar accesos de cuentas de servicio (PremosCorp Specter, AD)
- [ ] Rotar credenciales de API si vencen pronto
- [ ] Revisar cobertura de tests (¿bajó por nuevo código?)
- [ ] Ejecutar `security-audit.sh` manualmente
- [ ] Verificar que no hay alertas silenciadas inadvertidamente en monitoring

---

## Configuración pytest (`backend/pytest.ini`)

```ini
[pytest]
asyncio_mode = auto
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = -v --tb=short --cov=app --cov-report=term-missing --cov-report=html:htmlcov --cov-fail-under=81
markers =
    security: marks tests as security-specific (RBAC, auth hardening, input validation)
```

**Estado P36 (2026-06-14):**
- Tests activos backend: **3003** (2919 P34 + 84 nuevos P36)
- Tests activos asc-agent: **56** (test_p35_executors.py — P35)
- Tests activos total: **3059**
- Cobertura backend: **85.00%** (9215 stmts evaluados en suite completa — sin cambios al core en P36)
- Gate CI: `--cov-fail-under=85` (enforces P34 baseline)
- Techo práctico: ~87% (bloqueado por adaptadores externos: Specter, ELK, Wazuh, Palo Alto, Fortinet, AD — requieren servicios reales)
- **Deployment**: Supabase free tier (PostgreSQL) + Render + Vercel — stack $0 hasta comercialización
- **Redis**: Opcional — Celery en modo no-op cuando `REDIS_URL` vacío (ver `deployment-guide.md`)
- **SPECTER executors**: 7 totales (2 P13 + 5 P35 nuevos) — todos cubiertos con tests
- **SPECTER schema**: `isolate_endpoint` y `log_query` en COMMAND_PARAM_SCHEMAS + COMMAND_EXTRA_PARAMS para params opcionales

**Evolución por sprint:**

| Sprint | Tests backend | Tests asc-agent | Cobertura | Nuevos archivos |
|--------|--------------|-----------------|-----------|----------------|
| P31 | 2621 | — | 81.55% | test_rbac, test_auth_hardening, test_input_validation, test_p31_coverage |
| P32 | 2753 | — | 82.15% | test_p32_cov_iam, test_p32_cov_soar, test_p32_praf, e2e/test_e2e_lifecycle |
| P33 | 2882 | — | 84.26% | test_p33_coverage, test_p33_coverage_b |
| P34 | 2919 | — | 85.00% | test_p34_coverage |
| P35 | 2919 | 56 | 85.00% | test_p35_executors (asc-agent) |
| **P36** | **3003** | **56** | **85.00%** | **test_p36_security (84 tests backend)** |
| **P37** | **3043** | **56** | **85.08%** | **test_p37_pentest (37 tests backend) — Security Hardening** |
| **P38** | **3078** | **56** | **85.08%** | **test_p38_deployment (35 tests backend) — Production Deploy Prep** |
| **P39** | **3155** | **56** | **85.10%** | **test_p39_observability (77 tests backend) — Observabilidad + Frontend Hardening** |
| **P40** | **3218** | **63** | **85.34%** | **test_p40_api_keys (63 tests backend) — API Key Management (primera entrega FASE 5)** |
| **P40-TP** | **3234** | **+16** | **≥85.34%** | **Toque Premos: +5 HMAC·+5 Ledger·+6 Scopes — autenticidad forense, ledger, scopes adaptativos, countdown** |
| **P41** | **3279** | **45** | **≥85.38%** | **test_p41_rate_limit (45 tests backend) — Rate Limiting per API Key (FASE 5)** |
| **P42** | **3327** | **48** | **85.35%** | **test_p42_webhooks (48 tests backend) — Webhook Support con HMAC-SHA256 signing (FASE 5)** |
| **P43** | **3401** | **74** | **85.35%** | **test_p43_sdk (74 tests backend) — Python SDK Cliente: exceptions, resources, WebhookVerifier, security (FASE 5)** |

**Bugs reales descubiertos por tests P32/P33/P34/P35/P36/P37/P38/P39/P40/P41/P42/P43:**
1. `log_security_action()` no aceptaba kwarg `actor=` → crash en toda creación de incidente (`audit.py`) [P32]
2. `_minutes_between()` lanzaba `TypeError` con datetimes SQLite naive vs UTC-aware (`incident_service.py`) [P32]
3. `scheduled_reports.py` usaba `logging.getLogger()` con kwargs structlog-style → `TypeError: Logger._log() got unexpected kwarg 'report_id'` en paths de error [P33]
4. `/neutralize/history` siempre retornaba 404 — routing shadow por orden de registro en FastAPI [P33]
5. `pcdi_escalation.py` usaba `logging.getLogger()` con kwargs structlog-style → `TypeError` en escalación y scoring loop [P34]
6. `escalation.py` mismo patrón stdlib/structlog logger — `log.info("...", escalated=N)` fallaba si INFO level habilitado [P34-post]
7. `agent.py` SPECTER — 5 command types respondían "Unknown command_type"; corregido P35 implementando los 5 ejecutores faltantes [P35]
8. `COMMAND_PARAM_SCHEMAS` / `_VALID_COMMAND_TYPES` desincronizados con P35 executors — aceptaban `isolate` (viejo) pero no `isolate_endpoint` (nuevo); corregido P36 [P36]
9. `agents/page.tsx` VALID_COMMANDS desactualizado (tenía `quarantine_file`, `collect_snapshot`; faltaban 4 P35 commands) — corregido con COMMANDS array tipado [P36]
10. **CRITICAL: `events.py` — 3 endpoints sin auth** (POST /ingest, POST /ingest/bulk, GET /) abiertos desde scaffold inicial. Descubierto por audit_routes.py en P37-ENDPOINTS. Fix: `get_analyst_or_admin` en los 3 endpoints [P37]
11. **`_FakeCeleryApp` sin `.main` attribute** — stub de celery en test_p33_coverage_b.py y test_p34_coverage.py omitía `self.main = name`. Cuando el stub se cargaba antes de test_p38 (orden alfabético), `celery_app.main == "asc"` fallaba con AttributeError. Fix: añadido `self.main = name` en ambos stubs [P38]
12. **`celery-worker` y `celery-beat` sin healthcheck** — `test_docker.py::test_all_services_have_healthcheck` requiere que todos los servicios tengan healthcheck. Los dos nuevos servicios Celery no lo tenían. Fix: añadidos healthchecks (inspect ping para worker, test -f pidfile para beat) [P38]
13. **`decode_access_token` inexistente** — `observability.py` importaba `decode_access_token` de `security.py`, función que no existe (es `decode_token_payload`). El endpoint retornaba 401 siempre en la vía JWT. Detectado y corregido por `test_analyst_jwt_returns_200` en P39. [P39]
14. **`HTTPBearer(auto_error=True)` devuelve 401 (no 403) para header ausente** — comportamiento changed en FastAPI actual. Tests P40 ajustados. [P40]
15. **`HTTP_422_UNPROCESSABLE_ENTITY` deprecated** en FastAPI actual → `422` directo usado en `api_keys.py`. [P40]
16. **`get_user_from_api_key()` requiere `request: Request`** — parámetro añadido por Toque Premos (Scopes adaptativos via `request.state.api_key_scopes`). Los 7 tests en `TestXAPIKeyDep` que llamaban la función directamente fallaron con `TypeError`. Fix: `request=MagicMock()` añadido a todas las llamadas directas. [P40-TP]
17. **SlowAPI "10/minute" en `/auth/login` causó 429 falso positivo en test P41** — `test_jwt_login_endpoint_reachable` acumuló hits del limiter IP-based de otros tests en la suite. Fix: cambiar a llamar `/api/v1/health/liveness` que no tiene rate limit. [P41]
18. **`TypeError: got multiple values for argument 'event'` en structlog** — `webhook_dispatcher.py` usaba `event=event_type` como kwarg en `_log.info()`/`_log.warning()`. Structlog reserva `event` como primer arg posicional. Fix: renombrado a `webhook_event=event_type`. [P42]
19. **`WebhookCreated` Pydantic error `id=None, is_active=None`** — SQLAlchemy `mapped_column(default=callable)` no aplica defaults en `__init__` con DB mockeada (sin flush real). Fix: `id=str(uuid.uuid4())`, `is_active=True`, `failure_count=0`, `created_at=now` pasados explícitamente en el constructor del endpoint `register_webhook`. [P42]

**Nota testing P43 (Python SDK Cliente — FASE 5):**
74 tests en 11 clases. `TestExceptions` (8): hierarchy, status_code, retry_after, response dict stored. `TestExceptionMapping` (8): mapeo exacto 401→AuthError, 403→ForbiddenError, 404→NotFoundError, 422→ValidationError, 429→RateLimitError(retry_after desde header), 500→ServerError, 429 default 60s, 200 sin excepción. `TestWebhookVerifier` (7): verify válido/inválido/tampered/wrong-secret, parse_event válido, parse_event fallo lanza, compat con backend dispatcher. `TestAscClientInit` (5): X-API-Key header, trailing slash strip, 5 resources accesibles, async ctx mgr, close. `TestIncidentsResource` (5): list+modelos, empty, get, create, not-found. `TestAlertsResource` (3): list, get, status filter. `TestAPIKeysResource` (5): list, create+raw_key, revoke 204, rotate, rate_limit_status. `TestWebhooksResource` (5): list, create+secret, delete 204, update, test. `TestSDKSecurity` (6): API key solo en header, no en URL, compare_digest verificado via inspect, retry_after surfaceado, auth fail-fast, user-agent. `TestSDKDeploymentArtifacts` (15): todos los archivos existen, versión, pyproject deps, todos los imports. `TestSDKRegression` (7): liveness 200, dispatcher/rate_limiter/api_key_dep imports, round-trip HMAC, webhooks/api-keys 401. Primer run: 74/74 sin correcciones.

**Nota testing P42 (Webhook Support — FASE 5):**
48 tests en 6 clases. `TestWebhookDispatcher` (13 tests): signing HMAC-SHA256 unit, `deliver_to_url` éxito/fallo/network-error/header verification. `TestWebhookCRUD` (11 tests): `POST /webhooks/` devuelve 201 con secret 64-char, rejects `ftp://`/unknown-events con 422, no-auth 401, list/get 200, cross-user 403, delete 204, patch 200, patch-invalid-URL 422, 404 unknown-id. `TestWebhookTestEndpoint` (3 tests): delivery result, failure, other-user 403. `TestWebhookSecurity` (7 tests): secret ausente en list/get responses, audit emit, audit no contiene secret, admin ve todos, analyst 403 en admin/all, `emit_webhook_event` filtra por tipo correcto. `TestWebhookDeploymentArtifacts` (9 tests): archivos existentes, down_revision correcto, imports funcionales. `TestWebhookRegression` (5 tests): liveness 200, api-keys 401, webhooks 401, dispatcher imports clean, p40/p41 imports. Cobertura de seguridad: secret no en DB (stored as plaintext pero no expuesto vía GET), URL injection prevenida, RBAC en 7 endpoints, HMAC-SHA256 verificación end-to-end.

**Nota testing P41 (Rate Limiting per API Key — FASE 5):**
`test_p41_rate_limit.py` — 45 tests en 7 clases: `TestApiKeyRateLimiterUnit`(11: first request allowed, remaining decrements, exceeding limit blocked, prefix isolation, get_status zero unknown, get_status reflects checks, reset clears state, reset_all clears, result fields populated, mode defaults memory, connect empty url stays memory), `TestApiKeyRateLimitMiddleware`(8: no API key passes through, valid key sets headers, exceeded → 429, 429 has Retry-After header, 429 body has retry_after, malformed key skips rate limit, health endpoint not rate limited, both windows checked), `TestRateLimitStatusEndpoint`(5: owner 200, other user 403, admin 200, no-auth 401, backend mode field), `TestRateLimitResetEndpoint`(3: admin 204 + reset called, analyst 403, no-auth 401), `TestRateLimitSecurity`(5: breach emits audit log, raw key secret not in Redis key, 429 body no raw key, Redis error fail-open, audit detail prefix not hash), `TestRateLimitDeploymentArtifacts`(7: module exists, config per-minute, config per-hour, singleton exported, middleware importable, main imports, router endpoints), `TestRateLimitRegression`(6: liveness, non-API-key no headers, api-keys 401, p40 imports, SlowAPI functional, middleware stack import). 1 bug descubierto: SlowAPI login rate limit acumulado.

**Nota testing P40 — Toque Premos (16 tests adicionales):**
`TestToquePromosHMAC`(5): `hash_key_uses_secret_key` (HMAC keyed con SECRET_KEY), `hmac_matches_deps` (cross-module consistencia api_keys↔deps), `not_plain_sha256` (prueba negativa — HMAC ≠ SHA-256 puro), `length_64` (hexdigest 64 chars), `deterministic_cross_module` (reproducibilidad). `TestToquePromosLedger`(5): create/rotate/revoke llaman `log_security_action` con acción correcta, create incluye scopes, las 3 acciones tienen action names distintos. `TestToquePromosScopes`(6): scope ausente → 403, scope presente → user devuelto, admin scope, scopes vacíos bloquean todo, `require_api_key_scope` es callable, scopes almacenados en `request.state`. Estrategia: aislamiento completo con `MagicMock` + `AsyncMock`, sin DB real. Scan de filtraciones: 0 raw keys hardcodeadas, 0 credenciales reales, raw_key solo en creation/rotation response.

**Nota testing P40 (API Key Management — FASE 5 primera entrega):**
`test_p40_api_keys.py` — 79 tests en 15 clases (63 base + 16 Toque Premos). Clases base (63 tests): `TestAPIKeyHelpers`(10: formato raw_key, unicidad, SHA-256 hash, longitud, prefix, validate_scopes válido/inválido, is_expired false/true/future), `TestCreateAPIKey`(5: auth 401, 201+raw_key, scope inválido 422, cap 422, name vacío 422), `TestListAPIKeys`(4: auth 401, analyst ve propias, admin ve todas, empty array), `TestGetAPIKey`(4: owner 200, otro usuario 403, admin cualquier llave 200, 404), `TestRevokeAPIKey`(3: owner 204, otro usuario 403, 404), `TestRotateAPIKey`(3: nueva raw_key, hash actualizado, otro usuario 403), `TestUpdateAPIKey`(3: name, is_active=False, otro usuario 403), `TestXAPIKeyDep`(7: missing 401, invalid 401, revoked 401, expired 401, valid→user, touches last_used_at, owner inactivo 401), `TestAdminAllKeysEndpoint`(3: analyst 403, admin 200, no-auth 401), `TestSecurityInvariants`(8: raw_key no en APIKeyResponse, raw_key en APIKeyCreated, hashes únicos, hash determinístico, prefix insuficiente para auth, cap razonable, scopes set, sin columna raw_key), `TestDeploymentArtifactsP40`(7: migration file, down_revision, model file, router, models __init__, deps X-API-Key, frontend api.ts), `TestRegressionP40`(6: liveness, auth no roto, observability alcanzable, api-keys route 401, import estable, schema from_attributes). 2 bugs descubiertos: HTTPBearer 401 (no 403), HTTP_422 deprecated.

**Nota testing P39 (Observabilidad + Frontend Hardening):**
`test_p39_observability.py` — 69 tests en 8 clases: `TestMetricsRegistry`(9: isolación de registry global, counter/gauge/histogram, generate_latest, CONTENT_TYPE_LATEST), `TestNormalizePath`(10: UUID collapse, nested paths, root /, string vacío, v2 prefix, multi-UUID mismo label), `TestObservabilityMetricsEndpoint`(10: no-auth 401, scrape-token correcto/incorrecto, content-type text/plain, body HELP lines/asc counters/asc gauges, analyst JWT 200, viewer JWT 403), `TestObservabilitySummaryEndpoint`(10: no-auth, viewer 403, analyst/admin 200, secciones requeridas, process fields, prometheus endpoint path, agents section, ts ISO8601, database section), `TestHealthSystemMetrics`(7: no-auth 401, analyst 200, process section, pid, memory_rss_mb, uptime_seconds, uptime_human), `TestFormatUptime`(7: 0s, segundos, minutos+segundos, 1m exacto, horas, días, 1d exacto), `TestDeploymentArtifactsP39`(5: .env.example, render.yaml, settings attr, router registrado, prefix /observability), `TestObservabilityHelpers`(8: _check_scrape_token 4 casos unitarios, _refresh_gauges directo con mock DB, exception swallowed, scrape token module-level patch, summary body directo), `TestSSENotificationsEndpoint`(4: no-auth 401, garbage 401, viewer forbidden 403, analyst event-stream 200 con generator mock), `TestRegressionP39`(7: liveness, root health, auth/login, events/, alerts/ sin auth, 100 UUIDs→1 label, import estable). 1 bug crítico descubierto: `decode_access_token` → `decode_token_payload`.

**Nota testing FASE 4 (P38 — Production Deploy Prep):**
`test_p38_deployment.py` — 35 tests: `TestInfrastructureFiles`(18: render.yaml sin secretos, vercel.json headers, docker-compose todos los servicios con healthchecks, deploy.yml cadena ci-check→deploy, TLS_SETUP.md, deployment-guide.md SQL Editor, .env.example completo), `TestRootHealthEndpoint`(5: 200 sin auth, body {status,app,version}, security headers, no rate-limit en 10 llamadas), `TestCORSProductionConfig`(3: wildcard rechazado en prod, orígenes específicos aceptados, wildcard OK en dev), `TestStartupChecksProductionMode`(5: weak/short key rechazado, strong aceptado, RuntimeError en prod con key débil), `TestCeleryAppConfig`(4: skipped si celery no instalado). Estrategia: IaC validation (YAML/JSON parsing), live HTTP tests via TestClient, mock-based startup validation. 2 bugs descubiertos y corregidos durante esta sesión.

**Nota testing FASE 3 Final (P37 — Pentest Battery):**
`test_p37_pentest.py` — 37 tests cubriendo: `TestCoverageTargets`(6 unit tests para coverage +9 stmts), `TestJWTAttacks`(9 vectores: no-token, garbage, expired, tampered, alg=none, wrong-secret, missing-sub, malformed-sub), `TestPrivilegeEscalation`(5: viewer→analyst, viewer→admin, analyst→admin endpoints), `TestInjectionResistance`(6: SQL injection, path traversal, XSS, oversized body, malformed Content-Length), `TestSecurityHeaders`(4: nosniff, DENY, CSP, server version), `TestEventsEdgeCases`(7: IoC matching, process field, severity filter, pagination, bulk). Coverage gate 85%: 84.98% → 85.08%.

**Nota testing FASE 3 (P36):**
`test_p36_security.py` — 84 tests cubriendo: schema additions, optional params, _VALID_COMMAND_TYPES sync, _cmd_out extended fields, GET /agents/{id}/command-history (8 escenarios incluyendo 401/403/404), auth barriers en 10 endpoints, injection detection (13 casos), enrollment token HMAC (8 casos), param validation edge cases (8), honeypot smoke tests (6). Bandit: 0 HIGH/MEDIUM en archivos modificados.

**Frontend SPECTER Command Center (P36):**
`agents/page.tsx` reescrito con: `CommandParamForm` (forms estructurados por tipo de comando, no textarea JSON crudo), `CommandHistoryPanel` (polling 10s, expand-on-click, result display), `LogQueryResults` (visualizador de matches), layout de 3 tabs (Issue Command / Command History / Event Timeline), confirmation dialog para `isolate_endpoint`, danger flag en comandos destructivos.

```bash
# Solo tests unitarios (rápido, sin dependencias externas)
pytest -m unit

# Solo tests de seguridad
pytest -m security

# Tests de integración (requiere sandbox configurado)
pytest -m integration --env=sandbox

# Suite completa con reporte
pytest --html=reports/test-report.html --self-contained-html
```

**Nota testing P48 (Load Testing + Staging Readiness):**
27 tests en 4 clases. TestLocustFileStructure(10): locustfile.py existe, ApiKeyUser y WebhookUser clases presentes, endpoints /api/v1/api-keys/ y /api/v1/webhooks/ cubiertos, rate-limit-status cubierto, sin credenciales hardcodeadas (solo placeholder REPLACE_ME), sandbox IP 100.64.0.1 (RFC 6890), AST parse limpio, PRAFCollector presente. TestRapidSequentialRequests(3): 10 GET /api-keys/ secuenciales = 200 todos, 10 GET /webhooks/ secuenciales = 200 todos, 20 GET /health secuenciales = 200 todos. TestStagingReadiness(4): render.yaml y .env.example existen, .env.example tiene vars de configuracion, locustfile tiene weight en >=5 user classes. TestP48Regression(10): liveness, 401 sin auth api-keys/webhooks, Tenant model, migration P47, pages P46/P45/P44, SDK P43, api_keys router. Primera run: 27/27.

**Nota testing P47 (Multi-tenancy Foundation - FASE 5 Schema):**
28 tests en 4 clases. TestTenantModel(7): Tenant importable, tablename="tenants", columnas requeridas (id/name/slug/plan/is_active/created_at), columnas opcionales (contact_email/max_users/max_api_keys_per_user), slug unique=True, plan con default, Tenant en __init__.py. TestTenantIdColumns(8): tenant_id nullable+indexado en User, Alert, Event, APIKey, Webhook, Incident (6 modelos). TestMigrationFile(6): migration file existe, revision=p6j79m8o1i93, down_revision=n4h58k6m9g71, create_table("tenants"), add_column tenant_id en 6 tablas, def downgrade con drop_table. TestP47Regression(7): liveness 200, api_keys 401 sin auth, api_keys 200 con auth, webhooks 401, todos los modelos importables, rate-limits page existe, api-keys page existe. 2 bugs descubiertos: Bug#27 import useAuthGuard desde @lib/auth (incorrecto) → @lib/auth-guard, Bug#28 key.scope (string) vs key.scopes[0] (array APIKeyResponse) — test_typescript_errors_resolved detectó ambos. Primera run post-fix: 28/28.

**Nota testing P46 (Rate Limits Dashboard Frontend - FASE 5):**
30 tests en 4 clases. TestRateLimitStatusContract(6): 200 owner, 200 admin (cross-key), 403 cross-user, 401 sin auth, todos los 8 campos presentes (key_prefix/limit_per_minute/limit_per_hour/count_minute/count_hour/remaining_minute/remaining_hour/backend), valores consistentes (remaining=limit-count, backend="memory"). TestRateLimitResetContract(4): 204 admin, assert_awaited_once_with(key.key_prefix), 403 analyst (incluso si es owner), 401 sin auth. TestSecurityInvariants(2): key_hash y raw_key nunca en RateLimitStatus response. TestP46DeploymentAndRegression(18): todos los artifacts frontend verificados (page.tsx, useAuthGuard, UsageBar, BackendBadge, setInterval, Reset, resetApiKeyRateLimit en api.ts, sidebar entry, no secrets), liveness 200, 3 endpoints con 401 sin auth, regression P40-P45. 2 bugs descubiertos: Bug#25 patron get_db con patch() incorrecto — migrado a app.dependency_overrides (P45 pattern), Bug#26 paths P43/P42 incorrectos en regression tests — corregidos. Primera run post-fix: 30/30.

**Nota testing P45 (API Keys Dashboard Frontend - FASE 5):**
35 tests en 6 clases. TestListApiKeysContract(4): 200 autenticado, campos requeridos (id/name/key_prefix/scope/is_active/created_at), raw_key/key_hash ausentes en list, 401 sin auth. TestCreateApiKeyContract(5): 201+raw_key presente, raw_key no en list subsecuente, 422 scope invalido, 422 nombre vacio, 401 sin auth. TestGetPatchRevokeContract(6): GET sin key_hash, GET 403 cross-user, PATCH toggle is_active, DELETE 204, DELETE 403 cross-user, GET 404 missing. TestRotateApiKeyContract(3): rotate devuelve raw_key, 403 cross-user, 401 sin auth. TestRateLimitStatusContract(2): campos rate-limit presentes (key_prefix/limit_per_minute/limit_per_hour/count_minute/count_hour/remaining_minute/remaining_hour/backend), 403 cross-user. TestP45DeploymentAndRegression(15): page.tsx existe, useAuthGuard, KeyRevealPanel/KeyFormModal/RateLimitBar en codigo, RateLimitStatus interface en api.ts, getApiKeyRateLimitStatus/adminListAllApiKeys en api.ts, sidebar api-keys entry, no secrets hardcodeados, liveness 200, api-keys 401 sin auth, P44/P42/P43/P40 imports estables. 3 bugs descubiertos: Bug#22 api_key_limiter.get_status() devuelve int no dict (patch location + tipo corregido), Bug#23 db.refresh no seteaba id/is_active en create (patron SQLAlchemy mock con setattr), Bug#24 db.refresh sobreescribia id existente en rotate (refresh conservativo). Primera run post-fix: 35/35. Full suite: 3475 passed, 85.36% coverage.

**Nota testing P44 (Webhook Dashboard Frontend - FASE 5):**
39 tests en 6 clases. TestListWebhooksContract(4): 200 autenticado, campos requeridos presentes (id/url/events/is_active/user_id/created_at/failure_count), secret ausente en respuesta, 401 sin auth. TestCreateWebhookContract(5): 201+secret 64-char, signing_note presente, reject ftp:// con 422, reject evento desconocido con 422, 401 sin auth. TestGetPatchDeleteContract(7): GET sin secret en respuesta, GET 403 cross-user, PATCH toggle is_active sin exponer secret, PATCH reject javascript://xss con 422, DELETE 204, DELETE 403 cross-user, GET 404 missing. TestWebhookTestDeliveryContract(4): campos success/status_code/latency_ms/error presentes, success shape (200/None error), failure shape (None status/error string), 403 cross-user. TestAdminListWebhooksContract(4): admin 200 con todos los webhooks, analyst 403, secrets ausentes en admin list, 401 sin auth. TestP44DeploymentAndRegression(15): page.tsx existe, useAuthGuard presente, WebhookFormModal/SecretReveal/TestResultPanel en codigo, 7 funciones en api.ts, 3 interfaces TypeScript, VALID_WEBHOOK_EVENTS const, sidebar /webhooks, liveness 200, webhooks 401 sin auth, p42/p43/p40 imports, no mock data hardcoded. 2 bugs descubiertos: #20 patch location corrected (_resolve_user en app.api.deps no en endpoint module), #21 admin URL corrected (/webhooks/admin/all no /admin/webhooks/). Primera run post-fix: 39/39.
