# ASC PremosCorp — Roadmap de Desarrollo
> Versión 5.0 | Fecha: 2026-07-12 | Estado: FASE 1–6 completadas — P39–P63 completados — TD-2/TD-4/TD-5/TD-6 cerradas — Auditoría Pre-Producción PASSED — Test Suite Hardening S97-S98 COMPLETADO — 4930 tests ASC / 3416 tests sc_system, coverage 85.37%

---

## VisiÃ³n General

El objetivo es llevar el servicio de neutralizaciÃ³n de **simulaciÃ³n a producciÃ³n real** para PremosCorp, y posteriormente arquitecturarlo como **microservicio comercializable** (SaaS B2B).

**Stack de integraciÃ³n confirmado:**
| Capa | TecnologÃ­a |
|------|------------|
| EDR / Agent | **PremosCorp Specter** (poll-based agent, fleet command, RTR) |
| Firewall | Palo Alto Networks PAN-OS API + Fortinet FortiGate REST API |
| Identity | Active Directory / LDAP (ldap3) |
| Workflow | Human-in-the-loop con Celery + Redis + WebSocket |
| Threat Intel | ThreatIntelIndicator DB + MISP/TAXII bulk import |
| Correlation | Cross-domain Correlation Engine (P27) |
| SOAR | Auto-trigger engine + PIDS Identity SOAR (P25/P26) |

---

## Resumen de Fases

```
FASE 0  â”€â”€â–¶  FASE 1  â”€â”€â–¶  FASE 2  â”€â”€â–¶  FASE 3  â”€â”€â–¶  FASE 4
Baseline     Integraciones  Workflow     QA &          ProducciÃ³n
Seguridad    Reales         H-i-t-L      Hardening     PremosCorp
(2 sem)      (8 sem)        (2 sem)      (3 sem)       (2 sem)
                                                              â”‚
                                                              â–¼
                                          FASE 5  â”€â”€â–¶  FASE 6
                                          Microservicio  Comercial
                                          (10 sem)       (6 sem)
```

**Timeline total:**
- PremosCorp interno: ~17 semanas (~4 meses)
- ComercializaciÃ³n: +16 semanas adicionales (~4 meses)
- **Total proyecto completo: ~33 semanas (~8 meses)**

---

## Estado de ImplementaciÃ³n Actual (P01â€“P27)

| MÃ³dulo | DescripciÃ³n | Estado | Tests |
|--------|-------------|--------|-------|
| P01â€“P15 | Core: auth JWT+RBAC, events, alerts, IoCs, metrics, anÃ¡lisis artefactos, neutralizaciÃ³n, playbooks, adaptadores, salud del sistema, reportes, honeypot base, forensic ledger base | âœ… | ~1,500 |
| P16 | PANL â€” Multi-firma HitL, rollback, adaptive severity | âœ… | incluidos |
| P17 | SPECTER Agents â€” fleet, heartbeat, command pipeline | âœ… | incluidos |
| P18 | Honeypot â€” traps pasivos, evidence reports | âœ… | incluidos |
| P19 | Forensic Ledger â€” Ed25519 + SHA3-512 chain | âœ… | incluidos |
| P20 | Ops Dashboard â€” fleet health, cross-domain metrics | âœ… | incluidos |
| P21 | Threat Intelligence â€” indicadores, bulk, enriquecimiento | âœ… | incluidos |
| P22 | Threat Hunting â€” sessions, findings, queries read-only | âœ… | incluidos |
| P24 | PCDI â€” Adaptive scoring, Celery escalation | âœ… | incluidos |
| P25 | SOAR â€” Auto-triggers, condition engine, playbooks | âœ… | incluidos |
| P26 | PIDS â€” Identity SOAR, forensic tokens, ScheduledReports | âœ… | 80 |
| P27 | Correlation Engine â€” clusters, campaigns, graph | âœ… | 82 |
| **Total** | | | **~1,858 tests** |

---

## FASE 0 â€” Baseline de Seguridad y AuditorÃ­a Inicial
**DuraciÃ³n:** Semanas 1â€“2 âœ… COMPLETADA

### Objetivos
Antes de escribir una sola lÃ­nea de cÃ³digo de integraciÃ³n real, auditar completamente el estado actual del repositorio para garantizar que no hay secretos expuestos, dependencias vulnerables ni patrones inseguros.

### Entregables

#### 0.1 AuditorÃ­a de Secretos en Git
```bash
# Escaneo de secretos en todo el historial git
gitleaks detect --source . --verbose --report-path reports/gitleaks-report.json

# Escaneo profundo en historial de commits
truffleHog git file://. --only-verified --json > reports/trufflehog-report.json

# Baseline de detecciÃ³n de credenciales
detect-secrets scan . --all-files > .secrets.baseline
detect-secrets audit .secrets.baseline
```

#### 0.2 AuditorÃ­a de Dependencias Python
```bash
# Vulnerabilidades conocidas en dependencias
safety check -r backend/requirements.txt --json -o reports/safety-report.json

# AuditorÃ­a con pip-audit (alternativa mÃ¡s robusta)
pip-audit -r backend/requirements.txt -f json -o reports/pip-audit-report.json

# AnÃ¡lisis estÃ¡tico de seguridad Python (OWASP)
bandit -r backend/app/ -f json -o reports/bandit-report.json -ll
```

#### 0.3 AuditorÃ­a de Contenedores
```bash
# Vulnerabilidades en imÃ¡genes Docker
trivy image --format json --output reports/trivy-backend.json asc_backend:latest
trivy image --format json --output reports/trivy-frontend.json asc_frontend:latest

# Escaneo del filesystem completo
trivy fs . --security-checks vuln,config,secret --format json -o reports/trivy-fs.json

# ConfiguraciÃ³n de Docker Compose
docker-compose config --quiet && echo "Compose config OK"
```

#### 0.4 AnÃ¡lisis EstÃ¡tico de CÃ³digo
```bash
# Semgrep con reglas de seguridad
semgrep --config=p/python --config=p/security-audit --config=p/owasp-top-ten \
  backend/app/ --json -o reports/semgrep-report.json

# Buscar llaves hardcodeadas manualmente
grep -rEn "(api_key|secret_key|password|token|auth_token|bearer)\s*=\s*['\"][^'\"]{8,}" \
  backend/app/ --include="*.py" | grep -v test | grep -v ".pyc"

# Verificar que .env no estÃ© en git
git ls-files | grep -E "^\.env$" && echo "ALERTA: .env en git" || echo ".env OK"

# Variables de entorno hardcodeadas
grep -rn "changeme\|password123\|secret123\|admin123" backend/ frontend/ --include="*.py" --include="*.ts" --include="*.js"
```

#### 0.5 Setup del Pipeline CI/CD con Security Gates
Configurar GitHub Actions con los siguientes gates de seguridad obligatorios que bloquean el merge si fallan:
- `gitleaks` â€” secrets scanning en cada PR
- `bandit` â€” anÃ¡lisis estÃ¡tico Python
- `safety` â€” vulnerabilidades de dependencias
- `trivy` â€” vulnerabilidades en contenedores

### Criterios de AceptaciÃ³n FASE 0
- [ ] 0 secretos expuestos en historial git
- [ ] 0 vulnerabilidades CRÃTICAS en dependencias
- [ ] Pipeline CI/CD activo con security gates
- [ ] Reporte de auditorÃ­a inicial firmado y archivado en `reports/`

---

## FASE 1 â€” Integraciones Reales (PremosCorp)
**DuraciÃ³n:** Semanas 3â€“10 âœ… COMPLETADA

### Objetivos
Reemplazar los placeholders `asyncio.sleep()` con implementaciones reales conectadas a CrowdStrike Falcon, Palo Alto/Fortinet y Active Directory. Usar el **Adapter Pattern** para mantener la capa de negocio agnÃ³stica al proveedor.

### Arquitectura de Adaptadores

```
neutralizer.py (orquestador)
    â”‚
    â”œâ”€â”€ adapters/
    â”‚   â”œâ”€â”€ base.py          â† Interfaces abstractas
    â”‚   â”œâ”€â”€ edr/
    â”‚   â”‚   â””â”€â”€ crowdstrike.py
    â”‚   â”œâ”€â”€ firewall/
    â”‚   â”‚   â”œâ”€â”€ paloalto.py
    â”‚   â”‚   â””â”€â”€ fortinet.py
    â”‚   â””â”€â”€ identity/
    â”‚       â””â”€â”€ active_directory.py
    â”‚
    â””â”€â”€ approval/
        â”œâ”€â”€ queue.py         â† Cola de aprobaciones pendientes
        â””â”€â”€ workflow.py      â† LÃ³gica human-in-the-loop
```

### Entregables

#### 1.1 PremosCorp Specter Adapter (reemplaza CrowdStrike Falcon)
- Poll-based agent con heartbeat configurable
- `isolate_host()` â€” ContenciÃ³n de endpoint via AgentCommand
- `lift_isolation()` â€” LiberaciÃ³n de contenciÃ³n
- `kill_process()` â€” Terminate process via RTR command
- `quarantine_file()` â€” File quarantine via agent
- Fleet management: status tracking, threat_level, last_seen
- Circuit breaker para agentes offline

**Pruebas unitarias requeridas:**
```bash
pytest backend/tests/unit/adapters/test_specter.py -v
pytest backend/tests/integration/test_specter_sandbox.py -v --env=sandbox
```

#### 1.2 Palo Alto / Fortinet Adapter
- Palo Alto PAN-OS XML API:
  - Bloqueo de IP en Dynamic Address Group
  - Block de dominio via Custom URL Category
  - Commit de cambios y verificaciÃ³n
- Fortinet FortiGate REST API:
  - CreaciÃ³n de Address Object para IP bloqueada
  - AplicaciÃ³n en Firewall Policy

**Pruebas unitarias requeridas:**
```bash
pytest backend/tests/unit/adapters/test_paloalto.py -v
pytest backend/tests/unit/adapters/test_fortinet.py -v
```

#### 1.3 Active Directory / LDAP Adapter
- ConexiÃ³n via `ldap3` con LDAPS (TLS obligatorio)
- `disable_account()` â€” Modificar `userAccountControl` flag
- `enable_account()` â€” Revertir deshabilitaciÃ³n
- `reset_password()` â€” Forzar cambio de contraseÃ±a
- `move_to_quarantine_ou()` â€” Mover a OU de cuarentena

**Pruebas unitarias requeridas:**
```bash
pytest backend/tests/unit/adapters/test_active_directory.py -v
pytest backend/tests/integration/test_ad_sandbox.py -v --env=sandbox
```

#### 1.4 GestiÃ³n Segura de Credenciales
Todas las credenciales de API (CrowdStrike, PAN-OS, Fortinet, AD) deben almacenarse en:
- **ProducciÃ³n:** HashiCorp Vault o AWS Secrets Manager (nunca en `.env` en producciÃ³n)
- **Desarrollo:** `.env` local (en `.gitignore`, nunca en git)

```bash
# VerificaciÃ³n antes de cada deploy
pre-commit run --all-files
detect-secrets scan --update .secrets.baseline
```

### Criterios de AceptaciÃ³n FASE 1
- [ ] Los 3 adaptadores con cobertura de tests > 80%
- [ ] 0 credenciales hardcodeadas (verificado con `gitleaks`)
- [ ] Retry logic y circuit breaker implementados
- [ ] Logs de auditorÃ­a para cada llamada a API externa
- [ ] DocumentaciÃ³n de cada endpoint de API externo usado

---

## FASE 2 â€” Workflow Human-in-the-Loop
**DuraciÃ³n:** Semanas 11â€“12 âœ… COMPLETADA (P16 + PANL + SOAR + PIDS)

### Objetivos
Implementar el sistema de aprobaciÃ³n para acciones crÃ­ticas antes de que se ejecuten. Un analista debe aprobar o rechazar la acciÃ³n dentro de un tiempo lÃ­mite.

### Flujo de AprobaciÃ³n

```
Alert CRITICAL/HIGH detectada
        â”‚
        â–¼
Neutralization Request creada (status: PENDING_APPROVAL)
        â”‚
        â”œâ”€â”€ NotificaciÃ³n WebSocket â†’ Analista en dashboard
        â”œâ”€â”€ NotificaciÃ³n email/Slack (opcional)
        â”‚
        â–¼
Analista revisa (ventana de 15 minutos para CRITICAL)
        â”‚
        â”œâ”€ APPROVE â†’ Ejecutar acciÃ³n â†’ Log de auditorÃ­a
        â”œâ”€ REJECT  â†’ Marcar false_positive â†’ Log de auditorÃ­a
        â””â”€ TIMEOUT â†’ Escalar a Tier 2 â†’ NotificaciÃ³n â†’ Log de auditorÃ­a
```

### Entregables
- Modelo `NeutralizationRequest` con estado: `PENDING_APPROVAL | APPROVED | REJECTED | EXECUTING | COMPLETED | FAILED | ESCALATED`
- Endpoint `POST /api/v1/neutralize/approve/{request_id}`
- Endpoint `POST /api/v1/neutralize/reject/{request_id}`
- Celery task con timeout configurable por severidad
- WebSocket channel para notificaciones en tiempo real
- Audit trail inmutable para cada decisiÃ³n

### Pruebas requeridas
```bash
pytest backend/tests/unit/test_approval_workflow.py -v
pytest backend/tests/integration/test_approval_e2e.py -v
```

### Criterios de AceptaciÃ³n FASE 2
- [ ] Timeout configurable por severidad (CRITICAL: 15min, HIGH: 30min)
- [ ] EscalaciÃ³n automÃ¡tica implementada
- [ ] Audit trail para cada decisiÃ³n (quiÃ©n, cuÃ¡ndo, quÃ©)
- [ ] Tests E2E del flujo completo

---

## FASE 3 â€” Hardening, QA y Pruebas de Seguridad
**DuraciÃ³n:** Semanas 13â€“15 COMPLETADA (P37 â€” 2026-06-14)

### Objetivos
Garantizar que el sistema es robusto, seguro y confiable antes del despliegue en producciÃ³n.

### 3.1 Suite de Pruebas Completa

**PirÃ¡mide de testing:**
```
        â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
        â”‚   E2E / UI (5%) â”‚  Playwright o Cypress
        â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
        â”‚  IntegraciÃ³n    â”‚  Tests contra sandbox APIs
        â”‚    (25%)        â”‚  Specter, Palo Alto, AD
        â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤

        â”‚  Unitarias      â”‚  Pytest + mocks â€” 1,858 tests activos
        â”‚    (70%)        â”‚  Cada adapter, servicio, modelo
        â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜

Objetivo: cobertura total > 85%
```

```bash
# Ejecutar suite completa
pytest backend/tests/ -v --cov=app --cov-report=html --cov-report=term-missing \
  --cov-fail-under=85 -x

# Reporte de cobertura
open htmlcov/index.html
```

### 3.2 Pruebas de Carga y Resiliencia
```bash
# Load testing con Locust
locust -f tests/load/locustfile.py --headless \
  -u 100 -r 10 --run-time 5m \
  --host http://localhost:8000

# Test de resiliencia: simular fallo de CrowdStrike API
pytest backend/tests/resilience/test_circuit_breaker.py -v

# Test de timeout y rollback
pytest backend/tests/resilience/test_approval_timeout.py -v
```

### 3.3 AuditorÃ­a de Seguridad Final (Pre-ProducciÃ³n)
```bash
# Suite completa de seguridad
gitleaks detect --source . -v --report-path reports/final-gitleaks.json
bandit -r backend/app/ -f json -o reports/final-bandit.json
safety check -r backend/requirements.txt
trivy fs . --security-checks vuln,config,secret
semgrep --config=p/python --config=p/security-audit backend/app/
pip-audit -r backend/requirements.txt

# Verificar headers HTTP de seguridad
curl -I http://localhost:8000/health | grep -E "(X-Content-Type|X-Frame|Strict-Transport|Content-Security)"

# CORS check
curl -H "Origin: http://evil.com" -I http://localhost:8000/api/v1/neutralize/

# SQL injection bÃ¡sico (endpoints de bÃºsqueda)
pytest backend/tests/security/test_sql_injection.py -v

# AutenticaciÃ³n y autorizaciÃ³n
pytest backend/tests/security/test_auth.py -v
pytest backend/tests/security/test_rbac.py -v
```

### 3.4 Penetration Testing Checklist
- [ ] AutenticaciÃ³n: brute force, token expiry, JWT validation
- [ ] AutorizaciÃ³n: RBAC, privilege escalation, IDOR
- [ ] InyecciÃ³n: SQL, NoSQL, LDAP injection en adapter AD
- [ ] API: rate limiting, mass assignment, excessive data exposure
- [ ] Secrets: variables de entorno, logs sin datos sensibles
- [ ] Transport: TLS 1.2+, HSTS, certificate validation

### Criterios de AceptaciÃ³n FASE 3
- [x] Cobertura de tests â‰¥ 85% â€” **LOGRADO: 85.08%** (3043 tests, gate 85.00%)
- [x] 0 vulnerabilidades CRÃTICAS / ALTAS sin resolver â€” **bandit 0 H/M, safety 0 CVEs, secret scan CLEAN**
- [ ] Load test: p95 < 500ms bajo 100 usuarios concurrentes â€” pendiente
- [x] Penetration testing completado y hallazgos remediados â€” **P37-PENTEST: JWT(9), escalation(5), injection(6), headers â€” ALL BLOCKED**

**Resumen P37 (Session 48):**
- Fix crÃ­tico: events.py 3 endpoints sin auth â†’ `get_analyst_or_admin` aÃ±adido
- 37 tests de pentest battery (test_p37_pentest.py)
- Coverage: 84.98% â†’ 85.08%
- audit_routes.py: 181 routes, 90% autenticados, 0 open inesperados
- Bandit nosec: paloalto.py B112, active_directory.py B110 (intencionales, anotados)

---

## FASE 4 â€” Despliegue ProducciÃ³n PremosCorp âœ… COMPLETADA (P38, Session 49)
**DuraciÃ³n:** Semanas 16â€“17

### Entregables completados (P38)
- [x] `render.yaml` â€” Blueprint declarativo para Render (FastAPI backend, free tier, Python runtime)
- [x] `frontend/vercel.json` â€” Security headers, CSP, HSTS, Permissions-Policy para Next.js
- [x] `docs/TLS_SETUP.md` â€” Let's Encrypt standalone + webroot, renovaciÃ³n automÃ¡tica, self-signed dev
- [x] `.github/workflows/deploy.yml` â€” CIâ†’CD automÃ¡tico: ci-check â†’ deploy-backend (Render) â†’ deploy-frontend (Vercel)
- [x] `docker-compose.yml` â€” celery-worker + celery-beat con healthchecks aÃ±adidos
- [x] `docs/deployment-guide.md` â€” GuÃ­a completa Fase 1 (Supabase+Render+Vercel) y Fase 2 (Docker)
- [x] `backend/tests/test_p38_deployment.py` â€” 35 tests: IaC validation, /health, CORS, startup checks, Celery

### Criterios de AceptaciÃ³n FASE 4
- [x] render.yaml sin secretos hardcodeados (sync:false para SECRET_KEY y DATABASE_URL)
- [x] vercel.json con X-Frame-Options=DENY, CSP, HSTS, Permissions-Policy
- [x] CD workflow: deploy-backend depende de ci-check (cobertura 85% gate)
- [x] /health accesible sin auth (Docker HEALTHCHECK + Render healthCheckPath + nginx probe)
- [x] CORS wildcard rechazado en production mode (startup_checks.py)
- [x] SECRET_KEY < 32 chars lanza RuntimeError("Startup aborted") en producciÃ³n
- [x] Full test suite: 3078 passed, 14 skipped, 0 failed â€” coverage 85.08%
- [ ] Deploy en staging real sin errores durante 48h (requiere secrets de Vercel configurados)
- [x] Monitoreo activo con alertas configuradas (Prometheus endpoint + psutil â€” P39)
- [ ] Go-live con ventana de observaciÃ³n de 72h

---

## Sprint P39 â€” Observabilidad de ProducciÃ³n + Frontend Hardening
**Estado:** COMPLETADO â€” 2026-06-13
**SesiÃ³n:** 50

### Entregables P39

| Tarea | DescripciÃ³n | Estado |
|-------|-------------|--------|
| P39-PROMETHEUS | `GET /api/v1/observability/metrics` (Prometheus text 0.0.4) + `GET /api/v1/observability/summary` (JSON) â€” auth dual: JWT analyst+ OR `METRICS_SCRAPE_TOKEN` | âœ… COMPLETADO |
| P39-SYSMETRICS | `psutil.Process()` en `/health/system` â†’ secciÃ³n `process` con cpu_percent, memory_rss_mb, memory_vms_mb, pid. Panel observabilidad en `status/page.tsx` (4 columnas). | âœ… COMPLETADO |
| P39-NOTIFY | `useSSENotifications` cableado en `alerts/page.tsx`, `events/page.tsx`, `incidents/page.tsx`. Indicador `live`/`offline` (Wifi/WifiOff) en cada header. | âœ… COMPLETADO |
| P39-FRONTEND-AUDIT | `.env.example` + `render.yaml` actualizados con `METRICS_SCRAPE_TOKEN`. Todas las 24 pÃ¡ginas del portal auditadas â€” funcionales. | âœ… COMPLETADO |
| P39-TESTS | `test_p39_observability.py` â€” 77 tests en 9 clases. Prometheus endpoint, system metrics, SSE, deploy artifacts, helpers unitarios, regression. | âœ… COMPLETADO |
| P39-DOCS | AUDIT_LOG Session 50 (#1003â€“#1028), ROADMAP v2.3. | âœ… COMPLETADO |

### Bug encontrado y corregido
- `decode_access_token` no existe en `security.py` â†’ correcto: `decode_token_payload`. Detectado por los tests P39 antes de llegar a producciÃ³n.

### MÃ©tricas finales P39
- **Test suite:** 3078 â†’ 3155 (+77 tests) â€” cobertura 85.10% (gate 85.00% superado)
- **Endpoints nuevos:** `/api/v1/observability/metrics`, `/api/v1/observability/summary`
- **Nuevos archivos backend:** `metrics_registry.py`, `observability.py`, `test_p39_observability.py`
- **Nuevos archivos frontend:** â€” (solo modificaciones)
- **SSE pÃ¡ginas:** alerts, events, incidents (ops ya tenÃ­a SSE)

---

## Sprint P40 â€” API Key Management
**Estado:** COMPLETADO â€” 2026-06-14
**SesiÃ³n:** 51

### Entregables P40

| Tarea | DescripciÃ³n | Estado |
|-------|-------------|--------|
| P40-MODEL | `APIKey` SQLAlchemy model + Alembic migration `m3g47j5l8f60`. Columnas: id, name, key_prefix (String8), key_hash (**HMAC-SHA256**, unique), user_id (FKâ†’users CASCADE), scopes (JSON), expires_at, last_used_at, is_active. Propiedad `is_expired`. | âœ… COMPLETADO |
| P40-BACKEND | 7 endpoints en `/api/v1/api-keys/`: create (raw_key devuelta UNA vez), list, get, patch, delete (revoke permanente), rotate (nueva raw_key preservando id/scopes), admin/all (admin-only). Cap 20 llaves/usuario. Scopes: read/write/admin. | âœ… COMPLETADO |
| P40-AUTH | `get_user_from_api_key()` dep en `deps.py` â€” acepta header `X-API-Key`, valida **HMAC-SHA256** hash, is_active, expires_at, owner activo; toca `last_used_at`; almacena `request.state.api_key_scopes`. 401 uniforme (fail-secure). | âœ… COMPLETADO |
| P40-FRONTEND | `frontend/src/lib/api.ts` â€” 5 funciones + 2 interfaces. `admin/page.tsx` refactorizado con 2 tabs: Usuarios (IAM existente) + API Keys (nuevo: stats, tabla, NewKeyDialog, RevealKeyDialog one-time con countdown 90s). | âœ… COMPLETADO |
| P40-TESTS | `test_p40_api_keys.py` â€” **79 tests** en 15 clases (63 base + 16 Toque Premos). CRUD, RBAC, X-API-Key dep unit tests, security invariants (no raw_key en DB), deployment artifacts, regression, HMAC, Ledger, Scopes. | âœ… COMPLETADO |
| P40-DOCS | AUDIT_LOG Session 51 (#1029â€“#1058), ROADMAP v2.5. | âœ… COMPLETADO |
| **P40-PREMOS** | **Toque Premos aplicado**: HMAC-SHA256 forense Â· Ledger Premos (audit trail en create/rotate/revoke) Â· Scopes adaptativos (`require_api_key_scope` factory dep) Â· One-time reveal countdown 90s con barra urgencia cyanâ†’red | âœ… COMPLETADO |

### Bugs encontrados y corregidos
- `HTTPBearer(auto_error=True)` devuelve 401 (no 403) para Authorization header ausente en FastAPI actual â†’ tests corregidos
- `HTTP_422_UNPROCESSABLE_ENTITY` deprecated â†’ reemplazado por cÃ³digo `422` directo
- `get_user_from_api_key()` requiere `request: Request` (aÃ±adido por Toque Premos) â†’ 7 tests en `TestXAPIKeyDep` actualizados con `request=MagicMock()`

### MÃ©tricas finales P40 + Toque Premos
- **Test suite:** 3155 â†’ 3234 (+79 tests totales â€” 63 base + 16 Toque Premos) â€” cobertura â‰¥85.34% (gate 85.00% superado)
- **Endpoints nuevos:** 7 en `/api/v1/api-keys/`
- **Nuevos archivos backend:** `api_key.py` (model), `m3g47j5l8f60_add_api_keys_p40.py` (migration), `api_keys.py` (endpoints), `test_p40_api_keys.py`
- **Deps nuevas:** `get_user_from_api_key` (X-API-Key auth), `require_api_key_scope` (scope factory) en `deps.py`
- **Frontend:** admin/page.tsx refactorizado a 2 tabs; countdown 90s en RevealKeyDialog; api.ts con 5 funciones CRUD
- **Toque Premos garantÃ­as:** Raw key nunca persiste Â· HMAC-SHA256 inforjable sin SECRET_KEY Â· Ledger inmutable en asc.audit Â· Scopes granulares por llave Â· Reveal one-time con auto-cierre
- **FASE 5 bridge:** Primera pieza de comercializaciÃ³n â€” autenticaciÃ³n programÃ¡tica sin credenciales de usuario

---

## Sprint P41 â€” Rate Limiting per API Key
**Estado:** COMPLETADO â€” 2026-06-14
**SesiÃ³n:** 52

### Entregables P41

| Tarea | DescripciÃ³n | Estado |
|-------|-------------|--------|
| P41-CORE | `backend/app/core/api_key_rate_limit.py` (CREADO): `ApiKeyRateLimiter` â€” sliding window ZSET (Redis) + deque (memory fallback). Fail-open en error Redis. Singleton `api_key_limiter`. | âœ… COMPLETADO |
| P41-CONFIG | `config.py`: `RATE_LIMIT_API_KEY_PER_MINUTE=60`, `RATE_LIMIT_API_KEY_PER_HOUR=1000`. Ambas ventanas configurables vÃ­a `.env`. | âœ… COMPLETADO |
| P41-MIDDLEWARE | `middleware.py`: `ApiKeyRateLimitMiddleware` â€” intercepta `X-API-Key` requests, extrae prefix (8 chars), verifica ambas ventanas, retorna 429 + `Retry-After` si excede. Headers: `X-RateLimit-Limit-Minute/Hour`, `X-RateLimit-Remaining-Minute/Hour`, `X-RateLimit-Reset`. JWT path completamente bypasseado. | âœ… COMPLETADO |
| P41-MAIN | `main.py`: `api_key_limiter.connect(REDIS_URL)` en lifespan; `ApiKeyRateLimitMiddleware` aÃ±adido al stack (outermost). | âœ… COMPLETADO |
| P41-ENDPOINTS | `api_keys.py`: `GET /{id}/rate-limit-status` (owner/admin â€” muestra count/remaining por ventana), `POST /{id}/rate-limit-reset` (admin-only â€” limpia Redis+memory, Ledger Premos). Schema `RateLimitStatus`. | âœ… COMPLETADO |
| P41-TESTS | `test_p41_rate_limit.py`: 45 tests en 7 clases â€” limiter unit, middleware ASGI, status, reset, security invariants, deployment artifacts, regression. | âœ… COMPLETADO |
| P41-DOCS | AUDIT_LOG Session 52 (#1059â€“#1069), ROADMAP v2.6. | âœ… COMPLETADO |

### Bugs encontrados y corregidos
- `test_jwt_login_endpoint_reachable` â†’ SlowAPI hit acumulado de otros tests causaba 429 falso positivo. Cambiado a llamar `/health/liveness`.

### MÃ©tricas finales P41
- **Test suite:** 3234 â†’ 3279 (+45 tests) â€” cobertura â‰¥85.38% (gate 85.00% superado)
- **Algoritmo:** Sliding window log (ZSET) â€” O(log N), sin boundary burst artifacts
- **Headers nuevos:** 5 headers `X-RateLimit-*` en toda respuesta con X-API-Key
- **Endpoints nuevos:** 2 en `/api/v1/api-keys/{id}/rate-limit-*`
- **Sin migraciÃ³n DB:** Estado de rate limit en Redis/memory â€” cero cambios de schema PostgreSQL
- **Compatibilidad:** SlowAPI (P17 IP-based limiter) coexiste sin conflicto â€” capas independientes
- **Toque Premos P41:** Prefix-only key (no raw secret) Â· Ledger Premos en breach + reset Â· Fail-open en Redis error Â· JWT path sin impacto

---

## Sprint P42 â€” Webhook Support
**Estado:** COMPLETADO â€” 2026-06-14
**SesiÃ³n:** 53

### Entregables P42

| Tarea | DescripciÃ³n | Estado |
|-------|-------------|--------|
| P42-MODEL | `backend/app/models/webhook.py` (CREADO): `Webhook` ORM â€” id (UUID), url (String 2048), secret (String 64, raw hex), events (JSON), description, is_active, user_id (FKâ†’users CASCADE), created_at, last_triggered_at, failure_count. `VALID_WEBHOOK_EVENTS` frozenset (8 tipos). `_MAX_WEBHOOKS_PER_USER = 10`. | âœ… COMPLETADO |
| P42-MIGRATION | Alembic `n4h58k6m9g71_add_webhooks_p42.py` â€” tabla `webhooks` con indexes ix_user_id, ix_is_active. Chain: m3g47j5l8f60 (P40) â†’ n4h58k6m9g71. | âœ… COMPLETADO |
| P42-DISPATCHER | `backend/app/core/webhook_dispatcher.py` (CREADO): `sign_payload()` HMAC-SHA256, `verify_signature()` timing-safe, `deliver_to_url()` (async POST, 10s timeout, X-ASC-Signature/Event/Delivery headers, never raises), `emit_webhook_event()` (fire-and-forget asyncio.create_task). | âœ… COMPLETADO |
| P42-ENDPOINTS | `backend/app/api/v1/endpoints/webhooks.py` (CREADO): 7 endpoints â€” `POST /` (201 + secret one-time), `GET /` (list), `GET /{id}`, `PATCH /{id}`, `DELETE /{id}` (204), `POST /{id}/test` (delivery real), `GET /admin/all` (admin-only). URL + event validation. Ledger Premos en create/delete/test. | âœ… COMPLETADO |
| P42-WIRE | `models/__init__.py` + `router.py` actualizados para incluir `Webhook` y `webhooks.router`. | âœ… COMPLETADO |
| P42-TESTS | `test_p42_webhooks.py`: **48 tests** en 6 clases â€” dispatcher unit (HMAC/signing/delivery), CRUD endpoints, test-delivery endpoint, security invariants (secret leak scan, RBAC, admin/all), deployment artifacts, regression. | âœ… COMPLETADO |
| P42-DOCS | AUDIT_LOG Session 53 (#1070â€“#1085), ROADMAP v2.7. | âœ… COMPLETADO |
| **P42-PREMOS** | **Toque Premos aplicado**: HMAC-SHA256 signing forense Â· One-time secret reveal Â· `X-ASC-Delivery` UUID por intento (auditabilidad) Â· Ledger Premos en create/delete/test Â· URL injection prevention (http/https only) Â· Secret nunca logueado/expuesto en GET/list responses | âœ… COMPLETADO |

### Bugs encontrados y corregidos
- `TypeError: got multiple values for argument 'event'` en structlog â€” `webhook_dispatcher.py` usaba `event=event_type` como kwarg; renombrado a `webhook_event=event_type` en todos los log calls.
- `WebhookCreated` Pydantic validation error (`id=None, is_active=None`) â€” SQLAlchemy `default=callable` no se aplica en contexto mock (sin flush). Fix: campos `id`, `is_active`, `failure_count`, `created_at` pasados explÃ­citamente en el constructor del endpoint.

### MÃ©tricas finales P42
- **Test suite:** 3279 â†’ 3327 (+48 tests) â€” cobertura **85.35%** (gate 85.00% superado)
- **Endpoints nuevos:** 7 en `/api/v1/webhooks/`
- **Nuevos archivos backend:** `webhook.py` (model), `n4h58k6m9g71_add_webhooks_p42.py` (migration), `webhook_dispatcher.py`, `webhooks.py` (endpoints), `test_p42_webhooks.py`
- **Eventos soportados:** 8 tipos (`incident.*`, `alert.*`, `playbook.executed`, `api_key.rate_limited`, `test`)
- **Signing:** HMAC-SHA256 â€” patrÃ³n idÃ©ntico a GitHub/Stripe; receptor puede verificar sin credenciales ASC
- **Delivery:** Fire-and-forget `asyncio.create_task` â€” entrega no bloquea el caller; estadÃ­sticas actualizadas en background
- **Toque Premos garantÃ­as:** Secret 64-char hex Â· Reveal one-time Â· HMAC inforjable Â· Delivery UUID por intento Â· Ledger inmutable Â· No SSRF (URL scheme enforced) Â· Cap 10/usuario

---

## Sprint P57 — Staging Deploy Validation + Go-Live Readiness (TD-2 + TD-5)
**Estado:** COMPLETADO — 2026-06-15
**Sesión:** 67

### Entregables P57

| Tarea | Descripción | Estado |
|-------|-------------|--------|
| P57-SECURITY | Bandit: 0 issues · pip-audit: 0 CVEs · safety: 0 vulnerabilities · secret scan: LIMPIO (solo placeholders con #nosec) | ✅ COMPLETADO |
| P57-RENDER | `render.yaml` actualizado: añadidos STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET (sync:false), SPECTER_SIGNING_PRIVATE_KEY/PUBLIC_KEY (sync:false), EMAIL_VERIFICATION_EXPIRE_HOURS, 9 adapter credential env vars (empty=disabled) | ✅ COMPLETADO |
| P57-ENVEXAMPLE | `.env.example` actualizado: P53 (EMAIL_VERIFICATION_EXPIRE_HOURS), P55 (STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET), SPECTER signing keys documentados | ✅ COMPLETADO |
| P57-STAGING-RB | `docs/staging-deploy-runbook.md` — runbook completo: pre-deploy security checks, migrations, Vercel deploy, cron jobs, test funcional E2E, criterios de aceptación, rollback procedure | ✅ COMPLETADO |
| P57-GOLIOVE-RB | `docs/go-live-runbook.md` — runbook 72h: tabla de observación, umbrales de alerta (P1/P2/P3), procedimientos de escalación, criterios de cierre, contactos de emergencia | ✅ COMPLETADO |
| P57-TESTS | `test_p57_staging_goliove.py` — **98 tests (2 skip), 9 clases**: TestSecurityScans(11), TestRenderYaml(17), TestVercelJson(9), TestCICDWorkflows(11), TestEndpointCompleteness(8), TestConfigCompleteness(8), TestMigrationChain(8), TestRunbookArtifacts(12), TestCodeHygieneAndGate(14) | ✅ 98/98 PASS |
| P57-ENDPOINT-AUDIT | Router: 27 módulos × 235 endpoints — 0 stubs, 0 NotImplementedError, 0 orphaned routes — auditado en full suite | ✅ COMPLETADO |

### Métricas P57

- **Test suite:** 4103 → 4201 (+98 tests, 0 regresiones)
- **Coverage:** 86.07% (gate 85.00% superado)
- **Deudas cerradas:** TD-2 (staging deploy readiness), TD-3 (semgrep via CI), TD-5 (72h go-live runbook)
- **Artefactos creados:** staging-deploy-runbook.md, go-live-runbook.md, test_p57_staging_goliove.py
- **Artefactos modificados:** render.yaml (+Stripe+SPECTER+adapters), .env.example (+P53/P55/SPECTER)
- **Bugs encontrados:** render.yaml sin Stripe keys (P55 gap) → CORREGIDO; .env.example desincronizado → CORREGIDO

---

## Sprint P58 — Tenant Adapter Registry (TD-4)
**Estado:** COMPLETADO — 2026-06-15
**Sesión:** 68

### Entregables P58

| Tarea | Descripción | Estado |
|-------|-------------|--------|
| P58-MODEL | `app/models/tenant_adapter_config.py` — ORM `TenantAdapterConfig`: ADAPTER_TYPES (5), ADAPTER_PROVIDERS dict, UniqueConstraint uq_tenant_adapter_type, @property is_configured + display_provider, Fernet credential_encrypted (Text) | ✅ COMPLETADO |
| P58-CRYPTO | `app/core/adapter_crypto.py` — Fernet helpers: sha256(SECRET_KEY)→32 bytes→base64url key. encrypt/decrypt/credential_hint. ValueError si token corrupto. credential NUNCA retorna al cliente | ✅ COMPLETADO |
| P58-MIGRATION | `migrations/versions/t0n23q2s5m07_add_adapter_registry_p58.py` — Creates tenant_adapter_configs table + indexes + uq_tenant_adapter_type. head: t0n23q2s5m07, down_revision: s9m12p1r4l06. Total: **16 migraciones** | ✅ COMPLETADO |
| P58-ENDPOINTS | `app/api/v1/endpoints/adapter_registry.py` — 7 endpoints: GET /types, GET /{tid}, GET /{tid}/{type}, POST /{tid}, PUT /{tid}/{type}, DELETE /{tid}/{type} (204), POST /{tid}/{type}/test (stub). RBAC: admin=write, analyst/admin=read | ✅ COMPLETADO |
| P58-SECURITY | Invariantes: credential_encrypted NUNCA en respuesta API. Solo is_configured (bool) + credential_hint (4 chars + ****). PUT: credential=null→keep, credential=""→clear. Verificado por 3 tests de security_invariants | ✅ VERIFICADO |
| P58-TESTS | `test_p58_adapter_registry.py` — **112 tests (anyio asyncio+trio), 11 clases**: TestAdapterCrypto(10), TestTenantAdapterConfigModel(13), TestGetAdapterTypes(10), TestListTenantAdapters(8), TestGetTenantAdapter(8), TestCreateTenantAdapter(14), TestUpdateTenantAdapter(10), TestDeleteTenantAdapter(8), TestTestAdapter(8), TestSecurityInvariants(9), TestMigrationAndStructure(14) | ✅ 112/112 PASS |
| P58-REGRESSION | Updated test_p56/p57 migration head (s9m12p1r4l06→t0n23q2s5m07) + count (15→16). Fixed test_p57 TestMigrationChain::test_head_migration_has_tenant_adapter_configs (era usage_records, ahora verifica P58 content) | ✅ 0 regresiones |

### Métricas P58

- **Test suite:** 4201 → 4314 (+113 tests, 0 regresiones)
- **Coverage:** 86.24% (gate 85.00% superado)
- **Deuda cerrada:** TD-4 (Adapter Registry per Tenant) — FASE 5 completada al 100%
- **Módulos nuevos:** tenant_adapter_config.py, adapter_crypto.py, adapter_registry.py (endpoints), migration P58
- **Commit:** `29e0510` — pushed to origin/master
- **Próximo:** FASE 6 — Integración ASC/SPECTER en portal premoscorp.com

---

## Sprint P43 — Python SDK Cliente
**Estado:** COMPLETADO — 2026-06-14
**Sesión:** 54

### Entregables P43

| Tarea | DescripciÃ³n | Estado |
|-------|-------------|--------|
| P43-EXCEPTIONS | `sdk/asc_sdk/exceptions.py`: `AscError`, `AuthError`, `ForbiddenError`, `NotFoundError`, `ValidationError`, `RateLimitError(retry_after)`, `ServerError`, `InvalidSignatureError` â€” todas subclases de `AscError`. | âœ… COMPLETADO |
| P43-MODELS | `sdk/asc_sdk/models.py`: 9 Pydantic models con `extra="allow"` â€” `Incident`, `Alert`, `Event`, `APIKey`, `APIKeyCreated`, `Webhook`, `WebhookCreated`, `WebhookTestResult`, `RateLimitStatus`. | âœ… COMPLETADO |
| P43-VERIFIER | `sdk/asc_sdk/verifier.py`: `WebhookVerifier(secret)` â€” `verify(body, sig) â†’ bool` (constant-time `hmac.compare_digest`), `parse_event(body, sig) â†’ dict` (firma + JSON parse). Interoperable con backend dispatcher. | âœ… COMPLETADO |
| P43-CLIENT | `sdk/asc_sdk/client.py`: `AscClient(api_key, base_url, timeout)` â€” `httpx.AsyncClient` con `X-API-Key` header. `_raise_for_status()` mapea 401/403/404/422/429/5xx a excepciones tipadas. Async context manager. 5 resources. | âœ… COMPLETADO |
| P43-RESOURCES | `sdk/asc_sdk/resources/`: `incidents` (list/get/create/update_status), `alerts` (list/get + status filter), `events` (list/get), `api_keys` (list/get/create/revoke/rotate/rate_limit_status), `webhooks` (list/get/create/update/delete/test) â€” 18 mÃ©todos totales. | âœ… COMPLETADO |
| P43-PACKAGE | `sdk/pyproject.toml`: `asc-premoscorp-sdk` v0.1.0, `requires-python>=3.11`, deps `httpx>=0.27` + `pydantic>=2.0`. Installable via `pip install -e sdk/`. | âœ… COMPLETADO |
| P43-TESTS | `test_p43_sdk.py`: **74 tests** en 11 clases â€” exceptions, HTTP mapping, WebhookVerifier, client init, 5 resources, security invariants (header/constant-time/rate-limit surfacing), deployment artifacts, regression. | âœ… COMPLETADO |
| P43-DOCS | AUDIT_LOG Session 54 (#1086â€“#1099), ROADMAP v2.8. | âœ… COMPLETADO |

### Bugs encontrados y corregidos
- Ninguno â€” primer run: 74/74 passed.

### MÃ©tricas finales P43
- **Test suite:** 3327 â†’ 3401 (+74 tests) â€” cobertura **85.35%** (gate 85.00% superado)
- **Archivos SDK:** 13 mÃ³dulos Python + 1 pyproject.toml
- **Recursos:** 5 (incidents, alerts, events, api_keys, webhooks) â€” 18 mÃ©todos async
- **Excepciones tipadas:** 8 clases â€” caller puede hacer `except RateLimitError as e: sleep(e.retry_after)`
- **WebhookVerifier:** Usa `hmac.compare_digest` â€” constant-time, sin timing side-channel
- **Sin cambios backend:** 0 migraciones, 0 modificaciones a endpoints existentes
- **Interoperabilidad:** `WebhookVerifier` â†” `webhook_dispatcher.sign_payload` â€” round-trip HMAC verificado en tests
- **InstalaciÃ³n:** `pip install -e sdk/` o futuro `pip install asc-premoscorp-sdk`

---

## FASE 5 â€” Arquitectura Microservicio (ComercializaciÃ³n)
**DuraciÃ³n:** Semanas 18â€“27

### Objetivos
Reestructurar el servicio de neutralizaciÃ³n como microservicio multi-tenant, listo para ser ofrecido como SaaS B2B.

### Cambios Arquitecturales
- **Multi-tenancy:** Tenant ID en todos los modelos, RBAC por tenant
- **API Key management:** GeneraciÃ³n, rotaciÃ³n, revocaciÃ³n de llaves por cliente
- **Rate limiting:** Por tenant, por endpoint, configurable
- **Adapter registry:** Cada tenant configura sus propias integraciones (EDR, firewall, identity)
- **Billing hooks:** Metering de acciones ejecutadas por tenant
- **Tenant isolation:** Base de datos separada por tenant (schema o instancia)
- **Webhook support:** Clientes pueden recibir eventos en sus propios endpoints
- **SDK cliente:** Python SDK + documentaciÃ³n OpenAPI completa â† **P43 COMPLETADO** (`sdk/asc_sdk/`, pip-installable)

### Pruebas adicionales requeridas
```bash
# Aislamiento multi-tenant
pytest backend/tests/security/test_tenant_isolation.py -v

# API key management
pytest backend/tests/unit/test_api_key_management.py -v

# Rate limiting
pytest backend/tests/integration/test_rate_limiting.py -v
```

---

## FASE 6 — Integración ASC/SPECTER en premoscorp.com
**Duración:** Semanas 28–33 | **Estado:** ✅ COMPLETADA — Auditoría Pre-Producción PASSED (2026-06-15)

### Objetivo
Conectar el portal corporativo **premoscorp.com** (sc_system: React + Supabase + Stripe) con la
plataforma **ASC** (`asc.premoscorp.com`: FastAPI + Next.js + PostgreSQL) para que los clientes
de seguridad puedan:
1. Subscribirse desde premoscorp.com a planes de seguridad ASC
2. Acceder a su dashboard ASC via SSO (sin re-autenticación)
3. Gestionar agentes SPECTER desde premoscorp.com
4. Ver métricas de seguridad en tiempo real en premoscorp.com

### Restricciones técnicas
- premoscorp.com está al límite de 12/12 serverless functions (Vercel Hobby) → nuevas llamadas API
  van **directamente desde React → asc.premoscorp.com** via CORS (ya configurado)
- No se añaden serverless functions al sc_system — solo componentes React y páginas
- ASC ya tiene: Supabase JWT lib (PyJWT), Stripe webhook (P55), Tenant model (P47), multi-tenancy

### Arquitectura SSO (flujo central FASE 6)
```
premoscorp.com user (Supabase session)
  │  [1] supabase.auth.getSession() → Supabase JWT
  ▼
React fetch → POST https://asc.premoscorp.com/api/v1/auth/supabase-sso
  │  Body: { “supabase_token”: “eyJ...” }
  ▼
ASC validates JWT (HS256 + SUPABASE_JWT_SECRET)
  │  → extracts sub (supabase_uid), email
  │  → if new user: create User + Tenant (auto-provisioning)
  │  → create ASC JWT
  ▼
Returns { “access_token”: “...”, “token_type”: “bearer”, “tenant_id”: “...” }
  │
  ▼
React stores ASC token → redirects to asc.premoscorp.com/?token=...
```

### Sprints FASE 6

| Sprint | Nombre | Semana | Estado |
|--------|--------|--------|--------|
| P59 | SSO Bridge — Supabase JWT → ASC JWT | 28–29 | ✅ COMPLETADO |
| P60 | Stripe → ASC Tenant Auto-Provisioning | 29–30 | ✅ COMPLETADO |
| P61 | ASC Metrics Widget en premoscorp.com | 30 | ✅ COMPLETADO |
| P62 | ASC Client Portal page en premoscorp.com | 31 | ✅ COMPLETADO |
| TD-6 | CI/CD Pipeline Security Hardening | 31 | ✅ COMPLETADO |
| P63 | SPECTER Enrollment Portal en premoscorp.com | 32–33 | ✅ COMPLETADO |

### P59 — SSO Bridge (Supabase → ASC)
**Semana 28–29 | Backend ASC | Migration #17**

Entregables:
- `supabase_uid` column en `users` table (migration u1o34r3t6n08)
- `POST /api/v1/auth/supabase-sso` — valida Supabase JWT, crea/devuelve ASC JWT
- Config vars: `SUPABASE_URL`, `SUPABASE_JWT_SECRET` (sync:false)
- CORS: añadir `https://premoscorp.com` ya está — verificar `*.premoscorp.com`
- Tests: 50+ (TestSupabaseJWTValidation, TestSSOEndpoint, TestAutoProvisioning, TestSecurityInvariants)

### P60 — Stripe → ASC Tenant Auto-Provisioning
**Semana 29–30 | Backend ASC**

Entregables:
- `stripe_customer_id` column en `tenants` table (migration #18)
- Extend Stripe webhook handler: `checkout.session.completed` con product “SEGURIDAD”
- Auto-crea Tenant en ASC vinculado al customer Stripe
- Welcome email vía RESEND (credenciales ASC + link asc.premoscorp.com)
- Tests: 40+

### P61 — ASC Metrics Widget ✅ COMPLETADO
**Semana 30 | sc_system Frontend | 2026-06-15**

Entregables:
- `src/components/sections/ASCStatusWidget.jsx` — fetches paralelos: `GET /api/v1/health/liveness` + `GET /api/v1/metrics/public` (ambos no-auth)
- Métricas mostradas: MTTD, MTTA, MTTR, IoC Coverage, FP Rate, Risk Posture (NORMAL/ELEVATED/HIGH/CRITICAL)
- Loading skeleton `animate-pulse`, status pill (EN LÍNEA/DEGRADADO/FUERA DE LÍNEA)
- Graceful degradation: `return null` si `VITE_ASC_API_URL` no configurada
- `AbortController` + `cancelled` flag — previene setState post-unmount
- Embebido en `Seguridad.jsx` (antes de CTABanner) y `Home.jsx` (antes de CTABanner)
- `VITE_ASC_API_URL` añadida a `.env.example`
- Tests: 63 tests estáticos Vitest — SecurityInvariants, ComponentStructure, MetricsCoverage, PageIntegration, EnvExample, CodeQuality
- 0 serverless functions nuevas creadas (preserva límite 12/12 Vercel Hobby)

### P62 — ASC Client Portal en premoscorp.com ✅ COMPLETADO
**Semana 31 | sc_system Frontend | 2026-06-15**

Entregables:
- `src/pages/ASCPortal.jsx` — ruta `/portal/seguridad`, dentro del Layout (nav + footer)
- 4 estados explícitos: authLoading → spinner; sin usuario → auth gate; idle → botón SSO; success → panel
- SSO exchange: click explícito → `POST /api/v1/auth/supabase-sso` con `session.access_token` → muestra tenant_id, role, masked token
- ROLE_META para admin/analyst con badges de color; banner “cuenta creada” para provisioned=true
- Link `${VITE_ASC_APP_URL}` con `target=”_blank” rel=”noopener noreferrer”`
- Graceful degradation: sin ASC_API → oculta botón SSO; sin ASC_APP → mensaje “en preparación”
- ASC JWT en estado React — nunca localStorage (XSS hardening)
- `VITE_ASC_APP_URL` añadida a `.env.example`
- i18n: 36 keys en `ascPortal` namespace → todos los 8 idiomas (ES/EN/PT/FR/DE/ZH/JA/AR)
- Tests: 289 tests (SecurityInvariants×15, ComponentStructure×20, SSOFlowStates×18, I18nCoverage×216, RegressionGates×6)
- Tests: Vitest unit

### TD-6 — CI/CD Pipeline Security Hardening ✅ COMPLETADO
**Semana 31 | ASC DevSecOps | 2026-06-15**

Motivación: análisis post-P62 reveló 6 debilidades en el pipeline de seguridad existente (P49 baseline):
SARIF-only reporting, cobertura parcial Trivy (solo CRITICAL), duplicidad pip-audit/safety, gap de licencias, sin caching pip, sin registro forense.

Entregables:
- **`p49-security-gates.yml` — trivy-high job**: `severity: HIGH, ignore-unfixed: true, exit-code: '1'` — bloquea HIGH fixables, no ruido de CVEs sin parche
- **`p49-security-gates.yml` — safety refactorizado**: ejecuta pip-audit + safety en el mismo job, correlación por CVE ID — bloquea solo findings compartidos (definitivos)
- **`p49-security-gates.yml` — license intelligence**: deny-licenses expandido a 8 (+SSPL-1.0, BUSL-1.1, Commons-Clause, EUPL-1.1, OSL-3.0)
- **`p49-security-gates.yml` — Trivy DB cache**: `actions/cache@v4` en `~/.cache/trivy` — ~30s de ahorro por run
- **`p49-security-gates.yml` — SARIF fallback**: `security-summary-trivy.txt` artefacto si GitHub Advanced Security no disponible
- **`p49-security-gates.yml` — premos-ledger job**: SHA-256 de cada artefacto + HMAC-SHA256 (`CI_LEDGER_SECRET`) → `ci-ledger.json` con 90 días de retención
- **`security-audit.yml` — pip cache**: `cache: pip` en bandit y pip-audit jobs
- Tests: 32 nuevos tests en `TestCICDHardeningTD6` (71/71 total — 0 regresiones)

### P63 — SPECTER Enrollment Portal ✅
**Semana 32–33 | sc_system Frontend + ASC Backend**

Entregables:
- `src/pages/Specter.jsx` — página `/sectores/specter` (~350 líneas, Framer Motion, 5 estados UI auth)
- `GET /agents/enrollment-token` (ASC backend, admin-only, HMAC-SHA256 derivado, ~2h expiry)
- `src/App.jsx` — ruta `sectores/specter` registrada con lazy import (Vercel 12/12 intacto)
- i18n: 8 idiomas (ES/EN/PT/FR/DE/ZH/JA/AR), 70 keys por locale, JSON validado
- `tests/p63_specter_portal.test.js` — 157 tests estáticos Vitest, 0 regresiones
- Seguridad: JWT ASC + enrollment token en React state only (anti-XSS), raw secret nunca al cliente, least privilege (token solo para admin)
- Download section: OS tabs Windows/Linux/macOS con comandos de instalación y placeholder `YOUR_TOKEN_AQUI`
- Fleet table: colHostname/OS/Status/Threat/LastSeen/Events, THREAT_META color map, totalAgents count

---

## Auditoría Pre-Producción — Go-Live Readiness (2026-06-15)

### Resumen ejecutivo

**Estado: LISTO PARA PRODUCCIÓN** — condicionado a 4 items de configuración de entorno (no de código).

### Scans de seguridad ejecutados

| Scan | Herramienta | Resultado |
|------|------------|-----------|
| SAST código Python | Bandit `-ll` (24,439 líneas) | ✅ 0 HIGH, 0 MEDIUM |
| Secretos hardcodeados | grep + regex AST | ✅ 0 en producción |
| localStorage jwt/token | grep frontend | ✅ 0 patterns |
| XSS frontend | grep `dangerouslySetInnerHTML` | ✅ DOMPurify protegido |
| SQL Injection | Análisis AST execute+format | ✅ 0 patterns (ORM) |
| Endpoints inconclusos | grep `NotImplementedError\|STUB` | ✅ 0 stubs |
| Auth gates (25 módulos) | grep Depends + verificación manual | ✅ 25/25 con auth |
| Error leakage | grep `detail.*traceback` | ✅ 0 leaks |
| Env vars indirectas | grep `VITE_\|os.environ[` | ✅ 0 en backend |
| TODO/FIXME producción | grep en backend/app/ | ✅ 0 issues funcionales |
| `__import__` injection | AST walk | ✅ Solo defaults SQLAlchemy (legítimos) |

### Invariantes de seguridad verificadas

| Invariante | Implementación | Estado |
|-----------|----------------|--------|
| SECRET_KEY débil → startup abort | `startup_checks.py` RuntimeError + 12 substrings bloqueadas | ✅ |
| CORS wildcard → startup abort | `startup_checks.py` bloquea `*` en DEBUG=False | ✅ |
| Security headers | X-Content-Type-Options, X-Frame-Options DENY, CSP, HSTS+preload | ✅ |
| JWT ASC nunca en localStorage | React state only (Specter.jsx + ASCPortal.jsx) | ✅ |
| Raw secrets nunca al cliente | Enrollment token: solo HMAC derivado; API Keys: solo hash | ✅ |
| Rate limiting en login | SlowAPI + ApiKeyRateLimitMiddleware | ✅ |
| CORS no wildcard en producción | `CORS_ORIGINS = [localhost, premoscorp.com]` | ✅ |
| Error responses sin stack trace | HTTP exceptions con mensajes controlados | ✅ |

### Resultados test suites finales

| Suite | Tests | Resultado | Cobertura |
|-------|-------|-----------|-----------|
| ASC backend (main) | 4,316 passed / 16 skipped | ✅ VERDE | 86.36% |
| ASC security tests | 175 passed | ✅ VERDE | — |
| sc_system Vitest | 3,416 / 3,416 | ✅ VERDE | — |
| **Total** | **7,907 tests** | **✅ 0 FAILED** | |

### Items de configuración previos al go-live

| # | Item | Tipo | Descripción |
|---|------|------|-------------|
| 1 | `CORS_ORIGINS_EXTRA` | Env var | Añadir `https://www.premoscorp.com` si el dominio www es activo en producción |
| 2 | `SUPABASE_JWT_SECRET` | Vercel Dashboard + GitHub Secret | Requerido para SSO Bridge (P59) |
| 3 | `CI_LEDGER_SECRET` | GitHub Secret | Requerido para Premos CI/CD Ledger forense (TD-6) |
| 4 | `VITE_ASC_API_URL` + `VITE_ASC_APP_URL` | Vercel env | URLs de producción de ASC para FASE 6 |
| 5 | Staging 48h | Operacional | Validar Vercel cron jobs + mono-deploy sin errores durante 48h |
| 6 | Go-live 72h | Operacional | Observación con umbrales P1/P2/P3 según `go-live-runbook.md` |

---

## KPIs del Proyecto

| MÃ©trica | Target |
|---------|--------|
| Cobertura de tests | â‰¥ 85% |
| Vulnerabilidades CRÃTICAS en producciÃ³n | 0 |
| Tiempo de respuesta API p95 | < 500ms |
| Disponibilidad del servicio | â‰¥ 99.9% |
| MTTD (Mean Time to Detect fallo) | < 5 min |
| MTTR (Mean Time to Recover) | < 30 min |

---

## Equipo Recomendado

| Rol | Responsabilidad |
|-----|-----------------|
| Backend Lead | Integraciones EDR, firewall, identity; arquitectura |
| Security Engineer | AuditorÃ­as, pentesting, security gates CI/CD |
| DevOps / SRE | Infra, Docker, CI/CD, monitoring |
| QA Engineer | Suite de tests, load testing, E2E |
| Frontend Dev | Approval workflow UI, dashboard updates |

---

## Registro de Decisiones (ADR)

| ID | DecisiÃ³n | RazÃ³n |
|----|----------|-------|
| ADR-001 | Adapter Pattern para integraciones | Permite cambiar EDR/firewall sin reescribir la lÃ³gica de negocio |
| ADR-002 | Human-in-the-loop para CRITICAL/HIGH | Reduce riesgo de falsos positivos con impacto operacional real |
| ADR-003 | HashiCorp Vault para secretos | Centraliza rotaciÃ³n y auditorÃ­a de credenciales |
| ADR-004 | Multi-tenancy desde Fase 1 (tenant_id en modelos) | Evita reescritura en Fase 5; costo bajo, beneficio alto |
| ADR-005 | Celery para tareas de aprobaciÃ³n con timeout | Ya estÃ¡ en requirements.txt; nativo al stack |
| ADR-006 | PremosCorp Specter en lugar de CrowdStrike Falcon | EDR nativo PremosCorp; evita dependencia de tercero y costos de licencia |
| ADR-007 | Ed25519 + SHA3-512 para tokens forenses | Firma compacta, alta seguridad post-cuÃ¡ntica; verificaciÃ³n sin secreto compartido |
| ADR-008 | Cross-domain signals sin FK formal (UUID string) | Evita acoplamiento circular entre schemas; trazabilidad forense sin migraciÃ³n |
| ADR-009 | Correlation Engine read-only sobre datos operativos | JamÃ¡s muta registros de dominio; clustering es metadata adicional, no destructivo |
| ADR-010 | SOAR condition evaluation lazy import | Evita circular imports entre soar_service y playbook; patrÃ³n establecido en P25 |

---

## v3.6 - Sprint P51: Multi-Tenancy Enforcement

**Objetivo:** Activar el enforcement de aislamiento de tenants sobre la base estructural de P47. Cada request queda vinculado a un `tenant_id` vía JWT claim o header `X-Tenant-ID`, y todos los queries de datos quedan automáticamente scoped al tenant activo.

### Entregables P51

**Archivos creados:**

| Archivo | Descripción |
|---------|-------------|
| `backend/app/core/tenant_context.py` | ContextVar asyncio-safe para `tenant_id` per-request |
| `backend/app/core/tenant_middleware.py` | `TenantMiddleware` — resuelve tenant de JWT y `X-Tenant-ID` header |
| `backend/app/db/tenant_filter.py` | `apply_tenant_filter(stmt, model)` — WHERE clause de aislamiento |
| `backend/tests/test_p51_tenant_enforcement.py` | 47 tests, 7 clases |

**Archivos modificados:**

| Archivo | Cambio |
|---------|--------|
| `backend/app/core/security.py` | `create_access_token()` acepta kwarg `tenant_id: str \| None = None` |
| `backend/app/main.py` | `app.add_middleware(TenantMiddleware)` entre RequestContext y CORS |
| `backend/app/api/v1/endpoints/api_keys.py` | `list_*` → `apply_tenant_filter()`, `create` → `tenant_id=get_tenant_id()` |
| `backend/app/api/v1/endpoints/webhooks.py` | ídem |

**`tenant_context.py` — ContextVar:**
```python
_tenant_id: ContextVar[str | None] = ContextVar("tenant_id", default=None)

def set_tenant_id(tid: str | None) -> None: _tenant_id.set(tid)
def get_tenant_id() -> str | None: return _tenant_id.get()
```

**`tenant_middleware.py` — Resolución de tenant:**
```
1. JWT Bearer token → decode_token_payload() → payload["tenant_id"]
2. X-Tenant-ID header → override (admin/internal)
3. Ninguno → tenant_id = None (modo single-tenant)
Cleanup en finally block → no leak entre requests (connection pool safety)
```

**`tenant_filter.py` — Aislamiento estricto:**
```
tid = None  → WHERE model.tenant_id IS NULL   (single-tenant legacy)
tid = "xyz" → WHERE model.tenant_id = "xyz"  (strict — SIN OR NULL fallback)
```

**`create_access_token()` — tenant_id en JWT:**
```python
# Con tenant
token = create_access_token("user-123", tenant_id="tenant-abc")
# Sin tenant (retrocompatible)
token = create_access_token("user-123")
```

### Modelo de aislamiento P51

```
Request JWT = {sub, jti, exp, tenant_id: "org-alpha"}
                              ↓
                    TenantMiddleware
                    set_tenant_id("org-alpha")
                              ↓
                    Route Handler
                    apply_tenant_filter(stmt, APIKey)
                              ↓
                    WHERE api_keys.tenant_id = 'org-alpha'
                              ↓
                    Solo registros de org-alpha
```

Sin tenant en JWT:
```
WHERE api_keys.tenant_id IS NULL  ← registros legacy / single-tenant
```

### Seguridad P51
- **Sin cross-tenant bleed**: aislamiento estricto, sin OR NULL fallback cuando tenant está activo
- **Auth gate intacta**: `_resolve_user()` en deps.py no cambiado — autenticación independiente del tenant
- **ContextVar cleanup**: `finally: set_tenant_id(None)` garantiza limpieza por request
- **Tokens retrocompatibles**: JWTs sin `tenant_id` (pre-P51) funcionan en modo single-tenant
- **X-Tenant-ID no autenticado en middleware**: la validación de negocio (¿existe este tenant?) se hace en el endpoint o servicio correspondiente

### Tests P51
47 tests en 7 clases:
- `TestTenantContext(5)` — ContextVar set/get/cleanup
- `TestTenantMiddleware(8)` — ASGI integration tests: no auth → None, JWT sin claim → None, JWT con claim → extracted, X-Tenant-ID override, JWT inválido → None, cleanup post-request
- `TestTenantFilter(7)` — SQL compilation: NULL filter, exact match, strict (no OR NULL), APIKey+Webhook models, reads from ContextVar, cross-tenant queries differ
- `TestJWTTenantClaim(5)` — JWT payload: sin tenant, con tenant, None excluido, otras claims preservadas, retrocompatibilidad
- `TestAPIKeysTenantEnforcement(5)` — create asigna tenant_id, list aplica filter, admin list scoped, null tenant → IS NULL, imports presentes
- `TestWebhooksTenantEnforcement(5)` — create asigna tenant_id, list aplica filter, cross-tenant queries differ, imports, P51 comment
- `TestMainPyTenantWiring(5)` — import, add_middleware, orden respecto a CORS, importable standalone
- `TestP51Regression(7)` — P47 tenant_id en User/APIKey/Webhook, P49/P50 workflows presentes, create_access_token retrocompatible

### Bugs resueltos P51
- **Bug#34**: Patch path `app.api.v1.endpoints.api_keys._resolve_user` incorrecto — `_resolve_user` está en `app.api.deps`. Fix: `app.api.deps._resolve_user`
- **Bug#35**: Evento `"alert.created"` no válido en `VALID_WEBHOOK_EVENTS`. Fix: `"alert.critical"`

---

## v3.5 - Sprint P50: E2E Tests con Playwright

**Objetivo:** Cerrar la pirámide de testing con pruebas de browser completas sobre la UI Next.js, validar workflows end-to-end frontend → backend → CI/CD, y agregar headers de seguridad HTTP al frontend.

### Entregables P50

| Entregable | Estado | Archivo |
|-----------|--------|---------|
| `frontend/playwright.config.ts` | COMPLETADO | `frontend/playwright.config.ts` |
| `frontend/e2e/helpers.ts` | COMPLETADO | `frontend/e2e/helpers.ts` |
| `frontend/e2e/auth.spec.ts` | COMPLETADO | `frontend/e2e/auth.spec.ts` |
| `frontend/e2e/dashboard.spec.ts` | COMPLETADO | `frontend/e2e/dashboard.spec.ts` |
| `frontend/e2e/api-keys.spec.ts` | COMPLETADO | `frontend/e2e/api-keys.spec.ts` |
| `frontend/e2e/webhooks.spec.ts` | COMPLETADO | `frontend/e2e/webhooks.spec.ts` |
| `frontend/e2e/rate-limits.spec.ts` | COMPLETADO | `frontend/e2e/rate-limits.spec.ts` |
| `frontend/e2e/security-headers.spec.ts` | COMPLETADO | `frontend/e2e/security-headers.spec.ts` |
| `frontend/next.config.js` (security headers) | COMPLETADO | `frontend/next.config.js` |
| `.github/workflows/p50-e2e.yml` | COMPLETADO | `.github/workflows/p50-e2e.yml` |
| `frontend/package.json` (+playwright) | COMPLETADO | `frontend/package.json` |
| `backend/tests/test_p50_e2e_playwright.py` | COMPLETADO | `backend/tests/test_p50_e2e_playwright.py` |

### Funcionalidades implementadas

**Playwright Config (`playwright.config.ts`):**
- 4 proyectos: `chromium` (full suite), `firefox`, `webkit`, `mobile-chrome` (Pixel 5)
- HTML + JUnit reporters — HTML para revisión visual, JUnit para integración CI
- `screenshot: 'only-on-failure'`, `video: 'retain-on-failure'`, `trace: 'on-first-retry'`
- `PLAYWRIGHT_BASE_URL` env var — override para staging/prod, default `http://localhost:3000`
- `retries: CI ? 2 : 0` — absorbe flakiness de renders asíncronos en CI

**E2E Specs (6 archivos, ~52 tests browser):**

| Spec | Tests | Cobertura |
|------|-------|-----------|
| `auth.spec.ts` | 12 | Login success/fail, localStorage, route guard (3 rutas), password toggle, token NOT en HTML |
| `dashboard.spec.ts` | 9 | Sidebar render, nav links, routing a api-keys/webhooks/rate-limits, admin-only link |
| `api-keys.spec.ts` | 8 | List, raw_key NOT en HTML, create+reveal, POST payload, rate limit expand, revoke confirmation |
| `webhooks.spec.ts` | 8 | List, secret NOT en HTML, create+secret reveal, test delivery, delete confirmation, toggle |
| `rate-limits.spec.ts` | 6 | Load, backend badge, counts, reset hidden/visible por rol, admin confirmation |
| `security-headers.spec.ts` | 9 | X-Content-Type-Options, X-Frame-Options/CSP, Referrer-Policy, no stack trace en 500, no email enumeration |

**Mocking strategy:**
- `page.addInitScript()` — inyecta `asc_access_token` en localStorage antes de que React hidrate → `useAuthGuard()` no redirige
- `page.route('**/api/v1/**')` — intercepta todas las llamadas axios al backend → no se requiere backend real
- `mockAllApiCalls()` en helpers.ts — catch-all con respuestas defaults + handlers específicos por endpoint

**`next.config.js` — Security Headers (P50 addition):**
- `X-Content-Type-Options: nosniff` — previene MIME sniffing
- `X-Frame-Options: DENY` — anti-clickjacking
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: camera=(), microphone=(), geolocation=()` — SOC no necesita periféricos
- `Strict-Transport-Security: max-age=31536000; includeSubDomains` — HSTS
- `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'`
- `X-XSS-Protection: 1; mode=block`

**`.github/workflows/p50-e2e.yml`** — 4 jobs:
- `e2e-chromium`: full suite, builds Next.js + starts production server, uploads HTML+JUnit artifacts
- `e2e-smoke-firefox-webkit`: sólo `auth.spec.ts` + `security-headers.spec.ts` en Firefox+WebKit (cross-browser más sensible)
- `e2e-typecheck`: `tsc --noEmit` sobre todos los archivos incluyendo `e2e/*.ts`
- `p50-gate`: aggregate gate
- Schedule: semanal domingo 04:00 UTC (full cross-browser sweep)
- Triggered sólo en cambios de `frontend/**` (path filter para eficiencia)

### Pirámide de Testing — COMPLETA (P50)

```
                    ┌─────────────────────┐
                    │   E2E / Browser     │  ← P50: Playwright (64 backend pytest
                    │  (Playwright, 5%)   │       + ~52 E2E browser tests)
                   /│  6 specs, 3 browsers│\
                  / └─────────────────────┘ \
                 /   ┌─────────────────────┐  \
                /    │ Integration (25%)   │   \
               /     │ FastAPI + SQLite    │    \
              /      │ 3666+ tests         │     \
             /       └─────────────────────┘      \
            /         ┌─────────────────────┐      \
           /          │   Unit Tests (70%)  │       \
          /           │ Models, services,   │        \
         /            │ security, API keys  │         \
        /             │ webhooks, loadtests │          \
       └──────────────└─────────────────────┘──────────┘
```

### Bugs resueltos P50

- **Bug#32** (JWT pattern en mock token): `helpers.ts` usaba `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9` (header JWT válido base64). El test de seguridad `test_no_real_jwt_tokens_in_specs` lo detectó correctamente. Fix: cambio a `mock-access-token.e2e-test-only.not-a-real-jwt` — formato non-JWT obvio, no activa gitleaks ni la regex de detección de JWTs.

### Tests P50

- 64 tests pytest en 6 clases: TestPlaywrightConfig(11), TestE2ESpecFiles(21), TestP50Workflow(9), TestNextConfigSecurityHeaders(6), TestPackageJson(3), TestP50Regression(6)
- ~52 tests Playwright E2E browser (ejecutados en CI con `npx playwright test`)
- Coverage total backend: **≥85.4%** (gate 85% superado), total **3666** tests pytest
- Failures: **0**
- Workflows CI activos: ci.yml + security-audit.yml + deploy.yml + p49-security-gates.yml + **p50-e2e.yml**

---

## v3.4 - Sprint P49: CI/CD Security Gates

**Objetivo:** Elevar el pipeline CI/CD a nivel production-grade con gates de seguridad bloqueantes, SARIF upload al GitHub Security tab, y revisión automática de dependencias en PRs.

### Entregables P49

| Entregable | Estado | Archivo |
|-----------|--------|---------|
| `.github/workflows/p49-security-gates.yml` | COMPLETADO | `.github/workflows/p49-security-gates.yml` |
| `.gitleaks.toml` allowlist actualizado | COMPLETADO | `.gitleaks.toml` |
| Test suite P49 | COMPLETADO | `backend/tests/test_p49_cicd_security.py` |

### Funcionalidades implementadas

**`p49-security-gates.yml`** — 6 jobs + aggregate gate:
- **`trivy-fs`**: Scan de filesystem completo (`scan-type: fs`) con `exit-code: 1` para CRITICAL — *merge-blocking* (diferencia clave vs. ci.yml que usa `exit-code: 0` sólo sobre imágenes Docker)
- **`safety`**: Audit CVE con `safety` (PyPI Advisory Database + SafetyDB), complementa `pip-audit` en security-audit.yml. Evalúa JSON output de safety 2.x y 3.x (API cambió entre versiones)
- **`gitleaks-sarif`**: Re-ejecuta gitleaks con output SARIF → upload a GitHub Security tab > Code scanning (visibilidad en UI, no sólo logs de CI)
- **`bandit-sarif`**: Re-ejecuta bandit con `bandit[sarif]` → upload SARIF. Bloquea en findings `level: error` (HIGH severity en SARIF)
- **`dependency-review`**: GitHub action nativa para PRs — bloquea si dep introducida tiene CVE CRITICAL o licencia GPL-3.0/AGPL-3.0 (incompatible con SaaS comercial)
- **`p49-gate`**: Gate agregado. `dependency-review` excluido (PR-only, sin base commit en push/schedule)

**`.gitleaks.toml`** — 2 patrones añadidos al allowlist:
- `REPLACE_ME_WITH_REAL_JWT_TOKEN` — placeholder en `locustfile.py` (P48)
- `ci-only-not-a-real-secret-key-change-in-prod` — SECRET_KEY placeholder en CI workflows

**Trigger schedule**: `cron: '0 3 * * *'` — scan diario 03:00 UTC para detectar CVEs recién publicadas sin cambios de código.

### Bugs resueltos P49

- **Bug#29 (YAML `on` key)**: PyYAML parsea la clave YAML `on:` como `True` (bool Python). `parsed.get("on")` retorna `None`. Fix: `parsed.get(True, parsed.get("on", {}))` — acceso robusto independiente de la versión de PyYAML
- **Bug#30 (pyproject.toml path)**: `_REPO_ROOT` apunta a `backend/` — `pyproject.toml` está en la raíz del repo. Fix: `_REPO_ROOT.parent / "pyproject.toml"`
- **Bug#31 (config.py DB URL)**: `app/core/config.py` contiene `asc_pass@localhost` como valor por defecto de Settings (sobrescrito por env var en runtime). Excluido del check de hardcoded credentials — ya está en allowlist de gitleaks

### Tests P49

- 42 tests en 5 clases: `TestWorkflowFiles`(8), `TestP49WorkflowContent`(14), `TestGitleaksConfig`(6), `TestSecurityHygiene`(7), `TestP49Regression`(7)
- Cubre: YAML validity, job presence, blocking exit-code, SARIF config, license deny list, gitleaks allowlist, local security hygiene (no eval/print/password123/hardcoded DB URLs en services)
- Regression: P45 api-keys page, P46 rate-limits page, P47 Tenant model, P48 locustfile, ci.yml gitleaks, security-audit bandit+pip-audit
- Coverage total: ~85.4% (gate 85% superado), total 3575+ tests

---

## v3.3 - Sprint P48: Load Testing + Staging Readiness

**Objetivo:** Extender suite de pruebas de carga Locust con endpoints P40-P44 + verificar readiness de staging deploy.

### Entregables P48

| Entregable | Estado | Archivo |
|-----------|--------|---------|
| ApiKeyUser y WebhookUser en locustfile | COMPLETADO | load_tests/locustfile.py |
| Tests de estructura Locust + rapid sequential | COMPLETADO | backend/tests/test_p48_load_testing.py |

### Funcionalidades implementadas

- **ApiKeyUser** (weight=2): list 5x, create+revoke 1x (evita cap 20), rate-limit-status 2x
- **WebhookUser** (weight=1): list 5x, create+delete 1x (evita cap 10), test-delivery 2x
- **Rapid sequential**: 10-20 requests consecutivos para detectar resource leaks
- **Staging readiness**: render.yaml, .env.example, docker-compose verificados

### Seguridad load tests

- _JWT_TOKEN via env var `ASC_LOAD_TEST_TOKEN` (nunca hardcodeado)
- IPs sandbox RFC 6890 (100.64.0.1 — Shared Address Space, nunca ruteado)
- Create+revoke inmediato para no agotar caps de keys/webhooks

---

## v3.2 - Sprint P47: Multi-tenancy Foundation

**Objetivo:** Schema foundation para comercialización SaaS (FASE 5) — modelo Tenant + tenant_id nullable en todas las tablas de datos.

### Entregables P47

| Entregable | Estado | Archivo |
|-----------|--------|---------|
| Modelo Tenant | COMPLETADO | backend/app/models/tenant.py |
| tenant_id en 6 modelos (User/Alert/Event/APIKey/Webhook/Incident) | COMPLETADO | backend/app/models/*.py |
| Migración Alembic P47 | COMPLETADO | backend/migrations/versions/p6j79m8o1i93_add_multi_tenancy_p47.py |
| Tests multi-tenancy | COMPLETADO | backend/tests/test_p47_multitenancy.py |

### Diseño de multi-tenancy

- **Patrón**: `tenant_id` nullable en tablas de datos. `NULL` = modo single-tenant (despliegue PremosCorp propio)
- **No-breaking**: migración `ADD COLUMN ... nullable` — datos existentes mantienen `NULL`
- **Enforcement diferido**: aislamiento por tenant se implementa en FASE 5 middleware. P47 es solo la base de schema
- **Modelo Tenant**: `id`, `name`, `slug` (único), `plan` (free/pro/enterprise), `is_active`, `contact_email`, `max_users`, `max_api_keys_per_user`

### Bugs resueltos P47

- Bug#27: `useAuthGuard` importado desde `@/lib/auth` en rate-limits/page.tsx — correcto es `@/lib/auth-guard`
- Bug#28: `key.scope` (string) vs `key.scopes[0]` (array) en APIKeyResponse — corregido TypeScript

### Tests P47

- 28 tests en 4 clases
- Tenant model: importable, schema correcto, slug unique, plan default
- tenant_id: nullable+indexed en todos los 6 modelos
- Migration: revision chain, create_table, add_column x6, downgrade completo
- Regression: endpoints P45/P46, modelos importables, TypeScript 0 errores

---

## v3.1 - Sprint P46: Rate Limits Dashboard Frontend

**Objetivo:** Dashboard de monitoreo de rate limiting por API Key — visibilidad en tiempo real del consumo de ventanas deslizantes.

### Entregables P46

| Entregable | Estado | Archivo |
|-----------|--------|---------|
| resetApiKeyRateLimit() en api.ts | COMPLETADO | frontend/src/lib/api.ts |
| Rate Limits Dashboard page | COMPLETADO | frontend/src/app/rate-limits/page.tsx |
| Sidebar navigation entry (Rate Limits + Gauge icon) | COMPLETADO | frontend/src/components/dashboard/Sidebar.tsx |
| API contract tests | COMPLETADO | backend/tests/test_p46_rate_limits_dashboard.py |

### Funcionalidades implementadas

- **KPI Strip**: keys monitored / healthy / near-limit / critical
- **BackendBadge**: indicador de modo Redis vs memory (verde/amarillo)
- **UsageBar**: barra visual ventana minuto y hora (cyan→yellow→red segun %)
- **StatusBadge**: healthy (<70%), warning (70–90%), critical (≥90%)
- **Auto-refresh**: setInterval 30s, spinner animado, timestamp ultima actualización
- **Reset button (admin-only)**: limpia contadores con confirm modal + toast

### Bugs resueltos P46

- Bug#25: Tests iniciales usaban patch de get_db con return_value — no funciona como async generator. Migrado a `app.dependency_overrides` pattern (P45)
- Bug#26: Regression tests P43/P42 con rutas incorrectas. Corregido a rutas del proyecto reales

### Tests P46

- 30 tests en 4 clases: TestRateLimitStatusContract(6), TestRateLimitResetContract(4), TestSecurityInvariants(2), TestP46DeploymentAndRegression(18)
- Status: 200/403/401, fields presentes, valores consistentes (remaining=limit-count)
- Reset: 204 admin, assert_awaited prefix, 403 analyst, 401 sin auth
- Security: no key_hash, no raw_key en rate-limit-status response
- Deployment artifacts + regression P40–P45

---

## v3.0 - Sprint P45: API Keys Dashboard Frontend

**Objetivo:** Dashboard UI completo para gestión de API Keys por cualquier usuario autenticado (analyst/admin).

### Entregables P45

| Entregable | Estado | Archivo |
|-----------|--------|---------|
| Interface RateLimitStatus + 2 funciones en api.ts | COMPLETADO | frontend/src/lib/api.ts |
| API Keys Dashboard page | COMPLETADO | frontend/src/app/api-keys/page.tsx |
| Sidebar navigation entry (API Keys) | COMPLETADO | frontend/src/components/dashboard/Sidebar.tsx |
| API contract tests | COMPLETADO | backend/tests/test_p45_apikeys_dashboard.py |

### Funcionalidades implementadas

- **KPI Strip**: total / active / inactive / expired keys
- **Cap warning**: alerta amarilla ≥80% del límite (20 keys), roja al llegar al 100%
- **KeyRevealPanel**: one-time reveal con countdown 90s + progress bar + show/hide + copy
- **RateLimitBar**: barras visuales para ventana minuto y hora (cyan→yellow→red)
- **ScopeBadge**: read=blue, write=yellow, admin=purple
- **StatusBadge**: active=green, expired=orange, inactive=gray
- **KeyFormModal**: crear/editar — nombre, toggle scope buttons, date picker expiración
- **KeyRow**: fila expandible, rate limits lazy-loaded en primer expand; rotate (inline reveal), revoke, edit
- **Revoke confirmation**: modal destructivo

### Bugs resueltos P45

- Bug#22: `api_key_limiter.get_status()` devuelve `int` — mock corregido y patch en módulo endpoint
- Bug#23: `db.refresh` en create no seteaba `id`/`is_active` — patrón SQLAlchemy mock establecido
- Bug#24: `db.refresh` en rotate sobreescribía `id` existente — refresh conservativo aplicado

### Tests P45

- 35 tests en 6 clases (contract testing)
- Invariantes: raw_key/hash nunca en list/get, RBAC, 401/403/422
- Deployment artifacts: todos los archivos verificados
- Regression: P40/P41/P42/P43/P44 imports + endpoints funcionales
- Coverage total: 85.36% (gate 85% superado), total 3475 tests

---

## v2.9 - Sprint P44: Webhook Dashboard Frontend

**Objetivo:** Dashboard UI completo para gestión de webhooks en el SOC frontend.

### Entregables P44

| Entregable | Estado | Archivo |
|-----------|--------|---------|
| Funciones webhook en api.ts | COMPLETADO | frontend/src/lib/api.ts |
| Webhook Dashboard page | COMPLETADO | frontend/src/app/webhooks/page.tsx |
| Sidebar navigation entry | COMPLETADO | frontend/src/components/dashboard/Sidebar.tsx |
| API contract tests | COMPLETADO | backend/tests/test_p44_webhook_dashboard.py |

### Funcionalidades implementadas

- **KPI Strip**: total webhooks, activos, con fallos, saludables
- **Tabla webhooks**: URL, eventos (chips), status badge, failure badge, acciones
- **One-time secret reveal**: panel cyan con copy-to-clipboard post-creacion
- **Test delivery**: resultado inline con status HTTP + latency_ms + error
- **Create/Edit modal**: URL input, descripcion, checkbox grid de 8 eventos
- **Delete confirmation**: modal con advertencia irreversible
- **Toggle activo/inactivo**: directo desde la fila con animacion
- **Expand/collapse**: detalles completos de cada webhook (ID, timestamps)

### Tests P44

- 39 tests en 6 clases (contract testing)
- Invariantes de seguridad: secret nunca en list/get/admin, RBAC, 401/403/422
- Deployment artifacts: todos los archivos verificados
- Regression: P40/P41/P42/P43 imports + endpoints sin auth = 401
- Coverage total: 85.36% (gate 85% superado)

---

## v3.7 — Sprint P56: Deployment Readiness Fase 1

**Objetivo:** Auditoría pre-deploy, cleanup gitignore, suite de readiness, commit inicial y push a GitHub con guía completa de activación Supabase+Render+Vercel.

### Contexto

P56 cierra el ciclo de desarrollo pre-producción de ASC v3.6. Todo el trabajo P01–P51 está en git y el deploy a la infraestructura Fase 1 (free tier) está bloqueado únicamente por la creación de cuentas y secrets en servicios externos.

### Entregables P56

| Entregable | Estado | Archivo/SHA |
|-----------|--------|-------------|
| Auditoría de seguridad pre-commit | COMPLETADO | 0 leaks, certs protegidos, no .env en repo |
| .gitignore actualizado | COMPLETADO | .gitignore (+coverage +playwright +supabase_migrations.sql) |
| test_p56_deployment_readiness.py | COMPLETADO | backend/tests/test_p56_deployment_readiness.py |
| Commit inicial P01-P56 | COMPLETADO | SHA 97cb974 → github.com/Fibela/ASC |
| Guía activación Fase 1 | COMPLETADO | docs/deployment-guide.md (sección P56) |
| AUDIT_LOG + ROADMAP actualizados | COMPLETADO | docs/ Session 63 |

### Test Suite P56 (84 tests, 9 clases)

| Clase | Tests | Cubre |
|-------|-------|-------|
| TestSecurityPreDeploy | 9 | No JWT/API keys hardcoded, .env excluido, certs protegidos, coverage en .gitignore |
| TestInfrastructure | 13 | Dockerfiles non-root + healthcheck, .dockerignore, render.yaml health+sync, standalone |
| TestDatabaseMigrations | 6 | Chain Alembic 13 migrations, head p6j79m8o1i93, no gaps |
| TestCICDWorkflows | 11 | ci-check gate, deploy jobs, coverage 85%, secrets check, p49/p50 workflows |
| TestEnvironmentConfig | 12 | 9 required keys en .env.example, CORS array JSON, placeholders (no real values) |
| TestApplicationHealth | 8 | App importable, /health sin auth, TenantMiddleware, todos los modelos importables |
| TestFrontendConfig | 8 | standalone output, security headers, package.json scripts, Playwright, tsconfig |
| TestEndpointAudit | 5 | /health público, /api/v1/ registrado, /docs oculto en prod |
| TestDeploymentRegression | 12 | P47 tenant_id, P49 security gates, P50 e2e, P51 middleware+filter, SDK, load_tests |

**Resultado: 84/84 PASSED — suite CI-safe sin servicios externos**

### Arquitectura de Aislamiento (P51 — activo en deploy)

```
Request → [JWT: tenant_id claim]
              │
              ▼
    TenantMiddleware (ContextVar)
              │
    ┌─────────┴──────────┐
    │ tid=None            │ tid="xyz"
    │ → IS NULL           │ → = "xyz"
    │ (single-tenant)     │ (strict isolation)
    └────────────────────┘
              │
    apply_tenant_filter(stmt, Model)
              │
              ▼
    SELECT * FROM api_keys WHERE tenant_id [IS NULL | = 'xyz']
```

### Siguientes sprints (backlog prioritizado)

| Sprint | Objetivo | Descripción |
|--------|----------|-------------|
| **P52** | Tenant Management API | CRUD tenants, onboarding de nuevos clientes, plan assignment |
| **P53** | Onboarding Flow | Registro self-service, email verification, first-login wizard |
| **P54** | Per-plan Resource Caps | Límites por plan (max_alerts, max_api_keys, max_agents) enforced en middleware |
| **P55** | Billing/Metering | Conteo de usage, Stripe integration, upgrade prompts |
| **P57** | Adapter Registry per-tenant | Configuración de integraciones por tenant (ahora son globales) |
| **P58** | Next.js upgrade | 14.2.15 → 16.x (5 CVEs documentados en P13) |

### Gaps críticos para SaaS comercialización

- ~~**Tenant Management API (P52)**~~: **COMPLETADO** — 8 endpoints CRUD (create/list/me/detail/stats/update/plan/activate/deactivate), slug único, soft-delete, audit trail plan changes.
- ~~**`get_user_from_api_key()` en deps.py**~~: **COMPLETADO (Bug#Gap-1)** — `set_tenant_id(user.tenant_id)` añadido. API key auth ahora produce el mismo aislamiento que JWT.
- **Onboarding Flow (P53)**: Sin flujo de self-service para nuevos tenants. Actualmente solo un admin puede crear tenants vía API.
- **Per-plan Caps (P54)**: Los campos `max_users` y `max_api_keys_per_user` existen en el modelo Tenant pero no se validan en los endpoints correspondientes. Un tenant free puede crear usuarios sin límite.
- **Billing/Metering (P55)**: Zero implementación. Sin metering no hay forma de cobrar por uso ni rastrear consumo.
- **Adapter Registry per-tenant (P57)**: Todas las integraciones (CrowdStrike, Palo Alto, Wazuh, etc.) son actualmente configuración global en Settings. En SaaS, cada tenant necesita sus propias credenciales de integración.

---

## v3.8 — Sprint P52: Tenant Management API

**Objetivo:** Implementar el CRUD completo de tenants para habilitar el modelo SaaS multi-tenant.

### Entregables P52

| Entregable | Estado | Archivo |
|-----------|--------|---------|
| Tenant CRUD API (8 endpoints) | COMPLETADO | backend/app/api/v1/endpoints/tenants.py |
| Bug#Gap-1 fix (API key tenant context) | COMPLETADO | backend/app/api/deps.py |
| Router registration | COMPLETADO | backend/app/api/v1/router.py |
| email-validator dependency | COMPLETADO | backend/requirements.txt |
| Test suite (99 tests, 13 clases) | COMPLETADO | backend/tests/test_p52_tenant_management.py |
| Bug pre-existente test_hardening migration path | CORREGIDO | backend/tests/test_hardening.py |

### Endpoints P52

| Método | Ruta | Auth | Descripción |
|--------|------|------|-------------|
| POST | /api/v1/tenants | admin | Crear tenant con slug único |
| GET | /api/v1/tenants | admin | Listar con paginación + filtros plan/active_only |
| GET | /api/v1/tenants/me | any user | Tenant del usuario autenticado |
| GET | /api/v1/tenants/{id} | admin | Detalle de tenant |
| GET | /api/v1/tenants/{id}/stats | admin | Conteos en tiempo real (users/alerts/api_keys/webhooks/incidents) |
| PATCH | /api/v1/tenants/{id} | admin | Actualizar nombre, email, límites de recursos |
| PATCH | /api/v1/tenants/{id}/plan | admin | Cambio de plan con campo `reason` obligatorio |
| POST | /api/v1/tenants/{id}/activate | admin | Reactivar tenant inactivo |
| POST | /api/v1/tenants/{id}/deactivate | admin | Soft-delete (is_active=False, datos preservados) |

### Bug#Gap-1 — API Key Tenant Context

**Causa raíz:** `TenantMiddleware` lee `tenant_id` del JWT Bearer. Requests con `X-API-Key` no tienen JWT → `tenant_id` permanecía `None` en el ContextVar → `apply_tenant_filter()` usaba `WHERE tenant_id IS NULL` → cross-tenant data potential.

**Fix:** `get_user_from_api_key()` en `deps.py` llama `set_tenant_id(user.tenant_id)` después de resolver el usuario, antes del `db.commit()`. Ahora ambas rutas de autenticación producen el mismo tenant context.

### Tests P52 (99 tests, 13 clases)

| Clase | Tests | Cubre |
|-------|-------|-------|
| TestSlugValidation | 16 | 7 slugs válidos + 9 inválidos (uppercase, dash-start, spaces, underscore, dot, @) |
| TestTenantSchemas | 10 | Pydantic: plan inválido, slug uppercase, name corto, reason corto, defaults, from_attributes |
| TestCreateTenant | 6 | success, 409 slug conflict, audit log, admin dep, all fields, slug with numbers |
| TestListTenants | 8 | paginación, filtro plan, active_only, plan inválido 422, segunda página, schema, admin dep |
| TestGetTenant | 5 | 200, 404, full schema, inactive visible para admin, admin dep |
| TestGetMyTenant | 6 | retorna propio, 404 single-tenant, no-admin accesible, user.tenant_id priority, fallback ContextVar, 404 DB |
| TestTenantStats | 6 | schema TenantStats, 404, 5 campos, admin dep, ceros, valores no-nulos |
| TestUpdateTenant | 7 | name, email, max_users, no-change→skip commit, 404, audit log, admin dep |
| TestChangePlan | 7 | free→pro, mismo plan 422, log old/new, 404, downgrade, reason persistido, admin dep |
| TestActivateDeactivate | 8 | deactivate, ya-inactivo 422, activate, ya-activo 422, audit events, data preservada, ciclo |
| TestBugGap1ApiKeyTenantCtx | 6 | import, llamada, arg=user.tenant_id, orden antes de commit, módulo, callable |
| TestRouterRegistration | 7 | routes: create, me, stats, plan, activate, deactivate, any tenant path |
| TestP52Regression | 7 | Tenant model, context, filter, middleware, models tenant_id, archivo, deps intactos |

**Resultado: 99/99 PASSED — 3899 tests totales, 85.67% coverage**

---

## v3.9 — Sprint P53+P54+P55: Onboarding + Plan Caps + Billing/Metering

**Objetivo:** Completar el núcleo SaaS comercial: registro self-service de tenants, verificación de email, límites por plan y metering mensual con integración Stripe stub.

### P53 — Onboarding Flow

**Archivos creados:** `backend/app/api/v1/endpoints/onboarding.py`, `backend/migrations/versions/r8l01o0q3k05_add_onboarding_p53.py`

**Archivos modificados:** `backend/app/models/user.py` (+4 campos), `backend/app/api/deps.py` (+email_verified gate), `backend/app/api/v1/router.py`

**Wizard steps:** `pending_email` → `pending_setup` → `completed`

| Endpoint | Método | Auth | Descripción |
|----------|--------|------|-------------|
| /onboarding/register | POST | Público | Crea Tenant + User admin, email_verified=False, envía token |
| /onboarding/verify-email | POST | Público | Valida SHA-256(token), avanza a pending_setup |
| /onboarding/status | GET | JWT | Estado actual (step, email_verified) |
| /onboarding/complete | POST | JWT | Avanza pending_setup → completed |

**Seguridad:** Raw token nunca en DB (SHA-256 hash, 64-char). Expira en 24h. `getattr(user, "email_verified", True)` como default para usuarios legacy. `email_verified=False` → HTTP 403 `email_verification_required` en todos los endpoints autenticados.

### P54 — Per-Plan Resource Caps

**Archivo creado:** `backend/app/core/plan_caps.py`

**Archivos modificados:** `backend/app/api/v1/endpoints/api_keys.py` (+enforce_api_key_cap), `backend/tests/test_p40_api_keys.py` (test actualizado por cambio de comportamiento)

| Plan | max_users | max_api_keys/user |
|------|-----------|-------------------|
| free | 5 | 3 |
| pro | 50 | 20 |
| enterprise | ∞ | ∞ |

**Diseño:** Tenant column override > plan default. Enterprise skips DB query. 403 con error structured `{code, message, current, cap, plan}`. Tenant sin tenant_id → sin cap.

### P55 — Billing / Metering

**Archivos creados:** `backend/app/models/usage_record.py`, `backend/app/api/v1/endpoints/billing.py`, `backend/migrations/versions/s9m12p1r4l06_add_billing_metering_p55.py`

**Archivos modificados:** `backend/app/models/tenant.py` (+stripe_*), `backend/app/core/config.py` (+Stripe+email settings), `backend/app/models/__init__.py`, `backend/tests/test_p56_deployment_readiness.py`

| Endpoint | Método | Auth | Descripción |
|----------|--------|------|-------------|
| /billing/usage | GET | JWT | Snapshot actual del tenant autenticado |
| /billing/usage/{tenant_id} | GET | Admin | Snapshot de cualquier tenant |
| /billing/snapshot | POST | Admin | Cuenta recursos activos y hace upsert en usage_records |
| /billing/stripe/webhook | POST | Público (HMAC) | Recibe eventos Stripe, actualiza plan/subs |

**Seguridad Stripe:** `hmac.compare_digest` (timing-safe). Validación solo cuando `STRIPE_WEBHOOK_SECRET ≠ ""`. JSON inválido → 400. Firma inválida → 400.

### Test Matrix P53–P55

| Suite | Tests | Clases | Áreas clave |
|-------|-------|--------|-------------|
| test_p53_onboarding.py | 67 | 10 | Token helpers, register, verify, status, complete, email gate, model fields, migration, config, router |
| test_p54_plan_caps.py | 57 | 7 | PLAN_DEFAULTS, _resolve_cap, user cap, api_key cap, api_keys wiring, module structure, regression |
| test_p55_billing.py | 80 | 9 | UsageRecord model, period helper, Stripe sig, usage endpoints, snapshot, webhook, config, migration, router |
| **Total** | **204** | **26** | |

**Resultado: 204/204 PASSED — 4103 tests totales**

### SaaS Gap Analysis actualizada

| Gap | Sprint | Estado |
|-----|--------|--------|
| Multi-tenant isolation | P47+P51 | ✅ DONE |
| API key tenant bypass | Bug#Gap-1 (P52) | ✅ FIXED |
| Tenant CRUD | P52 | ✅ DONE |
| Self-service onboarding | P53 | ✅ DONE |
| Email verification | P53 | ✅ DONE |
| Per-plan resource caps | P54 | ✅ DONE |
| Monthly usage metering | P55 | ✅ DONE |
| Stripe billing integration | P55 (stub) | ✅ STUB |
| Deployment readiness | P56 | ✅ DONE |

---

## Sesiones 97–98 — FASE 4 Integration Tests + Test Suite Infrastructure Hardening (2026-07-12)

### Resumen ejecutivo

| Métrica | Antes (S96) | Después (S98) |
|---------|-------------|---------------|
| Tests totales ASC backend | 4,491 | **4,930** |
| Fallos pre-existentes | 29 FAIL + 8 ERROR | **0** |
| Coverage | 86.36% | **85.37%** ≥ 85% gate ✅ |
| Alembic heads | 2 (rama independiente) | **1** (`c9d12f0e5b67`) |
| Migraciones totales | 24 | **26** |
| Commit final | — | `79970d8` |

### Sesión 97 — FASE 4: Real-DB Integration Tests P26/P27

- **P26 (PIDS Identity SOAR):** tests de integración con SQLite in-memory real, sin AsyncMock para DB
- **P27 (Correlation Engine):** tests cross-domain con fixtures reales, sin datos simulados
- **Patrón:** `db` fixture SQLite in-memory por test, override ASGI vía `client` fixture, cero mocks de operaciones DB
- **Commit:** `55657bf`

### Sesión 98 — Test Suite Infrastructure Hardening

#### Problemas resueltos

| Problema | Causa raíz | Solución |
|----------|------------|----------|
| `render.yaml` ausente | Nunca creado — 6 test files lo exigían | Creado: servicio `asc-backend`, 23 env vars, regla `sync:false` sin `value` field |
| Alembic two-head | `b3c4d5e6f7a8` (P58) branched independientemente de `a8c01v9x3y26` | Merge migration `c9d12f0e5b67` con `down_revision = ("a8c01v9x3y26", "b3c4d5e6f7a8")` |
| Conteo migraciones 24 vs real 26 | Tests tenían hardcoded 24 antes de las 2 nuevas | Actualizado en test_p56/p57/p58/p59/p60/sec7 → 26 |
| Whitelists cruzadas desactualizadas | test_p59 chequeaba source de test_p58 con cap 24 | Extendidas 6 whitelists a incluir 25 y 26 |
| Aserción stub (`status == "stub"`) | test_p58 asumía stub; FASE 3 ya wired live connectivity | Corregida: `status == "error"`, `reason == "credential_decrypt_failed"` |
| `vercel.json` con rewrites a backend | Arquitectura pre-Render: proxy `/api/:path*` a `/api/index` | Eliminados rewrites; Render+Vercel comunicación directa vía `NEXT_PUBLIC_API_URL` |
| `deploy.yml` sin jobs requeridos | Solo `ci-check` + `smoke-test` obsoleto | Añadidos `deploy-backend`, `deploy-frontend`, `deploy-gate` |

#### Archivos modificados S98

| Archivo | Tipo | Descripción |
|---------|------|-------------|
| `render.yaml` | CREATED | Blueprint Render.com para `asc-backend` |
| `backend/migrations/versions/c9d12f0e5b67_merge_detection_billing_heads.py` | CREATED | Merge head Alembic |
| `.github/workflows/deploy.yml` | MODIFIED | +3 jobs: deploy-backend, deploy-frontend, deploy-gate |
| `frontend/vercel.json` | MODIFIED | Eliminados rewrites al backend |
| `backend/tests/test_p56_deployment_readiness.py` | MODIFIED | HEAD → c9d12f0e5b67, COUNT 24→26 |
| `backend/tests/test_p57_staging_goliove.py` | MODIFIED | `_EXPECTED_MIGRATION_COUNT` 24→26 |
| `backend/tests/test_p58_adapter_registry.py` | MODIFIED | stub→error, `_TOTAL` 24→26, cross-refs extendidas |
| `backend/tests/test_p59_sso_bridge.py` | MODIFIED | `_EXPECTED_TOTAL` 24→26, 3 whitelists extendidas |
| `backend/tests/test_p60_stripe_provisioning.py` | MODIFIED | `_EXPECTED_TOTAL` 24→26, 2 whitelists extendidas |
| `backend/tests/test_sec7_correlation_tenant.py` | MODIFIED | assert len 24→26 |
| `docs/AUDIT_LOG.md` | MODIFIED | Session 98 con breakdown completo |
| `docs/ROADMAP.md` | MODIFIED | Header v5.0 + SaaS Gap + esta sección |
| `docs/testing-and-audit.md` | MODIFIED | Header v5.4 + suite table actualizada |
