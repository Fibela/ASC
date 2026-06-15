# ASC PremosCorp — Deployment Guide

> "Calidad sobre Comodidad" — deployment escalado al ritmo del negocio.

---

## Resumen de Fases

| Fase | Cuándo | Stack | Costo mensual |
|------|--------|-------|---------------|
| **Fase 1** | Ahora (pre-comercialización) | Supabase + Render + Vercel | **$0** |
| **Fase 2** | Cuando ASC genere ingresos | Docker Compose auto-hosting | Variable según servidor |

---

## Fase 1 — Stack Gratuito (Actual)

### Arquitectura

```
Internet
  │
  ├─► Vercel (Next.js frontend)          — free tier, CDN global
  │       │ fetch /api/v1/...
  │       ▼
  ├─► Render (FastAPI backend)           — free tier, spin-down en inactividad
  │       │ asyncpg
  │       ▼
  │   Supabase (PostgreSQL)              — free tier, 500 MB, backups diarios
  │
  │   Redis → NO REQUERIDO               — Celery desactivado (OK para MVP)
  │   Celery → NO REQUERIDO
```

### Componentes y free tiers

| Servicio | Free tier | Límite práctico |
|----------|-----------|-----------------|
| [Supabase](https://supabase.com) | 500 MB PostgreSQL, backups 7 días | ~500k registros de alertas |
| [Render](https://render.com) | 750h/mes compute, spin-down 15min | OK para uso no 24/7 |
| [Vercel](https://vercel.com) | 100 GB bandwidth, builds ilimitados | Sin límite práctico para el portal |
| [Upstash](https://upstash.com) | 10,000 cmds/día Redis | Activar cuando se necesite Celery |

### Setup Paso a Paso

#### 1. Supabase — PostgreSQL

```bash
# 1. Crear proyecto en https://supabase.com (sin tarjeta de crédito)
# 2. Project Settings → Database → Connection String → URI
#    Seleccionar modo "Session" (puerto 5432)
# 3. Copiar la URL — formato:
#    postgresql+asyncpg://postgres.[ref]:[pass]@aws-0-us-east-1.pooler.supabase.com:5432/postgres

# 4. Configurar .env con la URL de Supabase:
echo 'DATABASE_URL=postgresql+asyncpg://postgres.XXX:PASS@aws-0-us-east-1.pooler.supabase.com:5432/postgres' >> .env

# 5. Ejecutar migraciones — IMPORTANTE: usar SQL Editor de Supabase
# asyncpg NO es compatible con el pooler de Supabase en transaction mode.
# La conexión directa requiere el add-on IPv4 ($4/mes) en free tier.
# Solución: generar SQL offline y ejecutarlo en el SQL Editor de Supabase.

cd backend
# Generar SQL de todas las migraciones (sin conexión a DB):
alembic upgrade head --sql > supabase_migrations.sql

# Si hay UUIDs None en el SQL (Python uuid4() no exporta en modo offline):
python gen_migration_sql.py   # script que reemplaza NULLs con UUIDs reales

# Luego en Supabase Dashboard → SQL Editor → pegar y ejecutar supabase_migrations.sql
# La cabeza esperada: l2f36i4k7e59

# 6. Verificar desde Supabase SQL Editor:
# SELECT version FROM alembic_version;  -- debe retornar: l2f36i4k7e59

# 7. Smoke test de conectividad (asyncpg directo):
python -c "
import asyncio, asyncpg, os
async def test():
    url = os.environ['DATABASE_URL'].replace('postgresql+asyncpg://', '')
    conn = await asyncpg.connect('postgresql://' + url)
    ver = await conn.fetchval('SELECT version()')
    print('PostgreSQL OK:', ver[:50])
    await conn.close()
asyncio.run(test())
"
```

**Nota importante — asyncpg y Supabase free tier:**
- Usar **puerto 5432** (Session mode), NO 6543 (Transaction mode/pgbouncer)
- asyncpg no es compatible con pgbouncer en transaction mode
- SSL se negocia automáticamente — no se necesita `?ssl=require` con asyncpg 0.29+
- La conexión directa (db.[ref].supabase.co:5432) requiere add-on IPv4 ($4/mes) en free tier
- **Solución para free tier**: generar SQL offline con `alembic upgrade head --sql` y ejecutarlo en Supabase SQL Editor (completado en P34-POSTGRES, Session 46)

#### 2. Render — FastAPI Backend

**Opción A — render.yaml (recomendado, P38)**

El archivo `render.yaml` en la raíz del repo declara el servicio. Render lo detecta automáticamente al conectar el repo de GitHub.

```bash
# 1. Crear cuenta en https://render.com
# 2. New → Blueprint → Connect GitHub repo
#    Render detectará render.yaml y creará el servicio asc-backend

# 3. Variables que necesitan valor manual (sync:false en render.yaml):
#    DATABASE_URL  = postgresql+asyncpg://postgres.XXX:PASS@aws-0-us-east-1.pooler.supabase.com:5432/postgres
#    SECRET_KEY    = $(python -c "import secrets; print(secrets.token_hex(32))")
#    CORS_ORIGINS  = ["https://asc-premoscorp.vercel.app","https://asc.premoscorp.com"]

# 4. Health check configurado en render.yaml → /health (no auth)
# 5. Auto-deploy activo: cada push a main hace deploy automático
```

**Opción B — Setup manual en Render Dashboard**

```
New → Web Service → Connect GitHub repo
Root Directory: backend
Build Command:  pip install -r requirements.txt
Start Command:  uvicorn app.main:app --host 0.0.0.0 --port $PORT
Runtime:        Python 3.12
Health Check:   /health
```

**IMPORTANTE — Render free tier:**
- Spin-down después de 15 min sin requests (cold start ~30s en el primer request)
- Para producción continua → Render Starter ($7/mes) o Fase 2 Docker
- Secret `RENDER_SERVICE_ID` + `RENDER_API_KEY` → GitHub Actions → deploy automático (ver `.github/workflows/deploy.yml`)

#### 3. Vercel — Next.js Frontend

```bash
# 1. Push to main → Vercel auto-deploys si conectaste el repo en Vercel Dashboard
# 2. O deploy manual:
npm install -g vercel
cd frontend
vercel deploy --prod

# 3. Variables en Vercel Dashboard (Settings → Environment Variables):
#    NEXT_PUBLIC_API_URL = https://asc-backend.onrender.com

# 4. Custom domain (opcional):
#    Vercel Dashboard → Domains → asc.premoscorp.com
#    DNS: CNAME asc → cname.vercel-dns.com

# Security headers: vercel.json en frontend/ ya los define (P38).
```

**GitHub Actions → CD automático (P38):**
Configurar en GitHub → Settings → Secrets and variables → Actions:
- `RENDER_API_KEY` — Render Dashboard → Account → API Keys
- `RENDER_SERVICE_ID` — Render Dashboard → Service → Settings → Service ID
- `VERCEL_TOKEN` — Vercel Dashboard → Settings → Tokens
- `VERCEL_ORG_ID` + `VERCEL_PROJECT_ID` — .vercel/project.json después de `vercel link`

#### 4. Variables de entorno mínimas para Fase 1

```env
# Mínimo absoluto para levantar en Render+Supabase:
SECRET_KEY=<generado_con_secrets.token_hex(32)>
DATABASE_URL=postgresql+asyncpg://postgres.XXX:PASS@aws-0-us-east-1.pooler.supabase.com:5432/postgres
REDIS_URL=                          # vacío — Celery en modo no-op
CORS_ORIGINS=["https://asc-premoscorp.vercel.app","https://asc.premoscorp.com"]
DEBUG=false
```

### Qué funciona sin Redis (Fase 1)

| Funcionalidad | Estado |
|---|---|
| API completa (auth, alerts, detection, playbooks, SOAR, PCDI, PIDS, IR) | ✅ |
| SPECTER agent registration, commands, telemetry | ✅ |
| Honeypot (canary tokens, signed evidence) | ✅ |
| SSE notifications (modo local — single-worker) | ✅ |
| Threat hunting + PCDI scoring | ✅ |
| Executive Reports + PIIL signing | ✅ |
| Celery Beat tasks (proactive escalation, SLA checks, scheduled reports) | ❌ desactivados |
| Rate limiting multi-worker (SLOWAPI_STORAGE_URI) | ❌ solo in-memory |

**Impacto de Celery desactivado:** Los análisis de escalación y SLA siguen existiendo pero son *lazy* (se ejecutan cuando un endpoint los llama, no periódicamente). Para un MVP con tráfico limitado esto es aceptable.

---

## Fase 2 — Docker Compose Auto-Hosting (Comercialización)

### Cuándo migrar

Migrar cuando se cumpla **cualquiera** de estas condiciones:
- ASC genera ingresos suficientes para cubrir el servidor (~$20-50/mes VPS)
- El team crece a más de 3 analistas simultáneos
- Se requieren logs de auditoría > 7 días (límite Supabase free)
- Se necesitan las tareas Celery periódicas (escalación proactiva automática)
- Requisitos de residencia de datos (datos no pueden salir de Colombia/DC específico)

### Setup Docker Compose

```bash
# 1. Requisitos mínimos del servidor:
#    VPS: 2 vCPU, 4 GB RAM, 40 GB SSD (ej: DigitalOcean Droplet $24/mes)
#    OS: Ubuntu 22.04 LTS
#    Software: Docker 24+, Docker Compose V2

# 2. Clonar repo en el servidor
git clone [repo] /opt/asc
cd /opt/asc

# 3. Configurar .env con los valores de Fase 2
cp .env.example .env
# Editar DATABASE_URL para que apunte al postgres del compose:
# DATABASE_URL=postgresql+asyncpg://asc_user:PASS@postgres:5432/asc_db

# 4. Generar certificado TLS
bash scripts/gen_selfsigned_cert.sh asc.premoscorp.com
# En producción real → Let's Encrypt:
# docker run --rm -v ./infra/nginx/certs:/etc/letsencrypt certbot/certbot \
#   certonly --webroot --webroot-path /var/www/html \
#   -d asc.premoscorp.com --agree-tos -m admin@premoscorp.com

# 5. Levantar stack completo
docker compose -f docker-compose.yml up -d --build

# 6. Aplicar migraciones (primera vez o tras upgrade)
docker compose exec backend alembic upgrade head

# 7. Verificar que todos los servicios estén healthy
docker compose ps
# Expected: postgres (healthy), redis (healthy), backend (healthy),
#           frontend (healthy), nginx (healthy)
```

### Stack Fase 2

```
Internet (80/443)
  │
  ▼
nginx (TLS termination, rate limiting, CSP)
  ├─► FastAPI backend (uvicorn, 4 workers)
  │       ├─► PostgreSQL 16 (local, persistent volume)
  │       └─► Redis 7 (local, password-protected)
  │
  ├─► Next.js frontend (standalone build)
  │
  └─► Celery Worker + Celery Beat (tareas periódicas activas)
          └─► Redis broker
```

### Migración Supabase → PostgreSQL Docker

```bash
# Exportar datos de Supabase
pg_dump "postgresql://postgres.XXX:PASS@db.XXX.supabase.co:5432/postgres" \
  --no-owner --no-acl -Fc -f asc_backup.dump

# Importar en PostgreSQL Docker
docker compose exec -T postgres pg_restore \
  -U asc_user -d asc_db --no-owner --clean < asc_backup.dump

# Verificar integridad
docker compose exec postgres psql -U asc_user asc_db \
  -c "SELECT count(*) FROM users; SELECT count(*) FROM alerts;"
```

---

## Checklist de Seguridad por Fase

### Fase 1 — Supabase

- [ ] `SECRET_KEY` generado con `secrets.token_hex(32)` — mínimo 32 chars
- [ ] `DATABASE_URL` solo en variables de entorno de Render (nunca en código)
- [ ] Supabase Row Level Security (RLS) habilitado en tablas sensibles (opcional pero recomendado)
- [ ] Supabase Dashboard → Auth → Email confirmations deshabilitado (usamos nuestro propio auth)
- [ ] Render → Environment: `DEBUG=false`
- [ ] Vercel → `NEXT_PUBLIC_API_URL` apunta a Render HTTPS (no HTTP)
- [ ] CORS_ORIGINS contiene solo el dominio de Vercel (no `*`)
- [ ] `SPECTER_SIGNING_PRIVATE_KEY` generado y configurado en Render

### Fase 2 — Docker

- [ ] Todos los secrets generados (no placeholders)
- [ ] `.env` con permisos `600` en el servidor
- [ ] TLS certificado válido (Let's Encrypt o corporativo)
- [ ] PostgreSQL y Redis sin exposición de puertos al host (solo red interna)
- [ ] `SPECTER_ENROLLMENT_SECRET` configurado (tokens de enrollment rotados)
- [ ] Firewall del servidor: solo puertos 80/443 públicos
- [ ] Backups automáticos configurados (volumen `postgres_data`)

---

## Comandos Útiles por Fase

```bash
# ── Fase 1 (local dev apuntando a Supabase) ──────────────────────────────────

# Correr migraciones contra Supabase
DATABASE_URL="postgresql+asyncpg://..." cd backend && alembic upgrade head

# Abrir psql contra Supabase desde local
psql "postgresql://postgres.XXX:PASS@db.XXX.supabase.co:5432/postgres"

# ── Tests (siempre en local con SQLite — sin tocar Supabase) ─────────────────
cd backend
python -m pytest tests/ -q --tb=short

# ── Fase 2 Docker ────────────────────────────────────────────────────────────

docker compose ps                                    # estado de servicios
docker compose logs -f backend                       # logs del backend
docker compose exec backend alembic upgrade head     # migraciones
docker compose exec backend alembic current          # revisión activa
docker compose exec postgres psql -U asc_user asc_db # psql directo
docker compose restart celery-worker                 # reiniciar workers
```

---

## P56 — Checklist de Activación (Fase 1 First Deploy)

> Estado: Código en GitHub (SHA 97cb974). Pasos pendientes que requieren acción en servicios externos.

### Paso 1 — GitHub Secrets (prerequisito para CI/CD)

Ir a `https://github.com/Fibela/ASC/settings/secrets/actions` y crear:

| Secret | Cómo obtener |
|--------|-------------|
| `SECRET_KEY` | `python -c "import secrets; print(secrets.token_hex(32))"` |
| `DATABASE_URL` | Supabase → Project Settings → Database → Connection String (Session mode, puerto 5432) |
| `CORS_ORIGINS` | `["https://<tu-proyecto>.vercel.app","https://asc.premoscorp.com"]` |
| `RENDER_API_KEY` | Render Dashboard → Account → API Keys → Create Key |
| `RENDER_SERVICE_ID` | Render Dashboard → asc-backend → Settings → Service ID |
| `VERCEL_TOKEN` | Vercel Dashboard → Settings → Tokens → Create |
| `VERCEL_ORG_ID` | `cat frontend/.vercel/project.json` tras `cd frontend && vercel link` |
| `VERCEL_PROJECT_ID` | Ídem |

### Paso 2 — Supabase

1. Crear proyecto en https://supabase.com (sin tarjeta de crédito)
2. Project Settings → Database → Connection String → modo **Session** (puerto 5432)
3. Generar SQL de migraciones: `cd backend && alembic upgrade head --sql > supabase_migrations.sql`
4. Supabase Dashboard → SQL Editor → New query → pegar y ejecutar `supabase_migrations.sql`
5. Verificar: `SELECT version FROM alembic_version;` — debe retornar `p6j79m8o1i93`
6. Auth → Disable "Enable email confirmations" (ASC usa su propio JWT, no Supabase Auth)

### Paso 3 — Render (Backend)

1. Crear cuenta en https://render.com
2. New → **Blueprint** → Connect GitHub repo `Fibela/ASC`
3. Render detecta `render.yaml` y crea el servicio `asc-backend` (Oregon, free tier)
4. En el servicio → Environment → añadir las variables con `sync: false`:
   - `SECRET_KEY` (desde GitHub Secret)
   - `DATABASE_URL` (URL de Supabase Session mode)
   - `CORS_ORIGINS` (JSON array con URL de Vercel)
   - `DEBUG=false`
   - `REDIS_URL=` (vacío — Celery desactivado en Fase 1)
5. Manual Deploy → deploy inicial
6. Smoke test: `curl https://asc-backend.onrender.com/health` → `{"status":"ok"}`

**Nota free tier:** Spin-down tras 15 min inactividad. Cold start ~30s. Para 24/7 → Render Starter $7/mes.

### Paso 4 — Vercel (Frontend)

```bash
cd frontend
npm install -g vercel
vercel link          # asocia el proyecto → genera .vercel/project.json
vercel deploy --prod
```

En Vercel Dashboard → Settings → Environment Variables:
- `NEXT_PUBLIC_API_URL` = `https://asc-backend.onrender.com`

Custom domain (opcional): Vercel → Domains → `asc.premoscorp.com` → DNS CNAME → `cname.vercel-dns.com`

### Paso 5 — Verificación final

```bash
# Backend health
curl https://asc-backend.onrender.com/health
# → {"status":"ok","version":"3.6","db":"connected"}

# Auth smoke test
curl -X POST https://asc-backend.onrender.com/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@premoscorp.com","password":"Admin@1234!","full_name":"Admin"}'
# → {"id":"...","email":"admin@premoscorp.com","role":"admin",...}

# Frontend
open https://<tu-proyecto>.vercel.app
# → Login page visible, no console errors
```

### P56 — Test Suite de Validación

```bash
# Ejecutar suite de deployment readiness (CI-safe, sin DB externa)
cd backend && python -m pytest tests/test_p56_deployment_readiness.py -v
# → 84/84 PASSED

# Suite completa con coverage
python -m pytest tests/ --cov=app --cov-fail-under=85
# → 3800 passed, coverage ≥ 85%
```
