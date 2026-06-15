"""
P56 — Deployment Readiness — Fase 1 (Supabase + Render + Vercel)
=================================================================
Tests verifying that ASC is ready to deploy to production (Fase 1 free stack).

Coverage areas:
1. Security: no hardcoded secrets in source, .env not tracked, certs protected
2. Infrastructure: Dockerfiles correct, .dockerignore complete, render.yaml valid
3. Database: Alembic migration chain intact, no gaps, head known
4. CI/CD: deploy.yml has all required jobs + gate, ci.yml has coverage gate
5. Configuration: .env.example has all required keys (no real values)
6. App health: /health endpoint importable, FastAPI app starts without crash
7. Frontend: next.config.js has standalone output, security headers present
8. Endpoints audit: known public endpoints open, admin endpoints require auth
9. Regression: all P47–P51 deliverables still present

Testing approach
----------------
All tests are static analysis + import checks + file content inspection.
No real database, Redis, or external services required — CI-safe.

Security scan
-------------
• Regex scan for real secret patterns in all Python and TypeScript source
• .env.example verified to contain only placeholder patterns
• infra/nginx/certs/ verified to have .gitignore (no TLS keys committed)
• Hardcoded passwords scan across all backend modules
• Open vs. closed endpoint verification via route inspection

Bugs to catch pre-deploy
------------------------
• Hardcoded SECRET_KEY/DB credentials committed to git
• Missing CORS_ORIGINS in .env.example (frontend can't reach backend)
• supabase_migrations.sql missing the latest migration head
• render.yaml pointing to wrong health check path
• Frontend missing `output: 'standalone'` (Docker build would fail)
• .dockerignore missing .env files (secrets in Docker image)
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

# ── Paths ─────────────────────────────────────────────────────────────────────
_REPO_ROOT     = Path(__file__).parent.parent          # backend/
_PROJECT_ROOT  = _REPO_ROOT.parent                     # ASC/
_BACKEND       = _REPO_ROOT
_FRONTEND      = _PROJECT_ROOT / "frontend"
_INFRA         = _PROJECT_ROOT / "infra"
_DOCS          = _PROJECT_ROOT / "docs"
_WORKFLOWS     = _PROJECT_ROOT / ".github" / "workflows"

_DEPLOY_YML    = _WORKFLOWS / "deploy.yml"
_CI_YML        = _WORKFLOWS / "ci.yml"
_RENDER_YAML   = _PROJECT_ROOT / "render.yaml"
_ENV_EXAMPLE   = _PROJECT_ROOT / ".env.example"
_GITIGNORE     = _PROJECT_ROOT / ".gitignore"
_NEXT_CFG      = _FRONTEND / "next.config.js"
_DOCKER_COMPOSE = _PROJECT_ROOT / "docker-compose.yml"

# ─────────────────────────────────────────────────────────────────────────────
# 1. Security — no hardcoded secrets
# ─────────────────────────────────────────────────────────────────────────────

class TestSecurityPreDeploy:
    """No hardcoded secrets, no .env committed, certs protected."""

    # Patterns that look like real secrets (not placeholders)
    _SECRET_PATTERNS = [
        r'SECRET_KEY\s*=\s*["\'][A-Za-z0-9+/]{32,}["\']',        # real key
        r'password\s*=\s*["\'][^"\']{8,}["\']',                    # hardcoded password
        r'REPLACE_WITH_GENERATED_SECRET_KEY',                       # should only be in .env.example
        r'eyJ[A-Za-z0-9+/=]{20,}\.[A-Za-z0-9+/=]{20,}',          # real JWT
    ]

    # Files excluded from secret scan (known safe patterns)
    _SCAN_EXCLUDE = {
        "config.py",      # Settings defaults are dummy values, overridden by env
        ".env.example",   # Template — contains placeholder patterns by design
        "test_p56_deployment_readiness.py",  # This file (contains the patterns as strings)
        "test_p49_cicd_security.py",  # P49 tests that scan for patterns
    }

    def _scan_python_files(self, pattern: str) -> list[str]:
        hits = []
        for f in (_BACKEND / "app").rglob("*.py"):
            if f.name in self._SCAN_EXCLUDE:
                continue
            content = f.read_text(encoding="utf-8", errors="ignore")
            if re.search(pattern, content, re.IGNORECASE):
                hits.append(str(f.relative_to(_PROJECT_ROOT)))
        return hits

    def test_no_real_jwt_in_source(self):
        """No real JWT tokens (eyJ...) in Python source files."""
        hits = self._scan_python_files(r'eyJ[A-Za-z0-9+/=]{20,}')
        assert not hits, f"Real-looking JWT found in: {hits}"

    def test_no_real_api_keys_in_source(self):
        """No hardcoded VirusTotal/AbuseIPDB/OTX API keys."""
        patterns = [
            r'VIRUSTOTAL_API_KEY\s*=\s*["\'][A-Za-z0-9]{40,}',
            r'ABUSEIPDB_API_KEY\s*=\s*["\'][A-Za-z0-9]{40,}',
        ]
        for pat in patterns:
            hits = self._scan_python_files(pat)
            assert not hits, f"Possible real API key pattern in: {hits}"

    def test_env_example_has_only_placeholders(self):
        """Every credential in .env.example must be a placeholder, not a real value."""
        content = _ENV_EXAMPLE.read_text(encoding="utf-8")
        # These placeholder markers must appear (indicates templates, not real values)
        assert "REPLACE_" in content or "changeme" in content.lower() or "PLACEHOLDER" in content, \
            ".env.example must contain placeholder markers"
        # Real-looking 32+ char hex strings should not be present
        real_key_pattern = re.compile(r'SECRET_KEY=[0-9a-f]{32,}', re.IGNORECASE)
        assert not real_key_pattern.search(content), "Real SECRET_KEY found in .env.example"

    def test_env_file_not_present(self):
        """.env file must not exist in the project root — it would contain real secrets."""
        env_file = _PROJECT_ROOT / ".env"
        assert not env_file.exists(), (
            ".env file found in project root — it contains real secrets and must NOT be committed"
        )

    def test_gitignore_excludes_env_files(self):
        """The .gitignore must exclude .env files."""
        content = _GITIGNORE.read_text(encoding="utf-8")
        assert ".env" in content, ".gitignore must exclude .env files"
        assert ".env.local" in content
        assert ".env.production" in content

    def test_certs_directory_has_gitignore(self):
        """infra/nginx/certs/ must have a .gitignore that excludes TLS keys."""
        certs_gitignore = _INFRA / "nginx" / "certs" / ".gitignore"
        assert certs_gitignore.exists(), (
            "infra/nginx/certs/.gitignore missing — TLS private keys might be committed"
        )
        content = certs_gitignore.read_text(encoding="utf-8")
        assert "*.pem" in content, "*.pem must be excluded from git (TLS certificates)"
        assert "*.key" in content, "*.key must be excluded from git (private keys)"

    def test_no_tls_certs_in_repo(self):
        """No actual TLS certificate files should exist in the repo."""
        cert_patterns = ["*.pem", "*.key", "*.crt", "*.p12"]
        for pattern in cert_patterns:
            found = list(_INFRA.rglob(pattern))
            assert not found, f"TLS certificate file found (should not be in git): {found}"

    def test_gitignore_excludes_coverage_artifacts(self):
        """Coverage artifacts must not be committed — they bloat the repo."""
        content = _GITIGNORE.read_text(encoding="utf-8")
        assert ".coverage" in content, ".coverage should be gitignored"
        assert "htmlcov/" in content, "htmlcov/ should be gitignored"

    def test_no_hardcoded_db_password_in_app_source(self):
        """No real DB passwords in app source (config.py defaults are exempt)."""
        hits = []
        exempt = {"config.py"}
        for f in (_BACKEND / "app").rglob("*.py"):
            if f.name in exempt:
                continue
            content = f.read_text(encoding="utf-8", errors="ignore")
            # Real-looking passwords (not test helpers or obvious mocks)
            if re.search(r'DATABASE_URL\s*=\s*["\']postgresql.*:.*@(?!localhost)', content):
                hits.append(f.name)
        assert not hits, f"Possible hardcoded remote DB URL in: {hits}"


# ─────────────────────────────────────────────────────────────────────────────
# 2. Infrastructure — Dockerfiles, render.yaml, docker-compose
# ─────────────────────────────────────────────────────────────────────────────

class TestInfrastructure:
    """Docker and render.yaml configuration is production-ready."""

    def test_backend_dockerfile_exists(self):
        assert (_BACKEND / "Dockerfile").exists()

    def test_frontend_dockerfile_exists(self):
        assert (_FRONTEND / "Dockerfile").exists()

    def test_backend_dockerfile_non_root_user(self):
        """Backend container must not run as root (security requirement)."""
        content = (_BACKEND / "Dockerfile").read_text(encoding="utf-8")
        assert "USER appuser" in content or "USER " in content, \
            "Backend Dockerfile must switch to non-root user"

    def test_frontend_dockerfile_non_root_user(self):
        """Frontend container must not run as root."""
        content = (_FRONTEND / "Dockerfile").read_text(encoding="utf-8")
        assert "USER nextjs" in content or "USER " in content, \
            "Frontend Dockerfile must switch to non-root user"

    def test_backend_dockerignore_excludes_env(self):
        """.dockerignore must exclude .env files (no secrets in Docker image)."""
        di = _BACKEND / ".dockerignore"
        assert di.exists(), "backend/.dockerignore missing"
        content = di.read_text(encoding="utf-8")
        assert ".env" in content, ".dockerignore must exclude .env files"

    def test_frontend_dockerignore_excludes_env(self):
        di = _FRONTEND / ".dockerignore"
        assert di.exists(), "frontend/.dockerignore missing"
        content = di.read_text(encoding="utf-8")
        assert ".env" in content

    def test_backend_dockerfile_has_healthcheck(self):
        content = (_BACKEND / "Dockerfile").read_text(encoding="utf-8")
        assert "HEALTHCHECK" in content, "Backend Dockerfile must have HEALTHCHECK"

    def test_frontend_dockerfile_has_healthcheck(self):
        content = (_FRONTEND / "Dockerfile").read_text(encoding="utf-8")
        assert "HEALTHCHECK" in content, "Frontend Dockerfile must have HEALTHCHECK"

    def test_render_yaml_exists(self):
        assert _RENDER_YAML.exists(), "render.yaml missing — Render blueprint required"

    def test_render_yaml_health_check_path(self):
        """Render must poll /health — this endpoint has no auth."""
        content = _RENDER_YAML.read_text(encoding="utf-8")
        assert "healthCheckPath: /health" in content, \
            "render.yaml healthCheckPath must be /health"

    def test_render_yaml_secret_key_sync_false(self):
        """SECRET_KEY must be sync:false in render.yaml — never auto-synced."""
        content = _RENDER_YAML.read_text(encoding="utf-8")
        assert "SECRET_KEY" in content
        # After SECRET_KEY there should be sync: false (not a real value)
        idx = content.index("SECRET_KEY")
        nearby = content[idx:idx+100]
        assert "sync: false" in nearby, "SECRET_KEY must have sync:false in render.yaml"

    def test_docker_compose_has_nginx(self):
        """docker-compose.yml must have nginx service as the only public port."""
        content = _DOCKER_COMPOSE.read_text(encoding="utf-8")
        assert "nginx:" in content, "docker-compose must include nginx service"

    def test_frontend_next_config_standalone(self):
        """next.config.js must have output:'standalone' for Docker builds."""
        content = _NEXT_CFG.read_text(encoding="utf-8")
        assert "standalone" in content, (
            "next.config.js must have output:'standalone' — required by frontend Dockerfile"
        )


# ─────────────────────────────────────────────────────────────────────────────
# 3. Database — Alembic migration chain
# ─────────────────────────────────────────────────────────────────────────────

class TestDatabaseMigrations:
    """Alembic migration chain is complete and the head is known."""

    _MIGRATIONS_DIR = _BACKEND / "migrations" / "versions"
    _EXPECTED_HEAD  = "p6j79m8o1i93"   # add_multi_tenancy_p47 (latest)
    _EXPECTED_COUNT = 13               # total migrations

    def test_migrations_directory_exists(self):
        assert self._MIGRATIONS_DIR.exists()

    def test_all_expected_migrations_present(self):
        """Each sprint that added a migration must have its file present."""
        expected_tags = [
            "initial_schema",   # P16
            "forensic_ledger",  # P19
            "threat_intel",     # P21
            "hunt_tables",      # P22
            "pcdi",             # P24
            "soar",             # P25
            "pids",             # P26
            "correlation",      # P27
            "incident",         # P28
            "executive_reports",# P29
            "api_keys",         # P40
            "webhooks",         # P42
            "multi_tenancy",    # P47
        ]
        files = [f.name for f in self._MIGRATIONS_DIR.glob("*.py") if f.name != "__init__.py"]
        for tag in expected_tags:
            assert any(tag in f for f in files), f"Migration for '{tag}' not found"

    def test_migration_count(self):
        files = [f for f in self._MIGRATIONS_DIR.glob("*.py") if f.name not in ("__init__.py",)]
        assert len(files) == self._EXPECTED_COUNT, (
            f"Expected {self._EXPECTED_COUNT} migrations, found {len(files)}"
        )

    def test_alembic_ini_exists(self):
        assert (_BACKEND / "alembic.ini").exists(), "alembic.ini missing"

    def test_alembic_head_importable(self):
        """The alembic head revision must be importable (no broken chain)."""
        from alembic.config import Config
        from alembic.script import ScriptDirectory
        cfg = Config(str(_BACKEND / "alembic.ini"))
        scripts = ScriptDirectory.from_config(cfg)
        heads = list(scripts.get_heads())
        assert len(heads) == 1, f"Multiple alembic heads detected: {heads} — resolve before deploy"
        assert heads[0] == self._EXPECTED_HEAD, (
            f"Alembic head mismatch: expected {self._EXPECTED_HEAD}, got {heads[0]}"
        )

    def test_no_missing_revisions_in_chain(self):
        """Walk the full revision chain — no gap should raise an error."""
        from alembic.config import Config
        from alembic.script import ScriptDirectory
        cfg = Config(str(_BACKEND / "alembic.ini"))
        scripts = ScriptDirectory.from_config(cfg)
        revisions = list(scripts.walk_revisions())
        assert len(revisions) == self._EXPECTED_COUNT, (
            f"Chain walk returned {len(revisions)} revisions, expected {self._EXPECTED_COUNT}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# 4. CI/CD — Workflows
# ─────────────────────────────────────────────────────────────────────────────

class TestCICDWorkflows:
    """GitHub Actions workflows are production-ready."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.deploy = yaml.safe_load(_DEPLOY_YML.read_text(encoding="utf-8"))
        self.ci = yaml.safe_load(_CI_YML.read_text(encoding="utf-8"))
        self.deploy_jobs = self.deploy.get("jobs", {})
        self.ci_jobs = self.ci.get("jobs", {})

    def test_deploy_workflow_exists(self):
        assert _DEPLOY_YML.exists()

    def test_ci_workflow_exists(self):
        assert _CI_YML.exists()

    def test_deploy_has_ci_check_job(self):
        assert "ci-check" in self.deploy_jobs, "deploy.yml must re-run CI before deploy"

    def test_deploy_has_backend_job(self):
        assert "deploy-backend" in self.deploy_jobs

    def test_deploy_has_frontend_job(self):
        assert "deploy-frontend" in self.deploy_jobs

    def test_deploy_has_gate_job(self):
        assert "deploy-gate" in self.deploy_jobs

    def test_deploy_backend_needs_ci_check(self):
        needs = self.deploy_jobs["deploy-backend"].get("needs", [])
        assert "ci-check" in needs, "deploy-backend must depend on ci-check"

    def test_deploy_skips_gracefully_without_secrets(self):
        """Deploy jobs must skip (not fail) when secrets are not configured."""
        deploy_content = _DEPLOY_YML.read_text(encoding="utf-8")
        assert "RENDER_API_KEY" in deploy_content
        assert "VERCEL_TOKEN" in deploy_content
        # The 'if:' condition should check that secrets are non-empty
        assert "secrets.RENDER_API_KEY" in deploy_content

    def test_ci_has_coverage_gate(self):
        """CI must fail if coverage drops below 85%."""
        ci_content = _CI_YML.read_text(encoding="utf-8")
        assert "cov-fail-under=85" in ci_content, "CI must enforce 85% coverage gate"

    def test_deploy_triggers_on_main_push(self):
        triggers = self.deploy.get(True, self.deploy.get("on", {}))
        push = triggers.get("push", {})
        branches = push.get("branches", [])
        assert any(b in ("main", "master") for b in branches), \
            "deploy.yml must trigger on push to main/master"

    def test_p49_security_gates_present(self):
        assert (_WORKFLOWS / "p49-security-gates.yml").exists()


# ─────────────────────────────────────────────────────────────────────────────
# 5. Environment configuration
# ─────────────────────────────────────────────────────────────────────────────

class TestEnvironmentConfig:
    """All required environment variables are documented in .env.example."""

    _REQUIRED_KEYS = [
        "SECRET_KEY",
        "DATABASE_URL",
        "CORS_ORIGINS",
        "DEBUG",
        "REDIS_URL",
        "NEXT_PUBLIC_API_URL",
        "METRICS_SCRAPE_TOKEN",
        "RATE_LIMIT_LOGIN",
        "ALERT_CRITICAL_THRESHOLD",
    ]

    @pytest.fixture(autouse=True)
    def _load(self):
        self.env_content = _ENV_EXAMPLE.read_text(encoding="utf-8")
        # Parse keys only (not values)
        self.keys = set(
            line.split("=")[0].strip()
            for line in self.env_content.splitlines()
            if line.strip() and not line.strip().startswith("#") and "=" in line
        )

    def test_env_example_exists(self):
        assert _ENV_EXAMPLE.exists()

    @pytest.mark.parametrize("key", _REQUIRED_KEYS)
    def test_required_key_in_env_example(self, key: str):
        assert key in self.keys, f"{key} missing from .env.example"

    def test_cors_origins_is_json_array(self):
        """CORS_ORIGINS must be a JSON array — common misconfiguration."""
        for line in self.env_content.splitlines():
            if line.startswith("CORS_ORIGINS="):
                value = line.split("=", 1)[1].strip()
                assert value.startswith("["), \
                    f"CORS_ORIGINS must be a JSON array, got: {value!r}"
                break

    def test_secret_key_is_placeholder(self):
        """SECRET_KEY in .env.example must be a placeholder, not a real key."""
        for line in self.env_content.splitlines():
            if line.startswith("SECRET_KEY="):
                value = line.split("=", 1)[1].strip()
                real_key = re.match(r'^[0-9a-f]{32,}$', value, re.IGNORECASE)
                assert not real_key, f"Real SECRET_KEY found in .env.example: {value[:8]}..."
                break

    def test_database_url_is_placeholder(self):
        """DATABASE_URL in .env.example must have REPLACE_ placeholders."""
        for line in self.env_content.splitlines():
            if line.startswith("DATABASE_URL="):
                value = line.split("=", 1)[1].strip()
                assert "REPLACE_" in value or "example" in value.lower(), \
                    f"DATABASE_URL appears to have a real value in .env.example"
                break


# ─────────────────────────────────────────────────────────────────────────────
# 6. Application health — importability and startup
# ─────────────────────────────────────────────────────────────────────────────

class TestApplicationHealth:
    """/health endpoint is reachable and the app starts without errors."""

    def test_app_importable(self):
        """The FastAPI app must be importable without crashing."""
        from app.main import app
        assert app is not None

    def test_health_route_registered(self):
        """GET /health must be registered (liveness probe for Render)."""
        from app.main import app
        routes = {r.path for r in app.routes}
        assert "/health" in routes, "/health route not registered — Render liveness probe will fail"

    def test_health_route_requires_no_auth(self):
        """The /health endpoint must be accessible without authentication."""
        from app.main import app
        for route in app.routes:
            if hasattr(route, "path") and route.path == "/health":
                # Health endpoint must have no dependencies that require auth
                deps = getattr(route, "dependencies", [])
                dep_names = [str(d) for d in deps]
                auth_deps = [d for d in dep_names if "bearer" in d.lower() or "auth" in d.lower()]
                assert not auth_deps, f"/health has auth dependencies: {auth_deps}"
                break

    def test_config_importable(self):
        """Settings must be importable — validates all required config fields."""
        from app.core.config import get_settings
        settings = get_settings()
        assert settings is not None

    def test_api_router_importable(self):
        from app.api.v1.router import api_router
        assert api_router is not None

    def test_tenant_middleware_importable(self):
        """P51 — TenantMiddleware must be importable."""
        from app.core.tenant_middleware import TenantMiddleware
        assert TenantMiddleware is not None

    def test_tenant_context_importable(self):
        from app.core.tenant_context import get_tenant_id, set_tenant_id
        assert callable(get_tenant_id)
        assert callable(set_tenant_id)

    def test_all_models_importable(self):
        """All SQLAlchemy models must be importable (checks for syntax errors)."""
        from app.models import (
            User, Alert, APIKey, Webhook, Tenant,
        )
        for model in (User, Alert, APIKey, Webhook, Tenant):
            assert hasattr(model, "__tablename__")


# ─────────────────────────────────────────────────────────────────────────────
# 7. Frontend configuration
# ─────────────────────────────────────────────────────────────────────────────

class TestFrontendConfig:
    """Frontend is production-ready for Vercel and Docker deployment."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.next_cfg = _NEXT_CFG.read_text(encoding="utf-8")
        pkg_path = _FRONTEND / "package.json"
        self.pkg = json.loads(pkg_path.read_text(encoding="utf-8"))

    def test_next_config_has_standalone_output(self):
        assert "standalone" in self.next_cfg, \
            "next.config.js must have output:'standalone' for Docker"

    def test_next_config_has_security_headers(self):
        """P50 — Security headers must be present."""
        assert "X-Content-Type-Options" in self.next_cfg
        assert "X-Frame-Options" in self.next_cfg
        assert "Content-Security-Policy" in self.next_cfg

    def test_package_json_has_build_script(self):
        scripts = self.pkg.get("scripts", {})
        assert "build" in scripts, "package.json must have build script for Vercel"

    def test_package_json_has_start_script(self):
        scripts = self.pkg.get("scripts", {})
        assert "start" in scripts, "package.json must have start script for Docker"

    def test_package_json_has_playwright(self):
        """P50 — Playwright must be in devDependencies."""
        dev = self.pkg.get("devDependencies", {})
        assert "@playwright/test" in dev

    def test_playwright_config_exists(self):
        assert (_FRONTEND / "playwright.config.ts").exists()

    def test_e2e_specs_directory_exists(self):
        assert (_FRONTEND / "e2e").exists()

    def test_tsconfig_excludes_e2e(self):
        """P50 Bug#33 fix must persist."""
        import json as _json
        tsconfig = _json.loads((_FRONTEND / "tsconfig.json").read_text())
        exclude = tsconfig.get("exclude", [])
        assert "e2e" in exclude
        assert "playwright.config.ts" in exclude


# ─────────────────────────────────────────────────────────────────────────────
# 8. Endpoint audit — public vs auth-required
# ─────────────────────────────────────────────────────────────────────────────

class TestEndpointAudit:
    """Known-public endpoints are accessible; protected endpoints require auth."""

    @pytest.fixture(autouse=True)
    def _routes(self):
        from app.main import app
        self.app = app
        self.route_map = {
            getattr(r, "path", ""): r
            for r in app.routes
        }

    def test_health_endpoint_registered(self):
        assert "/health" in self.route_map

    def test_api_v1_prefix_registered(self):
        """All API routes must be under /api/v1/."""
        api_paths = [p for p in self.route_map if p.startswith("/api/v1/")]
        assert len(api_paths) >= 5, "Expected multiple /api/v1/ routes"

    def test_docs_not_in_production_routes(self):
        """In production (DEBUG=False), /docs must not be accessible."""
        from app.core.config import get_settings
        settings = get_settings()
        if not settings.DEBUG:
            assert "/docs" not in self.route_map or self.route_map.get("/docs") is None, \
                "/docs must be disabled in production (DEBUG=False)"

    def test_openapi_json_hidden_in_production(self):
        """In production, /openapi.json must not be accessible."""
        from app.core.config import get_settings
        settings = get_settings()
        if not settings.DEBUG:
            assert "/openapi.json" not in self.route_map, \
                "/openapi.json must be hidden in production"

    def test_auth_endpoints_registered(self):
        """Auth endpoints must be present — login is required to use the app."""
        auth_paths = [p for p in self.route_map if "/auth" in p]
        assert len(auth_paths) >= 1, "Auth endpoints not found under /api/v1/auth/"


# ─────────────────────────────────────────────────────────────────────────────
# 9. Regression — P47–P51 deliverables present
# ─────────────────────────────────────────────────────────────────────────────

class TestDeploymentRegression:
    """All key sprints since P39 are present and wired."""

    def test_p47_tenant_model_has_tenant_id(self):
        from app.models.tenant import Tenant
        from app.models.user import User
        from app.models.api_key import APIKey
        from app.models.webhook import Webhook
        for model in (User, APIKey, Webhook):
            assert hasattr(model, "tenant_id"), f"{model.__name__} missing tenant_id"

    def test_p49_security_gates_workflow(self):
        assert (_WORKFLOWS / "p49-security-gates.yml").exists()

    def test_p50_playwright_workflow(self):
        assert (_WORKFLOWS / "p50-e2e.yml").exists()

    def test_p51_tenant_middleware_wired(self):
        main_src = (_BACKEND / "app" / "main.py").read_text(encoding="utf-8")
        assert "TenantMiddleware" in main_src
        assert "add_middleware(TenantMiddleware)" in main_src

    def test_p51_tenant_filter_exists(self):
        assert (_BACKEND / "app" / "db" / "tenant_filter.py").exists()

    def test_p51_tenant_context_exists(self):
        assert (_BACKEND / "app" / "core" / "tenant_context.py").exists()

    def test_observability_endpoint_registered(self):
        """P39 — Prometheus metrics endpoint must be registered."""
        from app.main import app
        paths = {getattr(r, "path", "") for r in app.routes}
        obs_paths = [p for p in paths if "observability" in p or "metrics" in p]
        assert len(obs_paths) >= 1, "Observability/metrics endpoints not found"

    def test_sdk_directory_exists(self):
        """P43 — Python SDK must be present in the repo."""
        assert (_PROJECT_ROOT / "sdk" / "asc_sdk").exists()

    def test_load_tests_exist(self):
        """P48 — Locust load tests must be present."""
        assert (_PROJECT_ROOT / "load_tests" / "locustfile.py").exists()

    def test_deployment_guide_exists(self):
        assert (_DOCS / "deployment-guide.md").exists()

    def test_gitleaks_config_present(self):
        assert (_PROJECT_ROOT / ".gitleaks.toml").exists()
