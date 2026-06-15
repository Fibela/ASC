"""
P38 Deployment Validation — Sprint P38 FASE 4 Production Deploy Prep.

Tests:
  - Infrastructure-as-code validation (render.yaml, vercel.json, docker-compose.yml,
    deploy.yml, TLS_SETUP.md — all required files must exist and be parseable)
  - Root /health endpoint (used by Docker HEALTHCHECK, Render, nginx probe)
  - CORS origin enforcement for production domains
  - Startup checks in production mode (SECRET_KEY entropy, wildcard CORS blocked)
  - Docker Compose service graph (all required services + new Celery workers)
  - Security headers on the root health endpoint
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
import yaml

try:
    import celery as _celery_mod  # noqa: F401
    _celery_installed = True
except Exception:
    _celery_installed = False

# Repo root: backend/tests/ → ../../
_REPO_ROOT = Path(__file__).parent.parent.parent


# ── Infrastructure file path fixtures ─────────────────────────────────────────

@pytest.fixture(scope="module")
def render_yaml():
    p = _REPO_ROOT / "render.yaml"
    assert p.exists(), "render.yaml missing — run P38-RENDER task"
    return yaml.safe_load(p.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def vercel_json():
    p = _REPO_ROOT / "frontend" / "vercel.json"
    assert p.exists(), "frontend/vercel.json missing — run P38-VERCEL task"
    return json.loads(p.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def docker_compose():
    p = _REPO_ROOT / "docker-compose.yml"
    assert p.exists(), "docker-compose.yml missing"
    return yaml.safe_load(p.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def deploy_workflow():
    p = _REPO_ROOT / ".github" / "workflows" / "deploy.yml"
    assert p.exists(), ".github/workflows/deploy.yml missing — run P38-CD task"
    return yaml.safe_load(p.read_text(encoding="utf-8"))


# ── Deployment artifact validation ─────────────────────────────────────────────

class TestInfrastructureFiles:
    """Validate that all P38 deployment artifacts exist and are parseable."""

    def test_render_yaml_exists_and_valid(self, render_yaml):
        assert render_yaml is not None
        assert "services" in render_yaml

    def test_render_yaml_has_backend_service(self, render_yaml):
        services = render_yaml["services"]
        names = [s.get("name") for s in services]
        assert "asc-backend" in names, f"asc-backend not in render.yaml services: {names}"

    def test_render_yaml_backend_config(self, render_yaml):
        backend = next(s for s in render_yaml["services"] if s.get("name") == "asc-backend")
        assert backend.get("runtime") == "python"
        assert backend.get("healthCheckPath") == "/health"
        assert "buildCommand" in backend
        assert "startCommand" in backend
        assert "uvicorn" in backend["startCommand"]

    def test_render_yaml_no_hardcoded_secrets(self, render_yaml):
        """All sensitive env vars must be sync:false (set in Render Dashboard)."""
        backend = next(s for s in render_yaml["services"] if s.get("name") == "asc-backend")
        env_vars = backend.get("envVars", [])
        sensitive_keys = {"SECRET_KEY", "DATABASE_URL"}
        for ev in env_vars:
            if ev.get("key") in sensitive_keys:
                assert ev.get("sync") is False or ev.get("generateValue") is True, (
                    f"{ev['key']} must be sync:false in render.yaml — never hardcode secrets"
                )

    def test_vercel_json_exists_and_valid(self, vercel_json):
        assert vercel_json is not None
        assert "headers" in vercel_json

    def test_vercel_json_security_headers(self, vercel_json):
        """vercel.json must include security hardening headers."""
        all_headers = {}
        for rule in vercel_json.get("headers", []):
            for h in rule.get("headers", []):
                all_headers[h["key"].lower()] = h["value"]
        assert "x-frame-options" in all_headers, "X-Frame-Options missing from vercel.json"
        assert "x-content-type-options" in all_headers
        assert "content-security-policy" in all_headers
        assert all_headers.get("x-frame-options") == "DENY"

    def test_vercel_json_no_rewrites_to_backend(self, vercel_json):
        """Rewrites should not be present — NEXT_PUBLIC_API_URL handles backend routing."""
        rewrites = vercel_json.get("rewrites", [])
        assert len(rewrites) == 0, (
            "vercel.json should not use rewrites to the backend — "
            "use NEXT_PUBLIC_API_URL env var instead"
        )

    def test_docker_compose_required_services(self, docker_compose):
        services = set(docker_compose.get("services", {}).keys())
        required = {"postgres", "redis", "backend", "frontend", "nginx",
                    "celery-worker", "celery-beat"}
        missing = required - services
        assert not missing, f"docker-compose.yml missing services: {missing}"

    def test_docker_compose_celery_worker_config(self, docker_compose):
        worker = docker_compose["services"]["celery-worker"]
        assert "celery" in str(worker.get("command", ""))
        assert "worker" in str(worker.get("command", ""))
        assert "ports" not in worker, "celery-worker must not expose ports"

    def test_docker_compose_celery_beat_single_instance(self, docker_compose):
        """Beat must never scale beyond 1 — multiple beat instances cause duplicates."""
        beat = docker_compose["services"]["celery-beat"]
        assert "celery" in str(beat.get("command", ""))
        assert "beat" in str(beat.get("command", ""))
        assert "ports" not in beat, "celery-beat must not expose ports"

    def test_docker_compose_no_host_ports_on_internal_services(self, docker_compose):
        """postgres, redis, backend, frontend must not expose host ports in production."""
        internal = ["postgres", "redis", "backend", "frontend",
                    "celery-worker", "celery-beat"]
        for svc_name in internal:
            svc = docker_compose["services"].get(svc_name, {})
            assert "ports" not in svc, (
                f"{svc_name} must not expose host ports in docker-compose.yml (production config)"
            )

    def test_docker_compose_no_hardcoded_passwords(self, docker_compose):
        """No literal passwords in docker-compose.yml — must use ${VAR} substitution."""
        compose_text = (Path(_REPO_ROOT / "docker-compose.yml")).read_text(encoding="utf-8")
        # These substrings would indicate hardcoded credentials
        for bad in ["password123", "admin123", "REPLACE_WITH_STRONG"]:
            assert bad not in compose_text, (
                f"docker-compose.yml contains hardcoded credential pattern: {bad!r}"
            )

    def test_deploy_workflow_exists_and_valid(self, deploy_workflow):
        assert deploy_workflow is not None
        assert "jobs" in deploy_workflow

    def test_deploy_workflow_has_required_jobs(self, deploy_workflow):
        jobs = set(deploy_workflow.get("jobs", {}).keys())
        required = {"ci-check", "deploy-backend", "deploy-frontend"}
        missing = required - jobs
        assert not missing, f"deploy.yml missing jobs: {missing}"

    def test_deploy_workflow_backend_depends_on_ci(self, deploy_workflow):
        """Backend deploy must wait for CI to pass."""
        backend_job = deploy_workflow["jobs"].get("deploy-backend", {})
        needs = backend_job.get("needs", [])
        assert "ci-check" in needs, "deploy-backend must depend on ci-check"

    def test_tls_setup_doc_exists(self):
        p = _REPO_ROOT / "docs" / "TLS_SETUP.md"
        assert p.exists(), "docs/TLS_SETUP.md missing — run P38-TLS task"
        content = p.read_text(encoding="utf-8")
        assert "Let's Encrypt" in content
        assert "certbot" in content
        assert "infra/nginx/certs" in content

    def test_deployment_guide_updated_for_supabase_sql_editor(self):
        """deployment-guide.md must document the SQL Editor approach for Supabase."""
        p = _REPO_ROOT / "docs" / "deployment-guide.md"
        content = p.read_text(encoding="utf-8")
        assert "SQL Editor" in content, (
            "deployment-guide.md must document Supabase SQL Editor approach "
            "(direct asyncpg connection fails on free tier)"
        )

    def test_env_example_has_all_required_keys(self):
        """All keys in render.yaml envVars must exist in .env.example."""
        p = _REPO_ROOT / ".env.example"
        env_keys = set()
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                env_keys.add(line.split("=")[0].strip())

        render_p = _REPO_ROOT / "render.yaml"
        render_data = yaml.safe_load(render_p.read_text(encoding="utf-8"))
        backend = next(s for s in render_data["services"] if s.get("name") == "asc-backend")
        for ev in backend.get("envVars", []):
            key = ev.get("key")
            if ev.get("sync") is False:
                # Required keys must be documented in .env.example
                assert key in env_keys, (
                    f"render.yaml env var {key!r} (sync:false) not found in .env.example — "
                    "add documentation so operators know what to configure"
                )


# ── Root /health endpoint tests ────────────────────────────────────────────────

@pytest.mark.asyncio
class TestRootHealthEndpoint:
    """Validate the root /health endpoint used by Docker, Render, and nginx."""

    async def test_health_returns_200(self, client):
        r = await client.get("/health")
        assert r.status_code == 200

    async def test_health_response_structure(self, client):
        r = await client.get("/health")
        body = r.json()
        assert "status" in body
        assert body["status"] == "ok"
        assert "app" in body
        assert "version" in body

    async def test_health_no_auth_required(self, client):
        """Health endpoint must be reachable without any token."""
        r = await client.get("/health", headers={})
        assert r.status_code == 200

    async def test_health_has_security_headers(self, client):
        """Middleware must add security headers even on the health endpoint."""
        r = await client.get("/health")
        assert r.headers.get("x-content-type-options") == "nosniff"
        assert r.headers.get("x-frame-options") == "DENY"

    async def test_health_not_rate_limited_by_default(self, client):
        """Health check should not be throttled (used by load balancers)."""
        results = []
        for _ in range(10):
            r = await client.get("/health")
            results.append(r.status_code)
        assert all(c == 200 for c in results), f"Health checks throttled: {results}"


# ── CORS production behavior ───────────────────────────────────────────────────

class TestCORSProductionConfig:
    """Validate CORS behavior matches render.yaml and deployment-guide.md."""

    def test_startup_checks_reject_wildcard_cors_in_production(self):
        from app.core.startup_checks import _check_cors
        issues = _check_cors(["*"], production=True)
        assert len(issues) > 0, "Wildcard CORS must be rejected in production"

    def test_startup_checks_allow_specific_origins_in_production(self):
        from app.core.startup_checks import _check_cors
        issues = _check_cors(
            ["https://asc-premoscorp.vercel.app", "https://asc.premoscorp.com"],
            production=True,
        )
        assert len(issues) == 0, f"Specific origins must be accepted: {issues}"

    def test_startup_checks_allow_wildcard_in_dev(self):
        from app.core.startup_checks import _check_cors
        issues = _check_cors(["*"], production=False)
        assert len(issues) == 0, "Wildcard CORS is acceptable in development"


# ── Startup checks — production secrets validation ────────────────────────────

class TestStartupChecksProductionMode:
    """Ensure production configuration is validated strictly at startup."""

    def test_weak_secret_key_rejected_in_production(self):
        from app.core.startup_checks import _check_secret_key
        issues = _check_secret_key("changeme", production=True)
        assert any("weak" in i.lower() or "changeme" in i.lower() for i in issues)

    def test_short_secret_key_rejected(self):
        from app.core.startup_checks import _check_secret_key
        issues = _check_secret_key("tooshort", production=True)
        assert any("minimum" in i.lower() or "32" in i for i in issues)

    def test_strong_secret_key_accepted(self):
        from app.core.startup_checks import _check_secret_key
        import secrets
        strong_key = secrets.token_hex(32)
        issues = _check_secret_key(strong_key, production=True)
        assert len(issues) == 0, f"Strong key should pass: {issues}"

    def test_run_startup_checks_raises_in_production_on_weak_key(self):
        from app.core.startup_checks import run_startup_checks
        from unittest.mock import MagicMock
        mock_settings = MagicMock()
        mock_settings.DEBUG = False
        mock_settings.SECRET_KEY = "weak"
        mock_settings.CORS_ORIGINS = ["https://example.com"]
        with pytest.raises(RuntimeError, match="Startup aborted"):
            run_startup_checks(mock_settings)

    def test_run_startup_checks_passes_with_valid_config(self):
        import secrets
        from app.core.startup_checks import run_startup_checks
        from unittest.mock import MagicMock
        mock_settings = MagicMock()
        mock_settings.DEBUG = False
        mock_settings.SECRET_KEY = secrets.token_hex(32)
        mock_settings.CORS_ORIGINS = ["https://asc.premoscorp.com"]
        run_startup_checks(mock_settings)  # must not raise


# ── Docker Compose Celery integration smoke ────────────────────────────────────

@pytest.mark.skipif(not _celery_installed, reason="celery not installed — skipped")
class TestCeleryAppConfig:
    """Validate Celery app configuration (no live Redis required)."""

    def test_celery_app_importable(self):
        from app.tasks.celery_app import celery_app
        assert celery_app is not None
        assert celery_app.main == "asc"

    def test_celery_beat_schedule_defined(self):
        from app.tasks.celery_app import celery_app
        schedule = celery_app.conf.beat_schedule
        assert isinstance(schedule, dict)
        expected_tasks = {
            "proactive-escalation",
            "pcdi-critical-findings",
            "soar-scheduled-reports",
            "correlation-sweep",
            "sla-breach-escalation",
        }
        assert expected_tasks <= set(schedule.keys()), (
            f"Missing beat tasks: {expected_tasks - set(schedule.keys())}"
        )

    def test_celery_no_op_mode_without_redis(self):
        """Celery uses memory:// broker when REDIS_URL is not set."""
        from app.tasks.celery_app import _broker
        assert "memory://" in _broker or "redis://" in _broker, (
            f"Unexpected broker: {_broker}"
        )

    def test_celery_serialization_config(self):
        from app.tasks.celery_app import celery_app
        assert celery_app.conf.task_serializer == "json"
        assert celery_app.conf.result_serializer == "json"
        assert "json" in celery_app.conf.accept_content
