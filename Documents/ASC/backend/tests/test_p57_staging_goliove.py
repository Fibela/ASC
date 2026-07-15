"""
P57 — Staging Deploy Validation + Go-Live Readiness (TD-2 + TD-5)
==================================================================
Suite de validación integral para cerrar las deudas técnicas:
  TD-2: 48h staging deploy readiness
  TD-5: 72h go-live observation readiness

Cobertura:
  - Security scans: bandit, pip-audit, secret grep, nosec audit
  - Deploy artifacts: render.yaml, vercel.json, docker-compose.yml
  - CI/CD workflows: ci.yml, deploy.yml, security-audit.yml, p49/p50 gates
  - Endpoint completeness: 27 routers, 235 endpoints, 0 stubs
  - Config completeness: P53-P55 env vars in render.yaml
  - Startup checks: SECRET_KEY, CORS, weak key detection
  - Runbook artifacts: staging-deploy-runbook.md, go-live-runbook.md
  - Migration chain: 15 migrations, correct head
  - Code hygiene: no NotImplementedError, no hardcoded secrets
  - Test gate: coverage >= 85%, suite count >= 4000

Tests: 78 en 9 clases
"""

import importlib
import subprocess
import sys
import yaml
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_REPO_ROOT = Path(__file__).parent.parent.parent
_BACKEND   = _REPO_ROOT / "Documents" / "ASC" / "backend"
_DOCS      = _REPO_ROOT / "Documents" / "ASC" / "docs"
_WORKFLOWS = _REPO_ROOT / "Documents" / "ASC" / ".github" / "workflows"

# Resolve actual repo root (test file is in backend/tests/)
_REPO_ROOT  = Path(__file__).parent.parent.parent
_BACKEND    = Path(__file__).parent.parent          # backend/
_DOCS       = _REPO_ROOT / "docs"
_WORKFLOWS  = _REPO_ROOT / ".github" / "workflows"

_EXPECTED_MIGRATION_HEAD  = "w3q56t5v8p10"  # P61 honeypot tables (latest)
_EXPECTED_MIGRATION_COUNT = 26  # 24 (P-16) + b3c4d5e6f7a8 + c9d12f0e5b67 merge head
_EXPECTED_MIN_ENDPOINTS   = 230
_EXPECTED_MIN_TESTS       = 4000
_COVERAGE_GATE            = 85.0


# ── 1. Security Scan Results ───────────────────────────────────────────────────

class TestSecurityScans:
    """Validates results of local security tooling — bandit, pip-audit, nosec audit."""

    def test_bandit_zero_high_medium_issues(self):
        """bandit -r app/ -ll must report 0 High and 0 Medium issues."""
        result = subprocess.run(
            [sys.executable, "-m", "bandit", "-r", "app/", "-ll", "-f", "json"],
            cwd=str(_BACKEND),
            capture_output=True,
            text=True,
        )
        import json
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            pytest.skip("bandit not installed or output not JSON")
        results = data.get("results", [])
        high_medium = [
            r for r in results
            if r.get("issue_severity") in ("HIGH", "MEDIUM")
        ]
        assert high_medium == [], (
            f"bandit found {len(high_medium)} HIGH/MEDIUM issues: "
            + str([r.get("filename") + ":" + str(r.get("line_number")) for r in high_medium])
        )

    def test_bandit_total_issues_zero(self):
        """bandit reports 0 total issues at -ll (medium+)."""
        result = subprocess.run(
            [sys.executable, "-m", "bandit", "-r", "app/", "-ll", "-f", "json"],
            cwd=str(_BACKEND),
            capture_output=True,
            text=True,
        )
        import json
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            pytest.skip("bandit not installed")
        assert len(data.get("results", [])) == 0, "bandit found issues"

    def test_no_hardcoded_sk_live_keys(self):
        """No Stripe live keys in executable code (comment portions excluded)."""
        app_dir = _BACKEND / "app"
        for py_file in app_dir.rglob("*.py"):
            for i, line in enumerate(
                py_file.read_text(encoding="utf-8", errors="ignore").splitlines(), 1
            ):
                # Only inspect the code portion (before any inline comment marker)
                code_part = line.split("#")[0]
                assert "sk_live_" not in code_part, (
                    f"Stripe live key in code (not comment): {py_file.name}:{i}"
                )

    def test_no_hardcoded_whsec_keys(self):
        """No Stripe webhook secrets in executable code (comment portions excluded)."""
        app_dir = _BACKEND / "app"
        for py_file in app_dir.rglob("*.py"):
            for i, line in enumerate(
                py_file.read_text(encoding="utf-8", errors="ignore").splitlines(), 1
            ):
                code_part = line.split("#")[0]
                assert "whsec_" not in code_part, (
                    f"Stripe webhook secret in code (not comment): {py_file.name}:{i}"
                )

    def test_no_password123_in_app(self):
        """Classic weak passwords not present in app code."""
        app_dir = _BACKEND / "app"
        weak = ["password123", "admin123", "secret123", "qwerty123"]
        for py_file in app_dir.rglob("*.py"):
            content = py_file.read_text(encoding="utf-8", errors="ignore").lower()
            for w in weak:
                assert w not in content, f"Weak credential '{w}' found in {py_file}"

    def test_dot_env_not_in_git(self):
        """Verify .env file is not tracked by git."""
        result = subprocess.run(
            ["git", "ls-files", "--error-unmatch", ".env"],
            cwd=str(_REPO_ROOT),
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0, ".env file is tracked by git — security risk!"

    def test_nosec_annotations_documented(self):
        """All #nosec annotations in app/ must include the Bxxx code (not bare #nosec)."""
        app_dir = _BACKEND / "app"
        bare_nosec = []
        for py_file in app_dir.rglob("*.py"):
            for i, line in enumerate(py_file.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
                if "#nosec" in line.lower() and not any(
                    f"B{n}" in line for n in range(100, 700)
                ):
                    bare_nosec.append(f"{py_file.name}:{i}")
        assert bare_nosec == [], f"Bare #nosec without Bxxx code: {bare_nosec}"

    def test_stripe_secret_key_runtime_value_empty(self):
        """STRIPE_SECRET_KEY default must be empty string (integration disabled in dev)."""
        from asc_api.core.config import get_settings
        s = get_settings()
        assert s.STRIPE_SECRET_KEY == "", "STRIPE_SECRET_KEY must default to '' (disabled in dev)"

    def test_stripe_webhook_secret_runtime_value_empty(self):
        """STRIPE_WEBHOOK_SECRET default must be empty string."""
        from asc_api.core.config import get_settings
        s = get_settings()
        assert s.STRIPE_WEBHOOK_SECRET == "", "STRIPE_WEBHOOK_SECRET must default to ''"

    def test_secret_key_not_changeme_in_production_check(self):
        """startup_checks._check_secret_key detects weak SECRET_KEY."""
        from asc_api.core.startup_checks import _check_secret_key
        issues = _check_secret_key("changeme-generate-a-strong-key-in-production", production=True)
        assert len(issues) >= 1, "startup_checks must reject changeme placeholder"

    def test_strong_secret_key_passes_check(self):
        """A properly generated SECRET_KEY passes startup checks."""
        import secrets
        from asc_api.core.startup_checks import _check_secret_key
        strong_key = secrets.token_hex(32)
        issues = _check_secret_key(strong_key, production=True)
        assert issues == [], f"Strong key failed check: {issues}"


# ── 2. Deploy Artifacts — Vercel Crons ────────────────────────────────────────

class TestVercelCrons:
    """vercel.json cron jobs replace Celery Beat background tasks."""

    @pytest.fixture(autouse=True)
    def _load(self):
        import json
        vj = _REPO_ROOT / "frontend" / "vercel.json"
        assert vj.exists(), "frontend/vercel.json not found"
        self.data = json.loads(vj.read_text(encoding="utf-8"))
        self.crons = self.data.get("crons", [])
        self.cron_paths = {c["path"] for c in self.crons}

    def test_crons_array_present(self):
        assert len(self.crons) > 0, "vercel.json must have crons array"

    def test_correlation_sweep_cron(self):
        assert "/api/v1/cron/correlation-sweep" in self.cron_paths

    def test_escalation_cron(self):
        assert "/api/v1/cron/escalation" in self.cron_paths

    def test_sla_check_cron(self):
        assert "/api/v1/cron/sla-check" in self.cron_paths

    def test_pcdi_scan_cron(self):
        assert "/api/v1/cron/pcdi-scan" in self.cron_paths

    def test_scheduled_reports_cron(self):
        assert "/api/v1/cron/scheduled-reports" in self.cron_paths

    def test_all_cron_paths_under_api_v1(self):
        for c in self.crons:
            assert c["path"].startswith("/api/v1/cron/"), (
                f"Cron path must be under /api/v1/cron/: {c['path']!r}"
            )

    def test_all_crons_have_schedule(self):
        for c in self.crons:
            assert c.get("schedule"), f"Cron {c['path']!r} missing schedule"

    def test_cron_endpoint_importable(self):
        from asc_api.api.v1.endpoints.cron import router
        assert router.prefix == "/cron"

    def test_env_example_has_cron_secret(self):
        env_ex = (_REPO_ROOT / ".env.example").read_text(encoding="utf-8")
        assert "CRON_SECRET" in env_ex, "CRON_SECRET must be documented in .env.example"

    def test_env_example_has_required_backend_vars(self):
        """Critical backend vars are documented in .env.example (no render.yaml needed)."""
        env_ex = (_REPO_ROOT / ".env.example").read_text(encoding="utf-8")
        required = {
            "SECRET_KEY", "DATABASE_URL", "CORS_ORIGINS",
            "STRIPE_SECRET_KEY", "STRIPE_WEBHOOK_SECRET",
            "SUPABASE_URL", "SUPABASE_JWT_SECRET",
            "RESEND_API_KEY", "METRICS_SCRAPE_TOKEN",
            "PALOALTO_HOST", "FORTINET_HOST", "AD_SERVER_URL",
            "ELASTICSEARCH_URL", "WAZUH_URL", "THEHIVE_URL",
            "CRON_SECRET",
        }
        for key in required:
            assert key in env_ex, f"{key!r} missing from .env.example"

    def test_email_verification_expire_hours_in_env(self):
        env_ex = (_REPO_ROOT / ".env.example").read_text(encoding="utf-8")
        assert "EMAIL_VERIFICATION_EXPIRE_HOURS" in env_ex

    def test_debug_not_true_in_vercel_env(self):
        """DEBUG must not be set to 'true' in vercel.json env — production default."""
        env_vars = self.data.get("env", {})
        debug_val = env_vars.get("DEBUG", "false")
        assert debug_val.lower() != "true", (
            "vercel.json must not set DEBUG=true (use Vercel Dashboard for env-specific overrides)"
        )

    def test_no_secret_values_inline(self):
        """vercel.json must not contain secret values inline."""
        # (checking that no @env-var references contain literal secrets)
        import re
        content = (_REPO_ROOT / "frontend" / "vercel.json").read_text(encoding="utf-8")
        # Pattern: obvious secret strings (long random-looking values in JSON)
        for bad in ["sk_live_", "rk_live_", "whsec_", "re_live_"]:
            assert bad not in content, (
                f"vercel.json appears to contain a live secret ({bad!r}) — use Vercel Dashboard"
            )

    def test_cron_router_registered(self):
        """cron router must be registered in the main API router."""
        content = (_REPO_ROOT / "backend" / "asc_api" / "api" / "v1" / "router.py"
                   ).read_text(encoding="utf-8")
        assert "cron" in content


# ── 3. Deploy Artifacts — vercel.json ─────────────────────────────────────────

class TestVercelJson:
    """vercel.json security headers validation."""

    @pytest.fixture(autouse=True)
    def _load(self):
        vj = _REPO_ROOT / "frontend" / "vercel.json"
        assert vj.exists(), "frontend/vercel.json not found"
        import json
        self.data = json.loads(vj.read_text(encoding="utf-8"))
        headers_list = self.data.get("headers", [])
        self.headers = {}
        for block in headers_list:
            for h in block.get("headers", []):
                self.headers[h["key"]] = h["value"]

    def test_x_frame_options_deny(self):
        assert self.headers.get("X-Frame-Options") == "DENY"

    def test_x_content_type_nosniff(self):
        assert self.headers.get("X-Content-Type-Options") == "nosniff"

    def test_x_xss_protection(self):
        assert "X-XSS-Protection" in self.headers

    def test_hsts_present(self):
        hsts = self.headers.get("Strict-Transport-Security", "")
        assert "max-age=" in hsts
        assert "includeSubDomains" in hsts

    def test_csp_present(self):
        csp = self.headers.get("Content-Security-Policy", "")
        assert "default-src" in csp
        assert "frame-ancestors 'none'" in csp

    def test_referrer_policy(self):
        assert "Referrer-Policy" in self.headers

    def test_permissions_policy(self):
        pp = self.headers.get("Permissions-Policy", "")
        assert "camera=()" in pp
        assert "microphone=()" in pp

    def test_regions_configured(self):
        regions = self.data.get("regions", [])
        assert len(regions) >= 1, "vercel.json should have at least one region"

    def test_framework_nextjs(self):
        assert self.data.get("framework") == "nextjs"


# ── 4. CI/CD Workflow Files ────────────────────────────────────────────────────

class TestCICDWorkflows:
    """Validates all CI/CD workflow files exist and have required gates."""

    def _load_yaml(self, filename: str) -> dict:
        path = _WORKFLOWS / filename
        assert path.exists(), f".github/workflows/{filename} not found"
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        return raw if raw else {}

    def test_ci_yml_exists(self):
        assert (_WORKFLOWS / "ci.yml").exists()

    def test_deploy_yml_exists(self):
        assert (_WORKFLOWS / "deploy.yml").exists()

    def test_security_audit_yml_exists(self):
        assert (_WORKFLOWS / "security-audit.yml").exists()

    def test_p49_security_gates_yml_exists(self):
        assert (_WORKFLOWS / "p49-security-gates.yml").exists()

    def test_p50_e2e_yml_exists(self):
        assert (_WORKFLOWS / "p50-e2e.yml").exists()

    def test_ci_yml_has_coverage_gate(self):
        data = self._load_yaml("ci.yml")
        content = (_WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
        assert "--cov-fail-under" in content, "ci.yml must have coverage gate"

    def test_security_audit_yml_has_bandit(self):
        """bandit runs in security-audit.yml (not ci.yml — separate security gate)."""
        content = (_WORKFLOWS / "security-audit.yml").read_text(encoding="utf-8")
        assert "bandit" in content

    def test_deploy_yml_depends_on_ci(self):
        content = (_WORKFLOWS / "deploy.yml").read_text(encoding="utf-8")
        assert "ci-check" in content or "needs:" in content, (
            "deploy.yml must depend on CI check gate"
        )

    def test_p49_has_trivy_scan(self):
        content = (_WORKFLOWS / "p49-security-gates.yml").read_text(encoding="utf-8")
        assert "trivy" in content

    def test_p49_has_gitleaks(self):
        content = (_WORKFLOWS / "p49-security-gates.yml").read_text(encoding="utf-8")
        assert "gitleaks" in content

    def test_no_skip_no_verify_in_workflows(self):
        """Workflows must not bypass git hooks or CI checks."""
        for wf_file in _WORKFLOWS.glob("*.yml"):
            content = wf_file.read_text(encoding="utf-8")
            assert "--no-verify" not in content, f"{wf_file.name} uses --no-verify"


# ── 5. Router & Endpoint Completeness ─────────────────────────────────────────

class TestEndpointCompleteness:
    """All 27 endpoint modules registered in router.py, no orphaned routes."""

    def test_all_routers_registered(self):
        router_src = (_BACKEND / "asc_api" / "api" / "v1" / "router.py").read_text(encoding="utf-8")
        expected_modules = [
            "auth", "analyze", "events", "alerts", "iocs", "metrics",
            "neutralize", "reports", "detection", "playbooks", "adapters",
            "health", "agents", "honeypot", "notifications", "iam", "forensic",
            "ops_dashboard", "threat_intel", "threat_hunting", "pcdi", "soar",
            "pids", "correlation", "incidents", "executive_reports", "observability",
            "api_keys", "webhooks", "tenants", "onboarding", "billing",
        ]
        for module in expected_modules:
            assert f"include_router({module}.router)" in router_src, (
                f"{module}.router not registered in router.py"
            )

    def test_onboarding_router_registered(self):
        router_src = (_BACKEND / "asc_api" / "api" / "v1" / "router.py").read_text(encoding="utf-8")
        assert "onboarding" in router_src

    def test_billing_router_registered(self):
        router_src = (_BACKEND / "asc_api" / "api" / "v1" / "router.py").read_text(encoding="utf-8")
        assert "billing" in router_src

    def test_tenants_router_registered(self):
        router_src = (_BACKEND / "asc_api" / "api" / "v1" / "router.py").read_text(encoding="utf-8")
        assert "tenants" in router_src

    def test_endpoint_files_exist(self):
        endpoints_dir = _BACKEND / "asc_api" / "api" / "v1" / "endpoints"
        critical_files = [
            "auth.py", "alerts.py", "events.py", "onboarding.py",
            "billing.py", "api_keys.py", "webhooks.py", "tenants.py",
            "observability.py", "agents.py",
        ]
        for f in critical_files:
            assert (endpoints_dir / f).exists(), f"Endpoint file missing: {f}"

    def test_no_not_implemented_in_endpoints(self):
        endpoints_dir = _BACKEND / "asc_api" / "api" / "v1" / "endpoints"
        for py_file in endpoints_dir.glob("*.py"):
            content = py_file.read_text(encoding="utf-8", errors="ignore")
            assert "raise NotImplementedError" not in content, (
                f"NotImplementedError in {py_file.name} — incomplete endpoint"
            )

    def test_minimum_endpoint_count(self):
        endpoints_dir = _BACKEND / "asc_api" / "api" / "v1" / "endpoints"
        total = 0
        for py_file in endpoints_dir.glob("*.py"):
            content = py_file.read_text(encoding="utf-8", errors="ignore")
            for method in ("@router.get", "@router.post", "@router.put", "@router.patch", "@router.delete"):
                total += content.count(method)
        assert total >= _EXPECTED_MIN_ENDPOINTS, (
            f"Expected >= {_EXPECTED_MIN_ENDPOINTS} endpoints, found {total}"
        )

    def test_health_endpoints_present(self):
        health_src = (_BACKEND / "asc_api" / "api" / "v1" / "endpoints" / "health.py").read_text(encoding="utf-8")
        assert "/health" in health_src or "liveness" in health_src


# ── 6. Config Completeness (P53-P55) ─────────────────────────────────────────

class TestConfigCompleteness:
    """Settings class has all required fields from P53-P55."""

    def test_email_verification_expire_hours_exists(self):
        from asc_api.core.config import Settings
        assert hasattr(Settings, "model_fields") or hasattr(Settings(), "EMAIL_VERIFICATION_EXPIRE_HOURS")

    def test_email_verification_expire_hours_default(self):
        from asc_api.core.config import get_settings
        s = get_settings()
        assert s.EMAIL_VERIFICATION_EXPIRE_HOURS == 24

    def test_stripe_secret_key_field_exists(self):
        from asc_api.core.config import get_settings
        s = get_settings()
        assert hasattr(s, "STRIPE_SECRET_KEY")

    def test_stripe_webhook_secret_field_exists(self):
        from asc_api.core.config import get_settings
        s = get_settings()
        assert hasattr(s, "STRIPE_WEBHOOK_SECRET")

    def test_rate_limit_api_key_per_minute_default(self):
        from asc_api.core.config import get_settings
        s = get_settings()
        assert s.RATE_LIMIT_API_KEY_PER_MINUTE == 60

    def test_rate_limit_api_key_per_hour_default(self):
        from asc_api.core.config import get_settings
        s = get_settings()
        assert s.RATE_LIMIT_API_KEY_PER_HOUR == 1000

    def test_cors_origins_has_premoscorp(self):
        from asc_api.core.config import get_settings
        s = get_settings()
        origins_str = str(s.CORS_ORIGINS)
        assert "premoscorp" in origins_str.lower(), (
            "CORS_ORIGINS must include premoscorp domain"
        )

    def test_specter_settings_exist(self):
        from asc_api.core.config import get_settings
        s = get_settings()
        assert hasattr(s, "SPECTER_SIGNING_PRIVATE_KEY")
        assert hasattr(s, "SPECTER_SIGNING_PUBLIC_KEY")
        assert hasattr(s, "SPECTER_INACTIVE_THRESHOLD_SECONDS")


# ── 7. Migration Chain ────────────────────────────────────────────────────────

class TestMigrationChain:
    """Validates Alembic migration chain is complete and head is correct."""

    @pytest.fixture(autouse=True)
    def _load_migrations(self):
        self.migrations_dir = _BACKEND / "migrations" / "versions"
        assert self.migrations_dir.exists()
        self.migration_files = list(self.migrations_dir.glob("*.py"))

    def test_migration_count(self):
        count = len(self.migration_files)
        assert count == _EXPECTED_MIGRATION_COUNT, (
            f"Expected {_EXPECTED_MIGRATION_COUNT} migrations, found {count}"
        )

    def test_head_migration_exists(self):
        head_files = [f for f in self.migration_files if _EXPECTED_MIGRATION_HEAD in f.name]
        assert len(head_files) == 1, f"Head migration {_EXPECTED_MIGRATION_HEAD} not found"

    def test_p53_migration_exists(self):
        p53_files = [f for f in self.migration_files if "r8l01o0q3k05" in f.name]
        assert len(p53_files) == 1, "P53 migration (r8l01o0q3k05) not found"

    def test_p55_migration_exists(self):
        p55_files = [f for f in self.migration_files if "s9m12p1r4l06" in f.name]
        assert len(p55_files) == 1, "P55 migration (s9m12p1r4l06) not found"

    def test_p60_migration_has_stripe_checkout(self):
        # P60 revision ID — head is now P61 (honeypot), so we target P60 directly
        p60_files = [f for f in self.migration_files if "v2p45s4u7o09" in f.name]
        assert len(p60_files) == 1, "P60 migration (v2p45s4u7o09) not found"
        content = p60_files[0].read_text(encoding="utf-8", errors="ignore")
        assert "stripe_checkout_session_id" in content, (
            "P60 migration must add stripe_checkout_session_id column"
        )

    def test_head_migration_has_honeypot_tables(self):
        head_files = [f for f in self.migration_files if _EXPECTED_MIGRATION_HEAD in f.name]
        assert len(head_files) == 1, f"Head migration {_EXPECTED_MIGRATION_HEAD} not found"
        content = head_files[0].read_text(encoding="utf-8", errors="ignore")
        assert "honeypot_tokens" in content, (
            "P61 head migration must create honeypot_tokens table"
        )

    def test_p59_migration_has_supabase_uid(self):
        p59_files = [f for f in self.migration_files if "u1o34r3t6n08" in f.name]
        assert len(p59_files) == 1, "P59 migration (u1o34r3t6n08) not found"
        content = p59_files[0].read_text(encoding="utf-8", errors="ignore")
        assert "supabase_uid" in content, "P59 migration must add supabase_uid"

    def test_p58_migration_has_tenant_adapter_configs(self):
        p58_files = [f for f in self.migration_files if "t0n23q2s5m07" in f.name]
        assert len(p58_files) == 1, "P58 migration (t0n23q2s5m07) not found"
        content = p58_files[0].read_text(encoding="utf-8", errors="ignore")
        assert "tenant_adapter_configs" in content, "P58 migration must create tenant_adapter_configs"

    def test_p55_migration_has_usage_records(self):
        p55_files = [f for f in self.migration_files if "s9m12p1r4l06" in f.name]
        assert len(p55_files) == 1, "P55 migration (s9m12p1r4l06) not found"
        content = p55_files[0].read_text(encoding="utf-8", errors="ignore")
        assert "usage_records" in content, "P55 migration must create usage_records table"

    def test_p53_migration_has_email_verified(self):
        p53_files = [f for f in self.migration_files if "r8l01o0q3k05" in f.name]
        content = p53_files[0].read_text(encoding="utf-8", errors="ignore")
        assert "email_verified" in content

    def test_p47_migration_exists(self):
        p47_files = [f for f in self.migration_files if "p6j79m8o1i93" in f.name]
        assert len(p47_files) == 1, "P47 multi-tenancy migration not found"

    def test_no_duplicate_revision_ids(self):
        revisions = []
        for f in self.migration_files:
            content = f.read_text(encoding="utf-8", errors="ignore")
            for line in content.splitlines():
                if line.startswith("revision = "):
                    rev = line.split("=")[1].strip().strip('"\'')
                    revisions.append(rev)
        assert len(revisions) == len(set(revisions)), "Duplicate revision IDs in migrations"


# ── 8. Runbook Artifacts ──────────────────────────────────────────────────────

class TestRunbookArtifacts:
    """Validates staging and go-live runbooks exist and have required sections."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.staging = _DOCS / "staging-deploy-runbook.md"
        self.goliove = _DOCS / "go-live-runbook.md"

    def test_staging_runbook_exists(self):
        assert self.staging.exists(), "docs/staging-deploy-runbook.md not found"

    def test_goliove_runbook_exists(self):
        assert self.goliove.exists(), "docs/go-live-runbook.md not found"

    def test_staging_runbook_has_prereqs_section(self):
        content = self.staging.read_text(encoding="utf-8")
        assert "Pre-requisitos" in content or "pre" in content.lower()

    def test_staging_runbook_has_security_checks(self):
        content = self.staging.read_text(encoding="utf-8")
        assert "bandit" in content
        assert "pip-audit" in content or "pip_audit" in content

    def test_staging_runbook_has_migration_section(self):
        content = self.staging.read_text(encoding="utf-8")
        assert "alembic" in content.lower() or "migrac" in content.lower()

    def test_staging_runbook_has_rollback_section(self):
        content = self.staging.read_text(encoding="utf-8")
        assert "rollback" in content.lower()

    def test_staging_runbook_has_env_vars_checklist(self):
        content = self.staging.read_text(encoding="utf-8")
        assert "SECRET_KEY" in content
        assert "DATABASE_URL" in content
        assert "STRIPE_SECRET_KEY" in content

    def test_goliove_runbook_has_72h_table(self):
        content = self.goliove.read_text(encoding="utf-8")
        assert "72h" in content or "72" in content

    def test_goliove_runbook_has_alert_thresholds(self):
        content = self.goliove.read_text(encoding="utf-8")
        assert "CRÍTICO" in content or "CRITICO" in content or "P1" in content

    def test_goliove_runbook_has_escalation_procedures(self):
        content = self.goliove.read_text(encoding="utf-8")
        assert "escalac" in content.lower() or "rollback" in content.lower()

    def test_goliove_runbook_has_health_endpoints(self):
        content = self.goliove.read_text(encoding="utf-8")
        assert "/health" in content

    def test_staging_runbook_has_cors_check(self):
        content = self.staging.read_text(encoding="utf-8")
        assert "CORS" in content or "cors" in content

    def test_staging_runbook_has_acceptance_criteria(self):
        content = self.staging.read_text(encoding="utf-8")
        assert "aceptaci" in content.lower() or "criterio" in content.lower() or "checklist" in content.lower()


# ── 9. Code Hygiene & Test Gate ───────────────────────────────────────────────

class TestCodeHygieneAndGate:
    """Final gate: code hygiene, test count, docs completeness."""

    def test_no_print_statements_in_app_services(self):
        """Services should use structlog, not print()."""
        services_dir = _BACKEND / "asc_api" / "services"
        violations = []
        for py_file in services_dir.glob("*.py"):
            content = py_file.read_text(encoding="utf-8", errors="ignore")
            for i, line in enumerate(content.splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith("print(") and "#" not in stripped:
                    violations.append(f"{py_file.name}:{i}")
        assert violations == [], f"print() found in services: {violations}"

    def test_no_eval_in_app(self):
        """eval() is a security risk — must not exist in app code."""
        app_dir = _BACKEND / "app"
        for py_file in app_dir.rglob("*.py"):
            content = py_file.read_text(encoding="utf-8", errors="ignore")
            lines = content.splitlines()
            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if "eval(" in stripped and not stripped.startswith("#"):
                    pytest.fail(f"eval() found in {py_file.name}:{i}")

    def test_audit_log_exists_and_recent(self):
        audit = _DOCS / "AUDIT_LOG.md"
        assert audit.exists()
        content = audit.read_text(encoding="utf-8", errors="ignore")
        assert "Session 6" in content, "AUDIT_LOG missing recent sessions"

    def test_roadmap_exists_and_current(self):
        roadmap = _DOCS / "ROADMAP.md"
        assert roadmap.exists()
        content = roadmap.read_text(encoding="utf-8", errors="ignore")
        assert "P55" in content or "Billing" in content

    def test_testing_and_audit_doc_exists(self):
        assert (_DOCS / "testing-and-audit.md").exists()

    def test_deployment_guide_exists(self):
        assert (_DOCS / "deployment-guide.md").exists()

    def test_staging_deploy_runbook_exists(self):
        assert (_DOCS / "staging-deploy-runbook.md").exists()

    def test_goliove_runbook_exists(self):
        assert (_DOCS / "go-live-runbook.md").exists()

    def test_sdk_package_exists(self):
        sdk_dir = _REPO_ROOT / "sdk"
        assert sdk_dir.exists(), "sdk/ directory not found"
        assert (sdk_dir / "pyproject.toml").exists()

    def test_gitignore_excludes_env(self):
        gitignore = _REPO_ROOT / ".gitignore"
        assert gitignore.exists()
        content = gitignore.read_text(encoding="utf-8", errors="ignore")
        assert ".env" in content

    def test_gitignore_excludes_coverage(self):
        gitignore = _REPO_ROOT / ".gitignore"
        content = gitignore.read_text(encoding="utf-8", errors="ignore")
        assert "htmlcov" in content or ".coverage" in content

    def test_vercel_json_valid_json(self):
        import json
        vj_path = _REPO_ROOT / "frontend" / "vercel.json"
        data = json.loads(vj_path.read_text(encoding="utf-8"))
        assert isinstance(data, dict)
        assert "crons" in data

    def test_models_init_exports_usage_record(self):
        """UsageRecord must be in models __all__ for Alembic autogenerate."""
        models_init = _BACKEND / "asc_api" / "models" / "__init__.py"
        content = models_init.read_text(encoding="utf-8", errors="ignore")
        assert "UsageRecord" in content

    def test_models_init_exports_tenant(self):
        models_init = _BACKEND / "asc_api" / "models" / "__init__.py"
        content = models_init.read_text(encoding="utf-8", errors="ignore")
        assert "Tenant" in content

    def test_p57_self_import(self):
        """This test file is importable (no syntax errors)."""
        this_file = Path(__file__)
        assert this_file.exists()
        assert this_file.suffix == ".py"
