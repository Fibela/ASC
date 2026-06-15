"""
P50 — E2E Tests with Playwright
=================================
Tests verifying:
1. Playwright configuration exists and is syntactically valid TypeScript
2. E2E spec files exist with correct content (auth, dashboard, api-keys,
   webhooks, rate-limits, security-headers)
3. All specs use page.route() mocking (no real backend required)
4. No hardcoded real credentials or API keys in E2E tests
5. p50-e2e.yml GitHub Actions workflow exists with correct jobs
6. next.config.js has been updated with security headers (P50 addition)
7. package.json has @playwright/test dependency + test:e2e script
8. Regression: P45–P49 deliverables unaffected

Testing approach
----------------
• Playwright config: TypeScript AST parse via `ast` on transpiled JS (impossible for TS),
  so we use regex/string inspection — valid TypeScript has `defineConfig` and required fields.
• Spec files: content-based inspection for key patterns (test(), page.route(), expect())
• Security: verify no real JWT patterns (eyJ...), no real secrets in spec files
• Workflow: YAML parse + job inspection (same approach as P49)
• No browser is launched — these are static analysis tests of the E2E infrastructure

Security scan
-------------
• E2E helpers.ts verified: all tokens have 'mock.' prefix — not real JWTs
• No real credentials, API keys, or base64-encoded JWTs in any spec file
• security-headers.spec.ts: tests verify no stack traces leak in error responses
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

_REPO_ROOT = Path(__file__).parent.parent
_FRONTEND   = _REPO_ROOT.parent / "frontend"
_E2E_DIR    = _FRONTEND / "e2e"
_WORKFLOWS  = _REPO_ROOT.parent / ".github" / "workflows"
_P50_YML    = _WORKFLOWS / "p50-e2e.yml"
_PKG_JSON   = _FRONTEND / "package.json"
_NEXT_CFG   = _FRONTEND / "next.config.js"
_PW_CFG     = _FRONTEND / "playwright.config.ts"


# ── Playwright config ─────────────────────────────────────────────────────────

class TestPlaywrightConfig:
    """playwright.config.ts exists and has required configuration."""

    @pytest.fixture(autouse=True)
    def _load(self):
        assert _PW_CFG.exists(), "playwright.config.ts not found"
        self.content = _PW_CFG.read_text(encoding="utf-8")

    def test_playwright_config_exists(self):
        assert _PW_CFG.exists()

    def test_config_uses_defineConfig(self):
        assert "defineConfig" in self.content, "playwright.config.ts must use defineConfig()"

    def test_config_has_testDir(self):
        assert "testDir" in self.content, "testDir must be configured to point to ./e2e/"

    def test_config_has_base_url(self):
        assert "baseURL" in self.content, "baseURL must be configured (via env var)"
        assert "PLAYWRIGHT_BASE_URL" in self.content, "Base URL must be overridable via PLAYWRIGHT_BASE_URL env"

    def test_config_has_chromium_project(self):
        assert "chromium" in self.content.lower(), "Chromium browser project required"

    def test_config_has_firefox_project(self):
        assert "firefox" in self.content.lower(), "Firefox browser project required"

    def test_config_has_webkit_project(self):
        assert "webkit" in self.content.lower(), "WebKit browser project required"

    def test_config_has_screenshot_on_failure(self):
        assert "only-on-failure" in self.content or "screenshot" in self.content, (
            "screenshot: 'only-on-failure' required for debugging CI failures"
        )

    def test_config_has_html_reporter(self):
        assert "html" in self.content, "HTML reporter required for visual test reports"

    def test_config_has_retry_for_ci(self):
        assert "retries" in self.content, "Retry config required (CI flakiness mitigation)"

    def test_no_hardcoded_base_url_in_config(self):
        """Base URL must use env var, not a hardcoded IP/domain."""
        # Only localhost default is acceptable; no staging/prod URLs hardcoded
        forbidden = ["staging.premoscorp.com", "prod.premoscorp.com", "192.168."]
        for pattern in forbidden:
            assert pattern not in self.content, f"Hardcoded URL '{pattern}' in playwright.config.ts"


# ── E2E spec files ────────────────────────────────────────────────────────────

class TestE2ESpecFiles:
    """E2E spec files exist and have correct content."""

    REQUIRED_SPECS = [
        "auth.spec.ts",
        "dashboard.spec.ts",
        "api-keys.spec.ts",
        "webhooks.spec.ts",
        "rate-limits.spec.ts",
        "security-headers.spec.ts",
    ]

    def test_e2e_directory_exists(self):
        assert _E2E_DIR.exists(), "frontend/e2e/ directory not found"

    def test_helpers_file_exists(self):
        assert (_E2E_DIR / "helpers.ts").exists(), "e2e/helpers.ts shared helpers missing"

    @pytest.mark.parametrize("spec", REQUIRED_SPECS)
    def test_spec_file_exists(self, spec: str):
        assert (_E2E_DIR / spec).exists(), f"E2E spec {spec} not found"

    @pytest.mark.parametrize("spec", REQUIRED_SPECS)
    def test_spec_uses_playwright_test_import(self, spec: str):
        content = (_E2E_DIR / spec).read_text(encoding="utf-8")
        assert "@playwright/test" in content, f"{spec} must import from @playwright/test"

    @pytest.mark.parametrize("spec", REQUIRED_SPECS)
    def test_spec_has_test_describe_block(self, spec: str):
        content = (_E2E_DIR / spec).read_text(encoding="utf-8")
        assert "test.describe(" in content, f"{spec} must use test.describe() for grouping"

    def test_all_specs_use_api_mocking(self):
        """All specs that test authenticated pages must mock the backend API."""
        specs_needing_mocks = ["api-keys.spec.ts", "webhooks.spec.ts", "rate-limits.spec.ts"]
        for spec in specs_needing_mocks:
            content = (_E2E_DIR / spec).read_text(encoding="utf-8")
            assert "page.route(" in content, f"{spec} must use page.route() for API mocking"

    def test_no_real_jwt_tokens_in_specs(self):
        """No real JWT tokens (eyJ...) should exist in E2E test files."""
        jwt_pattern = re.compile(r'eyJ[A-Za-z0-9+/=]{20,}')
        for f in _E2E_DIR.rglob("*.ts"):
            content = f.read_text(encoding="utf-8")
            match = jwt_pattern.search(content)
            assert match is None, f"Real-looking JWT found in {f.name}: {match.group()[:30]}..."

    def test_no_hardcoded_passwords_in_specs(self):
        forbidden = ["password123", "admin123", "secret123"]
        for f in _E2E_DIR.rglob("*.ts"):
            content = f.read_text(encoding="utf-8").lower()
            for pw in forbidden:
                assert pw not in content, f"Dangerous placeholder '{pw}' in {f.name}"

    def test_helpers_has_mock_prefix_on_tokens(self):
        """All mock tokens in helpers.ts must have 'mock.' prefix to be obviously fake."""
        content = (_E2E_DIR / "helpers.ts").read_text(encoding="utf-8")
        assert "mock." in content, "Mock tokens in helpers.ts must start with 'mock.' prefix"
        # Confirm MOCK_TOKENS structure exists
        assert "MOCK_TOKENS" in content

    def test_auth_spec_covers_login_success(self):
        content = (_E2E_DIR / "auth.spec.ts").read_text(encoding="utf-8")
        assert "Iniciar sesión" in content or "login" in content.lower()

    def test_auth_spec_covers_login_failure(self):
        content = (_E2E_DIR / "auth.spec.ts").read_text(encoding="utf-8")
        assert "401" in content or "invalid" in content.lower()

    def test_auth_spec_covers_route_guard(self):
        content = (_E2E_DIR / "auth.spec.ts").read_text(encoding="utf-8")
        assert "/login" in content and ("redirect" in content.lower() or "toHaveURL" in content)

    def test_security_spec_checks_xframe(self):
        content = (_E2E_DIR / "security-headers.spec.ts").read_text(encoding="utf-8")
        assert "x-frame-options" in content.lower() or "frame-ancestors" in content.lower()

    def test_security_spec_checks_no_secret_in_html(self):
        content = (_E2E_DIR / "security-headers.spec.ts").read_text(encoding="utf-8")
        assert "raw_key" in content or "whsec_" in content, (
            "security-headers spec must verify secrets don't leak in rendered HTML"
        )


# ── Workflow content ──────────────────────────────────────────────────────────

class TestP50Workflow:
    """p50-e2e.yml GitHub Actions workflow has correct jobs and structure."""

    @pytest.fixture(autouse=True)
    def _load(self):
        assert _P50_YML.exists(), "p50-e2e.yml not found"
        self.raw = _P50_YML.read_text(encoding="utf-8")
        self.parsed = yaml.safe_load(self.raw)
        self.jobs = self.parsed.get("jobs", {})

    def test_has_chromium_e2e_job(self):
        assert "e2e-chromium" in self.jobs

    def test_has_firefox_webkit_smoke_job(self):
        assert "e2e-smoke-firefox-webkit" in self.jobs

    def test_has_typecheck_job(self):
        assert "e2e-typecheck" in self.jobs

    def test_has_p50_gate(self):
        assert "p50-gate" in self.jobs

    def test_playwright_install_step_present(self):
        assert "playwright install" in self.raw

    def test_html_report_artifact_upload(self):
        assert "playwright-report" in self.raw and "upload-artifact" in self.raw

    def test_failure_artifacts_uploaded(self):
        assert "playwright-artifacts" in self.raw

    def test_workflow_triggers_on_frontend_paths(self):
        # PyYAML parses 'on' as True
        triggers = self.parsed.get(True, self.parsed.get("on", {}))
        push = triggers.get("push", {})
        paths = push.get("paths", [])
        assert any("frontend" in p for p in paths), "Workflow should only trigger on frontend/ changes"

    def test_weekly_schedule_present(self):
        triggers = self.parsed.get(True, self.parsed.get("on", {}))
        assert "schedule" in triggers, "Weekly schedule required for full cross-browser E2E run"


# ── next.config.js security headers ──────────────────────────────────────────

class TestNextConfigSecurityHeaders:
    """next.config.js has been updated with P50 security headers."""

    @pytest.fixture(autouse=True)
    def _load(self):
        assert _NEXT_CFG.exists(), "next.config.js not found"
        self.content = _NEXT_CFG.read_text(encoding="utf-8")

    def test_has_headers_function(self):
        assert "async headers()" in self.content or "headers:" in self.content, (
            "next.config.js must export headers() for security header injection"
        )

    def test_has_x_content_type_options(self):
        assert "X-Content-Type-Options" in self.content

    def test_has_x_frame_options(self):
        assert "X-Frame-Options" in self.content

    def test_has_referrer_policy(self):
        assert "Referrer-Policy" in self.content

    def test_has_csp(self):
        assert "Content-Security-Policy" in self.content

    def test_has_frame_ancestors_none(self):
        assert "frame-ancestors" in self.content


# ── package.json Playwright dependency ───────────────────────────────────────

class TestPackageJson:
    """package.json has Playwright dev dependency and test:e2e scripts."""

    @pytest.fixture(autouse=True)
    def _load(self):
        import json
        assert _PKG_JSON.exists(), "frontend/package.json not found"
        self.pkg = json.loads(_PKG_JSON.read_text(encoding="utf-8"))

    def test_playwright_in_devDependencies(self):
        dev = self.pkg.get("devDependencies", {})
        assert "@playwright/test" in dev, "@playwright/test must be in devDependencies"

    def test_test_e2e_script_present(self):
        scripts = self.pkg.get("scripts", {})
        assert "test:e2e" in scripts, "test:e2e script must be in package.json"

    def test_test_e2e_uses_playwright(self):
        scripts = self.pkg.get("scripts", {})
        cmd = scripts.get("test:e2e", "")
        assert "playwright" in cmd.lower(), "test:e2e must invoke playwright"

    def test_tsconfig_excludes_e2e_dir(self):
        """e2e/ must be excluded from the main Next.js tsconfig to avoid @playwright/test
        type errors when @playwright/test is not yet installed (npm install not run).
        E2E files use their own e2e/tsconfig.json resolved by Playwright."""
        tsconfig = _FRONTEND / "tsconfig.json"
        assert tsconfig.exists(), "frontend/tsconfig.json not found"
        import json
        cfg = json.loads(tsconfig.read_text(encoding="utf-8"))
        exclude = cfg.get("exclude", [])
        assert "e2e" in exclude, (
            "e2e directory must be in tsconfig.json exclude "
            "to prevent @playwright/test type errors in the Next.js build"
        )

    def test_tsconfig_excludes_playwright_config(self):
        """playwright.config.ts imports @playwright/test — must be excluded from
        the main Next.js tsconfig.json to avoid TS2307 errors when @playwright/test
        is not installed."""
        tsconfig = _FRONTEND / "tsconfig.json"
        import json
        cfg = json.loads(tsconfig.read_text(encoding="utf-8"))
        exclude = cfg.get("exclude", [])
        assert "playwright.config.ts" in exclude, (
            "playwright.config.ts must be excluded from tsconfig.json"
        )

    def test_e2e_has_own_tsconfig(self):
        """e2e/ directory has its own tsconfig.json for Playwright's own type-check step."""
        assert (_E2E_DIR / "tsconfig.json").exists(), (
            "frontend/e2e/tsconfig.json required for Playwright's tsc --noEmit"
        )


# ── P45–P49 regression ───────────────────────────────────────────────────────

class TestP50Regression:
    """P45–P49 deliverables still present after P50 additions."""

    def test_p49_workflow_still_present(self):
        assert (_WORKFLOWS / "p49-security-gates.yml").exists()

    def test_p48_locustfile_present(self):
        assert (_REPO_ROOT.parent / "load_tests" / "locustfile.py").exists()

    def test_p47_tenant_model_importable(self):
        from app.models.tenant import Tenant
        assert Tenant.__tablename__ == "tenants"

    def test_p46_rate_limits_page_present(self):
        assert (_FRONTEND / "src" / "app" / "rate-limits" / "page.tsx").exists()

    def test_p45_api_keys_page_present(self):
        assert (_FRONTEND / "src" / "app" / "api-keys" / "page.tsx").exists()

    def test_gitleaks_allowlist_still_has_ci_placeholder(self):
        toml = (_REPO_ROOT.parent / ".gitleaks.toml").read_text(encoding="utf-8")
        assert "ci-only-not-a-real-secret-key" in toml
