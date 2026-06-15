"""
P49 — CI/CD Security Gates
============================
Tests verifying:
1. All GitHub Actions workflow files exist and are valid YAML
2. P49 workflow has all required jobs (trivy-fs, safety, gitleaks-sarif, bandit-sarif,
   dependency-review, p49-gate)
3. Trivy filesystem scan is configured as CRITICAL-blocking (exit-code 1, not 0)
4. .gitleaks.toml exists with custom ASC rules and allowlist patterns
5. Safety CVE audit job present and evaluates JSON output
6. SARIF upload steps configured for Security tab visibility
7. Local security hygiene checks (no hardcoded secrets, no dangerous patterns)
8. Regression: P45–P48 workflows + test files still present

Testing approach
----------------
• Workflow YAML validation: parsed with PyYAML — catches malformed YAML before push
• Job/step presence: string search on raw YAML text (avoids YAML anchor complexity)
• Local security: targeted regex patterns against app code — mirrors what CI gates check
• No live network calls, no Docker, no real CI runner required
• Pattern checks mirror ci.yml + security-audit.yml + p49-security-gates.yml logic

Security scan
-------------
• Verified: no hardcoded credentials, API keys, or real tokens in test file
• All test assertions use placeholder-detection patterns, not actual secret values
• Backend code scanned for dangerous patterns (eval, exec, hardcoded passwords)
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest
import yaml

_REPO_ROOT = Path(__file__).parent.parent
_WORKFLOWS = _REPO_ROOT.parent / ".github" / "workflows"
_P49_YML = _WORKFLOWS / "p49-security-gates.yml"
_CI_YML = _WORKFLOWS / "ci.yml"
_SEC_YML = _WORKFLOWS / "security-audit.yml"
_DEPLOY_YML = _WORKFLOWS / "deploy.yml"
_GITLEAKS_TOML = _REPO_ROOT.parent / ".gitleaks.toml"


# ── Workflow file existence + YAML validity ───────────────────────────────────

class TestWorkflowFiles:
    """GitHub Actions workflow files exist and are syntactically valid YAML."""

    def test_ci_yml_exists(self):
        assert _CI_YML.exists(), "ci.yml missing — CI pipeline not configured"

    def test_security_audit_yml_exists(self):
        assert _SEC_YML.exists(), "security-audit.yml missing"

    def test_deploy_yml_exists(self):
        assert _DEPLOY_YML.exists(), "deploy.yml missing"

    def test_p49_security_gates_yml_exists(self):
        assert _P49_YML.exists(), "p49-security-gates.yml missing — P49 not deployed"

    def test_ci_yml_valid_yaml(self):
        content = _CI_YML.read_text(encoding="utf-8")
        parsed = yaml.safe_load(content)
        assert isinstance(parsed, dict), "ci.yml is not a valid YAML mapping"

    def test_security_audit_yml_valid_yaml(self):
        content = _SEC_YML.read_text(encoding="utf-8")
        parsed = yaml.safe_load(content)
        assert isinstance(parsed, dict)

    def test_p49_yml_valid_yaml(self):
        content = _P49_YML.read_text(encoding="utf-8")
        parsed = yaml.safe_load(content)
        assert isinstance(parsed, dict), "p49-security-gates.yml is not valid YAML"

    def test_p49_has_correct_workflow_name(self):
        parsed = yaml.safe_load(_P49_YML.read_text(encoding="utf-8"))
        name = parsed.get("name", "")
        assert "P49" in name or "Security Gate" in name, f"Unexpected workflow name: {name!r}"


# ── P49 workflow content: required jobs ──────────────────────────────────────

class TestP49WorkflowContent:
    """P49 workflow has all required security gate jobs with correct config."""

    @pytest.fixture(autouse=True)
    def _load(self):
        self.raw = _P49_YML.read_text(encoding="utf-8")
        self.parsed = yaml.safe_load(self.raw)
        self.jobs = self.parsed.get("jobs", {})

    def test_has_trivy_fs_job(self):
        assert "trivy-fs" in self.jobs, "trivy-fs job missing from P49 workflow"

    def test_has_safety_job(self):
        assert "safety" in self.jobs, "safety job missing from P49 workflow"

    def test_has_gitleaks_sarif_job(self):
        assert "gitleaks-sarif" in self.jobs, "gitleaks-sarif job missing"

    def test_has_bandit_sarif_job(self):
        assert "bandit-sarif" in self.jobs, "bandit-sarif job missing"

    def test_has_dependency_review_job(self):
        assert "dependency-review" in self.jobs, "dependency-review job missing"

    def test_has_p49_gate_job(self):
        assert "p49-gate" in self.jobs, "p49-gate aggregate job missing"

    def test_trivy_fs_is_blocking_exit_code_1(self):
        """Trivy must use exit-code 1 (CRITICAL blocking), not 0 (informational)."""
        assert "exit-code: '1'" in self.raw or 'exit-code: "1"' in self.raw, (
            "trivy-fs must set exit-code: '1' to block on CRITICAL findings"
        )

    def test_trivy_fs_scans_filesystem(self):
        """Trivy must scan the filesystem, not just Docker images."""
        assert "scan-type: fs" in self.raw, "trivy-fs must use scan-type: fs"

    def test_trivy_outputs_sarif(self):
        assert "format: sarif" in self.raw, "trivy must output SARIF for Security tab"

    def test_sarif_upload_steps_present(self):
        """At least one SARIF upload step to GitHub Security tab."""
        assert "upload-sarif" in self.raw, "No SARIF upload steps found in P49 workflow"

    def test_dependency_review_pr_only(self):
        """dependency-review must only run on pull_request events."""
        dep_job = self.jobs.get("dependency-review", {})
        condition = str(dep_job.get("if", ""))
        assert "pull_request" in condition, (
            "dependency-review must be gated with 'if: github.event_name == pull_request'"
        )

    def test_p49_gate_requires_all_core_jobs(self):
        """p49-gate must depend on trivy-fs, safety, gitleaks-sarif, bandit-sarif."""
        gate = self.jobs.get("p49-gate", {})
        needs = gate.get("needs", [])
        for required in ["trivy-fs", "safety", "gitleaks-sarif", "bandit-sarif"]:
            assert required in needs, f"p49-gate is missing 'needs: {required}'"

    def test_workflow_has_daily_schedule(self):
        """Daily scheduled run catches newly-disclosed CVEs without code changes."""
        # PyYAML parses YAML 'on' key as Python bool True — access via True key
        triggers = self.parsed.get(True, self.parsed.get("on", {}))
        assert "schedule" in triggers, "P49 workflow must have a scheduled cron trigger"
        crons = [s.get("cron", "") for s in triggers["schedule"]]
        assert any(crons), "schedule block has no cron entries"

    def test_deny_copyleft_licenses(self):
        """dependency-review must deny GPL/AGPL licenses for SaaS compatibility."""
        assert "GPL" in self.raw, (
            "dependency-review must deny GPL licenses (incompatible with commercial SaaS)"
        )


# ── Gitleaks config ───────────────────────────────────────────────────────────

class TestGitleaksConfig:
    """gitleaks.toml exists with ASC custom rules and safe allowlists."""

    @pytest.fixture(autouse=True)
    def _load(self):
        assert _GITLEAKS_TOML.exists(), ".gitleaks.toml not found at repo root"
        self.content = _GITLEAKS_TOML.read_text(encoding="utf-8")

    def test_gitleaks_toml_exists(self):
        assert _GITLEAKS_TOML.exists()

    def test_has_crowdstrike_rule(self):
        assert "crowdstrike" in self.content.lower(), (
            "Missing CrowdStrike detection rule in .gitleaks.toml"
        )

    def test_has_paloalto_rule(self):
        assert "paloalto" in self.content.lower(), (
            "Missing Palo Alto detection rule in .gitleaks.toml"
        )

    def test_allowlist_includes_test_dirs(self):
        assert "tests" in self.content, (
            "Allowlist must exclude test dirs (intentional test fixtures trigger false positives)"
        )

    def test_allowlist_includes_load_test_placeholder(self):
        assert "REPLACE_ME_WITH_REAL_JWT_TOKEN" in self.content, (
            "locustfile.py REPLACE_ME placeholder must be in gitleaks allowlist"
        )

    def test_allowlist_includes_ci_placeholder(self):
        assert "ci-only-not-a-real-secret-key" in self.content, (
            "CI-only SECRET_KEY placeholder must be in gitleaks allowlist"
        )


# ── Local security hygiene (mirrors CI gate checks) ──────────────────────────

class TestSecurityHygiene:
    """Local checks that mirror what the CI security gates enforce."""

    _APP = _REPO_ROOT / "app"

    def _app_py_files(self):
        return list(self._APP.rglob("*.py"))

    def _services(self):
        return list((self._APP / "services").rglob("*.py"))

    def test_no_password123_in_app(self):
        for f in self._app_py_files():
            content = f.read_text(encoding="utf-8", errors="ignore")
            assert "password123" not in content.lower(), (
                f"Dangerous placeholder 'password123' found in {f}"
            )

    def test_no_secret123_in_app(self):
        for f in self._app_py_files():
            content = f.read_text(encoding="utf-8", errors="ignore")
            assert "secret123" not in content.lower(), (
                f"Dangerous placeholder 'secret123' found in {f}"
            )

    def test_no_eval_in_app_services(self):
        """eval() in service code is an RCE vector — must not appear."""
        pattern = re.compile(r'\beval\s*\(')
        for f in self._services():
            content = f.read_text(encoding="utf-8", errors="ignore")
            match = pattern.search(content)
            assert match is None, f"eval() found in service: {f}"

    def test_no_hardcoded_db_password_in_app(self):
        """DATABASE_URL must never be hardcoded in service/endpoint code — use env vars.
        config.py is excluded because Settings classes declare defaults overridden by env vars.
        The 'asc_pass' placeholder there is also in the gitleaks allowlist.
        """
        hardcoded = re.compile(r'postgresql(\+asyncpg)?://\w+:[^@\$\{]{4,}@')
        excluded = {"config.py"}
        for f in self._app_py_files():
            if f.name in excluded:
                continue
            content = f.read_text(encoding="utf-8", errors="ignore")
            if hardcoded.search(content):
                pytest.fail(f"Hardcoded DB password in {f}")

    def test_no_print_in_services(self):
        """Services must use structlog, not print() — mirrors ci security gate."""
        for f in self._services():
            content = f.read_text(encoding="utf-8", errors="ignore")
            for i, line in enumerate(content.splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith("print("):
                    pytest.fail(f"print() found in service {f}:{i} — use structlog")

    def test_no_admin123_in_app(self):
        for f in self._app_py_files():
            content = f.read_text(encoding="utf-8", errors="ignore")
            assert "admin123" not in content.lower(), f"admin123 found in {f}"

    def test_pyproject_has_bandit_config(self):
        """bandit must be configured in pyproject.toml so local + CI runs are consistent.
        pyproject.toml lives at the repo root (one level above backend/).
        """
        pyproject = _REPO_ROOT.parent / "pyproject.toml"
        assert pyproject.exists(), f"pyproject.toml not found at {pyproject}"
        content = pyproject.read_text(encoding="utf-8")
        assert "[tool.bandit]" in content, "Missing [tool.bandit] section in pyproject.toml"


# ── P45–P48 regression ───────────────────────────────────────────────────────

class TestP49Regression:
    """Existing sprint deliverables unaffected by P49 additions."""

    def test_ci_yml_still_has_gitleaks_job(self):
        content = _CI_YML.read_text(encoding="utf-8")
        assert "gitleaks" in content

    def test_security_audit_still_has_bandit(self):
        content = _SEC_YML.read_text(encoding="utf-8")
        assert "bandit" in content

    def test_security_audit_still_has_pip_audit(self):
        content = _SEC_YML.read_text(encoding="utf-8")
        assert "pip-audit" in content

    def test_p48_locust_file_still_present(self):
        path = _REPO_ROOT.parent / "load_tests" / "locustfile.py"
        assert path.exists()

    def test_p47_tenant_model_importable(self):
        from app.models.tenant import Tenant
        assert Tenant.__tablename__ == "tenants"

    def test_p46_rate_limits_page_present(self):
        path = _REPO_ROOT.parent / "frontend" / "src" / "app" / "rate-limits" / "page.tsx"
        assert path.exists()

    def test_p45_api_keys_page_present(self):
        path = _REPO_ROOT.parent / "frontend" / "src" / "app" / "api-keys" / "page.tsx"
        assert path.exists()
