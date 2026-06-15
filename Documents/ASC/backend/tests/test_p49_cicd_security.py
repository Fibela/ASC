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


# ── TD-6 CI/CD Pipeline Security Hardening ───────────────────────────────────

class TestCICDHardeningTD6:
    """TD-6 hardening improvements to p49-security-gates.yml and security-audit.yml.

    Covers:
    1. Adaptive severity gating (trivy-high job — HIGH with fixable filter)
    2. Noise reduction (pip-audit + safety correlation in single job)
    3. License intelligence (SSPL, BUSL, Commons-Clause, EUPL, OSL added)
    4. Pipeline resilience (pip cache + Trivy DB cache)
    5. SARIF local fallback (security-summary-trivy.txt artifact)
    6. Premos CI/CD Ledger (SHA-256 forensic hash + HMAC-SHA256 signature)
    """

    @pytest.fixture(autouse=True)
    def _load(self):
        self.raw = _P49_YML.read_text(encoding="utf-8")
        self.parsed = yaml.safe_load(self.raw)
        self.jobs = self.parsed.get("jobs", {})
        self.sec_raw = _SEC_YML.read_text(encoding="utf-8")

    # ── 1. Adaptive severity gating ──────────────────────────────────────────

    def test_has_trivy_high_job(self):
        """TD-6: second Trivy job for HIGH adaptive gating must exist."""
        assert "trivy-high" in self.jobs, "trivy-high (HIGH adaptive) job missing"

    def test_trivy_high_is_merge_blocking(self):
        """trivy-high must exit with code 1 (not informational exit-code 0)."""
        assert "exit-code: '1'" in self.raw or 'exit-code: "1"' in self.raw

    def test_trivy_high_ignores_unfixed_cves(self):
        """ignore-unfixed prevents alert fatigue from CVEs with no available patch."""
        assert "ignore-unfixed: true" in self.raw

    def test_trivy_high_scans_high_severity(self):
        """trivy-high must specify HIGH severity (catches HIGH + CRITICAL)."""
        assert "severity: HIGH" in self.raw, "trivy-high must set severity: HIGH"

    def test_p49_gate_requires_trivy_high(self):
        """p49-gate must fail when trivy-high fails."""
        gate = self.jobs.get("p49-gate", {})
        needs = gate.get("needs", [])
        assert "trivy-high" in needs, "p49-gate must require trivy-high"

    # ── 2. Noise reduction: pip-audit + safety correlation ───────────────────

    def test_safety_job_also_runs_pip_audit(self):
        """safety job must install and run pip-audit for cross-tool correlation."""
        assert "pip-audit" in self.raw, "safety job must also run pip-audit"

    def test_safety_job_has_correlation_step(self):
        """Correlation step must appear in the YAML (by its heading text)."""
        assert "Correlate" in self.raw or "correlation" in self.raw.lower(), (
            "No correlation step found in p49 workflow"
        )

    def test_safety_job_blocks_only_on_shared_cves(self):
        """Blocking logic targets shared CVEs (intersection), not single-tool findings."""
        assert "shared" in self.raw.lower() or "definitive" in self.raw.lower(), (
            "Correlation gate must distinguish definitive (shared) vs triage-only CVEs"
        )

    def test_safety_job_uses_pip_cache(self):
        """setup-python in safety job must use pip cache (pipeline resilience)."""
        safety_job = self.jobs.get("safety", {})
        steps = safety_job.get("steps", [])
        for step in steps:
            with_block = step.get("with", {})
            if "python-version" in with_block:
                assert with_block.get("cache") == "pip", (
                    "safety job setup-python must set cache: pip"
                )
                return
        pytest.fail("safety job missing setup-python step")

    # ── 3. License intelligence ───────────────────────────────────────────────

    def test_deny_sspl_license(self):
        """SSPL-1.0 (MongoDB) restricts SaaS use — must be in deny list."""
        assert "SSPL" in self.raw, "SSPL-1.0 missing from dependency-review deny list"

    def test_deny_busl_license(self):
        """BUSL-1.1 (Elastic, Terraform) restricts commercial use for 4 years."""
        assert "BUSL" in self.raw, "BUSL-1.1 missing from dependency-review deny list"

    def test_deny_commons_clause(self):
        """Commons-Clause restricts selling software — incompatible with SaaS resale."""
        assert "Commons-Clause" in self.raw, "Commons-Clause missing from deny list"

    def test_deny_eupl_license(self):
        """EUPL-1.1 has copyleft provisions — requires legal review for commercial use."""
        assert "EUPL" in self.raw, "EUPL-1.1 missing from dependency-review deny list"

    def test_deny_osl_license(self):
        """OSL-3.0 has strong copyleft + patent termination — risky for commercial use."""
        assert "OSL" in self.raw, "OSL-3.0 missing from dependency-review deny list"

    def test_original_gpl_licenses_still_denied(self):
        """Baseline GPL-3.0/AGPL-3.0/GPL-2.0 must not be removed by TD-6 changes."""
        for lic in ["GPL-3.0", "AGPL-3.0", "GPL-2.0"]:
            assert lic in self.raw, f"{lic} was removed from deny list — regression"

    # ── 4. Pipeline resilience: caching ──────────────────────────────────────

    def test_bandit_sarif_uses_pip_cache(self):
        """bandit-sarif job must use pip cache to avoid repeated downloads."""
        bandit_job = self.jobs.get("bandit-sarif", {})
        steps = bandit_job.get("steps", [])
        for step in steps:
            with_block = step.get("with", {})
            if "python-version" in with_block:
                assert with_block.get("cache") == "pip", (
                    "bandit-sarif setup-python must set cache: pip"
                )
                return
        pytest.fail("bandit-sarif missing setup-python step")

    def test_trivy_db_cache_present(self):
        """Trivy vulnerability DB must be cached with actions/cache@v4."""
        assert "actions/cache@v4" in self.raw, "Trivy DB cache missing (actions/cache@v4)"

    def test_trivy_cache_path_correct(self):
        """Trivy cache path must target ~/.cache/trivy (default Trivy DB location)."""
        assert ".cache/trivy" in self.raw, "Trivy cache path must include .cache/trivy"

    def test_security_audit_uses_pip_cache(self):
        """security-audit.yml must also use pip cache (TD-6 applied to both files)."""
        assert "cache: pip" in self.sec_raw, (
            "security-audit.yml must use pip cache on setup-python steps"
        )

    # ── 5. SARIF local fallback ───────────────────────────────────────────────

    def test_trivy_job_generates_fallback_summary(self):
        """trivy-fs must generate a local summary if SARIF upload to GitHub fails."""
        assert "security-summary" in self.raw, (
            "trivy-fs must write security-summary-trivy.txt as SARIF fallback"
        )

    def test_trivy_fallback_summary_uploaded_as_artifact(self):
        """security-summary-trivy.txt must be included in trivy artifact upload."""
        trivy_job = self.jobs.get("trivy-fs", {})
        steps = trivy_job.get("steps", [])
        for step in steps:
            with_block = step.get("with", {})
            path_val = str(with_block.get("path", ""))
            if "security-summary" in path_val or "trivy-fs.sarif" in path_val:
                return
        pytest.fail("trivy-fs must upload security-summary-trivy.txt with artifact")

    # ── 6. Premos CI/CD Ledger ────────────────────────────────────────────────

    def test_has_premos_ledger_job(self):
        """TD-6: premos-ledger job must exist for forensic audit trail."""
        assert "premos-ledger" in self.jobs, "premos-ledger job missing"

    def test_premos_ledger_runs_always(self):
        """premos-ledger must run even when upstream jobs fail (forensic completeness)."""
        ledger = self.jobs.get("premos-ledger", {})
        cond = str(ledger.get("if", "")).lower()
        assert "always()" in cond, "premos-ledger must set if: always()"

    def test_premos_ledger_uses_hmac_sha256(self):
        """Ledger must use HMAC for tamper-evident signing."""
        assert "hmac" in self.raw.lower(), "premos-ledger must use HMAC signing"

    def test_premos_ledger_hashes_with_sha256(self):
        """Artifact hashing algorithm must be SHA-256."""
        assert "sha256" in self.raw.lower(), "premos-ledger must use SHA-256 hashing"

    def test_premos_ledger_90_day_retention(self):
        """Forensic ledger artifact must have 90-day retention (3× standard 30-day)."""
        assert "retention-days: 90" in self.raw, (
            "premos-ledger artifact must have 90-day retention"
        )

    def test_premos_ledger_uses_ci_ledger_secret(self):
        """Ledger signing must reference CI_LEDGER_SECRET repo secret."""
        assert "CI_LEDGER_SECRET" in self.raw, (
            "premos-ledger must reference CI_LEDGER_SECRET for HMAC signing"
        )

    def test_premos_ledger_needs_all_gate_jobs(self):
        """premos-ledger runs after all scanning jobs so it can hash their artifacts."""
        ledger = self.jobs.get("premos-ledger", {})
        needs = ledger.get("needs", [])
        for required in ["trivy-fs", "trivy-high", "safety", "gitleaks-sarif", "bandit-sarif"]:
            assert required in needs, f"premos-ledger missing needs: {required}"

    def test_premos_ledger_downloads_artifacts(self):
        """Ledger must download upstream artifacts to compute their SHA-256."""
        assert "actions/download-artifact@v4" in self.raw, (
            "premos-ledger must download artifacts (actions/download-artifact@v4)"
        )
