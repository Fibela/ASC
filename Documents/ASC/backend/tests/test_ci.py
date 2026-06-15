"""
Priority 8 — CI/CD Pipeline Validation Tests.

These tests validate that the CI/CD toolchain configuration is correct
and that the codebase meets the quality gates enforced in GitHub Actions.

What is tested:
  TestWorkflowYAML        — .github/workflows/*.yml are syntactically valid
                            and contain the expected jobs
  TestDependencies        — requirements files are complete for CI execution
  TestCodeQuality         — anti-patterns that CI checks would catch
  TestProjectConfig       — pyproject.toml and .gitignore hygiene
  TestSecurityBaseline    — no hardcoded secrets or dangerous patterns

These tests run as part of the normal pytest suite so CI failures
are caught locally before push, mirroring the GitHub Actions checks.
"""

import re
import ast
import tomllib
from pathlib import Path

import pytest
import yaml  # pyyaml — added to requirements-dev.txt in P8


# ─── Path constants ───────────────────────────────────────────────────────────

# Resolve paths relative to this file's location (backend/tests/test_ci.py)
TESTS_DIR  = Path(__file__).parent                        # backend/tests/
BACKEND    = TESTS_DIR.parent                             # backend/
ROOT       = BACKEND.parent                               # repo root (ASC/)
APP        = BACKEND / "app"
WORKFLOWS  = ROOT / ".github" / "workflows"
SERVICES   = APP / "services"
ENDPOINTS  = APP / "api" / "v1" / "endpoints"
ADAPTERS   = APP / "adapters"


# ═══════════════════════════════════════════════════════════════════════════════
# TestWorkflowYAML — GitHub Actions workflow files
# ═══════════════════════════════════════════════════════════════════════════════

class TestWorkflowYAML:
    """Validate .github/workflows/*.yml are syntactically valid and well-structured."""

    def _load(self, name: str) -> dict:
        path = WORKFLOWS / name
        assert path.exists(), f"Workflow file missing: {path}"
        with open(path, encoding="utf-8") as f:
            return yaml.safe_load(f)

    def test_ci_yml_is_valid_yaml(self):
        doc = self._load("ci.yml")
        assert isinstance(doc, dict), "ci.yml parsed as non-dict"

    def test_security_audit_yml_is_valid_yaml(self):
        doc = self._load("security-audit.yml")
        assert isinstance(doc, dict)

    def test_ci_yml_has_lint_job(self):
        doc = self._load("ci.yml")
        assert "lint" in doc["jobs"], "ci.yml is missing 'lint' job"

    def test_ci_yml_has_test_backend_job(self):
        doc = self._load("ci.yml")
        assert "test-backend" in doc["jobs"], "ci.yml is missing 'test-backend' job"

    def test_ci_yml_has_gitleaks_job(self):
        doc = self._load("ci.yml")
        assert "gitleaks" in doc["jobs"], "ci.yml is missing 'gitleaks' job"

    def test_ci_yml_has_ci_gate_job(self):
        doc = self._load("ci.yml")
        assert "ci-gate" in doc["jobs"], "ci.yml is missing 'ci-gate' job"

    def test_ci_yml_backend_job_no_marker_filter(self):
        """The -m 'unit' marker filter was the original bug — verify it's gone."""
        path = WORKFLOWS / "ci.yml"
        content = path.read_text(encoding="utf-8")
        assert "-m unit" not in content and "-m 'unit'" not in content, (
            "ci.yml still contains '-m unit' marker filter that produces 0 collected tests"
        )

    def test_ci_yml_backend_job_has_working_directory(self):
        """pytest must run from backend/ so pytest.ini is found correctly."""
        path = WORKFLOWS / "ci.yml"
        content = path.read_text(encoding="utf-8")
        assert "working-directory: backend" in content, (
            "test-backend job must set 'working-directory: backend'"
        )

    def test_ci_yml_no_hardcoded_secrets(self):
        """CI secrets should come from ${{ secrets.X }}, not be hardcoded."""
        content = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
        dangerous = re.findall(r'SECRET_KEY:\s*["\']?[a-zA-Z0-9]{32,}', content)
        # The one SECRET_KEY value in env: is a clearly labeled CI placeholder
        for d in dangerous:
            assert "ci-only" in d or "test" in d.lower(), (
                f"Possible real secret hardcoded in ci.yml: {d!r}"
            )

    def test_security_audit_yml_has_bandit_job(self):
        doc = self._load("security-audit.yml")
        assert "bandit" in doc["jobs"], "security-audit.yml missing 'bandit' job"

    def test_security_audit_yml_has_pip_audit_job(self):
        doc = self._load("security-audit.yml")
        assert "pip-audit" in doc["jobs"], "security-audit.yml missing 'pip-audit' job"

    def test_security_audit_yml_has_security_gate(self):
        doc = self._load("security-audit.yml")
        assert "security-gate" in doc["jobs"], "security-audit.yml missing 'security-gate' job"

    def test_security_audit_yml_has_schedule(self):
        """Weekly scheduled scan catches CVEs in pinned deps even without code changes."""
        doc = self._load("security-audit.yml")
        # PyYAML 1.1 parses bare `on:` as boolean True (YAML 1.1 quirk).
        # GitHub Actions workflows use `on:` as the trigger key — check both.
        triggers = doc.get(True, doc.get("on", {})) or {}
        assert "schedule" in triggers, (
            "security-audit.yml must have a schedule trigger for weekly CVE scans"
        )

    def test_ci_yml_has_concurrency_cancel(self):
        """Concurrent-run cancellation saves Actions minutes."""
        doc = self._load("ci.yml")
        assert "concurrency" in doc, "ci.yml should have concurrency: cancel-in-progress"


# ═══════════════════════════════════════════════════════════════════════════════
# TestDependencies — requirements files completeness
# ═══════════════════════════════════════════════════════════════════════════════

class TestDependencies:
    """Verify requirements files contain what CI actually needs."""

    def _read_req(self, filename: str) -> str:
        path = BACKEND / filename
        assert path.exists(), f"{filename} not found"
        return path.read_text(encoding="utf-8").lower()

    def test_aiosqlite_in_dev_requirements(self):
        """aiosqlite is required by conftest.py for in-memory SQLite tests."""
        content = self._read_req("requirements-dev.txt")
        assert "aiosqlite" in content, (
            "aiosqlite missing from requirements-dev.txt — conftest.py "
            "uses sqlite+aiosqlite:// and CI will fail without it"
        )

    def test_pyyaml_in_dev_requirements(self):
        """pyyaml is required by test_ci.py (this file)."""
        content = self._read_req("requirements-dev.txt")
        assert "pyyaml" in content, (
            "pyyaml missing from requirements-dev.txt — test_ci.py imports yaml"
        )

    def test_pytest_in_dev_requirements(self):
        content = self._read_req("requirements-dev.txt")
        assert "pytest" in content

    def test_pytest_asyncio_in_dev_requirements(self):
        content = self._read_req("requirements-dev.txt")
        assert "pytest-asyncio" in content

    def test_pytest_cov_in_dev_requirements(self):
        content = self._read_req("requirements-dev.txt")
        assert "pytest-cov" in content

    def test_fastapi_in_production_requirements(self):
        content = self._read_req("requirements.txt")
        assert "fastapi" in content

    def test_sqlalchemy_in_production_requirements(self):
        content = self._read_req("requirements.txt")
        assert "sqlalchemy" in content

    def test_no_dev_tools_in_production_requirements(self):
        """pytest, bandit, ruff must not be in the production requirements file."""
        content = self._read_req("requirements.txt")
        for dev_tool in ("pytest", "ruff", "bandit", "pip-audit"):
            assert dev_tool not in content, (
                f"{dev_tool!r} found in requirements.txt — move it to requirements-dev.txt"
            )


# ═══════════════════════════════════════════════════════════════════════════════
# TestCodeQuality — anti-patterns that CI checks catch
# ═══════════════════════════════════════════════════════════════════════════════

class TestCodeQuality:
    """Enforce code quality rules mirroring CI lint/hardcoded-check jobs."""

    def _collect_py_files(self, directory: Path) -> list[Path]:
        return list(directory.rglob("*.py"))

    def test_no_print_in_services(self):
        """Services must use structlog (log.*), not print()."""
        violations = []
        for py_file in self._collect_py_files(SERVICES):
            for i, line in enumerate(py_file.read_text(encoding="utf-8").splitlines(), 1):
                stripped = line.lstrip()
                if stripped.startswith("print(") and not stripped.startswith("print(f'"):
                    # Exclude debug-style commented print or print inside strings
                    if "# " not in line or line.index("print(") < line.index("# "):
                        violations.append(f"{py_file.name}:{i}: {line.rstrip()}")
        assert not violations, (
            "print() found in services/ — use structlog:\n" + "\n".join(violations)
        )

    def test_no_print_in_adapters(self):
        violations = []
        for py_file in self._collect_py_files(ADAPTERS):
            for i, line in enumerate(py_file.read_text(encoding="utf-8").splitlines(), 1):
                stripped = line.lstrip()
                if stripped.startswith("print("):
                    violations.append(f"{py_file.name}:{i}")
        assert not violations, f"print() in adapters/: {violations}"

    def test_all_test_files_are_discoverable(self):
        """All test files must start with test_ so pytest collects them."""
        for py_file in TESTS_DIR.rglob("*.py"):
            if py_file.name == "__init__.py" or py_file.name == "conftest.py":
                continue
            assert py_file.name.startswith("test_"), (
                f"{py_file.name} does not start with test_ and won't be collected by pytest"
            )

    def test_no_syntax_errors_in_app(self):
        """All Python files in app/ must be parseable by ast."""
        errors = []
        for py_file in self._collect_py_files(APP):
            try:
                ast.parse(py_file.read_text(encoding="utf-8"))
            except SyntaxError as e:
                errors.append(f"{py_file.name}: {e}")
        assert not errors, "Syntax errors found:\n" + "\n".join(errors)

    def test_no_dangerous_placeholders_in_app_code(self):
        """Dangerous placeholder credentials must not appear in app/ code."""
        pattern = re.compile(
            r"(password123|admin123|secret123|p@ssw0rd|REPLACE_ME|your-api-key-here)",
            re.IGNORECASE,
        )
        violations = []
        for py_file in self._collect_py_files(APP):
            for i, line in enumerate(py_file.read_text(encoding="utf-8").splitlines(), 1):
                if pattern.search(line):
                    violations.append(f"{py_file.name}:{i}: {line.rstrip()}")
        assert not violations, (
            "Dangerous placeholder credentials in app/:\n" + "\n".join(violations)
        )

    def test_no_hardcoded_private_ips_in_services(self):
        """Private IPs must not be embedded in service logic (use config/env vars)."""
        pattern = re.compile(
            r"(?<!\.)(?:192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)"
        )
        violations = []
        for py_file in self._collect_py_files(SERVICES):
            for i, line in enumerate(py_file.read_text(encoding="utf-8").splitlines(), 1):
                if pattern.search(line) and "#" not in line.split(pattern.pattern)[0]:
                    violations.append(f"{py_file.name}:{i}: {line.rstrip()}")
        assert not violations, (
            "Private IPs hardcoded in services/ — use Settings/env vars:\n"
            + "\n".join(violations)
        )


# ═══════════════════════════════════════════════════════════════════════════════
# TestProjectConfig — pyproject.toml and .gitignore hygiene
# ═══════════════════════════════════════════════════════════════════════════════

class TestProjectConfig:
    """Validate project configuration files that CI depends on."""

    def test_pyproject_toml_exists(self):
        assert (ROOT / "pyproject.toml").exists(), (
            "pyproject.toml not found at repo root — ruff and bandit need it"
        )

    def test_pyproject_has_ruff_config(self):
        with open(ROOT / "pyproject.toml", "rb") as f:
            config = tomllib.load(f)
        assert "ruff" in config.get("tool", {}), (
            "pyproject.toml is missing [tool.ruff] section"
        )

    def test_pyproject_has_bandit_config(self):
        with open(ROOT / "pyproject.toml", "rb") as f:
            config = tomllib.load(f)
        assert "bandit" in config.get("tool", {}), (
            "pyproject.toml is missing [tool.bandit] section"
        )

    def test_ruff_line_length_set(self):
        with open(ROOT / "pyproject.toml", "rb") as f:
            config = tomllib.load(f)
        ruff = config["tool"]["ruff"]
        assert "line-length" in ruff, "[tool.ruff] must specify line-length"

    def test_gitignore_excludes_env(self):
        gitignore = ROOT / ".gitignore"
        assert gitignore.exists(), ".gitignore not found"
        content = gitignore.read_text(encoding="utf-8")
        assert ".env" in content, ".gitignore must exclude .env files"

    def test_gitignore_excludes_pycache(self):
        content = (ROOT / ".gitignore").read_text(encoding="utf-8")
        assert "__pycache__" in content or "*.pyc" in content

    def test_env_file_not_tracked(self):
        """The .env file must not be committed — it contains production secrets."""
        env_path = ROOT / ".env"
        # We can't run git ls-files here, so we check the .gitignore instead
        gitignore_content = (ROOT / ".gitignore").read_text(encoding="utf-8")
        assert ".env" in gitignore_content, (
            ".env must be in .gitignore to prevent accidental secret leaks"
        )

    def test_pytest_ini_exists_in_backend(self):
        """pytest.ini must be in backend/ — CI uses working-directory: backend."""
        assert (BACKEND / "pytest.ini").exists(), (
            "backend/pytest.ini not found — pytest won't find tests in CI"
        )

    def test_workflows_directory_exists(self):
        assert WORKFLOWS.exists(), ".github/workflows/ directory not found"

    def test_local_ci_script_exists(self):
        assert (ROOT / "scripts" / "local-ci.sh").exists(), (
            "scripts/local-ci.sh not found — developers need this for pre-push checks"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# TestSecurityBaseline — security invariants enforced by CI
# ═══════════════════════════════════════════════════════════════════════════════

class TestSecurityBaseline:
    """Security invariants that mirror the security-audit.yml checks."""

    def test_no_env_file_at_repo_root(self):
        """Production .env must never be committed."""
        env = ROOT / ".env"
        if env.exists():
            content = env.read_text(encoding="utf-8")
            # A .env file is OK only if it contains purely placeholder values
            real_secrets = re.findall(
                r"(?:SECRET_KEY|API_KEY|PASSWORD|TOKEN)\s*=\s*(?!changeme|placeholder|your-|ci-only)[^\s#]{16,}",
                content,
                re.IGNORECASE,
            )
            assert not real_secrets, (
                f".env at repo root appears to contain real credentials: {real_secrets!r}\n"
                "Remove and rotate before committing."
            )

    def test_config_py_has_nosec_on_secret_key(self):
        """config.py SECRET_KEY default must have # nosec to silence bandit B105."""
        config_py = APP / "core" / "config.py"
        content = config_py.read_text(encoding="utf-8")
        line = next(
            (l for l in content.splitlines() if "SECRET_KEY" in l and '="' in l or "= '" in l),
            None,
        )
        if line:
            assert "nosec" in line, (
                "SECRET_KEY default in config.py should have '# nosec B105' "
                "to suppress bandit false positive"
            )

    def test_no_exposed_jwt_tokens_in_app_code(self):
        """JWT tokens must not appear hardcoded in app/ (only in tests, which is OK)."""
        jwt_pattern = re.compile(r"eyJ[A-Za-z0-9+/=]{20,}\.[A-Za-z0-9+/=]{10,}\.[A-Za-z0-9+/=_\-]{10,}")
        violations = []
        for py_file in APP.rglob("*.py"):
            content = py_file.read_text(encoding="utf-8")
            for match in jwt_pattern.finditer(content):
                line_no = content[: match.start()].count("\n") + 1
                violations.append(f"{py_file.name}:{line_no}")
        assert not violations, (
            f"Hardcoded JWT tokens in app/: {violations}\n"
            "JWT tokens belong in test fixtures only, never in production code."
        )

    def test_no_api_keys_in_app_code(self):
        """API keys (long alphanumeric strings in assignments) must come from settings."""
        pattern = re.compile(
            r'(?:API_KEY|TOKEN|SECRET)\s*=\s*["\'][A-Za-z0-9+/=_\-]{32,}["\']',
            re.IGNORECASE,
        )
        violations = []
        for py_file in APP.rglob("*.py"):
            content = py_file.read_text(encoding="utf-8")
            for match in pattern.finditer(content):
                # Allow if it ends with nosec or is clearly a placeholder
                snippet = content[match.start(): match.end()]
                if "nosec" not in snippet and "changeme" not in snippet.lower():
                    line_no = content[: match.start()].count("\n") + 1
                    violations.append(f"{py_file.name}:{line_no}: {snippet[:60]}")
        assert not violations, (
            "Possible hardcoded API keys/tokens in app/:\n" + "\n".join(violations)
        )

    def test_gitleaks_config_exists(self):
        """.gitleaks.toml must exist with an allowlist for known-safe test patterns."""
        assert (ROOT / ".gitleaks.toml").exists(), (
            ".gitleaks.toml not found — gitleaks will report false positives "
            "without an allowlist"
        )
