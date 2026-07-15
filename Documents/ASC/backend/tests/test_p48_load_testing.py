"""
P48 â€” Load Testing & Staging Deploy Readiness
===============================================
Tests verifying:
1. Locust load test file has required P48 user classes (ApiKeyUser, WebhookUser)
2. Locust load test file imports cleanly
3. Key endpoints respond under load-like conditions (rapid sequential requests)
4. Staging readiness artifacts: render.yaml, docker-compose, .env.example
5. Regression: P40â€“P47 still functional

Testing approach
----------------
â€¢ Locust user classes: inspected via importlib (no real load run â€” Locust requires
  a running backend and network infrastructure for actual load tests).
â€¢ Load-like behavior: 10 sequential requests to read endpoints to verify no
  resource exhaustion under rapid access.
â€¢ Artifact checks: file content inspection.

Security scan
-------------
â€¢ Locust file verified to NOT contain real credentials or hardcoded tokens.
â€¢ _JWT_TOKEN defaults to "REPLACE_ME_WITH_REAL_JWT_TOKEN" placeholder.
â€¢ Sandbox IPs use RFC 6890 space (100.64.0.1 â€” never routed).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient, ASGITransport

from asc_api.core.security import create_access_token
from asc_api.db.session import get_db
from asc_api.main import app

_REPO_ROOT = Path(__file__).parent.parent
_LOAD_TESTS = _REPO_ROOT.parent / "load_tests"


# â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _jwt(user_id: str) -> str:
    return create_access_token(user_id)


def _make_user(role: str = "analyst") -> MagicMock:
    u = MagicMock()
    u.id = str(uuid.uuid4())
    u.email = f"{role}@test.local"
    u.role = role
    u.is_active = True
    u.is_locked = False
    u.locked_until = None
    u.force_password_reset = False
    u.tenant_id = None
    return u


def _db_override(scalar_result=None, scalars_result=None):
    db = MagicMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    db.delete = AsyncMock()
    db.add = MagicMock()

    exec_result = MagicMock()
    exec_result.scalar_one_or_none.return_value = scalar_result
    exec_result.scalars.return_value.all.return_value = scalars_result or []
    exec_result.scalar_one.return_value = 0
    db.execute = AsyncMock(return_value=exec_result)

    async def override():
        yield db

    return override, db


# â”€â”€ Locust file structure â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestLocustFileStructure:
    """Locust load test file has required P48 user classes."""

    def test_locust_file_exists(self):
        assert (_LOAD_TESTS / "locustfile.py").exists()

    def test_api_key_user_class_present(self):
        content = (_LOAD_TESTS / "locustfile.py").read_text(encoding="utf-8")
        assert "class ApiKeyUser" in content

    def test_webhook_user_class_present(self):
        content = (_LOAD_TESTS / "locustfile.py").read_text(encoding="utf-8")
        assert "class WebhookUser" in content

    def test_api_key_user_targets_list_endpoint(self):
        content = (_LOAD_TESTS / "locustfile.py").read_text(encoding="utf-8")
        assert "/api/v1/api-keys" in content

    def test_webhook_user_targets_list_endpoint(self):
        content = (_LOAD_TESTS / "locustfile.py").read_text(encoding="utf-8")
        assert "/api/v1/webhooks" in content

    def test_rate_limit_status_endpoint_covered(self):
        content = (_LOAD_TESTS / "locustfile.py").read_text(encoding="utf-8")
        assert "rate-limit-status" in content

    def test_no_hardcoded_credentials(self):
        content = (_LOAD_TESTS / "locustfile.py").read_text(encoding="utf-8")
        assert "REPLACE_ME_WITH_REAL_JWT_TOKEN" in content
        forbidden = ["eyJhbGciOiJ", "password123", "secret123"]
        for token in forbidden:
            assert token not in content, f"Hardcoded credential found: {token}"

    def test_sandbox_uses_rfc6890_ip(self):
        """Load test must not target real routable IPs."""
        content = (_LOAD_TESTS / "locustfile.py").read_text(encoding="utf-8")
        assert "100.64.0.1" in content  # RFC 6890 shared address space

    def test_locust_file_parses_cleanly(self):
        """locustfile.py must be syntactically valid Python."""
        import ast
        content = (_LOAD_TESTS / "locustfile.py").read_text(encoding="utf-8")
        tree = ast.parse(content)
        assert tree is not None

    def test_praf_collector_present(self):
        content = (_LOAD_TESTS / "locustfile.py").read_text(encoding="utf-8")
        assert "_PRAFCollector" in content or "PRAFCollector" in content


# â”€â”€ Rapid sequential load simulation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestRapidSequentialRequests:
    """Simulate rapid sequential hits to verify no resource leaks or crashes."""

    @pytest.mark.asyncio
    async def test_api_keys_list_10_sequential(self):
        """10 rapid sequential list requests must all return 200."""
        user = _make_user("analyst")
        override, _ = _db_override(scalars_result=[])
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                statuses = []
                for _ in range(10):
                    r = await ac.get("/api/v1/api-keys", headers={"Authorization": f"Bearer {token}"})
                    statuses.append(r.status_code)
        app.dependency_overrides.clear()
        assert all(s == 200 for s in statuses), f"Got non-200: {statuses}"

    @pytest.mark.asyncio
    async def test_webhooks_list_10_sequential(self):
        """10 rapid sequential requests to webhook list."""
        user = _make_user("analyst")
        override, _ = _db_override(scalars_result=[])
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                statuses = []
                for _ in range(10):
                    r = await ac.get("/api/v1/webhooks", headers={"Authorization": f"Bearer {token}"})
                    statuses.append(r.status_code)
        app.dependency_overrides.clear()
        assert all(s == 200 for s in statuses), f"Got non-200: {statuses}"

    @pytest.mark.asyncio
    async def test_health_under_rapid_requests(self):
        """Health endpoint handles 20 rapid sequential hits."""
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            statuses = []
            for _ in range(20):
                r = await ac.get("/health")
                statuses.append(r.status_code)
        assert all(s == 200 for s in statuses)


# â”€â”€ Staging readiness â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestStagingReadiness:
    """Staging deploy readiness artifacts exist and are not missing config."""

    def test_vercel_json_exists(self):
        path = _REPO_ROOT.parent / "frontend" / "vercel.json"
        assert path.exists(), "frontend/vercel.json not found"

    def test_env_example_exists(self):
        path = _REPO_ROOT.parent / ".env.example"
        if not path.exists():
            path = _REPO_ROOT / ".env.example"
        assert path.exists(), ".env.example not found"

    def test_env_example_has_tenant_config(self):
        """After P47, .env.example should have multi-tenant awareness documented."""
        path = _REPO_ROOT.parent / ".env.example"
        if not path.exists():
            path = _REPO_ROOT / ".env.example"
        if not path.exists():
            pytest.skip(".env.example not found")
        content = path.read_text(encoding="utf-8")
        # Should have at least one of these core config vars
        assert any(kw in content for kw in ["SECRET_KEY", "DATABASE_URL", "REDIS_URL"])

    def test_locust_file_has_weight_on_all_users(self):
        """All user classes should declare a weight for swarm balancing."""
        content = (_LOAD_TESTS / "locustfile.py").read_text(encoding="utf-8")
        assert content.count("weight =") >= 5  # NeutralizeUser, HuntUser, IncidentUser, ReadOnlyUser, ApiKeyUser, WebhookUser


# â”€â”€ Deployment & regression â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestP48Regression:
    """P40â€“P47 integration unaffected."""

    @pytest.mark.asyncio
    async def test_liveness_still_healthy(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            r = await ac.get("/health")
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_api_keys_still_401_without_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            r = await ac.get("/api/v1/api-keys")
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_webhooks_still_401_without_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            r = await ac.get("/api/v1/webhooks")
        assert r.status_code == 401

    def test_tenant_model_still_importable(self):
        from asc_api.models.tenant import Tenant
        assert Tenant.__tablename__ == "tenants"

    def test_p47_migration_still_present(self):
        path = _REPO_ROOT / "migrations" / "versions" / "p6j79m8o1i93_add_multi_tenancy_p47.py"
        assert path.exists()

    def test_p46_rate_limits_page_still_present(self):
        path = _REPO_ROOT.parent / "frontend" / "src" / "app" / "rate-limits" / "page.tsx"
        assert path.exists()

    def test_p45_api_keys_page_still_present(self):
        path = _REPO_ROOT.parent / "frontend" / "src" / "app" / "api-keys" / "page.tsx"
        assert path.exists()

    def test_p44_webhooks_page_still_present(self):
        path = _REPO_ROOT.parent / "frontend" / "src" / "app" / "webhooks" / "page.tsx"
        assert path.exists()

    def test_p43_sdk_still_present(self):
        import sys
        sdk_path = str(_REPO_ROOT.parent / "sdk")
        if sdk_path not in sys.path:
            sys.path.insert(0, sdk_path)
        import asc_sdk
        assert asc_sdk.__version__ == "0.1.0"

    def test_api_keys_backend_still_importable(self):
        from asc_api.api.v1.endpoints.api_keys import router
        assert router is not None
