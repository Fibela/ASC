"""
P46 â€” Rate Limits Dashboard
===========================
Contract tests for the rate-limit monitoring dashboard.

Scope
-----
â€¢ GET  /api/v1/api-keys/{id}/rate-limit-status  â€” owner + admin access
â€¢ POST /api/v1/api-keys/{id}/rate-limit-reset   â€” admin-only
â€¢ Frontend artifacts: rate-limits/page.tsx, Sidebar entry, api.ts function
â€¢ Security: no raw keys exposed, cross-user isolation, admin RBAC on reset
â€¢ Regression: P40â€“P45 endpoints still functional

Pattern
-------
Uses app.dependency_overrides[get_db] = async_gen_override (established in P45).
auth patched via app.api.deps._resolve_user.
api_key_limiter patched at app.api.v1.endpoints.api_keys.api_key_limiter.
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

_REPO_ROOT = Path(__file__).parent.parent.parent


# â”€â”€ Factories â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
    return u


def _make_api_key(user_id: str) -> MagicMock:
    k = MagicMock()
    k.id = str(uuid.uuid4())
    k.user_id = user_id
    k.name = "Test Key"
    k.key_prefix = "aabbccdd"
    k.key_hash = "s3cr3th4sh" * 6
    k.scopes = ["read"]
    k.is_active = True
    k.created_at = datetime.now(timezone.utc)
    k.last_used_at = None
    k.expires_at = None
    k.is_expired = False
    return k


def _db_override(scalar_result=None, scalars_result=None, count_result=0):
    db = MagicMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    db.delete = AsyncMock()
    db.add = MagicMock()
    db.close = AsyncMock()

    exec_result = MagicMock()
    exec_result.scalar_one_or_none.return_value = scalar_result
    exec_result.scalars.return_value.all.return_value = scalars_result or []
    exec_result.scalar_one.return_value = count_result
    db.execute = AsyncMock(return_value=exec_result)

    async def override():
        yield db

    return override, db


def _make_limiter(count_m: int = 5, count_h: int = 120) -> MagicMock:
    m = MagicMock()
    m.get_status = AsyncMock(side_effect=lambda prefix, window: count_m if window == 60 else count_h)
    m.mode = "memory"
    m.reset_for_prefix_all = AsyncMock()
    return m


# â”€â”€ Rate limit status contract â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestRateLimitStatusContract:
    """GET /api-keys/{id}/rate-limit-status returns correct fields and shape."""

    @pytest.mark.asyncio
    async def test_status_returns_200_for_owner(self):
        user = _make_user("analyst")
        key = _make_api_key(user_id=user.id)
        override, _ = _db_override(scalar_result=key)
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)
        limiter = _make_limiter()

        with (
            patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)),
            patch("asc_api.api.v1.endpoints.api_keys.api_key_limiter", limiter),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.get(
                    f"/api/v1/api-keys/{key.id}/rate-limit-status",
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_status_fields_present(self):
        user = _make_user("analyst")
        key = _make_api_key(user_id=user.id)
        override, _ = _db_override(scalar_result=key)
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)
        limiter = _make_limiter(count_m=10, count_h=250)

        with (
            patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)),
            patch("asc_api.api.v1.endpoints.api_keys.api_key_limiter", limiter),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.get(
                    f"/api/v1/api-keys/{key.id}/rate-limit-status",
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()

        body = r.json()
        required = {
            "key_prefix", "limit_per_minute", "limit_per_hour",
            "count_minute", "count_hour",
            "remaining_minute", "remaining_hour", "backend",
        }
        assert required.issubset(body.keys())

    @pytest.mark.asyncio
    async def test_status_values_consistent(self):
        """remaining = limit - count, backend matches limiter mode."""
        user = _make_user("analyst")
        key = _make_api_key(user_id=user.id)
        override, _ = _db_override(scalar_result=key)
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)
        count_m, count_h = 15, 300
        limiter = _make_limiter(count_m=count_m, count_h=count_h)

        with (
            patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)),
            patch("asc_api.api.v1.endpoints.api_keys.api_key_limiter", limiter),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.get(
                    f"/api/v1/api-keys/{key.id}/rate-limit-status",
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()

        body = r.json()
        assert body["count_minute"] == count_m
        assert body["count_hour"] == count_h
        assert body["remaining_minute"] == max(0, body["limit_per_minute"] - count_m)
        assert body["remaining_hour"] == max(0, body["limit_per_hour"] - count_h)
        assert body["backend"] == "memory"

    @pytest.mark.asyncio
    async def test_status_admin_can_view_any_key(self):
        admin = _make_user("admin")
        key = _make_api_key(user_id=str(uuid.uuid4()))  # different owner
        override, _ = _db_override(scalar_result=key)
        app.dependency_overrides[get_db] = override
        token = _jwt(admin.id)
        limiter = _make_limiter()

        with (
            patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=admin)),
            patch("asc_api.api.v1.endpoints.api_keys.api_key_limiter", limiter),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.get(
                    f"/api/v1/api-keys/{key.id}/rate-limit-status",
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_status_forbidden_for_other_user(self):
        requester = _make_user("analyst")
        key = _make_api_key(user_id=str(uuid.uuid4()))  # different owner
        override, _ = _db_override(scalar_result=key)
        app.dependency_overrides[get_db] = override
        token = _jwt(requester.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=requester)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.get(
                    f"/api/v1/api-keys/{key.id}/rate-limit-status",
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()
        assert r.status_code == 403

    @pytest.mark.asyncio
    async def test_status_requires_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            r = await ac.get(f"/api/v1/api-keys/{uuid.uuid4()}/rate-limit-status")
        assert r.status_code == 401


# â”€â”€ Rate limit reset contract â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestRateLimitResetContract:
    """POST /api-keys/{id}/rate-limit-reset â€” admin-only."""

    @pytest.mark.asyncio
    async def test_reset_returns_204_for_admin(self):
        admin = _make_user("admin")
        key = _make_api_key(user_id=str(uuid.uuid4()))
        override, _ = _db_override(scalar_result=key)
        app.dependency_overrides[get_db] = override
        token = _jwt(admin.id)
        limiter = _make_limiter()

        with (
            patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=admin)),
            patch("asc_api.api.v1.endpoints.api_keys.api_key_limiter", limiter),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.post(
                    f"/api/v1/api-keys/{key.id}/rate-limit-reset",
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()
        assert r.status_code == 204

    @pytest.mark.asyncio
    async def test_reset_calls_limiter(self):
        """Reset endpoint must call api_key_limiter.reset_for_prefix_all."""
        admin = _make_user("admin")
        key = _make_api_key(user_id=str(uuid.uuid4()))
        override, _ = _db_override(scalar_result=key)
        app.dependency_overrides[get_db] = override
        token = _jwt(admin.id)
        limiter = _make_limiter()

        with (
            patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=admin)),
            patch("asc_api.api.v1.endpoints.api_keys.api_key_limiter", limiter),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                await ac.post(
                    f"/api/v1/api-keys/{key.id}/rate-limit-reset",
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()
        limiter.reset_for_prefix_all.assert_awaited_once_with(key.key_prefix)

    @pytest.mark.asyncio
    async def test_reset_forbidden_for_analyst(self):
        analyst = _make_user("analyst")
        key = _make_api_key(user_id=analyst.id)
        override, _ = _db_override(scalar_result=key)
        app.dependency_overrides[get_db] = override
        token = _jwt(analyst.id)
        limiter = _make_limiter()

        with (
            patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=analyst)),
            patch("asc_api.api.v1.endpoints.api_keys.api_key_limiter", limiter),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.post(
                    f"/api/v1/api-keys/{key.id}/rate-limit-reset",
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()
        assert r.status_code == 403

    @pytest.mark.asyncio
    async def test_reset_requires_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            r = await ac.post(f"/api/v1/api-keys/{uuid.uuid4()}/rate-limit-reset")
        assert r.status_code == 401


# â”€â”€ Security invariants â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestSecurityInvariants:
    """Rate limit status never leaks raw keys or hashes."""

    @pytest.mark.asyncio
    async def test_status_never_exposes_key_hash(self):
        user = _make_user("analyst")
        key = _make_api_key(user_id=user.id)
        key.key_hash = "hmac-sha256-hash-value"
        override, _ = _db_override(scalar_result=key)
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)
        limiter = _make_limiter()

        with (
            patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)),
            patch("asc_api.api.v1.endpoints.api_keys.api_key_limiter", limiter),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.get(
                    f"/api/v1/api-keys/{key.id}/rate-limit-status",
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()
        assert "key_hash" not in r.json()
        assert "hmac-sha256" not in r.text

    @pytest.mark.asyncio
    async def test_status_never_exposes_raw_key(self):
        user = _make_user("analyst")
        key = _make_api_key(user_id=user.id)
        override, _ = _db_override(scalar_result=key)
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)
        limiter = _make_limiter()

        with (
            patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)),
            patch("asc_api.api.v1.endpoints.api_keys.api_key_limiter", limiter),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.get(
                    f"/api/v1/api-keys/{key.id}/rate-limit-status",
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()
        assert "raw_key" not in r.json()


# â”€â”€ Deployment artifacts â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestP46DeploymentAndRegression:
    """Verify P46 frontend artifacts exist and P40â€“P45 regression."""

    def test_rate_limits_page_exists(self):
        path = _REPO_ROOT / "frontend" / "src" / "app" / "rate-limits" / "page.tsx"
        assert path.exists(), "rate-limits/page.tsx not found"

    def test_rate_limits_page_uses_auth_guard(self):
        path = _REPO_ROOT / "frontend" / "src" / "app" / "rate-limits" / "page.tsx"
        assert "useAuthGuard" in path.read_text(encoding="utf-8")

    def test_rate_limits_page_has_usage_bar(self):
        path = _REPO_ROOT / "frontend" / "src" / "app" / "rate-limits" / "page.tsx"
        assert "UsageBar" in path.read_text(encoding="utf-8")

    def test_rate_limits_page_has_backend_badge(self):
        path = _REPO_ROOT / "frontend" / "src" / "app" / "rate-limits" / "page.tsx"
        assert "BackendBadge" in path.read_text(encoding="utf-8")

    def test_rate_limits_page_has_auto_refresh(self):
        path = _REPO_ROOT / "frontend" / "src" / "app" / "rate-limits" / "page.tsx"
        content = path.read_text(encoding="utf-8")
        assert "setInterval" in content or "30_000" in content or "30000" in content

    def test_rate_limits_page_has_reset_button(self):
        path = _REPO_ROOT / "frontend" / "src" / "app" / "rate-limits" / "page.tsx"
        content = path.read_text(encoding="utf-8")
        assert "resetApiKeyRateLimit" in content or "Reset" in content

    def test_api_ts_has_reset_function(self):
        path = _REPO_ROOT / "frontend" / "src" / "lib" / "api.ts"
        assert "resetApiKeyRateLimit" in path.read_text(encoding="utf-8")

    def test_sidebar_has_rate_limits_entry(self):
        path = _REPO_ROOT / "frontend" / "src" / "components" / "dashboard" / "Sidebar.tsx"
        assert "rate-limits" in path.read_text(encoding="utf-8")

    def test_no_hardcoded_secrets_in_page(self):
        path = _REPO_ROOT / "frontend" / "src" / "app" / "rate-limits" / "page.tsx"
        content = path.read_text(encoding="utf-8")
        for token in ["sk-", "Bearer eyJ", "password123", "secret123"]:
            assert token not in content, f"Hardcoded secret found: {token}"

    @pytest.mark.asyncio
    async def test_liveness_still_healthy(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            r = await ac.get("/health")
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_api_keys_endpoint_still_needs_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            r = await ac.get("/api/v1/api-keys")
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_rate_limit_status_endpoint_needs_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            r = await ac.get(f"/api/v1/api-keys/{uuid.uuid4()}/rate-limit-status")
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_rate_limit_reset_endpoint_needs_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            r = await ac.post(f"/api/v1/api-keys/{uuid.uuid4()}/rate-limit-reset")
        assert r.status_code == 401

    def test_p45_api_keys_page_still_present(self):
        path = _REPO_ROOT / "frontend" / "src" / "app" / "api-keys" / "page.tsx"
        assert path.exists()

    def test_p44_webhooks_page_still_present(self):
        path = _REPO_ROOT / "frontend" / "src" / "app" / "webhooks" / "page.tsx"
        assert path.exists()

    def test_p43_sdk_still_present(self):
        import sys
        sdk_path = str(_REPO_ROOT / "sdk")
        if sdk_path not in sys.path:
            sys.path.insert(0, sdk_path)
        import asc_sdk
        assert asc_sdk.__version__ == "0.1.0"

    def test_p42_dispatcher_still_importable(self):
        from asc_api.core.webhook_dispatcher import sign_payload, verify_signature
        assert callable(sign_payload) and callable(verify_signature)

    def test_p40_api_keys_backend_still_importable(self):
        from asc_api.api.v1.endpoints.api_keys import router
        assert router is not None
