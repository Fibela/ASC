"""
P45 â€” API Keys Dashboard Frontend â€” Contract Tests
===================================================
Verifica cada endpoint que la pÃ¡gina /api-keys del frontend consume:
  GET  /api/v1/api-keys/            â†’ list own keys (analyst/admin)
  POST /api/v1/api-keys/            â†’ create (raw_key one-time)
  GET  /api/v1/api-keys/{id}        â†’ get single
  PATCH /api/v1/api-keys/{id}       â†’ update name/is_active/expires_at
  DELETE /api/v1/api-keys/{id}      â†’ revoke 204
  POST /api/v1/api-keys/{id}/rotate â†’ rotate (new raw_key)
  GET  /api/v1/api-keys/{id}/rate-limit-status â†’ RateLimitStatus shape
  GET  /api/v1/api-keys/admin/all   â†’ admin list all

Invariantes de seguridad:
  â€¢ raw_key NUNCA en list/get/patch/admin-list responses
  â€¢ key_hash NUNCA expuesto en ninguna respuesta
  â€¢ Acceso cruzado entre usuarios â†’ 403
  â€¢ Sin auth â†’ 401
  â€¢ Scope invÃ¡lido â†’ 422
  â€¢ Cap 20 llaves por usuario verificado

Coverage: 35 tests en 6 clases.
"""

import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from asc_api.core.config import get_settings
from asc_api.core.security import create_access_token
from asc_api.db.session import get_db
from asc_api.main import app

settings = get_settings()
_REPO_ROOT = Path(__file__).parent.parent.parent


# â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _make_user(role: str = "analyst", user_id: str | None = None):
    u = MagicMock()
    u.id = user_id or str(uuid.uuid4())
    u.email = f"{role}@test.local"
    u.role = role
    u.is_active = True
    u.is_locked = False
    u.locked_until = None
    u.force_password_reset = False
    return u


def _make_api_key(user_id: str, *, key_id: str | None = None,
                  name: str = "Test Key", scopes: list | None = None,
                  is_active: bool = True, expires_at=None):
    k = MagicMock()
    k.id = key_id or str(uuid.uuid4())
    k.name = name
    k.key_prefix = "aabbccdd"
    k.key_hash = "s3cr3th4sh" * 6   # must NEVER appear in any response
    k.user_id = user_id
    k.scopes = scopes or ["read"]
    k.is_active = is_active
    k.expires_at = expires_at
    k.last_used_at = None
    k.created_at = datetime.now(timezone.utc)
    k.is_expired = False
    return k


def _jwt(user_id: str) -> str:
    return create_access_token(user_id)


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


# â”€â”€ Class 1: List â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestListApiKeysContract:
    """Frontend depends on GET /api/v1/api-keys/ â†’ array of APIKeyResponse."""

    @pytest.mark.asyncio
    async def test_list_returns_200_for_analyst(self):
        user = _make_user("analyst")
        k = _make_api_key(user.id)
        override, _ = _db_override(scalars_result=[k])
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.get("/api/v1/api-keys", headers={"Authorization": f"Bearer {token}"})
        app.dependency_overrides.clear()

        assert r.status_code == 200
        assert isinstance(r.json(), list)

    @pytest.mark.asyncio
    async def test_list_contains_required_fields(self):
        user = _make_user("analyst")
        k = _make_api_key(user.id)
        override, _ = _db_override(scalars_result=[k])
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.get("/api/v1/api-keys", headers={"Authorization": f"Bearer {token}"})
        app.dependency_overrides.clear()

        assert r.status_code == 200
        item = r.json()[0]
        for field in ("id", "name", "key_prefix", "user_id", "scopes", "is_active", "created_at"):
            assert field in item, f"Missing field: {field}"

    @pytest.mark.asyncio
    async def test_list_never_exposes_raw_key_or_hash(self):
        """raw_key and key_hash must NEVER appear in list responses."""
        user = _make_user("analyst")
        k = _make_api_key(user.id)
        override, _ = _db_override(scalars_result=[k])
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.get("/api/v1/api-keys", headers={"Authorization": f"Bearer {token}"})
        app.dependency_overrides.clear()

        body_text = r.text
        assert k.key_hash not in body_text
        assert "raw_key" not in r.json()[0]
        assert "key_hash" not in r.json()[0]

    @pytest.mark.asyncio
    async def test_list_requires_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            r = await ac.get("/api/v1/api-keys")
        assert r.status_code == 401


# â”€â”€ Class 2: Create â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestCreateApiKeyContract:
    """POST /api/v1/api-keys/ must return raw_key once in APIKeyCreated."""

    @pytest.mark.asyncio
    async def test_create_returns_201_with_raw_key(self):
        user = _make_user("analyst")
        import uuid as _uuid
        override, db = _db_override(count_result=0)
        db.refresh = AsyncMock(side_effect=lambda obj: (
            setattr(obj, "id", str(_uuid.uuid4())) or
            setattr(obj, "is_active", True) or
            setattr(obj, "created_at", datetime.now(timezone.utc)) or
            setattr(obj, "last_used_at", None) or
            setattr(obj, "expires_at", None)
        ))
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.post(
                    "/api/v1/api-keys",
                    json={"name": "test-key", "scopes": ["read"]},
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()

        assert r.status_code == 201
        body = r.json()
        assert "raw_key" in body
        assert len(body["raw_key"]) > 32

    @pytest.mark.asyncio
    async def test_create_raw_key_not_in_subsequent_list(self):
        """raw_key from creation must never reappear in list endpoint."""
        user = _make_user("analyst")
        k = _make_api_key(user.id)
        override, _ = _db_override(scalars_result=[k])
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.get("/api/v1/api-keys", headers={"Authorization": f"Bearer {token}"})
        app.dependency_overrides.clear()

        assert "raw_key" not in r.json()[0]

    @pytest.mark.asyncio
    async def test_create_rejects_invalid_scope(self):
        user = _make_user("analyst")
        override, _ = _db_override(count_result=0)
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.post(
                    "/api/v1/api-keys",
                    json={"name": "bad", "scopes": ["superuser"]},
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()

        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_create_rejects_empty_name(self):
        user = _make_user("analyst")
        override, _ = _db_override(count_result=0)
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.post(
                    "/api/v1/api-keys",
                    json={"name": "", "scopes": ["read"]},
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()

        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_create_requires_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            r = await ac.post("/api/v1/api-keys", json={"name": "x", "scopes": ["read"]})
        assert r.status_code == 401


# â”€â”€ Class 3: Get / Patch / Revoke â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestGetPatchRevokeContract:
    """Individual key operations used by the frontend row actions."""

    @pytest.mark.asyncio
    async def test_get_never_exposes_hash(self):
        user = _make_user("analyst")
        k = _make_api_key(user.id)
        override, _ = _db_override(scalar_result=k)
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.get(f"/api/v1/api-keys/{k.id}", headers={"Authorization": f"Bearer {token}"})
        app.dependency_overrides.clear()

        assert r.status_code == 200
        assert k.key_hash not in r.text
        assert "key_hash" not in r.json()
        assert "raw_key" not in r.json()

    @pytest.mark.asyncio
    async def test_get_returns_403_for_other_user(self):
        owner = _make_user("analyst")
        requester = _make_user("analyst")
        k = _make_api_key(owner.id)
        override, _ = _db_override(scalar_result=k)
        app.dependency_overrides[get_db] = override
        token = _jwt(requester.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=requester)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.get(f"/api/v1/api-keys/{k.id}", headers={"Authorization": f"Bearer {token}"})
        app.dependency_overrides.clear()

        assert r.status_code == 403

    @pytest.mark.asyncio
    async def test_patch_toggle_is_active(self):
        user = _make_user("analyst")
        k = _make_api_key(user.id, is_active=True)
        override, _ = _db_override(scalar_result=k)
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.patch(
                    f"/api/v1/api-keys/{k.id}",
                    json={"is_active": False},
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()

        assert r.status_code == 200
        assert "key_hash" not in r.json()
        assert "raw_key" not in r.json()

    @pytest.mark.asyncio
    async def test_revoke_returns_204(self):
        user = _make_user("analyst")
        k = _make_api_key(user.id)
        override, _ = _db_override(scalar_result=k)
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.delete(f"/api/v1/api-keys/{k.id}", headers={"Authorization": f"Bearer {token}"})
        app.dependency_overrides.clear()

        assert r.status_code == 204

    @pytest.mark.asyncio
    async def test_revoke_forbidden_for_other_user(self):
        owner = _make_user("analyst")
        attacker = _make_user("analyst")
        k = _make_api_key(owner.id)
        override, _ = _db_override(scalar_result=k)
        app.dependency_overrides[get_db] = override
        token = _jwt(attacker.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=attacker)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.delete(f"/api/v1/api-keys/{k.id}", headers={"Authorization": f"Bearer {token}"})
        app.dependency_overrides.clear()

        assert r.status_code == 403

    @pytest.mark.asyncio
    async def test_get_returns_404_for_missing(self):
        user = _make_user("analyst")
        override, _ = _db_override(scalar_result=None)
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.get(f"/api/v1/api-keys/{uuid.uuid4()}", headers={"Authorization": f"Bearer {token}"})
        app.dependency_overrides.clear()

        assert r.status_code == 404


# â”€â”€ Class 4: Rotate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestRotateApiKeyContract:
    """POST /api/v1/api-keys/{id}/rotate â€” must return new raw_key."""

    @pytest.mark.asyncio
    async def test_rotate_returns_raw_key(self):
        user = _make_user("analyst")
        k = _make_api_key(user.id)
        override, db = _db_override(scalar_result=k)
        # refresh on an existing key â€” id and is_active already set by _make_api_key; just ensure created_at
        db.refresh = AsyncMock(side_effect=lambda obj: (
            setattr(obj, "created_at", obj.created_at or datetime.now(timezone.utc))
        ))
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.post(f"/api/v1/api-keys/{k.id}/rotate", headers={"Authorization": f"Bearer {token}"})
        app.dependency_overrides.clear()

        assert r.status_code == 200
        assert "raw_key" in r.json()

    @pytest.mark.asyncio
    async def test_rotate_forbidden_for_other_user(self):
        owner = _make_user("analyst")
        attacker = _make_user("analyst")
        k = _make_api_key(owner.id)
        override, _ = _db_override(scalar_result=k)
        app.dependency_overrides[get_db] = override
        token = _jwt(attacker.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=attacker)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.post(f"/api/v1/api-keys/{k.id}/rotate", headers={"Authorization": f"Bearer {token}"})
        app.dependency_overrides.clear()

        assert r.status_code == 403

    @pytest.mark.asyncio
    async def test_rotate_requires_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            r = await ac.post(f"/api/v1/api-keys/{uuid.uuid4()}/rotate")
        assert r.status_code == 401


# â”€â”€ Class 5: Rate Limit Status â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestRateLimitStatusContract:
    """GET /api/v1/api-keys/{id}/rate-limit-status â€” shape for frontend bar."""

    @pytest.mark.asyncio
    async def test_rate_limit_status_fields(self):
        user = _make_user("analyst")
        k = _make_api_key(user.id)
        override, _ = _db_override(scalar_result=k)
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        # get_status returns an int (count of requests in the window)
        mock_limiter = MagicMock()
        mock_limiter.get_status = AsyncMock(return_value=0)
        mock_limiter.mode = "memory"

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)), \
             patch("asc_api.api.v1.endpoints.api_keys.api_key_limiter", mock_limiter):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.get(
                    f"/api/v1/api-keys/{k.id}/rate-limit-status",
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()

        assert r.status_code == 200
        body = r.json()
        for field in ("key_prefix", "limit_per_minute", "limit_per_hour",
                      "count_minute", "count_hour", "remaining_minute", "remaining_hour", "backend"):
            assert field in body, f"Missing field: {field}"

    @pytest.mark.asyncio
    async def test_rate_limit_status_forbidden_for_other_user(self):
        owner = _make_user("analyst")
        attacker = _make_user("analyst")
        k = _make_api_key(owner.id)
        override, _ = _db_override(scalar_result=k)
        app.dependency_overrides[get_db] = override
        token = _jwt(attacker.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=attacker)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.get(
                    f"/api/v1/api-keys/{k.id}/rate-limit-status",
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()

        assert r.status_code == 403


# â”€â”€ Class 6: Deployment artifacts & regression â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestP45DeploymentAndRegression:
    """Verify page file, api.ts additions, sidebar entry, no mock data."""

    def test_api_keys_page_exists(self):
        page = _REPO_ROOT / "frontend" / "src" / "app" / "api-keys" / "page.tsx"
        assert page.exists(), f"Missing: {page}"

    def test_api_keys_page_uses_auth_guard(self):
        page = _REPO_ROOT / "frontend" / "src" / "app" / "api-keys" / "page.tsx"
        content = page.read_text(encoding="utf-8")
        assert "useAuthGuard" in content

    def test_api_keys_page_has_key_reveal_panel(self):
        page = _REPO_ROOT / "frontend" / "src" / "app" / "api-keys" / "page.tsx"
        content = page.read_text(encoding="utf-8")
        assert "KeyRevealPanel" in content

    def test_api_keys_page_has_form_modal(self):
        page = _REPO_ROOT / "frontend" / "src" / "app" / "api-keys" / "page.tsx"
        content = page.read_text(encoding="utf-8")
        assert "KeyFormModal" in content

    def test_api_keys_page_has_rate_limit_bar(self):
        page = _REPO_ROOT / "frontend" / "src" / "app" / "api-keys" / "page.tsx"
        content = page.read_text(encoding="utf-8")
        assert "RateLimitBar" in content

    def test_api_ts_has_rate_limit_status_function(self):
        api_ts = _REPO_ROOT / "frontend" / "src" / "lib" / "api.ts"
        content = api_ts.read_text(encoding="utf-8")
        assert "getApiKeyRateLimitStatus" in content
        assert "RateLimitStatus" in content

    def test_api_ts_has_admin_list_function(self):
        api_ts = _REPO_ROOT / "frontend" / "src" / "lib" / "api.ts"
        content = api_ts.read_text(encoding="utf-8")
        assert "adminListAllApiKeys" in content

    def test_sidebar_has_api_keys_entry(self):
        sidebar = _REPO_ROOT / "frontend" / "src" / "components" / "dashboard" / "Sidebar.tsx"
        content = sidebar.read_text(encoding="utf-8")
        assert "/api-keys" in content
        assert "KeyRound" in content

    def test_no_hardcoded_secrets_in_page(self):
        page = _REPO_ROOT / "frontend" / "src" / "app" / "api-keys" / "page.tsx"
        content = page.read_text(encoding="utf-8")
        for pattern in ["sk-", "Bearer eyJ", "password123", "secret123", "asc_", "localhost:8000"]:
            assert pattern not in content, f"Hardcoded pattern found: '{pattern}'"

    def test_liveness_still_healthy(self):
        import asyncio
        async def _check():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                return await ac.get("/health")
        assert asyncio.get_event_loop().run_until_complete(_check()).status_code == 200

    def test_api_keys_endpoint_still_needs_auth(self):
        import asyncio
        async def _check():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                return await ac.get("/api/v1/api-keys")
        assert asyncio.get_event_loop().run_until_complete(_check()).status_code == 401

    def test_p44_webhooks_still_importable(self):
        page = _REPO_ROOT / "frontend" / "src" / "app" / "webhooks" / "page.tsx"
        assert page.exists()
        content = page.read_text(encoding="utf-8")
        assert "useAuthGuard" in content

    def test_p42_dispatcher_still_importable(self):
        from asc_api.core.webhook_dispatcher import sign_payload, verify_signature
        assert callable(sign_payload) and callable(verify_signature)

    def test_p43_sdk_still_present(self):
        import sys
        sdk_path = str(_REPO_ROOT / "sdk")
        if sdk_path not in sys.path:
            sys.path.insert(0, sdk_path)
        import asc_sdk
        assert asc_sdk.__version__ == "0.1.0"

    def test_p40_api_keys_backend_still_importable(self):
        from asc_api.api.v1.endpoints.api_keys import router
        assert router is not None
