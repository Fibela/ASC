"""
P40 — API Key Management — Test Suite  (Toque Premos included)
==============================================================
Tests: model helpers, endpoint CRUD, RBAC, auth via X-API-Key,
       security invariants, migration artifact, regression,
       HMAC-SHA256 hash, Ledger Premos audit logging,
       Scopes adaptativos enforcement dep.

Pattern: AsyncClient + ASGITransport (bypasses app lifespan → no real DB).
DB is mocked via Depends(get_db) override returning a MagicMock session.
"""

import hashlib
import hmac as _hmac
import secrets
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


# ── Fixtures ──────────────────────────────────────────────────────────────────

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


def _make_api_key_row(
    user_id: str,
    name: str = "Test Key",
    scopes: list | None = None,
    is_active: bool = True,
    expires_at=None,
    key_id: str | None = None,
):
    k = MagicMock()
    k.id = key_id or str(uuid.uuid4())
    k.name = name
    k.key_prefix = "aabbccdd"
    k.key_hash = "a" * 64
    k.user_id = user_id
    k.scopes = scopes or ["read"]
    k.is_active = is_active
    k.expires_at = expires_at
    k.last_used_at = None
    k.created_at = datetime.now(timezone.utc)
    k.is_expired = (
        expires_at is not None and datetime.now(timezone.utc) > expires_at
    )
    return k


def _jwt(user_id: str) -> str:
    return create_access_token(user_id)


def _db_override(scalar_result=None, scalars_result=None):
    """Return a get_db override that yields a mock AsyncSession."""
    db = MagicMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    db.delete = AsyncMock()
    db.add = MagicMock()
    db.close = AsyncMock()

    exec_result = MagicMock()
    exec_result.scalar_one_or_none.return_value = scalar_result
    if scalars_result is not None:
        exec_result.scalars.return_value.all.return_value = scalars_result
    else:
        exec_result.scalars.return_value.all.return_value = []

    db.execute = AsyncMock(return_value=exec_result)

    async def override():
        yield db

    return override, db


@pytest.fixture
def analyst_id():
    return str(uuid.uuid4())


@pytest.fixture
def admin_id():
    return str(uuid.uuid4())


# ── Class 1: Model helpers ─────────────────────────────────────────────────────

class TestAPIKeyHelpers:
    """Unit tests for _generate_raw_key, _hash_key, _prefix_of, is_expired."""

    def test_generate_raw_key_format(self):
        from asc_api.api.v1.endpoints.api_keys import _generate_raw_key
        key = _generate_raw_key()
        parts = key.split("_")
        assert len(parts) == 3
        assert parts[0] == "asc"
        assert len(parts[1]) == 8
        assert len(parts[2]) == 40

    def test_generate_raw_key_uniqueness(self):
        from asc_api.api.v1.endpoints.api_keys import _generate_raw_key
        keys = {_generate_raw_key() for _ in range(50)}
        assert len(keys) == 50

    def test_hash_key_is_hmac_sha256(self):
        """Toque Premos: _hash_key must use HMAC-SHA256 keyed with SECRET_KEY."""
        from asc_api.api.v1.endpoints.api_keys import _hash_key
        raw = "asc_ab12cd34_" + "x" * 40
        expected = _hmac.new(
            settings.SECRET_KEY.encode(),
            raw.encode(),
            hashlib.sha256,
        ).hexdigest()
        assert _hash_key(raw) == expected
        # Must NOT equal plain SHA-256 (verifies the HMAC key is being used)
        plain_sha256 = hashlib.sha256(raw.encode()).hexdigest()
        assert _hash_key(raw) != plain_sha256

    def test_hash_key_length(self):
        from asc_api.api.v1.endpoints.api_keys import _hash_key
        assert len(_hash_key("any-value")) == 64

    def test_prefix_of_returns_8_chars(self):
        from asc_api.api.v1.endpoints.api_keys import _prefix_of
        raw = "asc_aabbccdd_" + "e" * 40
        assert _prefix_of(raw) == "aabbccdd"

    def test_validate_scopes_valid(self):
        from asc_api.api.v1.endpoints.api_keys import _validate_scopes
        _validate_scopes(["read"])
        _validate_scopes(["read", "write"])
        _validate_scopes(["read", "write", "admin"])

    def test_validate_scopes_invalid_raises(self):
        from fastapi import HTTPException
        from asc_api.api.v1.endpoints.api_keys import _validate_scopes
        with pytest.raises(HTTPException) as exc:
            _validate_scopes(["read", "superpower"])
        assert exc.value.status_code == 422  # 422 Unprocessable Content

    def test_api_key_model_is_expired_false_when_no_expiry(self):
        from asc_api.models.api_key import APIKey
        k = APIKey()
        k.expires_at = None
        assert k.is_expired is False

    def test_api_key_model_is_expired_true_when_past(self):
        from asc_api.models.api_key import APIKey
        k = APIKey()
        k.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
        assert k.is_expired is True

    def test_api_key_model_is_expired_false_when_future(self):
        from asc_api.models.api_key import APIKey
        k = APIKey()
        k.expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        assert k.is_expired is False


# ── Class 2: Create endpoint ───────────────────────────────────────────────────

class TestCreateAPIKey:
    URL = "/api/v1/api-keys/"

    @pytest.mark.asyncio
    async def test_create_requires_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.post(self.URL, json={"name": "k1"})
        assert r.status_code == 401  # HTTPBearer auto_error=True returns 401 when header missing

    @pytest.mark.asyncio
    async def test_create_returns_201_and_raw_key(self, analyst_id):
        override, db = _db_override(scalar_result=None, scalars_result=[])

        created_key = _make_api_key_row(analyst_id, "My Key")

        async def mock_refresh(obj):
            obj.id = created_key.id
            obj.name = created_key.name
            obj.key_prefix = created_key.key_prefix
            obj.key_hash = created_key.key_hash
            obj.user_id = created_key.user_id
            obj.scopes = created_key.scopes
            obj.is_active = created_key.is_active
            obj.expires_at = created_key.expires_at
            obj.last_used_at = created_key.last_used_at
            obj.created_at = created_key.created_at

        db.refresh = mock_refresh

        user = _make_user("analyst", analyst_id)

        app.dependency_overrides[get_db] = override
        with patch("app.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.post(
                    self.URL,
                    json={"name": "My Key", "scopes": ["read"]},
                    headers={"Authorization": f"Bearer {_jwt(analyst_id)}"},
                )
        app.dependency_overrides.pop(get_db, None)

        assert r.status_code == 201
        body = r.json()
        assert "raw_key" in body
        assert body["raw_key"].startswith("asc_")
        assert body["name"] == "My Key"

    @pytest.mark.asyncio
    async def test_create_invalid_scope_returns_422(self, analyst_id):
        override, _ = _db_override(scalar_result=None, scalars_result=[])
        user = _make_user("analyst", analyst_id)

        app.dependency_overrides[get_db] = override
        with patch("app.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.post(
                    self.URL,
                    json={"name": "Bad", "scopes": ["superpower"]},
                    headers={"Authorization": f"Bearer {_jwt(analyst_id)}"},
                )
        app.dependency_overrides.pop(get_db, None)

        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_create_no_tenant_bypasses_cap(self, analyst_id):
        # P54: the old hardcoded _MAX_KEYS_PER_USER=20 limit (422) was replaced
        # by per-plan cap enforcement (403) in plan_caps.py.
        # When the user has no tenant (tenant_id=None), plan caps are skipped
        # and the key is created successfully.
        # Per-plan cap 403 behavior is tested in test_p54_plan_caps.py.
        import uuid as _uuid

        from datetime import datetime, timezone as _tz

        override, db_mock = _db_override(scalar_result=None, scalars_result=[])
        user = _make_user("analyst", analyst_id)
        user.tenant_id = None  # no tenant → plan caps skipped

        # Simulate DB flush: assign UUIDs + fill SQL-level column defaults
        def _add_side_effect(obj):
            if getattr(obj, "id", None) is None:
                obj.id = str(_uuid.uuid4())
        db_mock.add.side_effect = _add_side_effect

        async def _refresh_side_effect(obj):
            if getattr(obj, "is_active", None) is None:
                obj.is_active = True
            if getattr(obj, "created_at", None) is None:
                obj.created_at = datetime.now(_tz.utc)
            if getattr(obj, "last_used_at", "sentinel") == "sentinel":
                obj.last_used_at = None
        db_mock.refresh.side_effect = _refresh_side_effect

        app.dependency_overrides[get_db] = override
        with patch("app.api.deps._resolve_user", AsyncMock(return_value=user)), \
             patch("app.api.v1.endpoints.api_keys._ledger_create"):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.post(
                    self.URL,
                    json={"name": "Overflow", "scopes": ["read"]},
                    headers={"Authorization": f"Bearer {_jwt(analyst_id)}"},
                )
        app.dependency_overrides.pop(get_db, None)

        assert r.status_code == 201

    @pytest.mark.asyncio
    async def test_create_name_required(self, analyst_id):
        override, _ = _db_override(scalar_result=None, scalars_result=[])
        user = _make_user("analyst", analyst_id)

        app.dependency_overrides[get_db] = override
        with patch("app.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.post(
                    self.URL,
                    json={"name": "", "scopes": ["read"]},
                    headers={"Authorization": f"Bearer {_jwt(analyst_id)}"},
                )
        app.dependency_overrides.pop(get_db, None)

        assert r.status_code == 422


# ── Class 3: List endpoint ─────────────────────────────────────────────────────

class TestListAPIKeys:
    URL = "/api/v1/api-keys/"

    @pytest.mark.asyncio
    async def test_list_requires_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get(self.URL)
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_analyst_sees_own_keys(self, analyst_id):
        keys = [_make_api_key_row(analyst_id, f"k{i}") for i in range(3)]
        override, _ = _db_override(scalars_result=keys)
        user = _make_user("analyst", analyst_id)

        app.dependency_overrides[get_db] = override
        with patch("app.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.get(self.URL, headers={"Authorization": f"Bearer {_jwt(analyst_id)}"})
        app.dependency_overrides.pop(get_db, None)

        assert r.status_code == 200
        assert len(r.json()) == 3

    @pytest.mark.asyncio
    async def test_admin_sees_all_keys(self, admin_id):
        keys = [_make_api_key_row(str(uuid.uuid4()), f"k{i}") for i in range(5)]
        override, _ = _db_override(scalars_result=keys)
        user = _make_user("admin", admin_id)

        app.dependency_overrides[get_db] = override
        with patch("app.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.get(self.URL, headers={"Authorization": f"Bearer {_jwt(admin_id)}"})
        app.dependency_overrides.pop(get_db, None)

        assert r.status_code == 200
        assert len(r.json()) == 5

    @pytest.mark.asyncio
    async def test_list_empty_returns_empty_array(self, analyst_id):
        override, _ = _db_override(scalars_result=[])
        user = _make_user("analyst", analyst_id)

        app.dependency_overrides[get_db] = override
        with patch("app.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.get(self.URL, headers={"Authorization": f"Bearer {_jwt(analyst_id)}"})
        app.dependency_overrides.pop(get_db, None)

        assert r.status_code == 200
        assert r.json() == []


# ── Class 4: Get single key ───────────────────────────────────────────────────

class TestGetAPIKey:
    @pytest.mark.asyncio
    async def test_owner_can_get_own_key(self, analyst_id):
        key = _make_api_key_row(analyst_id)
        override, _ = _db_override(scalar_result=key)
        user = _make_user("analyst", analyst_id)

        app.dependency_overrides[get_db] = override
        with patch("app.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.get(f"/api/v1/api-keys/{key.id}",
                                headers={"Authorization": f"Bearer {_jwt(analyst_id)}"})
        app.dependency_overrides.pop(get_db, None)

        assert r.status_code == 200
        assert r.json()["id"] == key.id

    @pytest.mark.asyncio
    async def test_other_user_gets_403(self, analyst_id):
        other_user_id = str(uuid.uuid4())
        key = _make_api_key_row(other_user_id)   # owned by other
        override, _ = _db_override(scalar_result=key)
        user = _make_user("analyst", analyst_id)  # different requester

        app.dependency_overrides[get_db] = override
        with patch("app.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.get(f"/api/v1/api-keys/{key.id}",
                                headers={"Authorization": f"Bearer {_jwt(analyst_id)}"})
        app.dependency_overrides.pop(get_db, None)

        assert r.status_code == 403

    @pytest.mark.asyncio
    async def test_admin_can_get_any_key(self, admin_id):
        owner_id = str(uuid.uuid4())
        key = _make_api_key_row(owner_id)
        override, _ = _db_override(scalar_result=key)
        user = _make_user("admin", admin_id)

        app.dependency_overrides[get_db] = override
        with patch("app.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.get(f"/api/v1/api-keys/{key.id}",
                                headers={"Authorization": f"Bearer {_jwt(admin_id)}"})
        app.dependency_overrides.pop(get_db, None)

        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_missing_key_returns_404(self, analyst_id):
        override, _ = _db_override(scalar_result=None)
        user = _make_user("analyst", analyst_id)

        app.dependency_overrides[get_db] = override
        with patch("app.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.get(f"/api/v1/api-keys/nonexistent",
                                headers={"Authorization": f"Bearer {_jwt(analyst_id)}"})
        app.dependency_overrides.pop(get_db, None)

        assert r.status_code == 404


# ── Class 5: Revoke endpoint ──────────────────────────────────────────────────

class TestRevokeAPIKey:
    @pytest.mark.asyncio
    async def test_owner_can_revoke(self, analyst_id):
        key = _make_api_key_row(analyst_id)
        override, db = _db_override(scalar_result=key)
        user = _make_user("analyst", analyst_id)

        app.dependency_overrides[get_db] = override
        with patch("app.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.delete(f"/api/v1/api-keys/{key.id}",
                                   headers={"Authorization": f"Bearer {_jwt(analyst_id)}"})
        app.dependency_overrides.pop(get_db, None)

        assert r.status_code == 204
        db.delete.assert_called_once()

    @pytest.mark.asyncio
    async def test_other_user_cannot_revoke(self, analyst_id):
        other_id = str(uuid.uuid4())
        key = _make_api_key_row(other_id)
        override, db = _db_override(scalar_result=key)
        user = _make_user("analyst", analyst_id)

        app.dependency_overrides[get_db] = override
        with patch("app.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.delete(f"/api/v1/api-keys/{key.id}",
                                   headers={"Authorization": f"Bearer {_jwt(analyst_id)}"})
        app.dependency_overrides.pop(get_db, None)

        assert r.status_code == 403
        db.delete.assert_not_called()

    @pytest.mark.asyncio
    async def test_revoke_nonexistent_returns_404(self, analyst_id):
        override, _ = _db_override(scalar_result=None)
        user = _make_user("analyst", analyst_id)

        app.dependency_overrides[get_db] = override
        with patch("app.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.delete("/api/v1/api-keys/ghost",
                                   headers={"Authorization": f"Bearer {_jwt(analyst_id)}"})
        app.dependency_overrides.pop(get_db, None)

        assert r.status_code == 404


# ── Class 6: Rotate endpoint ──────────────────────────────────────────────────

class TestRotateAPIKey:
    @pytest.mark.asyncio
    async def test_rotate_returns_new_raw_key(self, analyst_id):
        key = _make_api_key_row(analyst_id)
        override, db = _db_override(scalar_result=key)

        async def mock_refresh(obj):
            pass  # key already has all attrs

        db.refresh = mock_refresh
        user = _make_user("analyst", analyst_id)

        app.dependency_overrides[get_db] = override
        with patch("app.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.post(f"/api/v1/api-keys/{key.id}/rotate",
                                 headers={"Authorization": f"Bearer {_jwt(analyst_id)}"})
        app.dependency_overrides.pop(get_db, None)

        assert r.status_code == 200
        body = r.json()
        assert "raw_key" in body
        assert body["raw_key"].startswith("asc_")

    @pytest.mark.asyncio
    async def test_rotate_updates_hash_and_prefix(self, analyst_id):
        key = _make_api_key_row(analyst_id)
        original_hash = key.key_hash
        override, db = _db_override(scalar_result=key)

        async def mock_refresh(obj):
            pass

        db.refresh = mock_refresh
        user = _make_user("analyst", analyst_id)

        app.dependency_overrides[get_db] = override
        with patch("app.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.post(f"/api/v1/api-keys/{key.id}/rotate",
                                 headers={"Authorization": f"Bearer {_jwt(analyst_id)}"})
        app.dependency_overrides.pop(get_db, None)

        assert r.status_code == 200
        # The key object's hash must have been mutated to a new value
        assert key.key_hash != original_hash

    @pytest.mark.asyncio
    async def test_rotate_other_user_gets_403(self, analyst_id):
        other_id = str(uuid.uuid4())
        key = _make_api_key_row(other_id)
        override, _ = _db_override(scalar_result=key)
        user = _make_user("analyst", analyst_id)

        app.dependency_overrides[get_db] = override
        with patch("app.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.post(f"/api/v1/api-keys/{key.id}/rotate",
                                 headers={"Authorization": f"Bearer {_jwt(analyst_id)}"})
        app.dependency_overrides.pop(get_db, None)

        assert r.status_code == 403


# ── Class 7: Update endpoint ──────────────────────────────────────────────────

class TestUpdateAPIKey:
    @pytest.mark.asyncio
    async def test_update_name(self, analyst_id):
        key = _make_api_key_row(analyst_id)
        override, db = _db_override(scalar_result=key)

        async def mock_refresh(obj):
            pass

        db.refresh = mock_refresh
        user = _make_user("analyst", analyst_id)

        app.dependency_overrides[get_db] = override
        with patch("app.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.patch(
                    f"/api/v1/api-keys/{key.id}",
                    json={"name": "Renamed Key"},
                    headers={"Authorization": f"Bearer {_jwt(analyst_id)}"},
                )
        app.dependency_overrides.pop(get_db, None)

        assert r.status_code == 200
        assert key.name == "Renamed Key"

    @pytest.mark.asyncio
    async def test_update_deactivate(self, analyst_id):
        key = _make_api_key_row(analyst_id)
        override, db = _db_override(scalar_result=key)

        async def mock_refresh(obj):
            pass

        db.refresh = mock_refresh
        user = _make_user("analyst", analyst_id)

        app.dependency_overrides[get_db] = override
        with patch("app.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.patch(
                    f"/api/v1/api-keys/{key.id}",
                    json={"is_active": False},
                    headers={"Authorization": f"Bearer {_jwt(analyst_id)}"},
                )
        app.dependency_overrides.pop(get_db, None)

        assert r.status_code == 200
        assert key.is_active is False

    @pytest.mark.asyncio
    async def test_update_other_user_gets_403(self, analyst_id):
        other_id = str(uuid.uuid4())
        key = _make_api_key_row(other_id)
        override, _ = _db_override(scalar_result=key)
        user = _make_user("analyst", analyst_id)

        app.dependency_overrides[get_db] = override
        with patch("app.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.patch(
                    f"/api/v1/api-keys/{key.id}",
                    json={"name": "Hijack"},
                    headers={"Authorization": f"Bearer {_jwt(analyst_id)}"},
                )
        app.dependency_overrides.pop(get_db, None)

        assert r.status_code == 403


# ── Class 8: X-API-Key authentication dep ────────────────────────────────────

class TestXAPIKeyDep:
    """Unit tests for get_user_from_api_key in deps.py."""

    @pytest.mark.asyncio
    async def test_missing_header_returns_401(self):
        from fastapi import HTTPException
        from asc_api.api.deps import get_user_from_api_key

        db = MagicMock()
        db.execute = AsyncMock()
        db.commit = AsyncMock()

        with pytest.raises(HTTPException) as exc:
            await get_user_from_api_key(request=MagicMock(), raw_key=None, db=db)
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_invalid_key_returns_401(self):
        from fastapi import HTTPException
        from asc_api.api.deps import get_user_from_api_key

        db = MagicMock()
        exec_result = MagicMock()
        exec_result.scalar_one_or_none.return_value = None
        db.execute = AsyncMock(return_value=exec_result)
        db.commit = AsyncMock()

        with pytest.raises(HTTPException) as exc:
            await get_user_from_api_key(request=MagicMock(), raw_key="asc_bad_key", db=db)
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_revoked_key_returns_401(self):
        from fastapi import HTTPException
        from asc_api.api.deps import get_user_from_api_key

        revoked_key = MagicMock()
        revoked_key.is_active = False
        revoked_key.expires_at = None

        db = MagicMock()
        exec_result = MagicMock()
        exec_result.scalar_one_or_none.return_value = revoked_key
        db.execute = AsyncMock(return_value=exec_result)
        db.commit = AsyncMock()

        with pytest.raises(HTTPException) as exc:
            await get_user_from_api_key(request=MagicMock(), raw_key="asc_ab12cd34_" + "x" * 40, db=db)
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_expired_key_returns_401(self):
        from fastapi import HTTPException
        from asc_api.api.deps import get_user_from_api_key

        expired_key = MagicMock()
        expired_key.is_active = True
        expired_key.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)

        db = MagicMock()
        exec_result = MagicMock()
        exec_result.scalar_one_or_none.return_value = expired_key
        db.execute = AsyncMock(return_value=exec_result)
        db.commit = AsyncMock()

        with pytest.raises(HTTPException) as exc:
            await get_user_from_api_key(request=MagicMock(), raw_key="asc_ab12cd34_" + "x" * 40, db=db)
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_valid_key_returns_user(self):
        from asc_api.api.deps import get_user_from_api_key

        raw = "asc_ab12cd34_" + "e" * 40
        # HMAC-SHA256 (Toque Premos) — must match _hmac_key_hash in deps.py
        key_hash = _hmac.new(settings.SECRET_KEY.encode(), raw.encode(), hashlib.sha256).hexdigest()

        valid_key = MagicMock()
        valid_key.is_active = True
        valid_key.expires_at = None
        valid_key.user_id = str(uuid.uuid4())
        valid_key.last_used_at = None

        owner = _make_user("analyst")

        db = MagicMock()
        # First execute → api_key; second execute → user
        exec_key = MagicMock()
        exec_key.scalar_one_or_none.return_value = valid_key
        exec_user = MagicMock()
        exec_user.scalar_one_or_none.return_value = owner
        db.execute = AsyncMock(side_effect=[exec_key, exec_user])
        db.commit = AsyncMock()

        result = await get_user_from_api_key(request=MagicMock(), raw_key=raw, db=db)
        assert result is owner

    @pytest.mark.asyncio
    async def test_valid_key_touches_last_used_at(self):
        from asc_api.api.deps import get_user_from_api_key

        raw = "asc_ab12cd34_" + "f" * 40
        valid_key = MagicMock()
        valid_key.is_active = True
        valid_key.expires_at = None
        valid_key.user_id = str(uuid.uuid4())
        valid_key.last_used_at = None

        owner = _make_user("analyst")

        db = MagicMock()
        exec_key = MagicMock()
        exec_key.scalar_one_or_none.return_value = valid_key
        exec_user = MagicMock()
        exec_user.scalar_one_or_none.return_value = owner
        db.execute = AsyncMock(side_effect=[exec_key, exec_user])
        db.commit = AsyncMock()

        await get_user_from_api_key(request=MagicMock(), raw_key=raw, db=db)
        assert valid_key.last_used_at is not None
        db.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_inactive_owner_returns_401(self):
        from fastapi import HTTPException
        from asc_api.api.deps import get_user_from_api_key

        raw = "asc_ab12cd34_" + "g" * 40

        valid_key = MagicMock()
        valid_key.is_active = True
        valid_key.expires_at = None
        valid_key.user_id = str(uuid.uuid4())

        db = MagicMock()
        exec_key = MagicMock()
        exec_key.scalar_one_or_none.return_value = valid_key
        exec_user = MagicMock()
        exec_user.scalar_one_or_none.return_value = None  # user not found / inactive
        db.execute = AsyncMock(side_effect=[exec_key, exec_user])
        db.commit = AsyncMock()

        with pytest.raises(HTTPException) as exc:
            await get_user_from_api_key(request=MagicMock(), raw_key=raw, db=db)
        assert exc.value.status_code == 401


# ── Class 9: Admin-only endpoint ──────────────────────────────────────────────

class TestAdminAllKeysEndpoint:
    URL = "/api/v1/api-keys/admin/all"

    @pytest.mark.asyncio
    async def test_analyst_gets_403(self, analyst_id):
        override, _ = _db_override(scalars_result=[])
        user = _make_user("analyst", analyst_id)

        app.dependency_overrides[get_db] = override
        with patch("app.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.get(self.URL, headers={"Authorization": f"Bearer {_jwt(analyst_id)}"})
        app.dependency_overrides.pop(get_db, None)

        assert r.status_code == 403

    @pytest.mark.asyncio
    async def test_admin_gets_all(self, admin_id):
        keys = [_make_api_key_row(str(uuid.uuid4())) for _ in range(4)]
        override, _ = _db_override(scalars_result=keys)
        user = _make_user("admin", admin_id)

        app.dependency_overrides[get_db] = override
        with patch("app.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.get(self.URL, headers={"Authorization": f"Bearer {_jwt(admin_id)}"})
        app.dependency_overrides.pop(get_db, None)

        assert r.status_code == 200
        assert len(r.json()) == 4

    @pytest.mark.asyncio
    async def test_no_auth_gets_401(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get(self.URL)
        assert r.status_code == 401


# ── Class 10: Security invariants ─────────────────────────────────────────────

class TestSecurityInvariants:
    """Verify that raw keys are never stored and other security properties."""

    def test_raw_key_not_returned_in_list_schema(self):
        """APIKeyResponse schema must NOT include raw_key."""
        from asc_api.api.v1.endpoints.api_keys import APIKeyResponse
        assert "raw_key" not in APIKeyResponse.model_fields

    def test_raw_key_in_created_schema(self):
        """APIKeyCreated schema MUST include raw_key."""
        from asc_api.api.v1.endpoints.api_keys import APIKeyCreated
        assert "raw_key" in APIKeyCreated.model_fields

    def test_two_different_keys_have_different_hashes(self):
        from asc_api.api.v1.endpoints.api_keys import _generate_raw_key, _hash_key
        k1 = _generate_raw_key()
        k2 = _generate_raw_key()
        assert _hash_key(k1) != _hash_key(k2)

    def test_hash_is_deterministic(self):
        from asc_api.api.v1.endpoints.api_keys import _hash_key
        raw = "asc_test0000_abcdef123456789012345678901234567890"
        h1 = _hash_key(raw)
        h2 = _hash_key(raw)
        assert h1 == h2

    def test_key_prefix_not_sufficient_to_authenticate(self):
        """Supplying only the prefix (8 chars) should produce a hash that doesn't match."""
        from asc_api.api.v1.endpoints.api_keys import _generate_raw_key, _hash_key, _prefix_of
        raw = _generate_raw_key()
        prefix = _prefix_of(raw)
        # Hash of prefix alone is different from hash of full key
        assert _hash_key(prefix) != _hash_key(raw)

    def test_max_keys_per_user_constant(self):
        from asc_api.api.v1.endpoints.api_keys import _MAX_KEYS_PER_USER
        assert _MAX_KEYS_PER_USER >= 10  # reasonable lower bound
        assert _MAX_KEYS_PER_USER <= 100  # reasonable upper bound

    def test_valid_scopes_set(self):
        from asc_api.api.v1.endpoints.api_keys import VALID_SCOPES
        assert "read" in VALID_SCOPES
        assert "write" in VALID_SCOPES
        assert "admin" in VALID_SCOPES

    def test_api_key_model_has_no_raw_key_column(self):
        """The APIKey model must not have a raw_key or key_plain column."""
        from asc_api.models.api_key import APIKey
        columns = {c.key for c in APIKey.__table__.columns}
        assert "raw_key" not in columns
        assert "key_plain" not in columns
        assert "key" not in columns


# ── Class 11: Deployment artifacts ────────────────────────────────────────────

class TestDeploymentArtifactsP40:
    def test_migration_file_exists(self):
        mig = _REPO_ROOT / "backend" / "migrations" / "versions" / "m3g47j5l8f60_add_api_keys_p40.py"
        assert mig.exists(), "Migration file missing"

    def test_migration_has_correct_down_revision(self):
        mig = _REPO_ROOT / "backend" / "migrations" / "versions" / "m3g47j5l8f60_add_api_keys_p40.py"
        content = mig.read_text()
        assert 'down_revision = "l2f36i4k7e59"' in content

    def test_api_key_model_file_exists(self):
        model = _REPO_ROOT / "backend" / "app" / "models" / "api_key.py"
        assert model.exists()

    def test_router_includes_api_keys(self):
        router = _REPO_ROOT / "backend" / "app" / "api" / "v1" / "router.py"
        content = router.read_text()
        assert "api_keys" in content

    def test_models_init_exports_api_key(self):
        init = _REPO_ROOT / "backend" / "app" / "models" / "__init__.py"
        content = init.read_text()
        assert "APIKey" in content

    def test_deps_has_x_api_key_header(self):
        deps = _REPO_ROOT / "backend" / "app" / "api" / "deps.py"
        content = deps.read_text()
        assert "X-API-Key" in content
        assert "get_user_from_api_key" in content

    def test_frontend_api_has_api_key_functions(self):
        api_ts = _REPO_ROOT / "frontend" / "src" / "lib" / "api.ts"
        content = api_ts.read_text()
        assert "listApiKeys" in content
        assert "createApiKey" in content
        assert "revokeApiKey" in content
        assert "rotateApiKey" in content


# ── Class 12: Regression ──────────────────────────────────────────────────────

class TestRegressionP40:
    @pytest.mark.asyncio
    async def test_liveness_still_ok(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/v1/health/liveness")
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_existing_auth_endpoints_not_broken(self):
        # Test liveness — no auth, no DB, proves the app router still works after P40 changes
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/v1/health/liveness")
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_observability_still_reachable(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/v1/observability/metrics")
        assert r.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_api_keys_prefix_is_api_keys(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/v1/api-keys/")
        # 401 (no auth via HTTPBearer) — proves the route exists
        assert r.status_code == 401

    def test_import_stable(self):
        import asc_api.api.v1.endpoints.api_keys  # noqa: F401
        import asc_api.models.api_key              # noqa: F401
        import asc_api.api.deps                    # noqa: F401

    def test_api_key_schema_from_attributes(self):
        from asc_api.api.v1.endpoints.api_keys import APIKeyResponse
        key = _make_api_key_row(str(uuid.uuid4()))
        # Should not raise — model_config from_attributes=True
        resp = APIKeyResponse(
            id=key.id, name=key.name, key_prefix=key.key_prefix,
            user_id=key.user_id, scopes=key.scopes, expires_at=key.expires_at,
            last_used_at=key.last_used_at, is_active=key.is_active,
            created_at=key.created_at,
        )
        assert resp.id == key.id


# ── Class 13: Toque Premos — HMAC-SHA256 invariants ──────────────────────────

class TestToquePromosHMAC:
    """Verify the HMAC-SHA256 upgrade (Toque Premos — autenticidad forense)."""

    def test_hash_key_uses_secret_key(self):
        """Hash output changes when SECRET_KEY changes (proves HMAC is keyed)."""
        from asc_api.api.v1.endpoints.api_keys import _hash_key
        raw = "asc_test1234_abcdef1234567890abcdef1234567890abcd"
        h1 = _hash_key(raw)
        # Compute with a different secret — result must differ
        h_other = _hmac.new(b"other-secret", raw.encode(), hashlib.sha256).hexdigest()
        assert h1 != h_other

    def test_hmac_hash_matches_deps_hash(self):
        """_hash_key in api_keys.py and _hmac_key_hash in deps.py must agree."""
        from asc_api.api.v1.endpoints.api_keys import _hash_key
        from asc_api.api.deps import _hmac_key_hash
        raw = "asc_abcd1234_" + "z" * 40
        assert _hash_key(raw) == _hmac_key_hash(raw)

    def test_hmac_not_plain_sha256(self):
        """Stored hash must NOT equal plain SHA-256 (proves HMAC key is applied)."""
        from asc_api.api.v1.endpoints.api_keys import _hash_key
        raw = "asc_ff00aa11_" + "b" * 40
        plain = hashlib.sha256(raw.encode()).hexdigest()
        assert _hash_key(raw) != plain

    def test_hash_length_still_64(self):
        """HMAC-SHA256 digest is 32 bytes = 64 hex chars — same as before."""
        from asc_api.api.v1.endpoints.api_keys import _hash_key
        assert len(_hash_key("asc_testkey_" + "x" * 40)) == 64

    def test_hmac_deterministic_cross_module(self):
        """Same raw key → same hash from both modules on every call."""
        from asc_api.api.v1.endpoints.api_keys import _hash_key
        from asc_api.api.deps import _hmac_key_hash
        raw = "asc_cafe1234_" + "d" * 40
        for _ in range(5):
            assert _hash_key(raw) == _hmac_key_hash(raw)


# ── Class 14: Toque Premos — Ledger Premos audit logging ─────────────────────

class TestToquePromosLedger:
    """Verify Ledger Premos: lifecycle events emitted to asc.audit channel."""

    def test_ledger_create_calls_log_security_action(self, analyst_id):
        from asc_api.api.v1.endpoints.api_keys import _ledger_create
        user = _make_user("analyst", analyst_id)
        key = _make_api_key_row(analyst_id, "Prometheus scraper")

        with patch("app.api.v1.endpoints.api_keys.log_security_action") as mock_log:
            _ledger_create(user, key)
            mock_log.assert_called_once()
            call_kwargs = mock_log.call_args
            assert call_kwargs.args[0] == "api_key_created"
            assert call_kwargs.kwargs["user_id"] == analyst_id
            assert call_kwargs.kwargs["resource"] == "api_key"

    def test_ledger_rotate_records_old_and_new_prefix(self, analyst_id):
        from asc_api.api.v1.endpoints.api_keys import _ledger_rotate
        user = _make_user("analyst", analyst_id)
        key = _make_api_key_row(analyst_id)
        key.key_prefix = "newprefi"

        with patch("app.api.v1.endpoints.api_keys.log_security_action") as mock_log:
            _ledger_rotate(user, key, "oldprefi")
            mock_log.assert_called_once()
            call_kwargs = mock_log.call_args
            assert call_kwargs.args[0] == "api_key_rotated"
            detail = call_kwargs.kwargs["detail"]
            assert "oldprefi" in detail
            assert "newprefi" in detail

    def test_ledger_revoke_records_prefix(self, analyst_id):
        from asc_api.api.v1.endpoints.api_keys import _ledger_revoke
        user = _make_user("analyst", analyst_id)

        with patch("app.api.v1.endpoints.api_keys.log_security_action") as mock_log:
            _ledger_revoke(user, "key-uuid-here", "aabbccdd")
            mock_log.assert_called_once()
            call_kwargs = mock_log.call_args
            assert call_kwargs.args[0] == "api_key_revoked"
            assert "aabbccdd" in call_kwargs.kwargs["detail"]

    def test_ledger_create_includes_scopes(self, analyst_id):
        from asc_api.api.v1.endpoints.api_keys import _ledger_create
        user = _make_user("analyst", analyst_id)
        key = _make_api_key_row(analyst_id, scopes=["read", "write"])

        with patch("app.api.v1.endpoints.api_keys.log_security_action") as mock_log:
            _ledger_create(user, key)
            detail = mock_log.call_args.kwargs["detail"]
            assert "read" in detail
            assert "write" in detail

    def test_all_three_events_are_distinct_action_names(self):
        """create/rotate/revoke must use distinct action strings for auditability."""
        from asc_api.api.v1.endpoints.api_keys import _ledger_create, _ledger_rotate, _ledger_revoke
        actions = []
        uid = str(uuid.uuid4())
        user = _make_user("admin", uid)
        key = _make_api_key_row(uid)

        with patch("app.api.v1.endpoints.api_keys.log_security_action") as mock_log:
            _ledger_create(user, key)
            actions.append(mock_log.call_args.args[0])
            mock_log.reset_mock()
            _ledger_rotate(user, key, "oldprefi")
            actions.append(mock_log.call_args.args[0])
            mock_log.reset_mock()
            _ledger_revoke(user, key.id, "aabbccdd")
            actions.append(mock_log.call_args.args[0])

        assert len(set(actions)) == 3


# ── Class 15: Toque Premos — Scopes adaptativos ───────────────────────────────

class TestToquePromosScopes:
    """Verify require_api_key_scope dep factory (Toque Premos — scopes adaptativos)."""

    @pytest.mark.asyncio
    async def test_scope_missing_raises_403(self):
        from fastapi import HTTPException
        from asc_api.api.deps import require_api_key_scope

        request = MagicMock()
        request.state.api_key_scopes = ["read"]  # only read — no write
        user = _make_user("analyst")

        guard = require_api_key_scope("write")
        with pytest.raises(HTTPException) as exc:
            await guard(request=request, user=user)
        assert exc.value.status_code == 403
        assert "write" in exc.value.detail

    @pytest.mark.asyncio
    async def test_scope_present_returns_user(self):
        from asc_api.api.deps import require_api_key_scope

        request = MagicMock()
        request.state.api_key_scopes = ["read", "write"]
        user = _make_user("analyst")

        guard = require_api_key_scope("write")
        result = await guard(request=request, user=user)
        assert result is user

    @pytest.mark.asyncio
    async def test_admin_scope_accepted(self):
        from asc_api.api.deps import require_api_key_scope

        request = MagicMock()
        request.state.api_key_scopes = ["read", "write", "admin"]
        user = _make_user("admin")

        guard = require_api_key_scope("admin")
        result = await guard(request=request, user=user)
        assert result is user

    @pytest.mark.asyncio
    async def test_empty_scopes_blocks_all(self):
        from fastapi import HTTPException
        from asc_api.api.deps import require_api_key_scope

        request = MagicMock()
        request.state.api_key_scopes = []
        user = _make_user("analyst")

        for scope in ("read", "write", "admin"):
            guard = require_api_key_scope(scope)
            with pytest.raises(HTTPException) as exc:
                await guard(request=request, user=user)
            assert exc.value.status_code == 403

    def test_require_api_key_scope_exported_from_deps(self):
        """Scopes dep must be importable from deps module."""
        from asc_api.api.deps import require_api_key_scope
        assert callable(require_api_key_scope)

    def test_scopes_stored_on_request_state(self):
        """get_user_from_api_key must set request.state.api_key_scopes."""
        import inspect
        from asc_api.api.deps import get_user_from_api_key
        src = inspect.getsource(get_user_from_api_key)
        assert "api_key_scopes" in src
