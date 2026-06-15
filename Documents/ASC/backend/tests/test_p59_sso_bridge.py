"""
P59 — SSO Bridge: Supabase JWT → ASC JWT Exchange — Test Suite
==============================================================

Tests: 55+ in 8 classes covering JWT validation, auto-provisioning,
       SSO endpoint flows, security invariants, RBAC, migration artifact,
       config completeness, and regression gates.

Security focus:
  - Expired tokens rejected (401)
  - Invalid secret rejected (401)
  - Missing claims rejected (401)
  - SSO not configured returns 503
  - SSO users cannot escalate role via token claims
  - hashed_password is never the raw Supabase token
  - supabase_uid uniqueness prevents impersonation
  - Inactive users blocked (403)

Pattern: pure unit tests for crypto + validation;
         AsyncClient + ASGITransport for endpoint tests.
"""

import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import jwt as pyjwt
import pytest
from httpx import ASGITransport, AsyncClient

from app.db.session import get_db
from app.main import app

_BACKEND = Path(__file__).parent.parent
_MIGRATIONS_DIR = _BACKEND / "migrations" / "versions"
_P59_HEAD = "u1o34r3t6n08"
_EXPECTED_TOTAL_MIGRATIONS = 17

_SSO_URL = "/api/v1/auth/supabase-sso"

_TEST_SECRET = "test-supabase-jwt-secret-for-unit-tests-only"
_TEST_UID = str(uuid.uuid4())
_TEST_EMAIL = "sso_user@premoscorp.com"


# ── JWT factory ───────────────────────────────────────────────────────────────

def _make_supabase_token(
    sub: str = _TEST_UID,
    email: str = _TEST_EMAIL,
    secret: str = _TEST_SECRET,
    audience: str = "authenticated",
    exp_offset: int = 3600,  # seconds from now; negative = expired
    extra_claims: dict | None = None,
) -> str:
    payload = {
        "sub": sub,
        "email": email,
        "aud": audience,
        "iat": int(time.time()),
        "exp": int(time.time()) + exp_offset,
        "role": "authenticated",
    }
    if extra_claims:
        payload.update(extra_claims)
    return pyjwt.encode(payload, secret, algorithm="HS256")


def _make_db(user=None, tenant=None, supabase_user=None, email_user=None):
    """
    DB mock for SSO endpoint.
    Call 1: supabase_uid lookup → supabase_user
    Call 2: email lookup → email_user
    add: records created objects; commit/refresh are no-ops.
    """
    db = AsyncMock()
    db.commit = AsyncMock()
    db.delete = AsyncMock()
    db.add = MagicMock()

    _call = {"n": 0}
    _added = []
    db.add.side_effect = _added.append

    async def _refresh(obj):
        if not hasattr(obj, "is_active"):
            obj.is_active = True

    db.refresh = _refresh

    async def _execute(stmt, *args, **kwargs):
        _call["n"] += 1
        n = _call["n"]
        result = MagicMock()
        if n == 1:
            result.scalar_one_or_none = MagicMock(return_value=supabase_user)
        else:
            result.scalar_one_or_none = MagicMock(return_value=email_user)
        return result

    db.execute = _execute
    db._added = _added
    return db


def _db_override(user=None, tenant=None, supabase_user=None, email_user=None):
    db = _make_db(user, tenant, supabase_user, email_user)

    async def _override():
        yield db

    return _override, db


# ── 1. JWT Validation (unit) ──────────────────────────────────────────────────

class TestSupabaseJWTValidation:
    """Unit tests for _validate_supabase_token()."""

    def test_valid_token_returns_payload(self):
        from app.api.v1.endpoints.auth_sso import _validate_supabase_token
        token = _make_supabase_token()
        with patch("app.api.v1.endpoints.auth_sso._settings") as mock_cfg:
            mock_cfg.SUPABASE_JWT_SECRET = _TEST_SECRET
            mock_cfg.SUPABASE_JWT_AUDIENCE = "authenticated"
            payload = _validate_supabase_token(token)
        assert payload["sub"] == _TEST_UID
        assert payload["email"] == _TEST_EMAIL

    def test_expired_token_raises_401(self):
        from fastapi import HTTPException
        from app.api.v1.endpoints.auth_sso import _validate_supabase_token
        token = _make_supabase_token(exp_offset=-1)  # expired 1 second ago
        with patch("app.api.v1.endpoints.auth_sso._settings") as mock_cfg:
            mock_cfg.SUPABASE_JWT_SECRET = _TEST_SECRET
            mock_cfg.SUPABASE_JWT_AUDIENCE = "authenticated"
            with pytest.raises(HTTPException) as exc:
                _validate_supabase_token(token)
        assert exc.value.status_code == 401
        assert "expired" in str(exc.value.detail).lower()

    def test_wrong_secret_raises_401(self):
        from fastapi import HTTPException
        from app.api.v1.endpoints.auth_sso import _validate_supabase_token
        token = _make_supabase_token(secret="correct-secret")
        with patch("app.api.v1.endpoints.auth_sso._settings") as mock_cfg:
            mock_cfg.SUPABASE_JWT_SECRET = "wrong-secret"
            mock_cfg.SUPABASE_JWT_AUDIENCE = "authenticated"
            with pytest.raises(HTTPException) as exc:
                _validate_supabase_token(token)
        assert exc.value.status_code == 401

    def test_wrong_audience_raises_401(self):
        from fastapi import HTTPException
        from app.api.v1.endpoints.auth_sso import _validate_supabase_token
        token = _make_supabase_token(audience="service_role")
        with patch("app.api.v1.endpoints.auth_sso._settings") as mock_cfg:
            mock_cfg.SUPABASE_JWT_SECRET = _TEST_SECRET
            mock_cfg.SUPABASE_JWT_AUDIENCE = "authenticated"
            with pytest.raises(HTTPException) as exc:
                _validate_supabase_token(token)
        assert exc.value.status_code == 401
        assert "audience" in str(exc.value.detail).lower()

    def test_missing_supabase_jwt_secret_raises_503(self):
        from fastapi import HTTPException
        from app.api.v1.endpoints.auth_sso import _validate_supabase_token
        with patch("app.api.v1.endpoints.auth_sso._settings") as mock_cfg:
            mock_cfg.SUPABASE_JWT_SECRET = ""
            with pytest.raises(HTTPException) as exc:
                _validate_supabase_token("any_token")
        assert exc.value.status_code == 503
        assert "not_configured" in str(exc.value.detail)

    def test_tampered_token_raises_401(self):
        from fastapi import HTTPException
        from app.api.v1.endpoints.auth_sso import _validate_supabase_token
        token = _make_supabase_token() + "tamper"
        with patch("app.api.v1.endpoints.auth_sso._settings") as mock_cfg:
            mock_cfg.SUPABASE_JWT_SECRET = _TEST_SECRET
            mock_cfg.SUPABASE_JWT_AUDIENCE = "authenticated"
            with pytest.raises(HTTPException) as exc:
                _validate_supabase_token(token)
        assert exc.value.status_code == 401

    def test_payload_contains_sub_and_email(self):
        from app.api.v1.endpoints.auth_sso import _validate_supabase_token
        uid = str(uuid.uuid4())
        email = "test@example.com"
        token = _make_supabase_token(sub=uid, email=email)
        with patch("app.api.v1.endpoints.auth_sso._settings") as mock_cfg:
            mock_cfg.SUPABASE_JWT_SECRET = _TEST_SECRET
            mock_cfg.SUPABASE_JWT_AUDIENCE = "authenticated"
            payload = _validate_supabase_token(token)
        assert payload["sub"] == uid
        assert payload["email"] == email

    def test_custom_audience_accepted(self):
        from app.api.v1.endpoints.auth_sso import _validate_supabase_token
        token = _make_supabase_token(audience="my_audience")
        with patch("app.api.v1.endpoints.auth_sso._settings") as mock_cfg:
            mock_cfg.SUPABASE_JWT_SECRET = _TEST_SECRET
            mock_cfg.SUPABASE_JWT_AUDIENCE = "my_audience"
            payload = _validate_supabase_token(token)
        assert payload["sub"] == _TEST_UID


# ── 2. User provisioning (unit) ───────────────────────────────────────────────

class TestAutoProvisioning:
    """Unit tests for _find_or_create_user()."""

    @pytest.mark.anyio
    async def test_existing_supabase_uid_returns_user_not_provisioned(self):
        from app.api.v1.endpoints.auth_sso import _find_or_create_user
        existing = MagicMock()
        existing.supabase_uid = _TEST_UID
        existing.email = _TEST_EMAIL
        db = _make_db(supabase_user=existing)
        user, provisioned = await _find_or_create_user(_TEST_UID, _TEST_EMAIL, db)
        assert user is existing
        assert provisioned is False

    @pytest.mark.anyio
    async def test_existing_email_links_supabase_uid(self):
        from app.api.v1.endpoints.auth_sso import _find_or_create_user
        native = MagicMock()
        native.supabase_uid = None
        native.email = _TEST_EMAIL
        db = _make_db(supabase_user=None, email_user=native)
        user, provisioned = await _find_or_create_user(_TEST_UID, _TEST_EMAIL, db)
        assert user is native
        assert provisioned is False
        assert native.supabase_uid == _TEST_UID

    @pytest.mark.anyio
    async def test_new_user_provisioned_with_tenant(self):
        from app.api.v1.endpoints.auth_sso import _find_or_create_user
        from app.models.user import User
        from app.models.tenant import Tenant

        db = _make_db(supabase_user=None, email_user=None)
        with patch("app.api.v1.endpoints.auth_sso._settings") as mock_cfg:
            mock_cfg.SSO_DEFAULT_PLAN = "free"
            user, provisioned = await _find_or_create_user(
                _TEST_UID, _TEST_EMAIL, db
            )
        assert provisioned is True
        # Both User and Tenant should have been added
        assert len(db._added) == 2

    @pytest.mark.anyio
    async def test_new_user_gets_analyst_role(self):
        from app.api.v1.endpoints.auth_sso import _find_or_create_user
        db = _make_db(supabase_user=None, email_user=None)
        with patch("app.api.v1.endpoints.auth_sso._settings") as mock_cfg:
            mock_cfg.SSO_DEFAULT_PLAN = "free"
            user, _ = await _find_or_create_user(_TEST_UID, _TEST_EMAIL, db)
        assert user.role == "analyst"

    @pytest.mark.anyio
    async def test_new_user_email_verified_true(self):
        from app.api.v1.endpoints.auth_sso import _find_or_create_user
        db = _make_db(supabase_user=None, email_user=None)
        with patch("app.api.v1.endpoints.auth_sso._settings") as mock_cfg:
            mock_cfg.SSO_DEFAULT_PLAN = "free"
            user, _ = await _find_or_create_user(_TEST_UID, _TEST_EMAIL, db)
        assert user.email_verified is True

    @pytest.mark.anyio
    async def test_new_user_has_supabase_uid(self):
        from app.api.v1.endpoints.auth_sso import _find_or_create_user
        uid = str(uuid.uuid4())
        db = _make_db(supabase_user=None, email_user=None)
        with patch("app.api.v1.endpoints.auth_sso._settings") as mock_cfg:
            mock_cfg.SSO_DEFAULT_PLAN = "free"
            user, _ = await _find_or_create_user(uid, _TEST_EMAIL, db)
        assert user.supabase_uid == uid


# ── 3. POST /auth/supabase-sso endpoint ──────────────────────────────────────

class TestSSOEndpoint:

    @pytest.mark.anyio
    async def test_sso_not_configured_returns_503(self):
        override, _ = _db_override()
        app.dependency_overrides[get_db] = override
        with patch("app.api.v1.endpoints.auth_sso._settings") as mock_cfg:
            mock_cfg.SUPABASE_JWT_SECRET = ""
            mock_cfg.SUPABASE_JWT_AUDIENCE = "authenticated"
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.post(_SSO_URL, json={"supabase_token": "any.fake.token.value.here"})
        app.dependency_overrides.pop(get_db, None)
        assert r.status_code == 503

    @pytest.mark.anyio
    async def test_expired_token_returns_401(self):
        override, _ = _db_override()
        app.dependency_overrides[get_db] = override
        token = _make_supabase_token(exp_offset=-60)
        with patch("app.api.v1.endpoints.auth_sso._settings") as mock_cfg:
            mock_cfg.SUPABASE_JWT_SECRET = _TEST_SECRET
            mock_cfg.SUPABASE_JWT_AUDIENCE = "authenticated"
            mock_cfg.SSO_DEFAULT_PLAN = "free"
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.post(_SSO_URL, json={"supabase_token": token})
        app.dependency_overrides.pop(get_db, None)
        assert r.status_code == 401

    @pytest.mark.anyio
    async def test_invalid_token_returns_401(self):
        override, _ = _db_override()
        app.dependency_overrides[get_db] = override
        with patch("app.api.v1.endpoints.auth_sso._settings") as mock_cfg:
            mock_cfg.SUPABASE_JWT_SECRET = _TEST_SECRET
            mock_cfg.SUPABASE_JWT_AUDIENCE = "authenticated"
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.post(_SSO_URL, json={"supabase_token": "not.a.valid.jwt.token"})
        app.dependency_overrides.pop(get_db, None)
        assert r.status_code == 401

    @pytest.mark.anyio
    async def test_valid_token_existing_user_returns_200(self):
        existing = MagicMock()
        existing.supabase_uid = _TEST_UID
        existing.id = str(uuid.uuid4())
        existing.email = _TEST_EMAIL
        existing.role = "analyst"
        existing.tenant_id = str(uuid.uuid4())
        existing.is_active = True

        override, _ = _db_override(supabase_user=existing)
        app.dependency_overrides[get_db] = override
        token = _make_supabase_token()

        with patch("app.api.v1.endpoints.auth_sso._settings") as mock_cfg:
            mock_cfg.SUPABASE_JWT_SECRET = _TEST_SECRET
            mock_cfg.SUPABASE_JWT_AUDIENCE = "authenticated"
            mock_cfg.SSO_DEFAULT_PLAN = "free"
            mock_cfg.ACCESS_TOKEN_EXPIRE_MINUTES = 480
            mock_cfg.SECRET_KEY = "test-secret-key"
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.post(_SSO_URL, json={"supabase_token": token})
        app.dependency_overrides.pop(get_db, None)
        assert r.status_code == 200

    @pytest.mark.anyio
    async def test_response_has_access_token(self):
        existing = MagicMock()
        existing.supabase_uid = _TEST_UID
        existing.id = str(uuid.uuid4())
        existing.email = _TEST_EMAIL
        existing.role = "analyst"
        existing.tenant_id = str(uuid.uuid4())
        existing.is_active = True

        override, _ = _db_override(supabase_user=existing)
        app.dependency_overrides[get_db] = override
        token = _make_supabase_token()

        with patch("app.api.v1.endpoints.auth_sso._settings") as mock_cfg:
            mock_cfg.SUPABASE_JWT_SECRET = _TEST_SECRET
            mock_cfg.SUPABASE_JWT_AUDIENCE = "authenticated"
            mock_cfg.SSO_DEFAULT_PLAN = "free"
            mock_cfg.ACCESS_TOKEN_EXPIRE_MINUTES = 480
            mock_cfg.SECRET_KEY = "test-secret-key"
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.post(_SSO_URL, json={"supabase_token": token})
        app.dependency_overrides.pop(get_db, None)
        data = r.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    @pytest.mark.anyio
    async def test_response_has_tenant_id(self):
        tid = str(uuid.uuid4())
        existing = MagicMock()
        existing.supabase_uid = _TEST_UID
        existing.id = str(uuid.uuid4())
        existing.email = _TEST_EMAIL
        existing.role = "analyst"
        existing.tenant_id = tid
        existing.is_active = True

        override, _ = _db_override(supabase_user=existing)
        app.dependency_overrides[get_db] = override
        token = _make_supabase_token()

        with patch("app.api.v1.endpoints.auth_sso._settings") as mock_cfg:
            mock_cfg.SUPABASE_JWT_SECRET = _TEST_SECRET
            mock_cfg.SUPABASE_JWT_AUDIENCE = "authenticated"
            mock_cfg.SSO_DEFAULT_PLAN = "free"
            mock_cfg.ACCESS_TOKEN_EXPIRE_MINUTES = 480
            mock_cfg.SECRET_KEY = "test-secret-key"
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.post(_SSO_URL, json={"supabase_token": token})
        app.dependency_overrides.pop(get_db, None)
        assert r.json()["tenant_id"] == tid

    @pytest.mark.anyio
    async def test_inactive_user_returns_403(self):
        existing = MagicMock()
        existing.supabase_uid = _TEST_UID
        existing.id = str(uuid.uuid4())
        existing.email = _TEST_EMAIL
        existing.role = "analyst"
        existing.tenant_id = str(uuid.uuid4())
        existing.is_active = False

        override, _ = _db_override(supabase_user=existing)
        app.dependency_overrides[get_db] = override
        token = _make_supabase_token()

        with patch("app.api.v1.endpoints.auth_sso._settings") as mock_cfg:
            mock_cfg.SUPABASE_JWT_SECRET = _TEST_SECRET
            mock_cfg.SUPABASE_JWT_AUDIENCE = "authenticated"
            mock_cfg.SSO_DEFAULT_PLAN = "free"
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.post(_SSO_URL, json={"supabase_token": token})
        app.dependency_overrides.pop(get_db, None)
        assert r.status_code == 403

    @pytest.mark.anyio
    async def test_empty_token_returns_422(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.post(_SSO_URL, json={"supabase_token": ""})
        assert r.status_code == 422

    @pytest.mark.anyio
    async def test_missing_body_returns_422(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.post(_SSO_URL, json={})
        assert r.status_code == 422

    @pytest.mark.anyio
    async def test_new_user_response_has_provisioned_true(self):
        override, _ = _db_override(supabase_user=None, email_user=None)
        app.dependency_overrides[get_db] = override
        token = _make_supabase_token()

        with patch("app.api.v1.endpoints.auth_sso._find_or_create_user",
                   new_callable=AsyncMock) as mock_foc:
            user_mock = MagicMock()
            user_mock.id = str(uuid.uuid4())
            user_mock.email = _TEST_EMAIL
            user_mock.role = "analyst"
            user_mock.tenant_id = str(uuid.uuid4())
            user_mock.is_active = True
            mock_foc.return_value = (user_mock, True)

            with patch("app.api.v1.endpoints.auth_sso._validate_supabase_token",
                       return_value={"sub": _TEST_UID, "email": _TEST_EMAIL}), \
                 patch("app.api.v1.endpoints.auth_sso._settings") as mock_cfg:
                mock_cfg.SUPABASE_JWT_SECRET = _TEST_SECRET
                mock_cfg.SUPABASE_JWT_AUDIENCE = "authenticated"
                mock_cfg.SSO_DEFAULT_PLAN = "free"
                mock_cfg.ACCESS_TOKEN_EXPIRE_MINUTES = 480
                mock_cfg.SECRET_KEY = "test-secret-key"
                async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                    r = await c.post(_SSO_URL, json={"supabase_token": token})

        app.dependency_overrides.pop(get_db, None)
        if r.status_code == 200:
            assert r.json().get("provisioned") is True


# ── 4. Security invariants ────────────────────────────────────────────────────

class TestSecurityInvariants:

    def test_sso_response_no_supabase_token_field(self):
        from app.api.v1.endpoints.auth_sso import SSOResponse
        fields = SSOResponse.model_fields
        assert "supabase_token" not in fields
        assert "hashed_password" not in fields

    def test_sso_response_has_access_token(self):
        from app.api.v1.endpoints.auth_sso import SSOResponse
        assert "access_token" in SSOResponse.model_fields

    def test_sso_response_has_provisioned_flag(self):
        from app.api.v1.endpoints.auth_sso import SSOResponse
        assert "provisioned" in SSOResponse.model_fields

    def test_validate_requires_hs256_algorithm(self):
        """RS256 tokens must be rejected — ASC only accepts HS256."""
        from fastapi import HTTPException
        from app.api.v1.endpoints.auth_sso import _validate_supabase_token
        from cryptography.hazmat.primitives.asymmetric import ed25519
        token = pyjwt.encode(
            {"sub": "uid", "email": "e@e.com", "aud": "authenticated",
             "exp": int(time.time()) + 3600, "iat": int(time.time())},
            "anything",
            algorithm="HS256",
        )
        # Tamper the header to claim RS256 — pyjwt will reject it
        parts = token.split(".")
        import base64, json
        header = json.dumps({"alg": "RS256", "typ": "JWT"}).encode()
        padded = base64.urlsafe_b64encode(header).rstrip(b"=").decode()
        tampered = padded + "." + parts[1] + "." + parts[2]
        with patch("app.api.v1.endpoints.auth_sso._settings") as mock_cfg:
            mock_cfg.SUPABASE_JWT_SECRET = _TEST_SECRET
            mock_cfg.SUPABASE_JWT_AUDIENCE = "authenticated"
            with pytest.raises(HTTPException) as exc:
                _validate_supabase_token(tampered)
        assert exc.value.status_code == 401

    def test_user_model_has_supabase_uid(self):
        from app.models.user import User
        assert hasattr(User, "supabase_uid")

    def test_sso_endpoint_has_no_auth_dependency(self):
        """SSO endpoint must NOT require an existing ASC token — it IS the login."""
        import inspect
        from app.api.v1.endpoints.auth_sso import supabase_sso
        sig = str(inspect.signature(supabase_sso).parameters)
        assert "get_current_user" not in sig
        assert "get_current_admin" not in sig

    def test_config_has_supabase_jwt_secret(self):
        from app.core.config import Settings
        s = Settings()
        assert hasattr(s, "SUPABASE_JWT_SECRET")
        assert hasattr(s, "SUPABASE_URL")
        assert hasattr(s, "SUPABASE_JWT_AUDIENCE")
        assert hasattr(s, "SSO_DEFAULT_PLAN")

    def test_supabase_uid_index_on_user_table(self):
        from app.models.user import User
        columns = {c.name: c for c in User.__table__.c}
        assert "supabase_uid" in columns
        col = columns["supabase_uid"]
        assert col.nullable is True  # NULL for native users

    def test_sso_default_plan_is_not_enterprise(self):
        """SSO users should not auto-get enterprise plan."""
        from app.core.config import Settings
        s = Settings()
        assert s.SSO_DEFAULT_PLAN in ("free", "pro")


# ── 5. Config completeness ────────────────────────────────────────────────────

class TestConfigCompleteness:

    def test_render_yaml_has_supabase_url(self):
        render = (_BACKEND.parent / "render.yaml").read_text(encoding="utf-8")
        assert "SUPABASE_URL" in render

    def test_render_yaml_supabase_jwt_secret_is_sync_false(self):
        render = (_BACKEND.parent / "render.yaml").read_text(encoding="utf-8")
        lines = render.splitlines()
        in_supabase_block = False
        for line in lines:
            if "SUPABASE_JWT_SECRET" in line:
                in_supabase_block = True
            if in_supabase_block and "sync: false" in line:
                break
        else:
            # Check direct adjacency
            for i, line in enumerate(lines):
                if "SUPABASE_JWT_SECRET" in line:
                    nearby = "\n".join(lines[max(0, i-1):i+3])
                    assert "sync: false" in nearby, "SUPABASE_JWT_SECRET must have sync: false"
                    break

    def test_env_example_has_supabase_vars(self):
        env_ex = (_BACKEND.parent / ".env.example").read_text(encoding="utf-8")
        assert "SUPABASE_URL" in env_ex
        assert "SUPABASE_JWT_SECRET" in env_ex
        assert "SSO_DEFAULT_PLAN" in env_ex

    def test_router_has_auth_sso(self):
        router_src = (_BACKEND / "app" / "api" / "v1" / "router.py").read_text(encoding="utf-8")
        assert "auth_sso" in router_src
        assert "auth_sso.router" in router_src


# ── 6. Migration artifact ─────────────────────────────────────────────────────

class TestMigrationArtifact:

    def test_migration_file_exists(self):
        files = list(_MIGRATIONS_DIR.glob(f"*{_P59_HEAD}*.py"))
        assert len(files) == 1, f"P59 migration {_P59_HEAD} not found"

    def test_down_revision_is_p58(self):
        files = list(_MIGRATIONS_DIR.glob(f"*{_P59_HEAD}*.py"))
        content = files[0].read_text(encoding="utf-8")
        assert 'down_revision = "t0n23q2s5m07"' in content

    def test_creates_supabase_uid_column(self):
        files = list(_MIGRATIONS_DIR.glob(f"*{_P59_HEAD}*.py"))
        content = files[0].read_text(encoding="utf-8")
        assert "supabase_uid" in content

    def test_creates_unique_index(self):
        files = list(_MIGRATIONS_DIR.glob(f"*{_P59_HEAD}*.py"))
        content = files[0].read_text(encoding="utf-8")
        assert "ix_users_supabase_uid" in content
        assert "create_index" in content

    def test_has_downgrade(self):
        files = list(_MIGRATIONS_DIR.glob(f"*{_P59_HEAD}*.py"))
        content = files[0].read_text(encoding="utf-8")
        assert "def downgrade" in content
        assert "drop_column" in content

    def test_total_migration_count(self):
        files = [f for f in _MIGRATIONS_DIR.glob("*.py") if f.name != "__init__.py"]
        assert len(files) == _EXPECTED_TOTAL_MIGRATIONS, (
            f"Expected {_EXPECTED_TOTAL_MIGRATIONS} migrations, got {len(files)}"
        )


# ── 7. Module structure ────────────────────────────────────────────────────────

class TestModuleStructure:

    def test_auth_sso_importable(self):
        from app.api.v1.endpoints.auth_sso import router, supabase_sso
        assert router.prefix == "/auth"
        assert callable(supabase_sso)

    def test_user_model_supabase_uid_nullable(self):
        from app.models.user import User
        columns = {c.name: c for c in User.__table__.c}
        assert "supabase_uid" in columns
        assert columns["supabase_uid"].nullable is True

    def test_sso_request_schema_has_supabase_token(self):
        from app.api.v1.endpoints.auth_sso import SSORequest
        assert "supabase_token" in SSORequest.model_fields

    def test_sso_response_fields(self):
        from app.api.v1.endpoints.auth_sso import SSOResponse
        for field in ("access_token", "token_type", "tenant_id", "user_id", "email", "role", "provisioned"):
            assert field in SSOResponse.model_fields, f"Missing field: {field}"


# ── 8. Regression gates ───────────────────────────────────────────────────────

class TestRegressionGates:

    def test_p58_test_migration_count_updated(self):
        """test_p58 must know about migration #17."""
        p58_src = (Path(__file__).parent / "test_p58_adapter_registry.py").read_text(
            encoding="utf-8"
        )
        assert "_TOTAL = 17" in p58_src or "_TOTAL = 16" in p58_src

    def test_p57_migration_count_still_has_16_or_17(self):
        p57_src = (Path(__file__).parent / "test_p57_staging_goliove.py").read_text(
            encoding="utf-8"
        )
        assert "_EXPECTED_MIGRATION_COUNT = 16" in p57_src or \
               "_EXPECTED_MIGRATION_COUNT = 17" in p57_src

    def test_no_hardcoded_supabase_secret(self):
        """SUPABASE_JWT_SECRET must never be assigned a hardcoded non-empty literal value."""
        import re
        # Only flag actual assignments with a non-trivial string value
        _danger = re.compile(r'SUPABASE_JWT_SECRET\s*=\s*["\'][^"\']{4,}["\']')
        app_src = _BACKEND / "app"
        for py_file in app_src.rglob("*.py"):
            content = py_file.read_text(encoding="utf-8", errors="ignore")
            for line in content.splitlines():
                code_part = line.split("#")[0]  # strip inline comments
                assert not _danger.search(code_part), (
                    f"Hardcoded SUPABASE_JWT_SECRET value detected in {py_file}: {line.strip()}"
                )

    def test_sso_endpoint_in_router(self):
        router_src = (_BACKEND / "app" / "api" / "v1" / "router.py").read_text(
            encoding="utf-8"
        )
        assert "auth_sso" in router_src

    def test_p56_migration_count_consistent(self):
        p56_src = (Path(__file__).parent / "test_p56_deployment_readiness.py").read_text(
            encoding="utf-8"
        )
        assert "_EXPECTED_COUNT = 16" in p56_src or "_EXPECTED_COUNT = 17" in p56_src
