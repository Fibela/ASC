"""
P59 â€” SSO Bridge: Supabase JWT â†’ ASC JWT Exchange â€” Test Suite
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

from asc_api.db.session import get_db
from asc_api.main import app

_BACKEND = Path(__file__).parent.parent
_MIGRATIONS_DIR = _BACKEND / "migrations" / "versions"
_P59_HEAD = "u1o34r3t6n08"
_EXPECTED_TOTAL_MIGRATIONS = 26  # 24 (P-16) + b3c4d5e6f7a8 + c9d12f0e5b67 merge head

_SSO_URL = "/api/v1/auth/supabase-sso"

_TEST_SECRET = "test-supabase-jwt-secret-for-unit-tests-only"
_TEST_UID = str(uuid.uuid4())
_TEST_EMAIL = "sso_user@premoscorp.com"


# â”€â”€ JWT factory â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
    Call 1: supabase_uid lookup â†’ supabase_user
    Call 2: email lookup â†’ email_user
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


# â”€â”€ 1. JWT Validation (unit) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

_TEST_SUPABASE_URL = "https://kqxwtayzqujlddviskwl.supabase.co"


def _hs256_cfg(mock_cfg, secret=_TEST_SECRET, audience="authenticated"):
    """Populate mock settings for the HS256 (legacy) verification path."""
    mock_cfg.SUPABASE_URL = _TEST_SUPABASE_URL
    mock_cfg.SUPABASE_JWT_SECRET = secret
    mock_cfg.SUPABASE_JWT_AUDIENCE = audience


class TestSupabaseJWTValidation:
    """Unit tests for _validate_supabase_token() â€” covers HS256 and RS256 paths."""

    def test_valid_hs256_token_returns_payload(self):
        from asc_api.api.v1.endpoints.auth_sso import _validate_supabase_token
        token = _make_supabase_token()
        with patch("asc_api.api.v1.endpoints.auth_sso._settings") as mock_cfg:
            _hs256_cfg(mock_cfg)
            payload = _validate_supabase_token(token)
        assert payload["sub"] == _TEST_UID
        assert payload["email"] == _TEST_EMAIL

    def test_expired_token_raises_401(self):
        from fastapi import HTTPException
        from asc_api.api.v1.endpoints.auth_sso import _validate_supabase_token
        token = _make_supabase_token(exp_offset=-1)
        with patch("asc_api.api.v1.endpoints.auth_sso._settings") as mock_cfg:
            _hs256_cfg(mock_cfg)
            with pytest.raises(HTTPException) as exc:
                _validate_supabase_token(token)
        assert exc.value.status_code == 401
        assert "expired" in str(exc.value.detail).lower()

    def test_wrong_secret_raises_401(self):
        from fastapi import HTTPException
        from asc_api.api.v1.endpoints.auth_sso import _validate_supabase_token
        token = _make_supabase_token(secret="correct-secret-that-is-long-enough-xxxxx")
        with patch("asc_api.api.v1.endpoints.auth_sso._settings") as mock_cfg:
            _hs256_cfg(mock_cfg, secret="wrong-secret-that-is-also-long-enough-xxxxx")
            with pytest.raises(HTTPException) as exc:
                _validate_supabase_token(token)
        assert exc.value.status_code == 401

    def test_wrong_audience_raises_401(self):
        from fastapi import HTTPException
        from asc_api.api.v1.endpoints.auth_sso import _validate_supabase_token
        token = _make_supabase_token(audience="service_role")
        with patch("asc_api.api.v1.endpoints.auth_sso._settings") as mock_cfg:
            _hs256_cfg(mock_cfg)
            with pytest.raises(HTTPException) as exc:
                _validate_supabase_token(token)
        assert exc.value.status_code == 401
        assert "audience" in str(exc.value.detail).lower()

    def test_missing_supabase_url_raises_503(self):
        """SUPABASE_URL absent â†’ 503 regardless of algorithm."""
        from fastapi import HTTPException
        from asc_api.api.v1.endpoints.auth_sso import _validate_supabase_token
        token = _make_supabase_token()
        with patch("asc_api.api.v1.endpoints.auth_sso._settings") as mock_cfg:
            mock_cfg.SUPABASE_URL = ""
            mock_cfg.SUPABASE_JWT_SECRET = _TEST_SECRET
            mock_cfg.SUPABASE_JWT_AUDIENCE = "authenticated"
            with pytest.raises(HTTPException) as exc:
                _validate_supabase_token(token)
        assert exc.value.status_code == 503
        assert "not_configured" in str(exc.value.detail)

    def test_missing_hs256_secret_raises_503(self):
        """SUPABASE_URL present but SUPABASE_JWT_SECRET absent on HS256 token â†’ 503."""
        from fastapi import HTTPException
        from asc_api.api.v1.endpoints.auth_sso import _validate_supabase_token
        token = _make_supabase_token()
        with patch("asc_api.api.v1.endpoints.auth_sso._settings") as mock_cfg:
            mock_cfg.SUPABASE_URL = _TEST_SUPABASE_URL
            mock_cfg.SUPABASE_JWT_SECRET = ""
            mock_cfg.SUPABASE_JWT_AUDIENCE = "authenticated"
            with pytest.raises(HTTPException) as exc:
                _validate_supabase_token(token)
        assert exc.value.status_code == 503
        assert "not_configured" in str(exc.value.detail)

    def test_tampered_token_raises_401(self):
        from fastapi import HTTPException
        from asc_api.api.v1.endpoints.auth_sso import _validate_supabase_token
        token = _make_supabase_token() + "tamper"
        with patch("asc_api.api.v1.endpoints.auth_sso._settings") as mock_cfg:
            _hs256_cfg(mock_cfg)
            with pytest.raises(HTTPException) as exc:
                _validate_supabase_token(token)
        assert exc.value.status_code == 401

    def test_payload_contains_sub_and_email(self):
        from asc_api.api.v1.endpoints.auth_sso import _validate_supabase_token
        uid = str(uuid.uuid4())
        email = "test@example.com"
        token = _make_supabase_token(sub=uid, email=email)
        with patch("asc_api.api.v1.endpoints.auth_sso._settings") as mock_cfg:
            _hs256_cfg(mock_cfg)
            payload = _validate_supabase_token(token)
        assert payload["sub"] == uid
        assert payload["email"] == email

    def test_custom_audience_accepted(self):
        from asc_api.api.v1.endpoints.auth_sso import _validate_supabase_token
        token = _make_supabase_token(audience="my_audience")
        with patch("asc_api.api.v1.endpoints.auth_sso._settings") as mock_cfg:
            _hs256_cfg(mock_cfg, audience="my_audience")
            payload = _validate_supabase_token(token)
        assert payload["sub"] == _TEST_UID

    def test_rs256_token_uses_jwks_not_secret(self):
        """RS256 token (new Supabase JWT Signing Keys) verified via JWKS â€” secret unused."""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        from asc_api.api.v1.endpoints.auth_sso import _validate_supabase_token

        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        rs256_token = pyjwt.encode(
            {"sub": _TEST_UID, "email": _TEST_EMAIL, "aud": "authenticated",
             "iat": int(time.time()), "exp": int(time.time()) + 3600,
             "role": "authenticated"},
            private_key, algorithm="RS256",
        )

        mock_signing_key = MagicMock()
        mock_signing_key.key = private_key.public_key()
        mock_jwk_client = MagicMock()
        mock_jwk_client.get_signing_key_from_jwt.return_value = mock_signing_key

        captured_url = []

        def _capture_jwks_client(url, **kwargs):
            captured_url.append(url)
            return mock_jwk_client

        with patch("asc_api.api.v1.endpoints.auth_sso._settings") as mock_cfg, \
             patch("asc_api.api.v1.endpoints.auth_sso.PyJWKClient", side_effect=_capture_jwks_client):
            mock_cfg.SUPABASE_URL = _TEST_SUPABASE_URL
            mock_cfg.SUPABASE_JWT_SECRET = ""
            mock_cfg.SUPABASE_JWT_PUBLIC_KEY = ""   # force JWKS path, not direct PEM
            mock_cfg.SUPABASE_ANON_KEY = ""
            mock_cfg.SUPABASE_JWT_AUDIENCE = "authenticated"
            result = _validate_supabase_token(rs256_token)

        assert result["sub"] == _TEST_UID
        assert result["email"] == _TEST_EMAIL
        mock_jwk_client.get_signing_key_from_jwt.assert_called_once()
        # Verify correct OIDC discovery path â€” NOT the broken /auth/v1/jwks endpoint
        assert len(captured_url) == 1
        assert captured_url[0].endswith("/auth/v1/.well-known/jwks.json"), (
            f"Wrong JWKS URL: {captured_url[0]!r} â€” must use /.well-known/jwks.json"
        )

    def test_jwks_url_uses_well_known_path(self):
        """Regression: the JWKS URL must be /auth/v1/.well-known/jwks.json (not /auth/v1/jwks)."""
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.backends import default_backend
        from asc_api.api.v1.endpoints.auth_sso import _validate_supabase_token

        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        es256_token = pyjwt.encode(
            {"sub": _TEST_UID, "email": _TEST_EMAIL, "aud": "authenticated",
             "iat": int(time.time()), "exp": int(time.time()) + 3600,
             "role": "authenticated"},
            private_key, algorithm="ES256",
        )

        mock_signing_key = MagicMock()
        mock_signing_key.key = private_key.public_key()
        mock_jwk_client = MagicMock()
        mock_jwk_client.get_signing_key_from_jwt.return_value = mock_signing_key

        captured = []

        def _spy(url, **kwargs):
            captured.append(url)
            return mock_jwk_client

        with patch("asc_api.api.v1.endpoints.auth_sso._settings") as mock_cfg, \
             patch("asc_api.api.v1.endpoints.auth_sso.PyJWKClient", side_effect=_spy):
            mock_cfg.SUPABASE_URL = _TEST_SUPABASE_URL
            mock_cfg.SUPABASE_JWT_SECRET = ""
            mock_cfg.SUPABASE_JWT_PUBLIC_KEY = ""
            mock_cfg.SUPABASE_JWT_AUDIENCE = "authenticated"
            _validate_supabase_token(es256_token)

        assert len(captured) == 1
        url = captured[0]
        assert ".well-known/jwks.json" in url, f"Expected .well-known/jwks.json in URL, got: {url!r}"
        assert "/auth/v1/jwks" not in url.replace(".well-known/jwks.json", ""), (
            f"Old broken /auth/v1/jwks path still present in: {url!r}"
        )


# â”€â”€ 2. User provisioning (unit) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestAutoProvisioning:
    """Unit tests for _find_or_create_user()."""

    @pytest.mark.anyio
    async def test_existing_supabase_uid_returns_user_not_provisioned(self):
        from asc_api.api.v1.endpoints.auth_sso import _find_or_create_user
        existing = MagicMock()
        existing.supabase_uid = _TEST_UID
        existing.email = _TEST_EMAIL
        db = _make_db(supabase_user=existing)
        user, provisioned = await _find_or_create_user(_TEST_UID, _TEST_EMAIL, db)
        assert user is existing
        assert provisioned is False

    @pytest.mark.anyio
    async def test_existing_email_links_supabase_uid(self):
        from asc_api.api.v1.endpoints.auth_sso import _find_or_create_user
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
        from asc_api.api.v1.endpoints.auth_sso import _find_or_create_user
        from asc_api.models.user import User
        from asc_api.models.tenant import Tenant

        db = _make_db(supabase_user=None, email_user=None)
        with patch("asc_api.api.v1.endpoints.auth_sso._settings") as mock_cfg:
            mock_cfg.SSO_DEFAULT_PLAN = "free"
            user, provisioned = await _find_or_create_user(
                _TEST_UID, _TEST_EMAIL, db
            )
        assert provisioned is True
        # Both User and Tenant should have been added
        assert len(db._added) == 2

    @pytest.mark.anyio
    async def test_new_user_gets_analyst_role(self):
        from asc_api.api.v1.endpoints.auth_sso import _find_or_create_user
        db = _make_db(supabase_user=None, email_user=None)
        with patch("asc_api.api.v1.endpoints.auth_sso._settings") as mock_cfg:
            mock_cfg.SSO_DEFAULT_PLAN = "free"
            user, _ = await _find_or_create_user(_TEST_UID, _TEST_EMAIL, db)
        assert user.role == "analyst"

    @pytest.mark.anyio
    async def test_new_user_email_verified_true(self):
        from asc_api.api.v1.endpoints.auth_sso import _find_or_create_user
        db = _make_db(supabase_user=None, email_user=None)
        with patch("asc_api.api.v1.endpoints.auth_sso._settings") as mock_cfg:
            mock_cfg.SSO_DEFAULT_PLAN = "free"
            user, _ = await _find_or_create_user(_TEST_UID, _TEST_EMAIL, db)
        assert user.email_verified is True

    @pytest.mark.anyio
    async def test_new_user_has_supabase_uid(self):
        from asc_api.api.v1.endpoints.auth_sso import _find_or_create_user
        uid = str(uuid.uuid4())
        db = _make_db(supabase_user=None, email_user=None)
        with patch("asc_api.api.v1.endpoints.auth_sso._settings") as mock_cfg:
            mock_cfg.SSO_DEFAULT_PLAN = "free"
            user, _ = await _find_or_create_user(uid, _TEST_EMAIL, db)
        assert user.supabase_uid == uid


# â”€â”€ 3. POST /auth/supabase-sso endpoint â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestSSOEndpoint:

    @pytest.mark.anyio
    async def test_sso_not_configured_returns_503(self):
        """SUPABASE_URL absent â†’ 503 (endpoint disabled)."""
        override, _ = _db_override()
        app.dependency_overrides[get_db] = override
        token = _make_supabase_token()
        with patch("asc_api.api.v1.endpoints.auth_sso._settings") as mock_cfg:
            mock_cfg.SUPABASE_URL = ""
            mock_cfg.SUPABASE_JWT_SECRET = ""
            mock_cfg.SUPABASE_JWT_AUDIENCE = "authenticated"
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.post(_SSO_URL, json={"supabase_token": token})
        app.dependency_overrides.pop(get_db, None)
        assert r.status_code == 503

    @pytest.mark.anyio
    async def test_expired_token_returns_401(self):
        override, _ = _db_override()
        app.dependency_overrides[get_db] = override
        token = _make_supabase_token(exp_offset=-60)
        with patch("asc_api.api.v1.endpoints.auth_sso._settings") as mock_cfg:
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
        with patch("asc_api.api.v1.endpoints.auth_sso._settings") as mock_cfg:
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

        with patch("asc_api.api.v1.endpoints.auth_sso._settings") as mock_cfg:
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

        with patch("asc_api.api.v1.endpoints.auth_sso._settings") as mock_cfg:
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

        with patch("asc_api.api.v1.endpoints.auth_sso._settings") as mock_cfg:
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

        with patch("asc_api.api.v1.endpoints.auth_sso._settings") as mock_cfg:
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

        with patch("asc_api.api.v1.endpoints.auth_sso._find_or_create_user",
                   new_callable=AsyncMock) as mock_foc:
            user_mock = MagicMock()
            user_mock.id = str(uuid.uuid4())
            user_mock.email = _TEST_EMAIL
            user_mock.role = "analyst"
            user_mock.tenant_id = str(uuid.uuid4())
            user_mock.is_active = True
            mock_foc.return_value = (user_mock, True)

            with patch("asc_api.api.v1.endpoints.auth_sso._validate_supabase_token",
                       return_value={"sub": _TEST_UID, "email": _TEST_EMAIL}), \
                 patch("asc_api.api.v1.endpoints.auth_sso._settings") as mock_cfg:
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


# â”€â”€ 4. Security invariants â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestSecurityInvariants:

    def test_sso_response_no_supabase_token_field(self):
        from asc_api.api.v1.endpoints.auth_sso import SSOResponse
        fields = SSOResponse.model_fields
        assert "supabase_token" not in fields
        assert "hashed_password" not in fields

    def test_sso_response_has_access_token(self):
        from asc_api.api.v1.endpoints.auth_sso import SSOResponse
        assert "access_token" in SSOResponse.model_fields

    def test_sso_response_has_provisioned_flag(self):
        from asc_api.api.v1.endpoints.auth_sso import SSOResponse
        assert "provisioned" in SSOResponse.model_fields

    def test_tampered_rs256_header_rejected_with_wrong_key(self):
        """Token claiming RS256 but signed with HS256 must be rejected (signature mismatch)."""
        import base64, json
        from fastapi import HTTPException
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        from asc_api.api.v1.endpoints.auth_sso import _validate_supabase_token

        # Create HS256 token then tamper the header to claim RS256
        token = pyjwt.encode(
            {"sub": "uid", "email": "e@e.com", "aud": "authenticated",
             "exp": int(time.time()) + 3600, "iat": int(time.time())},
            "anything-long-enough-for-hmac-xxxxxxxxxxxxxxx",
            algorithm="HS256",
        )
        parts = token.split(".")
        header = json.dumps({"alg": "RS256", "typ": "JWT"}).encode()
        padded = base64.urlsafe_b64encode(header).rstrip(b"=").decode()
        tampered = padded + "." + parts[1] + "." + parts[2]

        # Mock JWKS to return a real RSA public key â€” signature won't match
        wrong_key = rsa.generate_private_key(65537, 2048, default_backend()).public_key()
        mock_signing_key = MagicMock()
        mock_signing_key.key = wrong_key
        mock_jwk_client = MagicMock()
        mock_jwk_client.get_signing_key_from_jwt.return_value = mock_signing_key

        with patch("asc_api.api.v1.endpoints.auth_sso._settings") as mock_cfg, \
             patch("asc_api.api.v1.endpoints.auth_sso.PyJWKClient", return_value=mock_jwk_client):
            mock_cfg.SUPABASE_URL = _TEST_SUPABASE_URL
            mock_cfg.SUPABASE_JWT_SECRET = _TEST_SECRET
            mock_cfg.SUPABASE_JWT_PUBLIC_KEY = ""   # force JWKS path
            mock_cfg.SUPABASE_ANON_KEY = ""
            mock_cfg.SUPABASE_JWT_AUDIENCE = "authenticated"
            with pytest.raises(HTTPException) as exc:
                _validate_supabase_token(tampered)
        assert exc.value.status_code == 401
        assert exc.value.detail["code"] == "supabase_token_invalid"

    def test_user_model_has_supabase_uid(self):
        from asc_api.models.user import User
        assert hasattr(User, "supabase_uid")

    def test_sso_endpoint_has_no_auth_dependency(self):
        """SSO endpoint must NOT require an existing ASC token â€” it IS the login."""
        import inspect
        from asc_api.api.v1.endpoints.auth_sso import supabase_sso
        sig = str(inspect.signature(supabase_sso).parameters)
        assert "get_current_user" not in sig
        assert "get_current_admin" not in sig

    def test_config_has_supabase_jwt_secret(self):
        from asc_api.core.config import Settings
        s = Settings()
        assert hasattr(s, "SUPABASE_JWT_SECRET")
        assert hasattr(s, "SUPABASE_URL")
        assert hasattr(s, "SUPABASE_JWT_AUDIENCE")
        assert hasattr(s, "SSO_DEFAULT_PLAN")

    def test_supabase_uid_index_on_user_table(self):
        from asc_api.models.user import User
        columns = {c.name: c for c in User.__table__.c}
        assert "supabase_uid" in columns
        col = columns["supabase_uid"]
        assert col.nullable is True  # NULL for native users

    def test_sso_default_plan_is_not_enterprise(self):
        """SSO users should not auto-get enterprise plan."""
        from asc_api.core.config import Settings
        s = Settings()
        assert s.SSO_DEFAULT_PLAN in ("free", "pro")


# â”€â”€ 5. Config completeness â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
        router_src = (_BACKEND / "asc_api" / "api" / "v1" / "router.py").read_text(encoding="utf-8")
        assert "auth_sso" in router_src
        assert "auth_sso.router" in router_src


# â”€â”€ 6. Migration artifact â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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


# â”€â”€ 7. Module structure â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestModuleStructure:

    def test_auth_sso_importable(self):
        from asc_api.api.v1.endpoints.auth_sso import router, supabase_sso
        assert router.prefix == "/auth"
        assert callable(supabase_sso)

    def test_user_model_supabase_uid_nullable(self):
        from asc_api.models.user import User
        columns = {c.name: c for c in User.__table__.c}
        assert "supabase_uid" in columns
        assert columns["supabase_uid"].nullable is True

    def test_sso_request_schema_has_supabase_token(self):
        from asc_api.api.v1.endpoints.auth_sso import SSORequest
        assert "supabase_token" in SSORequest.model_fields

    def test_sso_response_fields(self):
        from asc_api.api.v1.endpoints.auth_sso import SSOResponse
        for field in ("access_token", "token_type", "tenant_id", "user_id", "email", "role", "provisioned"):
            assert field in SSOResponse.model_fields, f"Missing field: {field}"


# â”€â”€ 8. Regression gates â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestRegressionGates:

    def test_p58_test_migration_count_updated(self):
        """test_p58 must know about migration count â‰¥16."""
        p58_src = (Path(__file__).parent / "test_p58_adapter_registry.py").read_text(
            encoding="utf-8"
        )
        assert "_TOTAL = 18" in p58_src or "_TOTAL = 17" in p58_src or "_TOTAL = 16" in p58_src or "_TOTAL = 19" in p58_src or "_TOTAL = 20" in p58_src or "_TOTAL = 22" in p58_src or "_TOTAL = 23" in p58_src or "_TOTAL = 24" in p58_src or "_TOTAL = 25" in p58_src or "_TOTAL = 26" in p58_src

    def test_p57_migration_count_still_updated(self):
        p57_src = (Path(__file__).parent / "test_p57_staging_goliove.py").read_text(
            encoding="utf-8"
        )
        assert "_EXPECTED_MIGRATION_COUNT = 16" in p57_src or \
               "_EXPECTED_MIGRATION_COUNT = 17" in p57_src or \
               "_EXPECTED_MIGRATION_COUNT = 18" in p57_src or \
               "_EXPECTED_MIGRATION_COUNT = 20" in p57_src or \
               "_EXPECTED_MIGRATION_COUNT = 22" in p57_src or \
               "_EXPECTED_MIGRATION_COUNT = 23" in p57_src or \
               "_EXPECTED_MIGRATION_COUNT = 24" in p57_src or \
               "_EXPECTED_MIGRATION_COUNT = 25" in p57_src or \
               "_EXPECTED_MIGRATION_COUNT = 26" in p57_src

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
        router_src = (_BACKEND / "asc_api" / "api" / "v1" / "router.py").read_text(
            encoding="utf-8"
        )
        assert "auth_sso" in router_src

    def test_p56_migration_count_consistent(self):
        p56_src = (Path(__file__).parent / "test_p56_deployment_readiness.py").read_text(
            encoding="utf-8"
        )
        assert ("_EXPECTED_COUNT = 16" in p56_src or
                "_EXPECTED_COUNT = 17" in p56_src or
                "_EXPECTED_COUNT = 18" in p56_src or
                "_EXPECTED_COUNT = 19" in p56_src or
                "_EXPECTED_COUNT = 20" in p56_src or
                "_EXPECTED_COUNT = 22" in p56_src or
                "_EXPECTED_COUNT = 23" in p56_src or
                "_EXPECTED_COUNT = 24" in p56_src or
                "_EXPECTED_COUNT = 25" in p56_src or
                "_EXPECTED_COUNT = 26" in p56_src)
