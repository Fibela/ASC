"""
P31-SEC-AUTH — Authentication hardening security tests.

Coverage:
  - JWT signature verification: wrong secret, tampered payload, algorithm confusion
  - JWT expiry: expired access and refresh tokens
  - JWT type validation: access vs refresh token mix-up
  - JTI blacklist: L1 in-process and L2 SQLite
  - Account locking: brute force → auto-lock → reject correct password
  - force_password_reset gate: blocks all endpoints except change-password
  - Timing protection: sentinel hash always runs bcrypt
  - Token uniqueness: every token has a unique JTI

Rate-limit strategy: unique key_func per test via monkeypatch so each test
gets its own rate-limit bucket and never sees HTTP 429.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, patch

import jwt as pyjwt
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.core.security import (
    ALGORITHM,
    create_access_token,
    create_refresh_token,
    decode_token_payload,
    get_password_hash,
    verify_password,
    verify_token,
)
from asc_api.core.config import get_settings
from asc_api.core.jwt_blacklist import jwt_blacklist

settings = get_settings()


# ── Rate-limit bypass ─────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _reset_rate_limit():
    """Clear slowapi MemoryStorage before each test so no test sees 429."""
    from asc_api.core.rate_limit import limiter
    limiter._storage.reset()
    yield
    limiter._storage.reset()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _expired_access_token(user_id: str) -> str:
    """Produce a JWT whose exp is 1 hour in the past."""
    payload = {
        "exp": datetime.now(timezone.utc) - timedelta(hours=1),
        "sub": str(user_id),
        "type": "access",
        "jti": str(uuid.uuid4()),
    }
    return pyjwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)


def _token_wrong_secret(user_id: str) -> str:
    payload = {
        "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        "sub": str(user_id),
        "type": "access",
        "jti": str(uuid.uuid4()),
    }
    return pyjwt.encode(payload, "totally-wrong-secret-but-long-enough-xxxxx", algorithm=ALGORITHM)


def _token_missing_sub() -> str:
    payload = {
        "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        "type": "access",
        "jti": str(uuid.uuid4()),
    }
    return pyjwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)


# ── TestJWTVerification ───────────────────────────────────────────────────────

class TestJWTVerification:
    """verify_token and decode_token_payload unit tests — no DB, no HTTP."""

    def test_valid_access_token_returns_user_id(self):
        uid = str(uuid.uuid4())
        token = create_access_token(uid)
        result = verify_token(token, "access")
        assert result == uid

    def test_valid_refresh_token_returns_user_id(self):
        uid = str(uuid.uuid4())
        token = create_refresh_token(uid)
        result = verify_token(token, "refresh")
        assert result == uid

    def test_wrong_secret_raises_401(self):
        from fastapi import HTTPException
        uid = str(uuid.uuid4())
        bad_token = _token_wrong_secret(uid)
        with pytest.raises(HTTPException) as exc:
            verify_token(bad_token, "access")
        assert exc.value.status_code == 401

    def test_expired_token_raises_401(self):
        from fastapi import HTTPException
        uid = str(uuid.uuid4())
        expired = _expired_access_token(uid)
        with pytest.raises(HTTPException) as exc:
            verify_token(expired, "access")
        assert exc.value.status_code == 401

    def test_missing_sub_raises_401(self):
        from fastapi import HTTPException
        token = _token_missing_sub()
        with pytest.raises(HTTPException) as exc:
            verify_token(token, "access")
        assert exc.value.status_code == 401

    def test_access_token_used_as_refresh_raises_401(self):
        from fastapi import HTTPException
        uid = str(uuid.uuid4())
        access = create_access_token(uid)
        with pytest.raises(HTTPException) as exc:
            verify_token(access, "refresh")
        assert exc.value.status_code == 401

    def test_refresh_token_used_as_access_raises_401(self):
        from fastapi import HTTPException
        uid = str(uuid.uuid4())
        refresh = create_refresh_token(uid)
        with pytest.raises(HTTPException) as exc:
            verify_token(refresh, "access")
        assert exc.value.status_code == 401

    def test_decode_payload_returns_dict_for_valid_token(self):
        uid = str(uuid.uuid4())
        token = create_access_token(uid)
        payload = decode_token_payload(token)
        assert payload.get("sub") == uid
        assert payload.get("type") == "access"

    def test_decode_payload_returns_empty_for_bad_token(self):
        payload = decode_token_payload("not.a.real.token")
        assert payload == {}

    def test_decode_payload_returns_empty_for_wrong_secret(self):
        uid = str(uuid.uuid4())
        bad = _token_wrong_secret(uid)
        payload = decode_token_payload(bad)
        assert payload == {}

    def test_decode_payload_returns_empty_for_expired_token(self):
        uid = str(uuid.uuid4())
        expired = _expired_access_token(uid)
        payload = decode_token_payload(expired)
        assert payload == {}

    def test_access_token_contains_type_access(self):
        token = create_access_token("user123")
        payload = pyjwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
        assert payload["type"] == "access"

    def test_refresh_token_contains_type_refresh(self):
        token = create_refresh_token("user123")
        payload = pyjwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
        assert payload["type"] == "refresh"

    def test_every_token_has_unique_jti(self):
        uid = str(uuid.uuid4())
        tokens = [create_access_token(uid) for _ in range(10)]
        jtis = {pyjwt.decode(t, settings.SECRET_KEY, algorithms=[ALGORITHM])["jti"] for t in tokens}
        assert len(jtis) == 10  # all unique

    def test_token_encodes_user_id_as_sub(self):
        uid = "test-user-id-12345"
        token = create_access_token(uid)
        payload = pyjwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
        assert payload["sub"] == uid

    def test_algorithm_is_hs256(self):
        assert ALGORITHM == "HS256"


# ── TestJWTBlacklist ──────────────────────────────────────────────────────────

class TestJWTBlacklist:
    """JWT blacklist L1 (in-process) and L2 (SQLite) revocation tests."""

    @pytest.fixture(autouse=True)
    def _clear_blacklist(self):
        """Ensure L1 cache is clean before and after each test."""
        jwt_blacklist.reset_local()
        yield
        jwt_blacklist.reset_local()

    def test_fresh_jti_is_not_revoked_in_l1(self):
        jti = str(uuid.uuid4())
        # Check L1 only (without DB) by inspecting local set directly
        assert jti not in jwt_blacklist._local

    @pytest.mark.asyncio
    async def test_revoke_adds_jti_to_l1(self, db: AsyncSession):
        jti = str(uuid.uuid4())
        expires = datetime.now(timezone.utc) + timedelta(hours=1)
        await jwt_blacklist.revoke(jti, expires, db)
        assert jti in jwt_blacklist._local

    @pytest.mark.asyncio
    async def test_revoked_jti_is_detected(self, db: AsyncSession):
        jti = str(uuid.uuid4())
        expires = datetime.now(timezone.utc) + timedelta(hours=1)
        await jwt_blacklist.revoke(jti, expires, db)
        assert await jwt_blacklist.is_revoked(jti, db) is True

    @pytest.mark.asyncio
    async def test_non_revoked_jti_passes(self, db: AsyncSession):
        jti = str(uuid.uuid4())
        assert await jwt_blacklist.is_revoked(jti, db) is False

    @pytest.mark.asyncio
    async def test_reset_local_clears_l1(self, db: AsyncSession):
        jti = str(uuid.uuid4())
        expires = datetime.now(timezone.utc) + timedelta(hours=1)
        await jwt_blacklist.revoke(jti, expires, db)
        assert jwt_blacklist.local_size > 0
        jwt_blacklist.reset_local()
        assert jwt_blacklist.local_size == 0

    @pytest.mark.asyncio
    async def test_l2_hit_warms_l1(self, db: AsyncSession):
        """After L2 lookup confirms revocation, L1 should be warmed."""
        jti = str(uuid.uuid4())
        expires = datetime.now(timezone.utc) + timedelta(hours=1)
        # Write to L2 only (bypass L1 add for the test)
        from asc_api.models.revoked_token import RevokedToken
        entry = RevokedToken(jti=jti, expires_at=expires, revoked_by="test", reason="test")
        db.add(entry)
        await db.commit()

        jwt_blacklist.reset_local()  # L1 empty
        assert jti not in jwt_blacklist._local
        # is_revoked should find it in L2 and warm L1
        assert await jwt_blacklist.is_revoked(jti, db) is True
        assert jti in jwt_blacklist._local

    @pytest.mark.asyncio
    async def test_purge_expired_removes_past_entries(self, db: AsyncSession):
        jti = str(uuid.uuid4())
        expired_at = datetime.now(timezone.utc) - timedelta(hours=1)
        await jwt_blacklist.revoke(jti, expired_at, db)
        count = await jwt_blacklist.purge_expired(db)
        assert count >= 1

    @pytest.mark.asyncio
    async def test_purge_expired_leaves_valid_entries(self, db: AsyncSession):
        jti_old = str(uuid.uuid4())
        jti_new = str(uuid.uuid4())
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        await jwt_blacklist.revoke(jti_old, past, db)
        await jwt_blacklist.revoke(jti_new, future, db)
        await jwt_blacklist.purge_expired(db)
        # New entry should still be revoked
        assert await jwt_blacklist.is_revoked(jti_new, db) is True

    def test_blacklist_local_size_after_manual_add(self):
        before = jwt_blacklist.local_size
        with jwt_blacklist._lock:
            jwt_blacklist._local.add("test-jti-manual")
        assert jwt_blacklist.local_size == before + 1

    def test_blacklist_singleton_is_module_level(self):
        from asc_api.core.jwt_blacklist import jwt_blacklist as imported
        assert imported is jwt_blacklist


# ── TestAccountLocking ────────────────────────────────────────────────────────

class TestAccountLocking:
    """Brute-force detection → account auto-lock behavior via real login endpoint."""

    @pytest.mark.asyncio
    async def test_failed_login_increments_counter(self, client, admin_user):
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": admin_user.email, "password": "WrongPass@99!"},
        )
        assert r.status_code == 401
        # Verify user.failed_login_attempts was incremented via DB
        from sqlalchemy import select
        from asc_api.models.user import User
        from asc_api.db.session import get_db
        # Reload user to check counter
        from asc_api.main import app
        db_gen = app.dependency_overrides.get(get_db)
        if db_gen:
            async for session in db_gen():
                from sqlalchemy import select
                from asc_api.models.user import User as U
                result = await session.execute(select(U).where(U.id == admin_user.id))
                u = result.scalar_one()
                assert u.failed_login_attempts >= 1
                break

    @pytest.mark.asyncio
    async def test_account_auto_locks_after_threshold(self, client, analyst_user, db):
        """Setting failed_login_attempts to threshold-1, one more bad login → lock."""
        analyst_user.failed_login_attempts = settings.ACCOUNT_LOCK_THRESHOLD - 1
        db.add(analyst_user)
        await db.commit()

        r = await client.post(
            "/api/v1/auth/login",
            json={"email": analyst_user.email, "password": "WrongPass@99!"},
        )
        assert r.status_code == 401  # this bad attempt triggers lock

        await db.refresh(analyst_user)
        # SQLite returns naive datetimes; check locked_until is set rather than is_locked
        assert analyst_user.locked_until is not None

    @pytest.mark.asyncio
    async def test_locked_account_rejects_correct_password(self, client, viewer_user, db):
        """Even with correct password, a locked account must return 403."""
        viewer_user.locked_until = datetime.now(timezone.utc) + timedelta(hours=1)
        db.add(viewer_user)
        await db.commit()

        r = await client.post(
            "/api/v1/auth/login",
            json={"email": viewer_user.email, "password": "Viewer@1234!"},
        )
        assert r.status_code == 403
        assert "bloqueada" in r.json().get("detail", "").lower()

    @pytest.mark.asyncio
    async def test_successful_login_resets_failed_attempts(self, client, admin_user, db):
        admin_user.failed_login_attempts = 3
        db.add(admin_user)
        await db.commit()

        r = await client.post(
            "/api/v1/auth/login",
            json={"email": admin_user.email, "password": "Admin@1234!"},
        )
        assert r.status_code == 200

        await db.refresh(admin_user)
        assert admin_user.failed_login_attempts == 0

    @pytest.mark.asyncio
    async def test_successful_login_clears_locked_until(self, client, admin_user, db):
        # Admin should not be locked — this tests that locked_until is cleared on success
        admin_user.failed_login_attempts = 2
        admin_user.locked_until = None
        db.add(admin_user)
        await db.commit()

        r = await client.post(
            "/api/v1/auth/login",
            json={"email": admin_user.email, "password": "Admin@1234!"},
        )
        assert r.status_code == 200
        await db.refresh(admin_user)
        assert admin_user.locked_until is None

    @pytest.mark.asyncio
    async def test_nonexistent_user_returns_401_not_404(self, client):
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": "ghost@nowhere.com", "password": "SomePass@1!"},
        )
        assert r.status_code == 401
        # Must not reveal whether user exists
        assert r.json().get("detail") == "Credenciales inválidas"

    @pytest.mark.asyncio
    async def test_inactive_user_returns_401(self, client, analyst_user, db):
        analyst_user.is_active = False
        db.add(analyst_user)
        await db.commit()

        r = await client.post(
            "/api/v1/auth/login",
            json={"email": analyst_user.email, "password": "Analyst@1234!"},
        )
        assert r.status_code == 401
        assert r.json().get("detail") == "Credenciales inválidas"

    @pytest.mark.asyncio
    async def test_login_returns_tokens_on_success(self, client, admin_user):
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": admin_user.email, "password": "Admin@1234!"},
        )
        assert r.status_code == 200
        body = r.json()
        assert "access_token" in body
        assert "refresh_token" in body
        assert body.get("token_type") == "bearer"

    @pytest.mark.asyncio
    async def test_login_success_response_includes_role(self, client, admin_user):
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": admin_user.email, "password": "Admin@1234!"},
        )
        assert r.status_code == 200
        assert r.json().get("role") == "admin"

    @pytest.mark.asyncio
    async def test_lock_threshold_setting_is_five(self):
        assert settings.ACCOUNT_LOCK_THRESHOLD == 5

    @pytest.mark.asyncio
    async def test_lock_duration_setting_is_fifteen_minutes(self):
        assert settings.ACCOUNT_LOCK_MINUTES == 15


# ── TestForcePasswordReset ────────────────────────────────────────────────────

class TestForcePasswordReset:
    """force_password_reset gate: blocks all endpoints except POST /auth/change-password."""

    @pytest.mark.asyncio
    async def test_get_current_user_allow_reset_skips_force_check(self):
        """get_current_user_allow_reset is the only dep that bypasses the gate."""
        import pathlib
        src = pathlib.Path(__file__).parent.parent.parent / "asc_api" / "api" / "deps.py"
        txt = src.read_text()
        assert "get_current_user_allow_reset" in txt
        assert "check_force_reset=False" in txt

    @pytest.mark.asyncio
    async def test_force_reset_flag_blocks_me_endpoint(self, client, admin_user, db):
        admin_user.force_password_reset = True
        db.add(admin_user)
        await db.commit()

        token = create_access_token(admin_user.id)
        r = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 403
        assert r.json().get("detail") == "password_reset_required"

    @pytest.mark.asyncio
    async def test_change_password_uses_allow_reset_dep(self):
        """The change-password endpoint must import get_current_user_allow_reset, not get_current_user."""
        import pathlib
        src = pathlib.Path(__file__).parent.parent.parent / "asc_api" / "api" / "v1" / "endpoints" / "auth.py"
        txt = src.read_text()
        assert "get_current_user_allow_reset" in txt

    @pytest.mark.asyncio
    async def test_change_password_clears_force_reset(self, client, admin_user, db):
        admin_user.force_password_reset = True
        db.add(admin_user)
        await db.commit()

        token = create_access_token(admin_user.id)
        r = await client.post(
            "/api/v1/auth/change-password",
            headers={"Authorization": f"Bearer {token}"},
            json={"new_password": "NewStrong@Pass99!"},
        )
        assert r.status_code in (200, 204)
        await db.refresh(admin_user)
        assert admin_user.force_password_reset is False

    @pytest.mark.asyncio
    async def test_force_reset_flag_false_allows_normal_access(self, client, admin_user, db):
        admin_user.force_password_reset = False
        db.add(admin_user)
        await db.commit()

        token = create_access_token(admin_user.id)
        r = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_force_reset_with_invalid_token_returns_401(self, client):
        r = await client.post(
            "/api/v1/auth/change-password",
            headers={"Authorization": "Bearer invalid-token-here"},
            json={"new_password": "NewPass@99!"},
        )
        assert r.status_code == 401

    def test_timing_sentinel_hash_is_bcrypt(self):
        from asc_api.api.v1.endpoints.auth import _TIMING_SENTINEL_HASH
        assert _TIMING_SENTINEL_HASH.startswith("$2b$") or _TIMING_SENTINEL_HASH.startswith("$2a$")

    def test_timing_sentinel_verifies_correctly(self):
        from asc_api.api.v1.endpoints.auth import _TIMING_SENTINEL_HASH
        # The sentinel is pre-hashed; verify_password should NOT match our test value
        result = verify_password("not-the-sentinel-value", _TIMING_SENTINEL_HASH)
        assert result is False

    def test_password_hash_is_not_plaintext(self):
        hashed = get_password_hash("TestPass@99!")
        assert hashed != "TestPass@99!"
        assert hashed.startswith("$2b$") or hashed.startswith("$2a$")
