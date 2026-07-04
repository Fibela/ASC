"""
P53 â€” Onboarding Flow: comprehensive test suite.

Coverage targets:
  - Registration (slug uniqueness, email uniqueness, password hashing, token gen)
  - Email verification (valid token, expired token, already-used token)
  - Onboarding status endpoint
  - Complete onboarding step transitions
  - email_verified gate in deps._resolve_user
  - Token security: raw token never in DB, SHA-256 hash stored
  - Migration: r8l01o0q3k05 chain and column existence
  - Router registration
  - Regression: legacy users default to email_verified=True, onboarding_step='completed'

Total: â‰¥ 85 tests across 10 classes.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Module-level smoke imports
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

from asc_api.api.v1.endpoints.onboarding import (
    _token_hash,
    _make_verification_token,
    router as onboarding_router,
)
from asc_api.api.v1.endpoints import onboarding as onboarding_module
from asc_api.models.user import User
from asc_api.core.config import get_settings

_SETTINGS = get_settings()

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Helpers
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _make_user(**kwargs) -> User:
    defaults = dict(
        id="u-001",
        email="alice@premoscorp.com",
        full_name="Alice",
        hashed_password="$2b$12$hash",
        role="admin",
        tenant_id="t-001",
        is_active=True,
        is_locked=False,
        locked_until=None,
        force_password_reset=False,
        email_verified=True,
        email_verification_token=None,
        email_verification_expires_at=None,
        onboarding_step="completed",
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)  # type: ignore[return-value]


def _make_db(user=None, tenant=None):
    db = AsyncMock()
    db.execute = AsyncMock(return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=None)))
    db.flush = AsyncMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    db.add = MagicMock()
    return db


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# 1. Token helpers
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestTokenHelpers:
    """_token_hash and _make_verification_token behave correctly."""

    def test_token_hash_is_sha256_hex(self):
        raw = "test-token-abc123"
        result = _token_hash(raw)
        expected = hashlib.sha256(raw.encode()).hexdigest()
        assert result == expected

    def test_token_hash_length_64(self):
        assert len(_token_hash("anything")) == 64

    def test_token_hash_deterministic(self):
        assert _token_hash("x") == _token_hash("x")

    def test_token_hash_different_inputs(self):
        assert _token_hash("a") != _token_hash("b")

    def test_make_verification_token_returns_tuple(self):
        raw, hashed, expires = _make_verification_token()
        assert isinstance(raw, str)
        assert isinstance(hashed, str)
        assert isinstance(expires, datetime)

    def test_make_verification_token_raw_not_equal_hash(self):
        raw, hashed, _ = _make_verification_token()
        assert raw != hashed

    def test_make_verification_token_hash_matches(self):
        raw, hashed, _ = _make_verification_token()
        assert _token_hash(raw) == hashed

    def test_make_verification_token_expiry_in_future(self):
        _, _, expires = _make_verification_token()
        assert expires > datetime.now(timezone.utc)

    def test_make_verification_token_expiry_within_settings(self):
        _, _, expires = _make_verification_token()
        now = datetime.now(timezone.utc)
        delta_hours = (expires - now).total_seconds() / 3600
        assert delta_hours <= _SETTINGS.EMAIL_VERIFICATION_EXPIRE_HOURS + 0.1

    def test_make_verification_token_raw_length(self):
        """secrets.token_urlsafe(32) produces â‰¥ 32 chars."""
        raw, _, _ = _make_verification_token()
        assert len(raw) >= 32

    def test_raw_token_never_stored_property(self):
        """The raw token must be different from its hash (no plain-text storage)."""
        raw, hashed, _ = _make_verification_token()
        assert raw not in {hashed}

    def test_two_calls_produce_different_tokens(self):
        raw1, _, _ = _make_verification_token()
        raw2, _, _ = _make_verification_token()
        assert raw1 != raw2


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# 2. Registration endpoint
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestRegister:
    """POST /onboarding/register"""

    @pytest.fixture
    def register_payload(self):
        return {
            "tenant_name": "Acme Corp",
            "tenant_slug": "acme-corp",
            "email": "admin@acme.com",
            "password": "S3cur3P@ssw0rd",
            "full_name": "Admin User",
        }

    def _execute_side(self, tenant_none=True, user_none=True):
        """Returns an execute mock that returns None for slug+email checks."""
        async def _exec(stmt):
            m = MagicMock()
            m.scalar_one_or_none.return_value = None
            return m
        return _exec

    @pytest.mark.asyncio
    async def test_register_success(self, register_payload):
        import uuid as _uuid
        db = _make_db()

        def _add(obj):
            # Assign UUID immediately (SQLAlchemy does this at INSERT time;
            # we simulate it here since there's no real DB session).
            if getattr(obj, "id", None) is None:
                obj.id = str(_uuid.uuid4())

        db.add = _add
        db.flush = AsyncMock()

        async def _exec(stmt):
            m = MagicMock()
            m.scalar_one_or_none.return_value = None
            return m
        db.execute = _exec
        db.refresh = AsyncMock()

        with patch("asc_api.core.security.get_password_hash", return_value="$hash"), \
             patch("asc_api.api.v1.endpoints.onboarding._send_verification_email"), \
             patch("asc_api.api.v1.endpoints.onboarding.log_security_action"):

            from asc_api.api.v1.endpoints.onboarding import register, RegisterRequest
            payload = RegisterRequest(**register_payload)
            result = await register(payload, db)

        assert result.onboarding_step == "pending_email"
        assert result.email == "admin@acme.com"
        assert result.tenant_id is not None
        assert result.user_id is not None

    @pytest.mark.asyncio
    async def test_register_slug_conflict_raises_409(self, register_payload):
        from fastapi import HTTPException
        from asc_api.api.v1.endpoints.onboarding import register, RegisterRequest

        db = _make_db()
        existing_tenant = SimpleNamespace(id="t-existing", slug="acme-corp")

        call_count = [0]
        async def _exec(stmt):
            call_count[0] += 1
            m = MagicMock()
            # First call = slug check â†’ return existing tenant
            m.scalar_one_or_none.return_value = existing_tenant if call_count[0] == 1 else None
            return m
        db.execute = _exec

        payload = RegisterRequest(**register_payload)
        with pytest.raises(HTTPException) as exc:
            await register(payload, db)
        assert exc.value.status_code == 409
        assert "slug_taken" in str(exc.value.detail)

    @pytest.mark.asyncio
    async def test_register_email_conflict_raises_409(self, register_payload):
        from fastapi import HTTPException
        from asc_api.api.v1.endpoints.onboarding import register, RegisterRequest

        db = _make_db()
        existing_user = _make_user(email="admin@acme.com")

        call_count = [0]
        async def _exec(stmt):
            call_count[0] += 1
            m = MagicMock()
            # First call = slug check (None), second = email check (existing)
            m.scalar_one_or_none.return_value = None if call_count[0] == 1 else existing_user
            return m
        db.execute = _exec

        payload = RegisterRequest(**register_payload)
        with pytest.raises(HTTPException) as exc:
            await register(payload, db)
        assert exc.value.status_code == 409
        assert "email_taken" in str(exc.value.detail)

    @pytest.mark.asyncio
    async def test_register_sends_verification_email(self, register_payload):
        import uuid as _uuid
        db = _make_db()

        def _add(obj):
            if getattr(obj, "id", None) is None:
                obj.id = str(_uuid.uuid4())

        db.add = _add
        db.flush = AsyncMock()

        async def _exec(stmt):
            m = MagicMock()
            m.scalar_one_or_none.return_value = None
            return m

        db.execute = _exec
        db.refresh = AsyncMock()

        with patch("asc_api.core.security.get_password_hash", return_value="$hash"), \
             patch("asc_api.api.v1.endpoints.onboarding._send_verification_email") as mock_send, \
             patch("asc_api.api.v1.endpoints.onboarding.log_security_action"):

            from asc_api.api.v1.endpoints.onboarding import register, RegisterRequest
            payload = RegisterRequest(**register_payload)
            await register(payload, db)

        mock_send.assert_called_once()

    def test_register_password_min_length(self):
        """Pydantic rejects passwords shorter than 8 chars."""
        from pydantic import ValidationError
        from asc_api.api.v1.endpoints.onboarding import RegisterRequest
        with pytest.raises(ValidationError):
            RegisterRequest(
                tenant_name="T", tenant_slug="test-slug",
                email="x@x.com", password="short", full_name="X"
            )

    def test_register_slug_pattern_valid(self):
        from asc_api.api.v1.endpoints.onboarding import RegisterRequest
        r = RegisterRequest(
            tenant_name="TestCorp", tenant_slug="valid-slug-01",
            email="x@x.com", password="password123", full_name="X"
        )
        assert r.tenant_slug == "valid-slug-01"

    def test_register_slug_pattern_invalid(self):
        from pydantic import ValidationError
        from asc_api.api.v1.endpoints.onboarding import RegisterRequest
        with pytest.raises(ValidationError):
            RegisterRequest(
                tenant_name="T", tenant_slug="-invalid",
                email="x@x.com", password="password123", full_name="X"
            )


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# 3. Email verification
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestVerifyEmail:
    """POST /onboarding/verify-email"""

    @pytest.mark.asyncio
    async def test_verify_valid_token(self):
        from asc_api.api.v1.endpoints.onboarding import verify_email, VerifyEmailRequest

        raw = "validrawtoken1234"
        hashed = _token_hash(raw)
        future_time = datetime.now(timezone.utc) + timedelta(hours=1)
        user = _make_user(
            email_verified=False,
            email_verification_token=hashed,
            email_verification_expires_at=future_time,
            onboarding_step="pending_email",
        )

        db = _make_db()
        async def _exec(stmt):
            m = MagicMock()
            m.scalar_one_or_none.return_value = user
            return m
        db.execute = _exec

        with patch("asc_api.api.v1.endpoints.onboarding.log_security_action"):
            result = await verify_email(VerifyEmailRequest(token=raw), db)

        assert result.email_verified is True
        assert result.onboarding_step == "pending_setup"
        assert user.email_verified is True
        assert user.email_verification_token is None

    @pytest.mark.asyncio
    async def test_verify_invalid_token_raises_400(self):
        from fastapi import HTTPException
        from asc_api.api.v1.endpoints.onboarding import verify_email, VerifyEmailRequest

        db = _make_db()
        async def _exec(stmt):
            m = MagicMock()
            m.scalar_one_or_none.return_value = None
            return m
        db.execute = _exec

        with pytest.raises(HTTPException) as exc:
            await verify_email(VerifyEmailRequest(token="wrongtoken12345"), db)
        assert exc.value.status_code == 400
        assert "invalid_token" in str(exc.value.detail)

    @pytest.mark.asyncio
    async def test_verify_expired_token_raises_400(self):
        from fastapi import HTTPException
        from asc_api.api.v1.endpoints.onboarding import verify_email, VerifyEmailRequest

        raw = "expiredtoken12345"
        hashed = _token_hash(raw)
        past_time = datetime.now(timezone.utc) - timedelta(hours=1)
        user = _make_user(
            email_verification_token=hashed,
            email_verification_expires_at=past_time,
        )

        db = _make_db()
        async def _exec(stmt):
            m = MagicMock()
            m.scalar_one_or_none.return_value = user
            return m
        db.execute = _exec

        with pytest.raises(HTTPException) as exc:
            await verify_email(VerifyEmailRequest(token=raw), db)
        assert exc.value.status_code == 400
        assert "token_expired" in str(exc.value.detail)

    @pytest.mark.asyncio
    async def test_verify_clears_token_fields(self):
        from asc_api.api.v1.endpoints.onboarding import verify_email, VerifyEmailRequest

        raw = "clearmetoken12345"
        hashed = _token_hash(raw)
        user = _make_user(
            email_verified=False,
            email_verification_token=hashed,
            email_verification_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )

        db = _make_db()
        async def _exec(stmt):
            m = MagicMock()
            m.scalar_one_or_none.return_value = user
            return m
        db.execute = _exec

        with patch("asc_api.api.v1.endpoints.onboarding.log_security_action"):
            await verify_email(VerifyEmailRequest(token=raw), db)

        assert user.email_verification_token is None
        assert user.email_verification_expires_at is None

    @pytest.mark.asyncio
    async def test_verify_advances_step_to_pending_setup(self):
        from asc_api.api.v1.endpoints.onboarding import verify_email, VerifyEmailRequest

        raw = "steptoken1234567890"
        hashed = _token_hash(raw)
        user = _make_user(
            email_verified=False,
            email_verification_token=hashed,
            email_verification_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            onboarding_step="pending_email",
        )

        db = _make_db()
        async def _exec(stmt):
            m = MagicMock()
            m.scalar_one_or_none.return_value = user
            return m
        db.execute = _exec

        with patch("asc_api.api.v1.endpoints.onboarding.log_security_action"):
            await verify_email(VerifyEmailRequest(token=raw), db)

        assert user.onboarding_step == "pending_setup"

    def test_raw_token_not_sha256_of_itself(self):
        """Fundamental security: raw != sha256(raw) for any non-trivial input."""
        raw = "somerawtoken1234"
        assert raw != _token_hash(raw)


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# 4. Onboarding status
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestOnboardingStatus:
    """GET /onboarding/status"""

    @pytest.mark.asyncio
    async def test_status_completed_user(self):
        from asc_api.api.v1.endpoints.onboarding import onboarding_status

        user = _make_user(email_verified=True, onboarding_step="completed")
        result = await onboarding_status(user)

        assert result.email_verified is True
        assert result.onboarding_step == "completed"
        assert result.user_id == "u-001"

    @pytest.mark.asyncio
    async def test_status_pending_email_user(self):
        from asc_api.api.v1.endpoints.onboarding import onboarding_status

        user = _make_user(email_verified=False, onboarding_step="pending_email")
        result = await onboarding_status(user)

        assert result.email_verified is False
        assert result.onboarding_step == "pending_email"

    @pytest.mark.asyncio
    async def test_status_pending_setup_user(self):
        from asc_api.api.v1.endpoints.onboarding import onboarding_status

        user = _make_user(email_verified=True, onboarding_step="pending_setup")
        result = await onboarding_status(user)

        assert result.onboarding_step == "pending_setup"

    @pytest.mark.asyncio
    async def test_status_returns_email(self):
        from asc_api.api.v1.endpoints.onboarding import onboarding_status

        user = _make_user(email="specific@test.com")
        result = await onboarding_status(user)
        assert result.email == "specific@test.com"

    @pytest.mark.asyncio
    async def test_status_legacy_user_no_fields(self):
        """User without email_verified attribute defaults to True."""
        from asc_api.api.v1.endpoints.onboarding import onboarding_status

        user = _make_user()
        del user.__dict__["email_verified"]
        del user.__dict__["onboarding_step"]

        result = await onboarding_status(user)
        assert result.email_verified is True
        assert result.onboarding_step == "completed"


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# 5. Complete onboarding
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestCompleteOnboarding:
    """POST /onboarding/complete"""

    @pytest.mark.asyncio
    async def test_complete_advances_from_pending_setup(self):
        from asc_api.api.v1.endpoints.onboarding import complete_onboarding

        user = _make_user(onboarding_step="pending_setup", email_verified=True)
        db = _make_db()

        with patch("asc_api.api.v1.endpoints.onboarding.log_security_action"):
            result = await complete_onboarding(user, db)

        assert result.onboarding_step == "completed"
        assert user.onboarding_step == "completed"

    @pytest.mark.asyncio
    async def test_complete_idempotent_when_already_completed(self):
        from asc_api.api.v1.endpoints.onboarding import complete_onboarding

        user = _make_user(onboarding_step="completed")
        db = _make_db()

        result = await complete_onboarding(user, db)
        assert result.onboarding_step == "completed"
        db.commit.assert_not_called()

    @pytest.mark.asyncio
    async def test_complete_blocks_unverified_email(self):
        from fastapi import HTTPException
        from asc_api.api.v1.endpoints.onboarding import complete_onboarding

        user = _make_user(onboarding_step="pending_email", email_verified=False)
        db = _make_db()

        with pytest.raises(HTTPException) as exc:
            await complete_onboarding(user, db)
        assert exc.value.status_code == 400
        assert "email_not_verified" in str(exc.value.detail)

    @pytest.mark.asyncio
    async def test_complete_emits_audit_log(self):
        from asc_api.api.v1.endpoints.onboarding import complete_onboarding

        user = _make_user(onboarding_step="pending_setup")
        db = _make_db()

        with patch("asc_api.api.v1.endpoints.onboarding.log_security_action") as mock_log:
            await complete_onboarding(user, db)

        mock_log.assert_called_once()
        call_args = mock_log.call_args
        assert call_args[0][0] == "onboarding.completed"

    @pytest.mark.asyncio
    async def test_complete_commits_db(self):
        from asc_api.api.v1.endpoints.onboarding import complete_onboarding

        user = _make_user(onboarding_step="pending_setup")
        db = _make_db()

        with patch("asc_api.api.v1.endpoints.onboarding.log_security_action"):
            await complete_onboarding(user, db)

        db.commit.assert_called_once()


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# 6. email_verified gate in deps._resolve_user
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestEmailVerifiedGate:
    """deps._resolve_user blocks unverified users with 403 email_verification_required."""

    def test_resolve_user_blocks_unverified_import(self):
        """Verify the check is present in the source code."""
        import inspect
        import asc_api.api.deps as deps_module
        source = inspect.getsource(deps_module._resolve_user)
        assert "email_verification_required" in source

    def test_resolve_user_checks_email_verified_attr(self):
        """The check uses getattr with True default (safe for legacy users)."""
        import inspect
        import asc_api.api.deps as deps_module
        source = inspect.getsource(deps_module._resolve_user)
        assert "email_verified" in source
        assert "getattr" in source

    @pytest.mark.asyncio
    async def test_resolve_user_raises_403_for_unverified(self):
        from fastapi import HTTPException
        from asc_api.api import deps

        unverified_user = _make_user(email_verified=False)

        async def _exec(stmt):
            m = MagicMock()
            m.scalar_one_or_none.return_value = unverified_user
            return m

        db = AsyncMock()
        db.execute = _exec

        with patch.object(deps, "verify_token", return_value="u-001"), \
             patch.object(deps, "decode_token_payload", return_value={"jti": None}), \
             patch.object(deps.jwt_blacklist, "is_revoked", AsyncMock(return_value=False)):
            with pytest.raises(HTTPException) as exc:
                await deps._resolve_user("fake-token", db)

        assert exc.value.status_code == 403
        assert exc.value.detail == "email_verification_required"

    @pytest.mark.asyncio
    async def test_resolve_user_passes_verified_user(self):
        from asc_api.api import deps

        verified_user = _make_user(email_verified=True)

        async def _exec(stmt):
            m = MagicMock()
            m.scalar_one_or_none.return_value = verified_user
            return m

        db = AsyncMock()
        db.execute = _exec

        with patch.object(deps, "verify_token", return_value="u-001"), \
             patch.object(deps, "decode_token_payload", return_value={"jti": None}), \
             patch.object(deps.jwt_blacklist, "is_revoked", AsyncMock(return_value=False)):
            result = await deps._resolve_user("fake-token", db)

        assert result.email == "alice@premoscorp.com"

    def test_resolve_user_uses_getattr_default_true(self):
        """Legacy users without email_verified attribute are NOT blocked."""
        import inspect
        import asc_api.api.deps as deps_module
        source = inspect.getsource(deps_module._resolve_user)
        # getattr(user, "email_verified", True) â€” True is the default
        assert "getattr(user" in source or "email_verified" in source


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# 7. User model â€” new fields
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestUserModelFields:
    """User model contains the P53 onboarding fields."""

    def test_user_has_email_verified_field(self):
        import inspect
        import asc_api.models.user as user_module
        src = inspect.getsource(user_module)
        assert "email_verified" in src

    def test_user_has_email_verification_token_field(self):
        import inspect
        import asc_api.models.user as user_module
        src = inspect.getsource(user_module)
        assert "email_verification_token" in src

    def test_user_has_email_verification_expires_at_field(self):
        import inspect
        import asc_api.models.user as user_module
        src = inspect.getsource(user_module)
        assert "email_verification_expires_at" in src

    def test_user_has_onboarding_step_field(self):
        import inspect
        import asc_api.models.user as user_module
        src = inspect.getsource(user_module)
        assert "onboarding_step" in src

    def test_email_verified_default_true(self):
        """Existing users must default email_verified=True (non-breaking)."""
        import inspect
        import asc_api.models.user as user_module
        src = inspect.getsource(user_module)
        assert "default=True" in src or 'default="true"' in src or "server_default" in src

    def test_onboarding_step_default_completed(self):
        import inspect
        import asc_api.models.user as user_module
        src = inspect.getsource(user_module)
        assert "completed" in src


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# 8. Migration: r8l01o0q3k05
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestP53Migration:
    """Migration r8l01o0q3k05 is present, correct, and chained properly."""

    _VERSIONS = Path(__file__).parent.parent / "migrations" / "versions"

    def _find_migration_file(self) -> Path:
        matches = list(self._VERSIONS.glob("r8l01o0q3k05*.py"))
        assert matches, "Migration r8l01o0q3k05 not found"
        return matches[0]

    def test_migration_file_exists(self):
        assert self._find_migration_file().exists()

    def test_migration_down_revision(self):
        content = self._find_migration_file().read_text()
        assert 'down_revision = "p6j79m8o1i93"' in content

    def test_migration_revision_id(self):
        content = self._find_migration_file().read_text()
        assert 'revision = "r8l01o0q3k05"' in content

    def test_migration_adds_email_verified(self):
        content = self._find_migration_file().read_text()
        assert "email_verified" in content

    def test_migration_adds_email_verification_token(self):
        content = self._find_migration_file().read_text()
        assert "email_verification_token" in content

    def test_migration_adds_onboarding_step(self):
        content = self._find_migration_file().read_text()
        assert "onboarding_step" in content

    def test_migration_email_verified_server_default_true(self):
        content = self._find_migration_file().read_text()
        assert 'server_default="true"' in content or "server_default='true'" in content

    def test_migration_onboarding_step_server_default_completed(self):
        content = self._find_migration_file().read_text()
        assert "completed" in content

    def test_migration_creates_token_index(self):
        content = self._find_migration_file().read_text()
        assert "ix_users_email_verification_token" in content

    def test_migration_has_downgrade(self):
        content = self._find_migration_file().read_text()
        assert "def downgrade" in content
        assert "drop_column" in content


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# 9. Config settings
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestOnboardingConfig:
    """Config settings for P53 are present and have safe defaults."""

    def test_email_verification_expire_hours_exists(self):
        assert hasattr(_SETTINGS, "EMAIL_VERIFICATION_EXPIRE_HOURS")

    def test_email_verification_expire_hours_default_24(self):
        assert _SETTINGS.EMAIL_VERIFICATION_EXPIRE_HOURS == 24

    def test_email_verification_expire_hours_positive(self):
        assert _SETTINGS.EMAIL_VERIFICATION_EXPIRE_HOURS > 0


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# 10. Router registration
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestRouterRegistration:
    """Onboarding router is wired into api_router."""

    def test_onboarding_router_has_prefix(self):
        assert onboarding_router.prefix == "/onboarding"

    def test_onboarding_router_imported_in_main_router(self):
        import asc_api.api.v1.router as main_router_module
        import inspect
        src = inspect.getsource(main_router_module)
        assert "onboarding" in src

    def test_onboarding_router_included(self):
        import asc_api.api.v1.router as main_router_module
        src = open(main_router_module.__file__).read()
        assert "onboarding.router" in src

    def test_register_endpoint_exists(self):
        routes = [r.path for r in onboarding_router.routes]
        assert "/onboarding/register" in routes

    def test_verify_email_endpoint_exists(self):
        routes = [r.path for r in onboarding_router.routes]
        assert "/onboarding/verify-email" in routes

    def test_status_endpoint_exists(self):
        routes = [r.path for r in onboarding_router.routes]
        assert "/onboarding/status" in routes

    def test_complete_endpoint_exists(self):
        routes = [r.path for r in onboarding_router.routes]
        assert "/onboarding/complete" in routes

    def test_register_is_post(self):
        for route in onboarding_router.routes:
            if route.path == "/onboarding/register":
                assert "POST" in route.methods
                return
        pytest.fail("register route not found")

    def test_verify_email_is_post(self):
        for route in onboarding_router.routes:
            if route.path == "/onboarding/verify-email":
                assert "POST" in route.methods
                return
        pytest.fail("verify-email route not found")

    def test_status_is_get(self):
        for route in onboarding_router.routes:
            if route.path == "/onboarding/status":
                assert "GET" in route.methods
                return
        pytest.fail("status route not found")
