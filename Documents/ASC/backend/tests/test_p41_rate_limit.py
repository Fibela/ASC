"""
P41 â€” Rate Limiting per API Key â€” Test Suite
=============================================
Tests: sliding window unit, middleware ASGI, status/reset endpoints,
       security invariants (breach audit log, fail-open, no secret leakage),
       regression (JWT paths unaffected, existing endpoints intact).

Pattern: AsyncClient + ASGITransport (bypasses app lifespan â†’ no real DB/Redis).
Rate limiter is mocked or exercised in memory mode for deterministic results.

Security scan coverage:
  â€¢ Raw API key secret never appears in rate limit keys, logs, or error responses
  â€¢ Breach logged to asc.audit channel (Ledger Premos)
  â€¢ Malformed key headers are forwarded to auth dep unchanged (no rate-limit slot consumed)
  â€¢ Fail-open: Redis error â†’ request allowed, not blocked
  â€¢ JWT-authenticated requests are completely bypassed by rate limit middleware
"""

import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from asc_api.core.api_key_rate_limit import ApiKeyRateLimiter, RateLimitResult, api_key_limiter
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


def _make_api_key(user_id: str, prefix: str = "aabbccdd"):
    k = MagicMock()
    k.id = str(uuid.uuid4())
    k.name = "Test Key"
    k.key_prefix = prefix
    k.key_hash = "a" * 64
    k.user_id = user_id
    k.scopes = ["read"]
    k.is_active = True
    k.expires_at = None
    k.last_used_at = None
    k.created_at = datetime.now(timezone.utc)
    return k


def _jwt(user_id: str) -> str:
    return create_access_token(user_id)


def _db_override(scalar_result=None, scalars_result=None):
    db = MagicMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    db.delete = AsyncMock()
    db.add = MagicMock()
    db.close = AsyncMock()

    exec_result = MagicMock()
    exec_result.scalar_one_or_none.return_value = scalar_result
    exec_result.scalars.return_value.all.return_value = scalars_result or []
    db.execute = AsyncMock(return_value=exec_result)

    async def override():
        yield db

    return override, db


# â”€â”€ Class 1: Unit tests â€” ApiKeyRateLimiter (memory mode) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestApiKeyRateLimiterUnit:
    """Unit tests for the core sliding window algorithm using in-memory backend."""

    def _fresh(self) -> ApiKeyRateLimiter:
        """Return a clean limiter instance in memory mode (no Redis)."""
        return ApiKeyRateLimiter()

    @pytest.mark.asyncio
    async def test_first_request_is_allowed(self):
        limiter = self._fresh()
        result = await limiter.check("aabbccdd", limit=10, window_seconds=60)
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_remaining_decrements_on_each_request(self):
        limiter = self._fresh()
        r1 = await limiter.check("aabbccdd", limit=5, window_seconds=60)
        r2 = await limiter.check("aabbccdd", limit=5, window_seconds=60)
        assert r1.remaining > r2.remaining

    @pytest.mark.asyncio
    async def test_exceeding_limit_blocks_request(self):
        limiter = self._fresh()
        prefix = "tst00001"
        for _ in range(3):
            await limiter.check(prefix, limit=3, window_seconds=60)
        # 4th request exceeds limit=3
        result = await limiter.check(prefix, limit=3, window_seconds=60)
        assert result.allowed is False
        assert result.remaining == 0
        assert result.retry_after > 0

    @pytest.mark.asyncio
    async def test_different_prefixes_are_isolated(self):
        limiter = self._fresh()
        for _ in range(3):
            await limiter.check("prefix01", limit=3, window_seconds=60)
        # prefix02 should be unaffected
        result = await limiter.check("prefix02", limit=3, window_seconds=60)
        assert result.allowed is True
        assert result.remaining == 2  # 1 used (this call)

    @pytest.mark.asyncio
    async def test_get_status_returns_zero_for_unknown_prefix(self):
        limiter = self._fresh()
        count = await limiter.get_status("unknwn01", window_seconds=60)
        assert count == 0

    @pytest.mark.asyncio
    async def test_get_status_reflects_check_calls(self):
        limiter = self._fresh()
        prefix = "stat0001"
        await limiter.check(prefix, limit=100, window_seconds=60)
        await limiter.check(prefix, limit=100, window_seconds=60)
        count = await limiter.get_status(prefix, window_seconds=60)
        assert count == 2

    @pytest.mark.asyncio
    async def test_reset_for_prefix_clears_state(self):
        limiter = self._fresh()
        prefix = "rst00001"
        for _ in range(5):
            await limiter.check(prefix, limit=10, window_seconds=60)
        assert await limiter.get_status(prefix, 60) == 5
        limiter.reset_for_prefix(prefix)
        assert await limiter.get_status(prefix, 60) == 0

    @pytest.mark.asyncio
    async def test_reset_for_prefix_all_also_calls_memory_reset(self):
        limiter = self._fresh()
        prefix = "rst00002"
        for _ in range(3):
            await limiter.check(prefix, limit=10, window_seconds=60)
        assert await limiter.get_status(prefix, 60) == 3
        # reset_for_prefix_all should clear memory even in memory mode
        await limiter.reset_for_prefix_all(prefix)
        assert await limiter.get_status(prefix, 60) == 0

    @pytest.mark.asyncio
    async def test_result_fields_are_populated(self):
        limiter = self._fresh()
        result = await limiter.check("fields01", limit=10, window_seconds=60)
        assert isinstance(result, RateLimitResult)
        assert result.limit == 10
        assert result.reset_at > 0
        assert result.retry_after == 0  # allowed â€” no retry needed

    @pytest.mark.asyncio
    async def test_mode_defaults_to_memory(self):
        limiter = self._fresh()
        assert limiter.mode == "memory"

    @pytest.mark.asyncio
    async def test_connect_with_empty_url_stays_memory(self):
        limiter = self._fresh()
        mode = await limiter.connect("")
        assert mode == "memory"
        assert limiter.mode == "memory"


# â”€â”€ Class 2: Middleware tests â€” ApiKeyRateLimitMiddleware â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestApiKeyRateLimitMiddleware:
    """Tests for the Starlette middleware via full ASGI stack."""

    @pytest.mark.asyncio
    async def test_request_without_api_key_passes_through(self):
        """JWT-authenticated requests must not be rate-limited at all."""
        user = _make_user("analyst")
        override, _ = _db_override()
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)
        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.get("/api/v1/health/liveness", headers={"Authorization": f"Bearer {token}"})
        app.dependency_overrides.clear()
        # No rate limit headers on non-API-key requests
        assert "X-RateLimit-Limit-Minute" not in r.headers

    @pytest.mark.asyncio
    async def test_valid_api_key_request_sets_rate_limit_headers(self):
        """Allowed API-key requests receive X-RateLimit-* headers."""
        from asc_api.core.middleware import ApiKeyRateLimitMiddleware

        allowed_result = RateLimitResult(allowed=True, limit=60, remaining=59, reset_at=9999999999)

        with patch.object(api_key_limiter, "check", AsyncMock(return_value=allowed_result)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.get(
                    "/api/v1/health/liveness",
                    headers={"X-API-Key": "asc_aabbccdd_" + "x" * 40},
                )
        assert "X-RateLimit-Limit-Minute" in r.headers
        assert "X-RateLimit-Limit-Hour" in r.headers
        assert "X-RateLimit-Remaining-Minute" in r.headers
        assert "X-RateLimit-Reset" in r.headers

    @pytest.mark.asyncio
    async def test_exceeded_rate_limit_returns_429(self):
        """When the minute window is full, middleware returns 429 before auth."""
        blocked_result = RateLimitResult(
            allowed=False, limit=60, remaining=0, reset_at=9999999999, retry_after=30
        )

        with patch.object(api_key_limiter, "check", AsyncMock(return_value=blocked_result)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.get(
                    "/api/v1/health/liveness",
                    headers={"X-API-Key": "asc_aabbccdd_" + "x" * 40},
                )
        assert r.status_code == 429

    @pytest.mark.asyncio
    async def test_429_response_contains_retry_after_header(self):
        blocked_result = RateLimitResult(
            allowed=False, limit=60, remaining=0, reset_at=9999999999, retry_after=45
        )
        with patch.object(api_key_limiter, "check", AsyncMock(return_value=blocked_result)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.get(
                    "/api/v1/health/liveness",
                    headers={"X-API-Key": "asc_aabbccdd_" + "x" * 40},
                )
        assert "Retry-After" in r.headers
        assert int(r.headers["Retry-After"]) == 45

    @pytest.mark.asyncio
    async def test_429_response_body_contains_retry_after_seconds(self):
        blocked_result = RateLimitResult(
            allowed=False, limit=60, remaining=0, reset_at=9999999999, retry_after=30
        )
        with patch.object(api_key_limiter, "check", AsyncMock(return_value=blocked_result)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.get(
                    "/api/v1/health/liveness",
                    headers={"X-API-Key": "asc_aabbccdd_" + "x" * 40},
                )
        body = r.json()
        assert "retry_after" in body
        assert body["retry_after"] == 30

    @pytest.mark.asyncio
    async def test_malformed_key_skips_rate_limiting(self):
        """A key that doesn't match asc_{8chars}_{rest} format is not rate-limited."""
        with patch.object(api_key_limiter, "check", AsyncMock()) as mock_check:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                await c.get(
                    "/api/v1/health/liveness",
                    headers={"X-API-Key": "not-a-valid-key"},
                )
        mock_check.assert_not_called()

    @pytest.mark.asyncio
    async def test_health_endpoint_without_api_key_is_not_rate_limited(self):
        """Health endpoint without any auth header passes through without rate limiting."""
        with patch.object(api_key_limiter, "check", AsyncMock()) as mock_check:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.get("/health")
        mock_check.assert_not_called()
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_both_windows_are_checked(self):
        """Both minute and hour windows must return allowed=True for request to proceed."""
        allowed = RateLimitResult(allowed=True, limit=60, remaining=50, reset_at=9999999999)
        blocked = RateLimitResult(allowed=False, limit=1000, remaining=0, reset_at=9999999999, retry_after=10)

        # minute OK but hour blocked â†’ 429
        with patch.object(api_key_limiter, "check", AsyncMock(side_effect=[allowed, blocked])):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.get(
                    "/api/v1/health/liveness",
                    headers={"X-API-Key": "asc_aabbccdd_" + "x" * 40},
                )
        assert r.status_code == 429


# â”€â”€ Class 3: Rate limit status endpoint â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestRateLimitStatusEndpoint:
    BASE = "/api/v1/api-keys"

    @pytest.mark.asyncio
    async def test_owner_can_see_own_key_status(self):
        user = _make_user("analyst")
        key = _make_api_key(user.id, prefix="aabbccdd")
        override, _ = _db_override(scalar_result=key)
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)), \
             patch.object(api_key_limiter, "get_status", AsyncMock(return_value=5)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.get(
                    f"{self.BASE}/{key.id}/rate-limit-status",
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()
        assert r.status_code == 200
        body = r.json()
        assert body["key_prefix"] == "aabbccdd"
        assert "limit_per_minute" in body
        assert "limit_per_hour" in body
        assert "count_minute" in body
        assert "remaining_minute" in body

    @pytest.mark.asyncio
    async def test_other_user_cannot_see_key_status(self):
        owner = _make_user("analyst")
        other = _make_user("analyst")
        key = _make_api_key(owner.id)
        override, _ = _db_override(scalar_result=key)
        app.dependency_overrides[get_db] = override
        token = _jwt(other.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=other)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.get(
                    f"{self.BASE}/{key.id}/rate-limit-status",
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()
        assert r.status_code == 403

    @pytest.mark.asyncio
    async def test_admin_can_see_any_key_status(self):
        admin = _make_user("admin")
        owner = _make_user("analyst")
        key = _make_api_key(owner.id)
        override, _ = _db_override(scalar_result=key)
        app.dependency_overrides[get_db] = override
        token = _jwt(admin.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=admin)), \
             patch.object(api_key_limiter, "get_status", AsyncMock(return_value=0)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.get(
                    f"{self.BASE}/{key.id}/rate-limit-status",
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_no_auth_returns_401(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get(f"{self.BASE}/some-key-id/rate-limit-status")
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_status_shows_backend_mode(self):
        user = _make_user("analyst")
        key = _make_api_key(user.id)
        override, _ = _db_override(scalar_result=key)
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)), \
             patch.object(api_key_limiter, "get_status", AsyncMock(return_value=0)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.get(
                    f"{self.BASE}/{key.id}/rate-limit-status",
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()
        assert r.status_code == 200
        assert r.json()["backend"] in ("redis", "memory")


# â”€â”€ Class 4: Rate limit reset endpoint (admin-only) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestRateLimitResetEndpoint:
    BASE = "/api/v1/api-keys"

    @pytest.mark.asyncio
    async def test_admin_can_reset_rate_limit(self):
        admin = _make_user("admin")
        key = _make_api_key(admin.id)
        override, _ = _db_override(scalar_result=key)
        app.dependency_overrides[get_db] = override
        token = _jwt(admin.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=admin)), \
             patch.object(api_key_limiter, "reset_for_prefix_all", AsyncMock()) as mock_reset:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.post(
                    f"{self.BASE}/{key.id}/rate-limit-reset",
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()
        assert r.status_code == 204
        mock_reset.assert_called_once_with(key.key_prefix)

    @pytest.mark.asyncio
    async def test_analyst_cannot_reset_rate_limit(self):
        analyst = _make_user("analyst")
        key = _make_api_key(analyst.id)
        override, _ = _db_override(scalar_result=key)
        app.dependency_overrides[get_db] = override
        token = _jwt(analyst.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=analyst)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.post(
                    f"{self.BASE}/{key.id}/rate-limit-reset",
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()
        assert r.status_code == 403

    @pytest.mark.asyncio
    async def test_no_auth_returns_401_on_reset(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.post(f"{self.BASE}/some-key-id/rate-limit-reset")
        assert r.status_code == 401


# â”€â”€ Class 5: Security invariants â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestRateLimitSecurity:
    """Security properties that must hold regardless of implementation details."""

    @pytest.mark.asyncio
    async def test_rate_limit_breach_emits_audit_log(self):
        """Ledger Premos â€” every 429 must generate a security_action audit entry."""
        blocked_result = RateLimitResult(
            allowed=False, limit=60, remaining=0, reset_at=9999999999, retry_after=30
        )
        with patch.object(api_key_limiter, "check", AsyncMock(return_value=blocked_result)), \
             patch("asc_api.core.middleware.log_security_action") as mock_log:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                await c.get(
                    "/api/v1/health/liveness",
                    headers={"X-API-Key": "asc_aabbccdd_" + "x" * 40},
                )
        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args
        assert call_kwargs.args[0] == "api_key_rate_limited"
        assert call_kwargs.kwargs.get("status") == "blocked"

    @pytest.mark.asyncio
    async def test_raw_key_secret_never_appears_in_rate_limit_key(self):
        """The 40-char secret portion of the raw key must never be used as a rate limit key."""
        secret_part = "s" * 40
        raw_key = f"asc_aabbccdd_{secret_part}"

        called_with_prefixes = []

        async def capture_check(prefix, limit, window_seconds):
            called_with_prefixes.append(prefix)
            return RateLimitResult(allowed=True, limit=limit, remaining=limit - 1, reset_at=9999999999)

        with patch.object(api_key_limiter, "check", side_effect=capture_check):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                await c.get("/api/v1/health/liveness", headers={"X-API-Key": raw_key})

        for prefix_used in called_with_prefixes:
            assert secret_part not in prefix_used, "Secret part must not be in rate limit key"
            assert prefix_used == "aabbccdd"

    @pytest.mark.asyncio
    async def test_429_response_body_does_not_contain_raw_key(self):
        """Error response must never echo the raw API key back to the client."""
        blocked_result = RateLimitResult(
            allowed=False, limit=60, remaining=0, reset_at=9999999999, retry_after=10
        )
        raw_key = "asc_aabbccdd_" + "z" * 40
        with patch.object(api_key_limiter, "check", AsyncMock(return_value=blocked_result)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.get(
                    "/api/v1/health/liveness",
                    headers={"X-API-Key": raw_key},
                )
        assert "z" * 40 not in r.text
        assert raw_key not in r.text

    @pytest.mark.asyncio
    async def test_redis_error_in_check_fails_open(self):
        """Redis failure during check must allow the request (fail-open policy)."""
        limiter = ApiKeyRateLimiter()
        limiter._mode = "redis"
        limiter._redis = MagicMock()
        # Simulate pipeline execute raising a connection error
        pipe_mock = MagicMock()
        pipe_mock.zremrangebyscore = MagicMock()
        pipe_mock.zadd = MagicMock()
        pipe_mock.zcard = MagicMock()
        pipe_mock.zrange = MagicMock()
        pipe_mock.expire = MagicMock()
        pipe_mock.execute = AsyncMock(side_effect=ConnectionError("Redis down"))
        limiter._redis.pipeline.return_value = pipe_mock

        result = await limiter.check("failopen", limit=5, window_seconds=60)
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_audit_log_detail_contains_prefix_not_hash(self):
        """The Ledger Premos detail field must reference the prefix, not the HMAC hash."""
        blocked_result = RateLimitResult(
            allowed=False, limit=60, remaining=0, reset_at=9999999999, retry_after=30
        )
        with patch.object(api_key_limiter, "check", AsyncMock(return_value=blocked_result)), \
             patch("asc_api.core.middleware.log_security_action") as mock_log:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                await c.get(
                    "/api/v1/health/liveness",
                    headers={"X-API-Key": "asc_aabbccdd_" + "x" * 40},
                )
        detail = mock_log.call_args.kwargs.get("detail", "")
        assert "aabbccdd" in detail
        # The 40-char secret must not appear in the audit detail
        assert "x" * 40 not in detail


# â”€â”€ Class 6: Deployment artifacts â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestRateLimitDeploymentArtifacts:
    """Verify P41 code artifacts exist and are wired up correctly."""

    def test_api_key_rate_limit_module_exists(self):
        path = _REPO_ROOT / "backend" / "asc_api" / "core" / "api_key_rate_limit.py"
        assert path.exists(), "api_key_rate_limit.py must exist"

    def test_config_has_rate_limit_per_minute(self):
        assert hasattr(settings, "RATE_LIMIT_API_KEY_PER_MINUTE")
        assert settings.RATE_LIMIT_API_KEY_PER_MINUTE > 0

    def test_config_has_rate_limit_per_hour(self):
        assert hasattr(settings, "RATE_LIMIT_API_KEY_PER_HOUR")
        assert settings.RATE_LIMIT_API_KEY_PER_HOUR > settings.RATE_LIMIT_API_KEY_PER_MINUTE

    def test_singleton_is_exported(self):
        from asc_api.core.api_key_rate_limit import api_key_limiter as singleton
        assert singleton is not None
        assert hasattr(singleton, "check")
        assert hasattr(singleton, "get_status")
        assert hasattr(singleton, "reset_for_prefix_all")

    def test_middleware_class_is_importable(self):
        from asc_api.core.middleware import ApiKeyRateLimitMiddleware
        assert ApiKeyRateLimitMiddleware is not None

    def test_main_imports_api_key_rate_limit(self):
        main_src = (_REPO_ROOT / "backend" / "asc_api" / "main.py").read_text()
        assert "api_key_limiter" in main_src
        assert "ApiKeyRateLimitMiddleware" in main_src

    def test_api_keys_router_has_status_endpoint(self):
        api_keys_src = (
            _REPO_ROOT / "backend" / "asc_api" / "api" / "v1" / "endpoints" / "api_keys.py"
        ).read_text()
        assert "rate-limit-status" in api_keys_src
        assert "rate-limit-reset" in api_keys_src
        assert "RateLimitStatus" in api_keys_src


# â”€â”€ Class 7: Regression â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestRateLimitRegression:
    """Ensure P41 changes do not break existing functionality."""

    @pytest.mark.asyncio
    async def test_liveness_endpoint_still_works(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/health")
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_non_api_key_path_is_not_rate_limited_by_p41(self):
        """P41 middleware must not set rate-limit headers on non-API-key requests."""
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/v1/health/liveness")
        # P41 middleware skips requests without X-API-Key header
        assert "X-RateLimit-Limit-Minute" not in r.headers
        assert "X-RateLimit-Limit-Hour" not in r.headers

    @pytest.mark.asyncio
    async def test_api_keys_crud_endpoint_still_401_without_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/v1/api-keys")
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_p40_imports_still_work(self):
        from asc_api.api.v1.endpoints.api_keys import (
            create_api_key,
            list_api_keys,
            revoke_api_key,
            rotate_api_key,
            RateLimitStatus,
        )
        assert all(callable(f) for f in [create_api_key, list_api_keys, revoke_api_key, rotate_api_key])

    @pytest.mark.asyncio
    async def test_existing_rate_limit_module_still_works(self):
        """SlowAPI limiter from P17 must still be importable and functional."""
        from asc_api.core.rate_limit import limiter
        assert limiter is not None

    @pytest.mark.asyncio
    async def test_middleware_stack_import_succeeds(self):
        from asc_api.core.middleware import (
            SecurityHeadersMiddleware,
            BodySizeLimitMiddleware,
            RequestContextMiddleware,
            ApiKeyRateLimitMiddleware,
        )
        assert all(c is not None for c in [
            SecurityHeadersMiddleware, BodySizeLimitMiddleware,
            RequestContextMiddleware, ApiKeyRateLimitMiddleware,
        ])
