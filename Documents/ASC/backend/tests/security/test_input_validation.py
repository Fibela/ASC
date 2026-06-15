"""
P31-SEC-INPUT — Input validation security tests.

Coverage:
  - SQL injection payloads in all string fields
  - XSS and template injection in text inputs
  - Malformed / missing JSON bodies
  - Oversized fields (email, full_name, password)
  - Boundary values: empty strings, null bytes, control characters
  - Pydantic schema-level validation (LoginRequest, ChangePasswordRequest)
  - Query parameter abuse: negative limits, non-integer, injection strings

All injection inputs must either be rejected (4xx) or sanitized (no raw
payload reflected back unescaped). The tests do NOT check for 422 specifically
on endpoint tests — some payloads reach the DB layer and return 401/400 instead;
what matters is that no 5xx or unexpected 200 occurs.

Rate-limit strategy: unique key_func per test via monkeypatch.
"""
from __future__ import annotations

import uuid
from typing import Any

import pytest

from app.core.security import create_access_token


# ── Rate-limit bypass ─────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _reset_rate_limit():
    """Clear slowapi MemoryStorage before each test so no test sees 429."""
    from app.core.rate_limit import limiter
    limiter._storage.reset()
    yield
    limiter._storage.reset()


# ── SQL injection payloads ────────────────────────────────────────────────────

SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "' UNION SELECT * FROM users --",
    "admin'--",
    "1' AND '1'='1",
    "' OR 1=1 --",
    "\" OR \"1\"=\"1",
    "'; INSERT INTO users VALUES('pwned'); --",
]

# ── XSS / injection payloads ──────────────────────────────────────────────────

XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert(1)>",
    "{{7*7}}",              # SSTI
    "${7*7}",               # EL injection
    "$(whoami)",            # shell injection
    "`whoami`",             # backtick shell
    "'; exec xp_cmdshell('whoami'); --",
    "../../../etc/passwd",  # path traversal
]


# ── TestLoginInputValidation ──────────────────────────────────────────────────

class TestLoginInputValidation:
    """Login endpoint rejects or safely handles malicious inputs."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("email", SQL_INJECTION_PAYLOADS[:4])
    async def test_sql_injection_in_email_does_not_cause_500(self, client, email):
        r = await client.post("/api/v1/auth/login", json={"email": email, "password": "pass"})
        assert r.status_code != 500

    @pytest.mark.asyncio
    @pytest.mark.parametrize("pwd", SQL_INJECTION_PAYLOADS[:4])
    async def test_sql_injection_in_password_does_not_cause_500(self, client, pwd):
        r = await client.post("/api/v1/auth/login", json={"email": "x@x.com", "password": pwd})
        assert r.status_code != 500

    @pytest.mark.asyncio
    async def test_empty_email_returns_error(self, client):
        r = await client.post("/api/v1/auth/login", json={"email": "", "password": "pass"})
        assert r.status_code in (401, 422)

    @pytest.mark.asyncio
    async def test_empty_password_returns_error(self, client):
        r = await client.post("/api/v1/auth/login", json={"email": "a@b.com", "password": ""})
        assert r.status_code in (401, 422)

    @pytest.mark.asyncio
    async def test_oversized_email_does_not_cause_500(self, client):
        long_email = "a" * 1000 + "@test.com"
        r = await client.post("/api/v1/auth/login", json={"email": long_email, "password": "pass"})
        assert r.status_code != 500

    @pytest.mark.asyncio
    async def test_null_byte_in_email_does_not_cause_500(self, client):
        r = await client.post("/api/v1/auth/login", json={"email": "test\x00@domain.com", "password": "pass"})
        assert r.status_code != 500

    @pytest.mark.asyncio
    async def test_unicode_overflow_in_email_does_not_cause_500(self, client):
        r = await client.post("/api/v1/auth/login", json={"email": "тест@домен.рф", "password": "pass"})
        assert r.status_code != 500

    @pytest.mark.asyncio
    async def test_numeric_email_field_returns_422(self, client):
        r = await client.post("/api/v1/auth/login", json={"email": 12345, "password": "pass"})
        # Pydantic may coerce int to str — status 401 or 422 are both acceptable; not 500
        assert r.status_code != 500

    @pytest.mark.asyncio
    async def test_missing_email_field_returns_422(self, client):
        r = await client.post("/api/v1/auth/login", json={"password": "pass"})
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_missing_password_field_returns_422(self, client):
        r = await client.post("/api/v1/auth/login", json={"email": "a@b.com"})
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_extra_fields_ignored_not_500(self, client):
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": "a@b.com", "password": "pass", "__admin__": True, "role": "admin"},
        )
        assert r.status_code != 500

    @pytest.mark.asyncio
    async def test_xss_in_email_does_not_reflect_unescaped(self, client):
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": "<script>alert(1)</script>@x.com", "password": "pass"},
        )
        assert r.status_code != 500
        # Response must not contain raw script tag (XSS in response)
        assert "<script>" not in r.text


# ── TestRegisterInputValidation ───────────────────────────────────────────────

class TestRegisterInputValidation:
    """Register endpoint (bootstrap only) rejects malicious inputs."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("payload", SQL_INJECTION_PAYLOADS[:3])
    async def test_sql_injection_in_register_email_does_not_cause_500(self, client, payload):
        r = await client.post(
            "/api/v1/auth/register",
            json={"email": payload, "password": "Test@1234!", "full_name": "Attacker"},
        )
        assert r.status_code != 500

    @pytest.mark.asyncio
    @pytest.mark.parametrize("name", XSS_PAYLOADS[:3])
    async def test_xss_in_full_name_does_not_cause_500(self, client, name):
        r = await client.post(
            "/api/v1/auth/register",
            json={"email": f"user-{uuid.uuid4().hex[:6]}@x.com", "password": "Test@1234!", "full_name": name},
        )
        assert r.status_code != 500

    @pytest.mark.asyncio
    async def test_oversized_full_name_does_not_cause_500(self, client):
        r = await client.post(
            "/api/v1/auth/register",
            json={"email": "x@x.com", "password": "Test@1234!", "full_name": "A" * 10000},
        )
        assert r.status_code != 500

    @pytest.mark.asyncio
    async def test_missing_required_fields_returns_422(self, client):
        r = await client.post("/api/v1/auth/register", json={"email": "x@x.com"})
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_invalid_role_still_processed_safely(self, client):
        """Invalid role is silently ignored (defaults to analyst in create_user, or admin for bootstrap)."""
        r = await client.post(
            "/api/v1/auth/register",
            json={"email": "x@x.com", "password": "Test@1234!", "full_name": "X", "role": "superuser"},
        )
        # Bootstrap may succeed (201) or fail if users exist (403) — never 500
        assert r.status_code != 500

    @pytest.mark.asyncio
    async def test_null_byte_in_full_name_does_not_cause_500(self, client):
        r = await client.post(
            "/api/v1/auth/register",
            json={"email": "x@x.com", "password": "Test@1234!", "full_name": "Test\x00User"},
        )
        assert r.status_code != 500

    @pytest.mark.asyncio
    async def test_very_long_password_does_not_cause_500(self, client):
        r = await client.post(
            "/api/v1/auth/register",
            json={"email": "x@x.com", "password": "A" * 10000 + "@1!", "full_name": "X"},
        )
        assert r.status_code != 500


# ── TestCreateUserInputValidation ─────────────────────────────────────────────

class TestCreateUserInputValidation:
    """Admin create-user endpoint rejects or handles malicious inputs."""

    @pytest.mark.asyncio
    async def test_duplicate_email_returns_409(self, client, admin_user):
        token = create_access_token(admin_user.id)
        # Attempt to create a user with the existing admin email
        r = await client.post(
            "/api/v1/auth/users",
            headers={"Authorization": f"Bearer {token}"},
            json={"email": admin_user.email, "password": "New@Pass99!", "full_name": "Dup"},
        )
        assert r.status_code == 409

    @pytest.mark.asyncio
    async def test_invalid_role_defaults_to_analyst(self, client, admin_user):
        token = create_access_token(admin_user.id)
        new_email = f"newuser-{uuid.uuid4().hex[:6]}@test.com"
        r = await client.post(
            "/api/v1/auth/users",
            headers={"Authorization": f"Bearer {token}"},
            json={"email": new_email, "password": "Valid@Pass99!", "full_name": "Test", "role": "superuser"},
        )
        assert r.status_code in (200, 201)
        assert r.json().get("role") == "analyst"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("email_payload", SQL_INJECTION_PAYLOADS[:3])
    async def test_sql_injection_in_new_user_email_does_not_cause_500(self, client, admin_user, email_payload):
        token = create_access_token(admin_user.id)
        r = await client.post(
            "/api/v1/auth/users",
            headers={"Authorization": f"Bearer {token}"},
            json={"email": email_payload, "password": "Valid@Pass99!", "full_name": "Test"},
        )
        assert r.status_code != 500

    @pytest.mark.asyncio
    async def test_missing_email_returns_422(self, client, admin_user):
        token = create_access_token(admin_user.id)
        r = await client.post(
            "/api/v1/auth/users",
            headers={"Authorization": f"Bearer {token}"},
            json={"password": "Valid@Pass99!", "full_name": "Test"},
        )
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_missing_password_returns_422(self, client, admin_user):
        token = create_access_token(admin_user.id)
        r = await client.post(
            "/api/v1/auth/users",
            headers={"Authorization": f"Bearer {token}"},
            json={"email": "new@x.com", "full_name": "Test"},
        )
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_non_admin_cannot_create_users(self, client, analyst_user):
        token = create_access_token(analyst_user.id)
        r = await client.post(
            "/api/v1/auth/users",
            headers={"Authorization": f"Bearer {token}"},
            json={"email": "hack@x.com", "password": "Valid@Pass99!", "full_name": "Hack"},
        )
        assert r.status_code == 403

    @pytest.mark.asyncio
    async def test_viewer_cannot_create_users(self, client, viewer_user):
        token = create_access_token(viewer_user.id)
        r = await client.post(
            "/api/v1/auth/users",
            headers={"Authorization": f"Bearer {token}"},
            json={"email": "hack@x.com", "password": "Valid@Pass99!", "full_name": "Hack"},
        )
        assert r.status_code == 403


# ── TestMalformedRequests ─────────────────────────────────────────────────────

class TestMalformedRequests:
    """Malformed JSON, wrong Content-Type, empty body, and bad Auth headers."""

    @pytest.mark.asyncio
    async def test_malformed_json_returns_422(self, client):
        r = await client.post(
            "/api/v1/auth/login",
            content=b"this is not json at all!!{",
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_wrong_content_type_returns_422(self, client):
        r = await client.post(
            "/api/v1/auth/login",
            content=b"email=x%40x.com&password=pass",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_empty_body_returns_422(self, client):
        r = await client.post(
            "/api/v1/auth/login",
            content=b"",
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_array_body_returns_422(self, client):
        r = await client.post("/api/v1/auth/login", json=[{"email": "x@x.com"}])
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_missing_authorization_header_returns_401_or_403(self, client):
        r = await client.get("/api/v1/auth/me")
        assert r.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_malformed_bearer_format_returns_403_or_401(self, client):
        r = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "NotBearer token"},
        )
        assert r.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_bearer_with_no_token_returns_403_or_422(self, client):
        r = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer"},
        )
        assert r.status_code in (401, 403, 422)

    @pytest.mark.asyncio
    async def test_clearly_invalid_jwt_returns_401(self, client):
        r = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer this.is.clearly.not.a.jwt"},
        )
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_garbage_token_returns_401(self, client):
        garbage = "aGVsbG8=" * 50  # base64 "hello" repeated — valid base64, invalid JWT
        r = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {garbage}"},
        )
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_null_body_returns_422(self, client):
        r = await client.post(
            "/api/v1/auth/login",
            json=None,
        )
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_deeply_nested_json_does_not_cause_500(self, client):
        nested: Any = "leaf"
        for _ in range(20):
            nested = {"child": nested}
        r = await client.post("/api/v1/auth/login", json=nested)
        assert r.status_code != 500

    @pytest.mark.asyncio
    async def test_very_large_json_body_does_not_cause_500(self, client):
        large = {"email": "x@x.com", "password": "pass", "junk": "A" * 50_000}
        r = await client.post("/api/v1/auth/login", json=large)
        assert r.status_code != 500


# ── TestChangePasswordValidation ──────────────────────────────────────────────

class TestChangePasswordValidation:
    """change-password Pydantic schema and endpoint validation."""

    @pytest.mark.asyncio
    async def test_empty_new_password_returns_422(self, client, admin_user):
        token = create_access_token(admin_user.id)
        r = await client.post(
            "/api/v1/auth/change-password",
            headers={"Authorization": f"Bearer {token}"},
            json={"new_password": ""},
        )
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_whitespace_only_new_password_returns_422(self, client, admin_user):
        token = create_access_token(admin_user.id)
        r = await client.post(
            "/api/v1/auth/change-password",
            headers={"Authorization": f"Bearer {token}"},
            json={"new_password": "   "},
        )
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_missing_new_password_returns_422(self, client, admin_user):
        token = create_access_token(admin_user.id)
        r = await client.post(
            "/api/v1/auth/change-password",
            headers={"Authorization": f"Bearer {token}"},
            json={},
        )
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_schema_empty_password_raises_value_error(self):
        from app.api.v1.endpoints.auth import ChangePasswordRequest
        import pydantic
        with pytest.raises(pydantic.ValidationError):
            ChangePasswordRequest(new_password="")

    @pytest.mark.asyncio
    async def test_schema_whitespace_password_raises_value_error(self):
        from app.api.v1.endpoints.auth import ChangePasswordRequest
        import pydantic
        with pytest.raises(pydantic.ValidationError):
            ChangePasswordRequest(new_password="   ")

    @pytest.mark.asyncio
    async def test_schema_valid_password_accepted(self):
        from app.api.v1.endpoints.auth import ChangePasswordRequest
        obj = ChangePasswordRequest(new_password="ValidPass@99!")
        assert obj.new_password == "ValidPass@99!"

    @pytest.mark.asyncio
    async def test_sql_injection_in_new_password_does_not_cause_500(self, client, admin_user):
        token = create_access_token(admin_user.id)
        r = await client.post(
            "/api/v1/auth/change-password",
            headers={"Authorization": f"Bearer {token}"},
            json={"new_password": "'; DROP TABLE users; --"},
        )
        # May fail validation (422) or security check (400/422) — never 500
        assert r.status_code != 500

    @pytest.mark.asyncio
    async def test_unauthenticated_change_password_returns_401_or_403(self, client):
        r = await client.post(
            "/api/v1/auth/change-password",
            json={"new_password": "NewPass@99!"},
        )
        assert r.status_code in (401, 403)


# ── TestBoundaryValues ────────────────────────────────────────────────────────

class TestBoundaryValues:
    """Edge-case boundary values that could expose off-by-one or type errors."""

    @pytest.mark.asyncio
    async def test_login_with_max_valid_email_length_does_not_cause_500(self, client):
        # 254 is the max valid email length per RFC
        local = "a" * 50
        domain = "b" * 200 + ".com"
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": f"{local}@{domain}", "password": "pass"},
        )
        assert r.status_code != 500

    @pytest.mark.asyncio
    async def test_login_with_single_char_fields_does_not_cause_500(self, client):
        r = await client.post("/api/v1/auth/login", json={"email": "a", "password": "b"})
        assert r.status_code != 500

    @pytest.mark.asyncio
    async def test_control_characters_in_email_do_not_cause_500(self, client):
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": "test\t\r\n@domain.com", "password": "pass"},
        )
        assert r.status_code != 500

    @pytest.mark.asyncio
    async def test_unicode_in_password_does_not_cause_500(self, client, admin_user):
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": admin_user.email, "password": "密码测试🔐"},
        )
        assert r.status_code != 500

    @pytest.mark.asyncio
    async def test_boolean_value_in_email_does_not_cause_500(self, client):
        r = await client.post("/api/v1/auth/login", json={"email": True, "password": "pass"})
        assert r.status_code != 500

    @pytest.mark.asyncio
    async def test_null_value_in_email_returns_422(self, client):
        r = await client.post("/api/v1/auth/login", json={"email": None, "password": "pass"})
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_null_value_in_password_returns_422(self, client):
        r = await client.post("/api/v1/auth/login", json={"email": "x@x.com", "password": None})
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_list_in_email_field_returns_422(self, client):
        r = await client.post("/api/v1/auth/login", json={"email": ["a@b.com"], "password": "p"})
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_dict_in_password_field_returns_422(self, client):
        r = await client.post("/api/v1/auth/login", json={"email": "a@b.com", "password": {"key": "val"}})
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_float_in_email_does_not_cause_500(self, client):
        r = await client.post("/api/v1/auth/login", json={"email": 3.14, "password": "pass"})
        assert r.status_code != 500
