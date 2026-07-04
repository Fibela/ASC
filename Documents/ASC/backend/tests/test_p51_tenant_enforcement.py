"""
P51 â€” Multi-Tenancy Enforcement
=================================
Tests verifying:
1. tenant_context.py â€” ContextVar set/get/cleanup
2. TenantMiddleware â€” JWT + X-Tenant-ID header resolution, cleanup, no-crash on bad tokens
3. apply_tenant_filter() â€” strict tenant isolation logic (SQL WHERE clause generation)
4. create_access_token() â€” optional tenant_id claim in JWT payload
5. API key endpoints â€” list/create respect tenant scope
6. Webhook endpoints â€” list/create respect tenant scope
7. main.py â€” TenantMiddleware wired into the middleware stack
8. Regression â€” P47â€“P50 deliverables unaffected

Testing approach
----------------
â€¢ Context / filter tests: pure Python unit tests â€” no HTTP, no DB
â€¢ Middleware tests: ASGI integration with an inline test app via httpx.AsyncClient
â€¢ Endpoint tests: app.dependency_overrides pattern (same as P47/P48/P49)
â€¢ Static analysis: import checks + file content inspection

Security scan
-------------
â€¢ No real tenant IDs or JWT secrets hardcoded
â€¢ All test credentials are obviously synthetic (test-tenant-*, test-user-*)
â€¢ Cross-tenant isolation assertions prove data never bleeds between tenants
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import jwt as _jwt
from httpx import AsyncClient, ASGITransport

from asc_api.core.security import create_access_token, decode_token_payload
from asc_api.core.tenant_context import get_tenant_id, set_tenant_id
from asc_api.db.session import get_db
from asc_api.main import app

_REPO_ROOT  = Path(__file__).parent.parent
_BACKEND    = _REPO_ROOT
_WORKFLOWS  = _REPO_ROOT.parent / ".github" / "workflows"


# â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _make_user(role: str = "analyst", tenant_id: str | None = None) -> MagicMock:
    u = MagicMock()
    u.id = str(uuid.uuid4())
    u.email = f"{role}@test.local"
    u.role = role
    u.is_active = True
    u.is_locked = False
    u.locked_until = None
    u.force_password_reset = False
    u.tenant_id = tenant_id
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


def _jwt_token(user_id: str, tenant_id: str | None = None) -> str:
    return create_access_token(user_id, tenant_id=tenant_id)


def _auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# â”€â”€ 1. TenantContext â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestTenantContext:
    """ContextVar set/get/cleanup behavior."""

    def setup_method(self):
        set_tenant_id(None)  # start clean

    def teardown_method(self):
        set_tenant_id(None)  # restore after each test

    def test_default_is_none(self):
        assert get_tenant_id() is None

    def test_set_and_get(self):
        set_tenant_id("tenant-abc")
        assert get_tenant_id() == "tenant-abc"

    def test_override_with_new_value(self):
        set_tenant_id("tenant-a")
        set_tenant_id("tenant-b")
        assert get_tenant_id() == "tenant-b"

    def test_reset_to_none(self):
        set_tenant_id("tenant-x")
        set_tenant_id(None)
        assert get_tenant_id() is None

    def test_module_exports_both_functions(self):
        from asc_api.core import tenant_context
        assert callable(tenant_context.set_tenant_id)
        assert callable(tenant_context.get_tenant_id)


# â”€â”€ 2. TenantMiddleware â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestTenantMiddleware:
    """Middleware resolves tenant_id from JWT and X-Tenant-ID header."""

    @pytest.mark.asyncio
    async def test_no_auth_sets_none(self):
        """Requests with no Authorization header â†’ tenant_id = None."""
        captured: list[str | None] = []

        from starlette.applications import Starlette
        from starlette.requests import Request
        from starlette.responses import JSONResponse
        from starlette.routing import Route
        from asc_api.core.tenant_middleware import TenantMiddleware

        async def probe(request: Request):
            captured.append(get_tenant_id())
            return JSONResponse({"tid": get_tenant_id()})

        test_app = Starlette(routes=[Route("/probe", probe)])
        test_app.add_middleware(TenantMiddleware)

        async with AsyncClient(
            transport=ASGITransport(app=test_app), base_url="http://test"
        ) as client:
            r = await client.get("/probe")

        assert r.status_code == 200
        assert captured[0] is None

    @pytest.mark.asyncio
    async def test_jwt_without_tenant_claim_sets_none(self):
        """JWT with no tenant_id claim â†’ tenant_id = None."""
        captured: list[str | None] = []

        from starlette.applications import Starlette
        from starlette.requests import Request
        from starlette.responses import JSONResponse
        from starlette.routing import Route
        from asc_api.core.tenant_middleware import TenantMiddleware

        async def probe(request: Request):
            captured.append(get_tenant_id())
            return JSONResponse({"tid": str(get_tenant_id())})

        test_app = Starlette(routes=[Route("/probe", probe)])
        test_app.add_middleware(TenantMiddleware)

        token = create_access_token("user-123")  # no tenant_id

        async with AsyncClient(
            transport=ASGITransport(app=test_app), base_url="http://test"
        ) as client:
            r = await client.get("/probe", headers={"Authorization": f"Bearer {token}"})

        assert r.status_code == 200
        assert captured[0] is None

    @pytest.mark.asyncio
    async def test_jwt_with_tenant_claim_sets_context(self):
        """JWT with tenant_id claim â†’ ContextVar holds that tenant_id."""
        captured: list[str | None] = []

        from starlette.applications import Starlette
        from starlette.requests import Request
        from starlette.responses import JSONResponse
        from starlette.routing import Route
        from asc_api.core.tenant_middleware import TenantMiddleware

        async def probe(request: Request):
            captured.append(get_tenant_id())
            return JSONResponse({"tid": get_tenant_id()})

        test_app = Starlette(routes=[Route("/probe", probe)])
        test_app.add_middleware(TenantMiddleware)

        token = create_access_token("user-123", tenant_id="tenant-premoscorp")

        async with AsyncClient(
            transport=ASGITransport(app=test_app), base_url="http://test"
        ) as client:
            r = await client.get("/probe", headers={"Authorization": f"Bearer {token}"})

        assert r.status_code == 200
        assert captured[0] == "tenant-premoscorp"

    @pytest.mark.asyncio
    async def test_x_tenant_id_header_takes_precedence(self):
        """X-Tenant-ID header overrides the JWT tenant claim."""
        captured: list[str | None] = []

        from starlette.applications import Starlette
        from starlette.requests import Request
        from starlette.responses import JSONResponse
        from starlette.routing import Route
        from asc_api.core.tenant_middleware import TenantMiddleware

        async def probe(request: Request):
            captured.append(get_tenant_id())
            return JSONResponse({"tid": get_tenant_id()})

        test_app = Starlette(routes=[Route("/probe", probe)])
        test_app.add_middleware(TenantMiddleware)

        token = create_access_token("user-123", tenant_id="jwt-tenant")

        async with AsyncClient(
            transport=ASGITransport(app=test_app), base_url="http://test"
        ) as client:
            r = await client.get(
                "/probe",
                headers={
                    "Authorization": f"Bearer {token}",
                    "X-Tenant-ID": "override-tenant",
                },
            )

        assert r.status_code == 200
        assert captured[0] == "override-tenant"

    @pytest.mark.asyncio
    async def test_invalid_jwt_falls_back_to_none(self):
        """A garbage Bearer token does not crash middleware â€” falls back to None."""
        captured: list[str | None] = []

        from starlette.applications import Starlette
        from starlette.requests import Request
        from starlette.responses import JSONResponse
        from starlette.routing import Route
        from asc_api.core.tenant_middleware import TenantMiddleware

        async def probe(request: Request):
            captured.append(get_tenant_id())
            return JSONResponse({})

        test_app = Starlette(routes=[Route("/probe", probe)])
        test_app.add_middleware(TenantMiddleware)

        async with AsyncClient(
            transport=ASGITransport(app=test_app), base_url="http://test"
        ) as client:
            r = await client.get(
                "/probe",
                headers={"Authorization": "Bearer not-a-real-jwt-at-all"},
            )

        assert r.status_code == 200
        assert captured[0] is None

    @pytest.mark.asyncio
    async def test_context_is_none_after_request(self):
        """ContextVar is reset to None after each request (connection-pool safety)."""
        from starlette.applications import Starlette
        from starlette.requests import Request
        from starlette.responses import JSONResponse
        from starlette.routing import Route
        from asc_api.core.tenant_middleware import TenantMiddleware

        async def probe(request: Request):
            return JSONResponse({})

        test_app = Starlette(routes=[Route("/probe", probe)])
        test_app.add_middleware(TenantMiddleware)

        token = create_access_token("user-123", tenant_id="tenant-premoscorp")

        async with AsyncClient(
            transport=ASGITransport(app=test_app), base_url="http://test"
        ) as client:
            await client.get("/probe", headers={"Authorization": f"Bearer {token}"})

        # After the request completes, the ContextVar should be reset
        assert get_tenant_id() is None

    def test_middleware_module_importable(self):
        from asc_api.core.tenant_middleware import TenantMiddleware
        assert TenantMiddleware is not None

    def test_middleware_is_base_http_middleware(self):
        from starlette.middleware.base import BaseHTTPMiddleware
        from asc_api.core.tenant_middleware import TenantMiddleware
        assert issubclass(TenantMiddleware, BaseHTTPMiddleware)


# â”€â”€ 3. apply_tenant_filter â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestTenantFilter:
    """apply_tenant_filter() generates correct WHERE clauses."""

    def setup_method(self):
        set_tenant_id(None)

    def teardown_method(self):
        set_tenant_id(None)

    def test_no_tenant_filters_null_records(self):
        """With no active tenant, query adds WHERE tenant_id IS NULL."""
        from sqlalchemy import select
        from asc_api.db.tenant_filter import apply_tenant_filter
        from asc_api.models.api_key import APIKey

        set_tenant_id(None)
        stmt = apply_tenant_filter(select(APIKey), APIKey)
        compiled = str(stmt.compile(compile_kwargs={"literal_binds": True}))
        assert "IS NULL" in compiled or "is NULL" in compiled.lower()

    def test_tenant_set_filters_by_tenant_id(self):
        """With active tenant, query adds WHERE tenant_id = <tid>."""
        from sqlalchemy import select
        from asc_api.db.tenant_filter import apply_tenant_filter
        from asc_api.models.api_key import APIKey

        set_tenant_id("tenant-alpha")
        stmt = apply_tenant_filter(select(APIKey), APIKey)
        compiled = str(stmt.compile(compile_kwargs={"literal_binds": True}))
        assert "tenant-alpha" in compiled

    def test_tenant_does_not_include_null_when_set(self):
        """Strict isolation: tenant-scoped queries do NOT fall back to NULL rows."""
        from sqlalchemy import select
        from asc_api.db.tenant_filter import apply_tenant_filter
        from asc_api.models.api_key import APIKey

        set_tenant_id("tenant-strict")
        stmt = apply_tenant_filter(select(APIKey), APIKey)
        compiled = str(stmt.compile(compile_kwargs={"literal_binds": True}))
        # Should NOT have "IS NULL" â€” strict isolation, no fallback to global rows
        assert "IS NULL" not in compiled.upper()

    def test_works_with_webhook_model(self):
        """Filter works with the Webhook model as well."""
        from sqlalchemy import select
        from asc_api.db.tenant_filter import apply_tenant_filter
        from asc_api.models.webhook import Webhook

        set_tenant_id("tenant-beta")
        stmt = apply_tenant_filter(select(Webhook), Webhook)
        compiled = str(stmt.compile(compile_kwargs={"literal_binds": True}))
        assert "tenant-beta" in compiled

    def test_callable_signature(self):
        from asc_api.db.tenant_filter import apply_tenant_filter
        import inspect
        sig = inspect.signature(apply_tenant_filter)
        params = list(sig.parameters.keys())
        assert "stmt" in params
        assert "model" in params

    def test_reads_from_context_var(self):
        """Filter uses get_tenant_id() â€” value changes with ContextVar."""
        from sqlalchemy import select
        from asc_api.db.tenant_filter import apply_tenant_filter
        from asc_api.models.api_key import APIKey

        set_tenant_id("tenant-x")
        stmt_x = apply_tenant_filter(select(APIKey), APIKey)
        compiled_x = str(stmt_x.compile(compile_kwargs={"literal_binds": True}))

        set_tenant_id("tenant-y")
        stmt_y = apply_tenant_filter(select(APIKey), APIKey)
        compiled_y = str(stmt_y.compile(compile_kwargs={"literal_binds": True}))

        assert "tenant-x" in compiled_x
        assert "tenant-y" in compiled_y
        assert "tenant-x" not in compiled_y

    def test_two_different_tenants_produce_different_queries(self):
        """Cross-tenant isolation: queries for different tenants are different."""
        from sqlalchemy import select
        from asc_api.db.tenant_filter import apply_tenant_filter
        from asc_api.models.api_key import APIKey

        set_tenant_id("org-a")
        compiled_a = str(apply_tenant_filter(select(APIKey), APIKey).compile(
            compile_kwargs={"literal_binds": True}
        ))

        set_tenant_id("org-b")
        compiled_b = str(apply_tenant_filter(select(APIKey), APIKey).compile(
            compile_kwargs={"literal_binds": True}
        ))

        assert compiled_a != compiled_b


# â”€â”€ 4. JWT tenant_id claim â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestJWTTenantClaim:
    """create_access_token() optional tenant_id in JWT payload."""

    def test_token_without_tenant_id(self):
        """No tenant_id kwarg â†’ no tenant_id field in payload."""
        token = create_access_token("user-1")
        payload = decode_token_payload(token)
        assert "tenant_id" not in payload

    def test_token_with_tenant_id(self):
        """tenant_id kwarg â†’ tenant_id present in payload."""
        token = create_access_token("user-1", tenant_id="tenant-123")
        payload = decode_token_payload(token)
        assert payload.get("tenant_id") == "tenant-123"

    def test_token_with_none_tenant_id_excluded(self):
        """tenant_id=None explicitly â†’ claim excluded (same as not passed)."""
        token = create_access_token("user-1", tenant_id=None)
        payload = decode_token_payload(token)
        assert "tenant_id" not in payload

    def test_other_claims_still_present(self):
        """Adding tenant_id does not remove standard claims."""
        token = create_access_token("user-42", tenant_id="t-abc")
        payload = decode_token_payload(token)
        assert payload.get("sub") == "user-42"
        assert payload.get("type") == "access"
        assert "jti" in payload
        assert "exp" in payload

    def test_token_backward_compatible(self):
        """Tokens without tenant_id (old format) are still decodable."""
        token = create_access_token("legacy-user")
        payload = decode_token_payload(token)
        # No KeyError, no exception â€” the key simply doesn't exist
        assert payload.get("tenant_id") is None


# â”€â”€ 5. API Keys endpoint tenant enforcement â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestAPIKeysTenantEnforcement:
    """api-keys endpoints enforce tenant isolation."""

    @pytest.mark.asyncio
    async def test_create_api_key_assigns_tenant_id(self):
        """POST /api-keys/ sets tenant_id = get_tenant_id() on the new key."""
        from asc_api.core.tenant_context import set_tenant_id

        user = _make_user(role="analyst", tenant_id="tenant-create")
        db_override, mock_db = _db_override(scalars_result=[])  # empty count â†’ cap not hit

        # Capture the object passed to db.add() and simulate what DB refresh does
        added_objects: list = []

        def _add(obj):
            # Simulate DB giving the object a primary key + defaults
            obj.id = str(uuid.uuid4())
            obj.is_active = True
            obj.created_at = datetime.now(timezone.utc)
            obj.last_used_at = None
            added_objects.append(obj)

        mock_db.add = _add

        app.dependency_overrides[get_db] = db_override
        set_tenant_id("tenant-create")

        try:
            with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)):
                async with AsyncClient(
                    transport=ASGITransport(app=app), base_url="http://test"
                ) as client:
                    token = _jwt_token(user.id, tenant_id="tenant-create")
                    r = await client.post(
                        "/api/v1/api-keys",
                        json={"name": "test-key", "scopes": ["read"]},
                        headers=_auth_headers(token),
                    )
        finally:
            app.dependency_overrides.pop(get_db, None)
            set_tenant_id(None)

        assert len(added_objects) == 1, f"Expected db.add() called once; got {len(added_objects)}"
        new_key = added_objects[0]
        assert new_key.tenant_id == "tenant-create"

    @pytest.mark.asyncio
    async def test_list_api_keys_applies_tenant_filter(self):
        """GET /api-keys/ executes a query that includes a tenant WHERE clause."""
        user = _make_user(role="analyst", tenant_id="tenant-list")
        db_override, mock_db = _db_override(scalars_result=[])

        captured_stmts: list = []
        original_execute = mock_db.execute.side_effect

        async def capture_execute(stmt, *args, **kwargs):
            captured_stmts.append(str(stmt.compile(compile_kwargs={"literal_binds": True})))
            from unittest.mock import MagicMock
            result = MagicMock()
            result.scalars.return_value.all.return_value = []
            return result

        mock_db.execute = AsyncMock(side_effect=capture_execute)
        app.dependency_overrides[get_db] = db_override

        try:
            with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)):
                async with AsyncClient(
                    transport=ASGITransport(app=app), base_url="http://test"
                ) as client:
                    token = _jwt_token(user.id, tenant_id="tenant-list")
                    r = await client.get(
                        "/api/v1/api-keys",
                        headers=_auth_headers(token),
                    )
        finally:
            app.dependency_overrides.pop(get_db, None)
            set_tenant_id(None)

        assert r.status_code == 200
        # The WHERE clause with tenant-list must appear in the executed SQL
        assert any("tenant-list" in s for s in captured_stmts), (
            f"No tenant filter in executed queries: {captured_stmts}"
        )

    @pytest.mark.asyncio
    async def test_admin_list_applies_tenant_filter(self):
        """GET /api-keys/ as admin also scopes results to tenant."""
        admin = _make_user(role="admin", tenant_id="tenant-admin")
        db_override, mock_db = _db_override(scalars_result=[])

        captured_stmts: list = []

        async def capture_execute(stmt, *args, **kwargs):
            captured_stmts.append(str(stmt.compile(compile_kwargs={"literal_binds": True})))
            from unittest.mock import MagicMock
            result = MagicMock()
            result.scalars.return_value.all.return_value = []
            return result

        mock_db.execute = AsyncMock(side_effect=capture_execute)
        app.dependency_overrides[get_db] = db_override

        try:
            with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=admin)):
                async with AsyncClient(
                    transport=ASGITransport(app=app), base_url="http://test"
                ) as client:
                    token = _jwt_token(admin.id, tenant_id="tenant-admin")
                    r = await client.get(
                        "/api/v1/api-keys",
                        headers=_auth_headers(token),
                    )
        finally:
            app.dependency_overrides.pop(get_db, None)
            set_tenant_id(None)

        assert r.status_code == 200
        assert any("tenant-admin" in s for s in captured_stmts)

    @pytest.mark.asyncio
    async def test_no_tenant_produces_null_filter(self):
        """GET /api-keys/ with no tenant in JWT â†’ WHERE tenant_id IS NULL."""
        user = _make_user(role="analyst")
        db_override, mock_db = _db_override(scalars_result=[])

        captured_stmts: list = []

        async def capture_execute(stmt, *args, **kwargs):
            captured_stmts.append(str(stmt.compile(compile_kwargs={"literal_binds": True})))
            from unittest.mock import MagicMock
            result = MagicMock()
            result.scalars.return_value.all.return_value = []
            return result

        mock_db.execute = AsyncMock(side_effect=capture_execute)
        app.dependency_overrides[get_db] = db_override

        try:
            with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)):
                async with AsyncClient(
                    transport=ASGITransport(app=app), base_url="http://test"
                ) as client:
                    token = _jwt_token(user.id)  # no tenant_id
                    r = await client.get(
                        "/api/v1/api-keys",
                        headers=_auth_headers(token),
                    )
        finally:
            app.dependency_overrides.pop(get_db, None)
            set_tenant_id(None)

        assert r.status_code == 200
        assert any("IS NULL" in s.upper() for s in captured_stmts), (
            f"Expected IS NULL filter for null-tenant request: {captured_stmts}"
        )

    def test_api_keys_endpoint_imports_tenant_context(self):
        """api_keys.py must import get_tenant_id (auto-assign on create)."""
        source = (_BACKEND / "app" / "api" / "v1" / "endpoints" / "api_keys.py").read_text()
        assert "get_tenant_id" in source
        assert "apply_tenant_filter" in source


# â”€â”€ 6. Webhooks endpoint tenant enforcement â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestWebhooksTenantEnforcement:
    """webhooks endpoints enforce tenant isolation."""

    @pytest.mark.asyncio
    async def test_create_webhook_assigns_tenant_id(self):
        """POST /webhooks/ sets tenant_id = get_tenant_id() on the new webhook."""
        from asc_api.core.tenant_context import set_tenant_id

        user = _make_user(role="analyst", tenant_id="tenant-wh")
        db_override, mock_db = _db_override(scalars_result=[])

        added_objects: list = []
        mock_db.add = lambda obj: added_objects.append(obj)
        app.dependency_overrides[get_db] = db_override
        set_tenant_id("tenant-wh")

        try:
            with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)):
                async with AsyncClient(
                    transport=ASGITransport(app=app), base_url="http://test"
                ) as client:
                    token = _jwt_token(user.id, tenant_id="tenant-wh")
                    r = await client.post(
                        "/api/v1/webhooks",
                        json={"url": "https://hooks.example.com/recv", "events": ["alert.critical"]},
                        headers=_auth_headers(token),
                    )
        finally:
            app.dependency_overrides.pop(get_db, None)
            set_tenant_id(None)

        assert len(added_objects) == 1
        new_wh = added_objects[0]
        assert new_wh.tenant_id == "tenant-wh"

    @pytest.mark.asyncio
    async def test_list_webhooks_applies_tenant_filter(self):
        """GET /webhooks/ executes a query with a tenant WHERE clause."""
        user = _make_user(role="analyst", tenant_id="tenant-wh-list")
        db_override, mock_db = _db_override(scalars_result=[])

        captured_stmts: list = []

        async def capture_execute(stmt, *args, **kwargs):
            captured_stmts.append(str(stmt.compile(compile_kwargs={"literal_binds": True})))
            from unittest.mock import MagicMock
            result = MagicMock()
            result.scalars.return_value.all.return_value = []
            return result

        mock_db.execute = AsyncMock(side_effect=capture_execute)
        app.dependency_overrides[get_db] = db_override

        try:
            with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)):
                async with AsyncClient(
                    transport=ASGITransport(app=app), base_url="http://test"
                ) as client:
                    token = _jwt_token(user.id, tenant_id="tenant-wh-list")
                    r = await client.get(
                        "/api/v1/webhooks",
                        headers=_auth_headers(token),
                    )
        finally:
            app.dependency_overrides.pop(get_db, None)
            set_tenant_id(None)

        assert r.status_code == 200
        assert any("tenant-wh-list" in s for s in captured_stmts)

    @pytest.mark.asyncio
    async def test_webhooks_cross_tenant_filter_differs(self):
        """Two requests with different tenant_ids produce different WHERE clauses."""
        stmts_a: list = []
        stmts_b: list = []

        async def run_list(user, tenant_id: str, out: list):
            db_override, mock_db = _db_override(scalars_result=[])

            async def capture_execute(stmt, *a, **kw):
                out.append(str(stmt.compile(compile_kwargs={"literal_binds": True})))
                from unittest.mock import MagicMock
                r = MagicMock()
                r.scalars.return_value.all.return_value = []
                return r

            mock_db.execute = AsyncMock(side_effect=capture_execute)
            app.dependency_overrides[get_db] = db_override
            try:
                with patch(
                    "app.api.deps._resolve_user",
                    AsyncMock(return_value=user),
                ):
                    async with AsyncClient(
                        transport=ASGITransport(app=app), base_url="http://test"
                    ) as client:
                        token = _jwt_token(user.id, tenant_id=tenant_id)
                        await client.get(
                            "/api/v1/webhooks",
                            headers=_auth_headers(token),
                        )
            finally:
                app.dependency_overrides.pop(get_db, None)
                set_tenant_id(None)

        user_a = _make_user(tenant_id="org-alpha")
        user_b = _make_user(tenant_id="org-beta")

        await run_list(user_a, "org-alpha", stmts_a)
        await run_list(user_b, "org-beta", stmts_b)

        assert stmts_a and stmts_b
        assert stmts_a[0] != stmts_b[0], "Cross-tenant queries must differ"

    def test_webhooks_endpoint_imports_tenant_context(self):
        """webhooks.py must import get_tenant_id and apply_tenant_filter."""
        source = (_BACKEND / "app" / "api" / "v1" / "endpoints" / "webhooks.py").read_text()
        assert "get_tenant_id" in source
        assert "apply_tenant_filter" in source

    def test_webhooks_endpoint_has_tenant_assign_comment(self):
        """P51 comment is present on the auto-assign line (traceability)."""
        source = (_BACKEND / "app" / "api" / "v1" / "endpoints" / "webhooks.py").read_text()
        assert "P51" in source


# â”€â”€ 7. main.py wires TenantMiddleware â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestMainPyTenantWiring:
    """main.py correctly imports and registers TenantMiddleware."""

    def test_main_imports_tenant_middleware(self):
        source = (_BACKEND / "app" / "main.py").read_text()
        assert "TenantMiddleware" in source

    def test_main_adds_tenant_middleware(self):
        source = (_BACKEND / "app" / "main.py").read_text()
        assert "add_middleware(TenantMiddleware)" in source

    def test_tenant_middleware_before_cors_in_runtime(self):
        """TenantMiddleware's add_middleware call appears before CORSMiddleware's in
        the source, meaning it wraps inside CORS (runs after CORS in the request path)."""
        source = (_BACKEND / "app" / "main.py").read_text()
        # Find positions of add_middleware calls
        pos_tenant = source.index("add_middleware(TenantMiddleware)")
        # CORSMiddleware may be split across lines â€” find first occurrence of CORSMiddleware
        # after the first add_middleware call
        first_add = source.index("add_middleware(")
        pos_cors = source.index("CORSMiddleware", first_add)
        # TenantMiddleware add_middleware call must precede CORSMiddleware's call
        # (added earlier = inner layer = runs after CORS in the request path)
        assert pos_tenant < pos_cors, (
            "TenantMiddleware must be added to middleware stack before CORSMiddleware "
            "so it runs inside (after) CORS in the request path"
        )

    def test_app_imports_correctly(self):
        """The app is importable â€” no circular import or missing module."""
        from asc_api.main import app
        assert app is not None

    def test_tenant_middleware_importable_standalone(self):
        from asc_api.core.tenant_middleware import TenantMiddleware
        assert TenantMiddleware is not None


# â”€â”€ 8. Regression: P47â€“P50 unaffected â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestP51Regression:
    """Key P47â€“P50 deliverables still present after P51 changes."""

    def test_tenant_model_still_importable(self):
        from asc_api.models.tenant import Tenant
        assert Tenant.__tablename__ == "tenants"

    def test_p49_workflow_still_present(self):
        assert (_WORKFLOWS / "p49-security-gates.yml").exists()

    def test_p50_workflow_still_present(self):
        assert (_WORKFLOWS / "p50-e2e.yml").exists()

    def test_p47_tenant_id_in_user_model(self):
        from asc_api.models.user import User
        assert hasattr(User, "tenant_id")

    def test_p47_tenant_id_in_api_key_model(self):
        from asc_api.models.api_key import APIKey
        assert hasattr(APIKey, "tenant_id")

    def test_p47_tenant_id_in_webhook_model(self):
        from asc_api.models.webhook import Webhook
        assert hasattr(Webhook, "tenant_id")

    def test_security_py_backward_compatible(self):
        """create_access_token() still works with a single positional arg (no tenant_id)."""
        token = create_access_token("user-999")
        payload = decode_token_payload(token)
        assert payload["sub"] == "user-999"
