"""
P44 — Webhook Dashboard Frontend — API Contract Tests
======================================================
Verifies every endpoint that the frontend webhooks page depends on:
  GET  /api/v1/webhooks/           → list (analyst sees own only)
  POST /api/v1/webhooks/           → create (returns secret once)
  GET  /api/v1/webhooks/{id}       → get single
  PATCH /api/v1/webhooks/{id}      → update (url, events, is_active, description)
  DELETE /api/v1/webhooks/{id}     → delete 204
  POST /api/v1/webhooks/{id}/test  → test delivery result shape
  GET  /api/v1/admin/webhooks/     → admin list-all

Security contract invariants tested here:
  • Secret field NEVER in list/get/patch/admin-list responses
  • URL scheme enforced (http/https only)
  • Unknown events rejected 422
  • Cross-user access returns 403
  • Unauthenticated access returns 401
  • Test delivery result always contains: success, status_code, latency_ms, error
  • Admin role required for GET /api/v1/admin/webhooks/

Coverage: 30 tests across 6 test classes.
"""

import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.core.config import get_settings
from app.core.security import create_access_token
from app.db.session import get_db
from app.main import app

settings = get_settings()
_REPO_ROOT = Path(__file__).parent.parent.parent


# ── Helpers ───────────────────────────────────────────────────────────────────

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


def _make_webhook(user_id: str, wh_id: str | None = None, *, active: bool = True, failures: int = 0):
    wh = MagicMock()
    wh.id = wh_id or str(uuid.uuid4())
    wh.url = "https://hook.example.com/recv"
    wh.secret = "s3cr3t" * 10  # 60-char hex-like string — must never appear in contract responses
    wh.events = ["incident.created", "alert.critical"]
    wh.description = "P44 contract test webhook"
    wh.is_active = active
    wh.user_id = user_id
    wh.created_at = datetime.now(timezone.utc)
    wh.last_triggered_at = None
    wh.failure_count = failures
    return wh


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


# ── Class 1: List endpoint (GET /webhooks/) ───────────────────────────────────

class TestListWebhooksContract:
    """Frontend depends on GET /api/v1/webhooks/ → array of webhook objects."""

    @pytest.mark.asyncio
    async def test_list_returns_200_for_authenticated_user(self):
        user = _make_user("analyst")
        wh = _make_webhook(user.id)
        override, _ = _db_override(scalars_result=[wh])
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        with patch("app.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.get("/api/v1/webhooks/", headers={"Authorization": f"Bearer {token}"})
        app.dependency_overrides.clear()

        assert r.status_code == 200
        assert isinstance(r.json(), list)

    @pytest.mark.asyncio
    async def test_list_response_contains_required_fields(self):
        user = _make_user("analyst")
        wh = _make_webhook(user.id)
        override, _ = _db_override(scalars_result=[wh])
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        with patch("app.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.get("/api/v1/webhooks/", headers={"Authorization": f"Bearer {token}"})
        app.dependency_overrides.clear()

        assert r.status_code == 200
        item = r.json()[0]
        for field in ("id", "url", "events", "is_active", "user_id", "created_at", "failure_count"):
            assert field in item, f"Missing field: {field}"

    @pytest.mark.asyncio
    async def test_list_never_exposes_secret(self):
        """Frontend contract: secret field must NOT appear in list responses."""
        user = _make_user("analyst")
        wh = _make_webhook(user.id)
        override, _ = _db_override(scalars_result=[wh])
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        with patch("app.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.get("/api/v1/webhooks/", headers={"Authorization": f"Bearer {token}"})
        app.dependency_overrides.clear()

        assert r.status_code == 200
        body_text = r.text
        assert wh.secret not in body_text
        assert "secret" not in r.json()[0]

    @pytest.mark.asyncio
    async def test_list_requires_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            r = await ac.get("/api/v1/webhooks/")
        assert r.status_code == 401


# ── Class 2: Create endpoint (POST /webhooks/) ────────────────────────────────

class TestCreateWebhookContract:
    """Frontend depends on POST returning { ...WebhookResponse, secret, signing_note }."""

    @pytest.mark.asyncio
    async def test_create_returns_201_with_secret(self):
        user = _make_user("analyst")
        override, db = _db_override()
        db.refresh = AsyncMock(
            side_effect=lambda obj: (
                setattr(obj, "created_at", datetime.now(timezone.utc)) or
                setattr(obj, "last_triggered_at", None) or
                setattr(obj, "failure_count", 0)
            )
        )
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        with patch("app.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.post(
                    "/api/v1/webhooks/",
                    json={"url": "https://test.com/hook", "events": ["incident.created"]},
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()

        assert r.status_code == 201
        body = r.json()
        assert "secret" in body
        assert len(body["secret"]) == 64  # 32 bytes hex

    @pytest.mark.asyncio
    async def test_create_response_contains_signing_note(self):
        user = _make_user("analyst")
        override, db = _db_override()
        db.refresh = AsyncMock(
            side_effect=lambda obj: (
                setattr(obj, "created_at", datetime.now(timezone.utc)) or
                setattr(obj, "last_triggered_at", None) or
                setattr(obj, "failure_count", 0)
            )
        )
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        with patch("app.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.post(
                    "/api/v1/webhooks/",
                    json={"url": "https://test.com/hook", "events": ["incident.created"]},
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()

        assert r.status_code == 201
        assert "signing_note" in r.json()

    @pytest.mark.asyncio
    async def test_create_rejects_non_https_url(self):
        user = _make_user("analyst")
        override, _ = _db_override()
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        with patch("app.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.post(
                    "/api/v1/webhooks/",
                    json={"url": "ftp://evil.com/hook", "events": ["incident.created"]},
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()

        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_create_rejects_unknown_event(self):
        user = _make_user("analyst")
        override, _ = _db_override()
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        with patch("app.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.post(
                    "/api/v1/webhooks/",
                    json={"url": "https://test.com/hook", "events": ["unknown.event.xyz"]},
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()

        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_create_requires_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            r = await ac.post(
                "/api/v1/webhooks/",
                json={"url": "https://test.com/hook", "events": ["incident.created"]},
            )
        assert r.status_code == 401


# ── Class 3: Get / Patch / Delete ─────────────────────────────────────────────

class TestGetPatchDeleteContract:
    """Individual webhook operations the frontend's edit/toggle/delete actions call."""

    @pytest.mark.asyncio
    async def test_get_never_exposes_secret(self):
        user = _make_user("analyst")
        wh = _make_webhook(user.id)
        override, _ = _db_override(scalar_result=wh)
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        with patch("app.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.get(
                    f"/api/v1/webhooks/{wh.id}",
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()

        assert r.status_code == 200
        assert wh.secret not in r.text
        assert "secret" not in r.json()

    @pytest.mark.asyncio
    async def test_get_returns_403_for_other_user(self):
        owner = _make_user("analyst")
        requester = _make_user("analyst")
        wh = _make_webhook(owner.id)
        override, _ = _db_override(scalar_result=wh)
        app.dependency_overrides[get_db] = override
        token = _jwt(requester.id)

        with patch("app.api.deps._resolve_user", AsyncMock(return_value=requester)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.get(
                    f"/api/v1/webhooks/{wh.id}",
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()

        assert r.status_code == 403

    @pytest.mark.asyncio
    async def test_patch_is_active_toggle(self):
        user = _make_user("analyst")
        wh = _make_webhook(user.id, active=True)
        override, _ = _db_override(scalar_result=wh)
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        with patch("app.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.patch(
                    f"/api/v1/webhooks/{wh.id}",
                    json={"is_active": False},
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()

        assert r.status_code == 200
        assert "secret" not in r.json()

    @pytest.mark.asyncio
    async def test_patch_rejects_invalid_url(self):
        user = _make_user("analyst")
        wh = _make_webhook(user.id)
        override, _ = _db_override(scalar_result=wh)
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        with patch("app.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.patch(
                    f"/api/v1/webhooks/{wh.id}",
                    json={"url": "javascript://xss"},
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()

        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_delete_returns_204(self):
        user = _make_user("analyst")
        wh = _make_webhook(user.id)
        override, _ = _db_override(scalar_result=wh)
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        with patch("app.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.delete(
                    f"/api/v1/webhooks/{wh.id}",
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()

        assert r.status_code == 204

    @pytest.mark.asyncio
    async def test_delete_forbidden_for_other_user(self):
        owner = _make_user("analyst")
        attacker = _make_user("analyst")
        wh = _make_webhook(owner.id)
        override, _ = _db_override(scalar_result=wh)
        app.dependency_overrides[get_db] = override
        token = _jwt(attacker.id)

        with patch("app.api.deps._resolve_user", AsyncMock(return_value=attacker)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.delete(
                    f"/api/v1/webhooks/{wh.id}",
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()

        assert r.status_code == 403

    @pytest.mark.asyncio
    async def test_get_returns_404_for_missing(self):
        user = _make_user("analyst")
        override, _ = _db_override(scalar_result=None)
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        with patch("app.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.get(
                    f"/api/v1/webhooks/{uuid.uuid4()}",
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()

        assert r.status_code == 404


# ── Class 4: Test delivery endpoint ──────────────────────────────────────────

class TestWebhookTestDeliveryContract:
    """POST /api/v1/webhooks/{id}/test — shape required by frontend TestResultPanel."""

    @pytest.mark.asyncio
    async def test_test_delivery_returns_required_fields(self):
        user = _make_user("analyst")
        wh = _make_webhook(user.id)
        override, _ = _db_override(scalar_result=wh)
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        mock_delivery = (True, 200, 42.0, None)
        with patch("app.api.deps._resolve_user", AsyncMock(return_value=user)), \
             patch("app.api.v1.endpoints.webhooks.deliver_to_url", AsyncMock(return_value=mock_delivery)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.post(
                    f"/api/v1/webhooks/{wh.id}/test",
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()

        assert r.status_code == 200
        body = r.json()
        for field in ("success", "status_code", "latency_ms", "error"):
            assert field in body, f"Missing contract field: {field}"

    @pytest.mark.asyncio
    async def test_test_delivery_success_shape(self):
        user = _make_user("analyst")
        wh = _make_webhook(user.id)
        override, _ = _db_override(scalar_result=wh)
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        mock_delivery = (True, 200, 123.4, None)
        with patch("app.api.deps._resolve_user", AsyncMock(return_value=user)), \
             patch("app.api.v1.endpoints.webhooks.deliver_to_url", AsyncMock(return_value=mock_delivery)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.post(
                    f"/api/v1/webhooks/{wh.id}/test",
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()

        body = r.json()
        assert body["success"] is True
        assert body["status_code"] == 200
        assert body["error"] is None

    @pytest.mark.asyncio
    async def test_test_delivery_failure_shape(self):
        user = _make_user("analyst")
        wh = _make_webhook(user.id)
        override, _ = _db_override(scalar_result=wh)
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        mock_delivery = (False, None, 5001.0, "Connection refused")
        with patch("app.api.deps._resolve_user", AsyncMock(return_value=user)), \
             patch("app.api.v1.endpoints.webhooks.deliver_to_url", AsyncMock(return_value=mock_delivery)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.post(
                    f"/api/v1/webhooks/{wh.id}/test",
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()

        body = r.json()
        assert body["success"] is False
        assert body["status_code"] is None
        assert "refused" in body["error"].lower()

    @pytest.mark.asyncio
    async def test_test_delivery_forbidden_for_other_user(self):
        owner = _make_user("analyst")
        attacker = _make_user("analyst")
        wh = _make_webhook(owner.id)
        override, _ = _db_override(scalar_result=wh)
        app.dependency_overrides[get_db] = override
        token = _jwt(attacker.id)

        with patch("app.api.deps._resolve_user", AsyncMock(return_value=attacker)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.post(
                    f"/api/v1/webhooks/{wh.id}/test",
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()

        assert r.status_code == 403


# ── Class 5: Admin list ───────────────────────────────────────────────────────

class TestAdminListWebhooksContract:
    """GET /api/v1/admin/webhooks/ — admin-only global view."""

    @pytest.mark.asyncio
    async def test_admin_list_returns_200_for_admin(self):
        admin = _make_user("admin")
        u1 = _make_user("analyst")
        u2 = _make_user("analyst")
        wh1 = _make_webhook(u1.id)
        wh2 = _make_webhook(u2.id)
        override, _ = _db_override(scalars_result=[wh1, wh2])
        app.dependency_overrides[get_db] = override
        token = _jwt(admin.id)

        with patch("app.api.deps._resolve_user", AsyncMock(return_value=admin)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.get(
                    "/api/v1/webhooks/admin/all",
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()

        assert r.status_code == 200
        assert len(r.json()) == 2

    @pytest.mark.asyncio
    async def test_admin_list_denied_for_analyst(self):
        analyst = _make_user("analyst")
        override, _ = _db_override(scalars_result=[])
        app.dependency_overrides[get_db] = override
        token = _jwt(analyst.id)

        with patch("app.api.deps._resolve_user", AsyncMock(return_value=analyst)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.get(
                    "/api/v1/webhooks/admin/all",
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()

        assert r.status_code == 403

    @pytest.mark.asyncio
    async def test_admin_list_never_exposes_secrets(self):
        admin = _make_user("admin")
        wh = _make_webhook(admin.id)
        override, _ = _db_override(scalars_result=[wh])
        app.dependency_overrides[get_db] = override
        token = _jwt(admin.id)

        with patch("app.api.deps._resolve_user", AsyncMock(return_value=admin)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.get(
                    "/api/v1/webhooks/admin/all",
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()

        assert r.status_code == 200
        assert wh.secret not in r.text
        for item in r.json():
            assert "secret" not in item

    @pytest.mark.asyncio
    async def test_admin_list_requires_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            r = await ac.get("/api/v1/webhooks/admin/all")
        assert r.status_code == 401


# ── Class 6: Deployment artifacts & regression ───────────────────────────────

class TestP44DeploymentAndRegression:
    """Verify page file exists, api.ts includes all 7 webhook functions, no regressions."""

    def test_webhooks_page_file_exists(self):
        page = _REPO_ROOT / "frontend" / "src" / "app" / "webhooks" / "page.tsx"
        assert page.exists(), f"Missing: {page}"

    def test_webhooks_page_uses_auth_guard(self):
        page = _REPO_ROOT / "frontend" / "src" / "app" / "webhooks" / "page.tsx"
        content = page.read_text(encoding="utf-8")
        assert "useAuthGuard" in content

    def test_webhooks_page_has_create_modal(self):
        page = _REPO_ROOT / "frontend" / "src" / "app" / "webhooks" / "page.tsx"
        content = page.read_text(encoding="utf-8")
        assert "WebhookFormModal" in content

    def test_webhooks_page_has_secret_reveal(self):
        page = _REPO_ROOT / "frontend" / "src" / "app" / "webhooks" / "page.tsx"
        content = page.read_text(encoding="utf-8")
        assert "SecretReveal" in content

    def test_webhooks_page_has_test_result_panel(self):
        page = _REPO_ROOT / "frontend" / "src" / "app" / "webhooks" / "page.tsx"
        content = page.read_text(encoding="utf-8")
        assert "TestResultPanel" in content

    def test_api_ts_has_all_seven_webhook_functions(self):
        api_ts = _REPO_ROOT / "frontend" / "src" / "lib" / "api.ts"
        content = api_ts.read_text(encoding="utf-8")
        for fn in (
            "listWebhooks", "getWebhook", "createWebhook",
            "updateWebhook", "deleteWebhook", "testWebhook",
            "adminListAllWebhooks",
        ):
            assert fn in content, f"Missing function: {fn}"

    def test_api_ts_has_webhook_response_interface(self):
        api_ts = _REPO_ROOT / "frontend" / "src" / "lib" / "api.ts"
        content = api_ts.read_text(encoding="utf-8")
        assert "WebhookResponse" in content
        assert "WebhookCreated" in content
        assert "WebhookTestResult" in content

    def test_api_ts_has_valid_webhook_events_const(self):
        api_ts = _REPO_ROOT / "frontend" / "src" / "lib" / "api.ts"
        content = api_ts.read_text(encoding="utf-8")
        assert "VALID_WEBHOOK_EVENTS" in content
        assert "incident.created" in content

    def test_sidebar_has_webhook_entry(self):
        sidebar = _REPO_ROOT / "frontend" / "src" / "components" / "dashboard" / "Sidebar.tsx"
        content = sidebar.read_text(encoding="utf-8")
        assert "/webhooks" in content
        assert "Webhook" in content

    def test_liveness_still_healthy(self):
        """Regression: liveness endpoint must remain 200 after P44."""
        import asyncio
        async def _check():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                return await ac.get("/health")
        r = asyncio.get_event_loop().run_until_complete(_check())
        assert r.status_code == 200

    def test_webhooks_endpoint_still_needs_auth(self):
        """Regression: P44 changes must not accidentally open the webhook list endpoint."""
        import asyncio
        async def _check():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                return await ac.get("/api/v1/webhooks/")
        r = asyncio.get_event_loop().run_until_complete(_check())
        assert r.status_code == 401

    def test_p42_webhook_dispatcher_still_importable(self):
        from app.core.webhook_dispatcher import sign_payload, verify_signature, emit_webhook_event
        assert callable(sign_payload)
        assert callable(verify_signature)
        assert callable(emit_webhook_event)

    def test_p43_sdk_still_present(self):
        import sys
        sdk_path = str(_REPO_ROOT / "sdk")
        if sdk_path not in sys.path:
            sys.path.insert(0, sdk_path)
        import asc_sdk
        assert asc_sdk.__version__ == "0.1.0"
        from asc_sdk import AscClient, WebhookVerifier
        assert AscClient is not None
        assert WebhookVerifier is not None

    def test_p40_api_keys_endpoint_still_closed(self):
        """Regression: API keys list must still require auth."""
        import asyncio
        async def _check():
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                return await ac.get("/api/v1/api-keys/")
        r = asyncio.get_event_loop().run_until_complete(_check())
        assert r.status_code == 401

    def test_no_mock_data_in_webhook_page(self):
        """Security: frontend page must not contain hardcoded secrets, tokens, or mock URLs."""
        page = _REPO_ROOT / "frontend" / "src" / "app" / "webhooks" / "page.tsx"
        content = page.read_text(encoding="utf-8")
        forbidden = ["sk-", "Bearer eyJ", "password123", "secret123", "localhost:8000"]
        for pattern in forbidden:
            assert pattern not in content, f"Potential hardcoded secret/mock: '{pattern}'"
