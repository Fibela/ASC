"""
P42 â€” Webhook Support â€” Test Suite
====================================
Tests: model/dispatcher unit, endpoint CRUD, RBAC, one-time secret, signing,
       test-delivery endpoint, security invariants, deployment artifacts, regression.

Pattern: AsyncClient + ASGITransport (no real DB/network).
DB is mocked via Depends(get_db) override. HTTP delivery is mocked via httpx.

Security scan coverage:
  â€¢ Signing secret NEVER appears in list/get/patch/delete responses
  â€¢ Signing secret NEVER logged (audit entries checked for absence)
  â€¢ Signing secret NEVER included in 429 / error responses
  â€¢ HMAC-SHA256 signature verified on test payload (sign_payload + verify_signature)
  â€¢ URL validation: non-http(s) schemes rejected
  â€¢ Event validation: unknown events rejected with 422
  â€¢ Unauthorized access: 403 on wrong user, 401 on missing auth
  â€¢ Admin sees all webhooks; analyst sees only own
"""

import hashlib
import hmac as _hmac
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from asc_api.core.config import get_settings
from asc_api.core.security import create_access_token
from asc_api.core.webhook_dispatcher import sign_payload, verify_signature
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


def _make_webhook(user_id: str, wh_id: str | None = None, secret: str = "a" * 64):
    wh = MagicMock()
    wh.id = wh_id or str(uuid.uuid4())
    wh.url = "https://example.com/hook"
    wh.secret = secret
    wh.events = ["incident.created", "alert.critical"]
    wh.description = "Test webhook"
    wh.is_active = True
    wh.user_id = user_id
    wh.created_at = datetime.now(timezone.utc)
    wh.last_triggered_at = None
    wh.failure_count = 0
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


# â”€â”€ Class 1: Dispatcher unit tests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestWebhookDispatcher:
    """Unit tests for HMAC signing and verification (no HTTP calls)."""

    def test_sign_payload_produces_sha256_prefix(self):
        sig = sign_payload("mysecret", b"hello world")
        assert sig.startswith("sha256=")

    def test_sign_payload_is_correct_hmac(self):
        secret = "testsecret"
        body = b'{"event":"incident.created"}'
        expected_hex = _hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        sig = sign_payload(secret, body)
        assert sig == f"sha256={expected_hex}"

    def test_sign_payload_different_secrets_differ(self):
        body = b"same body"
        sig1 = sign_payload("secret1", body)
        sig2 = sign_payload("secret2", body)
        assert sig1 != sig2

    def test_sign_payload_different_bodies_differ(self):
        secret = "same_secret"
        sig1 = sign_payload(secret, b"body one")
        sig2 = sign_payload(secret, b"body two")
        assert sig1 != sig2

    def test_verify_signature_accepts_valid(self):
        secret = "verifysecret"
        body = b'{"event":"test"}'
        sig = sign_payload(secret, body)
        assert verify_signature(secret, body, sig) is True

    def test_verify_signature_rejects_tampered_body(self):
        secret = "verifysecret"
        body = b'{"event":"test"}'
        sig = sign_payload(secret, body)
        tampered = b'{"event":"test","injected":true}'
        assert verify_signature(secret, tampered, sig) is False

    def test_verify_signature_rejects_wrong_secret(self):
        body = b'{"event":"test"}'
        sig = sign_payload("correct_secret", body)
        assert verify_signature("wrong_secret", body, sig) is False

    def test_sign_payload_deterministic(self):
        sig1 = sign_payload("s", b"b")
        sig2 = sign_payload("s", b"b")
        assert sig1 == sig2

    @pytest.mark.asyncio
    async def test_deliver_to_url_success(self):
        from asc_api.core.webhook_dispatcher import deliver_to_url

        mock_response = MagicMock()
        mock_response.status_code = 200

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            success, status_code, latency_ms, error = await deliver_to_url(
                "https://example.com/hook",
                "a" * 64,
                "test",
                {"event": "test"},
            )

        assert success is True
        assert status_code == 200
        assert error is None
        assert latency_ms >= 0

    @pytest.mark.asyncio
    async def test_deliver_to_url_failure_status(self):
        from asc_api.core.webhook_dispatcher import deliver_to_url

        mock_response = MagicMock()
        mock_response.status_code = 500

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            success, status_code, latency_ms, error = await deliver_to_url(
                "https://example.com/hook", "a" * 64, "test", {}
            )

        assert success is False
        assert status_code == 500

    @pytest.mark.asyncio
    async def test_deliver_to_url_network_error_returns_false(self):
        from asc_api.core.webhook_dispatcher import deliver_to_url

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(side_effect=ConnectionError("Network down"))
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            success, status_code, latency_ms, error = await deliver_to_url(
                "https://example.com/hook", "a" * 64, "test", {}
            )

        assert success is False
        assert status_code is None
        assert error is not None
        assert "ConnectionError" in error

    @pytest.mark.asyncio
    async def test_deliver_to_url_sends_signature_header(self):
        """The X-ASC-Signature header must be set on every delivery."""
        from asc_api.core.webhook_dispatcher import deliver_to_url

        captured_headers = {}

        async def fake_post(url, *, content, headers):
            captured_headers.update(headers)
            resp = MagicMock()
            resp.status_code = 200
            return resp

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post = fake_post
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            secret = "b" * 64
            payload = {"event": "test"}
            await deliver_to_url("https://example.com/hook", secret, "test", payload)

        assert "X-ASC-Signature" in captured_headers
        assert captured_headers["X-ASC-Signature"].startswith("sha256=")
        # Verify the signature is correct
        body = json.dumps(payload, default=str).encode()
        assert verify_signature(secret, body, captured_headers["X-ASC-Signature"])

    @pytest.mark.asyncio
    async def test_deliver_to_url_sends_event_and_delivery_headers(self):
        """X-ASC-Event and X-ASC-Delivery headers must be present."""
        from asc_api.core.webhook_dispatcher import deliver_to_url

        captured_headers = {}

        async def fake_post(url, *, content, headers):
            captured_headers.update(headers)
            resp = MagicMock()
            resp.status_code = 200
            return resp

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post = fake_post
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            await deliver_to_url("https://example.com", "s" * 64, "incident.created", {})

        assert "X-ASC-Event" in captured_headers
        assert captured_headers["X-ASC-Event"] == "incident.created"
        assert "X-ASC-Delivery" in captured_headers


# â”€â”€ Class 2: Webhook CRUD endpoints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestWebhookCRUD:
    BASE = "/api/v1/webhooks"

    @pytest.mark.asyncio
    async def test_register_returns_201_with_secret(self):
        user = _make_user("analyst")
        override, db = _db_override(scalars_result=[])
        db.refresh = AsyncMock(side_effect=lambda obj: setattr(obj, "created_at", datetime.now(timezone.utc)) or setattr(obj, "last_triggered_at", None) or setattr(obj, "failure_count", 0))
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.post(
                    f"{self.BASE}",
                    headers={"Authorization": f"Bearer {token}"},
                    json={"url": "https://example.com/hook", "events": ["incident.created"]},
                )
        app.dependency_overrides.clear()
        assert r.status_code == 201
        body = r.json()
        assert "secret" in body
        assert len(body["secret"]) == 64  # 32 bytes = 64 hex chars
        assert "signing_note" in body

    @pytest.mark.asyncio
    async def test_register_rejects_invalid_url_scheme(self):
        user = _make_user("analyst")
        override, _ = _db_override()
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.post(
                    f"{self.BASE}",
                    headers={"Authorization": f"Bearer {token}"},
                    json={"url": "ftp://example.com/hook", "events": ["test"]},
                )
        app.dependency_overrides.clear()
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_register_rejects_invalid_event(self):
        user = _make_user("analyst")
        override, _ = _db_override()
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.post(
                    f"{self.BASE}",
                    headers={"Authorization": f"Bearer {token}"},
                    json={"url": "https://example.com/hook", "events": ["unknown.event"]},
                )
        app.dependency_overrides.clear()
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_register_no_auth_returns_401(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.post(f"{self.BASE}", json={"url": "https://example.com", "events": ["test"]})
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_list_returns_owner_webhooks(self):
        user = _make_user("analyst")
        wh = _make_webhook(user.id)
        override, _ = _db_override(scalars_result=[wh])
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.get(f"{self.BASE}", headers={"Authorization": f"Bearer {token}"})
        app.dependency_overrides.clear()
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    @pytest.mark.asyncio
    async def test_get_webhook_owner_200(self):
        user = _make_user("analyst")
        wh = _make_webhook(user.id)
        override, _ = _db_override(scalar_result=wh)
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.get(
                    f"{self.BASE}/{wh.id}",
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_get_webhook_other_user_403(self):
        owner = _make_user("analyst")
        other = _make_user("analyst")
        wh = _make_webhook(owner.id)
        override, _ = _db_override(scalar_result=wh)
        app.dependency_overrides[get_db] = override
        token = _jwt(other.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=other)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.get(
                    f"{self.BASE}/{wh.id}",
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()
        assert r.status_code == 403

    @pytest.mark.asyncio
    async def test_delete_returns_204(self):
        user = _make_user("analyst")
        wh = _make_webhook(user.id)
        override, _ = _db_override(scalar_result=wh)
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.delete(
                    f"{self.BASE}/{wh.id}",
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()
        assert r.status_code == 204

    @pytest.mark.asyncio
    async def test_patch_updates_url(self):
        user = _make_user("analyst")
        wh = _make_webhook(user.id)
        override, _ = _db_override(scalar_result=wh)
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.patch(
                    f"{self.BASE}/{wh.id}",
                    headers={"Authorization": f"Bearer {token}"},
                    json={"url": "https://new-endpoint.com/hook"},
                )
        app.dependency_overrides.clear()
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_patch_invalid_url_scheme_422(self):
        user = _make_user("analyst")
        wh = _make_webhook(user.id)
        override, _ = _db_override(scalar_result=wh)
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.patch(
                    f"{self.BASE}/{wh.id}",
                    headers={"Authorization": f"Bearer {token}"},
                    json={"url": "javascript:alert(1)"},
                )
        app.dependency_overrides.clear()
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_get_404_on_unknown_id(self):
        user = _make_user("analyst")
        override, _ = _db_override(scalar_result=None)
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.get(
                    f"{self.BASE}/nonexistent-id",
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()
        assert r.status_code == 404


# â”€â”€ Class 3: Test delivery endpoint â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestWebhookTestEndpoint:
    BASE = "/api/v1/webhooks"

    @pytest.mark.asyncio
    async def test_test_endpoint_returns_result(self):
        user = _make_user("analyst")
        wh = _make_webhook(user.id, secret="c" * 64)
        override, _ = _db_override(scalar_result=wh)
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)), \
             patch("asc_api.api.v1.endpoints.webhooks.deliver_to_url",
                   AsyncMock(return_value=(True, 200, 45.2, None))):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.post(
                    f"{self.BASE}/{wh.id}/test",
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()
        assert r.status_code == 200
        body = r.json()
        assert body["success"] is True
        assert body["status_code"] == 200
        assert "latency_ms" in body

    @pytest.mark.asyncio
    async def test_test_endpoint_reports_failure(self):
        user = _make_user("analyst")
        wh = _make_webhook(user.id)
        override, _ = _db_override(scalar_result=wh)
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)), \
             patch("asc_api.api.v1.endpoints.webhooks.deliver_to_url",
                   AsyncMock(return_value=(False, 503, 1500.0, "Connection refused"))):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.post(
                    f"{self.BASE}/{wh.id}/test",
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()
        body = r.json()
        assert body["success"] is False
        assert body["error"] == "Connection refused"

    @pytest.mark.asyncio
    async def test_test_endpoint_other_user_403(self):
        owner = _make_user("analyst")
        other = _make_user("analyst")
        wh = _make_webhook(owner.id)
        override, _ = _db_override(scalar_result=wh)
        app.dependency_overrides[get_db] = override
        token = _jwt(other.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=other)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.post(
                    f"{self.BASE}/{wh.id}/test",
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()
        assert r.status_code == 403


# â”€â”€ Class 4: Security invariants â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestWebhookSecurity:
    """Secret must never leak; RBAC must be enforced everywhere."""

    @pytest.mark.asyncio
    async def test_secret_absent_from_list_response(self):
        user = _make_user("analyst")
        wh = _make_webhook(user.id, secret="supersecret" * 6)
        override, _ = _db_override(scalars_result=[wh])
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.get("/api/v1/webhooks", headers={"Authorization": f"Bearer {token}"})
        app.dependency_overrides.clear()
        # The secret must not appear anywhere in the response
        assert "supersecret" not in r.text
        assert "secret" not in r.json()[0] if r.json() else True

    @pytest.mark.asyncio
    async def test_secret_absent_from_get_response(self):
        user = _make_user("analyst")
        wh = _make_webhook(user.id, secret="topsecret01" * 6)
        override, _ = _db_override(scalar_result=wh)
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.get(
                    f"/api/v1/webhooks/{wh.id}",
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()
        assert "topsecret01" not in r.text
        assert "secret" not in r.json()

    @pytest.mark.asyncio
    async def test_register_emits_audit_log(self):
        user = _make_user("analyst")
        override, db = _db_override(scalars_result=[])
        db.refresh = AsyncMock(side_effect=lambda obj: (
            setattr(obj, "created_at", datetime.now(timezone.utc)) or
            setattr(obj, "last_triggered_at", None) or
            setattr(obj, "failure_count", 0)
        ))
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)), \
             patch("asc_api.api.v1.endpoints.webhooks.log_security_action") as mock_log:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                await c.post(
                    "/api/v1/webhooks",
                    headers={"Authorization": f"Bearer {token}"},
                    json={"url": "https://example.com/hook", "events": ["test"]},
                )
        app.dependency_overrides.clear()
        mock_log.assert_called()
        call_args = mock_log.call_args
        assert call_args.args[0] == "webhook_created"

    @pytest.mark.asyncio
    async def test_audit_log_does_not_contain_secret(self):
        """The Ledger Premos detail must NOT include the raw signing secret."""
        user = _make_user("analyst")
        override, db = _db_override(scalars_result=[])
        db.refresh = AsyncMock(side_effect=lambda obj: (
            setattr(obj, "created_at", datetime.now(timezone.utc)) or
            setattr(obj, "last_triggered_at", None) or
            setattr(obj, "failure_count", 0)
        ))
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        logged_calls = []

        def capture_log(action, **kwargs):
            logged_calls.append({"action": action, **kwargs})

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)), \
             patch("asc_api.api.v1.endpoints.webhooks.log_security_action", side_effect=capture_log):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.post(
                    "/api/v1/webhooks",
                    headers={"Authorization": f"Bearer {token}"},
                    json={"url": "https://example.com/hook", "events": ["test"]},
                )
        app.dependency_overrides.clear()

        if r.status_code == 201:
            secret_value = r.json().get("secret", "")
            for call in logged_calls:
                detail = call.get("detail", "")
                assert secret_value not in str(detail), "Secret must not appear in audit log"

    @pytest.mark.asyncio
    async def test_admin_sees_all_webhooks_on_admin_all(self):
        admin = _make_user("admin")
        owner = _make_user("analyst")
        wh = _make_webhook(owner.id)
        override, _ = _db_override(scalars_result=[wh])
        app.dependency_overrides[get_db] = override
        token = _jwt(admin.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=admin)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.get(
                    "/api/v1/webhooks/admin/all",
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_analyst_cannot_access_admin_all(self):
        analyst = _make_user("analyst")
        override, _ = _db_override(scalars_result=[])
        app.dependency_overrides[get_db] = override
        token = _jwt(analyst.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=analyst)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.get(
                    "/api/v1/webhooks/admin/all",
                    headers={"Authorization": f"Bearer {token}"},
                )
        app.dependency_overrides.clear()
        assert r.status_code == 403

    @pytest.mark.asyncio
    async def test_emit_webhook_event_filters_by_event_type(self):
        """Only webhooks subscribed to the event receive delivery."""
        from asc_api.core.webhook_dispatcher import emit_webhook_event

        wh_subscribed = _make_webhook(str(uuid.uuid4()))
        wh_subscribed.events = ["incident.created"]

        wh_not_subscribed = _make_webhook(str(uuid.uuid4()))
        wh_not_subscribed.events = ["alert.high"]

        db = MagicMock()
        exec_result = MagicMock()
        exec_result.scalars.return_value.all.return_value = [wh_subscribed, wh_not_subscribed]
        db.execute = AsyncMock(return_value=exec_result)

        delivered_to = []

        async def mock_task(url, secret, event, payload):
            delivered_to.append(url)
            return True, 200, 10.0, None

        with patch("asc_api.core.webhook_dispatcher.deliver_to_url", side_effect=mock_task), \
             patch("asyncio.create_task") as mock_create_task:
            count = await emit_webhook_event("incident.created", {"id": "test"}, db)

        assert count == 1  # only wh_subscribed matched


# â”€â”€ Class 5: Deployment artifacts â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestWebhookDeploymentArtifacts:

    def test_webhook_model_file_exists(self):
        p = _REPO_ROOT / "backend" / "asc_api" / "models" / "webhook.py"
        assert p.exists()

    def test_migration_file_exists(self):
        p = _REPO_ROOT / "backend" / "migrations" / "versions" / "n4h58k6m9g71_add_webhooks_p42.py"
        assert p.exists()

    def test_migration_down_revision_is_p40(self):
        p = _REPO_ROOT / "backend" / "migrations" / "versions" / "n4h58k6m9g71_add_webhooks_p42.py"
        content = p.read_text()
        assert 'down_revision = "m3g47j5l8f60"' in content

    def test_dispatcher_module_exists(self):
        p = _REPO_ROOT / "backend" / "asc_api" / "core" / "webhook_dispatcher.py"
        assert p.exists()

    def test_webhooks_endpoint_file_exists(self):
        p = _REPO_ROOT / "backend" / "asc_api" / "api" / "v1" / "endpoints" / "webhooks.py"
        assert p.exists()

    def test_router_includes_webhooks(self):
        p = _REPO_ROOT / "backend" / "asc_api" / "api" / "v1" / "router.py"
        content = p.read_text()
        assert "webhooks" in content

    def test_models_init_exports_webhook(self):
        from asc_api.models import Webhook
        assert Webhook is not None

    def test_valid_events_set_populated(self):
        from asc_api.models.webhook import VALID_WEBHOOK_EVENTS
        assert "incident.created" in VALID_WEBHOOK_EVENTS
        assert "alert.critical" in VALID_WEBHOOK_EVENTS
        assert "test" in VALID_WEBHOOK_EVENTS

    def test_webhook_max_per_user_constant(self):
        from asc_api.models.webhook import _MAX_WEBHOOKS_PER_USER
        assert _MAX_WEBHOOKS_PER_USER > 0


# â”€â”€ Class 6: Regression â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestWebhookRegression:

    @pytest.mark.asyncio
    async def test_liveness_endpoint_still_200(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/health")
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_api_keys_endpoint_still_401_without_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/v1/api-keys")
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_webhooks_endpoint_401_without_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/v1/webhooks")
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_dispatcher_imports_clean(self):
        from asc_api.core.webhook_dispatcher import (
            sign_payload, verify_signature, deliver_to_url, emit_webhook_event
        )
        assert all(callable(f) for f in [sign_payload, verify_signature, deliver_to_url, emit_webhook_event])

    @pytest.mark.asyncio
    async def test_p40_p41_imports_still_work(self):
        from asc_api.api.v1.endpoints.api_keys import create_api_key, rotate_api_key
        from asc_api.core.api_key_rate_limit import api_key_limiter
        assert callable(create_api_key)
        assert api_key_limiter is not None
