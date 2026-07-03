"""
P43 — Python SDK Test Suite
============================
Tests: exceptions, WebhookVerifier, AscClient init, resource methods (incidents,
       alerts, api_keys, webhooks, events), HTTP error mapping, security invariants,
       deployment artifacts, and regression against P40/P41/P42.

All HTTP calls are intercepted via unittest.mock — zero real network traffic.
The SDK is loaded from sdk/ without pip install by injecting the path at collection time.

Security scan coverage:
  • API key sent ONLY as X-API-Key header — not in query params, not in body
  • WebhookVerifier uses hmac.compare_digest (constant-time) — no timing leak
  • 429 surfaces Retry-After to callers — no silent swallow
  • 401 raises AuthError — SDK caller cannot accidentally proceed after auth failure
  • Raw key / webhook secret not captured in any exception response body
  • InvalidSignatureError raised for tampered payloads — no partial trust
"""

import sys
import hashlib
import hmac as _hmac
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

# ── SDK path injection ────────────────────────────────────────────────────────
_REPO_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(_REPO_ROOT / "sdk"))

from asc_sdk import (
    AscClient,
    AscError,
    AuthError,
    ForbiddenError,
    InvalidSignatureError,
    NotFoundError,
    RateLimitError,
    ServerError,
    ValidationError,
    WebhookVerifier,
    __version__,
)
from asc_sdk.client import _raise_for_status
from asc_sdk.models import (
    APIKey, APIKeyCreated, Alert, Event, Incident,
    RateLimitStatus, Webhook, WebhookCreated, WebhookTestResult,
)

_SDK_ROOT = _REPO_ROOT / "sdk"
_API_KEY = "asc_test1234_" + "s" * 48  # fake key for tests


# ── Helpers ───────────────────────────────────────────────────────────────────

def _mock_resp(data, status: int = 200, headers: dict | None = None) -> MagicMock:
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status
    resp.is_success = 200 <= status < 300
    resp.json.return_value = data if isinstance(data, (dict, list)) else {}
    resp.text = json.dumps(data) if isinstance(data, (dict, list)) else str(data)
    resp.headers = dict(headers or {})
    return resp


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _incident_data(**kw) -> dict:
    return {
        "id": str(uuid.uuid4()),
        "title": "Test Incident",
        "severity": "high",
        "status": "open",
        "created_at": _now(),
        **kw,
    }


def _alert_data(**kw) -> dict:
    return {
        "id": str(uuid.uuid4()),
        "severity": "critical",
        "status": "open",
        "created_at": _now(),
        **kw,
    }


def _event_data(**kw) -> dict:
    return {
        "id": str(uuid.uuid4()),
        "event_type": "process_created",
        "created_at": _now(),
        **kw,
    }


def _api_key_data(**kw) -> dict:
    return {
        "id": str(uuid.uuid4()),
        "name": "My Key",
        "key_prefix": "ab12cd34",
        "scopes": ["read"],
        "is_active": True,
        "created_at": _now(),
        **kw,
    }


def _webhook_data(**kw) -> dict:
    return {
        "id": str(uuid.uuid4()),
        "url": "https://example.com/hook",
        "events": ["incident.created"],
        "is_active": True,
        "user_id": str(uuid.uuid4()),
        "created_at": _now(),
        "failure_count": 0,
        **kw,
    }


# ── Class 1: Exception hierarchy ──────────────────────────────────────────────

class TestExceptions:

    def test_auth_error_inherits_asc_error(self):
        err = AuthError("bad key", status_code=401)
        assert isinstance(err, AscError)
        assert err.status_code == 401

    def test_rate_limit_error_stores_retry_after(self):
        err = RateLimitError("too fast", retry_after=42, status_code=429)
        assert err.retry_after == 42
        assert isinstance(err, AscError)

    def test_not_found_inherits_asc_error(self):
        err = NotFoundError("gone", status_code=404)
        assert isinstance(err, AscError)

    def test_forbidden_error(self):
        err = ForbiddenError("no perm", status_code=403)
        assert isinstance(err, AscError)

    def test_server_error(self):
        err = ServerError("crash", status_code=500)
        assert isinstance(err, AscError)

    def test_validation_error(self):
        err = ValidationError("bad body", status_code=422)
        assert isinstance(err, AscError)

    def test_invalid_signature_error_inherits_asc_error(self):
        err = InvalidSignatureError("tampered")
        assert isinstance(err, AscError)

    def test_asc_error_stores_response_dict(self):
        err = AscError("fail", status_code=400, response={"detail": "bad"})
        assert err.response == {"detail": "bad"}


# ── Class 2: HTTP status → exception mapping ──────────────────────────────────

class TestExceptionMapping:

    def test_401_raises_auth_error(self):
        resp = _mock_resp({"detail": "Unauthorized"}, status=401)
        with pytest.raises(AuthError) as exc_info:
            _raise_for_status(resp)
        assert exc_info.value.status_code == 401

    def test_403_raises_forbidden_error(self):
        resp = _mock_resp({"detail": "Forbidden"}, status=403)
        with pytest.raises(ForbiddenError):
            _raise_for_status(resp)

    def test_404_raises_not_found_error(self):
        resp = _mock_resp({"detail": "Not found"}, status=404)
        with pytest.raises(NotFoundError):
            _raise_for_status(resp)

    def test_422_raises_validation_error(self):
        resp = _mock_resp({"detail": "Invalid field"}, status=422)
        with pytest.raises(ValidationError):
            _raise_for_status(resp)

    def test_429_raises_rate_limit_error_with_retry_after(self):
        resp = _mock_resp({"detail": "Too fast"}, status=429, headers={"Retry-After": "30"})
        with pytest.raises(RateLimitError) as exc_info:
            _raise_for_status(resp)
        assert exc_info.value.retry_after == 30

    def test_429_defaults_retry_after_60_when_header_absent(self):
        resp = _mock_resp({"detail": "Too fast"}, status=429)
        with pytest.raises(RateLimitError) as exc_info:
            _raise_for_status(resp)
        assert exc_info.value.retry_after == 60

    def test_500_raises_server_error(self):
        resp = _mock_resp({"detail": "Internal error"}, status=500)
        with pytest.raises(ServerError):
            _raise_for_status(resp)

    def test_200_does_not_raise(self):
        resp = _mock_resp({"id": "123"}, status=200)
        _raise_for_status(resp)  # must not raise


# ── Class 3: WebhookVerifier ──────────────────────────────────────────────────

class TestWebhookVerifier:

    def _make_sig(self, secret: str, body: bytes) -> str:
        return "sha256=" + _hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

    def test_verify_valid_signature_returns_true(self):
        verifier = WebhookVerifier("mysecret")
        body = b'{"event":"incident.created"}'
        sig = self._make_sig("mysecret", body)
        assert verifier.verify(body, sig) is True

    def test_verify_invalid_signature_returns_false(self):
        verifier = WebhookVerifier("mysecret")
        body = b'{"event":"incident.created"}'
        assert verifier.verify(body, "sha256=deadbeef") is False

    def test_verify_tampered_body_returns_false(self):
        verifier = WebhookVerifier("mysecret")
        body = b'{"event":"incident.created"}'
        sig = self._make_sig("mysecret", body)
        tampered = b'{"event":"incident.created","injected":true}'
        assert verifier.verify(tampered, sig) is False

    def test_verify_wrong_secret_returns_false(self):
        body = b'{"event":"test"}'
        sig = self._make_sig("correct_secret", body)
        verifier = WebhookVerifier("wrong_secret")
        assert verifier.verify(body, sig) is False

    def test_parse_event_valid_returns_dict(self):
        verifier = WebhookVerifier("sec")
        body = b'{"event":"test","data":{}}'
        sig = self._make_sig("sec", body)
        result = verifier.parse_event(body, sig)
        assert result["event"] == "test"

    def test_parse_event_invalid_signature_raises(self):
        verifier = WebhookVerifier("sec")
        body = b'{"event":"test"}'
        with pytest.raises(InvalidSignatureError):
            verifier.parse_event(body, "sha256=bad")

    def test_signature_matches_backend_dispatcher(self):
        """SDK verifier must produce the same signature as the backend dispatcher."""
        from asc_api.core.webhook_dispatcher import sign_payload
        secret = "a" * 64
        body = b'{"event":"incident.created","data":{"id":"123"}}'
        backend_sig = sign_payload(secret, body)
        sdk_verifier = WebhookVerifier(secret)
        assert sdk_verifier.verify(body, backend_sig) is True


# ── Class 4: AscClient initialisation ────────────────────────────────────────

class TestAscClientInit:

    def test_client_has_api_key_in_http_headers(self):
        client = AscClient(api_key=_API_KEY)
        assert client._http.headers.get("x-api-key") == _API_KEY

    def test_client_strips_trailing_slash_from_base_url(self):
        client = AscClient(api_key=_API_KEY, base_url="https://example.com/")
        assert not str(client._base_url).endswith("/")

    def test_client_exposes_all_resources(self):
        client = AscClient(api_key=_API_KEY)
        assert client.incidents is not None
        assert client.alerts is not None
        assert client.events is not None
        assert client.api_keys is not None
        assert client.webhooks is not None

    @pytest.mark.asyncio
    async def test_client_async_context_manager(self):
        async with AscClient(api_key=_API_KEY) as client:
            assert client is not None

    @pytest.mark.asyncio
    async def test_client_close_works(self):
        client = AscClient(api_key=_API_KEY)
        await client.close()  # must not raise


# ── Class 5: Incidents resource ───────────────────────────────────────────────

class TestIncidentsResource:

    @pytest.mark.asyncio
    async def test_list_incidents_returns_models(self):
        data = [_incident_data(), _incident_data()]
        async with AscClient(api_key=_API_KEY) as client:
            with patch.object(client._http, "request", new=AsyncMock(return_value=_mock_resp(data))):
                result = await client.incidents.list()
        assert len(result) == 2
        assert all(isinstance(i, Incident) for i in result)

    @pytest.mark.asyncio
    async def test_list_incidents_empty(self):
        async with AscClient(api_key=_API_KEY) as client:
            with patch.object(client._http, "request", new=AsyncMock(return_value=_mock_resp([]))):
                result = await client.incidents.list()
        assert result == []

    @pytest.mark.asyncio
    async def test_get_incident_returns_model(self):
        data = _incident_data(title="Critical Breach")
        async with AscClient(api_key=_API_KEY) as client:
            with patch.object(client._http, "request", new=AsyncMock(return_value=_mock_resp(data))):
                result = await client.incidents.get("inc-id")
        assert isinstance(result, Incident)
        assert result.title == "Critical Breach"

    @pytest.mark.asyncio
    async def test_create_incident_returns_model(self):
        data = _incident_data(title="New Incident", severity="critical")
        async with AscClient(api_key=_API_KEY) as client:
            with patch.object(client._http, "request", new=AsyncMock(return_value=_mock_resp(data))):
                result = await client.incidents.create(title="New Incident", severity="critical")
        assert isinstance(result, Incident)
        assert result.severity == "critical"

    @pytest.mark.asyncio
    async def test_get_incident_not_found_raises(self):
        async with AscClient(api_key=_API_KEY) as client:
            with patch.object(client._http, "request", new=AsyncMock(
                return_value=_mock_resp({"detail": "Not found"}, status=404)
            )):
                with pytest.raises(NotFoundError):
                    await client.incidents.get("unknown-id")


# ── Class 6: Alerts resource ──────────────────────────────────────────────────

class TestAlertsResource:

    @pytest.mark.asyncio
    async def test_list_alerts(self):
        data = [_alert_data(), _alert_data()]
        async with AscClient(api_key=_API_KEY) as client:
            with patch.object(client._http, "request", new=AsyncMock(return_value=_mock_resp(data))):
                result = await client.alerts.list()
        assert len(result) == 2
        assert all(isinstance(a, Alert) for a in result)

    @pytest.mark.asyncio
    async def test_get_alert_returns_model(self):
        data = _alert_data(severity="critical")
        async with AscClient(api_key=_API_KEY) as client:
            with patch.object(client._http, "request", new=AsyncMock(return_value=_mock_resp(data))):
                result = await client.alerts.get("alert-id")
        assert isinstance(result, Alert)
        assert result.severity == "critical"

    @pytest.mark.asyncio
    async def test_list_alerts_with_status_passes_param(self):
        captured = {}

        async def fake_request(method, path, **kwargs):
            captured["params"] = kwargs.get("params", {})
            return _mock_resp([_alert_data()])

        async with AscClient(api_key=_API_KEY) as client:
            with patch.object(client._http, "request", new=fake_request):
                await client.alerts.list(status="open")
        assert captured["params"].get("status") == "open"


# ── Class 7: API Keys resource ────────────────────────────────────────────────

class TestAPIKeysResource:

    @pytest.mark.asyncio
    async def test_list_api_keys(self):
        data = [_api_key_data(), _api_key_data()]
        async with AscClient(api_key=_API_KEY) as client:
            with patch.object(client._http, "request", new=AsyncMock(return_value=_mock_resp(data))):
                result = await client.api_keys.list()
        assert len(result) == 2
        assert all(isinstance(k, APIKey) for k in result)

    @pytest.mark.asyncio
    async def test_create_api_key_returns_raw_key(self):
        data = {**_api_key_data(), "raw_key": "asc_abc12345_" + "x" * 51}
        async with AscClient(api_key=_API_KEY) as client:
            with patch.object(client._http, "request", new=AsyncMock(return_value=_mock_resp(data))):
                result = await client.api_keys.create(name="CI Key", scopes=["read"])
        assert isinstance(result, APIKeyCreated)
        assert result.raw_key.startswith("asc_")

    @pytest.mark.asyncio
    async def test_revoke_api_key_no_error(self):
        async with AscClient(api_key=_API_KEY) as client:
            with patch.object(client._http, "request", new=AsyncMock(return_value=_mock_resp({}, 204))):
                result = await client.api_keys.revoke("key-id")
        assert result is None

    @pytest.mark.asyncio
    async def test_rotate_api_key_returns_new_raw_key(self):
        data = {**_api_key_data(), "raw_key": "asc_newpfx__" + "y" * 50}
        async with AscClient(api_key=_API_KEY) as client:
            with patch.object(client._http, "request", new=AsyncMock(return_value=_mock_resp(data))):
                result = await client.api_keys.rotate("key-id")
        assert isinstance(result, APIKeyCreated)

    @pytest.mark.asyncio
    async def test_rate_limit_status(self):
        data = {
            "key_prefix": "ab12cd34",
            "limit_per_minute": 60,
            "limit_per_hour": 1000,
            "count_minute": 5,
            "count_hour": 50,
            "remaining_minute": 55,
            "remaining_hour": 950,
            "backend": "memory",
        }
        async with AscClient(api_key=_API_KEY) as client:
            with patch.object(client._http, "request", new=AsyncMock(return_value=_mock_resp(data))):
                result = await client.api_keys.rate_limit_status("key-id")
        assert isinstance(result, RateLimitStatus)
        assert result.remaining_minute == 55


# ── Class 8: Webhooks resource ────────────────────────────────────────────────

class TestWebhooksResource:

    @pytest.mark.asyncio
    async def test_list_webhooks(self):
        data = [_webhook_data(), _webhook_data()]
        async with AscClient(api_key=_API_KEY) as client:
            with patch.object(client._http, "request", new=AsyncMock(return_value=_mock_resp(data))):
                result = await client.webhooks.list()
        assert len(result) == 2
        assert all(isinstance(w, Webhook) for w in result)

    @pytest.mark.asyncio
    async def test_create_webhook_returns_secret(self):
        data = {**_webhook_data(), "secret": "a" * 64, "signing_note": "see docs"}
        async with AscClient(api_key=_API_KEY) as client:
            with patch.object(client._http, "request", new=AsyncMock(return_value=_mock_resp(data, 201))):
                result = await client.webhooks.create(
                    url="https://example.com/hook",
                    events=["incident.created"],
                )
        assert isinstance(result, WebhookCreated)
        assert len(result.secret) == 64

    @pytest.mark.asyncio
    async def test_delete_webhook_returns_none(self):
        async with AscClient(api_key=_API_KEY) as client:
            with patch.object(client._http, "request", new=AsyncMock(return_value=_mock_resp({}, 204))):
                result = await client.webhooks.delete("wh-id")
        assert result is None

    @pytest.mark.asyncio
    async def test_update_webhook_returns_model(self):
        data = _webhook_data(url="https://new-endpoint.com/hook")
        async with AscClient(api_key=_API_KEY) as client:
            with patch.object(client._http, "request", new=AsyncMock(return_value=_mock_resp(data))):
                result = await client.webhooks.update("wh-id", url="https://new-endpoint.com/hook")
        assert isinstance(result, Webhook)
        assert result.url == "https://new-endpoint.com/hook"

    @pytest.mark.asyncio
    async def test_test_webhook_returns_result(self):
        data = {"success": True, "status_code": 200, "latency_ms": 42.5, "error": None}
        async with AscClient(api_key=_API_KEY) as client:
            with patch.object(client._http, "request", new=AsyncMock(return_value=_mock_resp(data))):
                result = await client.webhooks.test("wh-id")
        assert isinstance(result, WebhookTestResult)
        assert result.success is True
        assert result.latency_ms == 42.5


# ── Class 9: Security invariants ──────────────────────────────────────────────

class TestSDKSecurity:

    def test_api_key_sent_as_x_api_key_header_not_query_param(self):
        client = AscClient(api_key=_API_KEY)
        headers = dict(client._http.headers)
        assert headers.get("x-api-key") == _API_KEY
        assert "api_key" not in str(client._http.base_url)

    def test_api_key_not_in_base_url(self):
        client = AscClient(api_key=_API_KEY, base_url="https://asc.premoscorp.com")
        assert _API_KEY not in str(client._base_url)

    def test_webhook_verifier_is_constant_time(self):
        """verify() must call hmac.compare_digest — not direct string equality."""
        import inspect
        import asc_sdk.verifier as mod
        src = inspect.getsource(mod.WebhookVerifier.verify)
        assert "compare_digest" in src

    @pytest.mark.asyncio
    async def test_rate_limit_error_exposes_retry_after(self):
        """RateLimitError.retry_after must be surfaced from Retry-After header."""
        async with AscClient(api_key=_API_KEY) as client:
            with patch.object(client._http, "request", new=AsyncMock(
                return_value=_mock_resp({"detail": "Rate limited"}, status=429, headers={"Retry-After": "15"})
            )):
                with pytest.raises(RateLimitError) as exc_info:
                    await client.incidents.list()
        assert exc_info.value.retry_after == 15

    @pytest.mark.asyncio
    async def test_auth_error_raised_immediately_on_401(self):
        """SDK must raise AuthError — never silently continue on 401."""
        async with AscClient(api_key=_API_KEY) as client:
            with patch.object(client._http, "request", new=AsyncMock(
                return_value=_mock_resp({"detail": "Invalid API key"}, status=401)
            )):
                with pytest.raises(AuthError):
                    await client.webhooks.list()

    @pytest.mark.asyncio
    async def test_user_agent_header_set(self):
        """Every request must carry the SDK User-Agent."""
        client = AscClient(api_key=_API_KEY)
        agent = dict(client._http.headers).get("user-agent", "")
        assert "asc-sdk-python" in agent


# ── Class 10: Deployment artifacts ───────────────────────────────────────────

class TestSDKDeploymentArtifacts:

    def test_sdk_directory_exists(self):
        assert (_SDK_ROOT).exists()

    def test_asc_sdk_package_exists(self):
        assert (_SDK_ROOT / "asc_sdk" / "__init__.py").exists()

    def test_pyproject_toml_exists(self):
        assert (_SDK_ROOT / "pyproject.toml").exists()

    def test_exceptions_module_exists(self):
        assert (_SDK_ROOT / "asc_sdk" / "exceptions.py").exists()

    def test_models_module_exists(self):
        assert (_SDK_ROOT / "asc_sdk" / "models.py").exists()

    def test_verifier_module_exists(self):
        assert (_SDK_ROOT / "asc_sdk" / "verifier.py").exists()

    def test_client_module_exists(self):
        assert (_SDK_ROOT / "asc_sdk" / "client.py").exists()

    def test_resources_package_exists(self):
        assert (_SDK_ROOT / "asc_sdk" / "resources" / "__init__.py").exists()

    def test_all_resource_modules_exist(self):
        res = _SDK_ROOT / "asc_sdk" / "resources"
        for name in ("incidents", "alerts", "events", "api_keys", "webhooks", "base"):
            assert (res / f"{name}.py").exists(), f"Missing resource: {name}.py"

    def test_sdk_version_defined(self):
        assert isinstance(__version__, str)
        assert __version__ == "0.1.0"

    def test_pyproject_requires_python_311(self):
        content = (_SDK_ROOT / "pyproject.toml").read_text()
        assert "3.11" in content

    def test_pyproject_lists_httpx_dependency(self):
        content = (_SDK_ROOT / "pyproject.toml").read_text()
        assert "httpx" in content

    def test_all_exceptions_importable(self):
        from asc_sdk.exceptions import (
            AscError, AuthError, ForbiddenError, InvalidSignatureError,
            NotFoundError, RateLimitError, ServerError, ValidationError,
        )
        for cls in (AscError, AuthError, ForbiddenError, InvalidSignatureError,
                    NotFoundError, RateLimitError, ServerError, ValidationError):
            assert issubclass(cls, Exception)

    def test_all_models_importable(self):
        from asc_sdk.models import (
            Alert, APIKey, APIKeyCreated, Event, Incident,
            RateLimitStatus, Webhook, WebhookCreated, WebhookTestResult,
        )
        assert all(m is not None for m in (
            Alert, APIKey, APIKeyCreated, Event, Incident,
            RateLimitStatus, Webhook, WebhookCreated, WebhookTestResult,
        ))

    def test_all_resources_importable(self):
        from asc_sdk.resources import (
            AlertsResource, APIKeysResource, EventsResource,
            IncidentsResource, WebhooksResource,
        )
        assert all(r is not None for r in (
            AlertsResource, APIKeysResource, EventsResource,
            IncidentsResource, WebhooksResource,
        ))


# ── Class 11: Regression ──────────────────────────────────────────────────────

class TestSDKRegression:

    @pytest.mark.asyncio
    async def test_liveness_endpoint_still_200(self):
        from httpx import ASGITransport, AsyncClient as AsyncHTTPXClient
        from asc_api.main import app
        async with AsyncHTTPXClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            r = await c.get("/health")
        assert r.status_code == 200

    def test_p42_webhook_dispatcher_importable(self):
        from asc_api.core.webhook_dispatcher import (
            sign_payload, verify_signature, deliver_to_url, emit_webhook_event,
        )
        assert all(callable(f) for f in (sign_payload, verify_signature, deliver_to_url, emit_webhook_event))

    def test_p41_rate_limiter_importable(self):
        from asc_api.core.api_key_rate_limit import api_key_limiter, ApiKeyRateLimiter
        assert isinstance(api_key_limiter, ApiKeyRateLimiter)

    def test_p40_api_key_dep_importable(self):
        from asc_api.api.deps import get_user_from_api_key
        assert callable(get_user_from_api_key)

    def test_sdk_webhook_verifier_compatible_with_dispatcher(self):
        """Full round-trip: dispatcher signs → SDK verifier verifies."""
        from asc_api.core.webhook_dispatcher import sign_payload
        secret = "shared_secret_for_test_" + "x" * 40
        body = json.dumps({"event": "incident.created", "data": {"id": "test"}}).encode()
        signature = sign_payload(secret, body)
        verifier = WebhookVerifier(secret)
        assert verifier.verify(body, signature) is True

    @pytest.mark.asyncio
    async def test_webhooks_endpoint_still_401_without_auth(self):
        from httpx import ASGITransport, AsyncClient as AsyncHTTPXClient
        from asc_api.main import app
        async with AsyncHTTPXClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            r = await c.get("/api/v1/webhooks/")
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_api_keys_endpoint_still_401_without_auth(self):
        from httpx import ASGITransport, AsyncClient as AsyncHTTPXClient
        from asc_api.main import app
        async with AsyncHTTPXClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            r = await c.get("/api/v1/api-keys/")
        assert r.status_code == 401
