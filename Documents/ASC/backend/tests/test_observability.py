"""
Priority 12 — Monitoreo/Observabilidad test suite.

Covers:
  TestFormatUptime            — pure function, no I/O (8 tests)
  TestHealthLiveness          — GET /api/v1/health/liveness (5 tests)
  TestHealthReadiness         — GET /api/v1/health/readiness (6 tests)
  TestHealthSystem            — GET /api/v1/health/system (7 tests)
  TestAuditLogger             — log_auth_event / log_security_action (10 tests)
  TestRequestContextMiddleware— X-Request-ID header injection (6 tests)
  TestUnhandledErrorHandler   — 500 handler shape + no stack trace (4 tests)

Total: 46 tests
"""

import re
import uuid
from unittest.mock import patch

import pytest
import structlog
from structlog.testing import capture_logs

from app.api.v1.endpoints.health import format_uptime
from app.core.audit import log_auth_event, log_security_action


# ══════════════════════════════════════════════════════════════════════════════
#  TestFormatUptime
# ══════════════════════════════════════════════════════════════════════════════

class TestFormatUptime:
    """format_uptime() — pure function, deterministic output."""

    def test_zero_seconds(self):
        assert format_uptime(0) == "0s"

    def test_sub_minute(self):
        assert format_uptime(45) == "45s"

    def test_exactly_one_minute(self):
        assert format_uptime(60) == "1m 0s"

    def test_minutes_and_seconds(self):
        assert format_uptime(65) == "1m 5s"

    def test_exactly_one_hour(self):
        assert format_uptime(3_600) == "1h 0s"

    def test_hours_minutes_seconds(self):
        assert format_uptime(3_661) == "1h 1m 1s"

    def test_exactly_one_day(self):
        assert format_uptime(86_400) == "1d 0s"

    def test_days_hours_minutes_seconds(self):
        # 1d + 2h + 3m + 4s = 86400 + 7200 + 180 + 4 = 93784
        assert format_uptime(93_784) == "1d 2h 3m 4s"

    def test_large_value(self):
        # 10 days = 864_000 seconds
        result = format_uptime(864_000)
        assert result.startswith("10d")

    def test_float_input_is_truncated(self):
        # int() truncates
        assert format_uptime(int(61.9)) == "1m 1s"


# ══════════════════════════════════════════════════════════════════════════════
#  TestHealthLiveness
# ══════════════════════════════════════════════════════════════════════════════

class TestHealthLiveness:
    """GET /api/v1/health/liveness — no auth required."""

    @pytest.mark.asyncio
    async def test_status_200(self, client):
        resp = await client.get("/api/v1/health/liveness")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_status_field_is_alive(self, client):
        resp = await client.get("/api/v1/health/liveness")
        assert resp.json()["status"] == "alive"

    @pytest.mark.asyncio
    async def test_ts_field_present(self, client):
        resp = await client.get("/api/v1/health/liveness")
        assert "ts" in resp.json()

    @pytest.mark.asyncio
    async def test_ts_is_iso8601(self, client):
        resp = await client.get("/api/v1/health/liveness")
        ts = resp.json()["ts"]
        assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", ts), f"Not ISO-8601: {ts}"

    @pytest.mark.asyncio
    async def test_no_auth_required(self, client):
        # No Authorization header — must still return 200
        resp = await client.get("/api/v1/health/liveness")
        assert resp.status_code == 200


# ══════════════════════════════════════════════════════════════════════════════
#  TestHealthReadiness
# ══════════════════════════════════════════════════════════════════════════════

class TestHealthReadiness:
    """GET /api/v1/health/readiness — no auth, DB ping."""

    @pytest.mark.asyncio
    async def test_status_200(self, client):
        resp = await client.get("/api/v1/health/readiness")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_status_ready_with_working_db(self, client):
        with patch("app.api.v1.endpoints.health.settings") as mock_settings:
            mock_settings.REDIS_URL = ""  # disable Redis check — not available in test env
            resp = await client.get("/api/v1/health/readiness")
        assert resp.json()["status"] == "ready"

    @pytest.mark.asyncio
    async def test_checks_key_present(self, client):
        resp = await client.get("/api/v1/health/readiness")
        assert "checks" in resp.json()

    @pytest.mark.asyncio
    async def test_database_check_ok(self, client):
        body = (await client.get("/api/v1/health/readiness")).json()
        assert body["checks"]["database"]["ok"] is True

    @pytest.mark.asyncio
    async def test_database_check_detail_ok(self, client):
        body = (await client.get("/api/v1/health/readiness")).json()
        assert body["checks"]["database"]["detail"] == "ok"

    @pytest.mark.asyncio
    async def test_ts_field_present(self, client):
        body = (await client.get("/api/v1/health/readiness")).json()
        assert "ts" in body


# ══════════════════════════════════════════════════════════════════════════════
#  TestHealthSystem
# ══════════════════════════════════════════════════════════════════════════════

class TestHealthSystem:
    """GET /api/v1/health/system — requires JWT."""

    @pytest.mark.asyncio
    async def test_401_without_token(self, client):
        # HTTPBearer raises 403 when no Authorization header is present
        resp = await client.get("/api/v1/health/system")
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_200_with_admin_token(self, client, admin_headers):
        resp = await client.get("/api/v1/health/system", headers=admin_headers)
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_200_with_analyst_token(self, client, analyst_headers):
        resp = await client.get("/api/v1/health/system", headers=analyst_headers)
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_app_name_present(self, client, admin_headers):
        body = (await client.get("/api/v1/health/system", headers=admin_headers)).json()
        assert "app" in body
        assert body["app"] != ""

    @pytest.mark.asyncio
    async def test_version_present(self, client, admin_headers):
        body = (await client.get("/api/v1/health/system", headers=admin_headers)).json()
        assert "version" in body

    @pytest.mark.asyncio
    async def test_uptime_seconds_non_negative(self, client, admin_headers):
        body = (await client.get("/api/v1/health/system", headers=admin_headers)).json()
        assert body["uptime_seconds"] >= 0

    @pytest.mark.asyncio
    async def test_uptime_human_non_empty(self, client, admin_headers):
        body = (await client.get("/api/v1/health/system", headers=admin_headers)).json()
        assert len(body["uptime_human"]) > 0

    @pytest.mark.asyncio
    async def test_environment_field(self, client, admin_headers):
        body = (await client.get("/api/v1/health/system", headers=admin_headers)).json()
        assert body["environment"] in ("development", "production")

    @pytest.mark.asyncio
    async def test_ts_present(self, client, admin_headers):
        body = (await client.get("/api/v1/health/system", headers=admin_headers)).json()
        assert "ts" in body


# ══════════════════════════════════════════════════════════════════════════════
#  TestAuditLogger
# ══════════════════════════════════════════════════════════════════════════════

class TestAuditLogger:
    """log_auth_event() and log_security_action() — structlog capture_logs."""

    def test_log_auth_event_action_field(self):
        with capture_logs() as logs:
            log_auth_event("login_success", user_id="u-1", email="a@b.com")
        assert logs[0]["action"] == "login_success"

    def test_log_auth_event_email_field(self):
        with capture_logs() as logs:
            log_auth_event("login_failure", email="bad@test.com")
        assert logs[0]["email"] == "bad@test.com"

    def test_log_auth_event_user_id_as_string(self):
        with capture_logs() as logs:
            log_auth_event("login_success", user_id=42)  # type: ignore[arg-type]
        assert logs[0]["user_id"] == "42"

    def test_log_auth_event_user_id_none_allowed(self):
        with capture_logs() as logs:
            log_auth_event("login_failure")  # no user_id — unauthenticated failure
        assert logs[0]["user_id"] is None

    def test_log_auth_event_ts_present(self):
        with capture_logs() as logs:
            log_auth_event("logout", user_id="u-1")
        assert "ts" in logs[0]

    def test_log_auth_event_no_password_field(self):
        with capture_logs() as logs:
            log_auth_event("login_success", user_id="u-1", email="a@b.com")
        event = logs[0]
        assert "password" not in event
        assert "hashed_password" not in event
        assert "token" not in event

    def test_log_security_action_action_field(self):
        with capture_logs() as logs:
            log_security_action(
                "playbook_trigger",
                user_id="u-1",
                role="analyst",
                resource="playbook",
                resource_id="PB-001",
            )
        assert logs[0]["action"] == "playbook_trigger"

    def test_log_security_action_role_and_resource(self):
        with capture_logs() as logs:
            log_security_action(
                "neutralize_execute",
                user_id="u-2",
                role="admin",
                resource="neutralization",
                resource_id="act-999",
            )
        event = logs[0]
        assert event["role"] == "admin"
        assert event["resource"] == "neutralization"
        assert event["resource_id"] == "act-999"

    def test_log_security_action_status_default_ok(self):
        with capture_logs() as logs:
            log_security_action("adapter_test", user_id="u-3", role="analyst", resource="adapter")
        assert logs[0]["status"] == "ok"

    def test_log_security_action_status_error(self):
        with capture_logs() as logs:
            log_security_action(
                "neutralize_execute", user_id="u-4", role="analyst",
                resource="neutralization", status="error",
            )
        assert logs[0]["status"] == "error"


# ══════════════════════════════════════════════════════════════════════════════
#  TestRequestContextMiddleware
# ══════════════════════════════════════════════════════════════════════════════

class TestRequestContextMiddleware:
    """RequestContextMiddleware — X-Request-ID injection via the test client."""

    @pytest.mark.asyncio
    async def test_response_has_request_id_header(self, client):
        resp = await client.get("/health")
        assert "x-request-id" in resp.headers

    @pytest.mark.asyncio
    async def test_auto_generated_id_is_valid_uuid(self, client):
        resp = await client.get("/health")
        rid = resp.headers["x-request-id"]
        uuid.UUID(rid)  # raises ValueError if not a valid UUID

    @pytest.mark.asyncio
    async def test_client_supplied_id_is_preserved(self, client):
        custom = str(uuid.uuid4())
        resp = await client.get("/health", headers={"X-Request-ID": custom})
        assert resp.headers["x-request-id"] == custom

    @pytest.mark.asyncio
    async def test_different_requests_get_different_ids(self, client):
        r1 = await client.get("/health")
        r2 = await client.get("/health")
        assert r1.headers["x-request-id"] != r2.headers["x-request-id"]

    @pytest.mark.asyncio
    async def test_request_id_propagated_on_api_endpoint(self, client):
        resp = await client.get("/api/v1/health/liveness")
        assert "x-request-id" in resp.headers

    @pytest.mark.asyncio
    async def test_request_id_header_on_404(self, client):
        resp = await client.get("/api/v1/nonexistent-route-xyz")
        # Middleware still runs even for 404
        assert "x-request-id" in resp.headers


# ══════════════════════════════════════════════════════════════════════════════
#  TestUnhandledErrorHandler
# ══════════════════════════════════════════════════════════════════════════════

class TestUnhandledErrorHandler:
    """The global exception handler must not leak internals to clients."""

    @pytest.mark.asyncio
    async def test_404_has_no_stack_trace(self, client):
        resp = await client.get("/api/v1/no-such-route")
        assert "traceback" not in resp.text.lower()
        assert "Traceback" not in resp.text

    @pytest.mark.asyncio
    async def test_401_response_has_detail_field(self, client):
        # HTTPBearer raises 403 (no header) or 401 (bad token) — always structured JSON
        resp = await client.get("/api/v1/health/system")
        assert resp.status_code in (401, 403)
        assert "detail" in resp.json()

    @pytest.mark.asyncio
    async def test_error_response_no_python_internals(self, client):
        resp = await client.get("/api/v1/no-such-route")
        body = resp.text
        assert "File \"" not in body
        assert "line " not in body or "line " not in body.lower()[:200]

    @pytest.mark.asyncio
    async def test_health_endpoint_returns_structured_json(self, client):
        resp = await client.get("/api/v1/health/liveness")
        assert resp.headers["content-type"].startswith("application/json")
        body = resp.json()
        assert isinstance(body, dict)


# ══════════════════════════════════════════════════════════════════════════════
#  TestAuditIntegration — audit calls fired from live endpoints
# ══════════════════════════════════════════════════════════════════════════════

class TestAuditIntegration:
    """Verify audit events are emitted when login/playbook endpoints are called."""

    @pytest.mark.asyncio
    async def test_login_success_fires_audit_event(self, client, admin_user):
        with capture_logs() as logs:
            resp = await client.post("/api/v1/auth/login", json={
                "email": admin_user.email,
                "password": "Admin@1234!",
            })
        assert resp.status_code == 200
        audit_events = [e for e in logs if e.get("action") == "login_success"]
        assert len(audit_events) == 1
        assert audit_events[0]["email"] == admin_user.email

    @pytest.mark.asyncio
    async def test_login_failure_fires_audit_event(self, client, admin_user):
        with capture_logs() as logs:
            resp = await client.post("/api/v1/auth/login", json={
                "email": admin_user.email,
                "password": "WrongPassword!",
            })
        assert resp.status_code == 401
        audit_events = [e for e in logs if e.get("action") == "login_failure"]
        assert len(audit_events) == 1

    @pytest.mark.asyncio
    async def test_login_failure_audit_has_no_password(self, client, admin_user):
        with capture_logs() as logs:
            await client.post("/api/v1/auth/login", json={
                "email": admin_user.email,
                "password": "WrongPassword!",
            })
        for event in logs:
            assert "password" not in event
            assert "WrongPassword" not in str(event)
