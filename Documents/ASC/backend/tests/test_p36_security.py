"""
P36 — Security hardening & Command Center tests (FASE 3).

Coverage areas:
  1. specter_security.py schema additions (isolate_endpoint, log_query, extra params)
  2. agents.py _VALID_COMMAND_TYPES sync + _cmd_out extended fields
  3. GET /agents/{id}/command-history endpoint (new P36 API)
  4. FASE 3 Auth barriers — unauthenticated / wrong-role / expired token
  5. Shell injection detection (check_injection)
  6. Enrollment token logic (HMAC-SHA256, window tolerance)
  7. Command param validation edge cases (missing required, unexpected, type mismatch)
  8. Honeypot endpoint smoke tests

Test count: ≥ 55 tests across 8 classes.
"""
from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
import pytest_asyncio

from asc_api.core.specter_security import (
    COMMAND_EXTRA_PARAMS,
    COMMAND_PARAM_SCHEMAS,
    check_injection,
    generate_enrollment_token,
    validate_command_params,
    verify_enrollment_token,
)
from asc_api.api.v1.endpoints.agents import _VALID_COMMAND_TYPES, _cmd_out
from asc_api.models.agent import AgentCommand


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_cmd(
    command_type: str = "kill_process",
    status: str = "completed",
    result: dict | None = None,
    error: str | None = None,
) -> AgentCommand:
    cmd = AgentCommand(
        id=str(uuid.uuid4()),
        agent_id="agent-001",
        command_type=command_type,
        params={},
        signature="sig",
        status=status,
        issued_by="user-001",
    )
    cmd.issued_at  = datetime.now(timezone.utc)
    cmd.delivered_at = datetime.now(timezone.utc) if status != "pending" else None
    cmd.completed_at = datetime.now(timezone.utc) if status in ("completed", "failed") else None
    cmd.result = result
    cmd.error  = error
    return cmd


async def _make_agent_in_db(db) -> str:
    """Insert a minimal Agent row and return its id."""
    from asc_api.models.agent import Agent
    from asc_api.services.agent_commander import compute_poll_interval
    from asc_api.core.signing import generate_keypair

    priv, pub = generate_keypair()
    agent = Agent(
        id=str(uuid.uuid4()),
        hostname="test-host",
        os_type="linux",
        os_version="22.04",
        arch="x86_64",
        ip_address="10.0.0.1",
        public_key=pub,
        specter_version="1.0.0",
        poll_interval=compute_poll_interval("normal"),
    )
    db.add(agent)
    await db.commit()
    return agent.id


# ─────────────────────────────────────────────────────────────────────────────
# 1. Schema additions — isolate_endpoint + log_query + extra params
# ─────────────────────────────────────────────────────────────────────────────

class TestSpecterSchemaP36:
    """validate_command_params for P35 command types added in P36."""

    # ── isolate_endpoint ──────────────────────────────────────────────────────

    def test_isolate_endpoint_in_schema(self):
        assert "isolate_endpoint" in COMMAND_PARAM_SCHEMAS

    def test_isolate_endpoint_requires_asc_server_ip(self):
        errs = validate_command_params("isolate_endpoint", {})
        assert any("asc_server_ip" in e for e in errs)

    def test_isolate_endpoint_valid_minimal(self):
        errs = validate_command_params("isolate_endpoint", {"asc_server_ip": "10.0.0.1"})
        assert errs == []

    def test_isolate_endpoint_optional_port_allowed(self):
        errs = validate_command_params("isolate_endpoint", {"asc_server_ip": "10.0.0.1", "asc_server_port": 8443})
        assert errs == []

    def test_isolate_endpoint_optional_comment_allowed(self):
        errs = validate_command_params("isolate_endpoint", {"asc_server_ip": "10.0.0.1", "comment": "P36 test"})
        assert errs == []

    def test_isolate_endpoint_unexpected_param_rejected(self):
        errs = validate_command_params("isolate_endpoint", {"asc_server_ip": "10.0.0.1", "evil_param": "x"})
        assert any("Unexpected" in e for e in errs)

    def test_isolate_endpoint_wrong_ip_type_rejected(self):
        errs = validate_command_params("isolate_endpoint", {"asc_server_ip": 12345})
        assert any("asc_server_ip" in e for e in errs)

    # ── log_query ─────────────────────────────────────────────────────────────

    def test_log_query_in_schema(self):
        assert "log_query" in COMMAND_PARAM_SCHEMAS

    def test_log_query_requires_pattern(self):
        errs = validate_command_params("log_query", {"read_only": True})
        assert any("pattern" in e for e in errs)

    def test_log_query_requires_read_only(self):
        errs = validate_command_params("log_query", {"pattern": "sshd"})
        assert any("read_only" in e for e in errs)

    def test_log_query_valid_minimal(self):
        errs = validate_command_params("log_query", {"pattern": "sshd", "read_only": True})
        assert errs == []

    def test_log_query_optional_data_source_allowed(self):
        errs = validate_command_params("log_query", {"pattern": "x", "read_only": True, "data_source": "auth"})
        assert errs == []

    def test_log_query_optional_log_path_allowed(self):
        errs = validate_command_params("log_query", {"pattern": "x", "read_only": True, "data_source": "file", "log_path": "/var/log/app.log"})
        assert errs == []

    def test_log_query_optional_since_minutes_allowed(self):
        errs = validate_command_params("log_query", {"pattern": "x", "read_only": True, "since_minutes": 120})
        assert errs == []

    def test_log_query_optional_max_results_allowed(self):
        errs = validate_command_params("log_query", {"pattern": "x", "read_only": True, "max_results": 100})
        assert errs == []

    def test_log_query_optional_is_regex_allowed(self):
        errs = validate_command_params("log_query", {"pattern": "^ERR", "read_only": True, "is_regex": True})
        assert errs == []

    def test_log_query_unexpected_param_rejected(self):
        errs = validate_command_params("log_query", {"pattern": "x", "read_only": True, "write_mode": True})
        assert any("Unexpected" in e for e in errs)

    # ── other P35 optional extras ──────────────────────────────────────────────

    def test_unisolate_dry_run_allowed(self):
        errs = validate_command_params("unisolate", {"dry_run": True})
        assert errs == []

    def test_unisolate_unexpected_param_rejected(self):
        errs = validate_command_params("unisolate", {"force": True})
        assert any("Unexpected" in e for e in errs)

    def test_unblock_ip_direction_allowed(self):
        errs = validate_command_params("unblock_ip", {"ip": "1.2.3.4", "direction": "inbound"})
        assert errs == []

    def test_command_extra_params_dict_present(self):
        assert "isolate_endpoint" in COMMAND_EXTRA_PARAMS
        assert "log_query" in COMMAND_EXTRA_PARAMS
        assert "unisolate" in COMMAND_EXTRA_PARAMS
        assert "unblock_ip" in COMMAND_EXTRA_PARAMS


# ─────────────────────────────────────────────────────────────────────────────
# 2. _VALID_COMMAND_TYPES sync + _cmd_out extended fields
# ─────────────────────────────────────────────────────────────────────────────

class TestValidCommandTypesP36:
    def test_isolate_endpoint_in_valid_types(self):
        assert "isolate_endpoint" in _VALID_COMMAND_TYPES

    def test_log_query_in_valid_types(self):
        assert "log_query" in _VALID_COMMAND_TYPES

    def test_unblock_ip_in_valid_types(self):
        assert "unblock_ip" in _VALID_COMMAND_TYPES

    def test_unblock_domain_in_valid_types(self):
        assert "unblock_domain" in _VALID_COMMAND_TYPES

    def test_original_commands_still_present(self):
        for ct in ("kill_process", "block_ip", "isolate", "unisolate", "canary_ping"):
            assert ct in _VALID_COMMAND_TYPES


class TestCmdOutExtendedFields:
    def test_without_result_includes_lifecycle_fields(self):
        cmd = _make_cmd(status="pending")
        out = _cmd_out(cmd)
        assert "issued_by" in out
        assert "delivered_at" in out
        assert "completed_at" in out

    def test_without_result_excludes_result_key(self):
        cmd = _make_cmd()
        out = _cmd_out(cmd, include_result=False)
        assert "result" not in out
        assert "error" not in out

    def test_with_result_includes_result_and_error(self):
        cmd = _make_cmd(result={"match_count": 5}, error=None)
        out = _cmd_out(cmd, include_result=True)
        assert out["result"] == {"match_count": 5}
        assert out["error"] is None

    def test_failed_command_includes_error_message(self):
        cmd = _make_cmd(status="failed", error="iptables not found")
        out = _cmd_out(cmd, include_result=True)
        assert out["error"] == "iptables not found"

    def test_completed_at_is_isoformat_string_or_none(self):
        cmd = _make_cmd(status="completed")
        out = _cmd_out(cmd, include_result=True)
        # completed_at should be an ISO-format string
        assert isinstance(out["completed_at"], str)
        datetime.fromisoformat(out["completed_at"])  # must parse without error

    def test_pending_command_delivered_at_is_none(self):
        cmd = _make_cmd(status="pending")
        out = _cmd_out(cmd)
        assert out["delivered_at"] is None


# ─────────────────────────────────────────────────────────────────────────────
# 3. GET /agents/{id}/command-history endpoint
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestCommandHistoryEndpoint:

    async def test_no_auth_returns_401(self, client):
        r = await client.get("/api/v1/agents/fake-id/command-history")
        assert r.status_code == 401

    async def test_viewer_returns_403(self, client, viewer_headers):
        r = await client.get("/api/v1/agents/fake-id/command-history", headers=viewer_headers)
        assert r.status_code == 403

    async def test_unknown_agent_returns_404(self, client, analyst_headers):
        r = await client.get(f"/api/v1/agents/{uuid.uuid4()}/command-history", headers=analyst_headers)
        assert r.status_code == 404

    async def test_analyst_sees_empty_history(self, client, db, analyst_headers):
        agent_id = await _make_agent_in_db(db)
        r = await client.get(f"/api/v1/agents/{agent_id}/command-history", headers=analyst_headers)
        assert r.status_code == 200
        body = r.json()
        assert body["commands"] == []
        assert body["total"] == 0
        assert body["agent_id"] == agent_id

    async def test_admin_sees_issued_command(self, client, db, admin_headers, admin_user):
        from asc_api.services.agent_commander import issue_command
        from asc_api.core.config import get_settings

        agent_id = await _make_agent_in_db(db)
        # Issue a command via the service directly (bypasses HTTP auth layer)
        from asc_api.models.agent import Agent
        from sqlalchemy import select
        res = await db.execute(select(Agent).where(Agent.id == agent_id))
        agent = res.scalar_one()
        await issue_command(db, agent, "log_query", {"pattern": "sshd", "read_only": True}, str(admin_user.id))

        r = await client.get(f"/api/v1/agents/{agent_id}/command-history", headers=admin_headers)
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 1
        cmd = body["commands"][0]
        assert cmd["command_type"] == "log_query"
        assert "result" in cmd        # include_result=True on this endpoint

    async def test_limit_param_respected(self, client, db, analyst_headers):
        agent_id = await _make_agent_in_db(db)
        r = await client.get(
            f"/api/v1/agents/{agent_id}/command-history",
            params={"limit": 5},
            headers=analyst_headers,
        )
        assert r.status_code == 200

    async def test_hostname_included_in_response(self, client, db, analyst_headers):
        agent_id = await _make_agent_in_db(db)
        r = await client.get(f"/api/v1/agents/{agent_id}/command-history", headers=analyst_headers)
        assert r.status_code == 200
        assert r.json()["hostname"] == "test-host"


# ─────────────────────────────────────────────────────────────────────────────
# 4. FASE 3 — Auth barriers
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestFase3AuthBarriers:
    """Verify authentication and role enforcement across key endpoints."""

    async def test_no_token_agents_list_returns_401(self, client):
        r = await client.get("/api/v1/agents/")
        assert r.status_code == 401

    async def test_no_token_alerts_returns_401(self, client):
        r = await client.get("/api/v1/alerts/")
        assert r.status_code == 401

    async def test_no_token_neutralize_history_returns_401(self, client):
        r = await client.get("/api/v1/neutralize/history")
        assert r.status_code == 401

    async def test_no_token_admin_users_returns_401(self, client):
        r = await client.get("/api/v1/auth/users")
        assert r.status_code == 401

    async def test_viewer_cannot_issue_agent_command(self, client, db, viewer_headers):
        agent_id = await _make_agent_in_db(db)
        r = await client.post(
            f"/api/v1/agents/{agent_id}/command",
            json={"command_type": "kill_process", "params": {"pid": 1}},
            headers=viewer_headers,
        )
        assert r.status_code == 403

    async def test_viewer_cannot_access_admin_users(self, client, viewer_headers):
        r = await client.get("/api/v1/auth/users", headers=viewer_headers)
        assert r.status_code == 403

    async def test_analyst_cannot_deregister_agent(self, client, db, analyst_headers):
        agent_id = await _make_agent_in_db(db)
        r = await client.delete(f"/api/v1/agents/{agent_id}", headers=analyst_headers)
        assert r.status_code == 403

    async def test_malformed_token_returns_401(self, client):
        r = await client.get(
            "/api/v1/agents/",
            headers={"Authorization": "Bearer not.a.valid.jwt"},
        )
        assert r.status_code == 401

    async def test_analyst_can_list_agents(self, client, analyst_headers):
        r = await client.get("/api/v1/agents/", headers=analyst_headers)
        assert r.status_code == 200

    async def test_analyst_can_read_command_history(self, client, db, analyst_headers):
        agent_id = await _make_agent_in_db(db)
        r = await client.get(f"/api/v1/agents/{agent_id}/command-history", headers=analyst_headers)
        assert r.status_code == 200


# ─────────────────────────────────────────────────────────────────────────────
# 5. Shell injection detection
# ─────────────────────────────────────────────────────────────────────────────

class TestFase3InjectionDetection:
    """check_injection must flag dangerous metacharacters in string param values."""

    def test_semicolon_flagged(self):
        assert check_injection({"ip": "1.2.3.4; rm -rf /"}) != []

    def test_pipe_flagged(self):
        assert check_injection({"path": "/tmp/file | cat /etc/passwd"}) != []

    def test_backtick_flagged(self):
        assert check_injection({"pattern": "`id`"}) != []

    def test_dollar_sign_flagged(self):
        assert check_injection({"domain": "evil.com$(whoami)"}) != []

    def test_ampersand_flagged(self):
        assert check_injection({"process_name": "legit && malicious"}) != []

    def test_newline_flagged(self):
        assert check_injection({"ip": "1.2.3.4\nrm -rf /"}) != []

    def test_clean_ip_not_flagged(self):
        assert check_injection({"ip": "203.0.113.42"}) == []

    def test_clean_domain_not_flagged(self):
        assert check_injection({"domain": "evil.premoscorp.com"}) == []

    def test_clean_path_not_flagged(self):
        assert check_injection({"path": "/var/log/app.log"}) == []

    def test_integer_param_not_flagged(self):
        assert check_injection({"pid": 1234}) == []

    def test_boolean_param_not_flagged(self):
        assert check_injection({"read_only": True}) == []

    def test_multiple_clean_params_not_flagged(self):
        assert check_injection({"pattern": "sshd", "read_only": True, "since_minutes": 60}) == []

    def test_returns_flagged_key_names(self):
        flagged = check_injection({"clean": "ok", "evil": "x; y"})
        assert "evil" in flagged
        assert "clean" not in flagged


# ─────────────────────────────────────────────────────────────────────────────
# 6. Enrollment token
# ─────────────────────────────────────────────────────────────────────────────

class TestFase3EnrollmentToken:

    def test_valid_token_current_window(self):
        secret = "test-secret-p36"
        token = generate_enrollment_token(secret)
        assert verify_enrollment_token(secret, token) is True

    def test_invalid_token_rejected(self):
        assert verify_enrollment_token("secret", "badtoken") is False

    def test_empty_secret_dev_mode_always_passes(self):
        assert verify_enrollment_token("", "anything") is True

    def test_empty_token_rejected(self):
        assert verify_enrollment_token("secret", "") is False

    def test_previous_window_token_accepted(self):
        secret = "test-secret-p36"
        prev_token = generate_enrollment_token(secret, window_offset=-1)
        assert verify_enrollment_token(secret, prev_token) is True

    def test_next_window_token_rejected(self):
        secret = "test-secret-p36"
        future_token = generate_enrollment_token(secret, window_offset=+1)
        assert verify_enrollment_token(secret, future_token) is False

    def test_different_secrets_produce_different_tokens(self):
        t1 = generate_enrollment_token("secret-a")
        t2 = generate_enrollment_token("secret-b")
        assert t1 != t2

    def test_token_constant_within_same_window(self):
        secret = "stable-secret"
        t1 = generate_enrollment_token(secret)
        t2 = generate_enrollment_token(secret)
        assert t1 == t2


# ─────────────────────────────────────────────────────────────────────────────
# 7. Command param validation edge cases (FASE 3 input hardening)
# ─────────────────────────────────────────────────────────────────────────────

class TestFase3ParamValidation:

    def test_unknown_command_type_rejected(self):
        errs = validate_command_params("rm_rf_slash", {})
        assert any("Unknown command_type" in e for e in errs)

    def test_kill_process_wrong_pid_type(self):
        errs = validate_command_params("kill_process", {"pid": "1234"})
        assert any("pid" in e for e in errs)

    def test_block_ip_wrong_type(self):
        errs = validate_command_params("block_ip", {"ip": 12345})
        assert any("ip" in e for e in errs)

    def test_log_query_read_only_must_be_bool(self):
        errs = validate_command_params("log_query", {"pattern": "x", "read_only": "true"})
        assert any("read_only" in e for e in errs)

    def test_canary_ping_requires_nonce(self):
        errs = validate_command_params("canary_ping", {})
        assert any("nonce" in e for e in errs)

    def test_multiple_missing_params_all_reported(self):
        errs = validate_command_params("remove_persistence", {})
        keys_mentioned = " ".join(errs)
        assert "persistence_type" in keys_mentioned
        assert "target" in keys_mentioned

    def test_empty_params_for_no_param_command_ok(self):
        errs = validate_command_params("isolate", {})
        assert errs == []

    def test_collect_snapshot_empty_params_ok(self):
        errs = validate_command_params("collect_snapshot", {})
        assert errs == []


# ─────────────────────────────────────────────────────────────────────────────
# 8. Honeypot endpoint smoke tests
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestFase3HoneypotEndpoints:
    """Honeypot paths must return 200 with decoy content (never 404 or 500)."""

    async def test_probe_returns_200(self, client):
        r = await client.get("/api/v1/agents/probe")
        assert r.status_code == 200

    async def test_probe_returns_json(self, client):
        r = await client.get("/api/v1/agents/probe")
        body = r.json()
        assert isinstance(body, dict)
        assert len(body) > 0

    async def test_dump_returns_200(self, client):
        r = await client.get("/api/v1/agents/dump")
        assert r.status_code == 200

    async def test_dump_returns_json(self, client):
        r = await client.get("/api/v1/agents/dump")
        assert isinstance(r.json(), dict)

    async def test_export_returns_200(self, client):
        r = await client.get("/api/v1/agents/export")
        assert r.status_code == 200

    async def test_probe_no_auth_required(self, client):
        r = await client.get("/api/v1/agents/probe")
        # Honeypot deliberately has no auth gate — it must be reachable
        assert r.status_code != 401
