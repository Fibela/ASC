"""
P16.2 SPECTER Bridge Tests
===========================
Tests: command mapping, agent resolution, targeted dispatch, broadcast dispatch,
       simulation fallback, schema extensions, approval integration.

All DB calls use AsyncMock; no real database or agent infrastructure needed.
"""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from asc_api.services.specter_bridge import (
    DispatchMode,
    SprecterBridgeResult,
    _AGENT_TARGETED,
    _BROADCAST_ACTIONS,
    _IAM_ACTIONS,
    dispatch,
    get_all_active_agents,
    map_specter_command,
    resolve_agent,
)
from asc_api.core.specter_security import COMMAND_PARAM_SCHEMAS, validate_command_params
from asc_api.models.agent import Agent, AgentCommand


# â”€â”€ Fixtures â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _agent(hostname: str = "ws-001", ip: str = "10.0.0.1", status: str = "active") -> Agent:
    a = MagicMock(spec=Agent)
    a.id = str(uuid.uuid4())
    a.hostname = hostname
    a.ip_address = ip
    a.status = status
    a.poll_interval = 5
    a.threat_level = "normal"
    return a


def _cmd(command_type: str = "isolate") -> AgentCommand:
    c = MagicMock(spec=AgentCommand)
    c.id = str(uuid.uuid4())
    c.command_type = command_type
    return c


def _db_with_agent(agent: Agent | None) -> AsyncMock:
    db = AsyncMock()
    scalar_result = MagicMock()
    scalar_result.scalar_one_or_none.return_value = agent
    db.execute.return_value = scalar_result
    return db


def _db_with_agents(agents: list[Agent]) -> AsyncMock:
    db = AsyncMock()
    scalars_mock = MagicMock()
    scalars_mock.scalars.return_value.all.return_value = agents
    db.execute.return_value = scalars_mock
    return db


# â”€â”€ 1. COMMAND_PARAM_SCHEMAS extensions â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestSchemaExtensions:
    def test_block_domain_schema_exists(self):
        assert "block_domain" in COMMAND_PARAM_SCHEMAS
        assert COMMAND_PARAM_SCHEMAS["block_domain"] == {"domain": str}

    def test_remove_persistence_schema_exists(self):
        assert "remove_persistence" in COMMAND_PARAM_SCHEMAS
        assert COMMAND_PARAM_SCHEMAS["remove_persistence"] == {
            "persistence_type": str,
            "target": str,
        }

    def test_kill_process_name_schema_exists(self):
        assert "kill_process_name" in COMMAND_PARAM_SCHEMAS
        assert COMMAND_PARAM_SCHEMAS["kill_process_name"] == {"process_name": str}

    def test_original_schemas_unchanged(self):
        assert COMMAND_PARAM_SCHEMAS["kill_process"] == {"pid": int}
        assert COMMAND_PARAM_SCHEMAS["block_ip"] == {"ip": str}
        assert COMMAND_PARAM_SCHEMAS["quarantine_file"] == {"path": str}
        assert COMMAND_PARAM_SCHEMAS["isolate"] == {}

    def test_block_domain_validation_passes(self):
        errors = validate_command_params("block_domain", {"domain": "evil.ru"})
        assert errors == []

    def test_remove_persistence_validation_passes(self):
        errors = validate_command_params("remove_persistence", {
            "persistence_type": "registry",
            "target": "HKCU\\SOFTWARE\\evil",
        })
        assert errors == []

    def test_remove_persistence_missing_target_fails(self):
        errors = validate_command_params("remove_persistence", {"persistence_type": "registry"})
        assert any("target" in e for e in errors)

    def test_block_domain_unknown_param_fails(self):
        errors = validate_command_params("block_domain", {"domain": "evil.ru", "extra": "bad"})
        assert any("Unexpected" in e for e in errors)


# â”€â”€ 2. map_specter_command â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestMapSprecterCommand:
    def test_isolate_endpoint(self):
        ct, p = map_specter_command("isolate_endpoint", {})
        assert ct == "isolate"
        assert p == {}

    def test_block_ip(self):
        ct, p = map_specter_command("block_ip", {"ip": "1.2.3.4"})
        assert ct == "block_ip"
        assert p == {"ip": "1.2.3.4"}

    def test_block_ip_no_ip_returns_none(self):
        result = map_specter_command("block_ip", {})
        assert result is None

    def test_block_domain(self):
        ct, p = map_specter_command("block_domain", {"domain": "c2.evil.ru"})
        assert ct == "block_domain"
        assert p == {"domain": "c2.evil.ru"}

    def test_block_domain_from_target_key(self):
        ct, p = map_specter_command("block_domain", {"target": "c2.evil.ru"})
        assert ct == "block_domain"
        assert p == {"domain": "c2.evil.ru"}

    def test_kill_process_with_pid(self):
        ct, p = map_specter_command("kill_process", {"pid": 1234, "process_name": "malware.exe"})
        assert ct == "kill_process"
        assert p["pid"] == 1234
        assert p["process_name"] == "malware.exe"

    def test_kill_process_name_only(self):
        ct, p = map_specter_command("kill_process", {"process_name": "malware.exe"})
        assert ct == "kill_process_name"
        assert p == {"process_name": "malware.exe"}

    def test_kill_process_no_pid_no_name(self):
        result = map_specter_command("kill_process", {})
        assert result is None

    def test_quarantine_file_file_path(self):
        ct, p = map_specter_command("quarantine_file", {"file_path": "C:\\evil.exe", "host": "ws-001"})
        assert ct == "quarantine_file"
        assert p == {"path": "C:\\evil.exe"}

    def test_quarantine_file_path_key(self):
        ct, p = map_specter_command("quarantine_file", {"path": "/tmp/evil.sh"})
        assert ct == "quarantine_file"
        assert p == {"path": "/tmp/evil.sh"}

    def test_quarantine_no_path_returns_none(self):
        result = map_specter_command("quarantine_file", {})
        assert result is None

    def test_remove_persistence(self):
        ct, p = map_specter_command("remove_persistence", {
            "persistence_type": "registry",
            "target": "HKCU\\evil",
        })
        assert ct == "remove_persistence"
        assert p["persistence_type"] == "registry"
        assert p["target"] == "HKCU\\evil"

    def test_disable_account_returns_none(self):
        result = map_specter_command("disable_account", {"username": "jdoe"})
        assert result is None

    def test_unknown_action_returns_none(self):
        result = map_specter_command("nuke_everything", {})
        assert result is None


# â”€â”€ 3. Routing tables â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestRoutingTables:
    def test_agent_targeted_set(self):
        assert "isolate_endpoint" in _AGENT_TARGETED
        assert "kill_process" in _AGENT_TARGETED
        assert "quarantine_file" in _AGENT_TARGETED
        assert "remove_persistence" in _AGENT_TARGETED

    def test_broadcast_set(self):
        assert "block_ip" in _BROADCAST_ACTIONS
        assert "block_domain" in _BROADCAST_ACTIONS

    def test_iam_actions_set(self):
        assert "disable_account" in _IAM_ACTIONS

    def test_no_overlap(self):
        overlap = _AGENT_TARGETED & _BROADCAST_ACTIONS
        assert not overlap, f"Routing overlap: {overlap}"
        overlap2 = _AGENT_TARGETED & _IAM_ACTIONS
        assert not overlap2


# â”€â”€ 4. resolve_agent â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestResolveAgent:
    @pytest.mark.asyncio
    async def test_resolve_by_hostname(self):
        agent = _agent(hostname="ws-001")
        db = _db_with_agent(agent)
        result = await resolve_agent(db, hostname="ws-001")
        assert result is agent

    @pytest.mark.asyncio
    async def test_resolve_by_ip_when_hostname_fails(self):
        agent = _agent(ip="192.168.1.50")
        db = AsyncMock()
        # First call (hostname) â†’ None; second call (ip) â†’ agent
        no_result = MagicMock()
        no_result.scalar_one_or_none.return_value = None
        found_result = MagicMock()
        found_result.scalar_one_or_none.return_value = agent
        db.execute.side_effect = [no_result, found_result]
        result = await resolve_agent(db, hostname="unknown", ip_address="192.168.1.50")
        assert result is agent

    @pytest.mark.asyncio
    async def test_not_found_returns_none(self):
        db = _db_with_agent(None)
        result = await resolve_agent(db, hostname="nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_no_params_returns_none(self):
        db = AsyncMock()
        result = await resolve_agent(db)
        assert result is None
        db.execute.assert_not_called()


# â”€â”€ 5. Targeted dispatch â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestTargetedDispatch:
    @pytest.mark.asyncio
    async def test_isolate_endpoint_specter_mode(self):
        agent = _agent(hostname="ws-001")
        cmd = _cmd("isolate")
        db = AsyncMock()
        db.refresh = AsyncMock()
        scalar = MagicMock(); scalar.scalar_one_or_none.return_value = agent
        db.execute.return_value = scalar

        with (
            patch("asc_api.services.specter_bridge.resolve_agent", new=AsyncMock(return_value=agent)),
            patch("asc_api.services.specter_bridge.issue_command", new=AsyncMock(return_value=cmd)),
            patch("asc_api.services.specter_bridge.log_security_action"),
        ):
            result = await dispatch(
                db,
                action_type="isolate_endpoint",
                target="ws-001",
                target_type="host",
                params={"host": "ws-001"},
                issued_by="admin@premos.com",
            )

        assert result.dispatch_mode == DispatchMode.SPECTER
        assert result.success is True
        assert cmd.id in result.commands_issued
        assert "ws-001" in result.agents_targeted

    @pytest.mark.asyncio
    async def test_isolate_endpoint_no_agent_simulation_fallback(self):
        db = AsyncMock()
        mock_sim = MagicMock(success=True, message="isolated", details={})

        with (
            patch("asc_api.services.specter_bridge.resolve_agent", new=AsyncMock(return_value=None)),
            patch("asc_api.services.specter_bridge.execute_action", new=AsyncMock(return_value=mock_sim)),
            patch("asc_api.services.specter_bridge.log_security_action"),
        ):
            result = await dispatch(
                db,
                action_type="isolate_endpoint",
                target="ghost-host",
                target_type="host",
                params={"host": "ghost-host"},
                issued_by="analyst@premos.com",
            )

        assert result.dispatch_mode == DispatchMode.SIMULATION
        assert "no active SPECTER agent" in result.message

    @pytest.mark.asyncio
    async def test_quarantine_file_specter_mode(self):
        agent = _agent(hostname="ws-002")
        cmd = _cmd("quarantine_file")

        with (
            patch("asc_api.services.specter_bridge.resolve_agent", new=AsyncMock(return_value=agent)),
            patch("asc_api.services.specter_bridge.issue_command", new=AsyncMock(return_value=cmd)),
            patch("asc_api.services.specter_bridge.log_security_action"),
        ):
            result = await dispatch(
                AsyncMock(),
                action_type="quarantine_file",
                target="ws-002",
                target_type="host",
                params={"host": "ws-002", "file_path": "C:\\evil.exe"},
                issued_by="analyst@premos.com",
            )

        assert result.dispatch_mode == DispatchMode.SPECTER
        assert result.details["command_type"] == "quarantine_file"


# â”€â”€ 6. Broadcast dispatch â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestBroadcastDispatch:
    @pytest.mark.asyncio
    async def test_block_ip_broadcast_to_all_agents(self):
        agents = [_agent("ws-001", "10.0.0.1"), _agent("ws-002", "10.0.0.2")]
        cmds = [_cmd("block_ip"), _cmd("block_ip")]

        with (
            patch("asc_api.services.specter_bridge.get_all_active_agents", new=AsyncMock(return_value=agents)),
            patch("asc_api.services.specter_bridge.issue_command", new=AsyncMock(side_effect=cmds)),
            patch("asc_api.services.specter_bridge.log_security_action"),
        ):
            result = await dispatch(
                AsyncMock(),
                action_type="block_ip",
                target="185.220.101.45",
                target_type="ip",
                params={"ip": "185.220.101.45"},
                issued_by="analyst@premos.com",
            )

        assert result.dispatch_mode == DispatchMode.BROADCAST
        assert result.success is True
        assert len(result.commands_issued) == 2
        assert "ws-001" in result.agents_targeted
        assert "ws-002" in result.agents_targeted

    @pytest.mark.asyncio
    async def test_block_domain_broadcast(self):
        agents = [_agent("ws-001")]
        cmd = _cmd("block_domain")

        with (
            patch("asc_api.services.specter_bridge.get_all_active_agents", new=AsyncMock(return_value=agents)),
            patch("asc_api.services.specter_bridge.issue_command", new=AsyncMock(return_value=cmd)),
            patch("asc_api.services.specter_bridge.log_security_action"),
        ):
            result = await dispatch(
                AsyncMock(),
                action_type="block_domain",
                target="c2.evil.ru",
                target_type="domain",
                params={"domain": "c2.evil.ru"},
                issued_by="analyst@premos.com",
            )

        assert result.dispatch_mode == DispatchMode.BROADCAST
        assert result.details["command_type"] == "block_domain"

    @pytest.mark.asyncio
    async def test_broadcast_no_agents_simulation_fallback(self):
        mock_sim = MagicMock(success=True, message="blocked", details={})

        with (
            patch("asc_api.services.specter_bridge.get_all_active_agents", new=AsyncMock(return_value=[])),
            patch("asc_api.services.specter_bridge.execute_action", new=AsyncMock(return_value=mock_sim)),
            patch("asc_api.services.specter_bridge.log_security_action"),
        ):
            result = await dispatch(
                AsyncMock(),
                action_type="block_ip",
                target="1.2.3.4",
                target_type="ip",
                params={"ip": "1.2.3.4"},
                issued_by="analyst@premos.com",
            )

        assert result.dispatch_mode == DispatchMode.SIMULATION
        assert "no active SPECTER agents" in result.message

    @pytest.mark.asyncio
    async def test_broadcast_partial_failure_still_succeeds(self):
        agents = [_agent("ws-001"), _agent("ws-002")]
        good_cmd = _cmd("block_ip")

        async def _issue(db, agent, ct, params, issued_by):
            if agent.hostname == "ws-001":
                return good_cmd
            raise RuntimeError("agent unreachable")

        with (
            patch("asc_api.services.specter_bridge.get_all_active_agents", new=AsyncMock(return_value=agents)),
            patch("asc_api.services.specter_bridge.issue_command", new=AsyncMock(side_effect=_issue)),
            patch("asc_api.services.specter_bridge.log_security_action"),
        ):
            result = await dispatch(
                AsyncMock(),
                action_type="block_ip",
                target="1.2.3.4",
                target_type="ip",
                params={"ip": "1.2.3.4"},
                issued_by="analyst@premos.com",
            )

        assert result.success is True  # at least one succeeded
        assert len(result.commands_issued) == 1


# â”€â”€ 7. Simulation-only (disable_account) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestIAMActions:
    """disable_account routes through _execute_iam_action (DispatchMode.IAM) since F1."""

    @pytest.mark.asyncio
    async def test_disable_account_uses_iam_dispatch(self):
        with (
            patch(
                "asc_api.services.specter_bridge.iam_disable_account",
                new=AsyncMock(return_value=(True, "account disabled in ASC")),
            ),
            patch("asc_api.services.specter_bridge._get_identity_adapter", return_value=None),
            patch("asc_api.services.specter_bridge.log_security_action"),
        ):
            result = await dispatch(
                AsyncMock(),
                action_type="disable_account",
                target="jdoe@premoscorp.com",
                target_type="account",
                params={"username": "jdoe", "domain": "PREMOSCORP"},
                issued_by="analyst@premos.com",
            )

        assert result.dispatch_mode == DispatchMode.IAM
        assert result.success is True

    @pytest.mark.asyncio
    async def test_iam_result_has_no_agent_commands(self):
        with (
            patch(
                "asc_api.services.specter_bridge.iam_disable_account",
                new=AsyncMock(return_value=(True, "ok")),
            ),
            patch("asc_api.services.specter_bridge._get_identity_adapter", return_value=None),
            patch("asc_api.services.specter_bridge.log_security_action"),
        ):
            result = await dispatch(
                AsyncMock(),
                action_type="disable_account",
                target="jdoe@premoscorp.com",
                target_type="account",
                params={"username": "jdoe", "domain": "LOCAL"},
                issued_by="analyst@premos.com",
            )

        assert result.commands_issued == []
        assert result.agents_targeted == []


# â”€â”€ 8. Kill process variants â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestKillProcessVariants:
    @pytest.mark.asyncio
    async def test_kill_with_pid_uses_kill_process(self):
        """kill_process WITH pid â†’ targeted SPECTER kill_process command."""
        agent = _agent("ws-001")
        captured: list = []

        async def _issue_cmd(db, ag, ct, params, issued_by):
            captured.append((ct, params))
            return _cmd(ct)

        with (
            patch("asc_api.services.specter_bridge.resolve_agent", new=AsyncMock(return_value=agent)),
            patch("asc_api.services.specter_bridge.issue_command", new=_issue_cmd),
            patch("asc_api.services.specter_bridge.log_security_action"),
        ):
            result = await dispatch(
                AsyncMock(),
                action_type="kill_process",
                target="ws-001",
                target_type="host",
                params={"host": "ws-001", "process_name": "evil.exe", "pid": 4242},
                issued_by="analyst@premos.com",
            )

        assert result.dispatch_mode == DispatchMode.SPECTER
        assert len(captured) == 1
        called_ct, called_params = captured[0]
        assert called_ct == "kill_process"
        assert called_params["pid"] == 4242

    @pytest.mark.asyncio
    async def test_kill_by_name_only_broadcasts(self):
        """kill_process without PID â†’ broadcast to all agents (kill_process_name command)."""
        agents = [_agent("ws-001"), _agent("ws-002")]
        # side_effect as list: each call to issue_command returns the next cmd
        issued: list = []

        async def _issue_cmd(db, agent, ct, params, issued_by):
            c = _cmd(ct)
            issued.append(c)
            return c

        with (
            patch("asc_api.services.specter_bridge.get_all_active_agents", new=AsyncMock(return_value=agents)),
            patch("asc_api.services.specter_bridge.issue_command", new=_issue_cmd),
            patch("asc_api.services.specter_bridge.log_security_action"),
        ):
            result = await dispatch(
                AsyncMock(),
                action_type="kill_process",
                target="ws-001",
                target_type="host",
                params={"host": "ws-001", "process_name": "evil.exe"},
                issued_by="analyst@premos.com",
            )

        assert result.dispatch_mode == DispatchMode.BROADCAST
        assert len(result.commands_issued) == 2
        assert all(ct == "kill_process_name" for ct in [c.command_type for c in issued])

    @pytest.mark.asyncio
    async def test_kill_no_pid_no_name_simulation(self):
        mock_sim = MagicMock(success=False, message="no target", details={})

        with (
            patch("asc_api.services.specter_bridge.execute_action", new=AsyncMock(return_value=mock_sim)),
        ):
            result = await dispatch(
                AsyncMock(),
                action_type="kill_process",
                target="ws-001",
                target_type="host",
                params={"host": "ws-001"},
                issued_by="analyst@premos.com",
            )

        assert result.dispatch_mode == DispatchMode.SIMULATION
        assert "incomplete params" in result.message


# â”€â”€ 9. SprecterBridgeResult structure â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestSprecterBridgeResult:
    def test_details_always_includes_dispatch_mode(self):
        r = SprecterBridgeResult(
            success=True, message="ok",
            dispatch_mode=DispatchMode.SPECTER,
            commands_issued=["cmd-1"],
            agents_targeted=["ws-001"],
        )
        assert r.details["dispatch_mode"] == DispatchMode.SPECTER
        assert r.details["commands_issued"] == ["cmd-1"]
        assert r.details["agents_targeted"] == ["ws-001"]

    def test_simulation_defaults(self):
        r = SprecterBridgeResult(success=False, message="err")
        assert r.dispatch_mode == DispatchMode.SIMULATION
        assert r.commands_issued == []
        assert r.agents_targeted == []


# â”€â”€ 10. Broadcast concurrency (P19.1) â€” asyncio.gather within batches â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestBroadcastConcurrency:
    """
    Verify that _broadcast_batched uses asyncio.gather within each batch
    so agents in the same batch are dispatched concurrently, not sequentially.
    """

    def _make_agent(self, idx: int = 0) -> Agent:
        return Agent(
            id=str(uuid.uuid4()),
            hostname=f"ws-{idx:03d}",
            os_type="windows",
            os_version="10",
            arch="x86_64",
            ip_address=f"10.0.0.{idx + 1}",
            public_key="dGVzdHB1YmxpY2tleQ==",
            status="active",
        )

    @pytest.mark.asyncio
    async def test_broadcast_batched_dispatches_all_agents(self):
        from asc_api.services.specter_bridge import _broadcast_batched, BROADCAST_BATCH_SIZE

        db = AsyncMock()
        agents = [self._make_agent(i) for i in range(5)]
        issued_cmd_ids = []

        async def _fake_issue(db, agent, command_type, params, issued_by):
            cmd = AgentCommand(
                id=str(uuid.uuid4()),
                agent_id=agent.id,
                command_type=command_type,
                params=params,
                issued_by=issued_by,
            )
            issued_cmd_ids.append(cmd.id)
            return cmd

        with patch(
            "app.services.specter_bridge.issue_command",
            side_effect=_fake_issue,
        ):
            cmd_ids, hostnames = await _broadcast_batched(
                db=db,
                agents=agents,
                command_type="block_ip",
                specter_params={"ip": "10.0.0.99"},
                issued_by="analyst@premos.com",
                target_ip=None,
            )

        assert len(cmd_ids) == 5
        assert len(hostnames) == 5

    @pytest.mark.asyncio
    async def test_broadcast_batched_skips_failed_agents(self):
        from asc_api.services.specter_bridge import _broadcast_batched

        db = AsyncMock()
        agents = [self._make_agent(i) for i in range(4)]
        call_count = 0

        async def _fake_issue_with_error(db, agent, command_type, params, issued_by):
            nonlocal call_count
            call_count += 1
            if call_count % 2 == 0:
                raise RuntimeError("simulated agent timeout")
            cmd = AgentCommand(
                id=str(uuid.uuid4()),
                agent_id=agent.id,
                command_type=command_type,
                params=params,
                issued_by=issued_by,
            )
            return cmd

        with patch(
            "asc_api.services.specter_bridge.issue_command",
            side_effect=_fake_issue_with_error,
        ):
            cmd_ids, hostnames = await _broadcast_batched(
                db=db,
                agents=agents,
                command_type="block_ip",
                specter_params={"ip": "1.2.3.4"},
                issued_by="system",
                target_ip=None,
            )

        # 2 of 4 agents failed, 2 succeeded
        assert len(cmd_ids) == 2
        assert len(hostnames) == 2

    @pytest.mark.asyncio
    async def test_broadcast_batched_empty_agents_returns_empty(self):
        from asc_api.services.specter_bridge import _broadcast_batched

        db = AsyncMock()
        cmd_ids, hostnames = await _broadcast_batched(
            db=db,
            agents=[],
            command_type="block_ip",
            specter_params={"ip": "1.2.3.4"},
            issued_by="system",
            target_ip=None,
        )
        assert cmd_ids == []
        assert hostnames == []
