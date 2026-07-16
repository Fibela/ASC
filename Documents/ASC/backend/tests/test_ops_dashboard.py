"""
P20 â€” Test Suite: Operational Dashboard + Neutralizer real-adapter wiring

Coverage
--------
TestFleetSummary         (6 tests)  â€” aggregation, connectivity buckets, at_risk, empty fleet
TestCommandMetrics       (7 tests)  â€” by_status, latency stats, success rate, empty window
TestInflightCommands     (5 tests)  â€” filter by status, age_seconds, limit, sort order
TestNeutralizationMetrics(6 tests)  â€” by_status/type/severity, escalations, approval_rate
TestOpsAuth              (4 tests)  â€” 401 unauthenticated, viewer blocked (if role-restricted)
TestNeutralizerFallback  (6 tests)  â€” block_ip/domain/account hit adapter; simulation fallback
TestNeutralizerSimOnly   (4 tests)  â€” isolate/kill/quarantine/remove always simulation

Total: 38 tests
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from asc_api.main import app
from asc_api.db.session import get_db
from asc_api.api.deps import get_analyst_or_admin, get_current_user
from asc_api.models.agent import Agent, AgentCommand
from asc_api.models.neutralization import NeutralizationAction
from asc_api.models.user import User
from asc_api.services import neutralizer


# â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _ts(minutes_ago: float = 0) -> datetime:
    return datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)


def _agent(status="active", threat_level="normal", last_seen_m: float | None = 2.0) -> Agent:
    a = MagicMock(spec=Agent)
    a.id = str(uuid.uuid4())
    a.status = status
    a.threat_level = threat_level
    a.last_seen = _ts(last_seen_m) if last_seen_m is not None else None
    return a


def _command(
    status: str = "completed",
    command_type: str = "isolate",
    issued_m: float = 5.0,
    completed_m: float | None = 4.0,
) -> AgentCommand:
    cmd = MagicMock(spec=AgentCommand)
    cmd.id = str(uuid.uuid4())
    cmd.agent_id = str(uuid.uuid4())
    cmd.command_type = command_type
    cmd.status = status
    cmd.issued_by = "analyst@asc.local"
    cmd.issued_at = _ts(issued_m)
    cmd.completed_at = _ts(completed_m) if completed_m is not None else None
    cmd.params = {}
    return cmd


def _action(
    status: str = "completed",
    action_type: str = "block_ip",
    severity: str = "high",
    created_m: float = 10.0,
    escalated: bool = False,
) -> NeutralizationAction:
    a = MagicMock(spec=NeutralizationAction)
    a.id = str(uuid.uuid4())
    a.action_type = action_type
    a.severity = severity
    a.status = status
    a.target = "192.168.1.1"
    a.initiated_by = "analyst@asc.local"
    a.created_at = _ts(created_m)
    a.escalated_at = _ts(5.0) if escalated else None
    return a


def _stub_user() -> User:
    u = MagicMock(spec=User)
    u.id = str(uuid.uuid4())
    u.email = "analyst@asc.local"
    u.role = "analyst"
    return u


def _mock_db_returning(rows: list) -> AsyncMock:
    db = AsyncMock()
    scalars_mock = MagicMock()
    scalars_mock.all.return_value = rows
    result_mock = MagicMock()
    result_mock.scalars.return_value = scalars_mock
    db.execute = AsyncMock(return_value=result_mock)
    return db


# â”€â”€ TestFleetSummary â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestFleetSummary:

    @pytest.mark.asyncio
    async def test_empty_fleet(self):
        db = _mock_db_returning([])
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.get("/api/v1/ops/fleet/summary")

        assert r.status_code == 200
        data = r.json()
        assert data["total_agents"] == 0
        assert data["at_risk"] == 0

    @pytest.mark.asyncio
    async def test_by_status_aggregation(self):
        agents = [
            _agent(status="active"), _agent(status="active"),
            _agent(status="compromised"),
        ]
        db = _mock_db_returning(agents)
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.get("/api/v1/ops/fleet/summary")

        data = r.json()
        assert data["by_status"]["active"] == 2
        assert data["by_status"]["compromised"] == 1

    @pytest.mark.asyncio
    async def test_at_risk_count(self):
        agents = [
            _agent(threat_level="critical"), _agent(threat_level="elevated"),
            _agent(threat_level="normal"),
        ]
        db = _mock_db_returning(agents)
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.get("/api/v1/ops/fleet/summary")

        data = r.json()
        assert data["at_risk"] == 2

    @pytest.mark.asyncio
    async def test_connectivity_online_5m(self):
        agents = [
            _agent(last_seen_m=2.0),   # online_5m
            _agent(last_seen_m=30.0),  # online_1h
            _agent(last_seen_m=90.0),  # offline
            _agent(last_seen_m=None),  # offline (never seen)
        ]
        db = _mock_db_returning(agents)
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.get("/api/v1/ops/fleet/summary")

        c = r.json()["connectivity"]
        assert c["online_5m"] == 1
        assert c["online_1h"] == 1
        assert c["offline"] == 2

    @pytest.mark.asyncio
    async def test_ts_field_present(self):
        db = _mock_db_returning([])
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.get("/api/v1/ops/fleet/summary")

        assert "ts" in r.json()

    @pytest.mark.asyncio
    async def test_by_threat_level_populated(self):
        agents = [_agent(threat_level="critical")] * 3 + [_agent(threat_level="normal")] * 2
        db = _mock_db_returning(agents)
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.get("/api/v1/ops/fleet/summary")

        tl = r.json()["by_threat_level"]
        assert tl["critical"] == 3
        assert tl["normal"] == 2

    def teardown_method(self):
        app.dependency_overrides.clear()


# â”€â”€ TestCommandMetrics â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestCommandMetrics:

    @pytest.mark.asyncio
    async def test_empty_returns_zero(self):
        db = _mock_db_returning([])
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.get("/api/v1/ops/commands/metrics?hours=24")

        data = r.json()
        assert data["total_commands"] == 0
        assert data["success_rate_pct"] is None
        assert data["latency"]["samples"] == 0

    @pytest.mark.asyncio
    async def test_success_rate_calculation(self):
        cmds = [
            _command(status="completed"), _command(status="completed"),
            _command(status="failed"),
        ]
        db = _mock_db_returning(cmds)
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.get("/api/v1/ops/commands/metrics?hours=24")

        data = r.json()
        # 2 completed, 1 failed â†’ 2/3 â‰ˆ 66.7%
        assert data["success_rate_pct"] == pytest.approx(66.7, abs=0.2)

    @pytest.mark.asyncio
    async def test_100_percent_success(self):
        cmds = [_command(status="completed")] * 5
        db = _mock_db_returning(cmds)
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.get("/api/v1/ops/commands/metrics?hours=24")

        assert r.json()["success_rate_pct"] == 100.0

    @pytest.mark.asyncio
    async def test_latency_stats_populated(self):
        # issued 10m ago, completed 5m ago â†’ ~300000ms
        cmds = [
            _command(status="completed", issued_m=10.0, completed_m=5.0),
        ]
        db = _mock_db_returning(cmds)
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.get("/api/v1/ops/commands/metrics?hours=24")

        lat = r.json()["latency"]
        assert lat["samples"] == 1
        assert lat["min_ms"] == lat["max_ms"]
        assert lat["p50_ms"] == lat["avg_ms"]

    @pytest.mark.asyncio
    async def test_by_status_counts(self):
        cmds = [
            _command(status="completed"),
            _command(status="failed"),
            _command(status="pending", completed_m=None),
        ]
        db = _mock_db_returning(cmds)
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.get("/api/v1/ops/commands/metrics?hours=24")

        bs = r.json()["by_status"]
        assert bs["completed"] == 1
        assert bs["failed"] == 1
        assert bs["pending"] == 1

    @pytest.mark.asyncio
    async def test_window_hours_param(self):
        db = _mock_db_returning([])
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.get("/api/v1/ops/commands/metrics?hours=72")

        assert r.status_code == 200
        assert r.json()["window_hours"] == 72

    @pytest.mark.asyncio
    async def test_invalid_hours_rejected(self):
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.get("/api/v1/ops/commands/metrics?hours=999")

        assert r.status_code == 422

    def teardown_method(self):
        app.dependency_overrides.clear()


# â”€â”€ TestInflightCommands â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestInflightCommands:

    @pytest.mark.asyncio
    async def test_empty_inflight(self):
        db = _mock_db_returning([])
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.get("/api/v1/ops/commands/inflight")

        data = r.json()
        assert data["total_inflight"] == 0
        assert data["commands"] == []

    @pytest.mark.asyncio
    async def test_age_seconds_computed(self):
        cmd = _command(status="pending", issued_m=5.0, completed_m=None)
        db = _mock_db_returning([cmd])
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.get("/api/v1/ops/commands/inflight")

        items = r.json()["commands"]
        assert len(items) == 1
        # ~300s ago; allow Â±10s for test latency
        assert 280 <= items[0]["age_seconds"] <= 320

    @pytest.mark.asyncio
    async def test_total_inflight_count(self):
        cmds = [_command(status="pending", completed_m=None)] * 3
        db = _mock_db_returning(cmds)
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.get("/api/v1/ops/commands/inflight")

        assert r.json()["total_inflight"] == 3

    @pytest.mark.asyncio
    async def test_response_fields_present(self):
        cmd = _command(status="executing", completed_m=None)
        db = _mock_db_returning([cmd])
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.get("/api/v1/ops/commands/inflight")

        item = r.json()["commands"][0]
        for field in ("id", "agent_id", "command_type", "status", "issued_by", "age_seconds"):
            assert field in item, f"Missing field: {field}"

    @pytest.mark.asyncio
    async def test_limit_param(self):
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.get("/api/v1/ops/commands/inflight?limit=501")

        assert r.status_code == 422

    def teardown_method(self):
        app.dependency_overrides.clear()


# â”€â”€ TestNeutralizationMetrics â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestNeutralizationMetrics:

    @pytest.mark.asyncio
    async def test_empty_window(self):
        db = _mock_db_returning([])
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.get("/api/v1/ops/neutralizations/metrics?hours=24")

        data = r.json()
        assert data["total_actions"] == 0
        assert data["escalation_count"] == 0
        assert data["approval_rate_pct"] is None

    @pytest.mark.asyncio
    async def test_escalations_listed(self):
        actions = [
            _action(status="escalated", escalated=True),
            _action(status="completed"),
        ]
        db = _mock_db_returning(actions)
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.get("/api/v1/ops/neutralizations/metrics?hours=24")

        data = r.json()
        assert data["escalation_count"] == 1
        assert len(data["escalations"]) == 1

    @pytest.mark.asyncio
    async def test_approval_rate(self):
        actions = [
            _action(status="completed"), _action(status="completed"),
            _action(status="rejected"),
        ]
        db = _mock_db_returning(actions)
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.get("/api/v1/ops/neutralizations/metrics?hours=24")

        # 2 approved, 1 rejected â†’ 66.7%
        assert r.json()["approval_rate_pct"] == pytest.approx(66.7, abs=0.2)

    @pytest.mark.asyncio
    async def test_by_severity_aggregation(self):
        actions = [
            _action(severity="critical"), _action(severity="critical"),
            _action(severity="medium"),
        ]
        db = _mock_db_returning(actions)
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.get("/api/v1/ops/neutralizations/metrics?hours=24")

        bsev = r.json()["by_severity"]
        assert bsev["critical"] == 2
        assert bsev["medium"] == 1

    @pytest.mark.asyncio
    async def test_escalations_capped_at_10(self):
        actions = [_action(status="escalated", escalated=True) for _ in range(15)]
        db = _mock_db_returning(actions)
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.get("/api/v1/ops/neutralizations/metrics?hours=24")

        data = r.json()
        assert data["escalation_count"] == 15
        assert len(data["escalations"]) == 10

    @pytest.mark.asyncio
    async def test_by_type_aggregation(self):
        actions = [
            _action(action_type="block_ip"), _action(action_type="block_ip"),
            _action(action_type="disable_account"),
        ]
        db = _mock_db_returning(actions)
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.get("/api/v1/ops/neutralizations/metrics?hours=24")

        bt = r.json()["by_type"]
        assert bt["block_ip"] == 2
        assert bt["disable_account"] == 1

    def teardown_method(self):
        app.dependency_overrides.clear()


# â”€â”€ TestOpsAuth â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestOpsAuth:

    @pytest.mark.asyncio
    async def test_fleet_summary_requires_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.get("/api/v1/ops/fleet/summary")
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_commands_metrics_requires_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.get("/api/v1/ops/commands/metrics")
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_inflight_requires_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.get("/api/v1/ops/commands/inflight")
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_neutralizations_requires_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.get("/api/v1/ops/neutralizations/metrics")
        assert r.status_code == 401

    def teardown_method(self):
        app.dependency_overrides.clear()


# â”€â”€ TestNeutralizerFallback â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestNeutralizerFallback:
    """block_ip/block_domain/disable_account: try adapter â†’ fallback to simulation."""

    @pytest.mark.asyncio
    async def test_block_ip_uses_real_adapter_when_configured(self):
        mock_fw = AsyncMock()
        mock_fw.block_ip = AsyncMock(return_value={"success": True, "message": "blocked by Fortinet"})
        with patch("asc_api.adapters.get_firewall_adapter", return_value=mock_fw):
            result = await neutralizer.block_ip("10.0.0.1", reason="test")
        assert result.success is True
        assert "[SIMULATION]" not in result.message
        mock_fw.block_ip.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_block_ip_falls_back_to_simulation_when_no_adapter(self):
        with patch("asc_api.adapters.get_firewall_adapter", return_value=None):
            result = await neutralizer.block_ip("10.0.0.1")
        assert result.success is False          # honestidad S103: una simulación no miente
        assert result.simulated is True
        assert result.status == "simulated"
        assert "[SIMULATION]" in result.message
        assert result.details.get("simulation") is True

    @pytest.mark.asyncio
    async def test_block_ip_falls_back_on_adapter_exception(self):
        mock_fw = AsyncMock()
        mock_fw.block_ip = AsyncMock(side_effect=RuntimeError("adapter timeout"))
        with patch("asc_api.adapters.get_firewall_adapter", return_value=mock_fw):
            result = await neutralizer.block_ip("10.0.0.2")
        assert result.success is False          # intento REAL que falló, no simulación (S103)
        assert result.simulated is False
        assert result.status == "failed"
        assert "FAILED" in result.message

    @pytest.mark.asyncio
    async def test_block_domain_uses_real_adapter(self):
        mock_fw = AsyncMock()
        mock_fw.block_domain = AsyncMock(return_value={"success": True, "message": "sinkholed"})
        with patch("asc_api.adapters.get_firewall_adapter", return_value=mock_fw):
            result = await neutralizer.block_domain("evil.com")
        assert result.success is True
        assert "[SIMULATION]" not in result.message

    @pytest.mark.asyncio
    async def test_disable_account_uses_real_adapter(self):
        mock_iam = AsyncMock()
        mock_iam.disable_account = AsyncMock(return_value={"success": True, "message": "account locked in AD"})
        with patch("asc_api.adapters.get_identity_adapter", return_value=mock_iam):
            result = await neutralizer.disable_account("malicious.user")
        assert result.success is True
        assert "[SIMULATION]" not in result.message

    @pytest.mark.asyncio
    async def test_disable_account_fallback_simulation(self):
        with patch("asc_api.adapters.get_identity_adapter", return_value=None):
            result = await neutralizer.disable_account("bad.actor", domain="CORP")
        assert result.success is False          # honestidad S103: una simulación no miente
        assert result.simulated is True
        assert result.status == "simulated"
        assert "[SIMULATION]" in result.message
        assert result.details.get("simulation") is True


# â”€â”€ TestNeutralizerSimOnly â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestNeutralizerSimOnly:
    """Agent-dependent actions must ALWAYS return simulation (with marker)."""

    @pytest.mark.asyncio
    async def test_isolate_endpoint_always_simulation(self):
        result = await neutralizer.isolate_endpoint("host-1")
        assert result.success is False          # honestidad S103: una simulación no miente
        assert result.simulated is True
        assert result.status == "simulated"
        assert "[SIMULATION]" in result.message
        assert result.details.get("simulation") is True

    @pytest.mark.asyncio
    async def test_kill_process_always_simulation(self):
        result = await neutralizer.kill_process("host-1", "malware.exe", pid=1234)
        assert result.success is False          # honestidad S103: una simulación no miente
        assert result.simulated is True
        assert result.status == "simulated"
        assert "[SIMULATION]" in result.message
        assert result.details.get("simulation") is True

    @pytest.mark.asyncio
    async def test_quarantine_file_always_simulation(self):
        result = await neutralizer.quarantine_file("host-1", "C:\\evil.exe")
        assert result.success is False          # honestidad S103: una simulación no miente
        assert result.simulated is True
        assert result.status == "simulated"
        assert "[SIMULATION]" in result.message
        assert result.details.get("simulation") is True

    @pytest.mark.asyncio
    async def test_remove_persistence_always_simulation(self):
        result = await neutralizer.remove_persistence("host-1", "registry", "HKCU\\Run\\malware")
        assert result.success is False          # honestidad S103: una simulación no miente
        assert result.simulated is True
        assert result.status == "simulated"
        assert "[SIMULATION]" in result.message
        assert result.details.get("simulation") is True
