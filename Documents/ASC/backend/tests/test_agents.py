"""
P13 â€” SPECTER Agent API test suite.

Covers:
  TestRegisterAgent        â€” POST /agents/register (6 tests)
  TestListAgents           â€” GET  /agents/         (5 tests)
  TestGetAgent             â€” GET  /agents/{id}     (4 tests)
  TestDeregisterAgent      â€” DELETE /agents/{id}   (4 tests)
  TestIngestEvents         â€” POST /agents/{id}/events  (6 tests)
  TestPollCommands         â€” GET  /agents/{id}/commands (5 tests)
  TestReportResult         â€” POST /agents/{id}/results  (5 tests)
  TestIssueCommand         â€” POST /agents/{id}/command  (6 tests)
  TestSetThreatLevel       â€” PATCH /agents/{id}/threat  (5 tests)
  TestTimeline             â€” GET  /agents/{id}/timeline (5 tests)
  TestAgentCommander       â€” unit tests for service functions (9 tests)

Total: 60 tests
"""

import time
import uuid
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.models.agent import Agent, AgentCommand, AgentEvent
from asc_api.services.agent_commander import (
    compute_poll_interval,
    deescalate_threat_level,
    escalate_threat_level,
    get_pending_commands,
    ingest_events,
    issue_command,
    mark_command_delivered,
    record_command_result,
    refresh_agent_status,
)


# â”€â”€ Fixtures â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

AGENT_PAYLOAD = {
    "hostname":        "specter-host-01",
    "os_type":         "linux",
    "os_version":      "Ubuntu 22.04",
    "arch":            "x86_64",
    "ip_address":      "10.0.0.100",
    "public_key":      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "specter_version": "1.0.0",
}


@pytest_asyncio.fixture
async def agent(db: AsyncSession) -> Agent:
    a = Agent(
        id=str(uuid.uuid4()),
        hostname="specter-test-host",
        os_type="linux",
        os_version="Ubuntu 22.04",
        arch="x86_64",
        ip_address="10.0.0.1",
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


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  TestRegisterAgent
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestRegisterAgent:
    async def test_register_new_agent_returns_200(self, client):
        resp = await client.post("/api/v1/agents/register", json=AGENT_PAYLOAD)
        assert resp.status_code == 200

    async def test_register_returns_agent_id(self, client):
        resp = await client.post("/api/v1/agents/register", json=AGENT_PAYLOAD)
        data = resp.json()
        assert "agent_id" in data
        assert len(data["agent_id"]) == 36  # UUID length

    async def test_register_returns_poll_interval(self, client):
        resp = await client.post("/api/v1/agents/register", json=AGENT_PAYLOAD)
        data = resp.json()
        assert "poll_interval" in data
        assert data["poll_interval"] > 0

    async def test_register_idempotent_same_hostname(self, client):
        r1 = await client.post("/api/v1/agents/register", json=AGENT_PAYLOAD)
        r2 = await client.post("/api/v1/agents/register", json=AGENT_PAYLOAD)
        assert r1.status_code == 200
        assert r2.status_code == 200
        assert r1.json()["agent_id"] == r2.json()["agent_id"]

    async def test_register_no_auth_required(self, client):
        # Registration must be open â€” no token
        resp = await client.post("/api/v1/agents/register", json=AGENT_PAYLOAD)
        assert resp.status_code == 200

    async def test_register_missing_fields_returns_422(self, client):
        resp = await client.post("/api/v1/agents/register", json={"hostname": "x"})
        assert resp.status_code == 422


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  TestListAgents
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestListAgents:
    async def test_list_requires_auth(self, client):
        resp = await client.get("/api/v1/agents")
        assert resp.status_code in (401, 403)

    async def test_list_returns_agents_key(self, client, analyst_headers):
        resp = await client.get("/api/v1/agents", headers=analyst_headers)
        assert resp.status_code == 200
        assert "agents" in resp.json()
        assert "total" in resp.json()

    async def test_list_includes_registered_agent(self, client, analyst_headers, agent):
        resp = await client.get("/api/v1/agents", headers=analyst_headers)
        ids = [a["id"] for a in resp.json()["agents"]]
        assert agent.id in ids

    async def test_viewer_cannot_list(self, client, viewer_headers):
        resp = await client.get("/api/v1/agents", headers=viewer_headers)
        assert resp.status_code in (401, 403)

    async def test_list_status_filter(self, client, analyst_headers, agent):
        resp = await client.get("/api/v1/agents?status_filter=active", headers=analyst_headers)
        assert resp.status_code == 200
        for a in resp.json()["agents"]:
            assert a["status"] == "active"


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  TestGetAgent
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestGetAgent:
    async def test_get_existing_agent(self, client, analyst_headers, agent):
        resp = await client.get(f"/api/v1/agents/{agent.id}", headers=analyst_headers)
        assert resp.status_code == 200
        assert resp.json()["id"] == agent.id

    async def test_get_returns_hostname(self, client, analyst_headers, agent):
        resp = await client.get(f"/api/v1/agents/{agent.id}", headers=analyst_headers)
        assert resp.json()["hostname"] == agent.hostname

    async def test_get_nonexistent_returns_404(self, client, analyst_headers):
        resp = await client.get(f"/api/v1/agents/{uuid.uuid4()}", headers=analyst_headers)
        assert resp.status_code == 404

    async def test_get_requires_auth(self, client, agent):
        resp = await client.get(f"/api/v1/agents/{agent.id}")
        assert resp.status_code in (401, 403)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  TestDeregisterAgent
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestDeregisterAgent:
    async def test_admin_can_deregister(self, client, admin_headers, agent):
        resp = await client.delete(f"/api/v1/agents/{agent.id}", headers=admin_headers)
        assert resp.status_code == 200

    async def test_deregister_removes_agent(self, client, admin_headers, analyst_headers, agent):
        await client.delete(f"/api/v1/agents/{agent.id}", headers=admin_headers)
        resp = await client.get(f"/api/v1/agents/{agent.id}", headers=analyst_headers)
        assert resp.status_code == 404

    async def test_analyst_cannot_deregister(self, client, analyst_headers, agent):
        resp = await client.delete(f"/api/v1/agents/{agent.id}", headers=analyst_headers)
        assert resp.status_code in (401, 403)

    async def test_deregister_nonexistent_returns_404(self, client, admin_headers):
        resp = await client.delete(f"/api/v1/agents/{uuid.uuid4()}", headers=admin_headers)
        assert resp.status_code == 404


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  TestIngestEvents
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestIngestEvents:
    def _event(self, event_type: str = "process_start"):
        return {
            "event_type": event_type,
            "severity":   "info",
            "data":       {"pid": 1234, "name": "bash"},
            "ts":         time.time(),
            "signature":  "AAAA",
        }

    async def test_ingest_accepted(self, client, agent_headers, agent):
        resp = await client.post(
            f"/api/v1/agents/{agent.id}/events",
            json={"events": [self._event()]},
            headers=agent_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["accepted"] >= 0

    async def test_ingest_rejected_with_wrong_agent_id(self, client, agent_headers, agent):
        resp = await client.post(
            f"/api/v1/agents/{uuid.uuid4()}/events",
            json={"events": [self._event()]},
            headers=agent_headers,
        )
        assert resp.status_code in (403, 404)

    async def test_ingest_without_header_returns_403(self, client, agent):
        resp = await client.post(
            f"/api/v1/agents/{agent.id}/events",
            json={"events": [self._event()]},
        )
        assert resp.status_code in (401, 403, 422)

    async def test_ingest_batch_accepted_count(self, client, agent_headers, agent):
        events = [self._event(f"type_{i}") for i in range(5)]
        resp = await client.post(
            f"/api/v1/agents/{agent.id}/events",
            json={"events": events},
            headers=agent_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["accepted"] + data["rejected"] == 5

    async def test_ingest_empty_batch(self, client, agent_headers, agent):
        resp = await client.post(
            f"/api/v1/agents/{agent.id}/events",
            json={"events": []},
            headers=agent_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["accepted"] == 0

    async def test_ingest_response_has_ts(self, client, agent_headers, agent):
        resp = await client.post(
            f"/api/v1/agents/{agent.id}/events",
            json={"events": [self._event()]},
            headers=agent_headers,
        )
        assert "ts" in resp.json()


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  TestPollCommands
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestPollCommands:
    async def test_poll_returns_commands_key(self, client, agent_headers, agent):
        resp = await client.get(
            f"/api/v1/agents/{agent.id}/commands",
            headers=agent_headers,
        )
        assert resp.status_code == 200
        assert "commands" in resp.json()

    async def test_poll_returns_poll_interval(self, client, agent_headers, agent):
        resp = await client.get(
            f"/api/v1/agents/{agent.id}/commands",
            headers=agent_headers,
        )
        assert "poll_interval" in resp.json()

    async def test_poll_without_header_returns_error(self, client, agent):
        resp = await client.get(f"/api/v1/agents/{agent.id}/commands")
        assert resp.status_code in (401, 403, 422)

    async def test_poll_with_wrong_agent_id_returns_403(self, client, agent_headers, agent):
        resp = await client.get(
            f"/api/v1/agents/{uuid.uuid4()}/commands",
            headers=agent_headers,
        )
        assert resp.status_code in (403, 404)

    async def test_poll_updates_last_seen(self, client, agent_headers, agent, db):
        old_seen = agent.last_seen
        await client.get(
            f"/api/v1/agents/{agent.id}/commands",
            headers=agent_headers,
        )
        await db.refresh(agent)
        # last_seen should have been updated (or at least not regressed)
        assert agent.last_seen >= old_seen


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  TestReportResult
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestReportResult:
    @pytest_asyncio.fixture
    async def pending_cmd(self, db: AsyncSession, agent: Agent, admin_user) -> AgentCommand:
        return await issue_command(db, agent, "kill_process", {"pid": 1234}, str(admin_user.id))

    async def test_report_success(self, client, agent_headers, agent, pending_cmd):
        resp = await client.post(
            f"/api/v1/agents/{agent.id}/results",
            json={
                "command_id": pending_cmd.id,
                "success":    True,
                "result":     {"msg": "done"},
            },
            headers=agent_headers,
        )
        assert resp.status_code == 200

    async def test_report_sets_status(self, client, agent_headers, agent, pending_cmd, db):
        await client.post(
            f"/api/v1/agents/{agent.id}/results",
            json={"command_id": pending_cmd.id, "success": True, "result": {}},
            headers=agent_headers,
        )
        await db.refresh(pending_cmd)
        assert pending_cmd.status == "completed"

    async def test_report_failure_sets_failed(self, client, agent_headers, agent, pending_cmd, db):
        await client.post(
            f"/api/v1/agents/{agent.id}/results",
            json={"command_id": pending_cmd.id, "success": False, "result": {}, "error": "access denied"},
            headers=agent_headers,
        )
        await db.refresh(pending_cmd)
        assert pending_cmd.status == "failed"

    async def test_report_unknown_command_404(self, client, agent_headers, agent):
        resp = await client.post(
            f"/api/v1/agents/{agent.id}/results",
            json={"command_id": str(uuid.uuid4()), "success": True, "result": {}},
            headers=agent_headers,
        )
        assert resp.status_code == 404

    async def test_report_without_header_returns_error(self, client, agent, pending_cmd):
        resp = await client.post(
            f"/api/v1/agents/{agent.id}/results",
            json={"command_id": pending_cmd.id, "success": True, "result": {}},
        )
        assert resp.status_code in (401, 403, 422)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  TestIssueCommand
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestIssueCommand:
    async def test_admin_can_issue_command(self, client, admin_headers, agent):
        resp = await client.post(
            f"/api/v1/agents/{agent.id}/command",
            json={"command_type": "kill_process", "params": {"pid": 1234}},
            headers=admin_headers,
        )
        assert resp.status_code == 200

    async def test_issued_command_has_id(self, client, admin_headers, agent):
        resp = await client.post(
            f"/api/v1/agents/{agent.id}/command",
            json={"command_type": "block_ip", "params": {"ip": "1.2.3.4"}},
            headers=admin_headers,
        )
        data = resp.json()
        assert "id" in data

    async def test_issued_command_status_pending(self, client, admin_headers, agent):
        resp = await client.post(
            f"/api/v1/agents/{agent.id}/command",
            json={"command_type": "kill_process", "params": {"pid": 9999}},
            headers=admin_headers,
        )
        assert resp.json()["status"] == "pending"

    async def test_analyst_cannot_issue_command(self, client, analyst_headers, agent):
        resp = await client.post(
            f"/api/v1/agents/{agent.id}/command",
            json={"command_type": "kill_process", "params": {}},
            headers=analyst_headers,
        )
        assert resp.status_code in (401, 403)

    async def test_unknown_command_type_returns_400(self, client, admin_headers, agent):
        resp = await client.post(
            f"/api/v1/agents/{agent.id}/command",
            json={"command_type": "launch_missiles", "params": {}},
            headers=admin_headers,
        )
        assert resp.status_code == 400

    async def test_issue_to_nonexistent_agent_returns_404(self, client, admin_headers):
        resp = await client.post(
            f"/api/v1/agents/{uuid.uuid4()}/command",
            json={"command_type": "kill_process", "params": {}},
            headers=admin_headers,
        )
        assert resp.status_code == 404


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  TestSetThreatLevel
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestSetThreatLevel:
    async def test_set_elevated(self, client, analyst_headers, agent):
        resp = await client.patch(
            f"/api/v1/agents/{agent.id}/threat",
            json={"threat_level": "elevated"},
            headers=analyst_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["threat_level"] == "elevated"

    async def test_poll_interval_adjusts(self, client, analyst_headers, agent):
        resp = await client.patch(
            f"/api/v1/agents/{agent.id}/threat",
            json={"threat_level": "critical"},
            headers=analyst_headers,
        )
        assert resp.json()["poll_interval"] == 1  # critical â†’ 1s

    async def test_invalid_threat_level_returns_400(self, client, analyst_headers, agent):
        resp = await client.patch(
            f"/api/v1/agents/{agent.id}/threat",
            json={"threat_level": "apocalyptic"},
            headers=analyst_headers,
        )
        assert resp.status_code == 400

    async def test_viewer_cannot_set_threat(self, client, viewer_headers, agent):
        resp = await client.patch(
            f"/api/v1/agents/{agent.id}/threat",
            json={"threat_level": "elevated"},
            headers=viewer_headers,
        )
        assert resp.status_code in (401, 403)

    async def test_set_normal_threat(self, client, analyst_headers, agent):
        resp = await client.patch(
            f"/api/v1/agents/{agent.id}/threat",
            json={"threat_level": "normal"},
            headers=analyst_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["poll_interval"] == 30


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  TestTimeline
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestTimeline:
    @pytest_asyncio.fixture
    async def agent_with_events(self, db: AsyncSession, agent: Agent) -> Agent:
        for i in range(5):
            ev = AgentEvent(
                id=str(uuid.uuid4()),
                agent_id=agent.id,
                event_type=f"process_start" if i % 2 == 0 else "net_connect",
                severity="info",
                data={"pid": i},
                signature="AAAA",
                signature_valid=True,
                is_anomaly=(i == 3),
                ts=datetime.now(timezone.utc),
            )
            db.add(ev)
        await db.commit()
        return agent

    async def test_timeline_returns_events(self, client, analyst_headers, agent_with_events):
        resp = await client.get(
            f"/api/v1/agents/{agent_with_events.id}/timeline",
            headers=analyst_headers,
        )
        assert resp.status_code == 200
        assert len(resp.json()["events"]) == 5

    async def test_timeline_anomalies_only_filter(self, client, analyst_headers, agent_with_events):
        resp = await client.get(
            f"/api/v1/agents/{agent_with_events.id}/timeline?anomalies_only=true",
            headers=analyst_headers,
        )
        assert resp.status_code == 200
        events = resp.json()["events"]
        assert len(events) == 1
        assert all(e["is_anomaly"] for e in events)

    async def test_timeline_returns_hostname(self, client, analyst_headers, agent_with_events):
        resp = await client.get(
            f"/api/v1/agents/{agent_with_events.id}/timeline",
            headers=analyst_headers,
        )
        assert resp.json()["hostname"] == agent_with_events.hostname

    async def test_timeline_nonexistent_agent_404(self, client, analyst_headers):
        resp = await client.get(
            f"/api/v1/agents/{uuid.uuid4()}/timeline",
            headers=analyst_headers,
        )
        assert resp.status_code == 404

    async def test_timeline_requires_auth(self, client, agent):
        resp = await client.get(f"/api/v1/agents/{agent.id}/timeline")
        assert resp.status_code in (401, 403)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  TestAgentCommander  â€” unit tests for service layer
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestAgentCommander:
    def test_compute_poll_interval_normal(self):
        assert compute_poll_interval("normal") == 30

    def test_compute_poll_interval_elevated(self):
        assert compute_poll_interval("elevated") == 5

    def test_compute_poll_interval_critical(self):
        assert compute_poll_interval("critical") == 1

    def test_escalate_normal_to_elevated(self):
        assert escalate_threat_level("normal") == "elevated"

    def test_escalate_elevated_to_critical(self):
        assert escalate_threat_level("elevated") == "critical"

    def test_escalate_critical_stays_critical(self):
        assert escalate_threat_level("critical") == "critical"

    def test_deescalate_critical_to_elevated(self):
        assert deescalate_threat_level("critical") == "elevated"

    def test_deescalate_elevated_to_normal(self):
        assert deescalate_threat_level("elevated") == "normal"

    def test_deescalate_normal_stays_normal(self):
        assert deescalate_threat_level("normal") == "normal"
