"""
P24 Post-Sprint Improvements â€” Test Suite
==========================================
Covers all four improvement areas:

  A-FLEET  â€” Fleet-aware Specter dispatch (priority scoring, broadcast mode)
  A-ESC    â€” Celery PCDI critical-findings escalation task
  A-FT     â€” Cryptographic forensic timeline (chain hashes, event ordering)
  A-XDASH  â€” Cross-domain dashboard endpoint (/ops/cross-domain)

Security posture:
  - No real DB connections â€” all DB calls are mocked with AsyncMock
  - No Specter/ELK/Wazuh connections â€” agent_commander fully mocked
  - No real cryptographic keys â€” ephemeral Ed25519 keys generated per-test
  - No SSE/Redis calls â€” notification_bus mocked
  - No Celery worker started â€” _run() tested directly as async coroutine

Target: â‰¥ 40 tests
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import importlib.util

from fastapi.testclient import TestClient

_celery_available = importlib.util.find_spec("celery") is not None


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Fixtures & helpers
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def _gen_keypair() -> tuple[str, str]:
    """Ephemeral Ed25519 keypair. Returns (priv_b64, pub_b64)."""
    key = Ed25519PrivateKey.generate()
    return (
        base64.b64encode(key.private_bytes_raw()).decode(),
        base64.b64encode(key.public_key().public_bytes_raw()).decode(),
    )


def _make_agent(
    *,
    status: str = "active",
    threat_level: str = "normal",
    last_seen_seconds_ago: float = 10,
    hostname: str | None = None,
) -> MagicMock:
    a = MagicMock()
    a.id = str(uuid.uuid4())
    a.hostname = hostname or f"agent-{a.id[:6]}"
    a.status = status
    a.threat_level = threat_level
    a.last_seen = datetime.now(timezone.utc) - timedelta(seconds=last_seen_seconds_ago)
    return a


def _make_cmd(agent_id: str | None = None) -> MagicMock:
    c = MagicMock()
    c.id = str(uuid.uuid4())
    c.agent_id = agent_id or str(uuid.uuid4())
    c.status = "pending"
    return c


def _make_hunt(
    *,
    status: str = "active",
    priority: str = "medium",
    completed_at: datetime | None = None,
    started_at: datetime | None = None,
) -> MagicMock:
    h = MagicMock()
    h.id = str(uuid.uuid4())
    h.name = "Test Hunt"
    h.status = status
    h.priority = priority
    h.scope = "all"
    h.mitre_technique = "T1055"
    h.created_by = "analyst@test.com"
    h.assigned_to = None
    h.created_at = datetime.now(timezone.utc) - timedelta(hours=2)
    h.started_at = started_at
    h.completed_at = completed_at
    h.updated_at = datetime.now(timezone.utc)
    h.findings_count = 2
    h.true_positive_count = 1
    h.conclusion = None
    h.tags = []
    return h


def _make_finding(
    *,
    hunt_id: str = "hunt-1",
    severity: str = "high",
    indicator_value: str | None = "10.0.0.1",
    is_confirmed: bool = False,
    is_false_positive: bool = False,
    affected_host: str | None = "host-01",
    affected_user: str | None = None,
    data_source: str = "elk",
) -> MagicMock:
    f = MagicMock()
    f.id = str(uuid.uuid4())
    f.hunt_id = hunt_id
    f.title = "Test Finding"
    f.severity = severity
    f.indicator_value = indicator_value
    f.indicator_type = "ip"
    f.affected_host = affected_host
    f.affected_user = affected_user
    f.is_confirmed = is_confirmed
    f.is_false_positive = is_false_positive
    f.data_source = data_source
    f.created_by = "analyst@test.com"
    f.created_at = datetime.now(timezone.utc) - timedelta(minutes=30)
    f.updated_at = datetime.now(timezone.utc)
    return f


def _make_panl_action(
    *,
    target: str = "10.0.0.1",
    action_type: str = "block_ip",
    status: str = "completed",
    initiated_by: str = "analyst@test.com",
    approved_by: str | None = None,
) -> MagicMock:
    a = MagicMock()
    a.id = str(uuid.uuid4())
    a.target = target
    a.target_type = "ip"
    a.action_type = action_type
    a.status = status
    a.severity = "high"
    a.initiated_by = initiated_by
    a.approved_by = approved_by
    a.automated = False
    a.created_at = datetime.now(timezone.utc) - timedelta(minutes=10)
    a.executed_at = datetime.now(timezone.utc) - timedelta(minutes=5) if status == "completed" else None
    return a


def _make_pcdi_report(*, hunt_id: str, score: int = 72) -> MagicMock:
    r = MagicMock()
    r.id = str(uuid.uuid4())
    r.hunt_id = hunt_id
    r.hunt_name = "Test Hunt"
    r.hash_sha3_512 = "a" * 128
    r.signature_ed25519 = "sig=="
    r.signed_by_email = "analyst@test.com"
    r.signed_by_user_id = str(uuid.uuid4())
    r.signed_at = datetime.now(timezone.utc)
    r.last_verified_at = None
    r.verified = False
    r.pcdi_version = "1"
    r.adaptive_score = score
    return r


def _scalars_result(items: list) -> MagicMock:
    r = MagicMock()
    r.scalars = MagicMock(return_value=MagicMock(all=MagicMock(return_value=items)))
    r.scalar_one_or_none = MagicMock(return_value=items[0] if items else None)
    return r


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# A-FLEET â€” Fleet-aware Specter dispatch
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestAgentPriorityScore:
    """_agent_priority_score() scoring logic."""

    def test_normal_threat_gets_zero_weight(self):
        from asc_api.services.query_executor import _agent_priority_score
        agent = _make_agent(threat_level="normal", last_seen_seconds_ago=5)
        score = _agent_priority_score(agent)
        assert score < 1.0  # only tiny recency penalty for 5s

    def test_elevated_threat_adds_10(self):
        from asc_api.services.query_executor import _agent_priority_score
        # Use the same last_seen instant to isolate threat_level contribution
        now = datetime.now(timezone.utc)
        a_normal = _make_agent(threat_level="normal", last_seen_seconds_ago=0)
        a_normal.last_seen = now
        a_elevated = _make_agent(threat_level="elevated", last_seen_seconds_ago=0)
        a_elevated.last_seen = now
        assert _agent_priority_score(a_elevated) == pytest.approx(_agent_priority_score(a_normal) + 10, abs=1e-6)

    def test_critical_threat_adds_20(self):
        from asc_api.services.query_executor import _agent_priority_score
        now = datetime.now(timezone.utc)
        a_normal = _make_agent(threat_level="normal", last_seen_seconds_ago=0)
        a_normal.last_seen = now
        a_critical = _make_agent(threat_level="critical", last_seen_seconds_ago=0)
        a_critical.last_seen = now
        assert _agent_priority_score(a_critical) == pytest.approx(_agent_priority_score(a_normal) + 20, abs=1e-6)

    def test_unknown_threat_gets_5_fallback(self):
        from asc_api.services.query_executor import _agent_priority_score
        agent = _make_agent(threat_level="unknown", last_seen_seconds_ago=0)
        assert _agent_priority_score(agent) == pytest.approx(5.0, abs=0.01)

    def test_older_agent_scores_higher(self):
        """More seconds ago = higher recency penalty = less preferred."""
        from asc_api.services.query_executor import _agent_priority_score
        recent = _make_agent(threat_level="normal", last_seen_seconds_ago=10)
        stale  = _make_agent(threat_level="normal", last_seen_seconds_ago=3600)
        assert _agent_priority_score(recent) < _agent_priority_score(stale)

    def test_normal_recent_beats_critical_ancient(self):
        """A fresh normal agent beats an ancient critical one."""
        from asc_api.services.query_executor import _agent_priority_score
        fresh_normal   = _make_agent(threat_level="normal",   last_seen_seconds_ago=1)
        ancient_critical = _make_agent(threat_level="critical", last_seen_seconds_ago=10_000)
        assert _agent_priority_score(fresh_normal) < _agent_priority_score(ancient_critical)

    def test_no_last_seen_gets_max_penalty(self):
        from asc_api.services.query_executor import _agent_priority_score
        agent = _make_agent(threat_level="normal", last_seen_seconds_ago=0)
        agent.last_seen = None
        score = _agent_priority_score(agent)
        assert score == pytest.approx(0 + 999_999 * 0.001, abs=0.01)

    def test_min_selects_best_agent_from_fleet(self):
        """min(agents, key=_agent_priority_score) picks the freshest normal agent."""
        from asc_api.services.query_executor import _agent_priority_score
        agents = [
            _make_agent(threat_level="critical", last_seen_seconds_ago=5),
            _make_agent(threat_level="normal",   last_seen_seconds_ago=2),   # â† best
            _make_agent(threat_level="elevated",  last_seen_seconds_ago=1),
        ]
        best = min(agents, key=_agent_priority_score)
        assert best.threat_level == "normal"


class TestSpecterFleetDispatch:
    """_dispatch_to_specter() single-agent and broadcast modes."""

    @pytest.mark.asyncio
    async def test_single_mode_picks_best_agent(self):
        from asc_api.services.query_executor import _dispatch_to_specter

        good  = _make_agent(threat_level="normal",   last_seen_seconds_ago=2)
        worse = _make_agent(threat_level="critical",  last_seen_seconds_ago=1)
        cmd   = _make_cmd(str(good.id))

        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalars_result([good, worse]))

        with patch("asc_api.services.agent_commander.issue_command", AsyncMock(return_value=cmd)) as mock_ic:
            result = await _dispatch_to_specter(
                db, "test query",
                query_id="q-1", hunt_id="h-1", executed_by="analyst@test.com",
            )

        assert result["success"] is True
        assert result["mode"] == "specter_async"
        assert result["specter_agent_id"] == str(good.id)
        assert "specter_command_id" in result
        mock_ic.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_single_mode_result_count_is_zero(self):
        """Specter is async â€” no results yet, result_count = 0."""
        from asc_api.services.query_executor import _dispatch_to_specter

        agent = _make_agent()
        cmd   = _make_cmd(str(agent.id))
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalars_result([agent]))

        with patch("asc_api.services.agent_commander.issue_command", AsyncMock(return_value=cmd)):
            result = await _dispatch_to_specter(
                db, "query", query_id="q", hunt_id="h", executed_by="x"
            )

        assert result["result_count"] == 0
        assert result["total"] == 0
        assert result["results"] == []

    @pytest.mark.asyncio
    async def test_single_mode_note_contains_command_id(self):
        from asc_api.services.query_executor import _dispatch_to_specter

        agent = _make_agent()
        cmd   = _make_cmd(str(agent.id))
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalars_result([agent]))

        with patch("asc_api.services.agent_commander.issue_command", AsyncMock(return_value=cmd)):
            result = await _dispatch_to_specter(
                db, "query", query_id="q", hunt_id="h", executed_by="x"
            )

        assert cmd.id[:8] in result["note"]

    @pytest.mark.asyncio
    async def test_broadcast_mode_dispatches_to_all_agents(self):
        from asc_api.services.query_executor import _dispatch_to_specter

        agents = [_make_agent() for _ in range(3)]
        cmds   = [_make_cmd(str(a.id)) for a in agents]
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalars_result(agents))

        with patch("asc_api.services.agent_commander.issue_command", AsyncMock(side_effect=cmds)) as mock_ic:
            result = await _dispatch_to_specter(
                db, "query", query_id="q", hunt_id="h", executed_by="x",
                broadcast=True,
            )

        assert result["success"] is True
        assert result["mode"] == "specter_broadcast"
        assert result["agents_dispatched"] == 3
        assert len(result["broadcast_commands"]) == 3
        assert mock_ic.await_count == 3

    @pytest.mark.asyncio
    async def test_broadcast_each_entry_has_agent_id_and_command_id(self):
        from asc_api.services.query_executor import _dispatch_to_specter

        agents = [_make_agent() for _ in range(2)]
        cmds   = [_make_cmd(str(a.id)) for a in agents]
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalars_result(agents))

        with patch("asc_api.services.agent_commander.issue_command", AsyncMock(side_effect=cmds)):
            result = await _dispatch_to_specter(
                db, "q", query_id="q", hunt_id="h", executed_by="x", broadcast=True
            )

        for entry in result["broadcast_commands"]:
            assert "agent_id" in entry
            assert "command_id" in entry
            assert "agent_label" in entry

    @pytest.mark.asyncio
    async def test_broadcast_partial_failure_skips_bad_agents(self):
        """If one agent raises during broadcast, others still succeed."""
        from asc_api.services.query_executor import _dispatch_to_specter

        agents = [_make_agent() for _ in range(2)]
        good_cmd = _make_cmd(str(agents[1].id))
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalars_result(agents))

        async def _side_effect(db, agent, *args, **kwargs):
            if agent.id == agents[0].id:
                raise RuntimeError("agent offline")
            return good_cmd

        with patch("asc_api.services.agent_commander.issue_command", side_effect=_side_effect):
            result = await _dispatch_to_specter(
                db, "q", query_id="q", hunt_id="h", executed_by="x", broadcast=True
            )

        assert result["agents_dispatched"] == 1

    @pytest.mark.asyncio
    async def test_no_active_agents_returns_error(self):
        from asc_api.services.query_executor import _dispatch_to_specter

        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalars_result([]))

        result = await _dispatch_to_specter(
            db, "query", query_id="q", hunt_id="h", executed_by="x"
        )

        assert result["success"] is False
        assert "No active Specter agents" in result["error"]

    @pytest.mark.asyncio
    async def test_params_include_read_only_flag(self):
        """Dispatched command must always carry read_only=True."""
        from asc_api.services.query_executor import _dispatch_to_specter

        agent = _make_agent()
        cmd   = _make_cmd(str(agent.id))
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalars_result([agent]))

        captured_params: dict = {}

        async def _capture(db, agent, cmd_type, params, **kw):
            captured_params.update(params)
            return cmd

        with patch("asc_api.services.agent_commander.issue_command", side_effect=_capture):
            await _dispatch_to_specter(
                db, "query", query_id="q", hunt_id="h", executed_by="x"
            )

        assert captured_params.get("read_only") is True


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# A-ESC â€” PCDI Critical Findings Escalation Task
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@pytest.mark.skipif(not _celery_available, reason="celery not installed locally â€” Docker only")
class TestPCDIEscalationTask:
    """pcdi_escalation._run() logic tested directly (no Celery worker)."""

    @pytest.mark.asyncio
    async def test_escalates_hunt_when_max_score_critical(self):
        """Hunt with score â‰¥ 80 gets priority upgraded to 'critical'."""
        from asc_api.tasks.pcdi_escalation import _run, PCDI_CRITICAL_THRESHOLD

        hunt = _make_hunt(status="active", priority="medium")
        finding = _make_finding(hunt_id=hunt.id, severity="critical")

        high_score_result = {
            "adaptive_score": 85,
            "finding_id": finding.id,
        }

        async def _mock_score(db, fid):
            return high_score_result

        mock_session = AsyncMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        def _db_execute_side_effect(stmt):
            r = AsyncMock()
            r.scalars = MagicMock(return_value=MagicMock(all=MagicMock(return_value=[hunt])))
            return asyncio.coroutine(lambda: r)()

        # We mock at a higher level to avoid complex SQLAlchemy statement matching
        with (
            patch("asc_api.tasks.pcdi_escalation.AsyncSessionLocal", return_value=mock_session),
            patch("asc_api.tasks.pcdi_escalation.compute_adaptive_score", side_effect=_mock_score),
        ):
            # Simulate the DB returning hunts and findings
            mock_session.execute = AsyncMock(side_effect=[
                _scalars_result([hunt]),      # active hunts
                _scalars_result([finding]),   # findings for hunt
            ])
            mock_session.commit = AsyncMock()

            with (
                patch("asc_api.tasks.pcdi_escalation.log_security_action"),
                patch("asc_api.tasks.pcdi_escalation.asyncio.ensure_future"),
            ):
                result = await _run()

        assert result["active_hunts_checked"] == 1
        assert result["findings_scored"] == 1
        assert hunt.id in result["escalated_hunt_ids"]

    @pytest.mark.asyncio
    async def test_no_escalation_when_score_below_threshold(self):
        """Score < 80 does not escalate the hunt."""
        from asc_api.tasks.pcdi_escalation import _run, PCDI_CRITICAL_THRESHOLD

        hunt = _make_hunt(status="active", priority="medium")
        finding = _make_finding(hunt_id=hunt.id, severity="medium")

        async def _low_score(db, fid):
            return {"adaptive_score": 50}

        mock_session = AsyncMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)
        mock_session.execute = AsyncMock(side_effect=[
            _scalars_result([hunt]),
            _scalars_result([finding]),
        ])
        mock_session.commit = AsyncMock()

        with (
            patch("asc_api.tasks.pcdi_escalation.AsyncSessionLocal", return_value=mock_session),
            patch("asc_api.tasks.pcdi_escalation.compute_adaptive_score", side_effect=_low_score),
            patch("asc_api.tasks.pcdi_escalation.log_security_action"),
        ):
            result = await _run()

        assert result["hunts_escalated"] == 0
        assert result["escalated_hunt_ids"] == []
        assert hunt.priority != "critical"  # not changed

    @pytest.mark.asyncio
    async def test_already_critical_hunt_not_re_escalated(self):
        """Hunts already at critical priority are not counted as newly escalated."""
        from asc_api.tasks.pcdi_escalation import _run

        hunt = _make_hunt(status="active", priority="critical")
        finding = _make_finding(hunt_id=hunt.id, severity="critical")

        async def _high_score(db, fid):
            return {"adaptive_score": 90}

        mock_session = AsyncMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)
        mock_session.execute = AsyncMock(side_effect=[
            _scalars_result([hunt]),
            _scalars_result([finding]),
        ])
        mock_session.commit = AsyncMock()

        with (
            patch("asc_api.tasks.pcdi_escalation.AsyncSessionLocal", return_value=mock_session),
            patch("asc_api.tasks.pcdi_escalation.compute_adaptive_score", side_effect=_high_score),
            patch("asc_api.tasks.pcdi_escalation.log_security_action"),
        ):
            result = await _run()

        assert result["hunts_escalated"] == 0

    @pytest.mark.asyncio
    async def test_scoring_error_is_skipped_not_fatal(self):
        """Individual finding scoring errors are logged and skipped, task continues."""
        from asc_api.tasks.pcdi_escalation import _run

        hunt = _make_hunt(status="active", priority="medium")
        finding = _make_finding(hunt_id=hunt.id)

        async def _broken_score(db, fid):
            raise RuntimeError("DB timeout")

        mock_session = AsyncMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)
        mock_session.execute = AsyncMock(side_effect=[
            _scalars_result([hunt]),
            _scalars_result([finding]),
        ])
        mock_session.commit = AsyncMock()

        with (
            patch("asc_api.tasks.pcdi_escalation.AsyncSessionLocal", return_value=mock_session),
            patch("asc_api.tasks.pcdi_escalation.compute_adaptive_score", side_effect=_broken_score),
            patch("asc_api.tasks.pcdi_escalation.log_security_action"),
        ):
            result = await _run()  # must not raise

        assert result["findings_scored"] == 0
        assert result["hunts_escalated"] == 0

    @pytest.mark.asyncio
    async def test_no_active_hunts_returns_zero_counts(self):
        from asc_api.tasks.pcdi_escalation import _run

        mock_session = AsyncMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)
        mock_session.execute = AsyncMock(return_value=_scalars_result([]))
        mock_session.commit = AsyncMock()

        with patch("asc_api.tasks.pcdi_escalation.AsyncSessionLocal", return_value=mock_session):
            result = await _run()

        assert result["active_hunts_checked"] == 0
        assert result["findings_scored"] == 0
        assert result["hunts_escalated"] == 0

    def test_threshold_constant_is_80(self):
        from asc_api.tasks.pcdi_escalation import PCDI_CRITICAL_THRESHOLD
        assert PCDI_CRITICAL_THRESHOLD == 80

    def test_celery_task_exists_and_is_named(self):
        from asc_api.tasks.pcdi_escalation import check_critical_findings
        assert check_critical_findings.name == "asc.pcdi_escalation.check_critical_findings"

    def test_celery_task_registered_in_beat(self):
        from asc_api.tasks.celery_app import celery_app
        assert "pcdi-critical-findings" in celery_app.conf.beat_schedule


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# A-FT â€” Forensic Timeline (chain hashes)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestForensicTimeline:
    """build_forensic_timeline() in pcdi_service."""

    @pytest.mark.asyncio
    async def test_returns_error_for_unknown_hunt(self):
        from asc_api.services.pcdi_service import build_forensic_timeline

        db = AsyncMock()
        r = MagicMock()
        r.scalar_one_or_none = MagicMock(return_value=None)
        db.execute = AsyncMock(return_value=r)

        result = await build_forensic_timeline(db, "nonexistent-hunt")

        assert "error" in result
        assert result["hunt_id"] == "nonexistent-hunt"

    @pytest.mark.asyncio
    async def test_empty_hunt_returns_empty_timeline(self):
        from asc_api.services.pcdi_service import build_forensic_timeline

        hunt = _make_hunt()

        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[
            _scalars_result([hunt]),        # Hunt lookup
            _scalars_result([]),             # HuntQuery
            _scalars_result([]),             # HuntFinding
            _scalars_result([]),             # PCDISignedReport
        ])

        # single-result mock for hunt
        hunt_r = MagicMock()
        hunt_r.scalar_one_or_none = MagicMock(return_value=hunt)

        db.execute = AsyncMock(side_effect=[
            hunt_r,
            _scalars_result([]),  # queries
            _scalars_result([]),  # findings
            _scalars_result([]),  # panl (skipped because no target_values)
            _scalars_result([]),  # signed reports
        ])

        result = await build_forensic_timeline(db, hunt.id)

        assert "error" not in result
        assert result["hunt_id"] == hunt.id
        # Only hunt_created event (no started_at or completed_at)
        assert result["event_count"] == 1
        assert result["timeline"][0]["event_type"] == "hunt_created"

    @pytest.mark.asyncio
    async def test_chain_hash_links_entries(self):
        """Each entry's prev_hash must equal the previous entry's entry_hash."""
        from asc_api.services.pcdi_service import build_forensic_timeline

        hunt = _make_hunt()
        finding = _make_finding(hunt_id=hunt.id)

        hunt_r = MagicMock()
        hunt_r.scalar_one_or_none = MagicMock(return_value=hunt)

        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[
            hunt_r,
            _scalars_result([]),         # queries
            _scalars_result([finding]),  # findings (has indicator_value â†’ triggers PANL query)
            _scalars_result([]),         # PANL neutralization actions
            _scalars_result([]),         # signed reports
        ])

        result = await build_forensic_timeline(db, hunt.id)

        timeline = result["timeline"]
        assert len(timeline) >= 2  # hunt_created + finding_created

        for i in range(1, len(timeline)):
            assert timeline[i]["prev_hash"] == timeline[i - 1]["entry_hash"], (
                f"Chain broken at sequence {i}: prev_hash mismatch"
            )

    @pytest.mark.asyncio
    async def test_entry_hashes_are_sha3_512_length(self):
        from asc_api.services.pcdi_service import build_forensic_timeline

        hunt = _make_hunt()
        hunt_r = MagicMock()
        hunt_r.scalar_one_or_none = MagicMock(return_value=hunt)

        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[
            hunt_r,
            _scalars_result([]),
            _scalars_result([]),
            _scalars_result([]),
        ])

        result = await build_forensic_timeline(db, hunt.id)

        for entry in result["timeline"]:
            assert len(entry["entry_hash"]) == 128  # SHA3-512 = 64 bytes = 128 hex chars
            assert len(entry["prev_hash"]) == 128 or entry["prev_hash"] == result["timeline"][0]["prev_hash"]

    @pytest.mark.asyncio
    async def test_chain_root_equals_last_entry_hash(self):
        from asc_api.services.pcdi_service import build_forensic_timeline

        hunt = _make_hunt()
        hunt_r = MagicMock()
        hunt_r.scalar_one_or_none = MagicMock(return_value=hunt)

        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[
            hunt_r,
            _scalars_result([]),
            _scalars_result([]),
            _scalars_result([]),
        ])

        result = await build_forensic_timeline(db, hunt.id)

        assert result["chain_root_hash"] == result["timeline"][-1]["entry_hash"]

    @pytest.mark.asyncio
    async def test_timeline_is_sorted_chronologically(self):
        from asc_api.services.pcdi_service import build_forensic_timeline

        hunt = _make_hunt(
            started_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        hunt_r = MagicMock()
        hunt_r.scalar_one_or_none = MagicMock(return_value=hunt)

        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[
            hunt_r,
            _scalars_result([]),
            _scalars_result([]),
            _scalars_result([]),
        ])

        result = await build_forensic_timeline(db, hunt.id)

        timestamps = [e["ts"] for e in result["timeline"]]
        assert timestamps == sorted(timestamps)

    @pytest.mark.asyncio
    async def test_sequence_numbers_are_zero_indexed_contiguous(self):
        from asc_api.services.pcdi_service import build_forensic_timeline

        hunt = _make_hunt(started_at=datetime.now(timezone.utc) - timedelta(minutes=5))
        hunt_r = MagicMock()
        hunt_r.scalar_one_or_none = MagicMock(return_value=hunt)

        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[
            hunt_r,
            _scalars_result([]),
            _scalars_result([]),
            _scalars_result([]),
        ])

        result = await build_forensic_timeline(db, hunt.id)
        seqs = [e["sequence"] for e in result["timeline"]]
        assert seqs == list(range(len(seqs)))

    @pytest.mark.asyncio
    async def test_genesis_seed_returned_in_response(self):
        from asc_api.services.pcdi_service import build_forensic_timeline, _GENESIS_SEED

        hunt = _make_hunt()
        hunt_r = MagicMock()
        hunt_r.scalar_one_or_none = MagicMock(return_value=hunt)

        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[
            hunt_r,
            _scalars_result([]),
            _scalars_result([]),
            _scalars_result([]),
        ])

        result = await build_forensic_timeline(db, hunt.id)
        assert result["genesis_seed"] == _GENESIS_SEED

    @pytest.mark.asyncio
    async def test_pcdi_report_event_appears_in_timeline(self):
        from asc_api.services.pcdi_service import build_forensic_timeline

        hunt = _make_hunt()
        report = _make_pcdi_report(hunt_id=hunt.id, score=88)

        hunt_r = MagicMock()
        hunt_r.scalar_one_or_none = MagicMock(return_value=hunt)

        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[
            hunt_r,
            _scalars_result([]),     # queries
            _scalars_result([]),     # findings
            _scalars_result([report]),  # reports
        ])

        result = await build_forensic_timeline(db, hunt.id)

        event_types = [e["event_type"] for e in result["timeline"]]
        assert "report_signed" in event_types

    @pytest.mark.asyncio
    async def test_finding_confirmed_event_appears(self):
        from asc_api.services.pcdi_service import build_forensic_timeline

        hunt = _make_hunt()
        finding = _make_finding(hunt_id=hunt.id, is_confirmed=True)

        hunt_r = MagicMock()
        hunt_r.scalar_one_or_none = MagicMock(return_value=hunt)

        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[
            hunt_r,
            _scalars_result([]),          # queries
            _scalars_result([finding]),   # findings (has indicator_value â†’ PANL query)
            _scalars_result([]),          # PANL actions
            _scalars_result([]),          # signed reports
        ])

        result = await build_forensic_timeline(db, hunt.id)

        event_types = [e["event_type"] for e in result["timeline"]]
        assert "finding_confirmed" in event_types


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# A-XDASH â€” Cross-Domain Dashboard endpoint
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestCrossDomainDashboard:
    """GET /ops/cross-domain endpoint."""

    def _get_test_client(self):
        from asc_api.main import app
        from asc_api.db.session import get_db
        from asc_api.api.deps import get_analyst_or_admin

        mock_user = MagicMock()
        mock_user.id = str(uuid.uuid4())
        mock_user.email = "analyst@test.com"
        mock_user.role = "analyst"

        async def _override_db():
            yield AsyncMock()

        async def _override_auth():
            return mock_user

        app.dependency_overrides[get_db] = _override_db
        app.dependency_overrides[get_analyst_or_admin] = _override_auth
        return TestClient(app), app

    def test_cross_domain_requires_auth(self):
        from asc_api.main import app
        client = TestClient(app)
        resp = client.get("/api/v1/ops/cross-domain")
        assert resp.status_code in (401, 403)

    def test_cross_domain_returns_all_sections(self):
        from asc_api.main import app
        from asc_api.db.session import get_db
        from asc_api.api.deps import get_analyst_or_admin
        from asc_api.models.agent import Agent, AgentCommand
        from asc_api.models.neutralization import NeutralizationAction
        from asc_api.models.hunt import Hunt, HuntFinding
        from asc_api.models.threat_intel import ThreatIntelIndicator
        from asc_api.models.pcdi import PCDISignedReport

        mock_user = MagicMock()
        mock_user.id = str(uuid.uuid4())
        mock_user.role = "analyst"

        # Return empty lists for all queries
        empty_r = _scalars_result([])

        async def _mock_db():
            db = AsyncMock()
            db.execute = AsyncMock(return_value=empty_r)
            yield db

        async def _mock_auth():
            return mock_user

        try:
            app.dependency_overrides[get_db] = _mock_db
            app.dependency_overrides[get_analyst_or_admin] = _mock_auth
            client = TestClient(app)
            resp = client.get("/api/v1/ops/cross-domain")
        finally:
            app.dependency_overrides.clear()

        assert resp.status_code == 200
        data = resp.json()
        assert "fleet" in data
        assert "hunting" in data
        assert "panl" in data
        assert "threat_intel" in data
        assert "pcdi" in data
        assert "window_hours" in data
        assert "ts" in data

    def test_cross_domain_fleet_section_structure(self):
        from asc_api.main import app
        from asc_api.db.session import get_db
        from asc_api.api.deps import get_analyst_or_admin

        mock_user = MagicMock()
        mock_user.id = str(uuid.uuid4())
        mock_user.role = "analyst"

        empty_r = _scalars_result([])

        async def _mock_db():
            db = AsyncMock()
            db.execute = AsyncMock(return_value=empty_r)
            yield db

        async def _mock_auth():
            return mock_user

        try:
            app.dependency_overrides[get_db] = _mock_db
            app.dependency_overrides[get_analyst_or_admin] = _mock_auth
            client = TestClient(app)
            resp = client.get("/api/v1/ops/cross-domain")
        finally:
            app.dependency_overrides.clear()

        fleet = resp.json()["fleet"]
        required_keys = {"total_agents", "active_agents", "online_5m", "at_risk_agents",
                         "commands_in_window", "command_success_rate_pct"}
        assert required_keys.issubset(fleet.keys())

    def test_cross_domain_hunting_section_structure(self):
        from asc_api.main import app
        from asc_api.db.session import get_db
        from asc_api.api.deps import get_analyst_or_admin

        mock_user = MagicMock()
        mock_user.id = str(uuid.uuid4())
        mock_user.role = "analyst"

        empty_r = _scalars_result([])

        async def _mock_db():
            db = AsyncMock()
            db.execute = AsyncMock(return_value=empty_r)
            yield db

        async def _mock_auth():
            return mock_user

        try:
            app.dependency_overrides[get_db] = _mock_db
            app.dependency_overrides[get_analyst_or_admin] = _mock_auth
            client = TestClient(app)
            resp = client.get("/api/v1/ops/cross-domain")
        finally:
            app.dependency_overrides.clear()

        hunting = resp.json()["hunting"]
        required_keys = {"active_hunts", "critical_priority_hunts", "total_hunts",
                         "completed_in_window", "true_positives_in_window",
                         "high_severity_findings", "active_hunt_ids"}
        assert required_keys.issubset(hunting.keys())

    def test_cross_domain_pcdi_section_structure(self):
        from asc_api.main import app
        from asc_api.db.session import get_db
        from asc_api.api.deps import get_analyst_or_admin

        mock_user = MagicMock()
        mock_user.id = str(uuid.uuid4())
        mock_user.role = "analyst"

        empty_r = _scalars_result([])

        async def _mock_db():
            db = AsyncMock()
            db.execute = AsyncMock(return_value=empty_r)
            yield db

        async def _mock_auth():
            return mock_user

        try:
            app.dependency_overrides[get_db] = _mock_db
            app.dependency_overrides[get_analyst_or_admin] = _mock_auth
            client = TestClient(app)
            resp = client.get("/api/v1/ops/cross-domain")
        finally:
            app.dependency_overrides.clear()

        pcdi = resp.json()["pcdi"]
        required_keys = {"total_signed_reports", "high_score_reports",
                         "avg_adaptive_score", "active_critical_hunts", "top_reports"}
        assert required_keys.issubset(pcdi.keys())

    def test_cross_domain_accepts_hours_param(self):
        from asc_api.main import app
        from asc_api.db.session import get_db
        from asc_api.api.deps import get_analyst_or_admin

        mock_user = MagicMock()
        mock_user.id = str(uuid.uuid4())
        mock_user.role = "analyst"

        empty_r = _scalars_result([])

        async def _mock_db():
            db = AsyncMock()
            db.execute = AsyncMock(return_value=empty_r)
            yield db

        async def _mock_auth():
            return mock_user

        try:
            app.dependency_overrides[get_db] = _mock_db
            app.dependency_overrides[get_analyst_or_admin] = _mock_auth
            client = TestClient(app)
            resp = client.get("/api/v1/ops/cross-domain?hours=72")
        finally:
            app.dependency_overrides.clear()

        assert resp.status_code == 200
        assert resp.json()["window_hours"] == 72


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# A-FT â€” Forensic Timeline Endpoint
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestForensicTimelineEndpoint:
    """GET /pcdi/forensic-timeline/{hunt_id}"""

    def test_forensic_timeline_requires_auth(self):
        from asc_api.main import app
        client = TestClient(app)
        resp = client.get("/api/v1/pcdi/forensic-timeline/some-hunt-id")
        assert resp.status_code in (401, 403)

    def test_forensic_timeline_404_for_unknown_hunt(self):
        from asc_api.main import app
        from asc_api.db.session import get_db
        from asc_api.api.deps import get_analyst_or_admin

        mock_user = MagicMock()
        mock_user.id = str(uuid.uuid4())
        mock_user.role = "analyst"

        async def _mock_db():
            db = AsyncMock()
            not_found_r = MagicMock()
            not_found_r.scalar_one_or_none = MagicMock(return_value=None)
            db.execute = AsyncMock(return_value=not_found_r)
            yield db

        async def _mock_auth():
            return mock_user

        try:
            app.dependency_overrides[get_db] = _mock_db
            app.dependency_overrides[get_analyst_or_admin] = _mock_auth
            client = TestClient(app)
            resp = client.get("/api/v1/pcdi/forensic-timeline/nonexistent")
        finally:
            app.dependency_overrides.clear()

        assert resp.status_code == 404

    def test_forensic_timeline_success_structure(self):
        from asc_api.main import app
        from asc_api.db.session import get_db
        from asc_api.api.deps import get_analyst_or_admin

        hunt = _make_hunt()
        mock_user = MagicMock()
        mock_user.id = str(uuid.uuid4())
        mock_user.role = "analyst"

        hunt_r = MagicMock()
        hunt_r.scalar_one_or_none = MagicMock(return_value=hunt)
        empty_r = _scalars_result([])

        async def _mock_db():
            db = AsyncMock()
            db.execute = AsyncMock(side_effect=[hunt_r, empty_r, empty_r, empty_r])
            yield db

        async def _mock_auth():
            return mock_user

        try:
            app.dependency_overrides[get_db] = _mock_db
            app.dependency_overrides[get_analyst_or_admin] = _mock_auth
            client = TestClient(app)
            resp = client.get(f"/api/v1/pcdi/forensic-timeline/{hunt.id}")
        finally:
            app.dependency_overrides.clear()

        assert resp.status_code == 200
        data = resp.json()
        required_keys = {"hunt_id", "hunt_name", "event_count", "chain_root_hash",
                         "chain_root_prefix", "genesis_seed", "timeline", "built_at"}
        assert required_keys.issubset(data.keys())
        assert isinstance(data["timeline"], list)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Additional integration checks
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestIntegration:

    def test_pcdi_router_includes_forensic_timeline_route(self):
        """Verify the route is registered at the expected path (prefix included)."""
        from asc_api.api.v1.endpoints.pcdi import router
        paths = [r.path for r in router.routes]
        assert any("forensic-timeline" in p for p in paths)

    def test_ops_router_includes_cross_domain_route(self):
        from asc_api.api.v1.endpoints.ops_dashboard import router
        paths = [r.path for r in router.routes]
        assert any("cross-domain" in p for p in paths)

    def test_pcdi_service_exports_build_forensic_timeline(self):
        from asc_api.services import pcdi_service
        assert hasattr(pcdi_service, "build_forensic_timeline")
        assert callable(pcdi_service.build_forensic_timeline)

    def test_pcdi_service_exports_iso_helper(self):
        from asc_api.services.pcdi_service import _iso
        result = _iso(datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc))
        assert "2024-01-15" in result

    def test_iso_helper_handles_naive_datetime(self):
        """Naive datetimes are coerced to UTC, not raising."""
        from asc_api.services.pcdi_service import _iso
        naive = datetime(2024, 6, 1, 10, 30, 0)
        result = _iso(naive)
        assert "2024-06-01" in result

    def test_iso_helper_handles_none(self):
        from asc_api.services.pcdi_service import _iso
        result = _iso(None)
        # Should return a valid ISO string (current time fallback)
        assert "T" in result

    def test_genesis_seed_constant_is_stable(self):
        """GENESIS_SEED must never change â€” changing it invalidates all stored timelines."""
        from asc_api.services.pcdi_service import _GENESIS_SEED
        assert _GENESIS_SEED == "GENESIS:pcdi-forensic-timeline:v1"

    def test_fleet_dispatch_function_signature(self):
        """_dispatch_to_specter accepts broadcast kwarg."""
        import inspect
        from asc_api.services.query_executor import _dispatch_to_specter
        sig = inspect.signature(_dispatch_to_specter)
        assert "broadcast" in sig.parameters
        assert sig.parameters["broadcast"].default is False

    def test_agent_priority_score_function_signature(self):
        import inspect
        from asc_api.services.query_executor import _agent_priority_score
        sig = inspect.signature(_agent_priority_score)
        assert "agent" in sig.parameters
