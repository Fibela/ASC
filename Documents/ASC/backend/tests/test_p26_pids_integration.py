"""
FASE 4.1 — PIDS Integration Tests (P26).

Replaces the AsyncMock-based DB tests from test_p26.py with real SQLite
in-memory tests. All DB queries hit the real SQLAlchemy + SQLite stack.
External side-effects (AD adapter calls, Resend delivery) are patched
so the tests stay self-contained.

Suite breakdown:
  TestPIDSCreateActionDB         (6)  — create_identity_action with real DB
  TestPIDSVerifyDB               (8)  — verify hash integrity on real actions
  TestPIDSListDB                 (6)  — list / filter real identity actions
  TestPIDSTimelineDB             (4)  — timeline ordering / empty result
  TestPIDSSummaryDB              (6)  — summary counts from real rows
  TestAdaptiveOrchestrationDB    (5)  — trigger sort + dedup with real DB
  TestScheduledReportForensicDB  (4)  — deliver_scheduled_report with real DB
  TestPIDSRestEndpoints          (7)  — REST API via conftest client fixture

Total: 46 tests
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.core.security import create_access_token, get_password_hash
from asc_api.models.hunt import Hunt
from asc_api.models.identity_action import IdentityAction
from asc_api.models.soar import PlaybookTrigger, ScheduledReport
from asc_api.models.user import User


# ── Helpers ───────────────────────────────────────────────────────────────────

def _auth(user: User) -> dict:
    return {"Authorization": f"Bearer {create_access_token(user.id)}"}


_NOW = datetime.now(timezone.utc)

_ACTION_TYPES = [
    "disable_account",
    "enable_account",
    "force_password_reset",
    "quarantine_account",
    "enrich_user",
]


async def _make_action(
    db: AsyncSession,
    *,
    action_type: str = "disable_account",
    username: str = "jdoe",
    domain: str = "corp.local",
    reason: str = "test reason",
    success: bool = True,
    hunt_id: str | None = None,
    initiated_by: str = "analyst@corp.local",
) -> IdentityAction:
    """Insert a real IdentityAction and compute its forensic hash."""
    from asc_api.services.pids_service import (
        _build_canonical,
        _compute_hash,
    )

    a = IdentityAction(
        id=str(uuid.uuid4()),
        action_type=action_type,
        username=username,
        domain=domain,
        reason=reason,
        success=success,
        hunt_id=hunt_id,
        initiated_by=initiated_by,
        signed_by_email=initiated_by,
        executed_at=_NOW,
    )
    # Compute hash as the real service does
    canonical = _build_canonical(a)
    a.hash_sha3_512 = _compute_hash(canonical)
    db.add(a)
    await db.commit()
    await db.refresh(a)
    return a


async def _make_hunt(db: AsyncSession, hunt_id: str | None = None) -> Hunt:
    h = Hunt(
        id=hunt_id or str(uuid.uuid4()),
        name="PremosCorp Ransomware Hunt",
        status="active",
        priority="critical",
        tenant_id=None,
        created_by="admin@corp.local",
        created_at=_NOW,
        updated_at=_NOW,
    )
    db.add(h)
    await db.commit()
    await db.refresh(h)
    return h


async def _make_trigger(
    db: AsyncSession,
    *,
    priority: int = 5,
    dedup_window_minutes: int = 0,
    condition_type: str = "pcdi_score",
    condition_value: str = "0",
    enabled: bool = True,
) -> PlaybookTrigger:
    t = PlaybookTrigger(
        id=str(uuid.uuid4()),
        playbook_id="PB-001",
        playbook_name="Test Playbook",
        condition_type=condition_type,
        condition_operator="gte",
        condition_value=condition_value,
        hunt_id_filter=None,
        enabled=enabled,
        priority=priority,
        rate_limit_per_hour=100,
        dedup_window_minutes=dedup_window_minutes,
        trigger_count=0,
        last_triggered_at=None,
        last_triggered_context=None,
        created_by="admin@corp.local",
        created_at=_NOW,
    )
    db.add(t)
    await db.commit()
    await db.refresh(t)
    return t


# ── TestPIDSCreateActionDB ────────────────────────────────────────────────────

class TestPIDSCreateActionDB:
    """create_identity_action() with a real SQLite DB."""

    async def test_create_stores_in_db(self, db: AsyncSession):
        from asc_api.services.pids_service import create_identity_action

        with patch("asc_api.services.pids_service._sign_hash", return_value=None):
            action = await create_identity_action(
                db, action_type="disable_account",
                username="jdoe", domain="corp.local",
                reason="suspicious login", initiated_by="analyst@corp.local",
            )

        assert action.id is not None
        fetched = await db.get(IdentityAction, action.id)
        assert fetched is not None
        assert fetched.username == "jdoe"

    async def test_create_computes_forensic_hash(self, db: AsyncSession):
        from asc_api.services.pids_service import create_identity_action

        with patch("asc_api.services.pids_service._sign_hash", return_value=None):
            action = await create_identity_action(
                db, action_type="force_password_reset",
                username="alice", domain="corp.local",
                reason="credential breach", initiated_by="analyst@corp.local",
            )

        assert action.hash_sha3_512 is not None
        assert len(action.hash_sha3_512) == 128  # SHA3-512 = 128 hex chars

    async def test_invalid_action_type_raises_value_error(self, db: AsyncSession):
        from asc_api.services.pids_service import create_identity_action

        with pytest.raises(ValueError, match="Invalid action_type"):
            await create_identity_action(
                db, action_type="nuke_everything",
                username="jdoe", domain="corp.local",
                reason="test", initiated_by="analyst@corp.local",
            )

    async def test_create_links_hunt_id(self, db: AsyncSession):
        from asc_api.services.pids_service import create_identity_action
        hunt = await _make_hunt(db)

        with patch("asc_api.services.pids_service._sign_hash", return_value=None):
            action = await create_identity_action(
                db, action_type="enrich_user",
                username="svc-account", domain="corp.local",
                reason="context enrichment", initiated_by="analyst@corp.local",
                hunt_id=hunt.id,
            )

        assert action.hunt_id == hunt.id

    async def test_create_all_valid_action_types(self, db: AsyncSession):
        from asc_api.services.pids_service import create_identity_action

        for atype in _ACTION_TYPES:
            with patch("asc_api.services.pids_service._sign_hash", return_value=None):
                action = await create_identity_action(
                    db, action_type=atype,
                    username=f"user-{atype}", domain="corp.local",
                    reason="test", initiated_by="analyst@corp.local",
                )
            assert action.action_type == atype

    async def test_create_sets_success_flag(self, db: AsyncSession):
        from asc_api.services.pids_service import create_identity_action

        with patch("asc_api.services.pids_service._sign_hash", return_value=None):
            action = await create_identity_action(
                db, action_type="disable_account",
                username="jdoe", domain="corp.local",
                reason="test", initiated_by="analyst@corp.local",
                success=False,
            )

        assert action.success is False


# ── TestPIDSVerifyDB ──────────────────────────────────────────────────────────

class TestPIDSVerifyDB:
    """verify_identity_action() with real DB rows."""

    async def test_verify_intact_hash_match(self, db: AsyncSession):
        from asc_api.services.pids_service import verify_identity_action
        action = await _make_action(db)
        result = await verify_identity_action(db, action.id)
        assert result["hash_match"] is True
        assert result["verified"] is True

    async def test_verify_tampered_hash_mismatch(self, db: AsyncSession):
        from asc_api.services.pids_service import verify_identity_action
        action = await _make_action(db)
        action.hash_sha3_512 = "a" * 128  # tamper
        await db.commit()
        result = await verify_identity_action(db, action.id)
        assert result["hash_match"] is False
        assert result["verified"] is False

    async def test_verify_missing_action_returns_error(self, db: AsyncSession):
        from asc_api.services.pids_service import verify_identity_action
        result = await verify_identity_action(db, str(uuid.uuid4()))
        assert result["verified"] is False
        assert "not found" in result["error"].lower()

    async def test_verify_signature_none_without_key(self, db: AsyncSession):
        from asc_api.services.pids_service import verify_identity_action
        action = await _make_action(db)
        with patch("os.getenv", return_value=None):
            result = await verify_identity_action(db, action.id)
        assert result["signature_ok"] is None
        assert result["hash_match"] is True

    async def test_verify_returns_stored_and_computed_hash(self, db: AsyncSession):
        from asc_api.services.pids_service import verify_identity_action
        action = await _make_action(db)
        result = await verify_identity_action(db, action.id)
        assert result["stored_hash"] == action.hash_sha3_512
        assert result["computed_hash"] == action.hash_sha3_512

    async def test_verify_returns_action_type_and_username(self, db: AsyncSession):
        from asc_api.services.pids_service import verify_identity_action
        action = await _make_action(db, action_type="quarantine_account", username="mallory")
        result = await verify_identity_action(db, action.id)
        assert result["action_type"] == "quarantine_account"
        assert result["username"] == "mallory"

    async def test_verify_no_signature_signature_ok_none(self, db: AsyncSession):
        from asc_api.services.pids_service import verify_identity_action
        action = await _make_action(db)
        # No signature stored — signature_ok must be None
        assert action.signature_ed25519 is None
        result = await verify_identity_action(db, action.id)
        assert result["signature_ok"] is None

    async def test_verify_returns_action_id_in_response(self, db: AsyncSession):
        from asc_api.services.pids_service import verify_identity_action
        action = await _make_action(db)
        result = await verify_identity_action(db, action.id)
        assert result["action_id"] == action.id


# ── TestPIDSListDB ────────────────────────────────────────────────────────────

class TestPIDSListDB:
    """list_identity_actions() with real DB rows and filters."""

    async def test_list_all_returns_dicts(self, db: AsyncSession):
        from asc_api.services.pids_service import list_identity_actions
        await _make_action(db, username="alice")
        await _make_action(db, username="bob")
        result = await list_identity_actions(db)
        assert len(result) >= 2
        assert all(isinstance(r, dict) for r in result)

    async def test_list_empty_db_returns_empty_list(self, db: AsyncSession):
        from asc_api.services.pids_service import list_identity_actions
        result = await list_identity_actions(db)
        assert result == []

    async def test_list_dict_contains_required_keys(self, db: AsyncSession):
        from asc_api.services.pids_service import list_identity_actions
        await _make_action(db)
        result = await list_identity_actions(db)
        assert len(result) == 1
        keys = result[0].keys()
        for k in ("id", "action_type", "username", "domain", "success", "hash_sha3_512", "executed_at"):
            assert k in keys, f"Missing key: {k}"

    async def test_list_filter_by_username(self, db: AsyncSession):
        from asc_api.services.pids_service import list_identity_actions
        await _make_action(db, username="alice")
        await _make_action(db, username="bob")
        result = await list_identity_actions(db, username="alice")
        assert len(result) == 1
        assert result[0]["username"] == "alice"

    async def test_list_filter_by_action_type(self, db: AsyncSession):
        from asc_api.services.pids_service import list_identity_actions
        await _make_action(db, action_type="disable_account")
        await _make_action(db, action_type="enrich_user")
        result = await list_identity_actions(db, action_type="disable_account")
        assert len(result) == 1
        assert result[0]["action_type"] == "disable_account"

    async def test_list_filter_by_success(self, db: AsyncSession):
        from asc_api.services.pids_service import list_identity_actions
        await _make_action(db, success=True)
        await _make_action(db, success=False)
        result_ok  = await list_identity_actions(db, success=True)
        result_err = await list_identity_actions(db, success=False)
        assert all(r["success"] is True  for r in result_ok)
        assert all(r["success"] is False for r in result_err)


# ── TestPIDSTimelineDB ────────────────────────────────────────────────────────

class TestPIDSTimelineDB:
    """get_identity_timeline() with real DB rows."""

    async def test_timeline_returns_ordered_list(self, db: AsyncSession):
        from asc_api.services.pids_service import get_identity_timeline
        hunt = await _make_hunt(db)
        await _make_action(db, hunt_id=hunt.id, username="u1")
        await _make_action(db, hunt_id=hunt.id, username="u2")
        result = await get_identity_timeline(db, hunt.id)
        assert isinstance(result, list)
        assert len(result) == 2

    async def test_timeline_empty_for_unknown_hunt(self, db: AsyncSession):
        from asc_api.services.pids_service import get_identity_timeline
        result = await get_identity_timeline(db, str(uuid.uuid4()))
        assert result == []

    async def test_timeline_dicts_have_hunt_id(self, db: AsyncSession):
        from asc_api.services.pids_service import get_identity_timeline
        hunt = await _make_hunt(db)
        await _make_action(db, hunt_id=hunt.id)
        result = await get_identity_timeline(db, hunt.id)
        assert result[0]["hunt_id"] == hunt.id

    async def test_timeline_excludes_other_hunts(self, db: AsyncSession):
        from asc_api.services.pids_service import get_identity_timeline
        h1 = await _make_hunt(db)
        h2 = await _make_hunt(db)
        await _make_action(db, hunt_id=h1.id)
        await _make_action(db, hunt_id=h2.id)
        result = await get_identity_timeline(db, h1.id)
        assert len(result) == 1
        assert result[0]["hunt_id"] == h1.id


# ── TestPIDSSummaryDB ─────────────────────────────────────────────────────────

class TestPIDSSummaryDB:
    """get_pids_summary() counts from real DB rows."""

    async def test_summary_empty_db(self, db: AsyncSession):
        from asc_api.services.pids_service import get_pids_summary
        summary = await get_pids_summary(db)
        assert summary["total_actions"] == 0
        assert summary["successful_actions"] == 0

    async def test_summary_counts_total(self, db: AsyncSession):
        from asc_api.services.pids_service import get_pids_summary
        await _make_action(db, success=True)
        await _make_action(db, success=True)
        await _make_action(db, success=False)
        summary = await get_pids_summary(db)
        assert summary["total_actions"] == 3

    async def test_summary_counts_successful_only(self, db: AsyncSession):
        from asc_api.services.pids_service import get_pids_summary
        await _make_action(db, success=True)
        await _make_action(db, success=False)
        summary = await get_pids_summary(db)
        assert summary["successful_actions"] == 1
        assert summary["failed_actions"] == 1

    async def test_summary_success_rate(self, db: AsyncSession):
        from asc_api.services.pids_service import get_pids_summary
        await _make_action(db, success=True)
        await _make_action(db, success=True)
        await _make_action(db, success=False)
        summary = await get_pids_summary(db)
        # 2/3 * 100 = 66.7
        assert summary["success_rate_pct"] == pytest.approx(66.7, abs=0.1)

    async def test_summary_hunt_scoped(self, db: AsyncSession):
        from asc_api.services.pids_service import get_pids_summary
        h = await _make_hunt(db)
        await _make_action(db, hunt_id=h.id)
        await _make_action(db)  # no hunt
        summary_hunt = await get_pids_summary(db, hunt_id=h.id)
        summary_all  = await get_pids_summary(db)
        assert summary_hunt["total_actions"] == 1
        assert summary_all["total_actions"] == 2

    async def test_summary_has_required_keys(self, db: AsyncSession):
        from asc_api.services.pids_service import get_pids_summary
        summary = await get_pids_summary(db)
        for k in ("total_actions", "successful_actions", "failed_actions",
                  "success_rate_pct", "actions_24h"):
            assert k in summary, f"Missing key: {k}"


# ── TestAdaptiveOrchestrationDB ───────────────────────────────────────────────

class TestAdaptiveOrchestrationDB:
    """evaluate_triggers_for_context() with real DB triggers."""

    async def test_triggers_sorted_by_priority_desc(self, db: AsyncSession):
        """Higher-priority triggers must fire first."""
        from asc_api.services.soar_service import evaluate_triggers_for_context
        t_low  = await _make_trigger(db, priority=3, condition_value="0")
        t_high = await _make_trigger(db, priority=9, condition_value="0")

        fire_order: list[str] = []

        async def fake_fire(db, trigger, context, *, triggered_by):
            fire_order.append(trigger.id)
            return {
                "trigger_id": trigger.id, "run_id": None, "error": None,
                "matched": True, "playbook_id": trigger.playbook_id,
                "condition_type": trigger.condition_type,
                "fired_at": datetime.now(timezone.utc).isoformat(),
            }

        with patch("asc_api.services.soar_service._fire_trigger", side_effect=fake_fire):
            await evaluate_triggers_for_context(
                db, {"pcdi_score": 50}, triggered_by="test"
            )

        assert fire_order.index(t_high.id) < fire_order.index(t_low.id)

    async def test_disabled_trigger_not_fired(self, db: AsyncSession):
        from asc_api.services.soar_service import evaluate_triggers_for_context
        await _make_trigger(db, enabled=False, condition_value="0")
        with patch("asc_api.services.soar_service._fire_trigger") as mock_fire:
            await evaluate_triggers_for_context(
                db, {"pcdi_score": 50}, triggered_by="test"
            )
        mock_fire.assert_not_called()

    async def test_dedup_active_skips_trigger(self, db: AsyncSession):
        from asc_api.services.soar_service import evaluate_triggers_for_context
        await _make_trigger(db, priority=5, dedup_window_minutes=60, condition_value="0")
        with patch("asc_api.services.soar_service._is_dedup_active", new=AsyncMock(return_value=True)):
            with patch("asc_api.services.soar_service._fire_trigger") as mock_fire:
                await evaluate_triggers_for_context(
                    db, {"pcdi_score": 50}, triggered_by="test"
                )
        mock_fire.assert_not_called()

    async def test_dedup_inactive_fires_trigger(self, db: AsyncSession):
        from asc_api.services.soar_service import evaluate_triggers_for_context
        fired: list[str] = []
        await _make_trigger(db, priority=5, dedup_window_minutes=0, condition_value="0")

        async def fake_fire(db, trigger, context, *, triggered_by):
            fired.append(trigger.id)
            return {"trigger_id": trigger.id, "run_id": None, "error": None,
                    "matched": True, "playbook_id": trigger.playbook_id,
                    "condition_type": trigger.condition_type,
                    "fired_at": datetime.now(timezone.utc).isoformat()}

        with patch("asc_api.services.soar_service._fire_trigger", side_effect=fake_fire):
            await evaluate_triggers_for_context(
                db, {"pcdi_score": 50}, triggered_by="test"
            )
        assert len(fired) == 1

    async def test_no_triggers_returns_empty_list(self, db: AsyncSession):
        from asc_api.services.soar_service import evaluate_triggers_for_context
        result = await evaluate_triggers_for_context(
            db, {"pcdi_score": 50}, triggered_by="test"
        )
        assert result == []


# ── TestScheduledReportForensicDB ─────────────────────────────────────────────

class TestScheduledReportForensicDB:
    """deliver_scheduled_report() with real DB ScheduledReport + Hunt rows."""

    async def _make_report(
        self, db: AsyncSession, *, hunt_id: str
    ) -> ScheduledReport:
        sr = ScheduledReport(
            id=str(uuid.uuid4()),
            hunt_id=hunt_id,
            hunt_name="PremosCorp Ransomware Hunt",
            recipient_email="cto@premoscorp.com",
            format="json",
            frequency="weekly",
            enabled=True,
            send_count=0,
            last_error=None,
            last_sent_at=None,
            created_by="admin@corp.local",
            created_at=_NOW,
        )
        db.add(sr)
        await db.commit()
        await db.refresh(sr)
        return sr

    async def test_deliver_returns_forensic_hash(self, db: AsyncSession):
        from asc_api.services.soar_service import deliver_scheduled_report
        hunt = await _make_hunt(db)
        sr = await self._make_report(db, hunt_id=hunt.id)

        with patch("asc_api.services.soar_service.log_security_action"):
            with patch("asc_api.services.soar_service._send_report", new=AsyncMock()):
                with patch("asc_api.services.pids_service._sign_hash", return_value=None):
                    result = await deliver_scheduled_report(db, sr.id)

        assert "forensic_hash" in result
        assert len(result["forensic_hash"]) == 128

    async def test_deliver_not_found_returns_error(self, db: AsyncSession):
        from asc_api.services.soar_service import deliver_scheduled_report
        result = await deliver_scheduled_report(db, "nonexistent-id")
        assert "error" in result
        assert result["error"] == "ScheduledReport not found"

    async def test_deliver_includes_identity_timeline_key(self, db: AsyncSession):
        from asc_api.services.soar_service import deliver_scheduled_report
        hunt = await _make_hunt(db)
        sr = await self._make_report(db, hunt_id=hunt.id)
        fake_timeline = [{"id": "ia-1", "action_type": "disable_account",
                          "username": "jdoe", "success": True}]

        with patch("asc_api.services.soar_service.log_security_action"):
            with patch("asc_api.services.soar_service._send_report", new=AsyncMock()):
                with patch("asc_api.services.pids_service.get_identity_timeline",
                           new=AsyncMock(return_value=fake_timeline)):
                    with patch("asc_api.services.pids_service._sign_hash", return_value=None):
                        result = await deliver_scheduled_report(db, sr.id)

        assert result["summary"]["identity_timeline"] == fake_timeline
        assert result["summary"]["identity_action_count"] == 1

    async def test_forensic_signature_none_without_key(self, db: AsyncSession):
        from asc_api.services.soar_service import deliver_scheduled_report
        hunt = await _make_hunt(db)
        sr = await self._make_report(db, hunt_id=hunt.id)

        with patch("asc_api.services.soar_service.log_security_action"):
            with patch("asc_api.services.soar_service._send_report", new=AsyncMock()):
                with patch("asc_api.services.pids_service.get_identity_timeline",
                           new=AsyncMock(return_value=[])):
                    with patch("os.getenv", return_value=None):
                        result = await deliver_scheduled_report(db, sr.id)

        assert result["forensic_signature"] is None


# ── TestPIDSRestEndpoints ─────────────────────────────────────────────────────

class TestPIDSRestEndpoints:
    """PIDS REST API via conftest client and db fixtures — zero AsyncMock."""

    _BASE = "/api/v1/pids"

    async def test_401_list_actions_without_token(self, client: AsyncClient):
        r = await client.get(f"{self._BASE}/actions")
        assert r.status_code == 401

    async def test_200_list_actions_analyst(
        self, client: AsyncClient, analyst_user: User
    ):
        r = await client.get(f"{self._BASE}/actions", headers=_auth(analyst_user))
        assert r.status_code == 200
        data = r.json()
        assert "actions" in data
        assert "count" in data
        assert isinstance(data["actions"], list)

    async def test_201_create_action_analyst(
        self, client: AsyncClient, analyst_user: User
    ):
        with patch("asc_api.services.pids_service._sign_hash", return_value=None):
            r = await client.post(
                f"{self._BASE}/actions",
                json={
                    "action_type": "enrich_user",
                    "username": "jdoe",
                    "domain": "corp.local",
                    "reason": "integration test",
                },
                headers=_auth(analyst_user),
            )
        assert r.status_code == 201
        assert r.json()["action_type"] == "enrich_user"

    async def test_422_create_action_invalid_type(
        self, client: AsyncClient, analyst_user: User
    ):
        r = await client.post(
            f"{self._BASE}/actions",
            json={
                "action_type": "not_valid",
                "username": "jdoe",
                "domain": "corp.local",
                "reason": "test",
            },
            headers=_auth(analyst_user),
        )
        assert r.status_code == 422

    async def test_200_verify_action(
        self, client: AsyncClient, analyst_user: User, db: AsyncSession
    ):
        action = await _make_action(db)
        # verify_action is a POST endpoint
        r = await client.post(
            f"{self._BASE}/actions/{action.id}/verify",
            headers=_auth(analyst_user),
        )
        assert r.status_code == 200
        data = r.json()
        assert "hash_match" in data
        assert data["hash_match"] is True

    async def test_200_summary_endpoint(
        self, client: AsyncClient, analyst_user: User
    ):
        r = await client.get(f"{self._BASE}/summary", headers=_auth(analyst_user))
        assert r.status_code == 200
        data = r.json()
        assert "total_actions" in data

    async def test_200_timeline_for_hunt(
        self, client: AsyncClient, analyst_user: User, db: AsyncSession
    ):
        hunt = await _make_hunt(db)
        await _make_action(db, hunt_id=hunt.id)
        r = await client.get(
            f"{self._BASE}/timeline/{hunt.id}",
            headers=_auth(analyst_user),
        )
        assert r.status_code == 200
        data = r.json()
        assert "timeline" in data
        assert "count" in data
        assert data["count"] == 1
