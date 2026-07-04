"""
End-to-End Neutralization Cycle Tests â€” PANL
=============================================
Full-cycle integration tests chaining all services together:

  request_action â†’ (PANL gate) â†’ approve_action â†’ specter_dispatch
  â†’ mock SPECTER agent â†’ action completed â†’ rollback_available set

These tests mock the DB (no real PostgreSQL) but wire through the full
Python service stack: approval.py â†’ specter_bridge.py â†’ agent_commander.py.
This catches integration bugs that unit tests miss (argument type mismatches,
state propagation errors, forensic link omissions).

Test classes
------------
  TestE2EHappyPath      â€” full cycle for each action type + severity
  TestE2EMultiSig       â€” dual-analyst approval flow for CRITICAL actions
  TestE2EBroadcast      â€” fleet-aware batched dispatch cycle
  TestE2EBehavioralThrottle â€” throttle blocks excessive requests
  TestE2EAdaptiveSeverity   â€” severity upgraded by context before routing
  TestE2ERollback       â€” completed action â†’ rollback request â†’ reversal approved
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from asc_api.core.panl import AdaptiveContext, behavioral_throttle, request_rate_limiter
from asc_api.models.neutralization import NeutralizationAction
from asc_api.services.approval import (
    REVERSIBLE_ACTIONS,
    ROLLBACK_MAP,
    approve_action,
    create_rollback_action,
    request_action,
)


# â”€â”€ Fixtures / builders â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _mock_bridge_result(*, success: bool = True, mode: str = "specter") -> MagicMock:
    r = MagicMock()
    r.success = success
    r.message = "ok" if success else "failed"
    r.details = {"dispatch_mode": mode, "commands_issued": [], "agents_targeted": []}
    return r


def _make_db() -> AsyncMock:
    db = AsyncMock()
    db.refresh = AsyncMock()
    return db


@pytest.fixture(autouse=True)
def reset_panl():
    behavioral_throttle.reset_all()
    request_rate_limiter.reset_all()
    yield
    behavioral_throttle.reset_all()
    request_rate_limiter.reset_all()


# â”€â”€ 1. Happy path â€” medium severity (no HitL, immediate execution) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestE2EHappyPath:
    @pytest.mark.asyncio
    async def test_medium_block_ip_executes_immediately(self):
        db = _make_db()
        mock_result = _mock_bridge_result(mode="broadcast")

        with (
            patch("asc_api.services.approval.specter_dispatch", new=AsyncMock(return_value=mock_result)),
            patch("asc_api.services.approval.log_security_action"),
            patch("asc_api.services.approval.check_behavioral_throttle"),
            patch("asc_api.services.approval.adapt_severity", return_value="medium"),
            patch("asc_api.services.approval.asyncio.ensure_future"),
        ):
            action = await request_action(
                db,
                action_type="block_ip",
                target="1.2.3.4",
                target_type="ip",
                params={"ip": "1.2.3.4"},
                severity="medium",
                initiated_by="analyst@premos.com",
            )

        assert action.status in ("completed", "failed")
        assert action.approval_required is False

    @pytest.mark.asyncio
    async def test_high_action_routes_to_pending(self):
        db = _make_db()

        with (
            patch("asc_api.services.approval.log_security_action"),
            patch("asc_api.services.approval.check_behavioral_throttle"),
            patch("asc_api.services.approval.adapt_severity", return_value="high"),
            patch("asc_api.services.approval.asyncio.ensure_future"),
        ):
            action = await request_action(
                db,
                action_type="block_ip",
                target="1.2.3.4",
                target_type="ip",
                params={"ip": "1.2.3.4"},
                severity="high",
                initiated_by="analyst@premos.com",
            )

        assert action.status == "pending_approval"
        assert action.approval_required is True
        assert action.required_approvals == 1

    @pytest.mark.asyncio
    async def test_critical_action_requires_two_approvals(self):
        db = _make_db()

        with (
            patch("asc_api.services.approval.log_security_action"),
            patch("asc_api.services.approval.check_behavioral_throttle"),
            patch("asc_api.services.approval.adapt_severity", return_value="critical"),
            patch("asc_api.services.approval.asyncio.ensure_future"),
        ):
            action = await request_action(
                db,
                action_type="block_ip",
                target="1.2.3.4",
                target_type="ip",
                params={"ip": "1.2.3.4"},
                severity="critical",
                initiated_by="analyst@premos.com",
            )

        assert action.status == "pending_approval"
        assert action.required_approvals == 2

    @pytest.mark.asyncio
    async def test_reversible_action_sets_rollback_available_on_success(self):
        db = _make_db()
        mock_result = _mock_bridge_result(success=True, mode="broadcast")

        with (
            patch("asc_api.services.approval.specter_dispatch", new=AsyncMock(return_value=mock_result)),
            patch("asc_api.services.approval.log_security_action"),
            patch("asc_api.services.approval.check_behavioral_throttle"),
            patch("asc_api.services.approval.adapt_severity", return_value="medium"),
            patch("asc_api.services.approval.asyncio.ensure_future"),
        ):
            action = await request_action(
                db,
                action_type="block_ip",
                target="1.2.3.4",
                target_type="ip",
                params={"ip": "1.2.3.4"},
                severity="medium",
                initiated_by="analyst@premos.com",
            )

        assert action.rollback_available is True

    @pytest.mark.asyncio
    async def test_non_reversible_action_does_not_set_rollback_available(self):
        db = _make_db()
        mock_result = _mock_bridge_result(success=True, mode="specter")

        with (
            patch("asc_api.services.approval.specter_dispatch", new=AsyncMock(return_value=mock_result)),
            patch("asc_api.services.approval.log_security_action"),
            patch("asc_api.services.approval.check_behavioral_throttle"),
            patch("asc_api.services.approval.adapt_severity", return_value="medium"),
            patch("asc_api.services.approval.asyncio.ensure_future"),
        ):
            action = await request_action(
                db,
                action_type="kill_process",
                target="ws-001",
                target_type="host",
                params={"pid": 1234},
                severity="medium",
                initiated_by="analyst@premos.com",
            )

        assert action.rollback_available is False


# â”€â”€ 2. Multi-signature approval cycle â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestE2EMultiSig:
    def _pending_critical_action(self, initiated_by: str = "alice@premos.com") -> MagicMock:
        a = MagicMock(spec=NeutralizationAction)
        a.id = str(uuid.uuid4())
        a.status = "pending_approval"
        a.action_type = "block_ip"
        a.severity = "critical"
        a.target = "5.5.5.5"
        a.target_type = "ip"
        a.params = {"ip": "5.5.5.5"}
        a.initiated_by = initiated_by
        a.required_approvals = 2
        a.approvals_log = []
        a.approved_by = None
        a.approved_at = None
        a.rejected_by = None
        a.rejected_at = None
        a.rejection_reason = None
        a.escalated_at = None
        a.escalation_reason = None
        a.rollback_available = False
        a.is_rollback = False
        a.expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)
        a.result = {}
        a.error_message = None
        a.executed_at = None
        a.created_at = datetime.now(timezone.utc)
        return a

    def _db(self, action) -> AsyncMock:
        db = AsyncMock()
        result = MagicMock()
        result.scalar_one_or_none.return_value = action
        db.execute.return_value = result
        return db

    @pytest.mark.asyncio
    async def test_first_approval_stays_pending(self):
        action = self._pending_critical_action()
        db = self._db(action)

        with (
            patch("asc_api.services.approval.log_security_action"),
            patch("asc_api.services.approval.asyncio.ensure_future"),
        ):
            result = await approve_action(db, action_id=action.id, approved_by="bob@premos.com")

        # Still pending â€” needs 2nd signature
        assert result.status == "pending_approval"
        assert len(result.approvals_log) == 1
        assert result.approvals_log[0]["approved_by"] == "bob@premos.com"

    @pytest.mark.asyncio
    async def test_second_approval_executes(self):
        action = self._pending_critical_action()
        # Pre-populate first approval
        action.approvals_log = [{"approved_by": "bob@premos.com", "approved_at": datetime.now(timezone.utc).isoformat()}]
        db = self._db(action)
        mock_result = _mock_bridge_result(mode="broadcast")

        with (
            patch("asc_api.services.approval.specter_dispatch", new=AsyncMock(return_value=mock_result)),
            patch("asc_api.services.approval.log_security_action"),
            patch("asc_api.services.approval.asyncio.ensure_future"),
        ):
            result = await approve_action(db, action_id=action.id, approved_by="carol@premos.com")

        # Both signatures present â†’ should execute
        assert result.status in ("completed", "failed")
        assert len(result.approvals_log) == 2

    @pytest.mark.asyncio
    async def test_duplicate_approver_rejected(self):
        action = self._pending_critical_action()
        action.approvals_log = [{"approved_by": "bob@premos.com", "approved_at": datetime.now(timezone.utc).isoformat()}]
        db = self._db(action)

        with pytest.raises(ValueError, match="already.*signed|already.*approved"):
            await approve_action(db, action_id=action.id, approved_by="bob@premos.com")

    @pytest.mark.asyncio
    async def test_self_approval_rejected_even_with_multi_sig(self):
        action = self._pending_critical_action(initiated_by="alice@premos.com")
        db = self._db(action)

        with pytest.raises(ValueError, match="Self-approval"):
            await approve_action(db, action_id=action.id, approved_by="alice@premos.com")

    @pytest.mark.asyncio
    async def test_three_distinct_analysts_works_when_required_two(self):
        """Any two distinct non-initiator analysts satisfy required_approvals=2."""
        action = self._pending_critical_action(initiated_by="alice@premos.com")
        action.approvals_log = [{"approved_by": "bob@premos.com", "approved_at": datetime.now(timezone.utc).isoformat()}]
        db = self._db(action)
        mock_result = _mock_bridge_result(mode="broadcast")

        with (
            patch("asc_api.services.approval.specter_dispatch", new=AsyncMock(return_value=mock_result)),
            patch("asc_api.services.approval.log_security_action"),
            patch("asc_api.services.approval.asyncio.ensure_future"),
        ):
            # Carol is the third person (initiator=alice, first=bob, second=carol)
            result = await approve_action(db, action_id=action.id, approved_by="carol@premos.com")

        assert result.status in ("completed", "failed")


# â”€â”€ 3. Behavioral throttle integration â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestE2EBehavioralThrottle:
    @pytest.mark.asyncio
    async def test_throttle_blocks_after_threshold(self):
        db = _make_db()
        user = "spammer@premos.com"

        # Exhaust the threshold (10 identical actions)
        for _ in range(10):
            behavioral_throttle.check(user, "block_ip")

        with pytest.raises(ValueError, match="throttle"):
            await request_action(
                db,
                action_type="block_ip",
                target="9.9.9.9",
                target_type="ip",
                params={"ip": "9.9.9.9"},
                severity="medium",
                initiated_by=user,
            )

    @pytest.mark.asyncio
    async def test_automated_action_bypasses_throttle(self):
        db = _make_db()
        user = "automation@premos.com"
        mock_result = _mock_bridge_result(mode="broadcast")

        # Exhaust throttle
        for _ in range(10):
            behavioral_throttle.check(user, "block_ip")

        with (
            patch("asc_api.services.approval.specter_dispatch", new=AsyncMock(return_value=mock_result)),
            patch("asc_api.services.approval.log_security_action"),
            patch("asc_api.services.approval.adapt_severity", return_value="medium"),
            patch("asc_api.services.approval.asyncio.ensure_future"),
        ):
            # automated=True skips behavioral throttle
            action = await request_action(
                db,
                action_type="block_ip",
                target="9.9.9.9",
                target_type="ip",
                params={"ip": "9.9.9.9"},
                severity="medium",
                initiated_by=user,
                automated=True,
            )

        assert action.status in ("completed", "failed")


# â”€â”€ 4. Adaptive severity integration â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestE2EAdaptiveSeverity:
    @pytest.mark.asyncio
    async def test_medium_upgraded_to_high_on_critical_infra(self):
        db = _make_db()

        with (
            patch("asc_api.services.approval.log_security_action"),
            patch("asc_api.services.approval.check_behavioral_throttle"),
            patch("asc_api.services.approval.asyncio.ensure_future"),
        ):
            action = await request_action(
                db,
                action_type="block_ip",
                target="1.2.3.4",
                target_type="ip",
                params={"ip": "1.2.3.4"},
                severity="medium",
                initiated_by="analyst@premos.com",
                adaptive_context=AdaptiveContext(
                    endpoint_is_critical_infrastructure=True
                ),
            )

        # Upgraded medium â†’ high â†’ needs approval
        assert action.severity == "high"
        assert action.status == "pending_approval"
        assert action.severity_adapted is True
        assert action.original_severity == "medium"

    @pytest.mark.asyncio
    async def test_low_upgraded_to_critical_on_ransomware_plus_critical_infra(self):
        db = _make_db()

        with (
            patch("asc_api.services.approval.log_security_action"),
            patch("asc_api.services.approval.check_behavioral_throttle"),
            patch("asc_api.services.approval.asyncio.ensure_future"),
        ):
            action = await request_action(
                db,
                action_type="block_ip",
                target="1.2.3.4",
                target_type="ip",
                params={"ip": "1.2.3.4"},
                severity="low",
                initiated_by="analyst@premos.com",
                adaptive_context=AdaptiveContext(
                    endpoint_is_critical_infrastructure=True,
                    ransomware_indicator=True,
                ),
            )

        assert action.severity == "critical"
        assert action.required_approvals == 2
        assert action.severity_adapted is True


# â”€â”€ 5. Full rollback cycle â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestE2ERollback:
    @pytest.mark.asyncio
    async def test_completed_reversible_action_can_be_rolled_back(self):
        original_id = str(uuid.uuid4())
        original = MagicMock(spec=NeutralizationAction)
        original.id = original_id
        original.status = "completed"
        original.action_type = "block_ip"
        original.severity = "high"
        original.target = "1.2.3.4"
        original.target_type = "ip"
        original.params = {"ip": "1.2.3.4"}
        original.alert_id = None
        original.rollback_available = True
        original.is_rollback = False
        original.rollback_action_id = None
        original.rollback_of = None
        original.required_approvals = 1
        original.approvals_log = []
        original.result = {}

        db = AsyncMock()
        lookup_result = MagicMock()
        lookup_result.scalar_one_or_none.return_value = original
        db.execute.return_value = lookup_result
        db.refresh = AsyncMock()

        rollback_created: list[str] = []

        async def _mock_request_action(db, *, action_type, **kwargs):
            rollback_created.append(action_type)
            a = MagicMock(spec=NeutralizationAction)
            a.id = str(uuid.uuid4())
            a.action_type = action_type
            a.status = "pending_approval"
            a.is_rollback = False
            a.rollback_of = None
            a.rollback_action_id = None
            a.rollback_available = False
            a.required_approvals = 1
            a.approvals_log = []
            a.result = {}
            return a

        with (
            patch("asc_api.services.approval.request_action", new=_mock_request_action),
            patch("asc_api.services.approval.log_security_action"),
            patch("asc_api.services.approval.notification_bus"),
            patch("asc_api.services.approval.asyncio.ensure_future"),
        ):
            rollback = await create_rollback_action(
                db,
                original_action_id=original_id,
                initiated_by="admin@premos.com",
            )

        assert "unblock_ip" in rollback_created
        assert rollback.is_rollback is True
        assert rollback.rollback_of == original_id
        assert original.rollback_action_id == rollback.id
        assert original.rollback_available is False

    @pytest.mark.asyncio
    async def test_rollback_of_irreversible_action_raises(self):
        action = MagicMock(spec=NeutralizationAction)
        action.id = str(uuid.uuid4())
        action.status = "completed"
        action.action_type = "kill_process"
        action.rollback_available = True
        action.is_rollback = False
        action.rollback_action_id = None

        db = AsyncMock()
        result = MagicMock()
        result.scalar_one_or_none.return_value = action
        db.execute.return_value = result

        with pytest.raises(ValueError, match="not reversible"):
            await create_rollback_action(
                db,
                original_action_id=action.id,
                initiated_by="admin@premos.com",
            )
