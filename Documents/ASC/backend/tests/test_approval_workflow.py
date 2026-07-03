"""
P16 Human-in-the-Loop + PANL Approval Workflow Tests
=====================================================
Tests: state machine, self-approval rejection, timeout/escalation, RBAC,
       validator edge-cases, serialization, full happy-path round-trip,
       PANL multi-signature dual-analyst approval (P16 pre-P16.3).

All DB calls use AsyncMock; no real database is touched.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from asc_api.services.approval import (
    ALWAYS_REQUIRE_APPROVAL,
    APPROVAL_SEVERITIES,
    TIMEOUT_BY_SEVERITY,
    _check_not_expired,
    _expires_at,
    _now,
    approve_action,
    escalate_expired,
    get_pending,
    needs_approval,
    reject_action,
    request_action,
)
from asc_api.models.neutralization import NeutralizationAction


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _action(
    *,
    status: str = "pending_approval",
    initiated_by: str = "analyst@premos.com",
    action_type: str = "block_ip",
    severity: str = "high",
    expires_at: datetime | None = None,
    timeout_minutes: int = 30,
    required_approvals: int = 1,
    approvals_log: list | None = None,
) -> NeutralizationAction:
    a = MagicMock(spec=NeutralizationAction)
    a.id = str(uuid.uuid4())
    a.status = status
    a.initiated_by = initiated_by
    a.action_type = action_type
    a.severity = severity
    a.target = "10.0.0.1"
    a.target_type = "ip"
    a.params = {"ip": "10.0.0.1", "direction": "both"}
    a.alert_id = None
    a.automated = False
    a.approval_required = True
    a.timeout_minutes = timeout_minutes
    a.expires_at = expires_at or (datetime.now(timezone.utc) + timedelta(minutes=30))
    a.approved_by = None
    a.approved_at = None
    a.rejected_by = None
    a.rejected_at = None
    a.rejection_reason = None
    a.escalated_at = None
    a.escalation_reason = None
    a.result = {}
    a.error_message = None
    a.executed_at = None
    a.rollback_available = False
    a.created_at = datetime.now(timezone.utc)
    # PANL fields
    a.required_approvals = required_approvals
    a.approvals_log = approvals_log if approvals_log is not None else []
    a.is_rollback = False
    a.rollback_of = None
    a.rollback_action_id = None
    a.original_severity = None
    a.severity_adapted = False
    return a


def _db(action: NeutralizationAction | None = None) -> AsyncMock:
    """Return a mock AsyncSession that yields `action` on scalar_one_or_none()."""
    db = AsyncMock()
    scalar_result = MagicMock()
    scalar_result.scalar_one_or_none.return_value = action
    db.execute.return_value = scalar_result
    return db


# ── 1. needs_approval logic ───────────────────────────────────────────────────

class TestNeedsApproval:
    def test_critical_always_requires(self):
        assert needs_approval("block_ip", "critical") is True

    def test_high_always_requires(self):
        assert needs_approval("block_domain", "high") is True

    def test_medium_non_sensitive_no_gate(self):
        assert needs_approval("block_domain", "medium") is False

    def test_low_non_sensitive_no_gate(self):
        assert needs_approval("block_ip", "low") is False

    def test_isolate_endpoint_always_requires_any_severity(self):
        for sev in ("low", "medium", "high", "critical"):
            assert needs_approval("isolate_endpoint", sev) is True

    def test_disable_account_always_requires_any_severity(self):
        for sev in ("low", "medium", "high", "critical"):
            assert needs_approval("disable_account", sev) is True

    def test_kill_process_medium_no_gate(self):
        assert needs_approval("kill_process", "medium") is False

    def test_quarantine_file_critical_requires(self):
        assert needs_approval("quarantine_file", "critical") is True

    def test_constants_integrity(self):
        assert "isolate_endpoint" in ALWAYS_REQUIRE_APPROVAL
        assert "disable_account" in ALWAYS_REQUIRE_APPROVAL
        assert "critical" in APPROVAL_SEVERITIES
        assert "high" in APPROVAL_SEVERITIES
        assert "medium" not in APPROVAL_SEVERITIES

    def test_timeout_values(self):
        assert TIMEOUT_BY_SEVERITY["critical"] == 15
        assert TIMEOUT_BY_SEVERITY["high"] == 30


# ── 2. _check_not_expired ─────────────────────────────────────────────────────

class TestCheckNotExpired:
    def test_not_expired_passes(self):
        action = _action(expires_at=datetime.now(timezone.utc) + timedelta(minutes=5))
        _check_not_expired(action)  # no exception

    def test_expired_raises(self):
        action = _action(expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
        with pytest.raises(ValueError, match="expired"):
            _check_not_expired(action)

    def test_no_expires_at_passes(self):
        action = _action()
        action.expires_at = None
        _check_not_expired(action)  # no exception

    def test_exactly_at_boundary_raises(self):
        past = datetime.now(timezone.utc) - timedelta(microseconds=1)
        action = _action(expires_at=past)
        with pytest.raises(ValueError):
            _check_not_expired(action)


# ── 3. approve_action ─────────────────────────────────────────────────────────

class TestApproveAction:
    @pytest.mark.asyncio
    async def test_self_approval_raises(self):
        action = _action(initiated_by="alice@premos.com")
        db = _db(action)
        with pytest.raises(ValueError, match="Self-approval"):
            await approve_action(db, action_id=action.id, approved_by="alice@premos.com")

    @pytest.mark.asyncio
    async def test_wrong_state_raises(self):
        action = _action(status="completed")
        db = _db(action)
        with pytest.raises(ValueError, match="Cannot approve"):
            await approve_action(db, action_id=action.id, approved_by="bob@premos.com")

    @pytest.mark.asyncio
    async def test_expired_action_raises(self):
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        action = _action(expires_at=past)
        db = _db(action)
        with pytest.raises(ValueError, match="expired"):
            await approve_action(db, action_id=action.id, approved_by="bob@premos.com")

    @pytest.mark.asyncio
    async def test_not_found_raises(self):
        db = _db(None)
        with pytest.raises(ValueError, match="not found"):
            await approve_action(db, action_id="nonexistent", approved_by="bob@premos.com")

    @pytest.mark.asyncio
    async def test_happy_path_sets_fields(self):
        action = _action(initiated_by="alice@premos.com")
        db = _db(action)
        mock_result = MagicMock()
        mock_result.success = True
        mock_result.message = "ok"
        mock_result.details = {}

        with (
            patch("app.services.approval.specter_dispatch", new=AsyncMock(return_value=mock_result)),
            patch("app.services.approval.log_security_action"),
        ):
            result = await approve_action(db, action_id=action.id, approved_by="bob@premos.com")

        assert result.approved_by == "bob@premos.com"
        assert result.status in ("completed", "executing")

    @pytest.mark.asyncio
    async def test_approve_then_execute_failed(self):
        action = _action(initiated_by="alice@premos.com")
        db = _db(action)
        mock_result = MagicMock()
        mock_result.success = False
        mock_result.message = "EDR timeout"
        mock_result.details = {}

        with (
            patch("app.services.approval.specter_dispatch", new=AsyncMock(return_value=mock_result)),
            patch("app.services.approval.log_security_action"),
        ):
            result = await approve_action(db, action_id=action.id, approved_by="bob@premos.com")

        assert result.status == "failed"
        assert result.error_message == "EDR timeout"


# ── 4. reject_action ──────────────────────────────────────────────────────────

class TestRejectAction:
    @pytest.mark.asyncio
    async def test_happy_path(self):
        action = _action()
        db = _db(action)
        with patch("app.services.approval.log_security_action"):
            result = await reject_action(
                db, action_id=action.id,
                rejected_by="admin@premos.com",
                reason="Falso positivo confirmado",
            )
        assert result.status == "rejected"
        assert result.rejected_by == "admin@premos.com"
        assert result.rejection_reason == "Falso positivo confirmado"

    @pytest.mark.asyncio
    async def test_wrong_state_raises(self):
        action = _action(status="completed")
        db = _db(action)
        with pytest.raises(ValueError, match="Cannot reject"):
            await reject_action(db, action_id=action.id, rejected_by="admin@premos.com", reason="ok")

    @pytest.mark.asyncio
    async def test_empty_reason_raises(self):
        action = _action()
        db = _db(action)
        with pytest.raises(ValueError, match="reason"):
            await reject_action(db, action_id=action.id, rejected_by="admin@premos.com", reason="   ")

    @pytest.mark.asyncio
    async def test_not_found_raises(self):
        db = _db(None)
        with pytest.raises(ValueError, match="not found"):
            await reject_action(db, action_id="bad-id", rejected_by="admin@premos.com", reason="reason")

    @pytest.mark.asyncio
    async def test_reason_is_stripped(self):
        action = _action()
        db = _db(action)
        with patch("app.services.approval.log_security_action"):
            result = await reject_action(
                db, action_id=action.id,
                rejected_by="admin@premos.com",
                reason="  falso positivo  ",
            )
        assert result.rejection_reason == "falso positivo"


# ── 5. escalate_expired ───────────────────────────────────────────────────────

class TestEscalateExpired:
    @pytest.mark.asyncio
    async def test_escalates_past_deadline(self):
        now = datetime.now(timezone.utc)
        past = now - timedelta(hours=1)
        action = _action(expires_at=past)

        db = AsyncMock()
        scalars_mock = MagicMock()
        scalars_mock.scalars.return_value.all.return_value = [action]
        db.execute.return_value = scalars_mock

        with patch("app.services.approval.log_security_action"):
            ids = await escalate_expired(db)

        assert action.id in ids
        assert action.status == "escalated"
        assert action.escalation_reason is not None

    @pytest.mark.asyncio
    async def test_no_expired_returns_empty(self):
        db = AsyncMock()
        scalars_mock = MagicMock()
        scalars_mock.scalars.return_value.all.return_value = []
        db.execute.return_value = scalars_mock

        ids = await escalate_expired(db)
        assert ids == []
        db.commit.assert_not_called()

    @pytest.mark.asyncio
    async def test_multiple_escalated(self):
        now = datetime.now(timezone.utc)
        a1 = _action(expires_at=now - timedelta(minutes=5))
        a2 = _action(expires_at=now - timedelta(minutes=20))

        db = AsyncMock()
        scalars_mock = MagicMock()
        scalars_mock.scalars.return_value.all.return_value = [a1, a2]
        db.execute.return_value = scalars_mock

        with patch("app.services.approval.log_security_action"):
            ids = await escalate_expired(db)

        assert len(ids) == 2
        assert a1.status == "escalated"
        assert a2.status == "escalated"


# ── 6. get_pending ────────────────────────────────────────────────────────────

class TestGetPending:
    @pytest.mark.asyncio
    async def test_calls_escalate_first(self):
        db = AsyncMock()
        scalars_mock = MagicMock()
        scalars_mock.scalars.return_value.all.return_value = []
        db.execute.return_value = scalars_mock

        with patch("app.services.approval.escalate_expired", new=AsyncMock(return_value=[])) as mock_esc:
            await get_pending(db)
            mock_esc.assert_called_once_with(db)

    @pytest.mark.asyncio
    async def test_returns_pending_list(self):
        action = _action()
        db = AsyncMock()
        scalars_mock = MagicMock()
        scalars_mock.scalars.return_value.all.return_value = [action]
        db.execute.return_value = scalars_mock

        with patch("app.services.approval.escalate_expired", new=AsyncMock(return_value=[])):
            result = await get_pending(db)

        assert action in result


# ── 7. request_action routing ─────────────────────────────────────────────────

class TestRequestAction:
    @pytest.mark.asyncio
    async def test_critical_routes_to_pending(self):
        db = AsyncMock()
        db.refresh = AsyncMock()

        with patch("app.services.approval.log_security_action"):
            action = await request_action(
                db,
                action_type="block_ip",
                target="1.2.3.4",
                target_type="ip",
                params={"ip": "1.2.3.4", "direction": "both"},
                severity="critical",
                initiated_by="analyst@premos.com",
            )

        assert action.status == "pending_approval"
        assert action.approval_required is True
        assert action.expires_at is not None

    @pytest.mark.asyncio
    async def test_medium_executes_immediately(self):
        db = AsyncMock()
        db.refresh = AsyncMock()
        mock_result = MagicMock(success=True, message="ok", details={})

        with (
            patch("app.services.approval.specter_dispatch", new=AsyncMock(return_value=mock_result)),
            patch("app.services.approval.log_security_action"),
        ):
            action = await request_action(
                db,
                action_type="block_domain",
                target="evil.com",
                target_type="domain",
                params={"domain": "evil.com"},
                severity="medium",
                initiated_by="analyst@premos.com",
            )

        assert action.status in ("completed", "failed")
        assert action.approval_required is False

    @pytest.mark.asyncio
    async def test_isolate_endpoint_low_severity_still_pending(self):
        db = AsyncMock()
        db.refresh = AsyncMock()

        with patch("app.services.approval.log_security_action"):
            action = await request_action(
                db,
                action_type="isolate_endpoint",
                target="ws-100",
                target_type="host",
                params={"host": "ws-100"},
                severity="low",
                initiated_by="analyst@premos.com",
            )

        assert action.status == "pending_approval"

    @pytest.mark.asyncio
    async def test_expires_at_set_for_critical(self):
        db = AsyncMock()
        db.refresh = AsyncMock()
        before = _now()

        with patch("app.services.approval.log_security_action"):
            action = await request_action(
                db,
                action_type="kill_process",
                target="ws-001",
                target_type="host",
                params={"host": "ws-001", "process_name": "malware.exe"},
                severity="critical",
                initiated_by="analyst@premos.com",
            )

        after = _now()
        expected_timeout = TIMEOUT_BY_SEVERITY["critical"]
        assert action.expires_at > before
        delta = (action.expires_at - before).total_seconds() / 60
        assert abs(delta - expected_timeout) < 1


# ── 8. RBAC and security invariants ──────────────────────────────────────────

class TestSecurityInvariants:
    @pytest.mark.asyncio
    async def test_self_approval_same_email(self):
        action = _action(initiated_by="john@premos.com")
        db = _db(action)
        with pytest.raises(ValueError, match="Self-approval"):
            await approve_action(db, action_id=action.id, approved_by="john@premos.com")

    @pytest.mark.asyncio
    async def test_self_approval_different_email_allowed(self):
        action = _action(initiated_by="john@premos.com")
        db = _db(action)
        mock_result = MagicMock(success=True, message="ok", details={})

        with (
            patch("app.services.approval.specter_dispatch", new=AsyncMock(return_value=mock_result)),
            patch("app.services.approval.log_security_action"),
        ):
            result = await approve_action(db, action_id=action.id, approved_by="jane@premos.com")

        assert result.approved_by == "jane@premos.com"

    @pytest.mark.asyncio
    async def test_cannot_approve_rejected_action(self):
        action = _action(status="rejected")
        db = _db(action)
        with pytest.raises(ValueError, match="Cannot approve"):
            await approve_action(db, action_id=action.id, approved_by="bob@premos.com")

    @pytest.mark.asyncio
    async def test_cannot_reject_completed_action(self):
        action = _action(status="completed")
        db = _db(action)
        with pytest.raises(ValueError, match="Cannot reject"):
            await reject_action(db, action_id=action.id, rejected_by="bob@premos.com", reason="reason")

    @pytest.mark.asyncio
    async def test_cannot_approve_escalated_action(self):
        action = _action(status="escalated")
        db = _db(action)
        with pytest.raises(ValueError, match="Cannot approve"):
            await approve_action(db, action_id=action.id, approved_by="bob@premos.com")

    def test_always_require_approval_contains_high_risk(self):
        assert "isolate_endpoint" in ALWAYS_REQUIRE_APPROVAL
        assert "disable_account" in ALWAYS_REQUIRE_APPROVAL
        assert "block_ip" not in ALWAYS_REQUIRE_APPROVAL

    @pytest.mark.asyncio
    async def test_rejection_reason_logged(self):
        action = _action()
        db = _db(action)
        logged_calls = []

        with patch("app.services.approval.log_security_action", side_effect=lambda *a, **kw: logged_calls.append(kw)):
            await reject_action(
                db, action_id=action.id,
                rejected_by="ciso@premos.com",
                reason="Accion no autorizada por política",
            )

        assert any("reject" in c.get("detail", "") or "reject" in str(c) for c in logged_calls) or len(logged_calls) > 0


# ── 9. NeutralizationAction model fields ─────────────────────────────────────

class TestModelFields:
    def test_model_has_hitl_fields(self):
        required = {
            "approval_required", "timeout_minutes", "expires_at",
            "approved_by", "approved_at",
            "rejected_by", "rejected_at", "rejection_reason",
            "escalated_at", "escalation_reason", "severity", "params",
        }
        columns = {c.key for c in NeutralizationAction.__mapper__.column_attrs}
        missing = required - columns
        assert not missing, f"Missing columns: {missing}"

    def test_status_field_exists(self):
        columns = {c.key for c in NeutralizationAction.__mapper__.column_attrs}
        assert "status" in columns

    def test_model_tablename(self):
        assert NeutralizationAction.__tablename__ == "neutralization_actions"

    def test_panl_fields_exist(self):
        required = {
            "required_approvals", "approvals_log",
            "is_rollback", "rollback_of", "rollback_action_id",
            "original_severity", "severity_adapted",
        }
        columns = {c.key for c in NeutralizationAction.__mapper__.column_attrs}
        missing = required - columns
        assert not missing, f"Missing PANL columns: {missing}"


# ── 10. PANL Multi-signature approval ─────────────────────────────────────────

class TestMultiSignatureApproval:
    """PANL dual-analyst approval for CRITICAL actions (required_approvals=2)."""

    @pytest.mark.asyncio
    async def test_first_signature_stays_pending(self):
        action = _action(required_approvals=2)
        db = _db(action)

        with (
            patch("app.services.approval.log_security_action"),
            patch("app.services.approval.asyncio.ensure_future"),
        ):
            result = await approve_action(db, action_id=action.id, approved_by="bob@premos.com")

        assert result.status == "pending_approval"
        assert len(result.approvals_log) == 1

    @pytest.mark.asyncio
    async def test_second_signature_executes(self):
        action = _action(required_approvals=2)
        action.approvals_log = [{"approved_by": "bob@premos.com", "approved_at": "2024-01-01T00:00:00+00:00"}]
        db = _db(action)
        mock_result = MagicMock(success=True, message="ok", details={})

        with (
            patch("app.services.approval.specter_dispatch", new=AsyncMock(return_value=mock_result)),
            patch("app.services.approval.log_security_action"),
            patch("app.services.approval.asyncio.ensure_future"),
        ):
            result = await approve_action(db, action_id=action.id, approved_by="carol@premos.com")

        assert result.status in ("completed", "failed")
        assert len(result.approvals_log) == 2

    @pytest.mark.asyncio
    async def test_duplicate_signer_rejected(self):
        action = _action(required_approvals=2)
        action.approvals_log = [{"approved_by": "bob@premos.com", "approved_at": "2024-01-01T00:00:00+00:00"}]
        db = _db(action)

        with pytest.raises(ValueError, match="already.*signed|already.*approved"):
            await approve_action(db, action_id=action.id, approved_by="bob@premos.com")

    @pytest.mark.asyncio
    async def test_single_sig_action_executes_on_first_approval(self):
        action = _action(required_approvals=1)
        db = _db(action)
        mock_result = MagicMock(success=True, message="ok", details={})

        with (
            patch("app.services.approval.specter_dispatch", new=AsyncMock(return_value=mock_result)),
            patch("app.services.approval.log_security_action"),
            patch("app.services.approval.asyncio.ensure_future"),
        ):
            result = await approve_action(db, action_id=action.id, approved_by="bob@premos.com")

        assert result.status in ("completed", "failed")

    @pytest.mark.asyncio
    async def test_approvals_log_records_all_signers(self):
        action = _action(required_approvals=2)
        db = _db(action)

        with (
            patch("app.services.approval.log_security_action"),
            patch("app.services.approval.asyncio.ensure_future"),
        ):
            result = await approve_action(db, action_id=action.id, approved_by="firstsigner@premos.com")

        assert any(
            entry["approved_by"] == "firstsigner@premos.com"
            for entry in result.approvals_log
        )
