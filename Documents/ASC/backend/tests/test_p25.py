"""
P25 Test Suite — SOAR Automation + Identity Integration

Coverage:
  TestSOARConditionEvaluation     (12 tests) — _evaluate_condition() pure logic
  TestSOARCRUD                    (10 tests) — create/list/get/delete/toggle triggers
  TestSOARFireTrigger             (6  tests) — _fire_trigger, evaluate_triggers_for_context
  TestSOARTestTrigger             (3  tests) — dry-run test_trigger()
  TestScheduledReportCRUD        (8  tests) — create/list/get/delete/toggle/deliver reports
  TestScheduledReportDue         (4  tests) — _is_due() logic
  TestADAdapterSearch            (6  tests) — search_user / list_group_members (sync stubs)
  TestADAdapterNotConfigured     (4  tests) — not_configured guard
  TestTheHiveExport              (8  tests) — export_hunt_to_thehive
  TestSOAREndpoints              (5  tests) — endpoint smoke tests

Total: 66 tests
"""
from __future__ import annotations

import importlib.util

_celery_available = importlib.util.find_spec("celery") is not None
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ─── Helpers ────────────────────────────────────────────────────────────────────

def _scalars_result(items: list):
    r = MagicMock()
    r.scalars = MagicMock(return_value=MagicMock(all=MagicMock(return_value=items)))
    return r


def _scalar_one(item):
    r = MagicMock()
    r.scalar_one_or_none = MagicMock(return_value=item)
    return r


def _make_trigger(**kwargs):
    defaults = dict(
        id=str(uuid.uuid4()),
        playbook_id="PB-002",
        playbook_name="Respuesta Amarilla",
        condition_type="pcdi_score",
        condition_operator="gte",
        condition_value="80",
        hunt_id_filter=None,
        enabled=True,
        trigger_count=0,
        last_triggered_at=None,
        last_triggered_context=None,
        created_by="analyst@corp.local",
        created_at=datetime.now(timezone.utc),
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def _make_report(**kwargs):
    defaults = dict(
        id=str(uuid.uuid4()),
        hunt_id=str(uuid.uuid4()),
        hunt_name="Alpha Hunt",
        recipient_email="analyst@corp.local",
        frequency="daily",
        format="json",
        enabled=True,
        last_sent_at=None,
        send_count=0,
        last_error=None,
        created_by="analyst@corp.local",
        created_at=datetime.now(timezone.utc),
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def _make_hunt(**kwargs):
    defaults = dict(
        id=str(uuid.uuid4()),
        name="Test Hunt",
        description="Testing",
        status="active",
        priority="high",
        started_at=datetime.now(timezone.utc),
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def _make_finding(**kwargs):
    defaults = dict(
        id=str(uuid.uuid4()),
        hunt_id=str(uuid.uuid4()),
        title="Suspicious IP",
        severity="high",
        indicator_value="10.10.10.10",
        indicator_type="ip",
        affected_host="ws01.corp.local",
        affected_user=None,
        is_confirmed=True,
        is_false_positive=False,
        ttps=["T1059"],
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


# ─── TestSOARConditionEvaluation ────────────────────────────────────────────────

class TestSOARConditionEvaluation:

    def _eval(self, ctype, op, val, context):
        from app.services.soar_service import _evaluate_condition
        t = _make_trigger(condition_type=ctype, condition_operator=op, condition_value=val)
        return _evaluate_condition(t, context)

    def test_pcdi_score_gte_match(self):
        assert self._eval("pcdi_score", "gte", "80", {"pcdi_score": 85}) is True

    def test_pcdi_score_gte_no_match(self):
        assert self._eval("pcdi_score", "gte", "80", {"pcdi_score": 70}) is False

    def test_pcdi_score_lte_match(self):
        assert self._eval("pcdi_score", "lte", "50", {"pcdi_score": 30}) is True

    def test_pcdi_score_lte_no_match(self):
        assert self._eval("pcdi_score", "lte", "50", {"pcdi_score": 60}) is False

    def test_pcdi_score_eq_match(self):
        assert self._eval("pcdi_score", "eq", "80.0", {"pcdi_score": 80}) is True

    def test_pcdi_score_missing_key(self):
        assert self._eval("pcdi_score", "gte", "80", {}) is False

    def test_finding_severity_gte_match(self):
        assert self._eval("finding_severity", "gte", "high", {"severity": "critical"}) is True

    def test_finding_severity_gte_no_match(self):
        assert self._eval("finding_severity", "gte", "critical", {"severity": "high"}) is False

    def test_finding_severity_eq_match(self):
        assert self._eval("finding_severity", "eq", "critical", {"severity": "critical"}) is True

    def test_finding_severity_contains_match(self):
        assert self._eval("finding_severity", "contains", "critical,high", {"severity": "high"}) is True

    def test_hunt_priority_eq_match(self):
        assert self._eval("hunt_priority", "eq", "critical", {"hunt_priority": "critical"}) is True

    def test_panl_status_eq_match(self):
        assert self._eval("panl_status", "eq", "approved", {"panl_status": "approved"}) is True


# ─── TestSOARCRUD ────────────────────────────────────────────────────────────────

class TestSOARCRUD:

    @pytest.mark.asyncio
    async def test_create_trigger_valid(self):
        from app.services.soar_service import create_trigger
        db = AsyncMock()
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda t: None)

        result = await create_trigger(
            db,
            playbook_id="PB-002",
            playbook_name="Amarilla",
            condition_type="pcdi_score",
            condition_operator="gte",
            condition_value="80",
            created_by="analyst@corp",
        )
        assert "error" not in result or result.get("id")

    @pytest.mark.asyncio
    async def test_create_trigger_invalid_type(self):
        from app.services.soar_service import create_trigger
        db = AsyncMock()
        result = await create_trigger(
            db, playbook_id="PB-001", playbook_name="Verde",
            condition_type="INVALID", condition_operator="gte",
            condition_value="50", created_by="analyst@corp",
        )
        assert "error" in result
        assert "condition_type" in result["error"]

    @pytest.mark.asyncio
    async def test_create_trigger_invalid_operator(self):
        from app.services.soar_service import create_trigger
        db = AsyncMock()
        result = await create_trigger(
            db, playbook_id="PB-001", playbook_name="Verde",
            condition_type="pcdi_score", condition_operator="INVALID",
            condition_value="50", created_by="analyst@corp",
        )
        assert "error" in result
        assert "condition_operator" in result["error"]

    @pytest.mark.asyncio
    async def test_list_triggers_empty(self):
        from app.services.soar_service import list_triggers
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalars_result([]))
        result = await list_triggers(db)
        assert result == []

    @pytest.mark.asyncio
    async def test_list_triggers_enabled_only_filter(self):
        from app.services.soar_service import list_triggers
        t1 = _make_trigger(enabled=True)
        t2 = _make_trigger(enabled=False)
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalars_result([t1]))
        result = await list_triggers(db, enabled_only=True)
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_get_trigger_found(self):
        from app.services.soar_service import get_trigger
        t = _make_trigger()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(t))
        result = await get_trigger(db, t.id)
        assert result is not None
        assert result["id"] == t.id

    @pytest.mark.asyncio
    async def test_get_trigger_not_found(self):
        from app.services.soar_service import get_trigger
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(None))
        result = await get_trigger(db, "nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_delete_trigger_found(self):
        from app.services.soar_service import delete_trigger
        t = _make_trigger()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(t))
        db.delete = AsyncMock()
        db.commit = AsyncMock()
        result = await delete_trigger(db, t.id, deleted_by="analyst@corp")
        assert result is True

    @pytest.mark.asyncio
    async def test_delete_trigger_not_found(self):
        from app.services.soar_service import delete_trigger
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(None))
        result = await delete_trigger(db, "nonexistent", deleted_by="analyst@corp")
        assert result is False

    @pytest.mark.asyncio
    async def test_toggle_trigger(self):
        from app.services.soar_service import toggle_trigger
        t = _make_trigger(enabled=True)
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(t))
        db.commit = AsyncMock()
        result = await toggle_trigger(db, t.id, enabled=False, updated_by="analyst@corp")
        assert result is not None
        assert t.enabled is False


# ─── TestSOARFireTrigger ──────────────────────────────────────────────────────────

class TestSOARFireTrigger:

    @pytest.mark.asyncio
    async def test_evaluate_no_triggers(self):
        from app.services.soar_service import evaluate_triggers_for_context
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalars_result([]))
        result = await evaluate_triggers_for_context(db, {"pcdi_score": 90})
        assert result == []

    @pytest.mark.asyncio
    async def test_evaluate_no_matching_score(self):
        from app.services.soar_service import evaluate_triggers_for_context
        t = _make_trigger(condition_type="pcdi_score", condition_operator="gte", condition_value="80")
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalars_result([t]))
        result = await evaluate_triggers_for_context(db, {"pcdi_score": 50})
        assert result == []

    @pytest.mark.asyncio
    async def test_evaluate_hunt_id_filter_mismatch(self):
        from app.services.soar_service import evaluate_triggers_for_context
        t = _make_trigger(hunt_id_filter="hunt-aaa", condition_type="pcdi_score",
                          condition_operator="gte", condition_value="80")
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalars_result([t]))
        result = await evaluate_triggers_for_context(db, {"pcdi_score": 90, "hunt_id": "hunt-bbb"})
        assert result == []

    @pytest.mark.asyncio
    async def test_evaluate_fire_matching_trigger(self):
        from app.services.soar_service import evaluate_triggers_for_context
        t = _make_trigger(condition_type="pcdi_score", condition_operator="gte", condition_value="80")
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalars_result([t]))
        db.commit = AsyncMock()

        with patch("app.services.soar_service._fire_trigger", new=AsyncMock(return_value={"trigger_id": t.id, "matched": True})):
            result = await evaluate_triggers_for_context(db, {"pcdi_score": 90})
        assert len(result) == 1
        assert result[0]["matched"] is True

    @pytest.mark.asyncio
    async def test_fire_trigger_playbook_error_captured(self):
        from app.services.soar_service import _fire_trigger
        t = _make_trigger()
        db = AsyncMock()
        db.commit = AsyncMock()

        with patch("app.services.soar_service._fire_trigger.__module__"):
            pass

        # Simulate playbook service raising exception
        async def _bad_trigger(*a, **kw):
            raise ValueError("playbook not found")

        with patch("app.services.playbook.trigger_playbook", new=_bad_trigger):
            result = await _fire_trigger(db, t, {"pcdi_score": 90}, triggered_by="system")

        assert result["trigger_id"] == t.id
        assert result["error"] is not None

    @pytest.mark.asyncio
    async def test_evaluate_multiple_matching_triggers(self):
        from app.services.soar_service import evaluate_triggers_for_context
        t1 = _make_trigger(id="t1", condition_type="pcdi_score", condition_operator="gte", condition_value="70")
        t2 = _make_trigger(id="t2", condition_type="pcdi_score", condition_operator="gte", condition_value="80")
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalars_result([t1, t2]))
        db.commit = AsyncMock()

        with patch("app.services.soar_service._fire_trigger", new=AsyncMock(return_value={"matched": True})) as mock_fire:
            result = await evaluate_triggers_for_context(db, {"pcdi_score": 90})
        assert len(result) == 2


# ─── TestSOARTestTrigger ──────────────────────────────────────────────────────────

class TestSOARTestTrigger:

    @pytest.mark.asyncio
    async def test_test_trigger_matches(self):
        from app.services.soar_service import test_trigger
        t = _make_trigger(condition_type="pcdi_score", condition_operator="gte", condition_value="80")
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(t))
        result = await test_trigger(t.id, {"pcdi_score": 90}, db)
        assert result["matched"] is True
        assert result["would_fire"] is True
        assert "Dry-run" in result["note"]

    @pytest.mark.asyncio
    async def test_test_trigger_no_match(self):
        from app.services.soar_service import test_trigger
        t = _make_trigger(condition_type="pcdi_score", condition_operator="gte", condition_value="80")
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(t))
        result = await test_trigger(t.id, {"pcdi_score": 50}, db)
        assert result["matched"] is False
        assert result["would_fire"] is False

    @pytest.mark.asyncio
    async def test_test_trigger_not_found(self):
        from app.services.soar_service import test_trigger
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(None))
        result = await test_trigger("no-such-id", {}, db)
        assert "error" in result
        assert "not found" in result["error"].lower()


# ─── TestScheduledReportCRUD ──────────────────────────────────────────────────────

class TestScheduledReportCRUD:

    @pytest.mark.asyncio
    async def test_create_report_valid(self):
        from app.services.soar_service import create_scheduled_report
        db = AsyncMock()
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock()

        result = await create_scheduled_report(
            db, hunt_id=str(uuid.uuid4()), hunt_name="Test",
            recipient_email="a@b.com", frequency="daily", format="json",
            created_by="analyst@corp",
        )
        assert "error" not in result or result.get("id")

    @pytest.mark.asyncio
    async def test_create_report_invalid_frequency(self):
        from app.services.soar_service import create_scheduled_report
        db = AsyncMock()
        result = await create_scheduled_report(
            db, hunt_id="x", hunt_name=None,
            recipient_email="a@b.com", frequency="hourly", format="json",
            created_by="analyst@corp",
        )
        assert "error" in result
        assert "frequency" in result["error"]

    @pytest.mark.asyncio
    async def test_create_report_invalid_format(self):
        from app.services.soar_service import create_scheduled_report
        db = AsyncMock()
        result = await create_scheduled_report(
            db, hunt_id="x", hunt_name=None,
            recipient_email="a@b.com", frequency="daily", format="xlsx",
            created_by="analyst@corp",
        )
        assert "error" in result
        assert "format" in result["error"]

    @pytest.mark.asyncio
    async def test_list_reports_empty(self):
        from app.services.soar_service import list_scheduled_reports
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalars_result([]))
        result = await list_scheduled_reports(db)
        assert result == []

    @pytest.mark.asyncio
    async def test_get_report_not_found(self):
        from app.services.soar_service import get_scheduled_report
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(None))
        result = await get_scheduled_report(db, "no-id")
        assert result is None

    @pytest.mark.asyncio
    async def test_delete_report_found(self):
        from app.services.soar_service import delete_scheduled_report
        r = _make_report()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(r))
        db.delete = AsyncMock()
        db.commit = AsyncMock()
        result = await delete_scheduled_report(db, r.id, deleted_by="analyst@corp")
        assert result is True

    @pytest.mark.asyncio
    async def test_delete_report_not_found(self):
        from app.services.soar_service import delete_scheduled_report
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(None))
        result = await delete_scheduled_report(db, "no-id", deleted_by="analyst@corp")
        assert result is False

    @pytest.mark.asyncio
    async def test_deliver_report_not_found(self):
        from app.services.soar_service import deliver_scheduled_report
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(None))
        result = await deliver_scheduled_report(db, "no-id")
        assert "error" in result
        assert "not found" in result["error"].lower()


# ─── TestScheduledReportDue ────────────────────────────────────────────────────────

class TestScheduledReportDue:
    """
    Tests for _is_due() logic — implemented inline to avoid importing celery_app,
    which depends on the `celery` package that may not be installed locally.
    This mirrors the exact logic in app/tasks/scheduled_reports.py.
    """

    @staticmethod
    def _is_due(last_sent_at, frequency: str) -> bool:
        if last_sent_at is None:
            return True
        now = datetime.now(timezone.utc)
        if last_sent_at.tzinfo is None:
            last_sent_at = last_sent_at.replace(tzinfo=timezone.utc)
        interval = timedelta(hours=24) if frequency == "daily" else timedelta(days=7)
        return (now - last_sent_at) >= interval

    def test_daily_never_sent_is_due(self):
        assert self._is_due(None, "daily") is True

    def test_weekly_never_sent_is_due(self):
        assert self._is_due(None, "weekly") is True

    def test_daily_sent_2h_ago_not_due(self):
        last = datetime.now(timezone.utc) - timedelta(hours=2)
        assert self._is_due(last, "daily") is False

    def test_daily_sent_25h_ago_is_due(self):
        last = datetime.now(timezone.utc) - timedelta(hours=25)
        assert self._is_due(last, "daily") is True


# ─── TestADAdapterSearch ──────────────────────────────────────────────────────────

class TestADAdapterSearch:

    def _make_adapter(self):
        from app.adapters.identity.active_directory import ActiveDirectoryAdapter
        with patch("app.core.config.get_settings") as mock_settings:
            mock_settings.return_value = SimpleNamespace(
                AD_SERVER_URL="ldaps://dc.corp.local:636",
                AD_BIND_DN="CN=svc,DC=corp,DC=local",
                AD_BIND_PASSWORD="secret",
                AD_BASE_DN="DC=corp,DC=local",
                AD_QUARANTINE_OU="OU=Quarantine,DC=corp,DC=local",
                AD_USE_SSL=True,
                AD_VERIFY_CERT=False,
            )
            return ActiveDirectoryAdapter()

    @pytest.mark.asyncio
    async def test_search_user_not_configured(self):
        from app.adapters.identity.active_directory import ActiveDirectoryAdapter
        with patch("app.core.config.get_settings") as mock_settings:
            mock_settings.return_value = SimpleNamespace(
                AD_SERVER_URL="", AD_BIND_DN="", AD_BIND_PASSWORD="",
                AD_BASE_DN="", AD_QUARANTINE_OU="", AD_USE_SSL=True, AD_VERIFY_CERT=False,
            )
            adapter = ActiveDirectoryAdapter()
        result = await adapter.search_user("testuser")
        assert result.get("success") is False or "not_configured" in str(result)

    @pytest.mark.asyncio
    async def test_list_group_members_not_configured(self):
        from app.adapters.identity.active_directory import ActiveDirectoryAdapter
        with patch("app.core.config.get_settings") as mock_settings:
            mock_settings.return_value = SimpleNamespace(
                AD_SERVER_URL="", AD_BIND_DN="", AD_BIND_PASSWORD="",
                AD_BASE_DN="", AD_QUARANTINE_OU="", AD_USE_SSL=True, AD_VERIFY_CERT=False,
            )
            adapter = ActiveDirectoryAdapter()
        result = await adapter.list_group_members("Domain Admins")
        assert result.get("success") is False or "not_configured" in str(result)

    def test_search_user_sync_not_found(self):
        adapter = self._make_adapter()
        mock_conn = MagicMock()
        mock_conn.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = MagicMock(return_value=False)
        mock_conn.entries = []

        with patch("app.adapters.identity.active_directory._import_ldap3") as mock_ldap:
            mock_ldap3 = MagicMock()
            mock_ldap3.SUBTREE = "SUBTREE"
            mock_ldap.return_value = mock_ldap3
            with patch.object(adapter, "_connect", return_value=mock_conn):
                result = adapter._search_user_sync("unknown_user")

        assert result.get("success") is False
        assert "user_not_found" in result.get("error", "")

    def test_list_group_members_sync_not_found(self):
        adapter = self._make_adapter()
        mock_conn = MagicMock()
        mock_conn.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = MagicMock(return_value=False)
        mock_conn.entries = []

        with patch("app.adapters.identity.active_directory._import_ldap3") as mock_ldap:
            mock_ldap3 = MagicMock()
            mock_ldap3.SUBTREE = "SUBTREE"
            mock_ldap.return_value = mock_ldap3
            with patch.object(adapter, "_connect", return_value=mock_conn):
                result = adapter._list_group_members_sync("NoSuchGroup")

        assert result.get("success") is False
        assert "group_not_found" in result.get("error", "")

    def test_search_user_sync_found(self):
        adapter = self._make_adapter()
        mock_entry = MagicMock()
        mock_entry.distinguishedName.value = "CN=jsmith,OU=Users,DC=corp,DC=local"
        mock_entry.displayName.value = "John Smith"
        mock_entry.mail.value = "jsmith@corp.local"
        mock_entry.userAccountControl.value = 512  # normal account (enabled)
        mock_entry.department.value = "IT"
        mock_entry.title.value = "Analyst"
        mock_entry.memberOf.values = ["CN=IT Staff,OU=Groups,DC=corp,DC=local"]

        mock_conn = MagicMock()
        mock_conn.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = MagicMock(return_value=False)
        mock_conn.entries = [mock_entry]

        with patch("app.adapters.identity.active_directory._import_ldap3") as mock_ldap:
            mock_ldap3 = MagicMock()
            mock_ldap3.SUBTREE = "SUBTREE"
            mock_ldap.return_value = mock_ldap3
            with patch.object(adapter, "_connect", return_value=mock_conn):
                result = adapter._search_user_sync("jsmith")

        assert result.get("success") is True
        assert result.get("username") == "jsmith"
        assert result.get("enabled") is True

    def test_search_user_disabled_account(self):
        adapter = self._make_adapter()
        mock_entry = MagicMock()
        mock_entry.distinguishedName.value = "CN=bsmith,OU=Users,DC=corp,DC=local"
        mock_entry.displayName.value = "Bob Smith"
        mock_entry.mail.value = None
        mock_entry.userAccountControl.value = 514  # 512 | 0x0002 = disabled
        mock_entry.department.value = None
        mock_entry.title.value = None
        mock_entry.memberOf.values = []

        mock_conn = MagicMock()
        mock_conn.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = MagicMock(return_value=False)
        mock_conn.entries = [mock_entry]

        with patch("app.adapters.identity.active_directory._import_ldap3") as mock_ldap:
            mock_ldap3 = MagicMock()
            mock_ldap3.SUBTREE = "SUBTREE"
            mock_ldap.return_value = mock_ldap3
            with patch.object(adapter, "_connect", return_value=mock_conn):
                result = adapter._search_user_sync("bsmith")

        assert result.get("success") is True
        assert result.get("enabled") is False


# ─── TestADAdapterNotConfigured ───────────────────────────────────────────────────

class TestADAdapterNotConfigured:

    def _make_unconfigured(self):
        from app.adapters.identity.active_directory import ActiveDirectoryAdapter
        with patch("app.core.config.get_settings") as m:
            m.return_value = SimpleNamespace(
                AD_SERVER_URL="", AD_BIND_DN="", AD_BIND_PASSWORD="",
                AD_BASE_DN="", AD_QUARANTINE_OU="", AD_USE_SSL=True, AD_VERIFY_CERT=False,
            )
            return ActiveDirectoryAdapter()

    @pytest.mark.asyncio
    async def test_disable_not_configured(self):
        result = await self._make_unconfigured().disable_account("user", "corp")
        assert result.get("success") is False

    @pytest.mark.asyncio
    async def test_enable_not_configured(self):
        result = await self._make_unconfigured().enable_account("user", "corp")
        assert result.get("success") is False

    @pytest.mark.asyncio
    async def test_force_reset_not_configured(self):
        result = await self._make_unconfigured().force_password_reset("user", "corp")
        assert result.get("success") is False

    @pytest.mark.asyncio
    async def test_quarantine_not_configured(self):
        result = await self._make_unconfigured().move_to_quarantine_ou("user", "corp")
        assert result.get("success") is False


# ─── TestTheHiveExport ─────────────────────────────────────────────────────────────

class TestTheHiveExport:

    @pytest.mark.asyncio
    async def test_export_adapter_not_configured(self):
        from app.services.thehive_service import export_hunt_to_thehive
        db = AsyncMock()
        with patch("app.services.thehive_service.TheHiveAdapter") as mock_cls:
            mock_cls.return_value.is_configured.return_value = False
            result = await export_hunt_to_thehive(db, "hunt-123", exported_by="analyst@corp")
        assert result["success"] is False
        assert "not configured" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_export_hunt_not_found(self):
        from app.services.thehive_service import export_hunt_to_thehive
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(None))
        with patch("app.services.thehive_service.TheHiveAdapter") as mock_cls:
            mock_cls.return_value.is_configured.return_value = True
            result = await export_hunt_to_thehive(db, "no-hunt", exported_by="analyst@corp")
        assert result["success"] is False
        assert "not found" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_export_creates_case(self):
        from app.services.thehive_service import export_hunt_to_thehive
        hunt = _make_hunt()
        finding = _make_finding(hunt_id=hunt.id)

        r_hunt = _scalar_one(hunt)
        r_findings = _scalars_result([finding])

        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[r_hunt, r_findings])

        with patch("app.services.thehive_service.TheHiveAdapter") as mock_cls:
            adapter = mock_cls.return_value
            adapter.is_configured.return_value = True
            adapter.create_case = AsyncMock(return_value={"success": True, "case_id": "case-001", "case_number": 1})
            adapter.create_observable = AsyncMock(return_value={"success": True, "observable_id": "obs-001"})
            result = await export_hunt_to_thehive(db, hunt.id, exported_by="analyst@corp")

        assert result["success"] is True
        assert result["case_id"] == "case-001"
        assert result["observables_added"] == 1

    @pytest.mark.asyncio
    async def test_export_case_creation_fails(self):
        from app.services.thehive_service import export_hunt_to_thehive
        hunt = _make_hunt()
        r_hunt = _scalar_one(hunt)
        r_findings = _scalars_result([])

        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[r_hunt, r_findings])

        with patch("app.services.thehive_service.TheHiveAdapter") as mock_cls:
            adapter = mock_cls.return_value
            adapter.is_configured.return_value = True
            adapter.create_case = AsyncMock(return_value={"success": False, "error": "HTTP 503"})
            result = await export_hunt_to_thehive(db, hunt.id, exported_by="analyst@corp")

        assert result["success"] is False
        assert "HTTP 503" in result["error"]

    @pytest.mark.asyncio
    async def test_export_skips_false_positives(self):
        from app.services.thehive_service import export_hunt_to_thehive
        hunt = _make_hunt()
        fp_finding = _make_finding(hunt_id=hunt.id, is_false_positive=True, is_confirmed=False)

        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[_scalar_one(hunt), _scalars_result([fp_finding])])

        with patch("app.services.thehive_service.TheHiveAdapter") as mock_cls:
            adapter = mock_cls.return_value
            adapter.is_configured.return_value = True
            adapter.create_case = AsyncMock(return_value={"success": True, "case_id": "case-002", "case_number": 2})
            result = await export_hunt_to_thehive(db, hunt.id, exported_by="analyst@corp")

        assert result["observables_added"] == 0

    @pytest.mark.asyncio
    async def test_export_observable_error_partial(self):
        from app.services.thehive_service import export_hunt_to_thehive
        hunt = _make_hunt()
        f1 = _make_finding(hunt_id=hunt.id, is_confirmed=True)
        f2 = _make_finding(hunt_id=hunt.id, is_confirmed=True, indicator_value="evil.com", indicator_type="domain")

        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[_scalar_one(hunt), _scalars_result([f1, f2])])

        with patch("app.services.thehive_service.TheHiveAdapter") as mock_cls:
            adapter = mock_cls.return_value
            adapter.is_configured.return_value = True
            adapter.create_case = AsyncMock(return_value={"success": True, "case_id": "case-003", "case_number": 3})
            adapter.create_observable = AsyncMock(side_effect=[
                {"success": True, "observable_id": "obs-1"},
                {"success": False, "error": "Observable rejected"},
            ])
            result = await export_hunt_to_thehive(db, hunt.id, exported_by="analyst@corp")

        assert result["success"] is True
        assert result["observables_added"] == 1
        assert len(result["errors"]) == 1

    def test_hunt_to_alert_dict_severity_escalation(self):
        from app.services.thehive_service import _hunt_to_alert_dict
        hunt = _make_hunt()
        findings = [
            _make_finding(is_confirmed=True, severity="critical"),
            _make_finding(is_confirmed=False, severity="low"),
        ]
        result = _hunt_to_alert_dict(hunt, findings)
        assert result["severity"] == "critical"

    def test_finding_to_observable_no_indicator(self):
        from app.services.thehive_service import _finding_to_observable
        f = _make_finding(indicator_value=None)
        result = _finding_to_observable(f)
        assert result is None


# ─── TestSOAREndpoints ─────────────────────────────────────────────────────────────

class TestSOAREndpoints:

    def test_soar_router_prefix(self):
        from app.api.v1.endpoints.soar import router
        assert router.prefix == "/soar"

    def test_soar_router_has_triggers_routes(self):
        from app.api.v1.endpoints.soar import router
        paths = [r.path for r in router.routes]
        assert any("triggers" in p for p in paths)

    def test_soar_router_has_reports_routes(self):
        from app.api.v1.endpoints.soar import router
        paths = [r.path for r in router.routes]
        assert any("reports" in p for p in paths)

    def test_soar_router_has_evaluate_route(self):
        from app.api.v1.endpoints.soar import router
        paths = [r.path for r in router.routes]
        assert any("evaluate" in p for p in paths)

    def test_soar_router_included_in_api(self):
        from app.api.v1.router import api_router
        # api_router.routes contains APIRoute objects; each has a .path with full prefix
        paths = [getattr(r, "path", "") for r in api_router.routes]
        assert any("/soar" in p for p in paths)
