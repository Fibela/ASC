"""
SOAR Service — unit + integration tests (Session 84).

Coverage targets:
  _evaluate_condition       — all 9 condition types × operators
  _trigger_to_dict          — serialization
  create_trigger            — validation + happy path
  list_triggers             — filters (playbook_id, condition_type, enabled_only)
  get_trigger               — found / not-found
  delete_trigger            — found / not-found
  toggle_trigger            — enable / disable
  test_trigger              — dry-run evaluation

All DB tests use the in-memory SQLite fixture from conftest.py.
"""

import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.soar import PlaybookTrigger
from app.services.soar_service import (
    _evaluate_condition,
    create_trigger,
    delete_trigger,
    get_trigger,
    list_triggers,
    test_trigger as soar_test_trigger,
    toggle_trigger,
)


# ── Helpers ─────────────────────────────────────────────────────────────────────

def _make_trigger(**overrides) -> PlaybookTrigger:
    """Build a PlaybookTrigger instance (no DB) for pure-unit tests."""
    defaults = dict(
        id=str(uuid.uuid4()),
        playbook_id="pb001",
        playbook_name="Test Playbook",
        condition_type="pcdi_score",
        condition_operator="gte",
        condition_value="80",
        hunt_id_filter=None,
        priority=5,
        rate_limit_per_hour=10,
        dedup_window_minutes=0,
        enabled=True,
        trigger_count=0,
        last_triggered_at=None,
        last_triggered_context=None,
        created_by="analyst@premoscorp.com",
        created_at=datetime.now(timezone.utc),
    )
    defaults.update(overrides)
    return PlaybookTrigger(**defaults)


def _make_trigger_kwargs(**overrides) -> dict:
    base = dict(
        playbook_id="pb001",
        playbook_name="SOAR Test",
        condition_type="pcdi_score",
        condition_operator="gte",
        condition_value="80",
        created_by="analyst@premoscorp.com",
    )
    base.update(overrides)
    return base


# ══════════════════════════════════════════════════════════════════════════════
#  Pure unit tests — _evaluate_condition
# ══════════════════════════════════════════════════════════════════════════════

class TestEvaluateConditionPcdiScore:
    def test_gte_above_threshold(self):
        t = _make_trigger(condition_type="pcdi_score", condition_operator="gte", condition_value="80")
        assert _evaluate_condition(t, {"pcdi_score": 85}) is True

    def test_gte_at_threshold(self):
        t = _make_trigger(condition_type="pcdi_score", condition_operator="gte", condition_value="80")
        assert _evaluate_condition(t, {"pcdi_score": 80}) is True

    def test_gte_below_threshold(self):
        t = _make_trigger(condition_type="pcdi_score", condition_operator="gte", condition_value="80")
        assert _evaluate_condition(t, {"pcdi_score": 75}) is False

    def test_lte_below_threshold(self):
        t = _make_trigger(condition_type="pcdi_score", condition_operator="lte", condition_value="20")
        assert _evaluate_condition(t, {"pcdi_score": 15}) is True

    def test_lte_above_threshold(self):
        t = _make_trigger(condition_type="pcdi_score", condition_operator="lte", condition_value="20")
        assert _evaluate_condition(t, {"pcdi_score": 25}) is False

    def test_eq_exact_match(self):
        t = _make_trigger(condition_type="pcdi_score", condition_operator="eq", condition_value="50")
        assert _evaluate_condition(t, {"pcdi_score": 50}) is True

    def test_eq_no_match(self):
        t = _make_trigger(condition_type="pcdi_score", condition_operator="eq", condition_value="50")
        assert _evaluate_condition(t, {"pcdi_score": 51}) is False

    def test_missing_score_returns_false(self):
        t = _make_trigger(condition_type="pcdi_score", condition_operator="gte", condition_value="80")
        assert _evaluate_condition(t, {}) is False

    def test_unknown_operator_returns_false(self):
        t = _make_trigger(condition_type="pcdi_score", condition_operator="contains", condition_value="80")
        assert _evaluate_condition(t, {"pcdi_score": 80}) is False


class TestEvaluateConditionFindingSeverity:
    def test_eq_exact_match(self):
        t = _make_trigger(condition_type="finding_severity", condition_operator="eq", condition_value="critical")
        assert _evaluate_condition(t, {"severity": "critical"}) is True

    def test_eq_no_match(self):
        t = _make_trigger(condition_type="finding_severity", condition_operator="eq", condition_value="critical")
        assert _evaluate_condition(t, {"severity": "high"}) is False

    def test_gte_critical_vs_high(self):
        t = _make_trigger(condition_type="finding_severity", condition_operator="gte", condition_value="high")
        assert _evaluate_condition(t, {"severity": "critical"}) is True

    def test_gte_low_vs_high(self):
        t = _make_trigger(condition_type="finding_severity", condition_operator="gte", condition_value="high")
        assert _evaluate_condition(t, {"severity": "low"}) is False

    def test_contains_multi_value(self):
        t = _make_trigger(condition_type="finding_severity", condition_operator="contains", condition_value="critical,high")
        assert _evaluate_condition(t, {"severity": "high"}) is True

    def test_contains_no_match(self):
        t = _make_trigger(condition_type="finding_severity", condition_operator="contains", condition_value="critical,high")
        assert _evaluate_condition(t, {"severity": "low"}) is False

    def test_missing_severity_key(self):
        t = _make_trigger(condition_type="finding_severity", condition_operator="eq", condition_value="critical")
        assert _evaluate_condition(t, {}) is False


class TestEvaluateConditionHuntPriority:
    def test_eq_match(self):
        t = _make_trigger(condition_type="hunt_priority", condition_operator="eq", condition_value="critical")
        assert _evaluate_condition(t, {"hunt_priority": "critical"}) is True

    def test_eq_no_match(self):
        t = _make_trigger(condition_type="hunt_priority", condition_operator="eq", condition_value="critical")
        assert _evaluate_condition(t, {"hunt_priority": "high"}) is False

    def test_contains_multi_value(self):
        t = _make_trigger(condition_type="hunt_priority", condition_operator="contains", condition_value="critical,high")
        assert _evaluate_condition(t, {"hunt_priority": "high"}) is True

    def test_missing_context_key(self):
        t = _make_trigger(condition_type="hunt_priority", condition_operator="eq", condition_value="critical")
        assert _evaluate_condition(t, {}) is False


class TestEvaluateConditionPanlStatus:
    def test_eq_match(self):
        t = _make_trigger(condition_type="panl_status", condition_operator="eq", condition_value="approved")
        assert _evaluate_condition(t, {"panl_status": "approved"}) is True

    def test_eq_no_match(self):
        t = _make_trigger(condition_type="panl_status", condition_operator="eq", condition_value="approved")
        assert _evaluate_condition(t, {"panl_status": "pending"}) is False

    def test_contains_multi_value(self):
        t = _make_trigger(condition_type="panl_status", condition_operator="contains", condition_value="approved,completed")
        assert _evaluate_condition(t, {"panl_status": "completed"}) is True


class TestEvaluateConditionIdentityGroup:
    def test_eq_group_in_list(self):
        t = _make_trigger(condition_type="identity_group", condition_operator="eq", condition_value="Domain Admins")
        assert _evaluate_condition(t, {"groups": ["Domain Admins", "Users"]}) is True

    def test_eq_group_not_in_list(self):
        t = _make_trigger(condition_type="identity_group", condition_operator="eq", condition_value="Domain Admins")
        assert _evaluate_condition(t, {"groups": ["Users"]}) is False

    def test_eq_empty_groups_list(self):
        t = _make_trigger(condition_type="identity_group", condition_operator="eq", condition_value="Domain Admins")
        assert _evaluate_condition(t, {"groups": []}) is False

    def test_eq_groups_not_a_list(self):
        t = _make_trigger(condition_type="identity_group", condition_operator="eq", condition_value="Domain Admins")
        assert _evaluate_condition(t, {"groups": "Domain Admins"}) is False

    def test_contains_any_match(self):
        t = _make_trigger(condition_type="identity_group", condition_operator="contains", condition_value="Domain Admins,Schema Admins")
        assert _evaluate_condition(t, {"groups": ["Schema Admins", "Users"]}) is True

    def test_contains_no_match(self):
        t = _make_trigger(condition_type="identity_group", condition_operator="contains", condition_value="Domain Admins,Schema Admins")
        assert _evaluate_condition(t, {"groups": ["Users", "Guests"]}) is False


class TestEvaluateConditionIamEvent:
    def test_eq_match(self):
        t = _make_trigger(condition_type="iam_event", condition_operator="eq", condition_value="disable_account")
        assert _evaluate_condition(t, {"iam_action": "disable_account"}) is True

    def test_eq_no_match(self):
        t = _make_trigger(condition_type="iam_event", condition_operator="eq", condition_value="disable_account")
        assert _evaluate_condition(t, {"iam_action": "enable_account"}) is False

    def test_contains_multi(self):
        t = _make_trigger(condition_type="iam_event", condition_operator="contains", condition_value="disable_account,quarantine_account")
        assert _evaluate_condition(t, {"iam_action": "quarantine_account"}) is True


class TestEvaluateConditionIncidentStatus:
    def test_eq_closed(self):
        t = _make_trigger(condition_type="incident_status_change", condition_operator="eq", condition_value="closed")
        assert _evaluate_condition(t, {"new_status": "closed"}) is True

    def test_contains_closed_or_resolved(self):
        t = _make_trigger(condition_type="incident_status_change", condition_operator="contains", condition_value="closed,resolved")
        assert _evaluate_condition(t, {"new_status": "resolved"}) is True

    def test_eq_no_match(self):
        t = _make_trigger(condition_type="incident_status_change", condition_operator="eq", condition_value="closed")
        assert _evaluate_condition(t, {"new_status": "open"}) is False


class TestEvaluateConditionIncidentSlaBreach:
    def test_breach_true(self):
        t = _make_trigger(condition_type="incident_sla_breach", condition_operator="eq", condition_value="true")
        assert _evaluate_condition(t, {"sla_breach": True}) is True

    def test_breach_false(self):
        t = _make_trigger(condition_type="incident_sla_breach", condition_operator="eq", condition_value="true")
        assert _evaluate_condition(t, {"sla_breach": False}) is False

    def test_missing_sla_breach_key(self):
        t = _make_trigger(condition_type="incident_sla_breach", condition_operator="eq", condition_value="true")
        assert _evaluate_condition(t, {}) is False


class TestEvaluateConditionIncidentSeverity:
    def test_eq_high(self):
        t = _make_trigger(condition_type="incident_severity", condition_operator="eq", condition_value="high")
        assert _evaluate_condition(t, {"severity": "high"}) is True

    def test_gte_high_vs_critical(self):
        t = _make_trigger(condition_type="incident_severity", condition_operator="gte", condition_value="high")
        assert _evaluate_condition(t, {"severity": "critical"}) is True

    def test_gte_high_vs_medium(self):
        t = _make_trigger(condition_type="incident_severity", condition_operator="gte", condition_value="high")
        assert _evaluate_condition(t, {"severity": "medium"}) is False

    def test_lte_low_vs_medium(self):
        t = _make_trigger(condition_type="incident_severity", condition_operator="lte", condition_value="medium")
        assert _evaluate_condition(t, {"severity": "low"}) is True

    def test_lte_critical_vs_medium(self):
        t = _make_trigger(condition_type="incident_severity", condition_operator="lte", condition_value="medium")
        assert _evaluate_condition(t, {"severity": "critical"}) is False

    def test_contains_multi_severity(self):
        t = _make_trigger(condition_type="incident_severity", condition_operator="contains", condition_value="critical,high")
        assert _evaluate_condition(t, {"severity": "high"}) is True


class TestEvaluateConditionUnknownType:
    def test_unknown_condition_type_returns_false(self):
        t = _make_trigger(condition_type="nonexistent_type", condition_operator="eq", condition_value="x")
        assert _evaluate_condition(t, {"nonexistent_type": "x"}) is False


# ══════════════════════════════════════════════════════════════════════════════
#  Integration tests — DB-backed service functions
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
class TestCreateTrigger:
    async def test_happy_path_returns_dict(self, db: AsyncSession):
        result = await create_trigger(db, **_make_trigger_kwargs())
        assert "id" in result
        assert result["playbook_id"] == "pb001"
        assert result["condition_type"] == "pcdi_score"
        assert result["enabled"] is True

    async def test_invalid_condition_type_returns_error(self, db: AsyncSession):
        result = await create_trigger(db, **_make_trigger_kwargs(condition_type="bad_type"))
        assert "error" in result
        assert "bad_type" in result["error"]

    async def test_invalid_operator_returns_error(self, db: AsyncSession):
        result = await create_trigger(db, **_make_trigger_kwargs(condition_operator="neq"))
        assert "error" in result

    async def test_invalid_priority_returns_error(self, db: AsyncSession):
        result = await create_trigger(db, **_make_trigger_kwargs(priority=11))
        assert "error" in result
        assert "priority" in result["error"]

    async def test_priority_zero_returns_error(self, db: AsyncSession):
        result = await create_trigger(db, **_make_trigger_kwargs(priority=0))
        assert "error" in result

    async def test_trigger_count_starts_at_zero(self, db: AsyncSession):
        result = await create_trigger(db, **_make_trigger_kwargs())
        assert result["trigger_count"] == 0

    async def test_hunt_id_filter_stored(self, db: AsyncSession):
        hid = str(uuid.uuid4())
        result = await create_trigger(db, **_make_trigger_kwargs(hunt_id_filter=hid))
        assert result["hunt_id_filter"] == hid

    async def test_dedup_window_stored(self, db: AsyncSession):
        result = await create_trigger(db, **_make_trigger_kwargs(dedup_window_minutes=15))
        assert result["dedup_window_minutes"] == 15


@pytest.mark.asyncio
class TestListTriggers:
    async def test_empty_db_returns_empty_list(self, db: AsyncSession):
        result = await list_triggers(db)
        assert result == []

    async def test_returns_created_trigger(self, db: AsyncSession):
        await create_trigger(db, **_make_trigger_kwargs())
        result = await list_triggers(db)
        assert len(result) == 1

    async def test_filter_by_playbook_id(self, db: AsyncSession):
        await create_trigger(db, **_make_trigger_kwargs(playbook_id="pb001"))
        await create_trigger(db, **_make_trigger_kwargs(playbook_id="pb002", condition_type="finding_severity", condition_operator="eq", condition_value="critical"))
        result = await list_triggers(db, playbook_id="pb001")
        assert len(result) == 1
        assert result[0]["playbook_id"] == "pb001"

    async def test_filter_by_condition_type(self, db: AsyncSession):
        await create_trigger(db, **_make_trigger_kwargs(condition_type="pcdi_score"))
        await create_trigger(db, **_make_trigger_kwargs(condition_type="finding_severity", condition_operator="eq", condition_value="critical"))
        result = await list_triggers(db, condition_type="finding_severity")
        assert len(result) == 1
        assert result[0]["condition_type"] == "finding_severity"

    async def test_enabled_only_filter(self, db: AsyncSession):
        r1 = await create_trigger(db, **_make_trigger_kwargs())
        await toggle_trigger(db, r1["id"], enabled=False, updated_by="admin")
        await create_trigger(db, **_make_trigger_kwargs(condition_type="hunt_priority", condition_operator="eq", condition_value="critical"))
        enabled = await list_triggers(db, enabled_only=True)
        assert len(enabled) == 1
        assert enabled[0]["enabled"] is True


@pytest.mark.asyncio
class TestGetTrigger:
    async def test_returns_none_for_unknown_id(self, db: AsyncSession):
        result = await get_trigger(db, str(uuid.uuid4()))
        assert result is None

    async def test_returns_dict_for_known_id(self, db: AsyncSession):
        created = await create_trigger(db, **_make_trigger_kwargs())
        found = await get_trigger(db, created["id"])
        assert found is not None
        assert found["id"] == created["id"]
        assert found["playbook_id"] == "pb001"


@pytest.mark.asyncio
class TestDeleteTrigger:
    async def test_delete_returns_true_for_existing(self, db: AsyncSession):
        created = await create_trigger(db, **_make_trigger_kwargs())
        result = await delete_trigger(db, created["id"], deleted_by="admin")
        assert result is True

    async def test_delete_returns_false_for_missing(self, db: AsyncSession):
        result = await delete_trigger(db, str(uuid.uuid4()), deleted_by="admin")
        assert result is False

    async def test_deleted_trigger_not_found_after(self, db: AsyncSession):
        created = await create_trigger(db, **_make_trigger_kwargs())
        await delete_trigger(db, created["id"], deleted_by="admin")
        found = await get_trigger(db, created["id"])
        assert found is None


@pytest.mark.asyncio
class TestToggleTrigger:
    async def test_disable_trigger(self, db: AsyncSession):
        created = await create_trigger(db, **_make_trigger_kwargs())
        result = await toggle_trigger(db, created["id"], enabled=False, updated_by="admin")
        assert result is not None
        assert result["enabled"] is False

    async def test_re_enable_trigger(self, db: AsyncSession):
        created = await create_trigger(db, **_make_trigger_kwargs())
        await toggle_trigger(db, created["id"], enabled=False, updated_by="admin")
        result = await toggle_trigger(db, created["id"], enabled=True, updated_by="admin")
        assert result["enabled"] is True

    async def test_toggle_unknown_id_returns_none(self, db: AsyncSession):
        result = await toggle_trigger(db, str(uuid.uuid4()), enabled=False, updated_by="admin")
        assert result is None


@pytest.mark.asyncio
class TestTestTrigger:
    async def test_dry_run_match(self, db: AsyncSession):
        created = await create_trigger(db, **_make_trigger_kwargs(
            condition_type="pcdi_score", condition_operator="gte", condition_value="80"
        ))
        result = await soar_test_trigger(created["id"], {"pcdi_score": 90}, db)
        assert result["matched"] is True
        assert result["would_fire"] is True
        assert "Dry-run" in result["note"]

    async def test_dry_run_no_match(self, db: AsyncSession):
        created = await create_trigger(db, **_make_trigger_kwargs(
            condition_type="pcdi_score", condition_operator="gte", condition_value="80"
        ))
        result = await soar_test_trigger(created["id"], {"pcdi_score": 70}, db)
        assert result["matched"] is False
        assert result["would_fire"] is False

    async def test_dry_run_unknown_trigger_id(self, db: AsyncSession):
        result = await soar_test_trigger(str(uuid.uuid4()), {}, db)
        assert "error" in result
        assert "not found" in result["error"].lower()

    async def test_dry_run_disabled_trigger_would_not_fire(self, db: AsyncSession):
        created = await create_trigger(db, **_make_trigger_kwargs(
            condition_type="pcdi_score", condition_operator="gte", condition_value="80"
        ))
        await toggle_trigger(db, created["id"], enabled=False, updated_by="admin")
        result = await soar_test_trigger(created["id"], {"pcdi_score": 90}, db)
        assert result["matched"] is True
        assert result["would_fire"] is False
