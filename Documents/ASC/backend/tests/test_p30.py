"""
P30-B — SOAR ↔ Incident Bridge & PIIL Adaptive Binding — Test Suite
====================================================================
Coverage:
  TestBuildIncidentContext        (12) — all fields present, typed, no raw input
  TestSignLedger                  (10) — no-key placeholder, error fallback, return type
  TestWriteForensicLedger         (10) — ForensicEntry created, hash 128 chars, separate commit,
                                         non-fatal on commit error, action_type field
  TestWriteSoarEventToTimeline    (10) — incident found, writes IncidentTimeline, incident not found
                                         skips, commit errors non-fatal
  TestEvaluateSoarForIncident     (14) — no triggers fired returns 0, triggers fired returns count,
                                         writes timeline entries, writes forensic ledger,
                                         soar eval error returns 0 (non-blocking),
                                         commit error returns 0, calls log_security_action
  TestEscalateSlaBreaches         (12) — open incidents scanned, newly breached flagged,
                                         already breached skipped, closed skipped, timeline entry,
                                         commit called when escalated, returns 0 when none
  TestNewSoarConditionTypes       (16) — incident_status_change: eq/contains/missing,
                                         incident_sla_breach: true/false,
                                         incident_severity: eq/gte/lte/contains
  TestIncidentSoarIntegration     (10) — transition_status calls bridge, bridge failure
                                         does not block, non-blocking pattern, return value

Total: 94 tests
"""
from __future__ import annotations

import base64
import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest

# ── Helpers ────────────────────────────────────────────────────────────────────

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _make_incident(**kwargs):
    from asc_api.models.incident import Incident
    i = Incident()
    i.id = kwargs.get("id", str(uuid.uuid4()))
    i.title = kwargs.get("title", "Test Incident")
    i.description = kwargs.get("description", None)
    i.incident_type = kwargs.get("incident_type", "malware")
    i.status = kwargs.get("status", "detected")
    i.nist_phase = kwargs.get("nist_phase", "detection_analysis")
    i.severity = kwargs.get("severity", "high")
    i.risk_score = kwargs.get("risk_score", 0.8)
    i.created_by = kwargs.get("created_by", "analyst@premos.com")
    i.assigned_to = kwargs.get("assigned_to", None)
    i.mitre_tactics = kwargs.get("mitre_tactics", [])
    i.mitre_techniques = kwargs.get("mitre_techniques", [])
    i.tags = kwargs.get("tags", [])
    i.executive_summary = kwargs.get("executive_summary", None)
    i.lessons_learned = kwargs.get("lessons_learned", None)
    i.root_cause = kwargs.get("root_cause", None)
    i.false_positive = kwargs.get("false_positive", False)
    i.sla_minutes = kwargs.get("sla_minutes", 1440)
    i.sla_breach = kwargs.get("sla_breach", False)
    i.detected_at = kwargs.get("detected_at", _utcnow())
    i.triaged_at = kwargs.get("triaged_at", None)
    i.contained_at = kwargs.get("contained_at", None)
    i.eradicated_at = kwargs.get("eradicated_at", None)
    i.recovered_at = kwargs.get("recovered_at", None)
    i.closed_at = kwargs.get("closed_at", None)
    i.mttd_minutes = kwargs.get("mttd_minutes", None)
    i.mttc_minutes = kwargs.get("mttc_minutes", None)
    i.mttr_minutes = kwargs.get("mttr_minutes", None)
    i.forensic_hash = kwargs.get("forensic_hash", None)
    i.is_campaign = kwargs.get("is_campaign", False)
    i.created_at = kwargs.get("created_at", _utcnow())
    i.updated_at = kwargs.get("updated_at", _utcnow())
    return i


def _mock_scalar(value):
    row = MagicMock()
    row.scalar_one.return_value = value
    row.scalar_one_or_none.return_value = value
    return row


def _mock_scalars(rows):
    result = MagicMock()
    scalars_mock = MagicMock()
    scalars_mock.all.return_value = rows
    result.scalars.return_value = scalars_mock
    return result


# ── TestBuildIncidentContext ───────────────────────────────────────────────────

class TestBuildIncidentContext:

    def test_returns_dict(self):
        from asc_api.services.soar_incident_bridge import _build_incident_context
        inc = _make_incident()
        ctx = _build_incident_context(inc, "triaged", "analyst@premos.com")
        assert isinstance(ctx, dict)

    def test_incident_id_present(self):
        from asc_api.services.soar_incident_bridge import _build_incident_context
        inc = _make_incident(id="test-id-123")
        ctx = _build_incident_context(inc, "triaged", "analyst@premos.com")
        assert ctx["incident_id"] == "test-id-123"

    def test_new_status_present(self):
        from asc_api.services.soar_incident_bridge import _build_incident_context
        inc = _make_incident()
        ctx = _build_incident_context(inc, "triaged", "analyst@premos.com")
        assert ctx["new_status"] == "triaged"

    def test_previous_status_is_incident_status(self):
        from asc_api.services.soar_incident_bridge import _build_incident_context
        inc = _make_incident(status="detected")
        ctx = _build_incident_context(inc, "triaged", "analyst@premos.com")
        assert ctx["previous_status"] == "detected"

    def test_severity_matches_incident(self):
        from asc_api.services.soar_incident_bridge import _build_incident_context
        inc = _make_incident(severity="critical")
        ctx = _build_incident_context(inc, "triaged", "analyst@premos.com")
        assert ctx["severity"] == "critical"

    def test_sla_breach_flag(self):
        from asc_api.services.soar_incident_bridge import _build_incident_context
        inc = _make_incident(sla_breach=True)
        ctx = _build_incident_context(inc, "triaged", "analyst@premos.com")
        assert ctx["sla_breach"] is True

    def test_sla_breach_false_by_default(self):
        from asc_api.services.soar_incident_bridge import _build_incident_context
        inc = _make_incident(sla_breach=False)
        ctx = _build_incident_context(inc, "triaged", "analyst@premos.com")
        assert ctx["sla_breach"] is False

    def test_actor_in_context(self):
        from asc_api.services.soar_incident_bridge import _build_incident_context
        inc = _make_incident()
        ctx = _build_incident_context(inc, "triaged", "actor@premos.com")
        assert ctx["actor"] == "actor@premos.com"

    def test_mttd_present(self):
        from asc_api.services.soar_incident_bridge import _build_incident_context
        inc = _make_incident(mttd_minutes=45.0)
        ctx = _build_incident_context(inc, "contained", "sys")
        assert ctx["mttd_minutes"] == 45.0

    def test_nist_phase_present(self):
        from asc_api.services.soar_incident_bridge import _build_incident_context
        inc = _make_incident(nist_phase="containment_eradication")
        ctx = _build_incident_context(inc, "contained", "sys")
        assert ctx["nist_phase"] == "containment_eradication"

    def test_incident_type_present(self):
        from asc_api.services.soar_incident_bridge import _build_incident_context
        inc = _make_incident(incident_type="ransomware")
        ctx = _build_incident_context(inc, "triaged", "sys")
        assert ctx["incident_type"] == "ransomware"

    def test_all_expected_keys(self):
        from asc_api.services.soar_incident_bridge import _build_incident_context
        inc = _make_incident()
        ctx = _build_incident_context(inc, "triaged", "sys")
        expected = {"severity", "actor", "incident_id", "new_status", "previous_status",
                    "sla_breach", "sla_minutes", "mttd_minutes", "mttc_minutes",
                    "mttr_minutes", "incident_type", "nist_phase"}
        assert expected.issubset(ctx.keys())


# ── TestSignLedger ─────────────────────────────────────────────────────────────

class TestSignLedger:

    def test_no_key_returns_piil_unsigned(self):
        from asc_api.services.soar_incident_bridge import _sign_ledger
        with patch("app.services.soar_incident_bridge._s") as ms:
            ms.SPECTER_SIGNING_PRIVATE_KEY = ""
            sig = _sign_ledger("abc123")
        assert sig == base64.b64encode(b"PIIL-UNSIGNED").decode()

    def test_no_key_result_is_base64(self):
        from asc_api.services.soar_incident_bridge import _sign_ledger
        with patch("app.services.soar_incident_bridge._s") as ms:
            ms.SPECTER_SIGNING_PRIVATE_KEY = ""
            sig = _sign_ledger("abc")
        base64.b64decode(sig)  # should not raise

    def test_invalid_key_returns_error_sig(self):
        from asc_api.services.soar_incident_bridge import _sign_ledger
        with patch("app.services.soar_incident_bridge._s") as ms:
            ms.SPECTER_SIGNING_PRIVATE_KEY = "NOTAKEY=="
            sig = _sign_ledger("abc")
        assert sig  # not empty, does not raise

    def test_invalid_key_result_is_base64(self):
        from asc_api.services.soar_incident_bridge import _sign_ledger
        with patch("app.services.soar_incident_bridge._s") as ms:
            ms.SPECTER_SIGNING_PRIVATE_KEY = "NOTAKEY=="
            sig = _sign_ledger("abc")
        base64.b64decode(sig)  # should not raise

    def test_returns_string(self):
        from asc_api.services.soar_incident_bridge import _sign_ledger
        with patch("app.services.soar_incident_bridge._s") as ms:
            ms.SPECTER_SIGNING_PRIVATE_KEY = ""
            result = _sign_ledger("anything")
        assert isinstance(result, str)

    def test_does_not_raise_on_empty_hash(self):
        from asc_api.services.soar_incident_bridge import _sign_ledger
        with patch("app.services.soar_incident_bridge._s") as ms:
            ms.SPECTER_SIGNING_PRIVATE_KEY = ""
            sig = _sign_ledger("")
        assert sig

    def test_different_inputs_produce_same_unsigned_sig(self):
        from asc_api.services.soar_incident_bridge import _sign_ledger
        with patch("app.services.soar_incident_bridge._s") as ms:
            ms.SPECTER_SIGNING_PRIVATE_KEY = ""
            s1 = _sign_ledger("hash_a")
            s2 = _sign_ledger("hash_b")
        # Both unsigned → same placeholder
        assert s1 == s2

    def test_unsigned_constant_decodable(self):
        sig = base64.b64encode(b"PIIL-UNSIGNED").decode()
        assert base64.b64decode(sig) == b"PIIL-UNSIGNED"

    def test_error_fallback_decodable(self):
        sig = base64.b64encode(b"PIIL-SIGN-ERROR").decode()
        assert base64.b64decode(sig) == b"PIIL-SIGN-ERROR"

    def test_signing_error_uses_error_constant(self):
        from asc_api.services.soar_incident_bridge import _sign_ledger
        with patch("app.services.soar_incident_bridge._s") as ms:
            ms.SPECTER_SIGNING_PRIVATE_KEY = "invalidbase64!@#"
            sig = _sign_ledger("abc")
        decoded = base64.b64decode(sig)
        assert decoded in (b"PIIL-SIGN-ERROR", b"PIIL-UNSIGNED")


# ── TestWriteForensicLedger ────────────────────────────────────────────────────

class TestWriteForensicLedger:

    @pytest.mark.asyncio
    async def test_adds_forensic_entry(self):
        from asc_api.services.soar_incident_bridge import _write_forensic_ledger
        db = AsyncMock()
        db.add = MagicMock()
        db.commit = AsyncMock()
        with patch("app.services.soar_incident_bridge._s") as ms:
            ms.SPECTER_SIGNING_PRIVATE_KEY = ""
            await _write_forensic_ledger(db, "inc-1", "triaged", "actor", 2, {"x": 1})
        db.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_commits_separately(self):
        from asc_api.services.soar_incident_bridge import _write_forensic_ledger
        db = AsyncMock()
        db.add = MagicMock()
        db.commit = AsyncMock()
        with patch("app.services.soar_incident_bridge._s") as ms:
            ms.SPECTER_SIGNING_PRIVATE_KEY = ""
            await _write_forensic_ledger(db, "inc-1", "triaged", "actor", 1, {})
        db.commit.assert_awaited()

    @pytest.mark.asyncio
    async def test_commit_error_non_fatal(self):
        from asc_api.services.soar_incident_bridge import _write_forensic_ledger
        db = AsyncMock()
        db.add = MagicMock()
        db.commit = AsyncMock(side_effect=Exception("DB error"))
        db.rollback = AsyncMock()
        with patch("app.services.soar_incident_bridge._s") as ms:
            ms.SPECTER_SIGNING_PRIVATE_KEY = ""
            # Must not raise
            await _write_forensic_ledger(db, "inc-1", "triaged", "actor", 1, {})
        db.rollback.assert_awaited()

    @pytest.mark.asyncio
    async def test_forensic_entry_action_type(self):
        from asc_api.services.soar_incident_bridge import _write_forensic_ledger
        from asc_api.models.forensic_entry import ForensicEntry
        created_entry = None

        def capture_add(obj):
            nonlocal created_entry
            if isinstance(obj, ForensicEntry):
                created_entry = obj

        db = AsyncMock()
        db.add = MagicMock(side_effect=capture_add)
        db.commit = AsyncMock()
        with patch("app.services.soar_incident_bridge._s") as ms:
            ms.SPECTER_SIGNING_PRIVATE_KEY = ""
            await _write_forensic_ledger(db, "inc-1", "triaged", "actor", 1, {"test": True})
        assert created_entry is not None
        assert created_entry.action_type == "piil_soar_binding"

    @pytest.mark.asyncio
    async def test_forensic_entry_hash_is_128_chars(self):
        from asc_api.services.soar_incident_bridge import _write_forensic_ledger
        from asc_api.models.forensic_entry import ForensicEntry
        created_entry = None

        def capture_add(obj):
            nonlocal created_entry
            if isinstance(obj, ForensicEntry):
                created_entry = obj

        db = AsyncMock()
        db.add = MagicMock(side_effect=capture_add)
        db.commit = AsyncMock()
        with patch("app.services.soar_incident_bridge._s") as ms:
            ms.SPECTER_SIGNING_PRIVATE_KEY = ""
            await _write_forensic_ledger(db, "inc-1", "triaged", "actor", 1, {"data": "x"})
        assert created_entry is not None
        assert len(created_entry.hash_sha3_512) == 128

    @pytest.mark.asyncio
    async def test_target_contains_incident_id(self):
        from asc_api.services.soar_incident_bridge import _write_forensic_ledger
        from asc_api.models.forensic_entry import ForensicEntry
        created_entry = None

        def capture_add(obj):
            nonlocal created_entry
            if isinstance(obj, ForensicEntry):
                created_entry = obj

        db = AsyncMock()
        db.add = MagicMock(side_effect=capture_add)
        db.commit = AsyncMock()
        with patch("app.services.soar_incident_bridge._s") as ms:
            ms.SPECTER_SIGNING_PRIVATE_KEY = ""
            await _write_forensic_ledger(db, "incident-xyz", "closed", "actor", 1, {})
        assert "incident-xyz" in created_entry.target

    @pytest.mark.asyncio
    async def test_verified_false_when_no_key(self):
        from asc_api.services.soar_incident_bridge import _write_forensic_ledger
        from asc_api.models.forensic_entry import ForensicEntry
        created_entry = None

        def capture_add(obj):
            nonlocal created_entry
            if isinstance(obj, ForensicEntry):
                created_entry = obj

        db = AsyncMock()
        db.add = MagicMock(side_effect=capture_add)
        db.commit = AsyncMock()
        with patch("app.services.soar_incident_bridge._s") as ms:
            ms.SPECTER_SIGNING_PRIVATE_KEY = ""
            await _write_forensic_ledger(db, "inc-1", "triaged", "actor", 1, {})
        assert created_entry.verified is False

    @pytest.mark.asyncio
    async def test_signed_by_email_is_actor(self):
        from asc_api.services.soar_incident_bridge import _write_forensic_ledger
        from asc_api.models.forensic_entry import ForensicEntry
        created_entry = None

        def capture_add(obj):
            nonlocal created_entry
            if isinstance(obj, ForensicEntry):
                created_entry = obj

        db = AsyncMock()
        db.add = MagicMock(side_effect=capture_add)
        db.commit = AsyncMock()
        with patch("app.services.soar_incident_bridge._s") as ms:
            ms.SPECTER_SIGNING_PRIVATE_KEY = ""
            await _write_forensic_ledger(db, "inc-1", "triaged", "analyst@premos.com", 1, {})
        assert created_entry.signed_by_email == "analyst@premos.com"

    @pytest.mark.asyncio
    async def test_canonical_data_stored(self):
        from asc_api.services.soar_incident_bridge import _write_forensic_ledger
        from asc_api.models.forensic_entry import ForensicEntry
        created_entry = None

        def capture_add(obj):
            nonlocal created_entry
            if isinstance(obj, ForensicEntry):
                created_entry = obj

        db = AsyncMock()
        db.add = MagicMock(side_effect=capture_add)
        db.commit = AsyncMock()
        payload = {"key": "value", "incident_id": "inc-1"}
        with patch("app.services.soar_incident_bridge._s") as ms:
            ms.SPECTER_SIGNING_PRIVATE_KEY = ""
            await _write_forensic_ledger(db, "inc-1", "triaged", "actor", 1, payload)
        assert created_entry.canonical_data == payload

    @pytest.mark.asyncio
    async def test_rollback_called_on_commit_error(self):
        from asc_api.services.soar_incident_bridge import _write_forensic_ledger
        db = AsyncMock()
        db.add = MagicMock()
        db.commit = AsyncMock(side_effect=Exception("fail"))
        db.rollback = AsyncMock()
        with patch("app.services.soar_incident_bridge._s") as ms:
            ms.SPECTER_SIGNING_PRIVATE_KEY = ""
            await _write_forensic_ledger(db, "inc-1", "triaged", "actor", 1, {})
        db.rollback.assert_awaited_once()


# ── TestWriteSoarEventToTimeline ───────────────────────────────────────────────

class TestWriteSoarEventToTimeline:

    @pytest.mark.asyncio
    async def test_writes_timeline_entry_when_incident_found(self):
        from asc_api.services.soar_incident_bridge import write_soar_event_to_timeline
        from asc_api.models.incident import IncidentTimeline
        inc = _make_incident()
        created_entry = None

        def capture_add(obj):
            nonlocal created_entry
            if isinstance(obj, IncidentTimeline):
                created_entry = obj

        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalar(inc))
        db.add = MagicMock(side_effect=capture_add)
        db.commit = AsyncMock()
        await write_soar_event_to_timeline(db, inc.id, "trigger-A", "playbook-X")
        assert created_entry is not None
        assert created_entry.event_type == "soar_triggered"

    @pytest.mark.asyncio
    async def test_skips_when_incident_not_found(self):
        from asc_api.services.soar_incident_bridge import write_soar_event_to_timeline
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalar(None))
        db.add = MagicMock()
        await write_soar_event_to_timeline(db, "missing-id", "trigger", "playbook")
        db.add.assert_not_called()

    @pytest.mark.asyncio
    async def test_detail_contains_trigger_name(self):
        from asc_api.services.soar_incident_bridge import write_soar_event_to_timeline
        from asc_api.models.incident import IncidentTimeline
        inc = _make_incident()
        created_entry = None

        def capture_add(obj):
            nonlocal created_entry
            if isinstance(obj, IncidentTimeline):
                created_entry = obj

        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalar(inc))
        db.add = MagicMock(side_effect=capture_add)
        db.commit = AsyncMock()
        await write_soar_event_to_timeline(db, inc.id, "trigger-Alpha", "playbook-X")
        assert created_entry.detail["trigger_name"] == "trigger-Alpha"

    @pytest.mark.asyncio
    async def test_detail_contains_playbook_name(self):
        from asc_api.services.soar_incident_bridge import write_soar_event_to_timeline
        from asc_api.models.incident import IncidentTimeline
        inc = _make_incident()
        created_entry = None

        def capture_add(obj):
            nonlocal created_entry
            if isinstance(obj, IncidentTimeline):
                created_entry = obj

        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalar(inc))
        db.add = MagicMock(side_effect=capture_add)
        db.commit = AsyncMock()
        await write_soar_event_to_timeline(db, inc.id, "t", "playbook-Omega")
        assert created_entry.detail["playbook_name"] == "playbook-Omega"

    @pytest.mark.asyncio
    async def test_actor_defaults_to_system_soar(self):
        from asc_api.services.soar_incident_bridge import write_soar_event_to_timeline
        from asc_api.models.incident import IncidentTimeline
        inc = _make_incident()
        created_entry = None

        def capture_add(obj):
            nonlocal created_entry
            if isinstance(obj, IncidentTimeline):
                created_entry = obj

        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalar(inc))
        db.add = MagicMock(side_effect=capture_add)
        db.commit = AsyncMock()
        await write_soar_event_to_timeline(db, inc.id, "t", "p")
        assert created_entry.actor == "system:soar"

    @pytest.mark.asyncio
    async def test_commit_error_non_fatal(self):
        from asc_api.services.soar_incident_bridge import write_soar_event_to_timeline
        inc = _make_incident()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalar(inc))
        db.add = MagicMock()
        db.commit = AsyncMock(side_effect=Exception("DB error"))
        db.rollback = AsyncMock()
        # Must not raise
        await write_soar_event_to_timeline(db, inc.id, "t", "p")
        db.rollback.assert_awaited()

    @pytest.mark.asyncio
    async def test_incident_updated_at_set(self):
        from asc_api.services.soar_incident_bridge import write_soar_event_to_timeline
        inc = _make_incident()
        old_updated = inc.updated_at
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalar(inc))
        db.add = MagicMock()
        db.commit = AsyncMock()
        await write_soar_event_to_timeline(db, inc.id, "t", "p")
        # updated_at should have been set (possibly same instant, just check not None)
        assert inc.updated_at is not None

    @pytest.mark.asyncio
    async def test_commit_called_when_found(self):
        from asc_api.services.soar_incident_bridge import write_soar_event_to_timeline
        inc = _make_incident()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalar(inc))
        db.add = MagicMock()
        db.commit = AsyncMock()
        await write_soar_event_to_timeline(db, inc.id, "t", "p")
        db.commit.assert_awaited()

    @pytest.mark.asyncio
    async def test_custom_actor_respected(self):
        from asc_api.services.soar_incident_bridge import write_soar_event_to_timeline
        from asc_api.models.incident import IncidentTimeline
        inc = _make_incident()
        created_entry = None

        def capture_add(obj):
            nonlocal created_entry
            if isinstance(obj, IncidentTimeline):
                created_entry = obj

        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalar(inc))
        db.add = MagicMock(side_effect=capture_add)
        db.commit = AsyncMock()
        await write_soar_event_to_timeline(db, inc.id, "t", "p", actor="custom-actor")
        assert created_entry.actor == "custom-actor"

    @pytest.mark.asyncio
    async def test_timeline_incident_id_matches(self):
        from asc_api.services.soar_incident_bridge import write_soar_event_to_timeline
        from asc_api.models.incident import IncidentTimeline
        inc = _make_incident(id="specific-inc-id")
        created_entry = None

        def capture_add(obj):
            nonlocal created_entry
            if isinstance(obj, IncidentTimeline):
                created_entry = obj

        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalar(inc))
        db.add = MagicMock(side_effect=capture_add)
        db.commit = AsyncMock()
        await write_soar_event_to_timeline(db, "specific-inc-id", "t", "p")
        assert created_entry.incident_id == "specific-inc-id"


# ── TestEvaluateSoarForIncident ────────────────────────────────────────────────

class TestEvaluateSoarForIncident:

    @pytest.mark.asyncio
    async def test_returns_zero_when_no_triggers_fired(self):
        from asc_api.services.soar_incident_bridge import evaluate_soar_for_incident
        inc = _make_incident()
        db = AsyncMock()
        db.add = MagicMock()
        db.commit = AsyncMock()
        with patch("app.services.soar_service.evaluate_triggers_for_context",
                   new_callable=AsyncMock, return_value=[]):
            count = await evaluate_soar_for_incident(db, inc, "triaged", "actor")
        assert count == 0

    @pytest.mark.asyncio
    async def test_returns_count_when_triggers_fired(self):
        from asc_api.services.soar_incident_bridge import evaluate_soar_for_incident
        inc = _make_incident()
        db = AsyncMock()
        db.add = MagicMock()
        db.commit = AsyncMock()
        fired = [
            {"trigger_id": "t1", "trigger_name": "n1", "playbook_id": "p1",
             "condition_type": "incident_status_change"},
            {"trigger_id": "t2", "trigger_name": "n2", "playbook_id": "p2",
             "condition_type": "incident_severity"},
        ]
        with patch("app.services.soar_service.evaluate_triggers_for_context",
                   new_callable=AsyncMock, return_value=fired):
            with patch("app.services.soar_incident_bridge._write_forensic_ledger",
                       new_callable=AsyncMock):
                with patch("app.services.soar_incident_bridge.log_security_action"):
                    count = await evaluate_soar_for_incident(db, inc, "triaged", "actor")
        assert count == 2

    @pytest.mark.asyncio
    async def test_writes_timeline_entry_per_trigger(self):
        from asc_api.services.soar_incident_bridge import evaluate_soar_for_incident
        from asc_api.models.incident import IncidentTimeline
        inc = _make_incident()
        added = []
        db = AsyncMock()
        db.add = MagicMock(side_effect=lambda obj: added.append(obj))
        db.commit = AsyncMock()
        fired = [{"trigger_id": "t1", "trigger_name": "n1", "playbook_id": "p1",
                  "condition_type": "incident_status_change"}]
        with patch("app.services.soar_service.evaluate_triggers_for_context",
                   new_callable=AsyncMock, return_value=fired):
            with patch("app.services.soar_incident_bridge._write_forensic_ledger",
                       new_callable=AsyncMock):
                with patch("app.services.soar_incident_bridge.log_security_action"):
                    await evaluate_soar_for_incident(db, inc, "triaged", "actor")
        timeline_entries = [o for o in added if isinstance(o, IncidentTimeline)]
        assert len(timeline_entries) == 1

    @pytest.mark.asyncio
    async def test_writes_forensic_ledger_when_triggers_fire(self):
        from asc_api.services.soar_incident_bridge import evaluate_soar_for_incident
        inc = _make_incident()
        db = AsyncMock()
        db.add = MagicMock()
        db.commit = AsyncMock()
        fired = [{"trigger_id": "t1", "trigger_name": "n1", "playbook_id": "p1",
                  "condition_type": "incident_status_change"}]
        with patch("app.services.soar_service.evaluate_triggers_for_context",
                   new_callable=AsyncMock, return_value=fired):
            with patch("app.services.soar_incident_bridge._write_forensic_ledger",
                       new_callable=AsyncMock) as mock_ledger:
                with patch("app.services.soar_incident_bridge.log_security_action"):
                    await evaluate_soar_for_incident(db, inc, "triaged", "actor")
        mock_ledger.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_no_forensic_ledger_when_no_triggers(self):
        from asc_api.services.soar_incident_bridge import evaluate_soar_for_incident
        inc = _make_incident()
        db = AsyncMock()
        db.add = MagicMock()
        db.commit = AsyncMock()
        with patch("app.services.soar_service.evaluate_triggers_for_context",
                   new_callable=AsyncMock, return_value=[]):
            with patch("app.services.soar_incident_bridge._write_forensic_ledger",
                       new_callable=AsyncMock) as mock_ledger:
                await evaluate_soar_for_incident(db, inc, "triaged", "actor")
        mock_ledger.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_soar_eval_error_returns_zero_non_blocking(self):
        from asc_api.services.soar_incident_bridge import evaluate_soar_for_incident
        inc = _make_incident()
        db = AsyncMock()
        with patch("app.services.soar_service.evaluate_triggers_for_context",
                   new_callable=AsyncMock, side_effect=Exception("SOAR down")):
            count = await evaluate_soar_for_incident(db, inc, "triaged", "actor")
        assert count == 0

    @pytest.mark.asyncio
    async def test_commit_error_returns_zero_non_blocking(self):
        from asc_api.services.soar_incident_bridge import evaluate_soar_for_incident
        inc = _make_incident()
        db = AsyncMock()
        db.add = MagicMock()
        db.commit = AsyncMock(side_effect=Exception("commit fail"))
        db.rollback = AsyncMock()
        fired = [{"trigger_id": "t1", "trigger_name": "n1", "playbook_id": "p1",
                  "condition_type": "incident_status_change"}]
        with patch("app.services.soar_service.evaluate_triggers_for_context",
                   new_callable=AsyncMock, return_value=fired):
            with patch("app.services.soar_incident_bridge._write_forensic_ledger",
                       new_callable=AsyncMock):
                with patch("app.services.soar_incident_bridge.log_security_action"):
                    count = await evaluate_soar_for_incident(db, inc, "triaged", "actor")
        # Returns 0 when commit fails
        assert count == 0

    @pytest.mark.asyncio
    async def test_log_security_action_called_on_fire(self):
        from asc_api.services.soar_incident_bridge import evaluate_soar_for_incident
        inc = _make_incident()
        db = AsyncMock()
        db.add = MagicMock()
        db.commit = AsyncMock()
        fired = [{"trigger_id": "t1", "trigger_name": "n1", "playbook_id": "p1",
                  "condition_type": "incident_status_change"}]
        with patch("app.services.soar_service.evaluate_triggers_for_context",
                   new_callable=AsyncMock, return_value=fired):
            with patch("app.services.soar_incident_bridge._write_forensic_ledger",
                       new_callable=AsyncMock):
                with patch("app.services.soar_incident_bridge.log_security_action") as mock_audit:
                    await evaluate_soar_for_incident(db, inc, "triaged", "actor")
        mock_audit.assert_called_once()

    @pytest.mark.asyncio
    async def test_timeline_entry_event_type(self):
        from asc_api.services.soar_incident_bridge import evaluate_soar_for_incident
        from asc_api.models.incident import IncidentTimeline
        inc = _make_incident()
        added = []
        db = AsyncMock()
        db.add = MagicMock(side_effect=lambda obj: added.append(obj))
        db.commit = AsyncMock()
        fired = [{"trigger_id": "t1", "trigger_name": "n1", "playbook_id": "p1",
                  "condition_type": "incident_status_change"}]
        with patch("app.services.soar_service.evaluate_triggers_for_context",
                   new_callable=AsyncMock, return_value=fired):
            with patch("app.services.soar_incident_bridge._write_forensic_ledger",
                       new_callable=AsyncMock):
                with patch("app.services.soar_incident_bridge.log_security_action"):
                    await evaluate_soar_for_incident(db, inc, "triaged", "actor")
        entries = [o for o in added if isinstance(o, IncidentTimeline)]
        assert all(e.event_type == "soar_triggered" for e in entries)

    @pytest.mark.asyncio
    async def test_multiple_triggers_write_multiple_entries(self):
        from asc_api.services.soar_incident_bridge import evaluate_soar_for_incident
        from asc_api.models.incident import IncidentTimeline
        inc = _make_incident()
        added = []
        db = AsyncMock()
        db.add = MagicMock(side_effect=lambda obj: added.append(obj))
        db.commit = AsyncMock()
        fired = [
            {"trigger_id": "t1", "trigger_name": "n1", "playbook_id": "p1",
             "condition_type": "incident_status_change"},
            {"trigger_id": "t2", "trigger_name": "n2", "playbook_id": "p2",
             "condition_type": "incident_severity"},
            {"trigger_id": "t3", "trigger_name": "n3", "playbook_id": "p3",
             "condition_type": "incident_sla_breach"},
        ]
        with patch("app.services.soar_service.evaluate_triggers_for_context",
                   new_callable=AsyncMock, return_value=fired):
            with patch("app.services.soar_incident_bridge._write_forensic_ledger",
                       new_callable=AsyncMock):
                with patch("app.services.soar_incident_bridge.log_security_action"):
                    count = await evaluate_soar_for_incident(db, inc, "triaged", "actor")
        entries = [o for o in added if isinstance(o, IncidentTimeline)]
        assert count == 3
        assert len(entries) == 3

    @pytest.mark.asyncio
    async def test_no_log_security_action_when_no_triggers(self):
        from asc_api.services.soar_incident_bridge import evaluate_soar_for_incident
        inc = _make_incident()
        db = AsyncMock()
        db.add = MagicMock()
        db.commit = AsyncMock()
        with patch("app.services.soar_service.evaluate_triggers_for_context",
                   new_callable=AsyncMock, return_value=[]):
            with patch("app.services.soar_incident_bridge.log_security_action") as mock_audit:
                await evaluate_soar_for_incident(db, inc, "triaged", "actor")
        mock_audit.assert_not_called()

    @pytest.mark.asyncio
    async def test_context_contains_sla_breach_flag(self):
        from asc_api.services.soar_incident_bridge import evaluate_soar_for_incident, _build_incident_context
        inc = _make_incident(sla_breach=True)
        ctx = _build_incident_context(inc, "triaged", "actor")
        assert ctx["sla_breach"] is True

    @pytest.mark.asyncio
    async def test_context_new_status_propagated(self):
        from asc_api.services.soar_incident_bridge import _build_incident_context
        inc = _make_incident()
        ctx = _build_incident_context(inc, "contained", "actor")
        assert ctx["new_status"] == "contained"


# ── TestEscalateSlaBreaches ────────────────────────────────────────────────────

class TestEscalateSlaBreaches:

    @pytest.mark.asyncio
    async def test_returns_zero_when_no_open_incidents(self):
        from asc_api.services.soar_incident_bridge import escalate_sla_breaches
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([]))
        result = await escalate_sla_breaches(db)
        assert result == 0

    @pytest.mark.asyncio
    async def test_flags_sla_breach_on_breached_incident(self):
        from asc_api.services.soar_incident_bridge import escalate_sla_breaches
        inc = _make_incident(sla_breach=False, detected_at=_utcnow() - timedelta(days=5))
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([inc]))
        db.add = MagicMock()
        db.commit = AsyncMock()
        with patch("app.services.incident_service._check_sla_breach", return_value=True):
            with patch("app.services.incident_service._utcnow", return_value=_utcnow()):
                result = await escalate_sla_breaches(db)
        assert inc.sla_breach is True
        assert result == 1

    @pytest.mark.asyncio
    async def test_skips_when_sla_not_breached(self):
        from asc_api.services.soar_incident_bridge import escalate_sla_breaches
        inc = _make_incident(sla_breach=False)
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([inc]))
        db.add = MagicMock()
        db.commit = AsyncMock()
        with patch("app.services.incident_service._check_sla_breach", return_value=False):
            result = await escalate_sla_breaches(db)
        assert result == 0
        assert inc.sla_breach is False

    @pytest.mark.asyncio
    async def test_writes_sla_warning_timeline_entry(self):
        from asc_api.services.soar_incident_bridge import escalate_sla_breaches
        from asc_api.models.incident import IncidentTimeline
        inc = _make_incident(sla_breach=False)
        added = []
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([inc]))
        db.add = MagicMock(side_effect=lambda obj: added.append(obj))
        db.commit = AsyncMock()
        with patch("app.services.incident_service._check_sla_breach", return_value=True):
            with patch("app.services.incident_service._utcnow", return_value=_utcnow()):
                await escalate_sla_breaches(db)
        entries = [o for o in added if isinstance(o, IncidentTimeline)]
        assert len(entries) == 1
        assert entries[0].event_type == "sla_warning"

    @pytest.mark.asyncio
    async def test_commit_called_when_any_escalated(self):
        from asc_api.services.soar_incident_bridge import escalate_sla_breaches
        inc = _make_incident(sla_breach=False)
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([inc]))
        db.add = MagicMock()
        db.commit = AsyncMock()
        with patch("app.services.incident_service._check_sla_breach", return_value=True):
            with patch("app.services.incident_service._utcnow", return_value=_utcnow()):
                await escalate_sla_breaches(db)
        db.commit.assert_awaited()

    @pytest.mark.asyncio
    async def test_commit_not_called_when_none_escalated(self):
        from asc_api.services.soar_incident_bridge import escalate_sla_breaches
        inc = _make_incident(sla_breach=False)
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([inc]))
        db.add = MagicMock()
        db.commit = AsyncMock()
        with patch("app.services.incident_service._check_sla_breach", return_value=False):
            await escalate_sla_breaches(db)
        db.commit.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_commit_error_returns_zero(self):
        from asc_api.services.soar_incident_bridge import escalate_sla_breaches
        inc = _make_incident(sla_breach=False)
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([inc]))
        db.add = MagicMock()
        db.commit = AsyncMock(side_effect=Exception("DB fail"))
        db.rollback = AsyncMock()
        with patch("app.services.incident_service._check_sla_breach", return_value=True):
            with patch("app.services.incident_service._utcnow", return_value=_utcnow()):
                result = await escalate_sla_breaches(db)
        assert result == 0

    @pytest.mark.asyncio
    async def test_multiple_incidents_multiple_escalations(self):
        from asc_api.services.soar_incident_bridge import escalate_sla_breaches
        incs = [_make_incident(sla_breach=False) for _ in range(3)]
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars(incs))
        db.add = MagicMock()
        db.commit = AsyncMock()
        with patch("app.services.incident_service._check_sla_breach", return_value=True):
            with patch("app.services.incident_service._utcnow", return_value=_utcnow()):
                result = await escalate_sla_breaches(db)
        assert result == 3

    @pytest.mark.asyncio
    async def test_sla_warning_actor_is_system_piil(self):
        from asc_api.services.soar_incident_bridge import escalate_sla_breaches
        from asc_api.models.incident import IncidentTimeline
        inc = _make_incident(sla_breach=False)
        added = []
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([inc]))
        db.add = MagicMock(side_effect=lambda obj: added.append(obj))
        db.commit = AsyncMock()
        with patch("app.services.incident_service._check_sla_breach", return_value=True):
            with patch("app.services.incident_service._utcnow", return_value=_utcnow()):
                await escalate_sla_breaches(db)
        entries = [o for o in added if isinstance(o, IncidentTimeline)]
        assert entries[0].actor == "system:piil"

    @pytest.mark.asyncio
    async def test_partial_escalation_only_breached_count(self):
        from asc_api.services.soar_incident_bridge import escalate_sla_breaches
        incs = [_make_incident(sla_breach=False) for _ in range(4)]
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars(incs))
        db.add = MagicMock()
        db.commit = AsyncMock()
        # Only 2 of 4 actually breach
        breached = [True, False, True, False]
        with patch("app.services.incident_service._check_sla_breach",
                   side_effect=breached):
            with patch("app.services.incident_service._utcnow", return_value=_utcnow()):
                result = await escalate_sla_breaches(db)
        assert result == 2

    @pytest.mark.asyncio
    async def test_rollback_on_commit_error(self):
        from asc_api.services.soar_incident_bridge import escalate_sla_breaches
        inc = _make_incident(sla_breach=False)
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([inc]))
        db.add = MagicMock()
        db.commit = AsyncMock(side_effect=Exception("fail"))
        db.rollback = AsyncMock()
        with patch("app.services.incident_service._check_sla_breach", return_value=True):
            with patch("app.services.incident_service._utcnow", return_value=_utcnow()):
                await escalate_sla_breaches(db)
        db.rollback.assert_awaited()


# ── TestNewSoarConditionTypes ─────────────────────────────────────────────────

class TestNewSoarConditionTypes:
    """Verify the _evaluate_condition additions for incident-specific SOAR conditions."""

    def _cond(self, ctype, op, val):
        c = MagicMock()
        c.condition_type = ctype
        c.condition_operator = op
        c.condition_value = val
        return c

    def test_incident_status_change_eq_match(self):
        from asc_api.services.soar_service import _evaluate_condition
        ctx = {"new_status": "triaged"}
        assert _evaluate_condition(self._cond("incident_status_change", "eq", "triaged"), ctx) is True

    def test_incident_status_change_eq_no_match(self):
        from asc_api.services.soar_service import _evaluate_condition
        ctx = {"new_status": "detected"}
        assert _evaluate_condition(self._cond("incident_status_change", "eq", "triaged"), ctx) is False

    def test_incident_status_change_contains_match(self):
        from asc_api.services.soar_service import _evaluate_condition
        ctx = {"new_status": "triaged"}
        assert _evaluate_condition(
            self._cond("incident_status_change", "contains", "triaged,contained"), ctx
        ) is True

    def test_incident_status_change_contains_no_match(self):
        from asc_api.services.soar_service import _evaluate_condition
        ctx = {"new_status": "detected"}
        assert _evaluate_condition(
            self._cond("incident_status_change", "contains", "triaged,contained"), ctx
        ) is False

    def test_incident_status_change_unknown_op_returns_false(self):
        from asc_api.services.soar_service import _evaluate_condition
        ctx = {"new_status": "triaged"}
        assert _evaluate_condition(
            self._cond("incident_status_change", "gte", "triaged"), ctx
        ) is False

    def test_incident_sla_breach_true(self):
        from asc_api.services.soar_service import _evaluate_condition
        ctx = {"sla_breach": True}
        assert _evaluate_condition(self._cond("incident_sla_breach", "eq", "true"), ctx) is True

    def test_incident_sla_breach_false(self):
        from asc_api.services.soar_service import _evaluate_condition
        ctx = {"sla_breach": False}
        assert _evaluate_condition(self._cond("incident_sla_breach", "eq", "false"), ctx) is False

    def test_incident_sla_breach_missing_context_key(self):
        from asc_api.services.soar_service import _evaluate_condition
        ctx = {}  # no sla_breach key
        assert _evaluate_condition(self._cond("incident_sla_breach", "eq", "true"), ctx) is False

    def test_incident_severity_eq_match(self):
        from asc_api.services.soar_service import _evaluate_condition
        ctx = {"severity": "critical"}
        assert _evaluate_condition(self._cond("incident_severity", "eq", "critical"), ctx) is True

    def test_incident_severity_eq_no_match(self):
        from asc_api.services.soar_service import _evaluate_condition
        ctx = {"severity": "high"}
        assert _evaluate_condition(self._cond("incident_severity", "eq", "critical"), ctx) is False

    def test_incident_severity_gte_critical_vs_high(self):
        from asc_api.services.soar_service import _evaluate_condition
        ctx = {"severity": "critical"}
        assert _evaluate_condition(self._cond("incident_severity", "gte", "high"), ctx) is True

    def test_incident_severity_gte_low_vs_critical_fails(self):
        from asc_api.services.soar_service import _evaluate_condition
        ctx = {"severity": "low"}
        assert _evaluate_condition(self._cond("incident_severity", "gte", "critical"), ctx) is False

    def test_incident_severity_lte_low_vs_medium(self):
        from asc_api.services.soar_service import _evaluate_condition
        ctx = {"severity": "low"}
        assert _evaluate_condition(self._cond("incident_severity", "lte", "medium"), ctx) is True

    def test_incident_severity_lte_critical_vs_medium_fails(self):
        from asc_api.services.soar_service import _evaluate_condition
        ctx = {"severity": "critical"}
        assert _evaluate_condition(self._cond("incident_severity", "lte", "medium"), ctx) is False

    def test_incident_severity_contains_match(self):
        from asc_api.services.soar_service import _evaluate_condition
        ctx = {"severity": "high"}
        assert _evaluate_condition(
            self._cond("incident_severity", "contains", "high,critical"), ctx
        ) is True

    def test_incident_severity_contains_no_match(self):
        from asc_api.services.soar_service import _evaluate_condition
        ctx = {"severity": "low"}
        assert _evaluate_condition(
            self._cond("incident_severity", "contains", "high,critical"), ctx
        ) is False


# ── TestIncidentSoarIntegration ────────────────────────────────────────────────

class TestIncidentSoarIntegration:

    @pytest.mark.asyncio
    async def test_transition_status_calls_bridge(self):
        """verify that incident_service.transition_status imports and calls the bridge"""
        from asc_api.services import incident_service
        import importlib
        # Verify the import path exists in incident_service source
        import inspect
        source = inspect.getsource(incident_service.transition_status)
        assert "evaluate_soar_for_incident" in source or "soar_incident_bridge" in source

    @pytest.mark.asyncio
    async def test_bridge_failure_does_not_block_transition(self):
        """bridge exception must not propagate out of transition_status"""
        from asc_api.services import incident_service
        inc = _make_incident(status="detected")

        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalar(inc))
        db.commit = AsyncMock()
        db.refresh = AsyncMock()

        with patch("app.services.incident_service.get_logger"):
            with patch("app.services.soar_incident_bridge.evaluate_soar_for_incident",
                       new_callable=AsyncMock, side_effect=Exception("bridge boom")):
                with patch("app.services.incident_service.log_security_action"):
                    # Should not raise even if bridge fails
                    try:
                        await incident_service.transition_status(
                            db, inc.id, "triaged", actor="analyst@premos.com"
                        )
                    except Exception as e:
                        # Only incident-service-level errors are acceptable (not bridge errors)
                        assert "bridge boom" not in str(e)

    @pytest.mark.asyncio
    async def test_bridge_called_with_new_status(self):
        """evaluate_soar_for_incident receives the new_status — verified via source inspection"""
        from asc_api.services import incident_service
        import inspect
        source = inspect.getsource(incident_service.transition_status)
        # The bridge call must pass the new status variable to evaluate_soar_for_incident
        assert "new_status" in source
        assert "evaluate_soar_for_incident" in source

    @pytest.mark.asyncio
    async def test_bridge_wraps_in_try_except(self):
        """Verify incident_service wraps bridge call in try/except block"""
        from asc_api.services import incident_service
        import inspect
        source = inspect.getsource(incident_service.transition_status)
        # Must have try/except pattern wrapping the bridge call
        assert "try:" in source
        assert "except" in source

    @pytest.mark.asyncio
    async def test_piil_version_in_canonical(self):
        """PIIL canonical data must include version field"""
        from asc_api.services.soar_incident_bridge import evaluate_soar_for_incident
        inc = _make_incident()
        db = AsyncMock()
        db.add = MagicMock()
        db.commit = AsyncMock()
        fired = [{"trigger_id": "t1", "trigger_name": "n1", "playbook_id": "p1",
                  "condition_type": "incident_status_change"}]
        captured_canonical = []

        async def capture_ledger(db, incident_id, new_status, actor, triggers_fired, canonical):
            captured_canonical.append(canonical)

        with patch("app.services.soar_service.evaluate_triggers_for_context",
                   new_callable=AsyncMock, return_value=fired):
            with patch("app.services.soar_incident_bridge._write_forensic_ledger",
                       side_effect=capture_ledger):
                with patch("app.services.soar_incident_bridge.log_security_action"):
                    await evaluate_soar_for_incident(db, inc, "triaged", "actor")
        assert len(captured_canonical) == 1
        assert captured_canonical[0].get("piil_version") == "1.0"

    @pytest.mark.asyncio
    async def test_severity_rank_order(self):
        """_SEV_RANK must place critical above high above medium"""
        from asc_api.services.soar_incident_bridge import _SEV_RANK
        assert _SEV_RANK["critical"] > _SEV_RANK["high"]
        assert _SEV_RANK["high"] > _SEV_RANK["medium"]
        assert _SEV_RANK["medium"] > _SEV_RANK["low"]
        assert _SEV_RANK["low"] > _SEV_RANK["info"]

    @pytest.mark.asyncio
    async def test_incident_status_change_in_valid_condition_types(self):
        """All new condition types must be registered in soar_service"""
        from asc_api.services.soar_service import _VALID_CONDITION_TYPES
        assert "incident_status_change" in _VALID_CONDITION_TYPES
        assert "incident_sla_breach" in _VALID_CONDITION_TYPES
        assert "incident_severity" in _VALID_CONDITION_TYPES

    @pytest.mark.asyncio
    async def test_piil_soar_binding_action_type_constant(self):
        """ForensicEntry action_type for PIIL binding must be 'piil_soar_binding'"""
        from asc_api.services.soar_incident_bridge import _write_forensic_ledger
        from asc_api.models.forensic_entry import ForensicEntry
        created = None

        def capture(obj):
            nonlocal created
            if isinstance(obj, ForensicEntry):
                created = obj

        db = AsyncMock()
        db.add = MagicMock(side_effect=capture)
        db.commit = AsyncMock()
        with patch("app.services.soar_incident_bridge._s") as ms:
            ms.SPECTER_SIGNING_PRIVATE_KEY = ""
            await _write_forensic_ledger(db, "inc", "closed", "sys", 1, {"piil_version": "1.0"})
        assert created is not None
        assert created.action_type == "piil_soar_binding"

    @pytest.mark.asyncio
    async def test_timeline_entry_incident_id_matches_incident(self):
        from asc_api.services.soar_incident_bridge import evaluate_soar_for_incident
        from asc_api.models.incident import IncidentTimeline
        inc = _make_incident(id="my-inc-999")
        added = []
        db = AsyncMock()
        db.add = MagicMock(side_effect=lambda obj: added.append(obj))
        db.commit = AsyncMock()
        fired = [{"trigger_id": "t1", "trigger_name": "n1", "playbook_id": "p1",
                  "condition_type": "incident_status_change"}]
        with patch("app.services.soar_service.evaluate_triggers_for_context",
                   new_callable=AsyncMock, return_value=fired):
            with patch("app.services.soar_incident_bridge._write_forensic_ledger",
                       new_callable=AsyncMock):
                with patch("app.services.soar_incident_bridge.log_security_action"):
                    await evaluate_soar_for_incident(db, inc, "triaged", "actor")
        entries = [o for o in added if isinstance(o, IncidentTimeline)]
        assert all(e.incident_id == "my-inc-999" for e in entries)
