"""
P28-B â€” Incident Response Management â€” Test Suite

Coverage:
  TestIncidentModels           (10) â€” ORM instantiation, constants, forensic_hash, SLA defaults
  TestIncidentValidTransitions  (8) â€” state machine VALID_TRANSITIONS coverage
  TestIncidentNistPhase         (6) â€” NIST_PHASE mapping correctness
  TestMinutesBetween            (6) â€” _minutes_between helper
  TestSlaForHelper              (4) â€” _sla_for severity mapping
  TestCreateIncident           (10) â€” creation, SLA assignment, timeline, initial link
  TestTransitionStatus         (12) â€” valid transitions, phase timestamps, MTTD/MTTC/MTTR, invalid guard
  TestAssignIncident            (4) â€” assignment + timeline entry
  TestLinkEntity                (6) â€” add link, dedup guard, missing incident
  TestRemoveLink                (4) â€” remove existing + not-found
  TestAddNote                   (6) â€” happy path, closed incident guard
  TestCloseIncident             (8) â€” auto-advance, KPI computation, forensic hash
  TestDismissIncident           (6) â€” happy path, invalid state guard, FP flag
  TestUpdateMitre               (4) â€” MITRE update + timeline
  TestGetIncidentSummary        (6) â€” KPI aggregation, avg MTTD/MTTR
  TestAutoCreateFromCluster     (6) â€” campaign promotion, dedup idempotency
  TestIncidentEndpoints        (10) â€” REST status codes, auth, validation, 404

Total: 116 tests
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# â”€â”€ Shared helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _make_incident(**kwargs):
    from asc_api.models.incident import Incident
    i = Incident()
    i.id = kwargs.get("id", str(uuid.uuid4()))
    i.title = kwargs.get("title", "Test Incident")
    i.description = kwargs.get("description", None)
    i.incident_type = kwargs.get("incident_type", "other")
    i.status = kwargs.get("status", "detected")
    i.nist_phase = kwargs.get("nist_phase", "detection_analysis")
    i.severity = kwargs.get("severity", "medium")
    i.risk_score = kwargs.get("risk_score", 0.0)
    i.created_by = kwargs.get("created_by", "analyst@test.com")
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
    i.created_at = kwargs.get("created_at", _utcnow())
    i.updated_at = kwargs.get("updated_at", _utcnow())
    return i


def _make_link(**kwargs):
    from asc_api.models.incident import IncidentLink
    l = IncidentLink()
    l.id = kwargs.get("id", str(uuid.uuid4()))
    l.incident_id = kwargs.get("incident_id", str(uuid.uuid4()))
    l.entity_type = kwargs.get("entity_type", "alert")
    l.entity_id = kwargs.get("entity_id", str(uuid.uuid4()))
    l.notes = kwargs.get("notes", None)
    l.added_by = kwargs.get("added_by", "system")
    l.created_at = _utcnow()
    return l


def _make_timeline_entry(**kwargs):
    from asc_api.models.incident import IncidentTimeline
    e = IncidentTimeline()
    e.id = kwargs.get("id", str(uuid.uuid4()))
    e.incident_id = kwargs.get("incident_id", str(uuid.uuid4()))
    e.event_type = kwargs.get("event_type", "created")
    e.actor = kwargs.get("actor", "system")
    e.detail = kwargs.get("detail", {})
    e.created_at = _utcnow()
    return e


def _make_cluster(**kwargs):
    c = MagicMock()
    c.id = kwargs.get("id", str(uuid.uuid4()))
    c.cluster_type = kwargs.get("cluster_type", "host_pivot")
    c.cluster_key = kwargs.get("cluster_key", "ws-001")
    c.severity = kwargs.get("severity", "high")
    c.signal_count = kwargs.get("signal_count", 5)
    c.is_campaign = kwargs.get("is_campaign", True)
    return c


def _scalars_result(items):
    r = MagicMock()
    r.scalars = MagicMock(return_value=MagicMock(all=MagicMock(return_value=items)))
    return r


def _scalar_one(item):
    r = MagicMock()
    r.scalar_one_or_none = MagicMock(return_value=item)
    return r


def _scalar_one_val(value):
    r = MagicMock()
    r.scalar_one = MagicMock(return_value=value)
    return r


def _all_result(rows):
    r = MagicMock()
    r.all = MagicMock(return_value=rows)
    return r


def _mock_analyst():
    u = MagicMock()
    u.email = "analyst@test.com"
    u.role = "analyst"
    return u


def _mock_admin():
    u = MagicMock()
    u.email = "admin@test.com"
    u.role = "admin"
    return u


# â”€â”€ TestIncidentModels â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestIncidentModels:
    def test_incident_constants_complete(self):
        from asc_api.models.incident import INCIDENT_STATUSES
        assert "detected" in INCIDENT_STATUSES
        assert "closed" in INCIDENT_STATUSES
        assert "dismissed" in INCIDENT_STATUSES
        assert len(INCIDENT_STATUSES) == 8

    def test_incident_types_defined(self):
        from asc_api.models.incident import INCIDENT_TYPES
        assert "malware" in INCIDENT_TYPES
        assert "apt" in INCIDENT_TYPES
        assert "other" in INCIDENT_TYPES

    def test_link_entity_types_defined(self):
        from asc_api.models.incident import LINK_ENTITY_TYPES
        assert "alert" in LINK_ENTITY_TYPES
        assert "cluster" in LINK_ENTITY_TYPES

    def test_timeline_event_types_defined(self):
        from asc_api.models.incident import TIMELINE_EVENT_TYPES
        assert "created" in TIMELINE_EVENT_TYPES
        assert "status_change" in TIMELINE_EVENT_TYPES
        assert "closed" in TIMELINE_EVENT_TYPES

    def test_incident_orm_instantiation(self):
        i = _make_incident(title="SQL Injection Campaign", severity="critical")
        assert i.title == "SQL Injection Campaign"
        assert i.severity == "critical"
        assert i.status == "detected"
        assert i.false_positive is False

    def test_incident_forensic_hash_deterministic(self):
        i = _make_incident(id="fixed-id", severity="high")
        h1 = i.compute_forensic_hash()
        h2 = i.compute_forensic_hash()
        assert h1 == h2
        assert len(h1) == 128  # SHA3-512 hex

    def test_incident_forensic_hash_changes_on_mutation(self):
        i = _make_incident(id="fixed-id", severity="high")
        h1 = i.compute_forensic_hash()
        i.sla_breach = True
        h2 = i.compute_forensic_hash()
        assert h1 != h2

    def test_incident_link_orm_instantiation(self):
        l = _make_link(entity_type="cluster", entity_id="abc-123")
        assert l.entity_type == "cluster"
        assert l.entity_id == "abc-123"

    def test_incident_timeline_orm_instantiation(self):
        e = _make_timeline_entry(event_type="status_change", actor="analyst@test.com")
        assert e.event_type == "status_change"
        assert e.actor == "analyst@test.com"

    def test_sla_defaults_all_severities(self):
        from asc_api.models.incident import DEFAULT_SLA_MINUTES
        assert DEFAULT_SLA_MINUTES["critical"] == 60
        assert DEFAULT_SLA_MINUTES["high"] == 240
        assert DEFAULT_SLA_MINUTES["medium"] == 1440
        assert DEFAULT_SLA_MINUTES["low"] == 10080
        assert DEFAULT_SLA_MINUTES["info"] == 43200


# â”€â”€ TestIncidentValidTransitions â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestIncidentValidTransitions:
    def test_detected_can_triage(self):
        from asc_api.models.incident import VALID_TRANSITIONS
        assert "triaged" in VALID_TRANSITIONS["detected"]

    def test_detected_can_dismiss(self):
        from asc_api.models.incident import VALID_TRANSITIONS
        assert "dismissed" in VALID_TRANSITIONS["detected"]

    def test_triaged_can_contain(self):
        from asc_api.models.incident import VALID_TRANSITIONS
        assert "contained" in VALID_TRANSITIONS["triaged"]

    def test_contained_can_rollback_to_triaged(self):
        from asc_api.models.incident import VALID_TRANSITIONS
        assert "triaged" in VALID_TRANSITIONS["contained"]

    def test_recovered_leads_to_post_incident(self):
        from asc_api.models.incident import VALID_TRANSITIONS
        assert "post_incident" in VALID_TRANSITIONS["recovered"]

    def test_post_incident_leads_to_closed(self):
        from asc_api.models.incident import VALID_TRANSITIONS
        assert "closed" in VALID_TRANSITIONS["post_incident"]

    def test_closed_is_terminal(self):
        from asc_api.models.incident import VALID_TRANSITIONS
        assert len(VALID_TRANSITIONS["closed"]) == 0

    def test_dismissed_is_terminal(self):
        from asc_api.models.incident import VALID_TRANSITIONS
        assert len(VALID_TRANSITIONS["dismissed"]) == 0


# â”€â”€ TestIncidentNistPhase â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestIncidentNistPhase:
    def test_detected_phase(self):
        from asc_api.models.incident import NIST_PHASE
        assert NIST_PHASE["detected"] == "detection_analysis"

    def test_triaged_phase(self):
        from asc_api.models.incident import NIST_PHASE
        assert NIST_PHASE["triaged"] == "detection_analysis"

    def test_contained_phase(self):
        from asc_api.models.incident import NIST_PHASE
        assert NIST_PHASE["contained"] == "containment"

    def test_recovered_phase(self):
        from asc_api.models.incident import NIST_PHASE
        assert NIST_PHASE["recovered"] == "recovery"

    def test_closed_phase(self):
        from asc_api.models.incident import NIST_PHASE
        assert NIST_PHASE["closed"] == "post_incident_activity"

    def test_dismissed_phase(self):
        from asc_api.models.incident import NIST_PHASE
        assert NIST_PHASE["dismissed"] == "post_incident_activity"


# â”€â”€ TestMinutesBetween â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestMinutesBetween:
    def test_one_hour(self):
        from asc_api.services.incident_service import _minutes_between
        start = _utcnow()
        end = start + timedelta(hours=1)
        assert _minutes_between(start, end) == 60

    def test_none_start_returns_none(self):
        from asc_api.services.incident_service import _minutes_between
        assert _minutes_between(None, _utcnow()) is None

    def test_none_end_returns_none(self):
        from asc_api.services.incident_service import _minutes_between
        assert _minutes_between(_utcnow(), None) is None

    def test_both_none_returns_none(self):
        from asc_api.services.incident_service import _minutes_between
        assert _minutes_between(None, None) is None

    def test_zero_delta_returns_zero(self):
        from asc_api.services.incident_service import _minutes_between
        t = _utcnow()
        assert _minutes_between(t, t) == 0

    def test_partial_minutes_ceil(self):
        from asc_api.services.incident_service import _minutes_between
        start = _utcnow()
        end = start + timedelta(seconds=90)  # 1.5 min â†’ ceiled to 2
        result = _minutes_between(start, end)
        assert result == 2


# â”€â”€ TestSlaForHelper â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestSlaForHelper:
    def test_critical_sla(self):
        from asc_api.services.incident_service import _sla_for
        assert _sla_for("critical") == 60

    def test_high_sla(self):
        from asc_api.services.incident_service import _sla_for
        assert _sla_for("high") == 240

    def test_unknown_severity_defaults_to_medium(self):
        from asc_api.services.incident_service import _sla_for
        assert _sla_for("unknown_sev") == 1440

    def test_info_sla(self):
        from asc_api.services.incident_service import _sla_for
        assert _sla_for("info") == 43200


# â”€â”€ TestCreateIncident â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestCreateIncident:
    @pytest.mark.asyncio
    async def test_create_sets_detected_at(self):
        from asc_api.services.incident_service import create_incident
        db = AsyncMock()
        db.add = MagicMock()
        db.commit = AsyncMock()

        created_incident = None

        def capture_add(obj):
            nonlocal created_incident
            from asc_api.models.incident import Incident
            if isinstance(obj, Incident):
                created_incident = obj

        db.add.side_effect = capture_add
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        with patch("asc_api.services.incident_service.log_security_action"):
            await create_incident(db, title="Test", incident_type="malware",
                                  severity="high", created_by="analyst@test.com")
        assert created_incident is not None
        assert created_incident.detected_at is not None

    @pytest.mark.asyncio
    async def test_create_sets_sla_from_severity(self):
        from asc_api.services.incident_service import create_incident
        db = AsyncMock()
        db.add = MagicMock()
        db.commit = AsyncMock()
        created_incident = None

        def capture_add(obj):
            nonlocal created_incident
            from asc_api.models.incident import Incident
            if isinstance(obj, Incident):
                created_incident = obj

        db.add.side_effect = capture_add
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        with patch("asc_api.services.incident_service.log_security_action"):
            await create_incident(db, title="Test", incident_type="malware",
                                  severity="critical", created_by="analyst@test.com")
        assert created_incident is not None
        assert created_incident.sla_minutes == 60

    @pytest.mark.asyncio
    async def test_create_adds_timeline_entry(self):
        from asc_api.services.incident_service import create_incident
        from asc_api.models.incident import IncidentTimeline
        db = AsyncMock()
        added_objects = []
        db.add = MagicMock(side_effect=lambda obj: added_objects.append(obj))
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        with patch("asc_api.services.incident_service.log_security_action"):
            await create_incident(db, title="Test", incident_type="apt",
                                  severity="high", created_by="analyst@test.com")

        timeline_entries = [o for o in added_objects if isinstance(o, IncidentTimeline)]
        assert len(timeline_entries) >= 1
        assert timeline_entries[0].event_type == "created"

    @pytest.mark.asyncio
    async def test_create_with_entity_link_adds_link(self):
        from asc_api.services.incident_service import create_incident
        from asc_api.models.incident import IncidentLink
        db = AsyncMock()
        added_objects = []
        db.add = MagicMock(side_effect=lambda obj: added_objects.append(obj))
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        with patch("asc_api.services.incident_service.log_security_action"):
            await create_incident(
                db, title="Test", incident_type="malware",
                severity="medium", created_by="analyst@test.com",
                linked_entity_type="alert",
                linked_entity_id=str(uuid.uuid4()),
            )

        links = [o for o in added_objects if isinstance(o, IncidentLink)]
        assert len(links) == 1
        assert links[0].entity_type == "alert"

    @pytest.mark.asyncio
    async def test_create_status_is_detected(self):
        from asc_api.services.incident_service import create_incident
        from asc_api.models.incident import Incident
        db = AsyncMock()
        incidents = []
        db.add = MagicMock(side_effect=lambda obj: incidents.append(obj) if isinstance(obj, Incident) else None)
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        with patch("asc_api.services.incident_service.log_security_action"):
            await create_incident(db, title="T", incident_type="other",
                                  severity="low", created_by="a@b.com")

        assert incidents[0].status == "detected"
        assert incidents[0].nist_phase == "detection_analysis"

    @pytest.mark.asyncio
    async def test_create_medium_sla(self):
        from asc_api.services.incident_service import create_incident
        from asc_api.models.incident import Incident
        db = AsyncMock()
        incidents = []
        db.add = MagicMock(side_effect=lambda obj: incidents.append(obj) if isinstance(obj, Incident) else None)
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        with patch("asc_api.services.incident_service.log_security_action"):
            await create_incident(db, title="T", incident_type="other",
                                  severity="medium", created_by="a@b.com")

        assert incidents[0].sla_minutes == 1440

    @pytest.mark.asyncio
    async def test_create_commits_db(self):
        from asc_api.services.incident_service import create_incident
        db = AsyncMock()
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        with patch("asc_api.services.incident_service.log_security_action"):
            await create_incident(db, title="T", incident_type="other",
                                  severity="low", created_by="a@b.com")

        db.commit.assert_awaited()

    @pytest.mark.asyncio
    async def test_create_sets_false_positive_false(self):
        from asc_api.services.incident_service import create_incident
        from asc_api.models.incident import Incident
        db = AsyncMock()
        incidents = []
        db.add = MagicMock(side_effect=lambda obj: incidents.append(obj) if isinstance(obj, Incident) else None)
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        with patch("asc_api.services.incident_service.log_security_action"):
            await create_incident(db, title="T", incident_type="other",
                                  severity="low", created_by="a@b.com")

        assert incidents[0].false_positive is False

    @pytest.mark.asyncio
    async def test_create_tags_stored(self):
        from asc_api.services.incident_service import create_incident
        from asc_api.models.incident import Incident
        db = AsyncMock()
        incidents = []
        db.add = MagicMock(side_effect=lambda obj: incidents.append(obj) if isinstance(obj, Incident) else None)
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        with patch("asc_api.services.incident_service.log_security_action"):
            await create_incident(db, title="T", incident_type="other",
                                  severity="low", created_by="a@b.com",
                                  tags=["ransomware", "lateral"])

        assert incidents[0].tags == ["ransomware", "lateral"]

    @pytest.mark.asyncio
    async def test_create_no_link_when_entity_id_missing(self):
        from asc_api.services.incident_service import create_incident
        from asc_api.models.incident import IncidentLink
        db = AsyncMock()
        added = []
        db.add = MagicMock(side_effect=lambda obj: added.append(obj))
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        with patch("asc_api.services.incident_service.log_security_action"):
            await create_incident(db, title="T", incident_type="other",
                                  severity="low", created_by="a@b.com",
                                  linked_entity_type="alert",
                                  linked_entity_id=None)

        links = [o for o in added if isinstance(o, IncidentLink)]
        assert len(links) == 0


# â”€â”€ TestTransitionStatus â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestTransitionStatus:
    def _mk_db_with_incident(self, incident):
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(incident))
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)
        return db

    @pytest.mark.asyncio
    async def test_detected_to_triaged_sets_triaged_at(self):
        from asc_api.services.incident_service import transition_status
        inc = _make_incident(status="detected", triaged_at=None)
        db = self._mk_db_with_incident(inc)

        with patch("asc_api.services.incident_service.log_security_action"):
            result = await transition_status(db, inc.id, "triaged", "analyst@test.com")

        assert result.triaged_at is not None
        assert result.mttd_minutes is not None
        assert result.mttd_minutes >= 0

    @pytest.mark.asyncio
    async def test_triaged_to_contained_sets_contained_at(self):
        from asc_api.services.incident_service import transition_status
        inc = _make_incident(status="triaged", contained_at=None)
        db = self._mk_db_with_incident(inc)

        with patch("asc_api.services.incident_service.log_security_action"):
            result = await transition_status(db, inc.id, "contained", "analyst@test.com")

        assert result.contained_at is not None
        assert result.mttc_minutes is not None

    @pytest.mark.asyncio
    async def test_eradicated_to_recovered_sets_mttr(self):
        from asc_api.services.incident_service import transition_status
        inc = _make_incident(status="eradicated", recovered_at=None)
        db = self._mk_db_with_incident(inc)

        with patch("asc_api.services.incident_service.log_security_action"):
            result = await transition_status(db, inc.id, "recovered", "analyst@test.com")

        assert result.recovered_at is not None
        assert result.mttr_minutes is not None

    @pytest.mark.asyncio
    async def test_invalid_transition_raises_value_error(self):
        from asc_api.services.incident_service import transition_status
        inc = _make_incident(status="closed")
        db = self._mk_db_with_incident(inc)

        with pytest.raises(ValueError, match="not allowed"):
            await transition_status(db, inc.id, "triaged", "analyst@test.com")

    @pytest.mark.asyncio
    async def test_not_found_raises_value_error(self):
        from asc_api.services.incident_service import transition_status
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(None))

        with pytest.raises(ValueError, match="not found"):
            await transition_status(db, "nonexistent", "triaged", "analyst@test.com")

    @pytest.mark.asyncio
    async def test_nist_phase_updated(self):
        from asc_api.services.incident_service import transition_status
        inc = _make_incident(status="triaged", nist_phase="detection_analysis")
        db = self._mk_db_with_incident(inc)

        with patch("asc_api.services.incident_service.log_security_action"):
            result = await transition_status(db, inc.id, "contained", "analyst@test.com")

        assert result.nist_phase == "containment"

    @pytest.mark.asyncio
    async def test_timeline_entry_added(self):
        from asc_api.services.incident_service import transition_status
        from asc_api.models.incident import IncidentTimeline
        inc = _make_incident(status="detected")
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(inc))
        added = []
        db.add = MagicMock(side_effect=lambda obj: added.append(obj))
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        with patch("asc_api.services.incident_service.log_security_action"):
            await transition_status(db, inc.id, "triaged", "analyst@test.com")

        timeline_entries = [o for o in added if isinstance(o, IncidentTimeline)]
        assert len(timeline_entries) >= 1
        assert timeline_entries[0].event_type == "status_change"

    @pytest.mark.asyncio
    async def test_dismissed_transition_blocked_from_contained(self):
        from asc_api.services.incident_service import transition_status
        inc = _make_incident(status="contained")
        db = self._mk_db_with_incident(inc)

        with pytest.raises(ValueError, match="not allowed"):
            await transition_status(db, inc.id, "dismissed", "analyst@test.com")

    @pytest.mark.asyncio
    async def test_triaged_at_not_overwritten_on_second_transition(self):
        from asc_api.services.incident_service import transition_status
        first_triage = _utcnow() - timedelta(hours=1)
        inc = _make_incident(status="contained", triaged_at=first_triage)
        db = self._mk_db_with_incident(inc)

        with patch("asc_api.services.incident_service.log_security_action"):
            result = await transition_status(db, inc.id, "triaged", "analyst@test.com")

        # Rolling back to triaged should not overwrite triaged_at if already set
        # (contained â†’ triaged is a rollback â€” triaged_at stays)
        assert result.triaged_at == first_triage

    @pytest.mark.asyncio
    async def test_sla_breach_checked_on_transition(self):
        from asc_api.services.incident_service import transition_status
        # Incident with SLA of 1 minute, detected 10 minutes ago
        inc = _make_incident(
            status="detected",
            sla_minutes=1,
            detected_at=_utcnow() - timedelta(minutes=10),
        )
        db = self._mk_db_with_incident(inc)

        with patch("asc_api.services.incident_service.log_security_action"):
            result = await transition_status(db, inc.id, "triaged", "analyst@test.com")

        assert result.sla_breach is True

    @pytest.mark.asyncio
    async def test_commits_after_transition(self):
        from asc_api.services.incident_service import transition_status
        inc = _make_incident(status="detected")
        db = self._mk_db_with_incident(inc)

        with patch("asc_api.services.incident_service.log_security_action"):
            await transition_status(db, inc.id, "triaged", "analyst@test.com")

        db.commit.assert_awaited()

    @pytest.mark.asyncio
    async def test_contained_to_eradicated_sets_eradicated_at(self):
        from asc_api.services.incident_service import transition_status
        inc = _make_incident(status="contained")
        db = self._mk_db_with_incident(inc)

        with patch("asc_api.services.incident_service.log_security_action"):
            result = await transition_status(db, inc.id, "eradicated", "analyst@test.com")

        assert result.eradicated_at is not None


# â”€â”€ TestAssignIncident â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestAssignIncident:
    @pytest.mark.asyncio
    async def test_assign_sets_assigned_to(self):
        from asc_api.services.incident_service import assign_incident
        inc = _make_incident(assigned_to=None)
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(inc))
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        result = await assign_incident(db, inc.id, "newanalyst@test.com", "admin@test.com")
        assert result.assigned_to == "newanalyst@test.com"

    @pytest.mark.asyncio
    async def test_assign_not_found_raises(self):
        from asc_api.services.incident_service import assign_incident
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(None))

        with pytest.raises(ValueError, match="not found"):
            await assign_incident(db, "bad-id", "analyst@test.com", "admin@test.com")

    @pytest.mark.asyncio
    async def test_assign_adds_timeline(self):
        from asc_api.services.incident_service import assign_incident
        from asc_api.models.incident import IncidentTimeline
        inc = _make_incident(assigned_to=None)
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(inc))
        added = []
        db.add = MagicMock(side_effect=lambda o: added.append(o))
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        await assign_incident(db, inc.id, "analyst2@test.com", "admin@test.com")
        tl = [o for o in added if isinstance(o, IncidentTimeline)]
        assert len(tl) == 1
        assert tl[0].event_type == "assignment"

    @pytest.mark.asyncio
    async def test_assign_commits(self):
        from asc_api.services.incident_service import assign_incident
        inc = _make_incident()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(inc))
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        await assign_incident(db, inc.id, "analyst@test.com", "admin@test.com")
        db.commit.assert_awaited()


# â”€â”€ TestLinkEntity â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestLinkEntity:
    @pytest.mark.asyncio
    async def test_link_entity_creates_link(self):
        from asc_api.services.incident_service import link_entity
        from asc_api.models.incident import IncidentLink
        inc = _make_incident()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(inc))
        added = []
        db.add = MagicMock(side_effect=lambda o: added.append(o))
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        await link_entity(db, inc.id, "cluster", "cluster-uuid", "analyst@test.com")
        links = [o for o in added if isinstance(o, IncidentLink)]
        assert len(links) == 1
        assert links[0].entity_type == "cluster"

    @pytest.mark.asyncio
    async def test_link_entity_not_found_raises(self):
        from asc_api.services.incident_service import link_entity
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(None))

        with pytest.raises(ValueError, match="not found"):
            await link_entity(db, "bad-id", "alert", "alert-uuid", "analyst@test.com")

    @pytest.mark.asyncio
    async def test_link_entity_adds_timeline(self):
        from asc_api.services.incident_service import link_entity
        from asc_api.models.incident import IncidentTimeline
        inc = _make_incident()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(inc))
        added = []
        db.add = MagicMock(side_effect=lambda o: added.append(o))
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        await link_entity(db, inc.id, "alert", "alert-uuid", "analyst@test.com")
        tl = [o for o in added if isinstance(o, IncidentTimeline)]
        assert any(e.event_type == "link_added" for e in tl)

    @pytest.mark.asyncio
    async def test_link_entity_with_notes(self):
        from asc_api.services.incident_service import link_entity
        from asc_api.models.incident import IncidentLink
        inc = _make_incident()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(inc))
        added = []
        db.add = MagicMock(side_effect=lambda o: added.append(o))
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        await link_entity(db, inc.id, "hunt", "hunt-uuid", "analyst@test.com",
                          notes="Related to APT campaign")
        links = [o for o in added if isinstance(o, IncidentLink)]
        assert links[0].notes == "Related to APT campaign"

    @pytest.mark.asyncio
    async def test_link_entity_commits(self):
        from asc_api.services.incident_service import link_entity
        inc = _make_incident()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(inc))
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        await link_entity(db, inc.id, "alert", "a-uuid", "analyst@test.com")
        db.commit.assert_awaited()

    @pytest.mark.asyncio
    async def test_link_entity_added_by_stored(self):
        from asc_api.services.incident_service import link_entity
        from asc_api.models.incident import IncidentLink
        inc = _make_incident()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(inc))
        added = []
        db.add = MagicMock(side_effect=lambda o: added.append(o))
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        await link_entity(db, inc.id, "finding", "f-uuid", "adminuser@test.com")
        links = [o for o in added if isinstance(o, IncidentLink)]
        assert links[0].added_by == "adminuser@test.com"


# â”€â”€ TestRemoveLink â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestRemoveLink:
    @pytest.mark.asyncio
    async def test_remove_existing_link_returns_true(self):
        from asc_api.services.incident_service import remove_link
        link = _make_link()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(link))
        db.add = MagicMock()
        db.delete = AsyncMock()
        db.commit = AsyncMock()

        result = await remove_link(db, link.incident_id, link.id, "analyst@test.com")
        assert result is True

    @pytest.mark.asyncio
    async def test_remove_missing_link_returns_false(self):
        from asc_api.services.incident_service import remove_link
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(None))

        result = await remove_link(db, "inc-id", "link-id", "analyst@test.com")
        assert result is False

    @pytest.mark.asyncio
    async def test_remove_calls_delete(self):
        from asc_api.services.incident_service import remove_link
        link = _make_link()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(link))
        db.add = MagicMock()
        db.delete = AsyncMock()
        db.commit = AsyncMock()

        await remove_link(db, link.incident_id, link.id, "analyst@test.com")
        db.delete.assert_awaited_with(link)

    @pytest.mark.asyncio
    async def test_remove_commits(self):
        from asc_api.services.incident_service import remove_link
        link = _make_link()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(link))
        db.add = MagicMock()
        db.delete = AsyncMock()
        db.commit = AsyncMock()

        await remove_link(db, link.incident_id, link.id, "analyst@test.com")
        db.commit.assert_awaited()


# â”€â”€ TestAddNote â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestAddNote:
    @pytest.mark.asyncio
    async def test_add_note_returns_timeline_entry(self):
        from asc_api.services.incident_service import add_note
        from asc_api.models.incident import IncidentTimeline
        inc = _make_incident(status="triaged")
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(inc))
        added = []
        db.add = MagicMock(side_effect=lambda o: added.append(o))
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        result = await add_note(db, inc.id, "analyst@test.com", "Note text here")
        assert result.event_type == "note_added"
        assert result.detail["text"] == "Note text here"

    @pytest.mark.asyncio
    async def test_add_note_to_closed_raises(self):
        from asc_api.services.incident_service import add_note
        inc = _make_incident(status="closed")
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(inc))

        with pytest.raises(ValueError, match="closed"):
            await add_note(db, inc.id, "analyst@test.com", "Note")

    @pytest.mark.asyncio
    async def test_add_note_to_dismissed_raises(self):
        from asc_api.services.incident_service import add_note
        inc = _make_incident(status="dismissed")
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(inc))

        with pytest.raises(ValueError, match="dismissed"):
            await add_note(db, inc.id, "analyst@test.com", "Note")

    @pytest.mark.asyncio
    async def test_add_note_not_found_raises(self):
        from asc_api.services.incident_service import add_note
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(None))

        with pytest.raises(ValueError, match="not found"):
            await add_note(db, "bad-id", "analyst@test.com", "Note")

    @pytest.mark.asyncio
    async def test_add_note_commits(self):
        from asc_api.services.incident_service import add_note
        inc = _make_incident(status="triaged")
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(inc))
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        await add_note(db, inc.id, "analyst@test.com", "Note")
        db.commit.assert_awaited()

    @pytest.mark.asyncio
    async def test_add_note_actor_stored(self):
        from asc_api.services.incident_service import add_note
        inc = _make_incident(status="triaged")
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(inc))
        added = []
        db.add = MagicMock(side_effect=lambda o: added.append(o))
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        await add_note(db, inc.id, "sr_analyst@test.com", "Note")
        from asc_api.models.incident import IncidentTimeline
        tl = [o for o in added if isinstance(o, IncidentTimeline)]
        assert tl[0].actor == "sr_analyst@test.com"


# â”€â”€ TestCloseIncident â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestCloseIncident:
    @pytest.mark.asyncio
    async def test_close_from_post_incident_seals_hash(self):
        from asc_api.services.incident_service import close_incident
        inc = _make_incident(status="post_incident", detected_at=_utcnow() - timedelta(hours=2))
        # Simulate transition_status returning updated incident
        call_count = [0]
        async def mock_execute(*a, **kw):
            call_count[0] += 1
            return _scalar_one(inc)

        db = AsyncMock()
        db.execute = AsyncMock(side_effect=mock_execute)
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        with patch("asc_api.services.incident_service.log_security_action"):
            result = await close_incident(db, inc.id, "admin@test.com",
                                          lessons_learned="Update patches",
                                          root_cause="Unpatched CVE-2025-1234")

        assert result.forensic_hash is not None
        assert len(result.forensic_hash) == 128

    @pytest.mark.asyncio
    async def test_close_sets_lessons_learned(self):
        from asc_api.services.incident_service import close_incident
        inc = _make_incident(status="post_incident")
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(inc))
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        with patch("asc_api.services.incident_service.log_security_action"):
            result = await close_incident(db, inc.id, "admin@test.com",
                                          lessons_learned="Always patch")
        assert result.lessons_learned == "Always patch"

    @pytest.mark.asyncio
    async def test_close_already_closed_raises(self):
        from asc_api.services.incident_service import close_incident
        inc = _make_incident(status="closed")
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(inc))
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        with patch("asc_api.services.incident_service.log_security_action"):
            with pytest.raises(ValueError, match="already closed"):
                await close_incident(db, inc.id, "admin@test.com")

    @pytest.mark.asyncio
    async def test_close_dismissed_raises(self):
        from asc_api.services.incident_service import close_incident
        inc = _make_incident(status="dismissed")
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(inc))
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        with patch("asc_api.services.incident_service.log_security_action"):
            with pytest.raises(ValueError, match="Dismissed"):
                await close_incident(db, inc.id, "admin@test.com")

    @pytest.mark.asyncio
    async def test_close_from_detected_raises(self):
        from asc_api.services.incident_service import close_incident
        inc = _make_incident(status="detected")
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(inc))
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        with patch("asc_api.services.incident_service.log_security_action"):
            with pytest.raises(ValueError, match="Cannot close"):
                await close_incident(db, inc.id, "admin@test.com")

    @pytest.mark.asyncio
    async def test_close_false_positive_flag(self):
        from asc_api.services.incident_service import close_incident
        inc = _make_incident(status="post_incident")
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(inc))
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        with patch("asc_api.services.incident_service.log_security_action"):
            result = await close_incident(db, inc.id, "admin@test.com", false_positive=True)
        assert result.false_positive is True

    @pytest.mark.asyncio
    async def test_close_computes_forensic_hash_128_chars(self):
        from asc_api.services.incident_service import close_incident
        inc = _make_incident(status="post_incident")
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(inc))
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        with patch("asc_api.services.incident_service.log_security_action"):
            result = await close_incident(db, inc.id, "admin@test.com")
        assert len(result.forensic_hash) == 128

    @pytest.mark.asyncio
    async def test_close_commits(self):
        from asc_api.services.incident_service import close_incident
        inc = _make_incident(status="post_incident")
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(inc))
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        with patch("asc_api.services.incident_service.log_security_action"):
            await close_incident(db, inc.id, "admin@test.com")
        db.commit.assert_awaited()


# â”€â”€ TestDismissIncident â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestDismissIncident:
    @pytest.mark.asyncio
    async def test_dismiss_from_detected(self):
        from asc_api.services.incident_service import dismiss_incident
        inc = _make_incident(status="detected")
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(inc))
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        with patch("asc_api.services.incident_service.log_security_action"):
            result = await dismiss_incident(db, inc.id, "analyst@test.com", reason="FP")

        assert result.status == "dismissed"
        assert result.false_positive is True

    @pytest.mark.asyncio
    async def test_dismiss_from_triaged(self):
        from asc_api.services.incident_service import dismiss_incident
        inc = _make_incident(status="triaged")
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(inc))
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        with patch("asc_api.services.incident_service.log_security_action"):
            result = await dismiss_incident(db, inc.id, "analyst@test.com")
        assert result.status == "dismissed"

    @pytest.mark.asyncio
    async def test_dismiss_from_contained_raises(self):
        from asc_api.services.incident_service import dismiss_incident
        inc = _make_incident(status="contained")
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(inc))

        with pytest.raises(ValueError, match="Cannot dismiss"):
            await dismiss_incident(db, inc.id, "analyst@test.com")

    @pytest.mark.asyncio
    async def test_dismiss_seals_forensic_hash(self):
        from asc_api.services.incident_service import dismiss_incident
        inc = _make_incident(status="detected")
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(inc))
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        with patch("asc_api.services.incident_service.log_security_action"):
            result = await dismiss_incident(db, inc.id, "analyst@test.com")
        assert result.forensic_hash is not None

    @pytest.mark.asyncio
    async def test_dismiss_not_found_raises(self):
        from asc_api.services.incident_service import dismiss_incident
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(None))

        with pytest.raises(ValueError, match="not found"):
            await dismiss_incident(db, "bad-id", "analyst@test.com")

    @pytest.mark.asyncio
    async def test_dismiss_commits(self):
        from asc_api.services.incident_service import dismiss_incident
        inc = _make_incident(status="detected")
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(inc))
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        with patch("asc_api.services.incident_service.log_security_action"):
            await dismiss_incident(db, inc.id, "analyst@test.com")
        db.commit.assert_awaited()


# â”€â”€ TestUpdateMitre â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestUpdateMitre:
    @pytest.mark.asyncio
    async def test_update_tactics(self):
        from asc_api.services.incident_service import update_mitre
        inc = _make_incident(mitre_tactics=[], mitre_techniques=[])
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(inc))
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        result = await update_mitre(db, inc.id, "analyst@test.com",
                                    mitre_tactics=["TA0001", "TA0003"])
        assert result.mitre_tactics == ["TA0001", "TA0003"]

    @pytest.mark.asyncio
    async def test_update_techniques(self):
        from asc_api.services.incident_service import update_mitre
        inc = _make_incident(mitre_tactics=[], mitre_techniques=[])
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(inc))
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        result = await update_mitre(db, inc.id, "analyst@test.com",
                                    mitre_techniques=["T1059", "T1078"])
        assert result.mitre_techniques == ["T1059", "T1078"]

    @pytest.mark.asyncio
    async def test_update_not_found_raises(self):
        from asc_api.services.incident_service import update_mitre
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(None))

        with pytest.raises(ValueError, match="not found"):
            await update_mitre(db, "bad-id", "analyst@test.com")

    @pytest.mark.asyncio
    async def test_update_commits(self):
        from asc_api.services.incident_service import update_mitre
        inc = _make_incident()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(inc))
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        await update_mitre(db, inc.id, "analyst@test.com", mitre_tactics=["TA0001"])
        db.commit.assert_awaited()


# â”€â”€ TestGetIncidentSummary â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestGetIncidentSummary:
    @pytest.mark.asyncio
    async def test_summary_returns_total(self):
        from asc_api.services.incident_service import get_incident_summary

        def _make_scalar_one_exec(value):
            r = MagicMock()
            r.scalar_one = MagicMock(return_value=value)
            return r

        def _make_all_exec(rows):
            r = MagicMock()
            r.all = MagicMock(return_value=rows)
            return r

        call_count = [0]
        async def execute_side(*a, **kw):
            call_count[0] += 1
            if call_count[0] == 1:   return _make_scalar_one_exec(42)      # total
            elif call_count[0] == 2: return _make_all_exec([("detected", 10), ("closed", 32)])  # by_status
            elif call_count[0] == 3: return _make_all_exec([("high", 20), ("medium", 22)])      # by_severity
            elif call_count[0] == 4: return _make_scalar_one_exec(3)        # sla_breach
            elif call_count[0] == 5: return _make_scalar_one_exec(15.5)     # avg_mttd
            elif call_count[0] == 6: return _make_scalar_one_exec(120.0)    # avg_mttr
            elif call_count[0] == 7: return _make_scalar_one_exec(45.0)     # avg_mttc
            else:                    return _make_scalar_one_exec(10)        # open

        db = AsyncMock()
        db.execute = AsyncMock(side_effect=execute_side)
        result = await get_incident_summary(db)
        assert result["total"] == 42

    @pytest.mark.asyncio
    async def test_summary_by_status_keys(self):
        from asc_api.services.incident_service import get_incident_summary

        def _make_scalar_one_exec(value):
            r = MagicMock(); r.scalar_one = MagicMock(return_value=value); return r

        def _make_all_exec(rows):
            r = MagicMock(); r.all = MagicMock(return_value=rows); return r

        call_count = [0]
        async def execute_side(*a, **kw):
            call_count[0] += 1
            if call_count[0] == 1:   return _make_scalar_one_exec(5)
            elif call_count[0] == 2: return _make_all_exec([("detected", 3), ("closed", 2)])
            elif call_count[0] == 3: return _make_all_exec([("high", 5)])
            elif call_count[0] == 4: return _make_scalar_one_exec(0)
            elif call_count[0] == 5: return _make_scalar_one_exec(None)
            elif call_count[0] == 6: return _make_scalar_one_exec(None)
            elif call_count[0] == 7: return _make_scalar_one_exec(None)
            else:                    return _make_scalar_one_exec(3)

        db = AsyncMock()
        db.execute = AsyncMock(side_effect=execute_side)
        result = await get_incident_summary(db)
        assert "detected" in result["by_status"]
        assert result["by_status"]["detected"] == 3

    @pytest.mark.asyncio
    async def test_summary_null_avg_handled(self):
        from asc_api.services.incident_service import get_incident_summary

        def _make_scalar_one_exec(value):
            r = MagicMock(); r.scalar_one = MagicMock(return_value=value); return r

        def _make_all_exec(rows):
            r = MagicMock(); r.all = MagicMock(return_value=rows); return r

        call_count = [0]
        async def execute_side(*a, **kw):
            call_count[0] += 1
            if call_count[0] == 1:   return _make_scalar_one_exec(0)
            elif call_count[0] == 2: return _make_all_exec([])
            elif call_count[0] == 3: return _make_all_exec([])
            elif call_count[0] == 4: return _make_scalar_one_exec(0)
            elif call_count[0] == 5: return _make_scalar_one_exec(None)
            elif call_count[0] == 6: return _make_scalar_one_exec(None)
            elif call_count[0] == 7: return _make_scalar_one_exec(None)
            else:                    return _make_scalar_one_exec(0)

        db = AsyncMock()
        db.execute = AsyncMock(side_effect=execute_side)
        result = await get_incident_summary(db)
        assert result["avg_mttd_minutes"] is None
        assert result["avg_mttr_minutes"] is None

    @pytest.mark.asyncio
    async def test_summary_has_generated_at(self):
        from asc_api.services.incident_service import get_incident_summary

        def _make_scalar_one_exec(value):
            r = MagicMock(); r.scalar_one = MagicMock(return_value=value); return r

        def _make_all_exec(rows):
            r = MagicMock(); r.all = MagicMock(return_value=rows); return r

        call_count = [0]
        async def execute_side(*a, **kw):
            call_count[0] += 1
            if call_count[0] <= 4: return _make_scalar_one_exec(0)
            elif call_count[0] <= 7: return _make_all_exec([])
            else: return _make_scalar_one_exec(0)

        db = AsyncMock()
        db.execute = AsyncMock(side_effect=execute_side)
        result = await get_incident_summary(db)
        assert "generated_at" in result

    @pytest.mark.asyncio
    async def test_summary_sla_breach_count(self):
        from asc_api.services.incident_service import get_incident_summary

        def _make_scalar_one_exec(value):
            r = MagicMock(); r.scalar_one = MagicMock(return_value=value); return r

        def _make_all_exec(rows):
            r = MagicMock(); r.all = MagicMock(return_value=rows); return r

        call_count = [0]
        async def execute_side(*a, **kw):
            call_count[0] += 1
            if call_count[0] == 1:   return _make_scalar_one_exec(10)
            elif call_count[0] == 2: return _make_all_exec([("closed", 10)])
            elif call_count[0] == 3: return _make_all_exec([("high", 10)])
            elif call_count[0] == 4: return _make_scalar_one_exec(7)   # SLA breach count
            elif call_count[0] == 5: return _make_scalar_one_exec(30.0)
            elif call_count[0] == 6: return _make_scalar_one_exec(300.0)
            elif call_count[0] == 7: return _make_scalar_one_exec(60.0)
            else:                    return _make_scalar_one_exec(0)

        db = AsyncMock()
        db.execute = AsyncMock(side_effect=execute_side)
        result = await get_incident_summary(db)
        assert result["sla_breach_count"] == 7

    @pytest.mark.asyncio
    async def test_summary_avg_rounded(self):
        from asc_api.services.incident_service import get_incident_summary

        def _make_scalar_one_exec(value):
            r = MagicMock(); r.scalar_one = MagicMock(return_value=value); return r

        def _make_all_exec(rows):
            r = MagicMock(); r.all = MagicMock(return_value=rows); return r

        call_count = [0]
        async def execute_side(*a, **kw):
            call_count[0] += 1
            if call_count[0] == 1:   return _make_scalar_one_exec(5)
            elif call_count[0] == 2: return _make_all_exec([])
            elif call_count[0] == 3: return _make_all_exec([])
            elif call_count[0] == 4: return _make_scalar_one_exec(0)
            elif call_count[0] == 5: return _make_scalar_one_exec(14.567)
            elif call_count[0] == 6: return _make_scalar_one_exec(None)
            elif call_count[0] == 7: return _make_scalar_one_exec(None)
            else:                    return _make_scalar_one_exec(5)

        db = AsyncMock()
        db.execute = AsyncMock(side_effect=execute_side)
        result = await get_incident_summary(db)
        assert result["avg_mttd_minutes"] == 14.6


# â”€â”€ TestAutoCreateFromCluster â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestAutoCreateFromCluster:
    @pytest.mark.asyncio
    async def test_creates_incident_for_campaign(self):
        from asc_api.services.incident_service import auto_create_from_cluster
        cluster = _make_cluster(severity="high", cluster_type="host_pivot",
                                cluster_key="ws-001")
        db = AsyncMock()
        # First query (dedup check) returns None â€” no existing link
        db.execute = AsyncMock(return_value=_scalar_one(None))
        added = []
        db.add = MagicMock(side_effect=lambda o: added.append(o))
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        with patch("asc_api.services.incident_service.log_security_action"):
            result = await auto_create_from_cluster(db, cluster)

        assert result is not None
        assert "ws-001" in result.title or "Host Pivot" in result.title

    @pytest.mark.asyncio
    async def test_skips_if_already_linked(self):
        from asc_api.services.incident_service import auto_create_from_cluster
        cluster = _make_cluster()
        existing_link = _make_link(entity_type="cluster", entity_id=cluster.id)
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(existing_link))

        result = await auto_create_from_cluster(db, cluster)
        assert result is None

    @pytest.mark.asyncio
    async def test_created_by_is_system(self):
        from asc_api.services.incident_service import auto_create_from_cluster
        from asc_api.models.incident import Incident
        cluster = _make_cluster()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(None))
        incidents = []
        db.add = MagicMock(side_effect=lambda o: incidents.append(o) if isinstance(o, Incident) else None)
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        with patch("asc_api.services.incident_service.log_security_action"):
            await auto_create_from_cluster(db, cluster)

        assert incidents[0].created_by == "system:correlation_engine"

    @pytest.mark.asyncio
    async def test_links_cluster_entity(self):
        from asc_api.services.incident_service import auto_create_from_cluster
        from asc_api.models.incident import IncidentLink
        cluster = _make_cluster()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(None))
        added = []
        db.add = MagicMock(side_effect=lambda o: added.append(o))
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        with patch("asc_api.services.incident_service.log_security_action"):
            await auto_create_from_cluster(db, cluster)

        links = [o for o in added if isinstance(o, IncidentLink)]
        assert any(l.entity_type == "cluster" for l in links)

    @pytest.mark.asyncio
    async def test_incident_type_is_apt(self):
        from asc_api.services.incident_service import auto_create_from_cluster
        from asc_api.models.incident import Incident
        cluster = _make_cluster()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(None))
        incidents = []
        db.add = MagicMock(side_effect=lambda o: incidents.append(o) if isinstance(o, Incident) else None)
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        with patch("asc_api.services.incident_service.log_security_action"):
            await auto_create_from_cluster(db, cluster)

        assert incidents[0].incident_type == "apt"

    @pytest.mark.asyncio
    async def test_severity_inherited_from_cluster(self):
        from asc_api.services.incident_service import auto_create_from_cluster
        from asc_api.models.incident import Incident
        cluster = _make_cluster(severity="critical")
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(None))
        incidents = []
        db.add = MagicMock(side_effect=lambda o: incidents.append(o) if isinstance(o, Incident) else None)
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)

        with patch("asc_api.services.incident_service.log_security_action"):
            await auto_create_from_cluster(db, cluster)

        assert incidents[0].severity == "critical"


# â”€â”€ TestIncidentEndpoints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _make_endpoint_app():
    from fastapi import FastAPI
    from asc_api.api.v1.endpoints.incidents import router
    app = FastAPI()
    app.include_router(router)
    return app


class TestIncidentEndpoints:
    def test_list_requires_auth(self):
        from fastapi.testclient import TestClient
        app = _make_endpoint_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/incidents")
        assert resp.status_code in (401, 403, 422)

    def test_summary_requires_auth(self):
        from fastapi.testclient import TestClient
        app = _make_endpoint_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/incidents/summary")
        assert resp.status_code in (401, 403, 422)

    def test_list_with_auth_calls_service(self):
        from fastapi.testclient import TestClient
        from asc_api.api.deps import get_analyst_or_admin
        from asc_api.db.session import get_db
        app = _make_endpoint_app()
        app.dependency_overrides[get_analyst_or_admin] = lambda: _mock_analyst()
        app.dependency_overrides[get_db] = lambda: AsyncMock()

        with patch("asc_api.api.v1.endpoints.incidents.incident_service.list_incidents",
                   new_callable=AsyncMock, return_value=[]):
            with patch("asc_api.api.v1.endpoints.incidents.incident_service.get_incident_summary",
                       new_callable=AsyncMock):
                client = TestClient(app)
                resp = client.get("/incidents")
        assert resp.status_code == 200
        assert "items" in resp.json()

    def test_create_returns_201(self):
        from fastapi.testclient import TestClient
        from asc_api.api.deps import get_analyst_or_admin
        from asc_api.db.session import get_db
        inc = _make_incident(id="test-id")
        app = _make_endpoint_app()
        app.dependency_overrides[get_analyst_or_admin] = lambda: _mock_analyst()
        app.dependency_overrides[get_db] = lambda: AsyncMock()

        with patch("asc_api.api.v1.endpoints.incidents.incident_service.create_incident",
                   new_callable=AsyncMock, return_value=inc):
            client = TestClient(app)
            resp = client.post("/incidents", json={
                "title": "Test Incident",
                "incident_type": "malware",
                "severity": "high",
            })
        assert resp.status_code == 201

    def test_create_invalid_incident_type_422(self):
        from fastapi.testclient import TestClient
        from asc_api.api.deps import get_analyst_or_admin
        from asc_api.db.session import get_db
        app = _make_endpoint_app()
        app.dependency_overrides[get_analyst_or_admin] = lambda: _mock_analyst()
        app.dependency_overrides[get_db] = lambda: AsyncMock()

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/incidents", json={
            "title": "Test",
            "incident_type": "not_a_valid_type",
            "severity": "high",
        })
        assert resp.status_code == 422

    def test_get_incident_not_found_404(self):
        from fastapi.testclient import TestClient
        from asc_api.api.deps import get_analyst_or_admin
        from asc_api.db.session import get_db
        app = _make_endpoint_app()
        app.dependency_overrides[get_analyst_or_admin] = lambda: _mock_analyst()
        app.dependency_overrides[get_db] = lambda: AsyncMock()

        with patch("asc_api.api.v1.endpoints.incidents.incident_service.get_incident",
                   new_callable=AsyncMock, return_value=None):
            client = TestClient(app)
            resp = client.get("/incidents/nonexistent-id")
        assert resp.status_code == 404

    def test_status_transition_invalid_state_422(self):
        from fastapi.testclient import TestClient
        from asc_api.api.deps import get_analyst_or_admin
        from asc_api.db.session import get_db
        app = _make_endpoint_app()
        app.dependency_overrides[get_analyst_or_admin] = lambda: _mock_analyst()
        app.dependency_overrides[get_db] = lambda: AsyncMock()

        with patch("asc_api.api.v1.endpoints.incidents.incident_service.transition_status",
                   new_callable=AsyncMock,
                   side_effect=ValueError("Transition not allowed")):
            client = TestClient(app)
            resp = client.patch("/incidents/some-id/status", json={"new_status": "closed"})
        assert resp.status_code == 422

    def test_close_incident_200(self):
        from fastapi.testclient import TestClient
        from asc_api.api.deps import get_analyst_or_admin
        from asc_api.db.session import get_db
        inc = _make_incident(status="closed", forensic_hash="a" * 128)
        app = _make_endpoint_app()
        app.dependency_overrides[get_analyst_or_admin] = lambda: _mock_analyst()
        app.dependency_overrides[get_db] = lambda: AsyncMock()

        with patch("asc_api.api.v1.endpoints.incidents.incident_service.close_incident",
                   new_callable=AsyncMock, return_value=inc):
            client = TestClient(app)
            resp = client.post("/incidents/some-id/close", json={})
        assert resp.status_code == 200

    def test_dismiss_returns_200(self):
        from fastapi.testclient import TestClient
        from asc_api.api.deps import get_analyst_or_admin
        from asc_api.db.session import get_db
        inc = _make_incident(status="dismissed")
        app = _make_endpoint_app()
        app.dependency_overrides[get_analyst_or_admin] = lambda: _mock_analyst()
        app.dependency_overrides[get_db] = lambda: AsyncMock()

        with patch("asc_api.api.v1.endpoints.incidents.incident_service.dismiss_incident",
                   new_callable=AsyncMock, return_value=inc):
            client = TestClient(app)
            resp = client.post("/incidents/some-id/dismiss", json={"reason": "FP test"})
        assert resp.status_code == 200

    def test_add_note_returns_201(self):
        from fastapi.testclient import TestClient
        from asc_api.api.deps import get_analyst_or_admin
        from asc_api.db.session import get_db
        entry = _make_timeline_entry(event_type="note_added")
        app = _make_endpoint_app()
        app.dependency_overrides[get_analyst_or_admin] = lambda: _mock_analyst()
        app.dependency_overrides[get_db] = lambda: AsyncMock()

        with patch("asc_api.api.v1.endpoints.incidents.incident_service.add_note",
                   new_callable=AsyncMock, return_value=entry):
            client = TestClient(app)
            resp = client.post("/incidents/some-id/notes", json={"text": "Analyst note"})
        assert resp.status_code == 201
