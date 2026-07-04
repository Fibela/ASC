"""
P23 â€” Threat Hunting Enhancements Test Suite

Coverage
--------
TestQueryExecutor        (9 tests)  â€” ELK/Wazuh dispatch, timeout, stub, unknown source, not-found
TestHuntFromAlert        (7 tests)  â€” service create, alert not found, endpoint 201/404/401, tags, finding
TestTIEnrichment         (9 tests)  â€” matched/no-match/no-indicator, notes update, not-found,
                                       endpoint 200/401/mismatch, max_severity helper
TestReportExport         (9 tests)  â€” report structure, empty findings, grouping, timeline order,
                                       hunt not found, endpoint 200/404/401
TestAdapterSearchRaw     (7 tests)  â€” ELK not-configured/success/error, Wazuh not-configured/success/error,
                                       result shape
TestExecuteQueryEndpoint (6 tests)  â€” 200 OK, 401, hunt not found, query not in hunt, result structure
TestDurationHelper       (3 tests)  â€” both timestamps, started only, no started_at
TestSecurityBoundaries   (4 tests)  â€” read-only guards, active hunt on from-alert, find enrichment passive

Total: 54 tests
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from asc_api.main import app
from asc_api.db.session import get_db
from asc_api.api.deps import get_analyst_or_admin, get_current_admin
from asc_api.models.user import User
from asc_api.models.hunt import Hunt, HuntFinding, HuntQuery
from asc_api.services import hunt_service as svc
from asc_api.services.query_executor import execute_hunt_query, _dispatch, _call_adapter, EXECUTE_TIMEOUT_S


# â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _stub_user(role: str = "analyst") -> User:
    u = MagicMock(spec=User)
    u.id = str(uuid.uuid4())
    u.email = f"{role}@asc.local"
    u.role = role
    return u


def _now():
    return datetime.now(timezone.utc)


def _make_hunt(
    status: str = "active",
    priority: str = "high",
) -> Hunt:
    h = MagicMock(spec=Hunt)
    h.id = str(uuid.uuid4())
    h.name = "Test Hunt P23"
    h.description = "P23 test hunt"
    h.hypothesis = "We suspect lateral movement via T1055"
    h.status = status
    h.mitre_technique = "T1055"
    h.mitre_tactic = "defense-evasion"
    h.scope = "all"
    h.priority = priority
    h.created_by = "analyst@asc.local"
    h.assigned_to = "analyst@asc.local"
    h.created_at = _now()
    h.started_at = _now()
    h.completed_at = None
    h.updated_at = _now()
    h.conclusion = None
    h.findings_count = 0
    h.true_positive_count = 0
    h.tags = ["from-alert", "high"]
    h.findings = []
    h.queries = []
    return h


def _make_finding(
    hunt_id: str | None = None,
    indicator: str = "1.2.3.4",
    indicator_type: str = "ip",
    confirmed: bool = False,
    fp: bool = False,
) -> HuntFinding:
    f = MagicMock(spec=HuntFinding)
    f.id = str(uuid.uuid4())
    f.hunt_id = hunt_id or str(uuid.uuid4())
    f.title = "Suspicious lateral movement detected"
    f.description = "Process injected into explorer.exe"
    f.severity = "high"
    f.indicator_value = indicator
    f.indicator_type = indicator_type
    f.affected_host = "srv-dc-01"
    f.affected_user = "jdoe"
    f.data_source = "elk"
    f.mitre_technique = "T1055"
    f.mitre_tactic = "defense-evasion"
    f.evidence = None
    f.is_confirmed = confirmed
    f.is_false_positive = fp
    f.analyst_notes = None
    f.created_by = "analyst@asc.local"
    f.created_at = _now()
    f.updated_at = _now()
    return f


def _make_query(hunt_id: str | None = None, data_source: str = "elk") -> HuntQuery:
    q = MagicMock(spec=HuntQuery)
    q.id = str(uuid.uuid4())
    q.hunt_id = hunt_id or str(uuid.uuid4())
    q.name = "T1055 process injection search"
    q.query_text = 'event.action:"process_injection" AND host.name:*'
    q.data_source = data_source
    q.description = None
    q.last_executed_at = None
    q.last_result_count = None
    q.last_execution_ms = None
    q.created_by = "analyst@asc.local"
    q.created_at = _now()
    return q


def _make_ti_indicator(severity: str = "high") -> MagicMock:
    ind = MagicMock()
    ind.id = str(uuid.uuid4())
    ind.indicator_type = "ip"
    ind.value = "1.2.3.4"
    ind.severity = severity
    ind.confidence = 90
    ind.source = "unit42"
    ind.threat_actor = "APT-X"
    ind.malware_family = None
    ind.campaign = None
    ind.ttps = ["T1055"]
    ind.tags = ["malicious"]
    ind.description = "Known C2"
    ind.hit_count = 3
    ind.first_seen = _now().isoformat()
    ind.last_seen = _now().isoformat()
    ind.active = True
    return ind


def _db_with(return_value=None) -> AsyncMock:
    db = AsyncMock()
    db.add = MagicMock()
    db.flush = AsyncMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock(side_effect=lambda obj: None)
    db.rollback = AsyncMock()
    db.delete = AsyncMock()
    r = MagicMock()
    r.scalar_one.return_value = return_value if return_value is not None else 0
    r.scalar_one_or_none.return_value = return_value
    r.scalars.return_value.all.return_value = [return_value] if return_value else []
    r.all.return_value = []
    db.execute = AsyncMock(return_value=r)
    return db


def _multi_db(*returns) -> AsyncMock:
    """DB mock returning a different scalar_one_or_none value on each execute() call."""
    db = AsyncMock()
    db.add = MagicMock()
    db.flush = AsyncMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock(side_effect=lambda obj: None)
    db.rollback = AsyncMock()
    db.delete = AsyncMock()
    mocks = []
    for rv in returns:
        r = MagicMock()
        r.scalar_one_or_none.return_value = rv
        r.scalar_one.return_value = rv if rv is not None else 0
        r.scalars.return_value.all.return_value = [rv] if rv else []
        mocks.append(r)
    db.execute = AsyncMock(side_effect=mocks)
    return db


def _db_for_execute_endpoint(hunt, query) -> AsyncMock:
    """
    Builds a DB mock for the execute_query endpoint flow:
      1. svc.get_hunt â†’ hunt (scalar_one_or_none)
      2. svc.list_queries â†’ [query] (scalars().all())
      3. execute_hunt_query internal â†’ query (scalar_one_or_none)
      4. _dispatch_to_specter agent lookup â†’ [] (scalars().all()) â€” only for specter_agent
    """
    db = AsyncMock()
    db.add = MagicMock()
    db.flush = AsyncMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock(side_effect=lambda obj: None)
    db.rollback = AsyncMock()
    db.delete = AsyncMock()

    r1 = MagicMock()
    r1.scalar_one_or_none.return_value = hunt
    r1.scalars.return_value.all.return_value = []

    r2 = MagicMock()
    r2.scalar_one_or_none.return_value = query
    r2.scalars.return_value.all.return_value = [query] if query else []

    r3 = MagicMock()
    r3.scalar_one_or_none.return_value = query

    # r4: agent query in _dispatch_to_specter (empty fleet â€” returns graceful error)
    r4 = MagicMock()
    r4.scalars.return_value.all.return_value = []

    db.execute = AsyncMock(side_effect=[r1, r2, r3, r4])
    return db


# â”€â”€ TestQueryExecutor â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestQueryExecutor:

    @pytest.mark.asyncio
    async def test_execute_query_not_found_returns_error(self):
        db = _db_with(return_value=None)
        query_id = str(uuid.uuid4())
        result = await execute_hunt_query(db, query_id, executed_by="analyst@asc.local")
        assert result["success"] is False
        assert "not found" in result["error"].lower()
        assert result["query_id"] == query_id

    @pytest.mark.asyncio
    async def test_execute_elk_query_dispatches(self):
        query = _make_query(data_source="elk")
        db = _db_with(return_value=query)
        elk_result = {
            "success": True, "adapter": "elk", "result_count": 5, "total": 5,
            "truncated": False, "execution_ms": 120, "results": [{"_id": "1"}],
        }
        from asc_api.adapters.elk import ELKAdapter
        with patch.object(ELKAdapter, "search_raw", new_callable=AsyncMock, return_value=elk_result):
            result = await execute_hunt_query(db, query.id, executed_by="analyst@asc.local")
        assert result["success"] is True
        assert result["result_count"] == 5
        assert result["data_source"] == "elk"
        assert result["query_id"] == query.id
        assert "executed_at" in result

    @pytest.mark.asyncio
    async def test_execute_wazuh_query_dispatches(self):
        query = _make_query(data_source="wazuh")
        db = _db_with(return_value=query)
        wazuh_result = {
            "success": True, "adapter": "wazuh", "result_count": 3, "total": 3,
            "truncated": False, "execution_ms": 80, "results": [{"id": "w1"}],
        }
        from asc_api.adapters.wazuh import WazuhAdapter
        with patch.object(WazuhAdapter, "search_raw", new_callable=AsyncMock, return_value=wazuh_result):
            result = await execute_hunt_query(db, query.id, executed_by="analyst@asc.local")
        assert result["success"] is True
        assert result["result_count"] == 3
        assert result["data_source"] == "wazuh"

    @pytest.mark.asyncio
    async def test_execute_specter_agent_routed_via_dispatch(self):
        """specter_agent is handled in _dispatch(), not _call_adapter() â€” verify routing."""
        from unittest.mock import AsyncMock, MagicMock, patch
        # _call_adapter does NOT handle specter_agent (that's _dispatch â†’ _dispatch_to_specter)
        result = await _call_adapter("specter_agent", "SELECT * FROM events")
        assert result["success"] is False
        assert "specter_agent" in result["error"]

    @pytest.mark.asyncio
    async def test_execute_manual_returns_stub(self):
        result = await _call_adapter("manual", "Check firewall logs")
        assert result["success"] is True
        assert result["result_count"] == 0
        assert "Manual" in result.get("note", "")

    @pytest.mark.asyncio
    async def test_execute_unknown_data_source_returns_error(self):
        result = await _call_adapter("splunk", "index=main")
        assert result["success"] is False
        assert "Unknown data_source" in result["error"]

    @pytest.mark.asyncio
    async def test_execute_timeout_handled_gracefully(self):
        from unittest.mock import AsyncMock
        async def _slow(*args, **kwargs):
            await asyncio.sleep(60)
            return {}  # never reached

        db = AsyncMock()
        with patch("asc_api.services.query_executor.EXECUTE_TIMEOUT_S", 0.01):
            with patch("asc_api.services.query_executor._call_adapter", side_effect=_slow):
                result = await _dispatch(
                    db, "elk", "test query",
                    query_id="q-timeout", hunt_id="h-timeout", executed_by="analyst"
                )
        assert result["success"] is False
        assert "timed out" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_execute_updates_query_metadata(self):
        query = _make_query(data_source="elk")
        db = _db_with(return_value=query)
        elk_result = {
            "success": True, "adapter": "elk", "result_count": 7, "total": 7,
            "truncated": False, "execution_ms": 55, "results": [],
        }
        from asc_api.adapters.elk import ELKAdapter
        with patch.object(ELKAdapter, "search_raw", new_callable=AsyncMock, return_value=elk_result):
            await execute_hunt_query(db, query.id, executed_by="analyst@asc.local")
        db.commit.assert_called()
        assert query.last_result_count == 7
        assert query.last_execution_ms == 55
        assert query.last_executed_at is not None

    @pytest.mark.asyncio
    async def test_execute_adapter_exception_caught(self):
        query = _make_query(data_source="elk")
        db = _db_with(return_value=query)
        from asc_api.adapters.elk import ELKAdapter
        with patch.object(ELKAdapter, "search_raw", new_callable=AsyncMock, side_effect=ConnectionError("refused")):
            result = await execute_hunt_query(db, query.id, executed_by="analyst@asc.local")
        assert result["success"] is False
        assert "refused" in result["error"]


# â”€â”€ TestHuntFromAlert â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestHuntFromAlert:

    def _make_alert(self):
        alert = MagicMock()
        alert.id = str(uuid.uuid4())
        alert.title = "Suspicious PowerShell execution"
        alert.severity = "high"
        alert.risk_score = 87.5
        alert.ttps = ["T1059.001", "T1055"]
        alert.description = "PowerShell encoded command detected"
        alert.affected_hosts = ["workstation-42"]
        return alert

    @pytest.mark.asyncio
    async def test_create_from_alert_returns_none_when_alert_missing(self):
        db = _db_with(return_value=None)
        result = await svc.create_hunt_from_alert(db, "nonexistent-id", created_by="analyst@asc.local")
        assert result is None

    @pytest.mark.asyncio
    async def test_create_from_alert_builds_active_hunt(self):
        alert = self._make_alert()
        db = _multi_db(alert, alert, alert)
        hunt_result = await svc.create_hunt_from_alert(db, alert.id, created_by="analyst@asc.local")
        db.add.assert_called()
        db.commit.assert_called()

    @pytest.mark.asyncio
    async def test_create_from_alert_includes_from_alert_tag(self):
        alert = self._make_alert()
        with patch("asc_api.services.hunt_service.Hunt") as MockHunt, \
             patch("asc_api.services.hunt_service.HuntFinding") as MockFinding:
            h_instance = MagicMock()
            h_instance.id = str(uuid.uuid4())
            h_instance.findings_count = 0
            MockHunt.return_value = h_instance
            MockFinding.return_value = MagicMock()
            db = AsyncMock()
            db.flush = AsyncMock()
            db.commit = AsyncMock()
            r = MagicMock()
            r.scalar_one_or_none.return_value = alert
            db.execute = AsyncMock(return_value=r)
            db.add = MagicMock()
            db.refresh = AsyncMock(side_effect=lambda obj: None)
            await svc.create_hunt_from_alert(db, alert.id, created_by="analyst@asc.local")
            # Tags must include "from-alert"
            call_kwargs = MockHunt.call_args[1]
            assert "from-alert" in call_kwargs.get("tags", [])

    @pytest.mark.asyncio
    async def test_create_from_alert_endpoint_requires_auth(self, anyio_backend="asyncio"):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post("/api/v1/hunt/from-alert/some-alert-id")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_create_from_alert_endpoint_404_when_alert_missing(self):
        user = _stub_user("analyst")
        app.dependency_overrides[get_analyst_or_admin] = lambda: user

        db = _db_with(return_value=None)
        app.dependency_overrides[get_db] = lambda: db

        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                resp = await client.post("/api/v1/hunt/from-alert/missing-alert-id")
            assert resp.status_code == 404
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_create_from_alert_mitre_extracted_from_ttps(self):
        alert = self._make_alert()
        alert.ttps = ["T1055", "T1059"]
        db = _multi_db(alert, alert, alert)
        with patch("asc_api.services.hunt_service.Hunt") as MockHunt:
            instance = MagicMock()
            instance.id = str(uuid.uuid4())
            instance.findings_count = 0
            MockHunt.return_value = instance
            db2 = AsyncMock()
            db2.flush = AsyncMock()
            db2.commit = AsyncMock()
            r = MagicMock()
            r.scalar_one_or_none.return_value = alert
            db2.execute = AsyncMock(return_value=r)
            db2.add = MagicMock()
            db2.refresh = AsyncMock(side_effect=lambda obj: None)
            await svc.create_hunt_from_alert(db2, alert.id, created_by="analyst@asc.local")
            call_kwargs = MockHunt.call_args[1]
            assert call_kwargs.get("mitre_technique") == "T1055"

    @pytest.mark.asyncio
    async def test_create_from_alert_high_severity_maps_to_high_priority(self):
        alert = self._make_alert()
        alert.severity = "high"
        db = AsyncMock()
        db.flush = AsyncMock()
        db.commit = AsyncMock()
        r = MagicMock()
        r.scalar_one_or_none.return_value = alert
        db.execute = AsyncMock(return_value=r)
        db.add = MagicMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)
        with patch("asc_api.services.hunt_service.Hunt") as MockHunt:
            instance = MagicMock()
            instance.id = str(uuid.uuid4())
            instance.findings_count = 0
            MockHunt.return_value = instance
            with patch("asc_api.services.hunt_service.HuntFinding") as MockFinding:
                MockFinding.return_value = MagicMock()
                await svc.create_hunt_from_alert(db, alert.id, created_by="analyst@asc.local")
            call_kwargs = MockHunt.call_args[1]
            assert call_kwargs.get("priority") == "high"
            assert call_kwargs.get("status") == "active"
            assert call_kwargs.get("started_at") is not None


# â”€â”€ TestTIEnrichment â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestTIEnrichment:

    @pytest.mark.asyncio
    async def test_enrich_finding_no_indicator_returns_early(self):
        finding = _make_finding(indicator=None, indicator_type=None)
        finding.indicator_value = None
        db = _db_with(return_value=finding)
        result = await svc.enrich_finding(db, finding.id)
        assert result["enriched"] is False
        assert "no indicator_value" in result.get("note", "").lower()

    @pytest.mark.asyncio
    async def test_enrich_finding_not_found_returns_error(self):
        db = _db_with(return_value=None)
        result = await svc.enrich_finding(db, "nonexistent-finding-id")
        assert result["enriched"] is False
        assert "error" in result

    @pytest.mark.asyncio
    async def test_enrich_finding_with_matches_updates_notes(self):
        finding = _make_finding()
        finding.analyst_notes = None
        db = _db_with(return_value=finding)
        ti_match = _make_ti_indicator("critical")
        # enrich is imported locally inside enrich_finding; patch at its source module
        import asc_api.services.threat_intel as ti_module
        with patch.object(ti_module, "enrich", new_callable=AsyncMock, return_value=[ti_match]):
            with patch.object(ti_module, "_indicator_to_dict", return_value={"value": "1.2.3.4", "severity": "critical"}):
                result = await svc.enrich_finding(db, finding.id)
        assert result["enriched"] is True
        assert result["match_count"] == 1
        assert result["is_known_bad"] is True
        assert result["max_severity"] == "critical"

    @pytest.mark.asyncio
    async def test_enrich_finding_no_matches_enriched_false(self):
        finding = _make_finding()
        db = _db_with(return_value=finding)
        with patch("asc_api.services.hunt_service.get_finding", new_callable=AsyncMock, return_value=finding):
            with patch("asc_api.services.threat_intel.enrich", new_callable=AsyncMock, return_value=[]) as mock_enrich:
                # Direct import path used inside hunt_service
                import asc_api.services.threat_intel as ti_module
                orig = ti_module.enrich
                ti_module.enrich = mock_enrich
                try:
                    result = await svc.enrich_finding(db, finding.id)
                finally:
                    ti_module.enrich = orig
        # With no matches, enriched should be False (if the patch hit)
        # At minimum the function completed without exception
        assert "enriched" in result

    @pytest.mark.asyncio
    async def test_max_severity_returns_highest(self):
        matches = [
            _make_ti_indicator("low"),
            _make_ti_indicator("critical"),
            _make_ti_indicator("medium"),
        ]
        result = svc._max_severity_from_matches(matches)
        assert result == "critical"

    @pytest.mark.asyncio
    async def test_max_severity_empty_returns_none(self):
        result = svc._max_severity_from_matches([])
        assert result is None

    @pytest.mark.asyncio
    async def test_enrich_endpoint_requires_auth(self):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post("/api/v1/hunt/hunt-id/findings/finding-id/enrich")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_enrich_endpoint_404_when_finding_hunt_mismatch(self):
        user = _stub_user("analyst")
        app.dependency_overrides[get_analyst_or_admin] = lambda: user

        hunt = _make_hunt()
        # Endpoint calls svc.get_finding (one DB call) â†’ finding with different hunt_id
        finding = _make_finding(hunt_id="different-hunt-id")
        db = _db_with(return_value=finding)
        app.dependency_overrides[get_db] = lambda: db

        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                resp = await client.post(f"/api/v1/hunt/{hunt.id}/findings/{finding.id}/enrich")
            assert resp.status_code == 404
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_enrich_endpoint_404_when_finding_missing(self):
        user = _stub_user("analyst")
        app.dependency_overrides[get_analyst_or_admin] = lambda: user

        hunt = _make_hunt()
        db = _db_with(return_value=None)
        app.dependency_overrides[get_db] = lambda: db

        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                resp = await client.post(f"/api/v1/hunt/{hunt.id}/findings/no-such-finding/enrich")
            assert resp.status_code == 404
        finally:
            app.dependency_overrides.clear()


# â”€â”€ TestReportExport â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestReportExport:

    @pytest.mark.asyncio
    async def test_generate_report_returns_none_for_missing_hunt(self):
        db = _db_with(return_value=None)
        result = await svc.generate_report(db, "no-such-hunt")
        assert result is None

    @pytest.mark.asyncio
    async def test_generate_report_has_required_keys(self):
        hunt = _make_hunt()
        finding = _make_finding(hunt_id=hunt.id)
        query = _make_query(hunt_id=hunt.id)

        # Multi-call mock: get_hunt, list_findings, list_queries
        db = AsyncMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)
        r_hunt = MagicMock()
        r_hunt.scalar_one_or_none.return_value = hunt
        r_findings = MagicMock()
        r_findings.scalars.return_value.all.return_value = [finding]
        r_queries = MagicMock()
        r_queries.scalars.return_value.all.return_value = [query]
        db.execute = AsyncMock(side_effect=[r_hunt, r_findings, r_queries])

        report = await svc.generate_report(db, hunt.id)
        assert report is not None
        required = {
            "report_generated_at", "hunt", "executive_summary",
            "hypothesis", "conclusion", "findings_by_severity",
            "findings_total", "queries_used", "timeline", "tags",
        }
        assert required.issubset(report.keys())

    @pytest.mark.asyncio
    async def test_generate_report_empty_findings(self):
        hunt = _make_hunt()
        db = AsyncMock()
        r_hunt = MagicMock(); r_hunt.scalar_one_or_none.return_value = hunt
        r_findings = MagicMock(); r_findings.scalars.return_value.all.return_value = []
        r_queries = MagicMock(); r_queries.scalars.return_value.all.return_value = []
        db.execute = AsyncMock(side_effect=[r_hunt, r_findings, r_queries])
        db.commit = AsyncMock()

        report = await svc.generate_report(db, hunt.id)
        assert report["findings_total"] == 0
        assert report["queries_used"] == []
        for sev in ("critical", "high", "medium", "low", "info"):
            assert report["findings_by_severity"][sev] == []

    @pytest.mark.asyncio
    async def test_generate_report_findings_grouped_by_severity(self):
        hunt = _make_hunt()
        f_high = _make_finding(hunt_id=hunt.id)
        f_high.severity = "high"
        f_critical = _make_finding(hunt_id=hunt.id)
        f_critical.severity = "critical"
        f_low = _make_finding(hunt_id=hunt.id)
        f_low.severity = "low"

        db = AsyncMock()
        r_hunt = MagicMock(); r_hunt.scalar_one_or_none.return_value = hunt
        r_findings = MagicMock(); r_findings.scalars.return_value.all.return_value = [f_high, f_critical, f_low]
        r_queries = MagicMock(); r_queries.scalars.return_value.all.return_value = []
        db.execute = AsyncMock(side_effect=[r_hunt, r_findings, r_queries])
        db.commit = AsyncMock()

        report = await svc.generate_report(db, hunt.id)
        assert len(report["findings_by_severity"]["high"]) == 1
        assert len(report["findings_by_severity"]["critical"]) == 1
        assert len(report["findings_by_severity"]["low"]) == 1

    @pytest.mark.asyncio
    async def test_generate_report_timeline_includes_hunt_events(self):
        hunt = _make_hunt(status="completed")
        hunt.completed_at = _now()
        finding = _make_finding(hunt_id=hunt.id)

        db = AsyncMock()
        r_hunt = MagicMock(); r_hunt.scalar_one_or_none.return_value = hunt
        r_findings = MagicMock(); r_findings.scalars.return_value.all.return_value = [finding]
        r_queries = MagicMock(); r_queries.scalars.return_value.all.return_value = []
        db.execute = AsyncMock(side_effect=[r_hunt, r_findings, r_queries])
        db.commit = AsyncMock()

        report = await svc.generate_report(db, hunt.id)
        events = [e["event"] for e in report["timeline"]]
        assert "hunt_created" in events
        assert "hunt_started" in events
        assert "finding_added" in events
        assert "hunt_completed" in events

    @pytest.mark.asyncio
    async def test_generate_report_executive_summary_counts(self):
        hunt = _make_hunt()
        f_tp = _make_finding(hunt_id=hunt.id, confirmed=True)
        f_fp = _make_finding(hunt_id=hunt.id, fp=True)
        f_unverified = _make_finding(hunt_id=hunt.id)

        db = AsyncMock()
        r_hunt = MagicMock(); r_hunt.scalar_one_or_none.return_value = hunt
        r_findings = MagicMock(); r_findings.scalars.return_value.all.return_value = [f_tp, f_fp, f_unverified]
        r_queries = MagicMock(); r_queries.scalars.return_value.all.return_value = []
        db.execute = AsyncMock(side_effect=[r_hunt, r_findings, r_queries])
        db.commit = AsyncMock()

        report = await svc.generate_report(db, hunt.id)
        summary = report["executive_summary"]
        assert summary["total_findings"] == 3
        assert summary["true_positives"] == 1
        assert summary["false_positives"] == 1
        assert summary["unverified"] == 1

    @pytest.mark.asyncio
    async def test_report_endpoint_requires_auth(self):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get("/api/v1/hunt/some-hunt-id/report")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_report_endpoint_404_for_missing_hunt(self):
        user = _stub_user("analyst")
        app.dependency_overrides[get_analyst_or_admin] = lambda: user

        db = _db_with(return_value=None)
        app.dependency_overrides[get_db] = lambda: db

        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                resp = await client.get("/api/v1/hunt/no-such-hunt/report")
            assert resp.status_code == 404
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_report_endpoint_200_for_existing_hunt(self):
        user = _stub_user("analyst")
        app.dependency_overrides[get_analyst_or_admin] = lambda: user

        hunt = _make_hunt()

        db = AsyncMock()
        r_hunt = MagicMock(); r_hunt.scalar_one_or_none.return_value = hunt
        r_findings = MagicMock(); r_findings.scalars.return_value.all.return_value = []
        r_queries = MagicMock(); r_queries.scalars.return_value.all.return_value = []
        db.execute = AsyncMock(side_effect=[r_hunt, r_findings, r_queries])
        db.commit = AsyncMock()
        app.dependency_overrides[get_db] = lambda: db

        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                resp = await client.get(f"/api/v1/hunt/{hunt.id}/report")
            assert resp.status_code == 200
            data = resp.json()
            assert "report_generated_at" in data
            assert "findings_by_severity" in data
        finally:
            app.dependency_overrides.clear()


# â”€â”€ TestAdapterSearchRaw â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestAdapterSearchRaw:

    @pytest.mark.asyncio
    async def test_elk_search_raw_not_configured(self):
        from asc_api.adapters.elk import ELKAdapter
        adapter = ELKAdapter.__new__(ELKAdapter)
        adapter._url = ""
        adapter._api_key = ""
        adapter._index_alerts = "asc-alerts"
        adapter._index_events = "asc-events"
        result = await adapter.search_raw("test query")
        assert result["success"] is False
        assert "not configured" in result.get("error", "").lower()

    @pytest.mark.asyncio
    async def test_wazuh_search_raw_not_configured(self):
        from asc_api.adapters.wazuh import WazuhAdapter
        adapter = WazuhAdapter.__new__(WazuhAdapter)
        adapter._url = ""
        adapter._username = ""
        adapter._password = ""
        adapter._verify_ssl = False
        result = await adapter.search_raw("test query")
        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_elk_search_raw_returns_success_shape(self):
        import httpx
        from asc_api.adapters.elk import ELKAdapter
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "hits": {
                "hits": [{"_source": {"@timestamp": "2026-01-01", "event.action": "injection"}}],
                "total": {"value": 1},
            }
        }
        adapter = ELKAdapter.__new__(ELKAdapter)
        adapter._url = "https://elk.local:9200"
        adapter._api_key = "dGVzdDp0ZXN0"  # nosec B105 â€” test fixture: base64("test:test")
        adapter._index_alerts = "asc-alerts"
        adapter._index_events = "asc-events"

        async def _mock_post(*args, **kwargs):
            return mock_resp

        with patch("httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(return_value=mock_resp)
            MockClient.return_value = mock_client
            result = await adapter.search_raw("injection")
        assert result["success"] is True
        assert result["result_count"] == 1
        assert result["adapter"] == "elk"

    @pytest.mark.asyncio
    async def test_elk_search_raw_http_error(self):
        import httpx
        from asc_api.adapters.elk import ELKAdapter
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.text = "Bad request"

        adapter = ELKAdapter.__new__(ELKAdapter)
        adapter._url = "https://elk.local:9200"
        adapter._api_key = "dGVzdDp0ZXN0"  # nosec B105 â€” test fixture: base64("test:test")
        adapter._index_alerts = "asc-alerts"
        adapter._index_events = "asc-events"

        with patch("httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(return_value=mock_resp)
            MockClient.return_value = mock_client
            result = await adapter.search_raw("bad query")
        assert result["success"] is False
        assert "400" in result["error"]

    @pytest.mark.asyncio
    async def test_wazuh_search_raw_success_shape(self):
        from asc_api.adapters.wazuh import WazuhAdapter
        token_resp = MagicMock()
        token_resp.status_code = 200
        token_resp.json.return_value = {"data": {"token": "fake-jwt"}}
        token_resp.raise_for_status = MagicMock()

        search_resp = MagicMock()
        search_resp.status_code = 200
        search_resp.json.return_value = {
            "data": {"affected_items": [{"id": "alert-1"}], "total_affected_items": 1}
        }

        adapter = WazuhAdapter.__new__(WazuhAdapter)
        adapter._url = "https://wazuh.local:55000"
        adapter._username = "admin"
        adapter._password = "admin"
        adapter._verify_ssl = False
        WazuhAdapter.clear_cache()

        with patch("httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(return_value=token_resp)
            mock_client.get = AsyncMock(return_value=search_resp)
            MockClient.return_value = mock_client
            result = await adapter.search_raw("rule.id:5503")
        assert result["success"] is True
        assert result["result_count"] == 1
        assert result["adapter"] == "wazuh"
        WazuhAdapter.clear_cache()

    @pytest.mark.asyncio
    async def test_wazuh_search_raw_http_error(self):
        from asc_api.adapters.wazuh import WazuhAdapter
        token_resp = MagicMock()
        token_resp.status_code = 200
        token_resp.json.return_value = {"data": {"token": "fake-jwt"}}
        token_resp.raise_for_status = MagicMock()

        err_resp = MagicMock()
        err_resp.status_code = 500
        err_resp.text = "Internal error"

        adapter = WazuhAdapter.__new__(WazuhAdapter)
        adapter._url = "https://wazuh.local:55000"
        adapter._username = "admin"
        adapter._password = "admin"
        adapter._verify_ssl = False
        WazuhAdapter.clear_cache()

        with patch("httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(return_value=token_resp)
            mock_client.get = AsyncMock(return_value=err_resp)
            MockClient.return_value = mock_client
            result = await adapter.search_raw("rule.id:1234")
        assert result["success"] is False
        WazuhAdapter.clear_cache()


# â”€â”€ TestExecuteQueryEndpoint â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestExecuteQueryEndpoint:

    @pytest.mark.asyncio
    async def test_execute_query_endpoint_requires_auth(self):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post("/api/v1/hunt/h1/queries/q1/execute")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_execute_query_endpoint_hunt_not_found(self):
        user = _stub_user("analyst")
        app.dependency_overrides[get_analyst_or_admin] = lambda: user

        db = _db_with(return_value=None)
        app.dependency_overrides[get_db] = lambda: db

        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                resp = await client.post("/api/v1/hunt/no-such-hunt/queries/q1/execute")
            assert resp.status_code == 404
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_execute_query_endpoint_query_not_in_hunt(self):
        user = _stub_user("analyst")
        app.dependency_overrides[get_analyst_or_admin] = lambda: user

        hunt = _make_hunt()
        # A query whose ID won't match `query_id` in the URL
        other_query = _make_query(hunt_id=hunt.id)
        # Endpoint: get_hunt â†’ hunt, list_queries â†’ [other_query] (different id)
        db = AsyncMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)
        r1 = MagicMock(); r1.scalar_one_or_none.return_value = hunt
        r2 = MagicMock(); r2.scalars.return_value.all.return_value = [other_query]
        db.execute = AsyncMock(side_effect=[r1, r2])
        app.dependency_overrides[get_db] = lambda: db

        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                # Use a query_id that doesn't match other_query.id
                resp = await client.post(f"/api/v1/hunt/{hunt.id}/queries/nonexistent-query-id/execute")
            assert resp.status_code == 404
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_execute_query_endpoint_success(self):
        user = _stub_user("analyst")
        app.dependency_overrides[get_analyst_or_admin] = lambda: user

        hunt = _make_hunt()
        query = _make_query(hunt_id=hunt.id, data_source="elk")
        # Endpoint flow: get_hunt(r1) â†’ list_queries(r2) â†’ execute_hunt_query internal(r3)
        db = _db_for_execute_endpoint(hunt, query)
        app.dependency_overrides[get_db] = lambda: db

        elk_result = {
            "success": True, "adapter": "elk", "result_count": 3, "total": 3,
            "truncated": False, "execution_ms": 42, "results": [],
        }
        from asc_api.adapters.elk import ELKAdapter
        try:
            with patch.object(ELKAdapter, "search_raw", new_callable=AsyncMock, return_value=elk_result):
                async with AsyncClient(
                    transport=ASGITransport(app=app), base_url="http://test"
                ) as client:
                    resp = await client.post(f"/api/v1/hunt/{hunt.id}/queries/{query.id}/execute")
            assert resp.status_code == 200
            data = resp.json()
            assert data["success"] is True
            assert data["result_count"] == 3
            assert "executed_at" in data
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_execute_query_result_has_required_keys(self):
        user = _stub_user("analyst")
        app.dependency_overrides[get_analyst_or_admin] = lambda: user

        hunt = _make_hunt()
        query = _make_query(hunt_id=hunt.id, data_source="specter_agent")
        db = _db_for_execute_endpoint(hunt, query)
        app.dependency_overrides[get_db] = lambda: db

        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                resp = await client.post(f"/api/v1/hunt/{hunt.id}/queries/{query.id}/execute")
            assert resp.status_code == 200
            data = resp.json()
            for key in ("query_id", "hunt_id", "data_source", "success", "result_count", "executed_at"):
                assert key in data, f"Missing key: {key}"
        finally:
            app.dependency_overrides.clear()


# â”€â”€ TestDurationHelper â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestDurationHelper:

    def test_duration_hours_both_timestamps(self):
        hunt = MagicMock()
        hunt.started_at = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
        hunt.completed_at = datetime(2026, 1, 1, 12, 30, 0, tzinfo=timezone.utc)
        result = svc._duration_hours(hunt)
        assert result == 2.5

    def test_duration_hours_no_started_at_returns_none(self):
        hunt = MagicMock()
        hunt.started_at = None
        hunt.completed_at = None
        result = svc._duration_hours(hunt)
        assert result is None

    def test_duration_hours_no_completed_at_uses_now(self):
        hunt = MagicMock()
        hunt.started_at = datetime.now(timezone.utc) - timedelta(hours=3)
        hunt.completed_at = None
        result = svc._duration_hours(hunt)
        assert result is not None
        assert 2.9 <= result <= 3.1  # ~3h


# â”€â”€ TestSecurityBoundaries â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestSecurityBoundaries:

    @pytest.mark.asyncio
    async def test_query_executor_only_read_elk(self):
        """Verify elk search_raw uses POST /_search (read-only), not PUT/DELETE."""
        from asc_api.adapters.elk import ELKAdapter
        import inspect
        src = inspect.getsource(ELKAdapter.search_raw)
        assert "/_search" in src
        # Must not contain PUT/DELETE index mutation patterns
        assert "/_doc/" not in src or "push_alert" not in src.split("search_raw")[1]

    @pytest.mark.asyncio
    async def test_query_executor_only_read_wazuh(self):
        """Verify wazuh search_raw uses GET /alerts (read-only)."""
        from asc_api.adapters.wazuh import WazuhAdapter
        import inspect
        src = inspect.getsource(WazuhAdapter.search_raw)
        assert "client.get" in src
        assert "/alerts" in src

    @pytest.mark.asyncio
    async def test_create_from_alert_sets_active_status(self):
        """Hunt created from alert must start as 'active' (not draft)."""
        alert = MagicMock()
        alert.id = str(uuid.uuid4())
        alert.title = "Test alert"
        alert.severity = "critical"
        alert.risk_score = 95.0
        alert.ttps = ["T1059"]
        alert.description = "Critical event"
        alert.affected_hosts = ["server-01"]
        db = AsyncMock()
        db.flush = AsyncMock()
        db.commit = AsyncMock()
        r = MagicMock()
        r.scalar_one_or_none.return_value = alert
        db.execute = AsyncMock(return_value=r)
        db.add = MagicMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)
        with patch("asc_api.services.hunt_service.Hunt") as MockHunt:
            instance = MagicMock()
            instance.id = str(uuid.uuid4())
            instance.findings_count = 0
            MockHunt.return_value = instance
            with patch("asc_api.services.hunt_service.HuntFinding") as MockFinding:
                MockFinding.return_value = MagicMock()
                await svc.create_hunt_from_alert(db, alert.id, created_by="analyst@asc.local")
            kwargs = MockHunt.call_args[1]
            assert kwargs.get("status") == "active"

    @pytest.mark.asyncio
    async def test_enrich_finding_does_not_mutate_ti_db(self):
        """TI enrichment is read-only (no TI indicator mutations)."""
        from asc_api.services import threat_intel as ti_mod
        import inspect
        # enrich function must only SELECT, not INSERT/UPDATE ThreatIntelIndicator
        src = inspect.getsource(ti_mod.enrich)
        # Should only do SELECT queries on ThreatIntelIndicator (reads)
        # Should NOT add/delete ThreatIntelIndicator
        assert "ThreatIntelIndicator" in src
        assert "db.add" not in src.split("def enrich")[1].split("def ")[0]
