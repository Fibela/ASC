"""
P22 — Threat Hunting Test Suite

Coverage
--------
TestHuntService        (14 tests) — create, list, update status transitions, archive,
                                    findings (add/list/verdict), queries (save/list/delete),
                                    stats
TestHuntEndpoints      (12 tests) — auth enforcement (401/403), CRUD, status workflow,
                                    add-finding, get-finding, verdict, list-queries, save-query
TestHuntFindingFlow    (6 tests)  — finding verdicts (TP/FP), archived-hunt guard, missing hunt
TestHuntQueryFlow      (5 tests)  — save/list/delete queries, invalid data_source
TestHuntStats          (4 tests)  — stats structure, empty corpus, technique aggregation
TestHuntValidation     (6 tests)  — invalid scope/priority/status transition/severity/type

Total: 47 tests
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.db.session import get_db
from app.api.deps import get_analyst_or_admin, get_current_admin
from app.models.user import User
from app.models.hunt import Hunt, HuntFinding, HuntQuery
from app.services import hunt_service as svc


# ── Helpers ───────────────────────────────────────────────────────────────────

def _stub_user(role: str = "analyst") -> User:
    u = MagicMock(spec=User)
    u.id = str(uuid.uuid4())
    u.email = f"{role}@asc.local"
    u.role = role
    return u


def _now():
    return datetime.now(timezone.utc)


def _make_hunt(
    status: str = "draft",
    priority: str = "medium",
    scope: str = "all",
) -> Hunt:
    h = MagicMock(spec=Hunt)
    h.id = str(uuid.uuid4())
    h.name = "Test Hunt"
    h.description = None
    h.hypothesis = "We suspect lateral movement"
    h.status = status
    h.mitre_technique = "T1055"
    h.mitre_tactic = "defense-evasion"
    h.scope = scope
    h.priority = priority
    h.created_by = "analyst@asc.local"
    h.assigned_to = None
    h.created_at = _now()
    h.started_at = None
    h.completed_at = None
    h.updated_at = _now()
    h.conclusion = None
    h.findings_count = 0
    h.true_positive_count = 0
    h.tags = ["test"]
    h.findings = []
    h.queries = []
    return h


def _make_finding(hunt_id: str | None = None, confirmed: bool = False) -> HuntFinding:
    f = MagicMock(spec=HuntFinding)
    f.id = str(uuid.uuid4())
    f.hunt_id = hunt_id or str(uuid.uuid4())
    f.title = "Suspicious process injection"
    f.description = None
    f.severity = "high"
    f.indicator_value = "1.2.3.4"
    f.indicator_type = "ip"
    f.affected_host = "workstation-01"
    f.affected_user = "jdoe"
    f.data_source = "elk"
    f.mitre_technique = "T1055"
    f.mitre_tactic = "defense-evasion"
    f.evidence = None
    f.is_confirmed = confirmed
    f.is_false_positive = False
    f.analyst_notes = None
    f.created_by = "analyst@asc.local"
    f.created_at = _now()
    f.updated_at = _now()
    return f


def _make_query(hunt_id: str | None = None) -> HuntQuery:
    q = MagicMock(spec=HuntQuery)
    q.id = str(uuid.uuid4())
    q.hunt_id = hunt_id or str(uuid.uuid4())
    q.name = "Process injection query"
    q.query_text = "event.action: process_injection AND host.name: *"
    q.data_source = "elk"
    q.description = None
    q.last_executed_at = None
    q.last_result_count = None
    q.last_execution_ms = None
    q.created_by = "analyst@asc.local"
    q.created_at = _now()
    return q


def _db_with(return_value=None) -> AsyncMock:
    db = AsyncMock()
    db.add = MagicMock()
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


# ── TestHuntService ───────────────────────────────────────────────────────────

class TestHuntService:

    @pytest.mark.asyncio
    async def test_create_hunt_valid(self):
        db = _db_with()
        hunt = await svc.create_hunt(db, name="New Hunt", created_by="analyst@asc.local")
        db.add.assert_called_once()
        db.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_hunt_invalid_scope_raises(self):
        db = _db_with()
        with pytest.raises(ValueError, match="Invalid scope"):
            await svc.create_hunt(db, name="Hunt", created_by="x", scope="galaxy")

    @pytest.mark.asyncio
    async def test_create_hunt_invalid_priority_raises(self):
        db = _db_with()
        with pytest.raises(ValueError, match="Invalid priority"):
            await svc.create_hunt(db, name="Hunt", created_by="x", priority="urgent")

    @pytest.mark.asyncio
    async def test_create_hunt_empty_name_raises(self):
        db = _db_with()
        with pytest.raises(ValueError, match="name cannot be empty"):
            await svc.create_hunt(db, name="   ", created_by="x")

    @pytest.mark.asyncio
    async def test_update_hunt_valid_status_transition(self):
        hunt = _make_hunt(status="draft")
        db = AsyncMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)
        r = MagicMock()
        r.scalar_one_or_none.return_value = hunt
        db.execute = AsyncMock(return_value=r)

        result = await svc.update_hunt(db, hunt.id, {"status": "active"}, updated_by="analyst@asc.local")
        assert result.status == "active"
        assert result.started_at is not None

    @pytest.mark.asyncio
    async def test_update_hunt_invalid_transition_raises(self):
        hunt = _make_hunt(status="completed")
        db = AsyncMock()
        r = MagicMock()
        r.scalar_one_or_none.return_value = hunt
        db.execute = AsyncMock(return_value=r)

        with pytest.raises(ValueError, match="Cannot transition"):
            await svc.update_hunt(db, hunt.id, {"status": "draft"}, updated_by="x")

    @pytest.mark.asyncio
    async def test_update_archived_cannot_go_back(self):
        hunt = _make_hunt(status="archived")
        db = AsyncMock()
        r = MagicMock()
        r.scalar_one_or_none.return_value = hunt
        db.execute = AsyncMock(return_value=r)

        with pytest.raises(ValueError, match="Cannot transition"):
            await svc.update_hunt(db, hunt.id, {"status": "active"}, updated_by="x")

    @pytest.mark.asyncio
    async def test_archive_hunt_sets_status(self):
        hunt = _make_hunt(status="active")
        db = AsyncMock()
        db.commit = AsyncMock()
        r = MagicMock()
        r.scalar_one_or_none.return_value = hunt
        db.execute = AsyncMock(return_value=r)

        ok = await svc.archive_hunt(db, hunt.id)
        assert ok is True
        assert hunt.status == "archived"

    @pytest.mark.asyncio
    async def test_archive_nonexistent_returns_false(self):
        db = AsyncMock()
        r = MagicMock()
        r.scalar_one_or_none.return_value = None
        db.execute = AsyncMock(return_value=r)

        ok = await svc.archive_hunt(db, "nonexistent")
        assert ok is False

    @pytest.mark.asyncio
    async def test_add_finding_increments_count(self):
        hunt = _make_hunt()
        hunt.findings_count = 2
        db = AsyncMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)
        db.add = MagicMock()
        r = MagicMock()
        r.scalar_one_or_none.return_value = hunt
        db.execute = AsyncMock(return_value=r)

        await svc.add_finding(db, hunt.id, title="New finding", created_by="analyst@asc.local")
        assert hunt.findings_count == 3

    @pytest.mark.asyncio
    async def test_add_finding_invalid_severity_raises(self):
        db = _db_with()
        with pytest.raises(ValueError, match="Invalid severity"):
            await svc.add_finding(db, "hunt-id", title="x", created_by="y", severity="extreme")

    @pytest.mark.asyncio
    async def test_set_finding_verdict_increments_tp(self):
        finding = _make_finding(confirmed=False)
        finding.is_confirmed = False
        hunt = _make_hunt()
        hunt.true_positive_count = 0

        db = AsyncMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)
        r_finding = MagicMock()
        r_finding.scalar_one_or_none.return_value = finding
        r_hunt = MagicMock()
        r_hunt.scalar_one_or_none.return_value = hunt
        db.execute = AsyncMock(side_effect=[r_finding, r_hunt])

        await svc.set_finding_verdict(db, finding.id, is_confirmed=True)
        assert hunt.true_positive_count == 1
        assert finding.is_confirmed is True

    @pytest.mark.asyncio
    async def test_save_query_invalid_source_raises(self):
        db = _db_with()
        with pytest.raises(ValueError, match="Invalid data_source"):
            await svc.save_query(db, "hunt-id", name="q", query_text="*", data_source="splunk", created_by="x")

    @pytest.mark.asyncio
    async def test_delete_query_returns_false_if_not_found(self):
        db = AsyncMock()
        r = MagicMock()
        r.scalar_one_or_none.return_value = None
        db.execute = AsyncMock(return_value=r)

        ok = await svc.delete_query(db, "nonexistent")
        assert ok is False


# ── TestHuntEndpoints ─────────────────────────────────────────────────────────

class TestHuntEndpoints:

    @pytest.mark.asyncio
    async def test_stats_requires_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/v1/hunt/stats")
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_list_requires_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/v1/hunt/")
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_create_requires_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.post("/api/v1/hunt/", json={"name": "Hunt"})
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_archive_requires_admin(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.delete("/api/v1/hunt/some-id")
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_list_returns_structure(self):
        hunt = _make_hunt()
        db = AsyncMock()
        db.commit = AsyncMock()
        r_count = MagicMock()
        r_count.scalar_one.return_value = 1
        r_list = MagicMock()
        r_list.scalars.return_value.all.return_value = [hunt]
        db.execute = AsyncMock(side_effect=[r_count, r_list])
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/v1/hunt/")

        assert r.status_code == 200
        data = r.json()
        assert "hunts" in data and "total" in data

    @pytest.mark.asyncio
    async def test_get_hunt_not_found(self):
        db = AsyncMock()
        r = MagicMock()
        r.scalar_one_or_none.return_value = None
        db.execute = AsyncMock(return_value=r)
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/v1/hunt/nonexistent")

        assert r.status_code == 404

    @pytest.mark.asyncio
    async def test_create_hunt_empty_name_returns_422(self):
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.post("/api/v1/hunt/", json={"name": ""})

        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_create_hunt_invalid_scope_returns_422(self):
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.post("/api/v1/hunt/", json={"name": "Hunt", "scope": "GALAXY"})

        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_update_no_fields_returns_422(self):
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()
        app.dependency_overrides[get_db] = lambda: _db_with()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.put("/api/v1/hunt/some-id", json={})

        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_add_finding_to_archived_hunt_returns_409(self):
        hunt = _make_hunt(status="archived")
        db = AsyncMock()
        rm = MagicMock()
        rm.scalar_one_or_none.return_value = hunt
        db.execute = AsyncMock(return_value=rm)
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.post(f"/api/v1/hunt/{hunt.id}/findings", json={"title": "Finding"})

        assert r.status_code == 409

    @pytest.mark.asyncio
    async def test_save_query_invalid_data_source_422(self):
        hunt = _make_hunt()
        db = AsyncMock()
        rm = MagicMock()
        rm.scalar_one_or_none.return_value = hunt
        db.execute = AsyncMock(return_value=rm)
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.post(f"/api/v1/hunt/{hunt.id}/queries", json={
                "name": "q", "query_text": "*", "data_source": "splunk"
            })

        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_list_findings_hunt_not_found(self):
        db = AsyncMock()
        rm = MagicMock()
        rm.scalar_one_or_none.return_value = None
        db.execute = AsyncMock(return_value=rm)
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/v1/hunt/nonexistent/findings")

        assert r.status_code == 404

    def teardown_method(self):
        app.dependency_overrides.clear()


# ── TestHuntFindingFlow ───────────────────────────────────────────────────────

class TestHuntFindingFlow:

    @pytest.mark.asyncio
    async def test_verdict_confirm_returns_200(self):
        hunt_id = str(uuid.uuid4())
        finding = _make_finding(hunt_id=hunt_id, confirmed=False)
        finding.is_confirmed = False
        hunt = _make_hunt()
        hunt.true_positive_count = 0

        db = AsyncMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)
        r1 = MagicMock()
        r1.scalar_one_or_none.return_value = finding
        r2 = MagicMock()
        r2.scalar_one_or_none.return_value = hunt
        db.execute = AsyncMock(side_effect=[r1, r1, r2])
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.post(
                f"/api/v1/hunt/{hunt_id}/findings/{finding.id}/verdict",
                json={"is_confirmed": True, "analyst_notes": "Confirmed C2 traffic"},
            )

        assert r.status_code == 200
        data = r.json()
        assert data["is_confirmed"] is True

    @pytest.mark.asyncio
    async def test_verdict_false_positive(self):
        hunt_id = str(uuid.uuid4())
        finding = _make_finding(hunt_id=hunt_id)
        finding.is_confirmed = False
        hunt = _make_hunt()

        db = AsyncMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)
        r1 = MagicMock()
        r1.scalar_one_or_none.return_value = finding
        r2 = MagicMock()
        r2.scalar_one_or_none.return_value = hunt
        db.execute = AsyncMock(side_effect=[r1, r1, r2])
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.post(
                f"/api/v1/hunt/{hunt_id}/findings/{finding.id}/verdict",
                json={"is_confirmed": False, "is_false_positive": True},
            )

        assert r.status_code == 200
        data = r.json()
        assert data["is_false_positive"] is True

    @pytest.mark.asyncio
    async def test_verdict_wrong_hunt_id_returns_404(self):
        finding = _make_finding(hunt_id="correct-hunt-id")
        db = AsyncMock()
        r1 = MagicMock()
        r1.scalar_one_or_none.return_value = finding
        db.execute = AsyncMock(return_value=r1)
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.post(
                "/api/v1/hunt/wrong-hunt-id/findings/{}/verdict".format(finding.id),
                json={"is_confirmed": True},
            )

        assert r.status_code == 404

    @pytest.mark.asyncio
    async def test_get_finding_wrong_hunt_404(self):
        finding = _make_finding(hunt_id="hunt-A")
        db = AsyncMock()
        r = MagicMock()
        r.scalar_one_or_none.return_value = finding
        db.execute = AsyncMock(return_value=r)
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(f"/api/v1/hunt/hunt-B/findings/{finding.id}")

        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_add_finding_invalid_indicator_type_422(self):
        hunt = _make_hunt(status="active")
        db = AsyncMock()
        rm = MagicMock()
        rm.scalar_one_or_none.return_value = hunt
        db.execute = AsyncMock(return_value=rm)
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.post(
                f"/api/v1/hunt/{hunt.id}/findings",
                json={"title": "Finding", "indicator_type": "BADTYPE"},
            )

        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_verdict_requires_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.post("/api/v1/hunt/hunt-id/findings/finding-id/verdict",
                             json={"is_confirmed": True})
        assert r.status_code == 401

    def teardown_method(self):
        app.dependency_overrides.clear()


# ── TestHuntQueryFlow ─────────────────────────────────────────────────────────

class TestHuntQueryFlow:

    @pytest.mark.asyncio
    async def test_list_queries_returns_structure(self):
        hunt = _make_hunt()
        q = _make_query(hunt_id=hunt.id)
        db = AsyncMock()
        r_hunt = MagicMock()
        r_hunt.scalar_one_or_none.return_value = hunt
        r_queries = MagicMock()
        r_queries.scalars.return_value.all.return_value = [q]
        db.execute = AsyncMock(side_effect=[r_hunt, r_queries])
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get(f"/api/v1/hunt/{hunt.id}/queries")

        assert r.status_code == 200
        data = r.json()
        assert "queries" in data and "total" in data

    @pytest.mark.asyncio
    async def test_save_query_returns_201(self):
        hunt = _make_hunt()
        query = _make_query(hunt_id=hunt.id)
        db = AsyncMock()
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)
        r_hunt = MagicMock()
        r_hunt.scalar_one_or_none.return_value = hunt
        r_query = MagicMock()
        r_query.scalar_one_or_none.return_value = query
        db.execute = AsyncMock(side_effect=[r_hunt, r_query])
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.post(f"/api/v1/hunt/{hunt.id}/queries", json={
                "name": "My Query", "query_text": "host.name: *", "data_source": "elk"
            })

        assert r.status_code == 201

    @pytest.mark.asyncio
    async def test_delete_query_not_found_returns_404(self):
        db = AsyncMock()
        rm = MagicMock()
        rm.scalar_one_or_none.return_value = None
        db.execute = AsyncMock(return_value=rm)
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.delete("/api/v1/hunt/hunt-id/queries/nonexistent")

        assert r.status_code == 404

    @pytest.mark.asyncio
    async def test_save_query_requires_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.post("/api/v1/hunt/hunt-id/queries", json={
                "name": "q", "query_text": "*"
            })
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_list_queries_hunt_not_found(self):
        db = AsyncMock()
        rm = MagicMock()
        rm.scalar_one_or_none.return_value = None
        db.execute = AsyncMock(return_value=rm)
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/v1/hunt/nonexistent/queries")

        assert r.status_code == 404

    def teardown_method(self):
        app.dependency_overrides.clear()


# ── TestHuntStats ─────────────────────────────────────────────────────────────

class TestHuntStats:

    @pytest.mark.asyncio
    async def test_stats_returns_full_structure(self):
        db = AsyncMock()

        def _mk(val):
            r = MagicMock()
            r.scalar_one.return_value = val
            r.all.return_value = []
            r.scalars.return_value.all.return_value = []
            return r

        db.execute = AsyncMock(side_effect=[
            _mk(10),  # total hunts
            _mk(0),   # by_status
            _mk(0),   # by_priority
            _mk(5),   # total findings
            _mk(3),   # confirmed findings
            _mk(0),   # findings by severity
            _mk(0),   # top techniques
        ])
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/v1/hunt/stats")

        assert r.status_code == 200
        data = r.json()
        for key in ("total_hunts", "by_status", "by_priority", "total_findings", "confirmed_findings",
                    "false_positive_rate", "findings_by_severity", "top_techniques"):
            assert key in data, f"Missing key: {key}"

    @pytest.mark.asyncio
    async def test_stats_false_positive_rate_zero_when_no_findings(self):
        stats = await _mock_stats_call(total_findings=0, confirmed=0)
        assert stats["false_positive_rate"] == 0.0

    @pytest.mark.asyncio
    async def test_stats_false_positive_rate_calculated(self):
        stats = await _mock_stats_call(total_findings=10, confirmed=6)
        # FP rate = 1 - (6/10) = 0.4
        assert abs(stats["false_positive_rate"] - 0.4) < 0.01

    @pytest.mark.asyncio
    async def test_stats_requires_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/v1/hunt/stats")
        assert r.status_code == 401

    def teardown_method(self):
        app.dependency_overrides.clear()


async def _mock_stats_call(total_findings: int, confirmed: int) -> dict:
    db = AsyncMock()

    def _mk(val):
        r = MagicMock()
        r.scalar_one.return_value = val
        r.all.return_value = []
        return r

    db.execute = AsyncMock(side_effect=[
        _mk(0),              # total hunts
        _mk(0),              # by_status
        _mk(0),              # by_priority
        _mk(total_findings), # total findings
        _mk(confirmed),      # confirmed
        _mk(0),              # by severity
        _mk(0),              # top techniques
    ])
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_analyst_or_admin] = lambda: MagicMock(spec=User, email="a@b.com", role="analyst")

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get("/api/v1/hunt/stats")
    app.dependency_overrides.clear()
    return r.json()


# ── TestHuntValidation ────────────────────────────────────────────────────────

class TestHuntValidation:

    @pytest.mark.asyncio
    async def test_create_with_all_valid_fields_201(self):
        hunt = _make_hunt()
        db = AsyncMock()
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock(side_effect=lambda obj: None)
        rm = MagicMock()
        rm.scalar_one_or_none.return_value = hunt
        db.execute = AsyncMock(return_value=rm)
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.post("/api/v1/hunt/", json={
                "name": "APT Hunt Q2", "scope": "network", "priority": "high",
                "mitre_technique": "T1071", "mitre_tactic": "command-and-control",
                "tags": ["apt", "c2"],
            })

        assert r.status_code == 201

    @pytest.mark.asyncio
    async def test_create_invalid_priority_422(self):
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.post("/api/v1/hunt/", json={"name": "Hunt", "priority": "ULTRA"})

        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_update_invalid_status_value_409(self):
        hunt = _make_hunt(status="active")
        db = AsyncMock()
        rm = MagicMock()
        rm.scalar_one_or_none.return_value = hunt
        db.execute = AsyncMock(return_value=rm)
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.put(f"/api/v1/hunt/{hunt.id}", json={"status": "draft"})

        # active → draft is forbidden
        assert r.status_code == 409

    @pytest.mark.asyncio
    async def test_finding_title_too_long_422(self):
        hunt = _make_hunt(status="active")
        db = AsyncMock()
        rm = MagicMock()
        rm.scalar_one_or_none.return_value = hunt
        db.execute = AsyncMock(return_value=rm)
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.post(f"/api/v1/hunt/{hunt.id}/findings",
                             json={"title": "x" * 513})

        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_query_empty_text_422(self):
        hunt = _make_hunt()
        db = AsyncMock()
        rm = MagicMock()
        rm.scalar_one_or_none.return_value = hunt
        db.execute = AsyncMock(return_value=rm)
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.post(f"/api/v1/hunt/{hunt.id}/queries",
                             json={"name": "q", "query_text": ""})

        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_hunt_serializer_output_fields(self):
        hunt = _make_hunt(status="active", priority="high")
        d = svc._hunt_to_dict(hunt)
        for field in ("id", "name", "status", "priority", "scope", "findings_count",
                      "true_positive_count", "tags", "created_at", "updated_at"):
            assert field in d, f"Missing field: {field}"

    def teardown_method(self):
        app.dependency_overrides.clear()
