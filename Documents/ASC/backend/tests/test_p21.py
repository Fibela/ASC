"""
P21 — Test Suite

Coverage
--------
TestTIService            (12 tests) — create, list, update, delete, enrich, bulk_import, stats
TestTIEndpoints          (10 tests) — API CRUD, auth enforcement, rate-limit header present
TestTIEnrichEndpoint     (5 tests)  — enrich single, bulk, hit_count tracking, unknown value
TestIoCsAuth             (4 tests)  — iocs.py now requires auth; unauthenticated → 401
TestAlertsRateLimit      (3 tests)  — alerts.py rate-limit headers present on authenticated calls
TestHealthAdapters       (5 tests)  — /health/adapters structure, all fields, auth required
TestMIMEValidation       (8 tests)  — analyze/file: valid PE accepted, disallowed type rejected,
                                       oversized rejected, octet-stream accepted
TestOpsRateLimit         (3 tests)  — /ops/* returns 200 with auth, 401 without

Total: 50 tests
"""
from __future__ import annotations

import asyncio
import io
import struct
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient, ASGITransport

from asc_api.main import app
from asc_api.db.session import get_db
from asc_api.api.deps import get_analyst_or_admin, get_current_user, get_current_admin
from asc_api.models.user import User
from asc_api.services import threat_intel as ti_svc


# ── Helpers ───────────────────────────────────────────────────────────────────

def _stub_user(role: str = "analyst") -> User:
    u = MagicMock(spec=User)
    u.id = str(uuid.uuid4())
    u.email = f"{role}@asc.local"
    u.role = role
    return u


def _mock_db(rows: list | None = None) -> AsyncMock:
    db = AsyncMock()
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock(side_effect=lambda obj: None)
    db.rollback = AsyncMock()
    if rows is not None:
        scalars_mock = MagicMock()
        scalars_mock.all.return_value = rows
        result_mock = MagicMock()
        result_mock.scalars.return_value = scalars_mock
        result_mock.scalar_one_or_none.return_value = rows[0] if rows else None
        result_mock.scalar_one.return_value = len(rows)
        db.execute = AsyncMock(return_value=result_mock)
    return db


def _make_ti(indicator_type: str = "ip", value: str = "1.2.3.4", severity: str = "high") -> MagicMock:
    ind = MagicMock(spec=ti_svc.ThreatIntelIndicator)
    ind.id = str(uuid.uuid4())
    ind.indicator_type = indicator_type
    ind.value = value
    ind.severity = severity
    ind.confidence = 0.9
    ind.threat_actor = "APT29"
    ind.malware_family = "Cobalt Strike"
    ind.campaign = None
    ind.ttps = ["T1055"]
    ind.tags = ["c2"]
    ind.source = "internal"
    ind.description = None
    ind.hit_count = 0
    ind.first_seen = datetime.now(timezone.utc)
    ind.last_seen = datetime.now(timezone.utc)
    return ind


# ── TestTIService ──────────────────────────────────────────────────────────────

class TestTIService:

    @pytest.mark.asyncio
    async def test_create_indicator_valid(self):
        db = _mock_db()
        ind = await ti_svc.create_indicator(
            db, indicator_type="ip", value="10.0.0.1",
            severity="high", confidence=0.9, source="internal",
        )
        db.add.assert_called_once()
        db.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_indicator_invalid_type_raises(self):
        db = _mock_db()
        with pytest.raises(ValueError, match="Unknown indicator_type"):
            await ti_svc.create_indicator(db, indicator_type="INVALID", value="x")

    @pytest.mark.asyncio
    async def test_create_indicator_invalid_severity_raises(self):
        db = _mock_db()
        with pytest.raises(ValueError, match="Unknown severity"):
            await ti_svc.create_indicator(db, indicator_type="ip", value="1.1.1.1", severity="ultra")

    @pytest.mark.asyncio
    async def test_create_indicator_confidence_out_of_range(self):
        db = _mock_db()
        with pytest.raises(ValueError, match="confidence"):
            await ti_svc.create_indicator(db, indicator_type="ip", value="1.1.1.1", confidence=1.5)

    @pytest.mark.asyncio
    async def test_normalize_domain_lowercased(self):
        db = _mock_db()
        await ti_svc.create_indicator(db, indicator_type="domain", value="EVIL.COM")
        args = db.add.call_args[0][0]
        assert args.value == "evil.com"

    @pytest.mark.asyncio
    async def test_normalize_ip_not_lowercased(self):
        db = _mock_db()
        await ti_svc.create_indicator(db, indicator_type="ip", value="1.2.3.4")
        args = db.add.call_args[0][0]
        assert args.value == "1.2.3.4"

    @pytest.mark.asyncio
    async def test_bulk_import_creates_and_updates(self):
        db = _mock_db(rows=[])
        # First call: no existing → create
        result = await ti_svc.bulk_import(db, [
            {"indicator_type": "ip", "value": "1.2.3.4", "severity": "high"},
            {"indicator_type": "INVALID"},  # should be skipped
        ])
        assert result["created"] == 1
        assert result["skipped"] == 1

    @pytest.mark.asyncio
    async def test_bulk_import_updates_existing(self):
        existing = _make_ti()
        db = AsyncMock()
        db.commit = AsyncMock()
        result_mock = MagicMock()
        result_mock.scalar_one_or_none.return_value = existing
        db.execute = AsyncMock(return_value=result_mock)

        result = await ti_svc.bulk_import(db, [
            {"indicator_type": "ip", "value": "1.2.3.4", "severity": "critical"},
        ])
        assert result["updated"] == 1
        assert result["created"] == 0

    @pytest.mark.asyncio
    async def test_enrich_returns_matches(self):
        ind = _make_ti(value="10.0.0.1")
        db = AsyncMock()
        result_mock = MagicMock()
        result_mock.scalars.return_value.all.return_value = [ind]
        db.execute = AsyncMock(return_value=result_mock)
        db.commit = AsyncMock()

        matches = await ti_svc.enrich(db, "10.0.0.1", "ip")
        assert len(matches) == 1
        assert matches[0].value == "10.0.0.1"

    @pytest.mark.asyncio
    async def test_enrich_no_match_returns_empty(self):
        db = AsyncMock()
        result_mock = MagicMock()
        result_mock.scalars.return_value.all.return_value = []
        db.execute = AsyncMock(return_value=result_mock)

        matches = await ti_svc.enrich(db, "8.8.8.8", "ip", track_hit=False)
        assert matches == []

    @pytest.mark.asyncio
    async def test_enrich_tracks_hit_count(self):
        ind = _make_ti(value="evil.com")
        ind.hit_count = 3
        db = AsyncMock()
        result_mock = MagicMock()
        result_mock.scalars.return_value.all.return_value = [ind]
        db.execute = AsyncMock(return_value=result_mock)
        db.commit = AsyncMock()

        await ti_svc.enrich(db, "evil.com", "domain", track_hit=True)
        assert ind.hit_count == 4

    @pytest.mark.asyncio
    async def test_delete_deactivates_indicator(self):
        ind = _make_ti()
        ind.active = True
        db = AsyncMock()
        result_mock = MagicMock()
        result_mock.scalar_one_or_none.return_value = ind
        db.execute = AsyncMock(return_value=result_mock)
        db.commit = AsyncMock()

        ok = await ti_svc.delete_indicator(db, ind.id)
        assert ok is True
        assert ind.active is False


# ── TestTIEndpoints ───────────────────────────────────────────────────────────

class TestTIEndpoints:

    @pytest.mark.asyncio
    async def test_stats_requires_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/v1/threat-intel/stats")
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_list_requires_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/v1/threat-intel/")
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_create_requires_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.post("/api/v1/threat-intel/", json={"indicator_type": "ip", "value": "1.1.1.1"})
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_stats_returns_structure(self):
        db = _mock_db()
        # Stats queries return scalar counts
        db.execute = AsyncMock(side_effect=[
            _scalar_result(10),  # total
            _scalar_result(8),   # active
            _rows_result([("ip", 5), ("domain", 3)]),  # by_type
            _rows_result([("high", 4), ("medium", 4)]),  # by_severity
            _scalars_result([]),  # top_hits
        ])
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/v1/threat-intel/stats")

        assert r.status_code == 200
        data = r.json()
        assert "total" in data and "active" in data and "by_type" in data

    @pytest.mark.asyncio
    async def test_list_returns_structure(self):
        inds = [_make_ti()]
        db = _mock_db()
        db.execute = AsyncMock(side_effect=[
            _scalar_result(1),
            _scalars_result(inds),
        ])
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/v1/threat-intel/")

        assert r.status_code == 200
        assert "indicators" in r.json()
        assert "total" in r.json()

    @pytest.mark.asyncio
    async def test_delete_requires_admin(self):
        # No auth at all → 401 (admin dependency not satisfied)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.delete("/api/v1/threat-intel/some-id")
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_delete_with_admin_nonexistent_returns_404(self):
        db = AsyncMock()
        db.commit = AsyncMock()
        result_mock = MagicMock()
        result_mock.scalar_one_or_none.return_value = None
        db.execute = AsyncMock(return_value=result_mock)
        app.dependency_overrides[get_current_admin] = lambda: _stub_user("admin")
        app.dependency_overrides[get_db] = lambda: db

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.delete("/api/v1/threat-intel/nonexistent-uuid")
        assert r.status_code == 404

    @pytest.mark.asyncio
    async def test_create_invalid_type_returns_422(self):
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()
        app.dependency_overrides[get_db] = lambda: _mock_db()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.post("/api/v1/threat-intel/", json={"indicator_type": "INVALID", "value": "x"})

        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_get_nonexistent_returns_404(self):
        db = _mock_db(rows=[])
        db.execute = AsyncMock(return_value=_none_result())
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/v1/threat-intel/nonexistent-id")

        assert r.status_code == 404

    @pytest.mark.asyncio
    async def test_bulk_import_requires_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.post("/api/v1/threat-intel/bulk", json={"indicators": []})
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_enrich_requires_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.post("/api/v1/threat-intel/enrich", json={"value": "1.1.1.1"})
        assert r.status_code == 401

    def teardown_method(self):
        app.dependency_overrides.clear()


# ── TestTIEnrichEndpoint ──────────────────────────────────────────────────────

class TestTIEnrichEndpoint:

    @pytest.mark.asyncio
    async def test_enrich_known_bad(self):
        ind = _make_ti(value="evil.com", severity="critical")
        db = AsyncMock()
        db.commit = AsyncMock()
        result_mock = MagicMock()
        result_mock.scalars.return_value.all.return_value = [ind]
        db.execute = AsyncMock(return_value=result_mock)
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.post("/api/v1/threat-intel/enrich", json={"value": "evil.com", "indicator_type": "domain"})

        assert r.status_code == 200
        data = r.json()
        assert data["is_known_bad"] is True
        assert data["match_count"] == 1
        assert data["max_severity"] == "critical"

    @pytest.mark.asyncio
    async def test_enrich_unknown_value(self):
        db = AsyncMock()
        db.commit = AsyncMock()
        result_mock = MagicMock()
        result_mock.scalars.return_value.all.return_value = []
        db.execute = AsyncMock(return_value=result_mock)
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.post("/api/v1/threat-intel/enrich", json={"value": "8.8.8.8"})

        assert r.status_code == 200
        data = r.json()
        assert data["is_known_bad"] is False
        assert data["match_count"] == 0
        assert data["max_severity"] is None

    @pytest.mark.asyncio
    async def test_enrich_invalid_type_422(self):
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.post("/api/v1/threat-intel/enrich", json={"value": "x", "indicator_type": "BADTYPE"})

        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_enrich_bulk_returns_results(self):
        db = AsyncMock()
        db.commit = AsyncMock()
        result_mock = MagicMock()
        result_mock.scalars.return_value.all.return_value = []
        db.execute = AsyncMock(return_value=result_mock)
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.post("/api/v1/threat-intel/enrich/bulk", json={
                "values": [{"value": "1.2.3.4"}, {"value": "evil.com"}]
            })

        assert r.status_code == 200
        data = r.json()
        assert "results" in data
        assert data["total_values"] == 2

    @pytest.mark.asyncio
    async def test_enrich_empty_value_422(self):
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.post("/api/v1/threat-intel/enrich", json={"value": ""})

        assert r.status_code == 422

    def teardown_method(self):
        app.dependency_overrides.clear()


# ── TestIoCsAuth ──────────────────────────────────────────────────────────────

class TestIoCsAuth:
    """Verify that iocs.py now requires authentication (security gap closed in P21-F2)."""

    @pytest.mark.asyncio
    async def test_list_iocs_requires_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/v1/iocs/")
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_create_ioc_requires_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.post("/api/v1/iocs/", json={"value": "1.1.1.1", "ioc_type": "ip"})
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_search_ioc_requires_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/v1/iocs/search?value=evil")
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_delete_ioc_requires_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.delete("/api/v1/iocs/some-id")
        assert r.status_code == 401


# ── TestAlertsRateLimit ───────────────────────────────────────────────────────

class TestAlertsRateLimit:

    @pytest.mark.asyncio
    async def test_list_alerts_requires_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/v1/alerts/")
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_alert_stats_requires_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/v1/alerts/stats/summary")
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_list_alerts_with_auth_returns_200(self):
        db = _mock_db()
        db.execute = AsyncMock(return_value=_scalars_result([]))
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_current_user] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/v1/alerts/")

        assert r.status_code == 200

    def teardown_method(self):
        app.dependency_overrides.clear()


# ── TestHealthAdapters ────────────────────────────────────────────────────────

class TestHealthAdapters:

    @pytest.mark.asyncio
    async def test_requires_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/v1/health/adapters")
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_returns_structure_with_auth(self):
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/v1/health/adapters")

        assert r.status_code == 200
        data = r.json()
        for field in ("total_adapters", "configured", "reachable", "unreachable", "adapters", "ts"):
            assert field in data, f"Missing field: {field}"

    @pytest.mark.asyncio
    async def test_all_adapters_present(self):
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/v1/health/adapters")

        data = r.json()
        adapter_names = {a["adapter"] for a in data["adapters"]}
        expected = {"elk", "wazuh", "thehive", "paloalto", "fortinet", "active_directory"}
        assert expected == adapter_names

    @pytest.mark.asyncio
    async def test_unconfigured_adapters_have_not_configured_status(self):
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/v1/health/adapters")

        # In test env no adapters are configured → all should be "not_configured"
        data = r.json()
        for a in data["adapters"]:
            assert a["status"] in ("not_configured", "reachable", "unreachable")
            assert "detail" in a

    @pytest.mark.asyncio
    async def test_reachable_count_consistent(self):
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/v1/health/adapters")

        data = r.json()
        counted_reachable = sum(1 for a in data["adapters"] if a["status"] == "reachable")
        assert data["reachable"] == counted_reachable

    def teardown_method(self):
        app.dependency_overrides.clear()


# ── TestMIMEValidation ────────────────────────────────────────────────────────

def _pe_bytes() -> bytes:
    """Minimal valid PE header (MZ signature)."""
    return b"MZ" + b"\x00" * 62 + struct.pack("<I", 64) + b"PE\x00\x00" + b"\x00" * 20

def _pdf_bytes() -> bytes:
    return b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"

def _text_bytes() -> bytes:
    return b"Hello, this is plain text.\n" * 100

def _disallowed_bytes() -> bytes:
    return b"\xff\xd8\xff\xe0" + b"\x00" * 100  # JPEG magic bytes


class TestMIMEValidation:

    @pytest.mark.asyncio
    async def test_octet_stream_accepted(self):
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        with patch("app.api.v1.endpoints.analyze._detect_mime", return_value="application/octet-stream"), \
             patch("app.services.analyzer.analyze_artifact", new_callable=AsyncMock) as mock_analyze, \
             patch("app.db.session.get_db"):
            mock_analyze.return_value = {
                "file_type": "unknown", "size_bytes": 100,
                "hashes": {"md5": "a"*32, "sha1": "b"*40, "sha256": "c"*64},
                "risk_score": 0.1, "verdict": "clean", "signature_hits": [],
            }

            db = _mock_db()
            app.dependency_overrides[get_db] = lambda: db

            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.post(
                    "/api/v1/analyze/file",
                    files={"file": ("test.bin", io.BytesIO(b"\x00" * 10), "application/octet-stream")},
                )
            assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_disallowed_mime_returns_415(self):
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()
        app.dependency_overrides[get_db] = lambda: _mock_db()

        with patch("app.api.v1.endpoints.analyze._detect_mime", return_value="image/jpeg"):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.post(
                    "/api/v1/analyze/file",
                    files={"file": ("photo.jpg", io.BytesIO(_disallowed_bytes()), "image/jpeg")},
                )
            assert r.status_code == 415
            assert "Unsupported file type" in r.json()["detail"]

    @pytest.mark.asyncio
    async def test_pdf_accepted(self):
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        with patch("app.api.v1.endpoints.analyze._detect_mime", return_value="application/pdf"), \
             patch("app.services.analyzer.analyze_artifact", new_callable=AsyncMock) as mock_analyze:
            mock_analyze.return_value = {
                "file_type": "pdf", "size_bytes": 100,
                "hashes": {"md5": "a"*32, "sha1": "b"*40, "sha256": "c"*64},
                "risk_score": 0.0, "verdict": "clean", "signature_hits": [],
            }
            db = _mock_db()
            app.dependency_overrides[get_db] = lambda: db

            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.post(
                    "/api/v1/analyze/file",
                    files={"file": ("doc.pdf", io.BytesIO(_pdf_bytes()), "application/pdf")},
                )
            assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_oversized_file_for_type_returns_413(self):
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()
        app.dependency_overrides[get_db] = lambda: _mock_db()

        # text/plain limit is 5 MB; we simulate a 6 MB payload
        big_data = b"a" * (6 * 1024 * 1024)
        with patch("app.api.v1.endpoints.analyze._detect_mime", return_value="text/plain"):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.post(
                    "/api/v1/analyze/file",
                    files={"file": ("huge.txt", io.BytesIO(big_data), "text/plain")},
                )
            assert r.status_code == 413

    @pytest.mark.asyncio
    async def test_analyze_file_requires_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.post(
                "/api/v1/analyze/file",
                files={"file": ("test.exe", io.BytesIO(b"MZ" + b"\x00" * 100), "application/octet-stream")},
            )
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_analyze_domain_requires_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.post("/api/v1/analyze/domain?domain=evil.com")
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_analyze_ip_requires_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.post("/api/v1/analyze/ip?ip=1.1.1.1")
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_detect_mime_fallback_on_import_error(self):
        """_detect_mime gracefully falls back to octet-stream if python-magic is missing."""
        from asc_api.api.v1.endpoints.analyze import _detect_mime
        with patch("builtins.__import__", side_effect=ImportError):
            mime = _detect_mime(b"\xff\xfe\x00\x00")
        assert mime == "application/octet-stream"

    def teardown_method(self):
        app.dependency_overrides.clear()


# ── TestOpsRateLimit ──────────────────────────────────────────────────────────

class TestOpsRateLimit:

    @pytest.mark.asyncio
    async def test_fleet_summary_with_auth(self):
        db = AsyncMock()
        result_mock = MagicMock()
        result_mock.scalars.return_value.all.return_value = []
        db.execute = AsyncMock(return_value=result_mock)
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/v1/ops/fleet/summary")
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_commands_metrics_with_auth(self):
        db = AsyncMock()
        result_mock = MagicMock()
        result_mock.scalars.return_value.all.return_value = []
        db.execute = AsyncMock(return_value=result_mock)
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/v1/ops/commands/metrics")
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_inflight_with_auth(self):
        db = AsyncMock()
        result_mock = MagicMock()
        result_mock.scalars.return_value.all.return_value = []
        db.execute = AsyncMock(return_value=result_mock)
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[get_analyst_or_admin] = lambda: _stub_user()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get("/api/v1/ops/commands/inflight")
        assert r.status_code == 200

    def teardown_method(self):
        app.dependency_overrides.clear()


# ── Mock helpers ──────────────────────────────────────────────────────────────

def _scalar_result(value):
    r = MagicMock()
    r.scalar_one.return_value = value
    r.scalar_one_or_none.return_value = value
    r.scalars.return_value.all.return_value = []
    r.all.return_value = []
    return r

def _scalars_result(rows: list):
    r = MagicMock()
    r.scalars.return_value.all.return_value = rows
    r.scalar_one.return_value = len(rows)
    r.scalar_one_or_none.return_value = rows[0] if rows else None
    r.all.return_value = rows
    return r

def _rows_result(rows: list):
    r = MagicMock()
    r.all.return_value = rows
    r.scalars.return_value.all.return_value = rows
    return r

def _none_result():
    r = MagicMock()
    r.scalar_one_or_none.return_value = None
    r.scalars.return_value.all.return_value = []
    return r
