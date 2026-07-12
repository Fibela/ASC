"""
P31-COV Extra â€” Additional endpoint coverage targeting miss lines in:
  iocs.py, alerts.py, detection.py, iam.py, metrics.py, notifications.py, forensic.py
"""
import uuid
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.main import app
from asc_api.models.ioc import IoC
from asc_api.models.alert import Alert
from asc_api.models.detection_rule import DetectionRule


pytestmark = pytest.mark.asyncio


# â”€â”€â”€ Rate limit reset (all tests) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@pytest.fixture(autouse=True)
def _reset_rate_limit():
    from asc_api.core.rate_limit import limiter
    limiter._storage.reset()
    yield
    limiter._storage.reset()


# â”€â”€â”€ IoC Endpoints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestIoCEndpoints:
    async def test_create_ioc_returns_201(self, client, analyst_headers):
        resp = await client.post(
            "/api/v1/iocs",
            json={"value": "192.168.1.100", "ioc_type": "ip"},
            headers=analyst_headers,
        )
        assert resp.status_code == 201
        body = resp.json()
        assert "id" in body
        assert body["value"] == "192.168.1.100"
        assert body["type"] == "ip"

    async def test_create_ioc_viewer_blocked(self, client, viewer_headers):
        resp = await client.post(
            "/api/v1/iocs",
            json={"value": "10.0.0.1", "ioc_type": "ip"},
            headers=viewer_headers,
        )
        assert resp.status_code == 403

    async def test_bulk_create_iocs_returns_count(self, client, admin_headers):
        resp = await client.post(
            "/api/v1/iocs/bulk",
            json={"iocs": [
                {"value": "evil.com", "ioc_type": "domain"},
                {"value": "bad.exe", "ioc_type": "hash_md5"},
            ]},
            headers=admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["created"] == 2
        assert body["total_submitted"] == 2

    async def test_bulk_create_iocs_skips_duplicate(self, client, admin_headers, db):
        existing = IoC(
            id=str(uuid.uuid4()), value="dupe.com",
            ioc_type="domain", source="internal",
        )
        db.add(existing)
        await db.commit()

        resp = await client.post(
            "/api/v1/iocs/bulk",
            json={"iocs": [
                {"value": "dupe.com", "ioc_type": "domain"},
                {"value": "new-domain.com", "ioc_type": "domain"},
            ]},
            headers=admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["created"] == 1
        assert body["total_submitted"] == 2

    async def test_list_iocs_returns_list(self, client, viewer_headers):
        resp = await client.get("/api/v1/iocs", headers=viewer_headers)
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    async def test_list_iocs_with_type_filter(self, client, analyst_headers, db):
        db.add(IoC(id=str(uuid.uuid4()), value="1.2.3.4", ioc_type="ip", source="internal"))
        db.add(IoC(id=str(uuid.uuid4()), value="bad.com", ioc_type="domain", source="internal"))
        await db.commit()

        resp = await client.get("/api/v1/iocs?ioc_type=ip", headers=analyst_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert all(i["type"] == "ip" for i in data)

    async def test_list_iocs_inactive_filter(self, client, analyst_headers, db):
        db.add(IoC(
            id=str(uuid.uuid4()), value="old.com",
            ioc_type="domain", source="internal", active=False,
        ))
        await db.commit()

        resp = await client.get("/api/v1/iocs?active=false", headers=analyst_headers)
        assert resp.status_code == 200

    async def test_search_ioc_returns_results(self, client, viewer_headers, db):
        db.add(IoC(
            id=str(uuid.uuid4()), value="malicious.example.com",
            ioc_type="domain", source="internal",
        ))
        await db.commit()

        resp = await client.get("/api/v1/iocs/search?value=malicious", headers=viewer_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) >= 1
        assert data[0]["value"] == "malicious.example.com"

    async def test_search_ioc_empty_results(self, client, viewer_headers):
        resp = await client.get("/api/v1/iocs/search?value=notfound12345xyz", headers=viewer_headers)
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_deactivate_ioc_success(self, client, analyst_headers, db):
        ioc_id = str(uuid.uuid4())
        db.add(IoC(id=ioc_id, value="tobedeleted.com", ioc_type="domain", source="internal"))
        await db.commit()

        resp = await client.delete(f"/api/v1/iocs/{ioc_id}", headers=analyst_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "deactivated"
        assert body["id"] == ioc_id

    async def test_deactivate_ioc_not_found(self, client, analyst_headers):
        resp = await client.delete(f"/api/v1/iocs/{uuid.uuid4()}", headers=analyst_headers)
        assert resp.status_code == 404

    async def test_deactivate_ioc_viewer_blocked(self, client, viewer_headers):
        resp = await client.delete(f"/api/v1/iocs/{uuid.uuid4()}", headers=viewer_headers)
        assert resp.status_code == 403


# â”€â”€â”€ Alert Endpoints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestAlertEndpointsExtra:
    def _make_alert(self, **overrides) -> Alert:
        return Alert(**{
            "id": str(uuid.uuid4()),
            "title": "Test Alert",
            "description": "Test description",
            "severity": "high",
            "risk_score": 0.8,
            **overrides,
        })

    async def test_alert_stats_empty_db(self, client, viewer_headers):
        resp = await client.get("/api/v1/alerts/stats/summary", headers=viewer_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 0
        assert body["false_positive_rate"] == 0.0

    async def test_alert_stats_with_data(self, client, analyst_headers, db):
        db.add(self._make_alert(severity="critical", status="open"))
        db.add(self._make_alert(severity="high", status="open", false_positive=True))
        await db.commit()

        resp = await client.get("/api/v1/alerts/stats/summary", headers=analyst_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 2
        assert body["critical"] == 1
        assert body["false_positive_rate"] > 0.0

    async def test_get_alert_by_id_not_found(self, client, viewer_headers):
        resp = await client.get(f"/api/v1/alerts/{uuid.uuid4()}", headers=viewer_headers)
        assert resp.status_code == 404

    async def test_get_alert_by_id_success(self, client, viewer_headers, db):
        alert = self._make_alert()
        db.add(alert)
        await db.commit()

        resp = await client.get(f"/api/v1/alerts/{alert.id}", headers=viewer_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["id"] == alert.id
        assert body["title"] == "Test Alert"

    async def test_update_alert_not_found(self, client, analyst_headers):
        resp = await client.patch(
            f"/api/v1/alerts/{uuid.uuid4()}",
            json={"status": "resolved"},
            headers=analyst_headers,
        )
        assert resp.status_code == 404

    async def test_update_alert_resolve(self, client, analyst_headers, db):
        alert = self._make_alert()
        db.add(alert)
        await db.commit()

        resp = await client.patch(
            f"/api/v1/alerts/{alert.id}",
            json={"status": "resolved"},
            headers=analyst_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "resolved"
        assert body["resolved_at"] is not None

    async def test_update_alert_false_positive(self, client, analyst_headers, db):
        alert = self._make_alert()
        db.add(alert)
        await db.commit()

        resp = await client.patch(
            f"/api/v1/alerts/{alert.id}",
            json={"false_positive": True, "status": "false_positive"},
            headers=analyst_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["false_positive"] is True

    async def test_update_alert_investigating(self, client, analyst_headers, db):
        alert = self._make_alert()
        db.add(alert)
        await db.commit()

        resp = await client.patch(
            f"/api/v1/alerts/{alert.id}",
            json={"status": "investigating", "analyst_notes": "under review"},
            headers=analyst_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "investigating"
        assert body["acknowledged_at"] is not None

    async def test_update_alert_assign_and_notes(self, client, analyst_headers, db):
        alert = self._make_alert()
        db.add(alert)
        await db.commit()

        resp = await client.patch(
            f"/api/v1/alerts/{alert.id}",
            json={"assigned_to": "analyst@premoscorp.com", "analyst_notes": "assigned"},
            headers=analyst_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["assigned_to"] == "analyst@premoscorp.com"

    async def test_update_alert_viewer_blocked(self, client, viewer_headers, db):
        alert = self._make_alert()
        db.add(alert)
        await db.commit()

        resp = await client.patch(
            f"/api/v1/alerts/{alert.id}",
            json={"status": "resolved"},
            headers=viewer_headers,
        )
        assert resp.status_code == 403

    async def test_list_alerts_with_severity_filter(self, client, viewer_headers, db):
        db.add(self._make_alert(severity="critical"))
        db.add(self._make_alert(severity="low"))
        await db.commit()

        resp = await client.get("/api/v1/alerts?severity=critical", headers=viewer_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert all(a["severity"] == "critical" for a in data)

    async def test_list_alerts_with_status_filter(self, client, viewer_headers, db):
        db.add(self._make_alert(status="resolved"))
        db.add(self._make_alert(status="open"))
        await db.commit()

        resp = await client.get("/api/v1/alerts?status=resolved", headers=viewer_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert all(a["status"] == "resolved" for a in data)


# â”€â”€â”€ Detection Endpoints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

_DET_RULES = [
    ("DET-001", "Suspicious acord32.exe Execution", "T1036.005", "critical/high", 0.88),
    ("DET-002", "Windows Hook API Detected",         "T1056.001", "critical/medium", 0.80),
    ("DET-003", "Registry Persistence Mechanism",    "T1547.001", "high",            0.75),
    ("DET-004", "Deferred Network Traffic",          "T1071.001", "critical/high",   0.82),
]


@pytest_asyncio.fixture
async def seeded_detection_rules(db: AsyncSession):
    """Seed DET-001…DET-004 into the in-memory test DB (migration data not applied in tests)."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    for rule_id, name, ttp, severity, score in _DET_RULES:
        db.add(DetectionRule(
            id=str(uuid.uuid4()), rule_id=rule_id, name=name,
            mitre_ttp=ttp, severity=severity, description=name,
            tags=[], risk_score_default=score, is_active=True,
            created_at=now, updated_at=now,
        ))
    await db.commit()


class TestDetectionEndpoints:
    async def test_list_rules_returns_4_rules(self, client, viewer_headers, seeded_detection_rules):
        resp = await client.get("/api/v1/detection/rules", headers=viewer_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["rules"]) == 4
        rule_ids = {r["rule_id"] for r in body["rules"]}
        assert rule_ids == {"DET-001", "DET-002", "DET-003", "DET-004"}

    async def test_list_rules_fingerprint_checks_present(self, client, analyst_headers):
        resp = await client.get("/api/v1/detection/rules", headers=analyst_headers)
        assert resp.status_code == 200
        assert "fingerprint_checks" in resp.json()

    async def test_evaluate_single_event_success(self, client, analyst_headers):
        resp = await client.post(
            "/api/v1/detection/evaluate",
            json={"host": "testhost", "process": "explorer.exe"},
            headers=analyst_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "total" in body
        assert "results" in body
        assert isinstance(body["results"], list)

    async def test_evaluate_single_event_with_valid_ts(self, client, analyst_headers):
        resp = await client.post(
            "/api/v1/detection/evaluate?original_analysis_ts=2026-06-01T10:00:00Z",
            json={"host": "host-a", "process": "cmd.exe", "action": "process_create"},
            headers=analyst_headers,
        )
        assert resp.status_code == 200

    async def test_evaluate_single_event_invalid_timestamp(self, client, analyst_headers):
        resp = await client.post(
            "/api/v1/detection/evaluate?original_analysis_ts=not-a-date",
            json={"host": "host-b"},
            headers=analyst_headers,
        )
        assert resp.status_code == 422

    async def test_evaluate_bulk_events_success(self, client, analyst_headers):
        resp = await client.post(
            "/api/v1/detection/evaluate/bulk",
            json={"events": [
                {"host": "host1", "process": "svchost.exe"},
                {"host": "host2", "action": "network_connect", "dst_ip": "10.0.0.1"},
            ]},
            headers=analyst_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "total" in body
        assert "events_submitted" in body
        assert body["events_submitted"] == 2

    async def test_evaluate_bulk_too_few_events(self, client, analyst_headers):
        resp = await client.post(
            "/api/v1/detection/evaluate/bulk",
            json={"events": []},
            headers=analyst_headers,
        )
        assert resp.status_code == 422

    async def test_fingerprint_artifact_too_large(self, client, analyst_headers):
        # 131073 hex chars = just over 64KB
        big_hex = "aa" * 65537
        resp = await client.post(
            "/api/v1/detection/fingerprint",
            json={"filename": "malware.exe", "data_hex": big_hex},
            headers=analyst_headers,
        )
        assert resp.status_code == 413

    async def test_fingerprint_artifact_invalid_hex(self, client, analyst_headers):
        resp = await client.post(
            "/api/v1/detection/fingerprint",
            json={"filename": "file.exe", "data_hex": "zzznotvalidhex"},
            headers=analyst_headers,
        )
        assert resp.status_code == 422

    async def test_fingerprint_artifact_valid_hex(self, client, analyst_headers):
        resp = await client.post(
            "/api/v1/detection/fingerprint",
            json={"filename": "sample.exe", "data_hex": "deadbeef"},
            headers=analyst_headers,
        )
        assert resp.status_code == 200

    async def test_detection_viewer_blocked_from_evaluate(self, client, viewer_headers):
        resp = await client.post(
            "/api/v1/detection/evaluate",
            json={"host": "host1"},
            headers=viewer_headers,
        )
        assert resp.status_code == 403

    async def test_detection_unauthenticated(self, client):
        resp = await client.get("/api/v1/detection/rules")
        assert resp.status_code in (401, 403)


# â”€â”€â”€ IAM Endpoints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestIAMEndpoints:
    async def test_user_iam_status_not_found(self, client, admin_headers):
        resp = await client.get(
            "/api/v1/iam/users/nobody@test.com/status",
            headers=admin_headers,
        )
        assert resp.status_code == 404

    async def test_user_iam_status_success(self, client, admin_headers, analyst_user):
        resp = await client.get(
            f"/api/v1/iam/users/{analyst_user.email}/status",
            headers=admin_headers,
        )
        assert resp.status_code == 200

    async def test_lock_user_not_found(self, client, admin_headers):
        resp = await client.post(
            "/api/v1/iam/users/nobody@test.com/lock",
            json={"minutes": 15},
            headers=admin_headers,
        )
        assert resp.status_code == 404

    async def test_lock_user_success(self, client, admin_headers, analyst_user):
        resp = await client.post(
            f"/api/v1/iam/users/{analyst_user.email}/lock",
            json={"minutes": 30},
            headers=admin_headers,
        )
        assert resp.status_code == 200
        assert "message" in resp.json()

    async def test_lock_user_default_minutes(self, client, admin_headers, analyst_user):
        # No body â†’ uses default LockRequest (15 minutes)
        resp = await client.post(
            f"/api/v1/iam/users/{analyst_user.email}/lock",
            headers=admin_headers,
        )
        assert resp.status_code == 200

    async def test_unlock_user_not_found(self, client, admin_headers):
        resp = await client.post(
            "/api/v1/iam/users/nobody@test.com/unlock",
            headers=admin_headers,
        )
        assert resp.status_code == 404

    async def test_unlock_user_success(self, client, admin_headers, analyst_user):
        resp = await client.post(
            f"/api/v1/iam/users/{analyst_user.email}/unlock",
            headers=admin_headers,
        )
        assert resp.status_code == 200
        assert "message" in resp.json()

    async def test_disable_user_self_not_allowed(self, client, admin_headers, admin_user):
        resp = await client.post(
            f"/api/v1/iam/users/{admin_user.email}/disable",
            headers=admin_headers,
        )
        assert resp.status_code == 422

    async def test_disable_user_not_found(self, client, admin_headers):
        resp = await client.post(
            "/api/v1/iam/users/nobody@test.com/disable",
            headers=admin_headers,
        )
        assert resp.status_code == 404

    async def test_disable_user_success(self, client, admin_headers, analyst_user):
        resp = await client.post(
            f"/api/v1/iam/users/{analyst_user.email}/disable",
            headers=admin_headers,
        )
        assert resp.status_code == 200
        assert "message" in resp.json()

    async def test_enable_user_not_found(self, client, admin_headers):
        resp = await client.post(
            "/api/v1/iam/users/nobody@test.com/enable",
            headers=admin_headers,
        )
        assert resp.status_code == 404

    async def test_enable_user_success(self, client, admin_headers, analyst_user):
        resp = await client.post(
            f"/api/v1/iam/users/{analyst_user.email}/enable",
            headers=admin_headers,
        )
        assert resp.status_code == 200

    async def test_force_reset_user_not_found(self, client, admin_headers):
        resp = await client.post(
            "/api/v1/iam/users/nobody@test.com/force-reset",
            headers=admin_headers,
        )
        assert resp.status_code == 404

    async def test_force_reset_user_success(self, client, admin_headers, analyst_user):
        resp = await client.post(
            f"/api/v1/iam/users/{analyst_user.email}/force-reset",
            headers=admin_headers,
        )
        assert resp.status_code == 200

    async def test_purge_expired_tokens(self, client, admin_headers):
        resp = await client.delete(
            "/api/v1/iam/tokens/purge",
            headers=admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "purged" in body
        assert "l1_cache_size" in body

    async def test_rotate_analyst_keys_not_found(self, client, admin_headers):
        resp = await client.post(
            "/api/v1/iam/users/nobody@test.com/rotate-keys",
            headers=admin_headers,
        )
        assert resp.status_code == 404

    async def test_rotate_analyst_keys_success(self, client, admin_headers, analyst_user):
        resp = await client.post(
            f"/api/v1/iam/users/{analyst_user.email}/rotate-keys",
            headers=admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "public_key" in body

    async def test_iam_analyst_blocked(self, client, analyst_headers):
        resp = await client.get(
            "/api/v1/iam/users/any@test.com/status",
            headers=analyst_headers,
        )
        assert resp.status_code == 403

    async def test_iam_unauthenticated_blocked(self, client):
        resp = await client.get("/api/v1/iam/users/any@test.com/status")
        assert resp.status_code in (401, 403)


# â”€â”€â”€ Metrics Endpoints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestMetricsEndpoints:
    def _make_alert(self, **overrides) -> Alert:
        return Alert(**{
            "id": str(uuid.uuid4()),
            "title": "Metric Test Alert",
            "description": "Metric test",
            "severity": "high",
            "risk_score": 0.7,
            **overrides,
        })

    async def test_public_metrics_no_auth_required(self, client):
        resp = await client.get("/api/v1/metrics/public")
        assert resp.status_code == 200
        body = resp.json()
        # FASE 0.5: public endpoint returns only operational status
        assert body["status"] == "operational"
        assert body["uptime"] is True
        assert "as_of" in body

    async def test_public_metrics_does_not_leak_kpis(self, client):
        resp = await client.get("/api/v1/metrics/public")
        assert resp.status_code == 200
        body = resp.json()
        for field in ("mttd_minutes", "risk_posture", "ioc_coverage", "false_positive_rate"):
            assert field not in body

    async def test_soc_metrics_empty_db(self, client, admin_headers):
        resp = await client.get("/api/v1/metrics/soc", headers=admin_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["total_alerts"] == 0
        assert body["false_positive_rate"] == 0.0
        assert body["risk_posture"] == "NORMAL"

    async def test_soc_metrics_critical_posture(self, client, admin_headers, db):
        db.add(self._make_alert(severity="critical"))
        await db.commit()

        resp = await client.get("/api/v1/metrics/soc?hours=8760", headers=admin_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["by_severity"]["critical"] >= 1
        assert body["risk_posture"] == "CRITICAL"

    async def test_soc_metrics_high_posture(self, client, admin_headers, db):
        # >3 high-severity alerts â†’ HIGH posture
        for _ in range(4):
            db.add(self._make_alert(severity="high"))
        await db.commit()

        resp = await client.get("/api/v1/metrics/soc?hours=8760", headers=admin_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["risk_posture"] == "HIGH"

    async def test_soc_metrics_false_positive_rate(self, client, analyst_headers, db):
        db.add(self._make_alert(false_positive=True))
        db.add(self._make_alert(false_positive=False))
        await db.commit()

        resp = await client.get("/api/v1/metrics/soc?hours=8760", headers=analyst_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["false_positive_rate"] == 0.5

    async def test_performance_metrics(self, client, admin_headers):
        resp = await client.get("/api/v1/metrics/performance", headers=admin_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "mttd" in body
        assert "mtta" in body
        assert "mttr" in body
        assert "by_severity" in body
        assert "status_funnel" in body
        assert "daily_trend" in body

    async def test_performance_metrics_custom_window(self, client, admin_headers):
        resp = await client.get(
            "/api/v1/metrics/performance?hours=48&trend_days=3",
            headers=admin_headers,
        )
        assert resp.status_code == 200

    async def test_timeline_empty_db(self, client, admin_headers):
        resp = await client.get("/api/v1/metrics/timeline", headers=admin_headers)
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)
        assert len(resp.json()) == 0

    async def test_timeline_custom_bucket(self, client, analyst_headers):
        resp = await client.get(
            "/api/v1/metrics/timeline?hours=12&bucket_minutes=30",
            headers=analyst_headers,
        )
        assert resp.status_code == 200

    async def test_metrics_unauthenticated_blocked(self, client):
        resp = await client.get("/api/v1/metrics/soc")
        assert resp.status_code in (401, 403)


# â”€â”€â”€ Notifications Endpoints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestNotificationsEndpoints:
    async def test_notification_status_returns_subscriber_count(self, client, analyst_headers):
        resp = await client.get(
            "/api/v1/notifications/status",
            headers=analyst_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "subscribers" in body
        assert "heartbeat_interval_s" in body
        assert body["heartbeat_interval_s"] == 30

    async def test_notification_status_admin_can_access(self, client, admin_headers):
        resp = await client.get(
            "/api/v1/notifications/status",
            headers=admin_headers,
        )
        assert resp.status_code == 200

    async def test_notification_status_viewer_blocked(self, client, viewer_headers):
        resp = await client.get(
            "/api/v1/notifications/status",
            headers=viewer_headers,
        )
        assert resp.status_code == 403

    async def test_notification_stream_unauthenticated_blocked(self, client):
        resp = await client.get("/api/v1/notifications/stream")
        assert resp.status_code in (401, 403)

    async def test_notification_stream_viewer_blocked(self, client, viewer_headers):
        resp = await client.get(
            "/api/v1/notifications/stream",
            headers=viewer_headers,
        )
        assert resp.status_code == 403


# â”€â”€â”€ Forensic Endpoints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestForensicEndpoints:
    async def test_get_forensic_proof_not_found(self, client, analyst_headers):
        resp = await client.get(
            f"/api/v1/forensic/actions/{uuid.uuid4()}",
            headers=analyst_headers,
        )
        assert resp.status_code == 404

    async def test_get_forensic_proof_viewer_can_access(self, client, viewer_headers):
        # get_current_user (any role) â€” viewer gets 404, not 403
        resp = await client.get(
            f"/api/v1/forensic/actions/{uuid.uuid4()}",
            headers=viewer_headers,
        )
        assert resp.status_code == 404

    async def test_get_forensic_proof_unauthenticated_blocked(self, client):
        resp = await client.get(f"/api/v1/forensic/actions/{uuid.uuid4()}")
        assert resp.status_code in (401, 403)

    async def test_verify_forensic_proof_not_found(self, client, analyst_headers):
        resp = await client.post(
            f"/api/v1/forensic/actions/{uuid.uuid4()}/verify",
            headers=analyst_headers,
        )
        assert resp.status_code == 404

    async def test_verify_forensic_proof_viewer_can_access(self, client, viewer_headers):
        resp = await client.post(
            f"/api/v1/forensic/actions/{uuid.uuid4()}/verify",
            headers=viewer_headers,
        )
        assert resp.status_code == 404

    async def test_list_forensic_ledger_empty(self, client, admin_headers):
        resp = await client.get(
            "/api/v1/forensic/ledger",
            headers=admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 0
        assert body["entries"] == []
        assert "limit" in body
        assert "offset" in body

    async def test_list_forensic_ledger_admin_only(self, client, analyst_headers):
        resp = await client.get(
            "/api/v1/forensic/ledger",
            headers=analyst_headers,
        )
        assert resp.status_code == 403

    async def test_list_forensic_ledger_viewer_blocked(self, client, viewer_headers):
        resp = await client.get(
            "/api/v1/forensic/ledger",
            headers=viewer_headers,
        )
        assert resp.status_code == 403
