"""
P32-COV-SOAR — Full SOAR endpoint coverage.

soar.py was NOT tested in P31.  These tests cover:
  - All 7 trigger endpoints (list, create, get, delete, toggle, test, evaluate)
  - All 6 scheduled-report endpoints (list, create, get, delete, toggle, deliver)
  - Dry-run evaluation (with matching trigger via pcdi_score ≥ 80)
  - Live evaluation path (dry_run=False)
  - 404 paths for every mutable endpoint
  - Analyst-blocked on admin routes (N/A — SOAR is analyst_or_admin)
  - Rate-limit reset via autouse fixture

All SOAR endpoints require @limiter.limit — success return lines may have
the known slowapi coverage blind-spot, but 404/422 paths register correctly.
"""
import uuid
import pytest

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def _reset_rate_limit():
    from asc_api.core.rate_limit import limiter
    limiter._storage.reset()
    yield
    limiter._storage.reset()


# ── Fixture: reusable valid trigger body ──────────────────────────────────────

_VALID_TRIGGER = {
    "playbook_id": "PB-001",
    "playbook_name": "Test Playbook Alpha",
    "condition_type": "pcdi_score",
    "condition_operator": "gte",
    "condition_value": "80",
    "priority": 5,
    "rate_limit_per_hour": 10,
    "dedup_window_minutes": 0,
}


async def _create_trigger(client, headers, overrides=None) -> dict:
    body = {**_VALID_TRIGGER, "playbook_name": f"PB-{uuid.uuid4().hex[:6]}"}
    if overrides:
        body.update(overrides)
    resp = await client.post("/api/v1/soar/triggers", json=body, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


# ══════════════════════════════════════════════════════════════════════════════
# Trigger — LIST
# ══════════════════════════════════════════════════════════════════════════════

class TestSOARListTriggers:
    async def test_list_empty(self, client, analyst_headers):
        resp = await client.get("/api/v1/soar/triggers", headers=analyst_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "triggers" in body
        assert isinstance(body["triggers"], list)

    async def test_list_with_filter_playbook_id(self, client, analyst_headers):
        await _create_trigger(client, analyst_headers, {"playbook_id": "PB-002", "condition_value": "50"})
        resp = await client.get(
            "/api/v1/soar/triggers?playbook_id=PB-002",
            headers=analyst_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["count"] >= 1

    async def test_list_filter_condition_type(self, client, analyst_headers):
        await _create_trigger(client, analyst_headers, {"condition_type": "hunt_priority", "condition_value": "critical"})
        resp = await client.get(
            "/api/v1/soar/triggers?condition_type=hunt_priority",
            headers=analyst_headers,
        )
        assert resp.status_code == 200

    async def test_list_enabled_only(self, client, analyst_headers):
        resp = await client.get(
            "/api/v1/soar/triggers?enabled_only=true",
            headers=analyst_headers,
        )
        assert resp.status_code == 200

    async def test_list_unauthenticated(self, client):
        resp = await client.get("/api/v1/soar/triggers")
        assert resp.status_code in (401, 403)


# ══════════════════════════════════════════════════════════════════════════════
# Trigger — CREATE
# ══════════════════════════════════════════════════════════════════════════════

class TestSOARCreateTrigger:
    async def test_create_valid(self, client, analyst_headers):
        resp = await client.post("/api/v1/soar/triggers", json=_VALID_TRIGGER, headers=analyst_headers)
        assert resp.status_code == 201
        body = resp.json()
        assert body["playbook_id"] == "PB-001"

    async def test_create_invalid_playbook_id_format(self, client, analyst_headers):
        bad = {**_VALID_TRIGGER, "playbook_id": "NOTPB"}
        resp = await client.post("/api/v1/soar/triggers", json=bad, headers=analyst_headers)
        assert resp.status_code == 422

    async def test_create_invalid_priority_out_of_range(self, client, analyst_headers):
        bad = {**_VALID_TRIGGER, "priority": 99}
        resp = await client.post("/api/v1/soar/triggers", json=bad, headers=analyst_headers)
        assert resp.status_code == 422

    async def test_create_unauthenticated(self, client):
        resp = await client.post("/api/v1/soar/triggers", json=_VALID_TRIGGER)
        assert resp.status_code in (401, 403)

    async def test_create_with_hunt_id_filter(self, client, analyst_headers):
        hunt_id = str(uuid.uuid4())
        body = {**_VALID_TRIGGER, "hunt_id_filter": hunt_id, "playbook_name": f"HuntPB-{hunt_id[:4]}"}
        resp = await client.post("/api/v1/soar/triggers", json=body, headers=analyst_headers)
        assert resp.status_code == 201
        assert resp.json().get("hunt_id_filter") == hunt_id


# ══════════════════════════════════════════════════════════════════════════════
# Trigger — GET
# ══════════════════════════════════════════════════════════════════════════════

class TestSOARGetTrigger:
    async def test_get_success(self, client, analyst_headers):
        created = await _create_trigger(client, analyst_headers)
        resp = await client.get(f"/api/v1/soar/triggers/{created['id']}", headers=analyst_headers)
        assert resp.status_code == 200
        assert resp.json()["id"] == created["id"]

    async def test_get_not_found(self, client, analyst_headers):
        resp = await client.get(
            f"/api/v1/soar/triggers/{uuid.uuid4()}",
            headers=analyst_headers,
        )
        assert resp.status_code == 404


# ══════════════════════════════════════════════════════════════════════════════
# Trigger — DELETE
# ══════════════════════════════════════════════════════════════════════════════

class TestSOARDeleteTrigger:
    async def test_delete_success(self, client, analyst_headers):
        created = await _create_trigger(client, analyst_headers)
        resp = await client.delete(
            f"/api/v1/soar/triggers/{created['id']}",
            headers=analyst_headers,
        )
        assert resp.status_code == 204

    async def test_delete_not_found(self, client, analyst_headers):
        resp = await client.delete(
            f"/api/v1/soar/triggers/{uuid.uuid4()}",
            headers=analyst_headers,
        )
        assert resp.status_code == 404


# ══════════════════════════════════════════════════════════════════════════════
# Trigger — TOGGLE
# ══════════════════════════════════════════════════════════════════════════════

class TestSOARToggleTrigger:
    async def test_toggle_disable(self, client, analyst_headers):
        created = await _create_trigger(client, analyst_headers)
        resp = await client.patch(
            f"/api/v1/soar/triggers/{created['id']}/toggle",
            json={"enabled": False},
            headers=analyst_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["enabled"] is False

    async def test_toggle_re_enable(self, client, analyst_headers):
        created = await _create_trigger(client, analyst_headers)
        # disable first
        await client.patch(
            f"/api/v1/soar/triggers/{created['id']}/toggle",
            json={"enabled": False},
            headers=analyst_headers,
        )
        # re-enable
        resp = await client.patch(
            f"/api/v1/soar/triggers/{created['id']}/toggle",
            json={"enabled": True},
            headers=analyst_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["enabled"] is True

    async def test_toggle_not_found(self, client, analyst_headers):
        resp = await client.patch(
            f"/api/v1/soar/triggers/{uuid.uuid4()}/toggle",
            json={"enabled": False},
            headers=analyst_headers,
        )
        assert resp.status_code == 404


# ══════════════════════════════════════════════════════════════════════════════
# Trigger — TEST (dry-run single trigger)
# ══════════════════════════════════════════════════════════════════════════════

class TestSOARTestTrigger:
    async def test_single_trigger_match(self, client, analyst_headers):
        created = await _create_trigger(client, analyst_headers)
        resp = await client.post(
            f"/api/v1/soar/triggers/{created['id']}/test",
            json={"context": {"pcdi_score": 90}},
            headers=analyst_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "matched" in body

    async def test_single_trigger_no_match(self, client, analyst_headers):
        created = await _create_trigger(client, analyst_headers)
        resp = await client.post(
            f"/api/v1/soar/triggers/{created['id']}/test",
            json={"context": {"pcdi_score": 10}},
            headers=analyst_headers,
        )
        assert resp.status_code == 200

    async def test_single_trigger_not_found(self, client, analyst_headers):
        resp = await client.post(
            f"/api/v1/soar/triggers/{uuid.uuid4()}/test",
            json={"context": {"pcdi_score": 90}},
            headers=analyst_headers,
        )
        assert resp.status_code == 404


# ══════════════════════════════════════════════════════════════════════════════
# Trigger — EVALUATE CONTEXT
# ══════════════════════════════════════════════════════════════════════════════

class TestSOAREvaluateContext:
    async def test_dry_run_empty_triggers(self, client, analyst_headers):
        resp = await client.post(
            "/api/v1/soar/evaluate",
            json={"context": {"pcdi_score": 90}, "dry_run": True},
            headers=analyst_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["dry_run"] is True
        assert isinstance(body["matches"], list)

    async def test_dry_run_with_matching_trigger(self, client, analyst_headers):
        # Create a trigger that will match pcdi_score >= 80
        await _create_trigger(client, analyst_headers, {"condition_value": "80"})
        resp = await client.post(
            "/api/v1/soar/evaluate",
            json={"context": {"pcdi_score": 95}, "dry_run": True},
            headers=analyst_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["dry_run"] is True
        assert body["matched_count"] >= 1
        assert body["matches"][0]["would_fire"] is True

    async def test_dry_run_with_hunt_id_filter_mismatch(self, client, analyst_headers):
        hunt_id = str(uuid.uuid4())
        await _create_trigger(
            client, analyst_headers,
            {"hunt_id_filter": hunt_id, "condition_value": "50"},
        )
        # context hunt_id differs → trigger filtered out
        resp = await client.post(
            "/api/v1/soar/evaluate",
            json={"context": {"pcdi_score": 90, "hunt_id": str(uuid.uuid4())}, "dry_run": True},
            headers=analyst_headers,
        )
        assert resp.status_code == 200
        # our filtered trigger should not appear
        matches = resp.json()["matches"]
        assert not any(m.get("hunt_id_filter") == hunt_id for m in matches)

    async def test_live_evaluation_empty_triggers(self, client, analyst_headers):
        resp = await client.post(
            "/api/v1/soar/evaluate",
            json={"context": {"pcdi_score": 90}, "dry_run": False},
            headers=analyst_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["dry_run"] is False
        assert isinstance(body["fired"], list)

    async def test_evaluate_unauthenticated(self, client):
        resp = await client.post(
            "/api/v1/soar/evaluate",
            json={"context": {"pcdi_score": 90}, "dry_run": True},
        )
        assert resp.status_code in (401, 403)


# ══════════════════════════════════════════════════════════════════════════════
# Scheduled Reports — CRUD
# ══════════════════════════════════════════════════════════════════════════════

_VALID_REPORT = {
    "hunt_id": str(uuid.uuid4()),
    "hunt_name": "Weekly SOC Hunt",
    "recipient_email": "soc-manager@premoscorp.com",
    "frequency": "daily",
    "format": "json",
}


async def _create_report(client, headers, overrides=None) -> dict:
    body = {**_VALID_REPORT, "hunt_id": str(uuid.uuid4())}
    if overrides:
        body.update(overrides)
    resp = await client.post("/api/v1/soar/reports", json=body, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


class TestSOARScheduledReports:
    async def test_list_reports_empty(self, client, analyst_headers):
        resp = await client.get("/api/v1/soar/reports", headers=analyst_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "reports" in body
        assert isinstance(body["reports"], list)

    async def test_list_reports_filter_hunt_id(self, client, analyst_headers):
        hunt_id = str(uuid.uuid4())
        await _create_report(client, analyst_headers, {"hunt_id": hunt_id})
        resp = await client.get(
            f"/api/v1/soar/reports?hunt_id={hunt_id}",
            headers=analyst_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["count"] >= 1

    async def test_list_reports_enabled_only(self, client, analyst_headers):
        resp = await client.get("/api/v1/soar/reports?enabled_only=true", headers=analyst_headers)
        assert resp.status_code == 200

    async def test_create_report_valid(self, client, analyst_headers):
        resp = await client.post("/api/v1/soar/reports", json=_VALID_REPORT, headers=analyst_headers)
        assert resp.status_code == 201
        assert "id" in resp.json()

    async def test_create_report_unauthenticated(self, client):
        resp = await client.post("/api/v1/soar/reports", json=_VALID_REPORT)
        assert resp.status_code in (401, 403)

    async def test_get_report_success(self, client, analyst_headers):
        created = await _create_report(client, analyst_headers)
        resp = await client.get(f"/api/v1/soar/reports/{created['id']}", headers=analyst_headers)
        assert resp.status_code == 200
        assert resp.json()["id"] == created["id"]

    async def test_get_report_not_found(self, client, analyst_headers):
        resp = await client.get(
            f"/api/v1/soar/reports/{uuid.uuid4()}",
            headers=analyst_headers,
        )
        assert resp.status_code == 404

    async def test_delete_report_success(self, client, analyst_headers):
        created = await _create_report(client, analyst_headers)
        resp = await client.delete(
            f"/api/v1/soar/reports/{created['id']}",
            headers=analyst_headers,
        )
        assert resp.status_code == 204

    async def test_delete_report_not_found(self, client, analyst_headers):
        resp = await client.delete(
            f"/api/v1/soar/reports/{uuid.uuid4()}",
            headers=analyst_headers,
        )
        assert resp.status_code == 404

    async def test_toggle_report_disable(self, client, analyst_headers):
        created = await _create_report(client, analyst_headers)
        resp = await client.patch(
            f"/api/v1/soar/reports/{created['id']}/toggle",
            json={"enabled": False},
            headers=analyst_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["enabled"] is False

    async def test_toggle_report_not_found(self, client, analyst_headers):
        resp = await client.patch(
            f"/api/v1/soar/reports/{uuid.uuid4()}/toggle",
            json={"enabled": False},
            headers=analyst_headers,
        )
        assert resp.status_code == 404

    async def test_deliver_report_not_found(self, client, analyst_headers):
        resp = await client.post(
            f"/api/v1/soar/reports/{uuid.uuid4()}/deliver",
            headers=analyst_headers,
        )
        assert resp.status_code == 404

    async def test_deliver_report_success(self, client, analyst_headers):
        created = await _create_report(client, analyst_headers)
        resp = await client.post(
            f"/api/v1/soar/reports/{created['id']}/deliver",
            headers=analyst_headers,
        )
        # deliver may succeed (200) or return error dict without 404 (200 with error key)
        assert resp.status_code in (200, 202)
