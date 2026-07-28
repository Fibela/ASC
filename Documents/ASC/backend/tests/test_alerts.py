"""
test_alerts.py â€” Tech Debt P2: Alert CRUD endpoints + JWT auth enforcement

Tests:
  TestAlertAuth         (6)  â€” all endpoints reject unauthenticated requests
  TestAlertList         (6)  â€” GET /alerts/ pagination, filtering, auth levels
  TestAlertGet          (4)  â€” GET /alerts/{id} happy + 404
  TestAlertPatch        (10) â€” PATCH /alerts/{id}: status transitions, MTTA
                               timestamps, role enforcement, 404
  TestAlertStats        (4)  â€” GET /alerts/stats/summary counts
"""
from __future__ import annotations

import uuid
import pytest
from datetime import datetime, timezone, timedelta
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.models.alert import Alert


# â”€â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _make_alert(
    severity: str = "high",
    status: str = "open",
    risk_score: float = 0.75,
    threat_start_offset_m: int | None = 30,
) -> Alert:
    now = datetime.now(timezone.utc)
    return Alert(
        id=str(uuid.uuid4()),
        title=f"Test Alert [{severity}]",
        description="Automated test alert",
        severity=severity,
        status=status,
        risk_score=risk_score,
        source_events=[],
        matched_iocs=[],
        affected_hosts=["PREMOS-WS-01"],
        ttps=["T1110"],
        recommended_actions=["isolate_host"],
        threat_start_at=now - timedelta(minutes=threat_start_offset_m) if threat_start_offset_m else None,
        detected_at=now,
    )


async def _seed_alert(db: AsyncSession, **kwargs) -> Alert:
    alert = _make_alert(**kwargs)
    db.add(alert)
    await db.commit()
    await db.refresh(alert)
    return alert


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 1. Authentication enforcement (TD2 fix)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
class TestAlertAuth:
    """Every alert endpoint must reject unauthenticated requests."""

    async def test_list_requires_auth(self, client: AsyncClient):
        resp = await client.get("/api/v1/alerts")
        assert resp.status_code in (401, 403)

    async def test_get_requires_auth(self, client: AsyncClient):
        resp = await client.get("/api/v1/alerts/nonexistent-id")
        assert resp.status_code in (401, 403)

    async def test_patch_requires_auth(self, client: AsyncClient):
        resp = await client.patch("/api/v1/alerts/nonexistent-id", json={"status": "resolved"})
        assert resp.status_code in (401, 403)

    async def test_stats_requires_auth(self, client: AsyncClient):
        resp = await client.get("/api/v1/alerts/stats/summary")
        assert resp.status_code in (401, 403)

    async def test_patch_viewer_forbidden(self, client: AsyncClient, viewer_headers: dict, db: AsyncSession):
        """Viewer role must not be able to modify alerts â€” analyst_or_admin required."""
        alert = await _seed_alert(db)
        resp = await client.patch(
            f"/api/v1/alerts/{alert.id}",
            json={"status": "investigating"},
            headers=viewer_headers,
        )
        assert resp.status_code == 403

    async def test_patch_analyst_allowed(self, client: AsyncClient, analyst_headers: dict, db: AsyncSession):
        """Analyst role can update alert status."""
        alert = await _seed_alert(db)
        resp = await client.patch(
            f"/api/v1/alerts/{alert.id}",
            json={"status": "investigating"},
            headers=analyst_headers,
        )
        assert resp.status_code == 200


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 2. GET /alerts/  â€” list with filtering
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
class TestAlertList:

    async def test_empty_db_returns_empty_list(self, client: AsyncClient, viewer_headers: dict):
        resp = await client.get("/api/v1/alerts", headers=viewer_headers)
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_list_returns_seeded_alerts(
        self, client: AsyncClient, viewer_headers: dict, db: AsyncSession
    ):
        await _seed_alert(db, severity="critical")
        await _seed_alert(db, severity="high")
        resp = await client.get("/api/v1/alerts", headers=viewer_headers)
        assert resp.status_code == 200
        assert len(resp.json()) == 2

    async def test_filter_by_severity(
        self, client: AsyncClient, viewer_headers: dict, db: AsyncSession
    ):
        await _seed_alert(db, severity="critical")
        await _seed_alert(db, severity="low")
        resp = await client.get("/api/v1/alerts", params={"severity": "critical"}, headers=viewer_headers)
        assert resp.status_code == 200
        assert all(a["severity"] == "critical" for a in resp.json())

    async def test_filter_by_status(
        self, client: AsyncClient, viewer_headers: dict, db: AsyncSession
    ):
        await _seed_alert(db, status="open")
        await _seed_alert(db, status="resolved")
        resp = await client.get("/api/v1/alerts", params={"status": "open"}, headers=viewer_headers)
        assert resp.status_code == 200
        assert all(a["status"] == "open" for a in resp.json())

    async def test_response_fields_complete(
        self, client: AsyncClient, viewer_headers: dict, db: AsyncSession
    ):
        await _seed_alert(db)
        resp = await client.get("/api/v1/alerts", headers=viewer_headers)
        assert resp.status_code == 200
        alert = resp.json()[0]
        for field in ("id", "title", "severity", "status", "risk_score", "detected_at"):
            assert field in alert, f"Missing field: {field}"

    async def test_limit_respected(
        self, client: AsyncClient, viewer_headers: dict, db: AsyncSession
    ):
        for _ in range(5):
            await _seed_alert(db)
        resp = await client.get("/api/v1/alerts", params={"limit": 2}, headers=viewer_headers)
        assert resp.status_code == 200
        assert len(resp.json()) == 2


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 3. GET /alerts/{id}
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
class TestAlertGet:

    async def test_get_existing_alert(
        self, client: AsyncClient, viewer_headers: dict, db: AsyncSession
    ):
        alert = await _seed_alert(db, severity="critical")
        resp = await client.get(f"/api/v1/alerts/{alert.id}", headers=viewer_headers)
        assert resp.status_code == 200
        assert resp.json()["id"] == alert.id

    async def test_get_nonexistent_returns_404(self, client: AsyncClient, viewer_headers: dict):
        resp = await client.get("/api/v1/alerts/does-not-exist", headers=viewer_headers)
        assert resp.status_code == 404

    async def test_get_returns_all_required_fields(
        self, client: AsyncClient, viewer_headers: dict, db: AsyncSession
    ):
        alert = await _seed_alert(db, severity="high")
        body = (await client.get(f"/api/v1/alerts/{alert.id}", headers=viewer_headers)).json()
        for f in ("id", "title", "description", "severity", "status", "risk_score",
                  "ttps", "affected_hosts", "detected_at"):
            assert f in body

    async def test_viewer_can_read_alert(
        self, client: AsyncClient, viewer_headers: dict, db: AsyncSession
    ):
        alert = await _seed_alert(db)
        resp = await client.get(f"/api/v1/alerts/{alert.id}", headers=viewer_headers)
        assert resp.status_code == 200


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 4. PATCH /alerts/{id} â€” status transitions + MTTA timestamps
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
class TestAlertPatch:
    """
    PATCH is the mechanism that drives MTTA and MTTR metrics:
      status â†’ "investigating"  sets acknowledged_at  (MTTA denominator)
      status â†’ "resolved"       sets resolved_at       (MTTR denominator)
    """

    async def test_patch_status_to_investigating(
        self, client: AsyncClient, analyst_headers: dict, db: AsyncSession
    ):
        alert = await _seed_alert(db, status="open")
        resp = await client.patch(
            f"/api/v1/alerts/{alert.id}",
            json={"status": "investigating"},
            headers=analyst_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "investigating"

    async def test_patch_sets_acknowledged_at_on_investigating(
        self, client: AsyncClient, analyst_headers: dict, db: AsyncSession
    ):
        """MTTA requires acknowledged_at to be populated when an analyst picks up the alert."""
        alert = await _seed_alert(db, status="open")
        assert alert.acknowledged_at is None
        resp = await client.patch(
            f"/api/v1/alerts/{alert.id}",
            json={"status": "investigating"},
            headers=analyst_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["acknowledged_at"] is not None

    async def test_patch_status_to_resolved(
        self, client: AsyncClient, analyst_headers: dict, db: AsyncSession
    ):
        alert = await _seed_alert(db, status="investigating")
        resp = await client.patch(
            f"/api/v1/alerts/{alert.id}",
            json={"status": "resolved"},
            headers=analyst_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "resolved"

    async def test_patch_sets_resolved_at_on_resolved(
        self, client: AsyncClient, analyst_headers: dict, db: AsyncSession
    ):
        """MTTR requires resolved_at to be populated when status â†’ resolved."""
        alert = await _seed_alert(db, status="investigating")
        assert alert.resolved_at is None
        resp = await client.patch(
            f"/api/v1/alerts/{alert.id}",
            json={"status": "resolved"},
            headers=analyst_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["resolved_at"] is not None

    async def test_patch_false_positive_sets_resolved_at(
        self, client: AsyncClient, analyst_headers: dict, db: AsyncSession
    ):
        alert = await _seed_alert(db)
        resp = await client.patch(
            f"/api/v1/alerts/{alert.id}",
            json={"status": "false_positive"},
            headers=analyst_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["resolved_at"] is not None

    async def test_patch_analyst_notes(
        self, client: AsyncClient, analyst_headers: dict, db: AsyncSession
    ):
        alert = await _seed_alert(db)
        notes = "Confirmed C2 beacon to known Cobalt Strike infra."
        resp = await client.patch(
            f"/api/v1/alerts/{alert.id}",
            json={"analyst_notes": notes},
            headers=analyst_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["analyst_notes"] == notes

    async def test_patch_assigned_to(
        self, client: AsyncClient, analyst_headers: dict, admin_user, db: AsyncSession
    ):
        alert = await _seed_alert(db)
        resp = await client.patch(
            f"/api/v1/alerts/{alert.id}",
            json={"assigned_to": admin_user.id},
            headers=analyst_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["assigned_to"] == admin_user.id

    async def test_patch_false_positive_flag(
        self, client: AsyncClient, analyst_headers: dict, db: AsyncSession
    ):
        alert = await _seed_alert(db)
        resp = await client.patch(
            f"/api/v1/alerts/{alert.id}",
            json={"false_positive": True},
            headers=analyst_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["false_positive"] is True

    async def test_patch_nonexistent_returns_404(
        self, client: AsyncClient, analyst_headers: dict
    ):
        resp = await client.patch(
            "/api/v1/alerts/does-not-exist",
            json={"status": "resolved"},
            headers=analyst_headers,
        )
        assert resp.status_code == 404

    async def test_patch_does_not_override_existing_acknowledged_at(
        self, client: AsyncClient, analyst_headers: dict, db: AsyncSession
    ):
        """acknowledged_at must not be overwritten on subsequent status changes."""
        alert = await _seed_alert(db, status="open")
        # First patch: open â†’ investigating (sets acknowledged_at)
        r1 = await client.patch(
            f"/api/v1/alerts/{alert.id}",
            json={"status": "investigating"},
            headers=analyst_headers,
        )
        first_ack = r1.json()["acknowledged_at"]
        # Second patch: investigating â†’ contained
        r2 = await client.patch(
            f"/api/v1/alerts/{alert.id}",
            json={"status": "contained"},
            headers=analyst_headers,
        )
        assert r2.json()["acknowledged_at"] == first_ack


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 5. GET /alerts/stats/summary
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
class TestAlertStats:

    async def test_empty_stats(self, client: AsyncClient, viewer_headers: dict):
        resp = await client.get("/api/v1/alerts/stats/summary", headers=viewer_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 0
        assert body["false_positive_rate"] == 0.0

    async def test_stats_count_severity(
        self, client: AsyncClient, viewer_headers: dict, db: AsyncSession
    ):
        await _seed_alert(db, severity="critical")
        await _seed_alert(db, severity="critical")
        await _seed_alert(db, severity="high")
        resp = await client.get("/api/v1/alerts/stats/summary", headers=viewer_headers)
        body = resp.json()
        assert body["total"] == 3
        assert body["critical"] == 2
        assert body["high"] == 1

    async def test_stats_false_positive_rate(
        self, client: AsyncClient, analyst_headers: dict, viewer_headers: dict, db: AsyncSession
    ):
        alert = await _seed_alert(db)
        await _seed_alert(db)
        # Mark one as false positive via PATCH
        await client.patch(
            f"/api/v1/alerts/{alert.id}",
            json={"false_positive": True},
            headers=analyst_headers,
        )
        resp = await client.get("/api/v1/alerts/stats/summary", headers=viewer_headers)
        assert resp.json()["false_positive_rate"] == 0.5

    async def test_stats_open_count(
        self, client: AsyncClient, analyst_headers: dict, viewer_headers: dict, db: AsyncSession
    ):
        alert = await _seed_alert(db, status="open")
        await _seed_alert(db, status="open")
        # Resolve one
        await client.patch(
            f"/api/v1/alerts/{alert.id}",
            json={"status": "resolved"},
            headers=analyst_headers,
        )
        resp = await client.get("/api/v1/alerts/stats/summary", headers=viewer_headers)
        body = resp.json()
        assert body["open"] == 1
        # S118.5: by_status debe existir y reflejar los estados sembrados
        assert body["by_status"].get("open") == 1
        assert body["by_status"].get("resolved") == 1
        assert "avg_risk_score" in body
