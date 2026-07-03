"""
P31-COV — Targeted coverage tests to push overall coverage from 80% to ≥85%.

Modules targeted (uncovered path coverage):
  - app/api/v1/endpoints/auth.py         (33% → target 75%+)
    * GET  /auth/me
    * POST /auth/logout
    * POST /auth/refresh
    * POST /auth/change-password (normal + force_reset paths)
    * GET  /auth/users
    * PATCH /auth/users/{id}
    * POST /auth/users/{id}/unlock
  - app/api/v1/endpoints/events.py       (40% → target 90%+)
    * POST /events/ingest
    * POST /events/ingest/bulk
    * GET  /events/ (with and without severity filter)
  - app/api/v1/endpoints/neutralize.py   (43% → target 65%+)
    * GET  /neutralize/recommended
    * GET  /neutralize/pending
    * POST /neutralize/ (low severity auto-execute path)
    * GET  /neutralize/escalated (if exists)

All tests use the shared `client` fixture (SQLite in-memory) and real JWT tokens.
Rate limits are reset before every test via `_reset_rate_limit` autouse fixture.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.core.security import create_access_token, create_refresh_token
from asc_api.models.user import User


# ── Rate-limit bypass ─────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _reset_rate_limit():
    from asc_api.core.rate_limit import limiter
    limiter._storage.reset()
    yield
    limiter._storage.reset()


# ── TestAuthMe ────────────────────────────────────────────────────────────────

class TestAuthMe:
    """GET /auth/me — authenticated user profile."""

    @pytest.mark.asyncio
    async def test_me_returns_current_user_profile(self, client, admin_user):
        token = create_access_token(admin_user.id)
        r = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        body = r.json()
        assert body["email"] == admin_user.email
        assert body["role"] == "admin"

    @pytest.mark.asyncio
    async def test_me_returns_analyst_role(self, client, analyst_user):
        token = create_access_token(analyst_user.id)
        r = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert r.json()["role"] == "analyst"

    @pytest.mark.asyncio
    async def test_me_returns_viewer_role(self, client, viewer_user):
        token = create_access_token(viewer_user.id)
        r = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert r.json()["role"] == "viewer"

    @pytest.mark.asyncio
    async def test_me_returns_user_id(self, client, admin_user):
        token = create_access_token(admin_user.id)
        r = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert r.json()["id"] == admin_user.id

    @pytest.mark.asyncio
    async def test_me_without_token_blocked(self, client):
        r = await client.get("/api/v1/auth/me")
        assert r.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_me_returns_is_active_true(self, client, analyst_user):
        token = create_access_token(analyst_user.id)
        r = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert r.json()["is_active"] is True


# ── TestAuthLogout ────────────────────────────────────────────────────────────

class TestAuthLogout:
    """POST /auth/logout — token revocation."""

    @pytest.mark.asyncio
    async def test_logout_returns_success_message(self, client, admin_user):
        token = create_access_token(admin_user.id)
        r = await client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert "cerrada" in r.json().get("message", "").lower()

    @pytest.mark.asyncio
    async def test_logout_revokes_token_in_blacklist(self, client, admin_user):
        from asc_api.core.jwt_blacklist import jwt_blacklist
        jwt_blacklist.reset_local()

        token = create_access_token(admin_user.id)
        r = await client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        # L1 cache should have the JTI
        assert jwt_blacklist.local_size >= 1

    @pytest.mark.asyncio
    async def test_logout_requires_authentication(self, client):
        r = await client.post("/api/v1/auth/logout")
        assert r.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_analyst_can_logout(self, client, analyst_user):
        token = create_access_token(analyst_user.id)
        r = await client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_viewer_can_logout(self, client, viewer_user):
        token = create_access_token(viewer_user.id)
        r = await client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200


# ── TestAuthRefresh ───────────────────────────────────────────────────────────

class TestAuthRefresh:
    """POST /auth/refresh — token rotation."""

    @pytest.mark.asyncio
    async def test_refresh_returns_new_access_token(self, client, admin_user):
        refresh = create_refresh_token(admin_user.id)
        r = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
        assert r.status_code == 200
        assert "access_token" in r.json()

    @pytest.mark.asyncio
    async def test_refresh_returns_new_refresh_token(self, client, admin_user):
        refresh = create_refresh_token(admin_user.id)
        r = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
        assert r.status_code == 200
        assert "refresh_token" in r.json()

    @pytest.mark.asyncio
    async def test_refresh_with_invalid_token_returns_401(self, client):
        r = await client.post("/api/v1/auth/refresh", json={"refresh_token": "not.a.valid.token"})
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_refresh_with_access_token_as_refresh_returns_401(self, client, admin_user):
        access = create_access_token(admin_user.id)
        r = await client.post("/api/v1/auth/refresh", json={"refresh_token": access})
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_refresh_rotates_old_token(self, client, admin_user):
        """Old refresh token should be revoked after rotation."""
        from asc_api.core.jwt_blacklist import jwt_blacklist
        jwt_blacklist.reset_local()

        refresh = create_refresh_token(admin_user.id)
        r = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
        assert r.status_code == 200
        assert jwt_blacklist.local_size >= 1

    @pytest.mark.asyncio
    async def test_refresh_missing_body_returns_422(self, client):
        r = await client.post("/api/v1/auth/refresh", json={})
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_analyst_can_refresh_token(self, client, analyst_user):
        refresh = create_refresh_token(analyst_user.id)
        r = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
        assert r.status_code == 200


# ── TestAuthChangePassword ────────────────────────────────────────────────────

class TestAuthChangePassword:
    """POST /auth/change-password — password management."""

    @pytest.mark.asyncio
    async def test_change_password_success_with_current_password(self, client, admin_user):
        token = create_access_token(admin_user.id)
        r = await client.post(
            "/api/v1/auth/change-password",
            headers={"Authorization": f"Bearer {token}"},
            json={"current_password": "Admin@1234!", "new_password": "NewAdmin@5678!"},
        )
        assert r.status_code == 200
        assert "contraseña" in r.json().get("message", "").lower()

    @pytest.mark.asyncio
    async def test_change_password_wrong_current_password_returns_401(self, client, admin_user):
        token = create_access_token(admin_user.id)
        r = await client.post(
            "/api/v1/auth/change-password",
            headers={"Authorization": f"Bearer {token}"},
            json={"current_password": "WrongPassword@99!", "new_password": "NewAdmin@5678!"},
        )
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_change_password_without_current_password_returns_422(self, client, admin_user):
        token = create_access_token(admin_user.id)
        r = await client.post(
            "/api/v1/auth/change-password",
            headers={"Authorization": f"Bearer {token}"},
            json={"new_password": "NewAdmin@5678!"},
        )
        # requires current_password when not in forced reset
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_change_password_force_reset_skips_current_password(self, client, admin_user, db):
        admin_user.force_password_reset = True
        db.add(admin_user)
        await db.commit()

        token = create_access_token(admin_user.id)
        r = await client.post(
            "/api/v1/auth/change-password",
            headers={"Authorization": f"Bearer {token}"},
            json={"new_password": "NewAdmin@5678!"},
        )
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_change_password_weak_password_returns_422(self, client, admin_user):
        token = create_access_token(admin_user.id)
        r = await client.post(
            "/api/v1/auth/change-password",
            headers={"Authorization": f"Bearer {token}"},
            json={"current_password": "Admin@1234!", "new_password": "weak"},
        )
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_change_password_reuse_same_password_returns_422(self, client, admin_user):
        token = create_access_token(admin_user.id)
        r = await client.post(
            "/api/v1/auth/change-password",
            headers={"Authorization": f"Bearer {token}"},
            json={"current_password": "Admin@1234!", "new_password": "Admin@1234!"},
        )
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_change_password_clears_force_reset_flag(self, client, analyst_user, db):
        analyst_user.force_password_reset = True
        db.add(analyst_user)
        await db.commit()

        token = create_access_token(analyst_user.id)
        await client.post(
            "/api/v1/auth/change-password",
            headers={"Authorization": f"Bearer {token}"},
            json={"new_password": "NewAnalyst@5678!"},
        )
        await db.refresh(analyst_user)
        assert analyst_user.force_password_reset is False


# ── TestAuthAdminUserManagement ───────────────────────────────────────────────

class TestAuthAdminUserManagement:
    """Admin endpoints: list, update, unlock users."""

    @pytest.mark.asyncio
    async def test_list_users_returns_all_users(self, client, admin_user, analyst_user):
        token = create_access_token(admin_user.id)
        r = await client.get("/api/v1/auth/users", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert isinstance(r.json(), list)
        assert len(r.json()) >= 2

    @pytest.mark.asyncio
    async def test_list_users_requires_admin(self, client, analyst_user):
        token = create_access_token(analyst_user.id)
        r = await client.get("/api/v1/auth/users", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 403

    @pytest.mark.asyncio
    async def test_list_users_each_item_has_email(self, client, admin_user, analyst_user):
        token = create_access_token(admin_user.id)
        r = await client.get("/api/v1/auth/users", headers={"Authorization": f"Bearer {token}"})
        users = r.json()
        assert all("email" in u for u in users)

    @pytest.mark.asyncio
    async def test_update_user_role(self, client, admin_user, analyst_user):
        token = create_access_token(admin_user.id)
        r = await client.patch(
            f"/api/v1/auth/users/{analyst_user.id}",
            headers={"Authorization": f"Bearer {token}"},
            json={"role": "viewer"},
        )
        assert r.status_code == 200
        assert r.json()["role"] == "viewer"

    @pytest.mark.asyncio
    async def test_update_user_force_password_reset(self, client, admin_user, analyst_user):
        token = create_access_token(admin_user.id)
        r = await client.patch(
            f"/api/v1/auth/users/{analyst_user.id}",
            headers={"Authorization": f"Bearer {token}"},
            json={"force_password_reset": True},
        )
        assert r.status_code == 200
        assert r.json()["force_password_reset"] is True

    @pytest.mark.asyncio
    async def test_update_user_invalid_role_returns_422(self, client, admin_user, analyst_user):
        token = create_access_token(admin_user.id)
        r = await client.patch(
            f"/api/v1/auth/users/{analyst_user.id}",
            headers={"Authorization": f"Bearer {token}"},
            json={"role": "superuser"},
        )
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_update_nonexistent_user_returns_404(self, client, admin_user):
        token = create_access_token(admin_user.id)
        r = await client.patch(
            f"/api/v1/auth/users/{uuid.uuid4()}",
            headers={"Authorization": f"Bearer {token}"},
            json={"role": "viewer"},
        )
        assert r.status_code == 404

    @pytest.mark.asyncio
    async def test_update_user_full_name(self, client, admin_user, analyst_user):
        token = create_access_token(admin_user.id)
        r = await client.patch(
            f"/api/v1/auth/users/{analyst_user.id}",
            headers={"Authorization": f"Bearer {token}"},
            json={"full_name": "Updated Name"},
        )
        assert r.status_code == 200
        assert r.json()["full_name"] == "Updated Name"

    @pytest.mark.asyncio
    async def test_unlock_user_not_locked_returns_message(self, client, admin_user, analyst_user):
        token = create_access_token(admin_user.id)
        r = await client.post(
            f"/api/v1/auth/users/{analyst_user.id}/unlock",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200
        assert "bloqueada" in r.json().get("message", "").lower()

    @pytest.mark.asyncio
    async def test_unlock_locked_user_clears_lockout(self, client, admin_user, analyst_user, db):
        analyst_user.locked_until = datetime.now(timezone.utc) + timedelta(hours=1)
        analyst_user.failed_login_attempts = 5
        db.add(analyst_user)
        await db.commit()

        token = create_access_token(admin_user.id)
        r = await client.post(
            f"/api/v1/auth/users/{analyst_user.id}/unlock",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200
        assert "desbloqueada" in r.json().get("message", "").lower()

    @pytest.mark.asyncio
    async def test_unlock_nonexistent_user_returns_404(self, client, admin_user):
        token = create_access_token(admin_user.id)
        r = await client.post(
            f"/api/v1/auth/users/{uuid.uuid4()}/unlock",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 404

    @pytest.mark.asyncio
    async def test_create_user_as_admin_returns_201(self, client, admin_user):
        token = create_access_token(admin_user.id)
        new_email = f"new-{uuid.uuid4().hex[:8]}@premoscorp.com"
        r = await client.post(
            "/api/v1/auth/users",
            headers={"Authorization": f"Bearer {token}"},
            json={"email": new_email, "password": "NewUser@1234!", "full_name": "New User", "role": "analyst"},
        )
        assert r.status_code == 201
        assert r.json()["role"] == "analyst"

    @pytest.mark.asyncio
    async def test_create_user_as_analyst_returns_403(self, client, analyst_user):
        token = create_access_token(analyst_user.id)
        r = await client.post(
            "/api/v1/auth/users",
            headers={"Authorization": f"Bearer {token}"},
            json={"email": "hack@premoscorp.com", "password": "Hack@1234!", "full_name": "Hacker"},
        )
        assert r.status_code == 403


# ── TestEventsEndpoints ───────────────────────────────────────────────────────

class TestEventsEndpoints:
    """Events ingestion and listing endpoints (analyst+ required — P37 fix)."""

    @pytest.mark.asyncio
    async def test_ingest_single_event_returns_event_id(self, client, analyst_headers):
        r = await client.post(
            "/api/v1/events/ingest",
            json={
                "source": "wazuh",
                "category": "authentication",
                "action": "login_failed",
                "host": "dc01.premoscorp.local",
                "raw_log": "Failed auth attempt",
            },
            headers=analyst_headers,
        )
        assert r.status_code == 200
        assert "event_id" in r.json()

    @pytest.mark.asyncio
    async def test_ingest_event_returns_severity(self, client, analyst_headers):
        r = await client.post(
            "/api/v1/events/ingest",
            json={
                "source": "elastic",
                "category": "malware",
                "action": "process_spawn",
                "host": "workstation-42",
            },
            headers=analyst_headers,
        )
        assert r.status_code == 200
        assert r.json()["severity"] in ("critical", "high", "medium", "low")

    @pytest.mark.asyncio
    async def test_ingest_event_returns_risk_score(self, client, analyst_headers):
        r = await client.post(
            "/api/v1/events/ingest",
            json={
                "source": "firewall",
                "category": "network",
                "action": "block",
                "host": "fw-01",
                "data": {"src_ip": "10.0.0.1"},
            },
            headers=analyst_headers,
        )
        assert r.status_code == 200
        assert "risk_score" in r.json()

    @pytest.mark.asyncio
    async def test_ingest_event_unauthenticated_returns_401(self, client):
        r = await client.post(
            "/api/v1/events/ingest",
            json={"source": "wazuh", "category": "auth", "action": "fail", "host": "dc01"},
        )
        assert r.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_ingest_event_missing_required_fields_returns_422(self, client, analyst_headers):
        r = await client.post(
            "/api/v1/events/ingest",
            json={"source": "wazuh"},
            headers=analyst_headers,
        )
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_ingest_bulk_returns_events_ingested_count(self, client, analyst_headers):
        r = await client.post(
            "/api/v1/events/ingest/bulk",
            json={
                "events": [
                    {"source": "wazuh", "category": "auth", "action": "login", "host": "dc01"},
                    {"source": "wazuh", "category": "auth", "action": "logout", "host": "dc01"},
                    {"source": "elastic", "category": "network", "action": "scan", "host": "srv01"},
                ]
            },
            headers=analyst_headers,
        )
        assert r.status_code == 200
        assert r.json()["events_ingested"] == 3

    @pytest.mark.asyncio
    async def test_ingest_bulk_empty_list_returns_zero(self, client, analyst_headers):
        r = await client.post(
            "/api/v1/events/ingest/bulk",
            json={"events": []},
            headers=analyst_headers,
        )
        assert r.status_code == 200
        assert r.json()["events_ingested"] == 0

    @pytest.mark.asyncio
    async def test_ingest_bulk_returns_alert_ids(self, client, analyst_headers):
        r = await client.post(
            "/api/v1/events/ingest/bulk",
            json={
                "events": [
                    {"source": "wazuh", "category": "auth", "action": "brute_force", "host": "dc01"}
                ]
            },
            headers=analyst_headers,
        )
        assert r.status_code == 200
        assert "alert_ids" in r.json()

    @pytest.mark.asyncio
    async def test_ingest_bulk_unauthenticated_returns_401(self, client):
        r = await client.post(
            "/api/v1/events/ingest/bulk",
            json={"events": [{"source": "x", "category": "y", "action": "z", "host": "h"}]},
        )
        assert r.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_list_events_returns_list(self, client, analyst_headers):
        r = await client.get("/api/v1/events/", headers=analyst_headers)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    @pytest.mark.asyncio
    async def test_list_events_unauthenticated_returns_401(self, client):
        r = await client.get("/api/v1/events/")
        assert r.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_list_events_default_limit_fifty(self, client, analyst_headers):
        r = await client.get("/api/v1/events/", headers=analyst_headers)
        assert r.status_code == 200
        assert len(r.json()) <= 50

    @pytest.mark.asyncio
    async def test_list_events_with_severity_filter(self, client, analyst_headers):
        await client.post(
            "/api/v1/events/ingest",
            json={"source": "wazuh", "category": "auth", "action": "fail", "host": "dc01"},
            headers=analyst_headers,
        )
        r = await client.get("/api/v1/events/?severity=low", headers=analyst_headers)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    @pytest.mark.asyncio
    async def test_list_events_with_offset_and_limit(self, client, analyst_headers):
        r = await client.get("/api/v1/events/?limit=10&offset=0", headers=analyst_headers)
        assert r.status_code == 200
        assert len(r.json()) <= 10

    @pytest.mark.asyncio
    async def test_list_events_each_item_has_event_id(self, client, analyst_headers):
        await client.post(
            "/api/v1/events/ingest",
            json={"source": "wazuh", "category": "auth", "action": "fail", "host": "dc01"},
            headers=analyst_headers,
        )
        r = await client.get("/api/v1/events/", headers=analyst_headers)
        if r.json():
            assert "id" in r.json()[0]


# ── TestNeutralizeEndpoints ───────────────────────────────────────────────────

class TestNeutralizeEndpoints:
    """Neutralization recommendation and pending action endpoints."""

    @pytest.mark.asyncio
    async def test_get_recommended_actions_for_high_severity(self, client, analyst_user):
        token = create_access_token(analyst_user.id)
        r = await client.get(
            "/api/v1/neutralize/recommended/high",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200
        body = r.json()
        assert "recommended_actions" in body

    @pytest.mark.asyncio
    async def test_get_recommended_for_critical_severity(self, client, analyst_user):
        token = create_access_token(analyst_user.id)
        r = await client.get(
            "/api/v1/neutralize/recommended/critical",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_get_recommended_invalid_severity_returns_4xx(self, client, analyst_user):
        token = create_access_token(analyst_user.id)
        r = await client.get(
            "/api/v1/neutralize/recommended/ultra",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code in (400, 422)

    @pytest.mark.asyncio
    async def test_get_recommended_requires_analyst_or_admin(self, client, viewer_user):
        token = create_access_token(viewer_user.id)
        r = await client.get(
            "/api/v1/neutralize/recommended/high",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 403

    @pytest.mark.asyncio
    async def test_get_pending_actions_returns_dict_with_actions(self, client, analyst_user):
        token = create_access_token(analyst_user.id)
        r = await client.get(
            "/api/v1/neutralize/pending",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200
        body = r.json()
        assert "total" in body
        assert "actions" in body

    @pytest.mark.asyncio
    async def test_get_pending_empty_returns_zero_total(self, client, analyst_user):
        token = create_access_token(analyst_user.id)
        r = await client.get(
            "/api/v1/neutralize/pending",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200
        assert r.json()["total"] == 0

    @pytest.mark.asyncio
    async def test_get_pending_requires_analyst_or_admin(self, client, viewer_user):
        token = create_access_token(viewer_user.id)
        r = await client.get(
            "/api/v1/neutralize/pending",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 403

    @pytest.mark.asyncio
    async def test_post_neutralize_invalid_action_type_returns_422(self, client, analyst_user):
        token = create_access_token(analyst_user.id)
        r = await client.post(
            "/api/v1/neutralize/",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "action_type": "not_a_valid_action",
                "target": "10.0.0.1",
                "target_type": "ip",
                "severity": "high",
            },
        )
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_post_neutralize_invalid_severity_returns_422(self, client, analyst_user):
        token = create_access_token(analyst_user.id)
        r = await client.post(
            "/api/v1/neutralize/",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "action_type": "block_ip",
                "target": "10.0.0.1",
                "target_type": "ip",
                "severity": "ultra_critical",
            },
        )
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_post_neutralize_viewer_cannot_request_action(self, client, viewer_user):
        token = create_access_token(viewer_user.id)
        r = await client.post(
            "/api/v1/neutralize/",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "action_type": "block_ip",
                "target": "10.0.0.1",
                "target_type": "ip",
                "severity": "low",
            },
        )
        assert r.status_code == 403

    @pytest.mark.asyncio
    async def test_post_neutralize_missing_required_fields_returns_422(self, client, analyst_user):
        token = create_access_token(analyst_user.id)
        r = await client.post(
            "/api/v1/neutralize/",
            headers={"Authorization": f"Bearer {token}"},
            json={"action_type": "block_ip"},
        )
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_neutralize_schema_valid_severity_values(self):
        from asc_api.api.v1.endpoints.neutralize import NeutralizeRequest
        for sev in ("critical", "high", "medium", "low"):
            obj = NeutralizeRequest(action_type="block_ip", target="1.2.3.4", target_type="ip", severity=sev)
            assert obj.severity == sev

    @pytest.mark.asyncio
    async def test_neutralize_schema_rejects_invalid_action_type(self):
        import pydantic
        from asc_api.api.v1.endpoints.neutralize import NeutralizeRequest
        with pytest.raises(pydantic.ValidationError):
            NeutralizeRequest(action_type="delete_everything", target="host", target_type="endpoint")

    @pytest.mark.asyncio
    async def test_reject_schema_empty_reason_raises(self):
        import pydantic
        from asc_api.api.v1.endpoints.neutralize import RejectRequest
        with pytest.raises(pydantic.ValidationError):
            RejectRequest(reason="")


# ── TestAuthRegisterBootstrap ─────────────────────────────────────────────────

class TestAuthRegisterBootstrap:
    """POST /auth/register — bootstrap path (empty DB only)."""

    @pytest.mark.asyncio
    async def test_register_first_user_succeeds(self, client):
        """Empty DB → first user registration succeeds and becomes admin."""
        r = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "founder@premoscorp.com",
                "password": "Founder@1234!",
                "full_name": "First Admin",
            },
        )
        assert r.status_code == 201
        body = r.json()
        assert body["role"] == "admin"
        assert body["email"] == "founder@premoscorp.com"

    @pytest.mark.asyncio
    async def test_register_second_user_blocked(self, client, admin_user):
        """Non-empty DB → registration returns 403."""
        r = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "second@premoscorp.com",
                "password": "Second@1234!",
                "full_name": "Second User",
            },
        )
        assert r.status_code == 403
