"""
FASE 2.1 — Role Elevation Tests.

Covers PATCH /api/v1/auth/users/{user_id} for role changes.
All tests use real SQLite in-memory DB via conftest fixtures — no AsyncMock.

Suite breakdown:
  TestRoleElevationAuth        (4)  — 401 anon, 403 analyst, 403 viewer, 200 admin
  TestRoleElevationValidation  (4)  — invalid role, self-demotion, 404 wrong id, empty payload
  TestRoleElevationAudit       (3)  — audit event emitted, old→new in detail, no audit on name-only patch
  TestRoleElevationTenantIso   (4)  — cross-tenant update rejected, list scoped per tenant
  TestRoleElevationIdempotent  (3)  — promote analyst→admin→analyst roundtrip, viewer→admin

Total: 18 tests
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.models.user import User
from asc_api.core.security import get_password_hash, create_access_token


# ── Helpers ───────────────────────────────────────────────────────────────────

def _auth(user: User) -> dict:
    token = create_access_token(user.id)
    return {"Authorization": f"Bearer {token}"}


async def _create_user(
    db: AsyncSession,
    email: str,
    role: str = "analyst",
    tenant_id: str | None = None,
) -> User:
    u = User(
        email=email,
        full_name="Test User",
        hashed_password=get_password_hash("Test@1234!"),
        role=role,
        is_active=True,
        tenant_id=tenant_id,
    )
    db.add(u)
    await db.commit()
    await db.refresh(u)
    return u


# ── Auth guards ───────────────────────────────────────────────────────────────

class TestRoleElevationAuth:
    async def test_401_anonymous(self, client: AsyncClient, analyst_user: User):
        r = await client.patch(f"/api/v1/auth/users/{analyst_user.id}", json={"role": "admin"})
        assert r.status_code == 401

    async def test_403_analyst_cannot_elevate(
        self, client: AsyncClient, analyst_user: User, admin_user: User
    ):
        headers = _auth(analyst_user)
        r = await client.patch(
            f"/api/v1/auth/users/{admin_user.id}", json={"role": "viewer"}, headers=headers
        )
        assert r.status_code == 403

    async def test_403_viewer_cannot_elevate(
        self, client: AsyncClient, viewer_user: User, analyst_user: User
    ):
        headers = _auth(viewer_user)
        r = await client.patch(
            f"/api/v1/auth/users/{analyst_user.id}", json={"role": "admin"}, headers=headers
        )
        assert r.status_code == 403

    async def test_200_admin_can_change_role(
        self, client: AsyncClient, admin_user: User, analyst_user: User
    ):
        headers = _auth(admin_user)
        r = await client.patch(
            f"/api/v1/auth/users/{analyst_user.id}", json={"role": "admin"}, headers=headers
        )
        assert r.status_code == 200
        assert r.json()["role"] == "admin"


# ── Validation guards ─────────────────────────────────────────────────────────

class TestRoleElevationValidation:
    async def test_422_invalid_role_rejected(
        self, client: AsyncClient, admin_user: User, analyst_user: User
    ):
        headers = _auth(admin_user)
        r = await client.patch(
            f"/api/v1/auth/users/{analyst_user.id}",
            json={"role": "superadmin"},
            headers=headers,
        )
        assert r.status_code == 422
        assert "Rol inválido" in r.text

    async def test_422_self_demotion_rejected(
        self, client: AsyncClient, admin_user: User
    ):
        headers = _auth(admin_user)
        r = await client.patch(
            f"/api/v1/auth/users/{admin_user.id}",
            json={"role": "viewer"},
            headers=headers,
        )
        assert r.status_code == 422
        assert "propio rol" in r.text

    async def test_404_unknown_user_id(self, client: AsyncClient, admin_user: User):
        headers = _auth(admin_user)
        r = await client.patch(
            "/api/v1/auth/users/00000000-0000-0000-0000-000000000000",
            json={"role": "analyst"},
            headers=headers,
        )
        assert r.status_code == 404

    async def test_200_empty_payload_is_noop(
        self, client: AsyncClient, admin_user: User, analyst_user: User
    ):
        headers = _auth(admin_user)
        r = await client.patch(
            f"/api/v1/auth/users/{analyst_user.id}",
            json={},
            headers=headers,
        )
        assert r.status_code == 200
        assert r.json()["role"] == analyst_user.role  # unchanged


# ── Audit logging ─────────────────────────────────────────────────────────────

class TestRoleElevationAudit:
    async def test_audit_event_emitted_on_role_change(
        self, client: AsyncClient, admin_user: User, analyst_user: User
    ):
        from unittest.mock import patch as mpatch
        with mpatch("asc_api.api.v1.endpoints.auth.log_iam_event") as mock_log:
            headers = _auth(admin_user)
            r = await client.patch(
                f"/api/v1/auth/users/{analyst_user.id}",
                json={"role": "admin"},
                headers=headers,
            )
        assert r.status_code == 200
        mock_log.assert_called_once_with(
            "role_changed",
            performed_by=admin_user.email,
            target_user=analyst_user.email,
            detail="analyst → admin",
        )

    async def test_audit_detail_contains_old_and_new_role(
        self, client: AsyncClient, admin_user: User, analyst_user: User
    ):
        from unittest.mock import patch as mpatch
        with mpatch("asc_api.api.v1.endpoints.auth.log_iam_event") as mock_log:
            headers = _auth(admin_user)
            await client.patch(
                f"/api/v1/auth/users/{analyst_user.id}",
                json={"role": "viewer"},
                headers=headers,
            )
        call_kwargs = mock_log.call_args
        assert call_kwargs is not None
        assert call_kwargs.kwargs.get("detail") == "analyst → viewer"

    async def test_no_audit_on_full_name_only_patch(
        self, client: AsyncClient, admin_user: User, analyst_user: User
    ):
        from unittest.mock import patch as mpatch
        with mpatch("asc_api.api.v1.endpoints.auth.log_iam_event") as mock_log:
            headers = _auth(admin_user)
            await client.patch(
                f"/api/v1/auth/users/{analyst_user.id}",
                json={"full_name": "Nuevo Nombre"},
                headers=headers,
            )
        # log_iam_event must NOT have been called for a name-only patch
        mock_log.assert_not_called()


# ── Tenant isolation ──────────────────────────────────────────────────────────

class TestRoleElevationTenantIso:
    async def test_admin_cannot_update_user_in_other_tenant(
        self, client: AsyncClient, db: AsyncSession
    ):
        admin_a = await _create_user(db, "admin-a@test.com", role="admin", tenant_id="tenant-a")
        user_b = await _create_user(db, "user-b@test.com", role="analyst", tenant_id="tenant-b")
        headers = _auth(admin_a)
        r = await client.patch(
            f"/api/v1/auth/users/{user_b.id}", json={"role": "admin"}, headers=headers
        )
        assert r.status_code == 404

    async def test_admin_can_update_user_in_same_tenant(
        self, client: AsyncClient, db: AsyncSession
    ):
        admin = await _create_user(db, "admin-c@test.com", role="admin", tenant_id="tenant-c")
        user = await _create_user(db, "user-c@test.com", role="analyst", tenant_id="tenant-c")
        headers = _auth(admin)
        r = await client.patch(
            f"/api/v1/auth/users/{user.id}", json={"role": "viewer"}, headers=headers
        )
        assert r.status_code == 200
        assert r.json()["role"] == "viewer"

    async def test_list_users_scoped_to_own_tenant(
        self, client: AsyncClient, db: AsyncSession
    ):
        admin = await _create_user(db, "admin-d@test.com", role="admin", tenant_id="tenant-d")
        await _create_user(db, "same-tenant@test.com", role="analyst", tenant_id="tenant-d")
        await _create_user(db, "other-tenant@test.com", role="analyst", tenant_id="tenant-e")
        headers = _auth(admin)
        r = await client.get("/api/v1/auth/users", headers=headers)
        assert r.status_code == 200
        emails = [u["email"] for u in r.json()]
        assert "same-tenant@test.com" in emails
        assert "other-tenant@test.com" not in emails

    async def test_null_tenant_admin_sees_null_tenant_users(
        self, client: AsyncClient, db: AsyncSession
    ):
        # Root admin (tenant_id=None) sees users also with tenant_id=None
        admin = await _create_user(db, "root-admin@test.com", role="admin", tenant_id=None)
        u1 = await _create_user(db, "no-tenant-1@test.com", role="analyst", tenant_id=None)
        await _create_user(db, "has-tenant@test.com", role="analyst", tenant_id="tenant-x")
        headers = _auth(admin)
        r = await client.get("/api/v1/auth/users", headers=headers)
        assert r.status_code == 200
        emails = [u["email"] for u in r.json()]
        assert u1.email in emails


# ── Roundtrip role changes ────────────────────────────────────────────────────

class TestRoleElevationIdempotent:
    async def test_promote_analyst_to_admin_and_back(
        self, client: AsyncClient, admin_user: User, analyst_user: User
    ):
        headers = _auth(admin_user)
        # Promote
        r = await client.patch(
            f"/api/v1/auth/users/{analyst_user.id}", json={"role": "admin"}, headers=headers
        )
        assert r.status_code == 200
        assert r.json()["role"] == "admin"
        # Demote back
        r = await client.patch(
            f"/api/v1/auth/users/{analyst_user.id}", json={"role": "analyst"}, headers=headers
        )
        assert r.status_code == 200
        assert r.json()["role"] == "analyst"

    async def test_elevate_viewer_to_admin(
        self, client: AsyncClient, admin_user: User, viewer_user: User
    ):
        headers = _auth(admin_user)
        r = await client.patch(
            f"/api/v1/auth/users/{viewer_user.id}", json={"role": "admin"}, headers=headers
        )
        assert r.status_code == 200
        assert r.json()["role"] == "admin"

    async def test_all_valid_roles_accepted(
        self, client: AsyncClient, admin_user: User, analyst_user: User
    ):
        headers = _auth(admin_user)
        for role in ("admin", "viewer", "analyst"):
            r = await client.patch(
                f"/api/v1/auth/users/{analyst_user.id}", json={"role": role}, headers=headers
            )
            assert r.status_code == 200, f"Expected 200 for role={role}"
            assert r.json()["role"] == role
