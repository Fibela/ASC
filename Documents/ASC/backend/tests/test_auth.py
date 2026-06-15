"""
Unit tests — Auth layer (core/security.py + api/v1/endpoints/auth.py)

Covers token creation/verification, bootstrap registration, login,
refresh, role-based access, and /auth/me.

Uses the fixtures from conftest.py (in-memory SQLite, AsyncClient).
"""
import pytest
import pytest_asyncio
from httpx import AsyncClient
from datetime import datetime, timedelta, timezone

from app.core.security import (
    create_access_token,
    create_refresh_token,
    verify_token,
    get_password_hash,
    verify_password,
)
from app.models.user import User
from fastapi import HTTPException


# ─── Security utility tests ───────────────────────────────────────────────────

class TestSecurityUtils:
    def test_access_token_round_trip(self):
        token = create_access_token("user-abc-123")
        subject = verify_token(token, token_type="access")
        assert subject == "user-abc-123"

    def test_refresh_token_round_trip(self):
        token = create_refresh_token("user-xyz-999")
        subject = verify_token(token, token_type="refresh")
        assert subject == "user-xyz-999"

    def test_access_token_rejected_as_refresh(self):
        token = create_access_token("user-1")
        with pytest.raises(HTTPException) as exc:
            verify_token(token, token_type="refresh")
        assert exc.value.status_code == 401

    def test_refresh_token_rejected_as_access(self):
        token = create_refresh_token("user-1")
        with pytest.raises(HTTPException) as exc:
            verify_token(token, token_type="access")
        assert exc.value.status_code == 401

    def test_expired_token_raises_401(self):
        token = create_access_token("user-1", expires_delta=timedelta(seconds=-1))
        with pytest.raises(HTTPException) as exc:
            verify_token(token)
        assert exc.value.status_code == 401

    def test_invalid_token_string_raises_401(self):
        with pytest.raises(HTTPException) as exc:
            verify_token("invalid.jwt.token")
        assert exc.value.status_code == 401

    def test_password_hash_and_verify(self):
        plain = "Super$ecure!99"
        hashed = get_password_hash(plain)
        assert hashed != plain
        assert verify_password(plain, hashed)

    def test_wrong_password_fails_verify(self):
        hashed = get_password_hash("correct-password")
        assert not verify_password("wrong-password", hashed)


# ─── Bootstrap registration ───────────────────────────────────────────────────

@pytest.mark.asyncio
class TestBootstrapRegister:
    async def test_first_user_registers_as_admin(self, client: AsyncClient):
        resp = await client.post("/api/v1/auth/register", json={
            "email":     "bootstrap@premoscorp.com",
            "full_name": "Bootstrap Admin",
            "password":  "Bootstrap@123!",
        })
        assert resp.status_code in (200, 201)
        data = resp.json()
        # Register endpoint returns account data, not tokens (use /login for tokens)
        assert data["role"] == "admin"
        assert data["email"] == "bootstrap@premoscorp.com"

    async def test_second_registration_blocked(self, client: AsyncClient, admin_user: User):
        resp = await client.post("/api/v1/auth/register", json={
            "email":     "intruder@evil.com",
            "full_name": "Intruder",
            "password":  "Intruder@123!",
        })
        assert resp.status_code == 403

    async def test_register_missing_fields_unprocessable(self, client: AsyncClient):
        resp = await client.post("/api/v1/auth/register", json={"email": "x@x.com"})
        assert resp.status_code == 422


# ─── Login ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestLogin:
    async def test_valid_credentials_return_tokens(
        self, client: AsyncClient, admin_user: User
    ):
        resp = await client.post("/api/v1/auth/login", json={
            "email":    "admin@premoscorp.com",
            "password": "Admin@1234!",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["token_type"] == "bearer"
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["role"] == "admin"
        assert "expires_in" in data

    async def test_wrong_password_returns_401(self, client: AsyncClient, admin_user: User):
        resp = await client.post("/api/v1/auth/login", json={
            "email":    "admin@premoscorp.com",
            "password": "wrong-password",
        })
        assert resp.status_code == 401

    async def test_unknown_email_returns_401(self, client: AsyncClient):
        resp = await client.post("/api/v1/auth/login", json={
            "email":    "nobody@premoscorp.com",
            "password": "whatever",
        })
        assert resp.status_code == 401

    async def test_missing_email_field_unprocessable(self, client: AsyncClient):
        resp = await client.post("/api/v1/auth/login", json={"password": "x"})
        assert resp.status_code == 422


# ─── /auth/me ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestAuthMe:
    async def test_me_returns_user_info(
        self, client: AsyncClient, admin_user: User, admin_headers: dict
    ):
        resp = await client.get("/api/v1/auth/me", headers=admin_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["email"] == "admin@premoscorp.com"
        assert data["role"] == "admin"
        assert "id" in data

    async def test_me_without_token_returns_403_or_401(self, client: AsyncClient):
        resp = await client.get("/api/v1/auth/me")
        assert resp.status_code in (401, 403)

    async def test_me_with_expired_token_returns_401(self, client: AsyncClient, admin_user: User):
        token = create_access_token(admin_user.id, expires_delta=timedelta(seconds=-1))
        resp = await client.get("/api/v1/auth/me",
                                headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401


# ─── Token refresh ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestTokenRefresh:
    async def test_valid_refresh_token_issues_new_pair(
        self, client: AsyncClient, admin_user: User
    ):
        refresh = create_refresh_token(admin_user.id)
        resp = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert "refresh_token" in data

    async def test_access_token_rejected_as_refresh(
        self, client: AsyncClient, admin_user: User
    ):
        access = create_access_token(admin_user.id)
        resp = await client.post("/api/v1/auth/refresh", json={"refresh_token": access})
        assert resp.status_code == 401

    async def test_invalid_refresh_token_returns_401(self, client: AsyncClient):
        resp = await client.post("/api/v1/auth/refresh",
                                 json={"refresh_token": "invalid.jwt.token"})
        assert resp.status_code == 401


# ─── Admin user creation ──────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestAdminUserCreation:
    async def test_admin_can_create_analyst(
        self, client: AsyncClient, admin_user: User, admin_headers: dict
    ):
        resp = await client.post("/api/v1/auth/users", headers=admin_headers, json={
            "email":     "newanalyst@premoscorp.com",
            "full_name": "New Analyst",
            "password":  "Analyst@9999!",
            "role":      "analyst",
        })
        assert resp.status_code in (200, 201)
        data = resp.json()
        assert data["role"] == "analyst"
        assert data["email"] == "newanalyst@premoscorp.com"

    async def test_analyst_cannot_create_user(
        self, client: AsyncClient, analyst_user: User, analyst_headers: dict
    ):
        resp = await client.post("/api/v1/auth/users", headers=analyst_headers, json={
            "email":     "sneaky@premoscorp.com",
            "full_name": "Sneaky",
            "password":  "Sneaky@123!",
        })
        assert resp.status_code == 403

    async def test_unauthenticated_cannot_create_user(self, client: AsyncClient):
        resp = await client.post("/api/v1/auth/users", json={
            "email":     "ghost@premoscorp.com",
            "full_name": "Ghost",
            "password":  "Ghost@123!",
        })
        assert resp.status_code in (401, 403)


# ─── User list ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestUserList:
    async def test_admin_can_list_users(
        self, client: AsyncClient, admin_user: User, admin_headers: dict
    ):
        resp = await client.get("/api/v1/auth/users", headers=admin_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert any(u["email"] == "admin@premoscorp.com" for u in data)

    async def test_analyst_cannot_list_users(
        self, client: AsyncClient, analyst_user: User, analyst_headers: dict
    ):
        resp = await client.get("/api/v1/auth/users", headers=analyst_headers)
        assert resp.status_code == 403

    async def test_viewer_cannot_list_users(
        self, client: AsyncClient, viewer_user: User, viewer_headers: dict
    ):
        resp = await client.get("/api/v1/auth/users", headers=viewer_headers)
        assert resp.status_code == 403


# ─── Admin unlock endpoint (P19.2) ───────────────────────────────────────────

@pytest.mark.asyncio
class TestAdminUnlock:
    async def test_unlock_locked_user(
        self,
        client: AsyncClient,
        db,
        admin_user: User,
        admin_headers: dict,
        analyst_user: User,
    ):
        from datetime import timedelta
        analyst_user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)
        analyst_user.failed_login_attempts = 5
        await db.commit()

        resp = await client.post(
            f"/api/v1/auth/users/{analyst_user.id}/unlock",
            headers=admin_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["user"]["is_locked"] is False
        assert data["user"]["failed_login_attempts"] == 0

    async def test_unlock_already_unlocked_user_returns_message(
        self,
        client: AsyncClient,
        admin_user: User,
        admin_headers: dict,
        analyst_user: User,
    ):
        resp = await client.post(
            f"/api/v1/auth/users/{analyst_user.id}/unlock",
            headers=admin_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "no está bloqueada" in data["message"]

    async def test_unlock_nonexistent_user_returns_404(
        self, client: AsyncClient, admin_user: User, admin_headers: dict
    ):
        resp = await client.post(
            "/api/v1/auth/users/does-not-exist/unlock",
            headers=admin_headers,
        )
        assert resp.status_code == 404

    async def test_analyst_cannot_unlock(
        self, client: AsyncClient, analyst_user: User, analyst_headers: dict
    ):
        resp = await client.post(
            f"/api/v1/auth/users/{analyst_user.id}/unlock",
            headers=analyst_headers,
        )
        assert resp.status_code == 403

    async def test_unauthenticated_cannot_unlock(
        self, client: AsyncClient, analyst_user: User
    ):
        resp = await client.post(
            f"/api/v1/auth/users/{analyst_user.id}/unlock"
        )
        assert resp.status_code == 401
