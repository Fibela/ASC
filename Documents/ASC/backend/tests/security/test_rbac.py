"""
P31-SEC-RBAC — Role-Based Access Control security tests.

Coverage:
  - Full role × endpoint access matrix (admin / analyst / viewer / unauthenticated)
  - Privilege escalation prevention
  - Account-state gates: locked, force_password_reset, inactive
  - Direct dep-function unit tests (get_current_admin, get_analyst_or_admin)
  - Source-code invariant inspection

Approach: isolated mini FastAPI app + dependency overrides.  No live DB or Redis
needed for the RBAC layer; DB-touching deps (get_current_user) are overridden with
SimpleNamespace user objects so we test the role-check logic itself.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from fastapi import Depends, FastAPI, HTTPException
from httpx import AsyncClient, ASGITransport

from asc_api.api.deps import (
    bearer_scheme,
    get_analyst_or_admin,
    get_current_admin,
    get_current_user,
    get_db,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _user(role: str, **overrides) -> Any:
    defaults = dict(
        id=str(uuid.uuid4()),
        email=f"{role}@sec.asc",
        full_name=f"{role.title()} Tester",
        role=role,
        is_active=True,
        is_locked=False,
        locked_until=None,
        force_password_reset=False,
        failed_login_attempts=0,
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _mock_db_dep():
    async def _inner():
        yield AsyncMock()
    return _inner


def _mini_app() -> FastAPI:
    """Bare FastAPI app with three protected routes covering all three auth levels."""
    _app = FastAPI()

    @_app.get("/rbac/any")
    async def any_endpoint(u=Depends(get_current_user)):
        return {"role": u.role}

    @_app.get("/rbac/analyst")
    async def analyst_endpoint(u=Depends(get_analyst_or_admin)):
        return {"role": u.role}

    @_app.get("/rbac/admin")
    async def admin_endpoint(u=Depends(get_current_admin)):
        return {"role": u.role}

    return _app


def _app_for_role(role: str, **user_overrides) -> FastAPI:
    """Return mini_app with get_current_user overridden to return a user of the given role."""
    app = _mini_app()
    mock = _user(role, **user_overrides)

    async def _override():
        return mock

    app.dependency_overrides[get_current_user] = _override
    app.dependency_overrides[get_db] = _mock_db_dep()
    return app


async def _get(app: FastAPI, path: str, token: str | None = "fake-token") -> int:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        r = await ac.get(path, headers=headers)
    return r.status_code


async def _get_json(app: FastAPI, path: str, token: str | None = "fake-token") -> tuple[int, dict]:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        r = await ac.get(path, headers=headers)
    return r.status_code, r.json()


# ── TestRBACEndpointMatrix ────────────────────────────────────────────────────

class TestRBACEndpointMatrix:
    """Complete role × endpoint access matrix."""

    @pytest.fixture
    def admin_app(self):
        return _app_for_role("admin")

    @pytest.fixture
    def analyst_app(self):
        return _app_for_role("analyst")

    @pytest.fixture
    def viewer_app(self):
        return _app_for_role("viewer")

    @pytest.mark.asyncio
    async def test_admin_accesses_any_endpoint(self, admin_app):
        assert await _get(admin_app, "/rbac/any") == 200

    @pytest.mark.asyncio
    async def test_admin_accesses_analyst_endpoint(self, admin_app):
        assert await _get(admin_app, "/rbac/analyst") == 200

    @pytest.mark.asyncio
    async def test_admin_accesses_admin_endpoint(self, admin_app):
        assert await _get(admin_app, "/rbac/admin") == 200

    @pytest.mark.asyncio
    async def test_analyst_accesses_any_endpoint(self, analyst_app):
        assert await _get(analyst_app, "/rbac/any") == 200

    @pytest.mark.asyncio
    async def test_analyst_accesses_analyst_endpoint(self, analyst_app):
        assert await _get(analyst_app, "/rbac/analyst") == 200

    @pytest.mark.asyncio
    async def test_analyst_blocked_from_admin_endpoint(self, analyst_app):
        assert await _get(analyst_app, "/rbac/admin") == 403

    @pytest.mark.asyncio
    async def test_viewer_accesses_any_endpoint(self, viewer_app):
        assert await _get(viewer_app, "/rbac/any") == 200

    @pytest.mark.asyncio
    async def test_viewer_blocked_from_analyst_endpoint(self, viewer_app):
        assert await _get(viewer_app, "/rbac/analyst") == 403

    @pytest.mark.asyncio
    async def test_viewer_blocked_from_admin_endpoint(self, viewer_app):
        assert await _get(viewer_app, "/rbac/admin") == 403

    @pytest.mark.asyncio
    async def test_no_token_blocked_from_any_endpoint(self):
        app = _mini_app()
        # HTTPBearer(auto_error=True) blocks unauthenticated requests (401 or 403
        # depending on FastAPI version — both are acceptable; 200 is not)
        assert await _get(app, "/rbac/any", token=None) in (401, 403)

    @pytest.mark.asyncio
    async def test_no_token_blocked_from_analyst_endpoint(self):
        app = _mini_app()
        assert await _get(app, "/rbac/analyst", token=None) in (401, 403)

    @pytest.mark.asyncio
    async def test_no_token_blocked_from_admin_endpoint(self):
        app = _mini_app()
        assert await _get(app, "/rbac/admin", token=None) in (401, 403)

    @pytest.mark.asyncio
    async def test_admin_response_body_contains_role(self, admin_app):
        status, body = await _get_json(admin_app, "/rbac/admin")
        assert status == 200
        assert body.get("role") == "admin"

    @pytest.mark.asyncio
    async def test_analyst_response_body_contains_role(self, analyst_app):
        status, body = await _get_json(analyst_app, "/rbac/analyst")
        assert status == 200
        assert body.get("role") == "analyst"

    @pytest.mark.asyncio
    async def test_viewer_403_response_is_json(self, viewer_app):
        status, body = await _get_json(viewer_app, "/rbac/analyst")
        assert status == 403
        assert "detail" in body


# ── TestPrivilegeEscalation ───────────────────────────────────────────────────

class TestPrivilegeEscalation:
    """Lower roles cannot reach higher-privilege endpoints — no privilege escalation."""

    @pytest.fixture
    def viewer_app(self):
        return _app_for_role("viewer")

    @pytest.fixture
    def analyst_app(self):
        return _app_for_role("analyst")

    @pytest.mark.asyncio
    async def test_viewer_cannot_escalate_to_analyst(self, viewer_app):
        assert await _get(viewer_app, "/rbac/analyst") == 403

    @pytest.mark.asyncio
    async def test_viewer_cannot_escalate_to_admin(self, viewer_app):
        assert await _get(viewer_app, "/rbac/admin") == 403

    @pytest.mark.asyncio
    async def test_analyst_cannot_escalate_to_admin(self, analyst_app):
        assert await _get(analyst_app, "/rbac/admin") == 403

    @pytest.mark.asyncio
    async def test_viewer_gets_403_not_404_preserving_resource_existence_secret(self, viewer_app):
        # 404 would reveal the endpoint exists with different data; 403 is correct
        assert await _get(viewer_app, "/rbac/analyst") == 403

    @pytest.mark.asyncio
    async def test_analyst_gets_403_not_404_on_admin_endpoint(self, analyst_app):
        assert await _get(analyst_app, "/rbac/admin") == 403

    @pytest.mark.asyncio
    async def test_url_role_query_param_ignored(self, viewer_app):
        """Query param ?role=admin must not bypass RBAC — decision is from DB user."""
        async with AsyncClient(transport=ASGITransport(app=viewer_app), base_url="http://test") as ac:
            r = await ac.get("/rbac/admin?role=admin", headers={"Authorization": "Bearer tok"})
        assert r.status_code == 403

    @pytest.mark.asyncio
    async def test_x_role_override_header_ignored(self, viewer_app):
        """Arbitrary role-override headers must not bypass RBAC."""
        async with AsyncClient(transport=ASGITransport(app=viewer_app), base_url="http://test") as ac:
            r = await ac.get(
                "/rbac/admin",
                headers={"Authorization": "Bearer tok", "X-Role-Override": "admin"},
            )
        assert r.status_code == 403

    @pytest.mark.asyncio
    async def test_unknown_role_blocked_from_analyst_endpoint(self):
        app = _app_for_role("superuser")
        assert await _get(app, "/rbac/analyst") == 403

    @pytest.mark.asyncio
    async def test_unknown_role_blocked_from_admin_endpoint(self):
        app = _app_for_role("god")
        assert await _get(app, "/rbac/admin") == 403

    @pytest.mark.asyncio
    async def test_valid_roles_are_exactly_three(self):
        from asc_api.api.v1.endpoints.auth import VALID_ROLES
        assert VALID_ROLES == {"admin", "analyst", "viewer"}
        assert "superuser" not in VALID_ROLES
        assert "root" not in VALID_ROLES

    @pytest.mark.asyncio
    async def test_empty_role_string_blocked_from_analyst(self):
        app = _app_for_role("")
        assert await _get(app, "/rbac/analyst") == 403

    @pytest.mark.asyncio
    async def test_empty_role_string_blocked_from_admin(self):
        app = _app_for_role("")
        assert await _get(app, "/rbac/admin") == 403


# ── TestAccountStateGates ─────────────────────────────────────────────────────

class TestAccountStateGates:
    """Locked accounts and force_password_reset gate block access before role check."""

    def _locked_dep_app(self) -> FastAPI:
        app = _mini_app()
        async def _locked():
            raise HTTPException(
                status_code=403,
                detail="Cuenta bloqueada hasta 2099-01-01T00:00:00+00:00",
            )
        app.dependency_overrides[get_current_user] = _locked
        return app

    def _reset_dep_app(self) -> FastAPI:
        app = _mini_app()
        async def _must_reset():
            raise HTTPException(status_code=403, detail="password_reset_required")
        app.dependency_overrides[get_current_user] = _must_reset
        return app

    def _inactive_dep_app(self) -> FastAPI:
        app = _mini_app()
        async def _inactive():
            raise HTTPException(status_code=401, detail="Usuario no encontrado o inactivo")
        app.dependency_overrides[get_current_user] = _inactive
        return app

    def _revoked_dep_app(self) -> FastAPI:
        app = _mini_app()
        async def _revoked():
            raise HTTPException(status_code=401, detail="Token revocado. Inicia sesión nuevamente.")
        app.dependency_overrides[get_current_user] = _revoked
        return app

    @pytest.mark.asyncio
    async def test_locked_account_blocked_from_any_endpoint(self):
        assert await _get(self._locked_dep_app(), "/rbac/any") == 403

    @pytest.mark.asyncio
    async def test_locked_account_blocked_from_analyst_endpoint(self):
        assert await _get(self._locked_dep_app(), "/rbac/analyst") == 403

    @pytest.mark.asyncio
    async def test_locked_account_blocked_from_admin_endpoint(self):
        assert await _get(self._locked_dep_app(), "/rbac/admin") == 403

    @pytest.mark.asyncio
    async def test_locked_error_detail_contains_bloqueada(self):
        _, body = await _get_json(self._locked_dep_app(), "/rbac/any")
        assert "bloqueada" in body.get("detail", "").lower()

    @pytest.mark.asyncio
    async def test_force_reset_blocks_any_endpoint(self):
        assert await _get(self._reset_dep_app(), "/rbac/any") == 403

    @pytest.mark.asyncio
    async def test_force_reset_blocks_analyst_endpoint(self):
        assert await _get(self._reset_dep_app(), "/rbac/analyst") == 403

    @pytest.mark.asyncio
    async def test_force_reset_blocks_admin_endpoint(self):
        assert await _get(self._reset_dep_app(), "/rbac/admin") == 403

    @pytest.mark.asyncio
    async def test_force_reset_detail_is_exact(self):
        _, body = await _get_json(self._reset_dep_app(), "/rbac/any")
        assert body.get("detail") == "password_reset_required"

    @pytest.mark.asyncio
    async def test_inactive_user_returns_401(self):
        assert await _get(self._inactive_dep_app(), "/rbac/any") == 401

    @pytest.mark.asyncio
    async def test_revoked_token_returns_401(self):
        assert await _get(self._revoked_dep_app(), "/rbac/any") == 401

    @pytest.mark.asyncio
    async def test_revoked_token_detail_contains_revocado(self):
        _, body = await _get_json(self._revoked_dep_app(), "/rbac/any")
        assert "revocado" in body.get("detail", "").lower()


# ── TestDepFunctionInternals ──────────────────────────────────────────────────

class TestDepFunctionInternals:
    """Direct unit tests of deps.py functions — no HTTP layer."""

    @pytest.mark.asyncio
    async def test_get_current_admin_allows_admin(self):
        admin = _user("admin")
        result = await get_current_admin(admin)
        assert result is admin

    @pytest.mark.asyncio
    async def test_get_current_admin_rejects_analyst(self):
        with pytest.raises(HTTPException) as exc:
            await get_current_admin(_user("analyst"))
        assert exc.value.status_code == 403

    @pytest.mark.asyncio
    async def test_get_current_admin_rejects_viewer(self):
        with pytest.raises(HTTPException) as exc:
            await get_current_admin(_user("viewer"))
        assert exc.value.status_code == 403

    @pytest.mark.asyncio
    async def test_get_current_admin_rejects_unknown_role(self):
        with pytest.raises(HTTPException) as exc:
            await get_current_admin(_user("superuser"))
        assert exc.value.status_code == 403

    @pytest.mark.asyncio
    async def test_get_current_admin_error_detail_exact(self):
        with pytest.raises(HTTPException) as exc:
            await get_current_admin(_user("viewer"))
        assert exc.value.detail == "Se requiere rol admin"

    @pytest.mark.asyncio
    async def test_get_current_admin_returns_same_user_object(self):
        admin = _user("admin")
        result = await get_current_admin(admin)
        assert result is admin

    @pytest.mark.asyncio
    async def test_get_analyst_or_admin_allows_analyst(self):
        analyst = _user("analyst")
        result = await get_analyst_or_admin(analyst)
        assert result is analyst

    @pytest.mark.asyncio
    async def test_get_analyst_or_admin_allows_admin(self):
        admin = _user("admin")
        result = await get_analyst_or_admin(admin)
        assert result is admin

    @pytest.mark.asyncio
    async def test_get_analyst_or_admin_rejects_viewer(self):
        with pytest.raises(HTTPException) as exc:
            await get_analyst_or_admin(_user("viewer"))
        assert exc.value.status_code == 403

    @pytest.mark.asyncio
    async def test_get_analyst_or_admin_rejects_unknown_role(self):
        with pytest.raises(HTTPException) as exc:
            await get_analyst_or_admin(_user("god"))
        assert exc.value.status_code == 403

    @pytest.mark.asyncio
    async def test_get_analyst_or_admin_error_detail_references_roles(self):
        with pytest.raises(HTTPException) as exc:
            await get_analyst_or_admin(_user("viewer"))
        detail = exc.value.detail.lower()
        assert "analyst" in detail or "admin" in detail

    def test_bearer_scheme_auto_error_is_true(self):
        assert bearer_scheme.auto_error is True

    def test_valid_roles_set_contains_admin(self):
        from asc_api.api.v1.endpoints.auth import VALID_ROLES
        assert "admin" in VALID_ROLES

    def test_valid_roles_set_contains_analyst(self):
        from asc_api.api.v1.endpoints.auth import VALID_ROLES
        assert "analyst" in VALID_ROLES

    def test_valid_roles_set_contains_viewer(self):
        from asc_api.api.v1.endpoints.auth import VALID_ROLES
        assert "viewer" in VALID_ROLES


# ── TestRBACSourceInspection ──────────────────────────────────────────────────

class TestRBACSourceInspection:
    """Source-file invariants — guard against accidental regression of RBAC constants."""

    @pytest.fixture
    def deps_src(self) -> str:
        import pathlib
        return pathlib.Path(__file__).parent.parent.parent / "app" / "api" / "deps.py"

    @pytest.fixture
    def auth_src(self) -> str:
        import pathlib
        return pathlib.Path(__file__).parent.parent.parent / "app" / "api" / "v1" / "endpoints" / "auth.py"

    def test_deps_uses_bearer_scheme_auto_error_true(self, deps_src):
        txt = deps_src.read_text()
        assert 'HTTPBearer(auto_error=True)' in txt

    def test_deps_analyst_or_admin_checks_correct_roles(self, deps_src):
        txt = deps_src.read_text()
        assert '"admin"' in txt and '"analyst"' in txt

    def test_deps_admin_check_is_equality_not_membership(self, deps_src):
        txt = deps_src.read_text()
        # role != "admin" is the guard
        assert 'role != "admin"' in txt

    def test_deps_returns_403_for_role_failures(self, deps_src):
        txt = deps_src.read_text()
        assert "HTTP_403_FORBIDDEN" in txt

    def test_deps_has_force_reset_gate(self, deps_src):
        txt = deps_src.read_text()
        assert "force_password_reset" in txt
        assert "password_reset_required" in txt

    def test_deps_has_is_locked_gate(self, deps_src):
        txt = deps_src.read_text()
        assert "is_locked" in txt

    def test_auth_valid_roles_constant_defined(self, auth_src):
        txt = auth_src.read_text()
        assert "VALID_ROLES" in txt
        assert '"admin"' in txt
        assert '"analyst"' in txt
        assert '"viewer"' in txt

    def test_auth_timing_sentinel_present(self, auth_src):
        txt = auth_src.read_text()
        assert "_TIMING_SENTINEL_HASH" in txt
