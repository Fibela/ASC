"""
P47 â€” Multi-tenancy Foundation
================================
Tests verifying:
1. Tenant model is importable and has correct attributes
2. Alembic migration file exists with correct revision chain
3. All key data models have tenant_id column
4. tenant_id is nullable (backward-compatible with existing data)
5. Existing endpoints still work (regression: tenant_id doesn't break anything)

Testing approach
----------------
Schema and model tests: pure Python inspection (no real DB).
Endpoint regression: same async pattern as P45/P46 with app.dependency_overrides.

Security
--------
- tenant_id column is NULLABLE â€” NULL = single-tenant / default deployment
- No tenant enforcement yet (deferred to FASE 5)
- Existing auth/RBAC unaffected by P47 schema changes
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient, ASGITransport

from asc_api.core.security import create_access_token
from asc_api.db.session import get_db
from asc_api.main import app

_REPO_ROOT = Path(__file__).parent.parent


# â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _jwt(user_id: str) -> str:
    return create_access_token(user_id)


def _make_user(role: str = "analyst") -> MagicMock:
    u = MagicMock()
    u.id = str(uuid.uuid4())
    u.email = f"{role}@test.local"
    u.role = role
    u.is_active = True
    u.is_locked = False
    u.locked_until = None
    u.force_password_reset = False
    u.tenant_id = None
    return u


def _db_override(scalar_result=None, scalars_result=None):
    db = MagicMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    db.delete = AsyncMock()
    db.add = MagicMock()

    exec_result = MagicMock()
    exec_result.scalar_one_or_none.return_value = scalar_result
    exec_result.scalars.return_value.all.return_value = scalars_result or []
    exec_result.scalar_one.return_value = 0
    db.execute = AsyncMock(return_value=exec_result)

    async def override():
        yield db

    return override, db


# â”€â”€ Tenant model tests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestTenantModel:
    """Tenant model importable and has expected structure."""

    def test_tenant_model_importable(self):
        from asc_api.models.tenant import Tenant
        assert Tenant is not None

    def test_tenant_tablename(self):
        from asc_api.models.tenant import Tenant
        assert Tenant.__tablename__ == "tenants"

    def test_tenant_has_required_columns(self):
        from asc_api.models.tenant import Tenant
        cols = {c.name for c in Tenant.__table__.columns}
        required = {"id", "name", "slug", "plan", "is_active", "created_at"}
        assert required.issubset(cols)

    def test_tenant_has_optional_columns(self):
        from asc_api.models.tenant import Tenant
        cols = {c.name for c in Tenant.__table__.columns}
        assert "contact_email" in cols
        assert "max_users" in cols
        assert "max_api_keys_per_user" in cols

    def test_tenant_slug_unique(self):
        from asc_api.models.tenant import Tenant
        slug_col = next(c for c in Tenant.__table__.columns if c.name == "slug")
        assert slug_col.unique

    def test_tenant_plan_default(self):
        from asc_api.models.tenant import Tenant
        plan_col = next(c for c in Tenant.__table__.columns if c.name == "plan")
        assert plan_col.default is not None

    def test_tenant_in_models_init(self):
        from asc_api.models import Tenant
        assert Tenant is not None


# â”€â”€ tenant_id in key models â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestTenantIdColumns:
    """All key data models must have nullable tenant_id column."""

    def test_user_has_tenant_id(self):
        from asc_api.models.user import User
        cols = {c.name: c for c in User.__table__.columns}
        assert "tenant_id" in cols
        assert cols["tenant_id"].nullable

    def test_alert_has_tenant_id(self):
        from asc_api.models.alert import Alert
        cols = {c.name: c for c in Alert.__table__.columns}
        assert "tenant_id" in cols
        assert cols["tenant_id"].nullable

    def test_event_has_tenant_id(self):
        from asc_api.models.event import Event
        cols = {c.name: c for c in Event.__table__.columns}
        assert "tenant_id" in cols
        assert cols["tenant_id"].nullable

    def test_api_key_has_tenant_id(self):
        from asc_api.models.api_key import APIKey
        cols = {c.name: c for c in APIKey.__table__.columns}
        assert "tenant_id" in cols
        assert cols["tenant_id"].nullable

    def test_webhook_has_tenant_id(self):
        from asc_api.models.webhook import Webhook
        cols = {c.name: c for c in Webhook.__table__.columns}
        assert "tenant_id" in cols
        assert cols["tenant_id"].nullable

    def test_incident_has_tenant_id(self):
        from asc_api.models.incident import Incident
        cols = {c.name: c for c in Incident.__table__.columns}
        assert "tenant_id" in cols
        assert cols["tenant_id"].nullable

    def test_tenant_id_indexed_in_users(self):
        """tenant_id should be indexed for performant tenant-scoped queries."""
        from asc_api.models.user import User
        indexed = {
            col.name
            for idx in User.__table__.indexes
            for col in idx.columns
        }
        assert "tenant_id" in indexed

    def test_tenant_id_indexed_in_alerts(self):
        from asc_api.models.alert import Alert
        indexed = {
            col.name
            for idx in Alert.__table__.indexes
            for col in idx.columns
        }
        assert "tenant_id" in indexed


# â”€â”€ Migration file â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestMigrationFile:
    """P47 migration file exists and chains correctly."""

    def test_migration_file_exists(self):
        path = _REPO_ROOT / "migrations" / "versions" / "p6j79m8o1i93_add_multi_tenancy_p47.py"
        assert path.exists(), "P47 migration file not found"

    def test_migration_revision_id(self):
        path = _REPO_ROOT / "migrations" / "versions" / "p6j79m8o1i93_add_multi_tenancy_p47.py"
        content = path.read_text(encoding="utf-8")
        assert 'revision = "p6j79m8o1i93"' in content

    def test_migration_down_revision(self):
        """P47 must chain from P42 (webhooks)."""
        path = _REPO_ROOT / "migrations" / "versions" / "p6j79m8o1i93_add_multi_tenancy_p47.py"
        content = path.read_text(encoding="utf-8")
        assert 'down_revision = "n4h58k6m9g71"' in content

    def test_migration_creates_tenants_table(self):
        path = _REPO_ROOT / "migrations" / "versions" / "p6j79m8o1i93_add_multi_tenancy_p47.py"
        content = path.read_text(encoding="utf-8")
        assert "create_table" in content
        assert '"tenants"' in content

    def test_migration_adds_tenant_id_to_key_tables(self):
        path = _REPO_ROOT / "migrations" / "versions" / "p6j79m8o1i93_add_multi_tenancy_p47.py"
        content = path.read_text(encoding="utf-8")
        for table in ("users", "alerts", "events", "api_keys", "webhooks", "incidents"):
            assert f'"{table}"' in content, f"tenant_id migration missing for {table}"

    def test_migration_has_downgrade(self):
        path = _REPO_ROOT / "migrations" / "versions" / "p6j79m8o1i93_add_multi_tenancy_p47.py"
        content = path.read_text(encoding="utf-8")
        assert "def downgrade" in content
        assert "drop_table" in content


# â”€â”€ Regression: existing endpoints unaffected â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestP47Regression:
    """Verify P45/P46 endpoints still work after schema changes."""

    @pytest.mark.asyncio
    async def test_liveness_still_healthy(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            r = await ac.get("/health")
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_api_keys_list_still_requires_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            r = await ac.get("/api/v1/api-keys")
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_api_keys_list_still_works(self):
        user = _make_user("analyst")
        override, _ = _db_override(scalars_result=[])
        app.dependency_overrides[get_db] = override
        token = _jwt(user.id)

        with patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user)):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                r = await ac.get("/api/v1/api-keys", headers={"Authorization": f"Bearer {token}"})
        app.dependency_overrides.clear()
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_webhooks_still_requires_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            r = await ac.get("/api/v1/webhooks")
        assert r.status_code == 401

    def test_tenant_model_importable_with_all_models(self):
        """Full model registry import must succeed."""
        import asc_api.models
        assert hasattr(asc_api.models, "Tenant")
        assert hasattr(asc_api.models, "User")
        assert hasattr(asc_api.models, "Alert")
        assert hasattr(asc_api.models, "Webhook")

    def test_p46_rate_limits_page_still_present(self):
        path = Path(__file__).parent.parent.parent / "frontend" / "src" / "app" / "rate-limits" / "page.tsx"
        assert path.exists()

    def test_p45_api_keys_page_still_present(self):
        path = Path(__file__).parent.parent.parent / "frontend" / "src" / "app" / "api-keys" / "page.tsx"
        assert path.exists()
