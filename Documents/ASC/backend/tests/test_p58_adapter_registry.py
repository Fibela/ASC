"""
P58 â€” Tenant Adapter Registry â€” Test Suite (TD-4)
==================================================
Tests: crypto helpers, ORM model, CRUD endpoints, RBAC enforcement,
       security invariants (credentials never leaked), migration artifact,
       module wiring.

Pattern: AsyncClient + ASGITransport â€” no real DB.
DB mocked via app.dependency_overrides[get_db] â†’ yields AsyncMock session.
Auth mocked via patch("asc_api.api.deps._resolve_user").

Tests: 75+ in 11 classes
"""

import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from asc_api.db.session import get_db
from asc_api.main import app

_MIGRATIONS_DIR = Path(__file__).parent.parent / "migrations" / "versions"
_BACKEND = Path(__file__).parent.parent

URL_BASE = "/api/v1/adapter-registry"

# â”€â”€ Mock builders â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


def _make_user(role: str = "admin"):
    u = MagicMock()
    u.id = str(uuid.uuid4())
    u.email = f"{role}@test.local"
    u.role = role
    u.is_active = True
    u.is_locked = False
    u.locked_until = None
    u.force_password_reset = False
    u.email_verified = True
    u.tenant_id = str(uuid.uuid4())
    return u


def _make_tenant(tenant_id: str | None = None):
    t = MagicMock()
    t.id = tenant_id or str(uuid.uuid4())
    t.name = "Test Corp"
    t.is_active = True
    return t


def _make_config(
    tenant_id: str | None = None,
    adapter_type: str = "edr",
    provider: str = "specter",
    is_enabled: bool = True,
    host: str | None = "specter.local",
    credential_encrypted: str | None = "enc_tok",
    credential_hint: str | None = "sk_t****",
):
    c = MagicMock()
    c.id = str(uuid.uuid4())
    c.tenant_id = tenant_id or str(uuid.uuid4())
    c.adapter_type = adapter_type
    c.provider = provider
    c.is_enabled = is_enabled
    c.host = host
    c.settings_json = None
    c.credential_encrypted = credential_encrypted
    c.credential_hint = credential_hint
    c.is_configured = credential_encrypted is not None
    c.display_provider = provider if provider != "none" else "disabled"
    c.created_at = datetime.now(timezone.utc)
    c.updated_at = datetime.now(timezone.utc)
    return c


def _make_db(tenant=None, config=None, configs=None):
    """
    Async DB mock whose execute() always returns a result supporting both:
      result.scalar_one_or_none()  â†’ point lookups
      result.scalars().all()       â†’ list queries
    Call 1 returns tenant; subsequent calls return config or configs.
    """
    db = AsyncMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    db.delete = AsyncMock()
    db.add = MagicMock()

    _call = {"n": 0}

    async def _execute(stmt, *args, **kwargs):
        _call["n"] += 1
        n = _call["n"]

        result = MagicMock()
        result.scalar_one_or_none = MagicMock(
            return_value=tenant if n == 1 else config
        )
        scalars_result = MagicMock()
        scalars_result.all = MagicMock(return_value=list(configs or []))
        result.scalars = MagicMock(return_value=scalars_result)
        return result

    db.execute = _execute

    async def _override():
        yield db

    return _override, db


def _auth(user):
    """Context manager: patches _resolve_user to return user."""
    return patch("asc_api.api.deps._resolve_user", AsyncMock(return_value=user))


# â”€â”€ 1. Adapter Crypto â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestAdapterCrypto:
    """Unit tests for Fernet encryption helpers in app.core.adapter_crypto."""

    _SK = "stable-secret-32chars-padding-!!"

    def test_encrypt_decrypt_roundtrip(self):
        from asc_api.core.adapter_crypto import encrypt_credential, decrypt_credential
        token = encrypt_credential("my-api-key", self._SK)
        assert decrypt_credential(token, self._SK) == "my-api-key"

    def test_encrypted_differs_from_plaintext(self):
        from asc_api.core.adapter_crypto import encrypt_credential
        assert encrypt_credential("value", self._SK) != "value"

    def test_encrypt_returns_str(self):
        from asc_api.core.adapter_crypto import encrypt_credential
        assert isinstance(encrypt_credential("v", self._SK), str)

    def test_decrypt_bad_token_raises_value_error(self):
        from asc_api.core.adapter_crypto import decrypt_credential
        with pytest.raises(ValueError, match="Invalid or tampered"):
            decrypt_credential("not-a-fernet-token", self._SK)

    def test_hint_first_four_plus_mask(self):
        from asc_api.core.adapter_crypto import credential_hint
        assert credential_hint("sk_test_abc123") == "sk_t****"

    def test_hint_short_credential(self):
        from asc_api.core.adapter_crypto import credential_hint
        assert credential_hint("AB") == "AB****"

    def test_hint_empty_string(self):
        from asc_api.core.adapter_crypto import credential_hint
        assert credential_hint("") == ""

    def test_different_secrets_different_tokens(self):
        from asc_api.core.adapter_crypto import encrypt_credential
        sk2 = "other-secret-32chars-padding-!!"
        t1 = encrypt_credential("v", self._SK)
        t2 = encrypt_credential("v", sk2)
        assert t1 != t2

    def test_fernet_random_iv_per_call(self):
        """Same plaintext â†’ different ciphertext each call (random IV)."""
        from asc_api.core.adapter_crypto import encrypt_credential
        assert encrypt_credential("v", self._SK) != encrypt_credential("v", self._SK)

    def test_decrypt_wrong_secret_raises(self):
        from asc_api.core.adapter_crypto import encrypt_credential, decrypt_credential
        token = encrypt_credential("v", self._SK)
        with pytest.raises(ValueError):
            decrypt_credential(token, "wrong-secret-32chars-padding-!!!")


# â”€â”€ 2. TenantAdapterConfig model â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestTenantAdapterConfigModel:

    def test_tablename(self):
        from asc_api.models.tenant_adapter_config import TenantAdapterConfig
        assert TenantAdapterConfig.__tablename__ == "tenant_adapter_configs"

    def test_adapter_types_has_five(self):
        from asc_api.models.tenant_adapter_config import ADAPTER_TYPES
        assert len(ADAPTER_TYPES) == 5
        assert ADAPTER_TYPES >= {"edr", "firewall", "identity", "siem", "soar"}

    def test_edr_providers(self):
        from asc_api.models.tenant_adapter_config import ADAPTER_PROVIDERS
        assert {"specter", "none"}.issubset(ADAPTER_PROVIDERS["edr"])

    def test_firewall_providers(self):
        from asc_api.models.tenant_adapter_config import ADAPTER_PROVIDERS
        assert {"paloalto", "fortinet", "none"}.issubset(ADAPTER_PROVIDERS["firewall"])

    def test_identity_providers(self):
        from asc_api.models.tenant_adapter_config import ADAPTER_PROVIDERS
        assert "active_directory" in ADAPTER_PROVIDERS["identity"]

    def test_siem_providers(self):
        from asc_api.models.tenant_adapter_config import ADAPTER_PROVIDERS
        assert {"elasticsearch", "wazuh"}.issubset(ADAPTER_PROVIDERS["siem"])

    def test_soar_providers(self):
        from asc_api.models.tenant_adapter_config import ADAPTER_PROVIDERS
        assert "thehive" in ADAPTER_PROVIDERS["soar"]

    def test_is_configured_true(self):
        from asc_api.models.tenant_adapter_config import TenantAdapterConfig
        assert TenantAdapterConfig(credential_encrypted="tok").is_configured is True

    def test_is_configured_false(self):
        from asc_api.models.tenant_adapter_config import TenantAdapterConfig
        assert TenantAdapterConfig(credential_encrypted=None).is_configured is False

    def test_display_provider_known(self):
        from asc_api.models.tenant_adapter_config import TenantAdapterConfig
        assert TenantAdapterConfig(provider="specter").display_provider == "specter"

    def test_display_provider_none_disabled(self):
        from asc_api.models.tenant_adapter_config import TenantAdapterConfig
        assert TenantAdapterConfig(provider="none").display_provider == "disabled"

    def test_unique_constraint_name(self):
        from asc_api.models.tenant_adapter_config import TenantAdapterConfig
        args = TenantAdapterConfig.__table_args__
        names = [c.name for c in args if hasattr(c, "name")]
        assert "uq_tenant_adapter_type" in names

    def test_exported_from_models_init(self):
        from asc_api.models import TenantAdapterConfig
        assert TenantAdapterConfig.__tablename__ == "tenant_adapter_configs"


# â”€â”€ 3. GET /types â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestGetAdapterTypes:

    URL = f"{URL_BASE}/types"

    @pytest.mark.anyio
    async def test_admin_gets_200(self):
        override, _ = _make_db()
        app.dependency_overrides[get_db] = override
        with _auth(_make_user("admin")):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.get(self.URL, headers={"Authorization": "Bearer fake"})
        app.dependency_overrides.pop(get_db, None)
        assert r.status_code == 200

    @pytest.mark.anyio
    async def test_analyst_gets_200(self):
        override, _ = _make_db()
        app.dependency_overrides[get_db] = override
        with _auth(_make_user("analyst")):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.get(self.URL, headers={"Authorization": "Bearer fake"})
        app.dependency_overrides.pop(get_db, None)
        assert r.status_code == 200

    @pytest.mark.anyio
    async def test_returns_5_types(self):
        override, _ = _make_db()
        app.dependency_overrides[get_db] = override
        with _auth(_make_user("admin")):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.get(self.URL, headers={"Authorization": "Bearer fake"})
        app.dependency_overrides.pop(get_db, None)
        assert len(r.json()) == 5

    @pytest.mark.anyio
    async def test_includes_all_type_names(self):
        override, _ = _make_db()
        app.dependency_overrides[get_db] = override
        with _auth(_make_user("admin")):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.get(self.URL, headers={"Authorization": "Bearer fake"})
        app.dependency_overrides.pop(get_db, None)
        types = {t["adapter_type"] for t in r.json()}
        assert {"edr", "firewall", "identity", "siem", "soar"} == types

    @pytest.mark.anyio
    async def test_requires_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get(self.URL)
        assert r.status_code in (401, 403)


# â”€â”€ 4. GET /{tenant_id} â€” list adapters â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestListTenantAdapters:

    @pytest.mark.anyio
    async def test_returns_200(self):
        tid = str(uuid.uuid4())
        cfg = _make_config(tid)
        override, _ = _make_db(tenant=_make_tenant(tid), configs=[cfg])
        app.dependency_overrides[get_db] = override
        with _auth(_make_user("admin")):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.get(f"{URL_BASE}/{tid}", headers={"Authorization": "Bearer fake"})
        app.dependency_overrides.pop(get_db, None)
        assert r.status_code == 200

    @pytest.mark.anyio
    async def test_tenant_not_found_returns_404(self):
        override, _ = _make_db(tenant=None)
        app.dependency_overrides[get_db] = override
        with _auth(_make_user("admin")):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.get(f"{URL_BASE}/nonexistent",
                                headers={"Authorization": "Bearer fake"})
        app.dependency_overrides.pop(get_db, None)
        assert r.status_code == 404

    @pytest.mark.anyio
    async def test_credential_not_in_response(self):
        tid = str(uuid.uuid4())
        cfg = _make_config(tid, credential_encrypted="TOP_SECRET_FERNET_TOKEN")
        override, _ = _make_db(tenant=_make_tenant(tid), configs=[cfg])
        app.dependency_overrides[get_db] = override
        with _auth(_make_user("admin")):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.get(f"{URL_BASE}/{tid}", headers={"Authorization": "Bearer fake"})
        app.dependency_overrides.pop(get_db, None)
        assert "TOP_SECRET_FERNET_TOKEN" not in r.text
        assert "credential_encrypted" not in r.text

    @pytest.mark.anyio
    async def test_requires_auth(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.get(f"{URL_BASE}/any-tenant")
        assert r.status_code in (401, 403)


# â”€â”€ 5. GET /{tenant_id}/{adapter_type} â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestGetTenantAdapter:

    @pytest.mark.anyio
    async def test_returns_200(self):
        tid = str(uuid.uuid4())
        cfg = _make_config(tid, adapter_type="edr")
        override, _ = _make_db(tenant=_make_tenant(tid), config=cfg)
        app.dependency_overrides[get_db] = override
        with _auth(_make_user("admin")):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.get(f"{URL_BASE}/{tid}/edr",
                                headers={"Authorization": "Bearer fake"})
        app.dependency_overrides.pop(get_db, None)
        assert r.status_code == 200

    @pytest.mark.anyio
    async def test_invalid_type_422(self):
        override, _ = _make_db(tenant=_make_tenant())
        app.dependency_overrides[get_db] = override
        with _auth(_make_user("admin")):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.get(f"{URL_BASE}/tid/invalid_type",
                                headers={"Authorization": "Bearer fake"})
        app.dependency_overrides.pop(get_db, None)
        assert r.status_code == 422

    @pytest.mark.anyio
    async def test_config_not_found_404(self):
        tid = str(uuid.uuid4())
        override, _ = _make_db(tenant=_make_tenant(tid), config=None)
        app.dependency_overrides[get_db] = override
        with _auth(_make_user("admin")):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.get(f"{URL_BASE}/{tid}/edr",
                                headers={"Authorization": "Bearer fake"})
        app.dependency_overrides.pop(get_db, None)
        assert r.status_code == 404

    @pytest.mark.anyio
    async def test_credential_not_in_response(self):
        tid = str(uuid.uuid4())
        cfg = _make_config(tid, credential_encrypted="LEAKED_SECRET_VALUE")
        override, _ = _make_db(tenant=_make_tenant(tid), config=cfg)
        app.dependency_overrides[get_db] = override
        with _auth(_make_user("admin")):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.get(f"{URL_BASE}/{tid}/edr",
                                headers={"Authorization": "Bearer fake"})
        app.dependency_overrides.pop(get_db, None)
        assert "LEAKED_SECRET_VALUE" not in r.text
        assert "credential_encrypted" not in r.text


# â”€â”€ 6. POST /{tenant_id} â€” create â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestCreateTenantAdapter:

    @pytest.mark.anyio
    async def test_analyst_forbidden(self):
        override, _ = _make_db()
        app.dependency_overrides[get_db] = override
        with _auth(_make_user("analyst")):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.post(f"{URL_BASE}/tid",
                                 json={"adapter_type": "edr", "provider": "specter"},
                                 headers={"Authorization": "Bearer fake"})
        app.dependency_overrides.pop(get_db, None)
        assert r.status_code == 403

    @pytest.mark.anyio
    async def test_invalid_adapter_type_422(self):
        override, _ = _make_db()
        app.dependency_overrides[get_db] = override
        with _auth(_make_user("admin")):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.post(f"{URL_BASE}/tid",
                                 json={"adapter_type": "unknown", "provider": "specter"},
                                 headers={"Authorization": "Bearer fake"})
        app.dependency_overrides.pop(get_db, None)
        assert r.status_code == 422

    @pytest.mark.anyio
    async def test_invalid_provider_422(self):
        override, _ = _make_db()
        app.dependency_overrides[get_db] = override
        with _auth(_make_user("admin")):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.post(f"{URL_BASE}/tid",
                                 json={"adapter_type": "edr", "provider": "crowdstrike"},
                                 headers={"Authorization": "Bearer fake"})
        app.dependency_overrides.pop(get_db, None)
        assert r.status_code == 422

    @pytest.mark.anyio
    async def test_duplicate_returns_409(self):
        tid = str(uuid.uuid4())
        existing = _make_config(tid, adapter_type="edr")
        override, _ = _make_db(tenant=_make_tenant(tid), config=existing)
        app.dependency_overrides[get_db] = override
        with _auth(_make_user("admin")):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.post(f"{URL_BASE}/{tid}",
                                 json={"adapter_type": "edr", "provider": "specter"},
                                 headers={"Authorization": "Bearer fake"})
        app.dependency_overrides.pop(get_db, None)
        assert r.status_code == 409

    @pytest.mark.anyio
    async def test_create_returns_201(self):
        tid = str(uuid.uuid4())
        override, _ = _make_db(tenant=_make_tenant(tid), config=None)
        app.dependency_overrides[get_db] = override
        with _auth(_make_user("admin")), \
             patch("asc_api.api.v1.endpoints.adapter_registry.encrypt_credential",
                   return_value="fernet_enc"):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.post(
                    f"{URL_BASE}/{tid}",
                    json={"adapter_type": "edr", "provider": "specter",
                          "host": "specter.local", "credential": "sk_test_xyz"},
                    headers={"Authorization": "Bearer fake"},
                )
        app.dependency_overrides.pop(get_db, None)
        assert r.status_code == 201

    @pytest.mark.anyio
    async def test_credential_not_in_create_response(self):
        tid = str(uuid.uuid4())
        override, _ = _make_db(tenant=_make_tenant(tid), config=None)
        app.dependency_overrides[get_db] = override
        with _auth(_make_user("admin")), \
             patch("asc_api.api.v1.endpoints.adapter_registry.encrypt_credential",
                   return_value="super_secret_fernet"):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.post(
                    f"{URL_BASE}/{tid}",
                    json={"adapter_type": "firewall", "provider": "paloalto",
                          "credential": "MY_REAL_API_KEY"},
                    headers={"Authorization": "Bearer fake"},
                )
        app.dependency_overrides.pop(get_db, None)
        body = r.text
        assert "MY_REAL_API_KEY" not in body
        assert "super_secret_fernet" not in body
        assert "credential_encrypted" not in body

    @pytest.mark.anyio
    async def test_tenant_not_found_404(self):
        override, _ = _make_db(tenant=None)
        app.dependency_overrides[get_db] = override
        with _auth(_make_user("admin")):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.post(f"{URL_BASE}/bad-tenant",
                                 json={"adapter_type": "edr", "provider": "specter"},
                                 headers={"Authorization": "Bearer fake"})
        app.dependency_overrides.pop(get_db, None)
        assert r.status_code == 404


# â”€â”€ 7. PUT /{tenant_id}/{adapter_type} â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestUpdateTenantAdapter:

    @pytest.mark.anyio
    async def test_analyst_forbidden(self):
        override, _ = _make_db()
        app.dependency_overrides[get_db] = override
        with _auth(_make_user("analyst")):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.put(f"{URL_BASE}/tid/edr",
                                json={"is_enabled": False},
                                headers={"Authorization": "Bearer fake"})
        app.dependency_overrides.pop(get_db, None)
        assert r.status_code == 403

    @pytest.mark.anyio
    async def test_invalid_type_422(self):
        override, _ = _make_db()
        app.dependency_overrides[get_db] = override
        with _auth(_make_user("admin")):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.put(f"{URL_BASE}/tid/bad_type",
                                json={"is_enabled": False},
                                headers={"Authorization": "Bearer fake"})
        app.dependency_overrides.pop(get_db, None)
        assert r.status_code == 422

    @pytest.mark.anyio
    async def test_config_not_found_404(self):
        tid = str(uuid.uuid4())
        override, _ = _make_db(tenant=_make_tenant(tid), config=None)
        app.dependency_overrides[get_db] = override
        with _auth(_make_user("admin")):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.put(f"{URL_BASE}/{tid}/edr",
                                json={"is_enabled": False},
                                headers={"Authorization": "Bearer fake"})
        app.dependency_overrides.pop(get_db, None)
        assert r.status_code == 404

    @pytest.mark.anyio
    async def test_update_is_enabled_returns_200(self):
        tid = str(uuid.uuid4())
        cfg = _make_config(tid, adapter_type="edr")
        override, _ = _make_db(tenant=_make_tenant(tid), config=cfg)
        app.dependency_overrides[get_db] = override
        with _auth(_make_user("admin")):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.put(f"{URL_BASE}/{tid}/edr",
                                json={"is_enabled": False},
                                headers={"Authorization": "Bearer fake"})
        app.dependency_overrides.pop(get_db, None)
        assert r.status_code == 200

    @pytest.mark.anyio
    async def test_invalid_provider_422(self):
        tid = str(uuid.uuid4())
        cfg = _make_config(tid, adapter_type="edr")
        override, _ = _make_db(tenant=_make_tenant(tid), config=cfg)
        app.dependency_overrides[get_db] = override
        with _auth(_make_user("admin")):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.put(f"{URL_BASE}/{tid}/edr",
                                json={"provider": "crowdstrike"},
                                headers={"Authorization": "Bearer fake"})
        app.dependency_overrides.pop(get_db, None)
        assert r.status_code == 422


# â”€â”€ 8. DELETE /{tenant_id}/{adapter_type} â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestDeleteTenantAdapter:

    @pytest.mark.anyio
    async def test_returns_204(self):
        tid = str(uuid.uuid4())
        cfg = _make_config(tid)
        override, _ = _make_db(tenant=_make_tenant(tid), config=cfg)
        app.dependency_overrides[get_db] = override
        with _auth(_make_user("admin")):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.delete(f"{URL_BASE}/{tid}/edr",
                                   headers={"Authorization": "Bearer fake"})
        app.dependency_overrides.pop(get_db, None)
        assert r.status_code == 204

    @pytest.mark.anyio
    async def test_not_found_404(self):
        tid = str(uuid.uuid4())
        override, _ = _make_db(tenant=_make_tenant(tid), config=None)
        app.dependency_overrides[get_db] = override
        with _auth(_make_user("admin")):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.delete(f"{URL_BASE}/{tid}/edr",
                                   headers={"Authorization": "Bearer fake"})
        app.dependency_overrides.pop(get_db, None)
        assert r.status_code == 404

    @pytest.mark.anyio
    async def test_analyst_forbidden(self):
        override, _ = _make_db()
        app.dependency_overrides[get_db] = override
        with _auth(_make_user("analyst")):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.delete(f"{URL_BASE}/tid/edr",
                                   headers={"Authorization": "Bearer fake"})
        app.dependency_overrides.pop(get_db, None)
        assert r.status_code == 403

    @pytest.mark.anyio
    async def test_invalid_type_422(self):
        override, _ = _make_db()
        app.dependency_overrides[get_db] = override
        with _auth(_make_user("admin")):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.delete(f"{URL_BASE}/tid/unknown_type",
                                   headers={"Authorization": "Bearer fake"})
        app.dependency_overrides.pop(get_db, None)
        assert r.status_code == 422


# â”€â”€ 9. POST /{tenant_id}/{adapter_type}/test â€” connectivity stub â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestTestAdapter:

    @pytest.mark.anyio
    async def test_stub_when_configured_and_enabled(self):
        tid = str(uuid.uuid4())
        cfg = _make_config(tid, is_enabled=True, credential_encrypted="tok")
        override, _ = _make_db(tenant=_make_tenant(tid), config=cfg)
        app.dependency_overrides[get_db] = override
        with _auth(_make_user("admin")):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.post(f"{URL_BASE}/{tid}/edr/test",
                                 headers={"Authorization": "Bearer fake"})
        app.dependency_overrides.pop(get_db, None)
        assert r.status_code == 200
        # FASE 3 wired real connectivity: invalid Fernet token → decrypt error
        assert r.json()["status"] == "error"
        assert r.json()["reason"] == "credential_decrypt_failed"

    @pytest.mark.anyio
    async def test_skipped_when_disabled(self):
        tid = str(uuid.uuid4())
        cfg = _make_config(tid, is_enabled=False)
        override, _ = _make_db(tenant=_make_tenant(tid), config=cfg)
        app.dependency_overrides[get_db] = override
        with _auth(_make_user("admin")):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.post(f"{URL_BASE}/{tid}/edr/test",
                                 headers={"Authorization": "Bearer fake"})
        app.dependency_overrides.pop(get_db, None)
        assert r.status_code == 200
        assert r.json()["status"] == "skipped"

    @pytest.mark.anyio
    async def test_not_configured_without_credential(self):
        tid = str(uuid.uuid4())
        cfg = _make_config(tid, is_enabled=True, credential_encrypted=None)
        override, _ = _make_db(tenant=_make_tenant(tid), config=cfg)
        app.dependency_overrides[get_db] = override
        with _auth(_make_user("admin")):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.post(f"{URL_BASE}/{tid}/edr/test",
                                 headers={"Authorization": "Bearer fake"})
        app.dependency_overrides.pop(get_db, None)
        assert r.status_code == 200
        assert r.json()["status"] == "not_configured"

    @pytest.mark.anyio
    async def test_analyst_forbidden(self):
        override, _ = _make_db()
        app.dependency_overrides[get_db] = override
        with _auth(_make_user("analyst")):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.post(f"{URL_BASE}/tid/edr/test",
                                 headers={"Authorization": "Bearer fake"})
        app.dependency_overrides.pop(get_db, None)
        assert r.status_code == 403


# â”€â”€ 10. Security invariants â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestSecurityInvariants:

    def test_response_schema_no_credential_field(self):
        from asc_api.api.v1.endpoints.adapter_registry import AdapterConfigResponse
        fields = AdapterConfigResponse.model_fields
        assert "credential" not in fields
        assert "credential_encrypted" not in fields

    def test_response_schema_has_is_configured(self):
        from asc_api.api.v1.endpoints.adapter_registry import AdapterConfigResponse
        assert "is_configured" in AdapterConfigResponse.model_fields

    def test_response_schema_has_credential_hint_not_value(self):
        from asc_api.api.v1.endpoints.adapter_registry import AdapterConfigResponse
        fields = AdapterConfigResponse.model_fields
        assert "credential_hint" in fields
        assert "credential_encrypted" not in fields

    def test_create_uses_get_current_admin(self):
        import inspect
        from asc_api.api.v1.endpoints.adapter_registry import create_tenant_adapter
        sig = str(inspect.signature(create_tenant_adapter).parameters)
        assert "get_current_admin" in sig

    def test_update_uses_get_current_admin(self):
        import inspect
        from asc_api.api.v1.endpoints.adapter_registry import update_tenant_adapter
        sig = str(inspect.signature(update_tenant_adapter).parameters)
        assert "get_current_admin" in sig

    def test_delete_uses_get_current_admin(self):
        import inspect
        from asc_api.api.v1.endpoints.adapter_registry import delete_tenant_adapter
        sig = str(inspect.signature(delete_tenant_adapter).parameters)
        assert "get_current_admin" in sig

    def test_list_uses_analyst_or_admin(self):
        import inspect
        from asc_api.api.v1.endpoints.adapter_registry import list_tenant_adapters
        sig = str(inspect.signature(list_tenant_adapters).parameters)
        assert "get_analyst_or_admin" in sig

    def test_get_uses_analyst_or_admin(self):
        import inspect
        from asc_api.api.v1.endpoints.adapter_registry import get_tenant_adapter
        sig = str(inspect.signature(get_tenant_adapter).parameters)
        assert "get_analyst_or_admin" in sig

    def test_none_provider_allowed_for_all_types(self):
        from asc_api.models.tenant_adapter_config import ADAPTER_PROVIDERS, ADAPTER_TYPES
        for t in ADAPTER_TYPES:
            assert "none" in ADAPTER_PROVIDERS[t], f"'none' missing from {t} providers"


# â”€â”€ 11. Migration + module structure â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestMigrationAndStructure:

    _HEAD = "t0n23q2s5m07"
    _TOTAL = 26  # P-16 (24) + b3c4d5e6f7a8 + c9d12f0e5b67 merge head

    def test_migration_file_exists(self):
        files = list(_MIGRATIONS_DIR.glob(f"*{self._HEAD}*.py"))
        assert len(files) == 1, f"Migration {self._HEAD} not found"

    def test_down_revision_is_p55(self):
        files = list(_MIGRATIONS_DIR.glob(f"*{self._HEAD}*.py"))
        content = files[0].read_text(encoding="utf-8")
        assert 'down_revision = "s9m12p1r4l06"' in content

    def test_creates_tenant_adapter_configs_table(self):
        files = list(_MIGRATIONS_DIR.glob(f"*{self._HEAD}*.py"))
        content = files[0].read_text(encoding="utf-8")
        assert "tenant_adapter_configs" in content

    def test_has_unique_constraint(self):
        files = list(_MIGRATIONS_DIR.glob(f"*{self._HEAD}*.py"))
        content = files[0].read_text(encoding="utf-8")
        assert "uq_tenant_adapter_type" in content

    def test_has_credential_encrypted_column(self):
        files = list(_MIGRATIONS_DIR.glob(f"*{self._HEAD}*.py"))
        content = files[0].read_text(encoding="utf-8")
        assert "credential_encrypted" in content

    def test_total_migration_count(self):
        files = [f for f in _MIGRATIONS_DIR.glob("*.py") if f.name != "__init__.py"]
        assert len(files) == self._TOTAL, (
            f"Expected {self._TOTAL} migrations, got {len(files)}"
        )

    def test_router_has_adapter_registry(self):
        src = (_BACKEND / "asc_api" / "api" / "v1" / "router.py").read_text(encoding="utf-8")
        assert "adapter_registry" in src
        assert "include_router(adapter_registry.router)" in src

    def test_model_in_models_init(self):
        from asc_api.models import TenantAdapterConfig
        assert TenantAdapterConfig.__tablename__ == "tenant_adapter_configs"

    def test_adapter_crypto_importable(self):
        from asc_api.core.adapter_crypto import encrypt_credential, decrypt_credential, credential_hint
        assert all(callable(f) for f in (encrypt_credential, decrypt_credential, credential_hint))

    def test_endpoint_router_prefix(self):
        from asc_api.api.v1.endpoints.adapter_registry import router
        assert router.prefix == "/adapter-registry"

    def test_cryptography_in_requirements(self):
        req = (_BACKEND / "requirements.txt").read_text(encoding="utf-8")
        assert "cryptography" in req

    def test_no_duplicate_revision_ids(self):
        revisions = []
        for f in _MIGRATIONS_DIR.glob("*.py"):
            if f.name == "__init__.py":
                continue
            for line in f.read_text(encoding="utf-8", errors="ignore").splitlines():
                if line.startswith("revision = "):
                    revisions.append(line.split("=")[1].strip().strip("\"'"))
        assert len(revisions) == len(set(revisions)), "Duplicate revision IDs detected"

    def test_p56_references_current_head(self):
        """test_p56 must reference a known head revision (P58 or later)."""
        src = (Path(__file__).parent / "test_p56_deployment_readiness.py").read_text(
            encoding="utf-8"
        )
        assert ("t0n23q2s5m07" in src or "u1o34r3t6n08" in src or "v2p45s4u7o09" in src or "w3q56t5v8p10" in src or "x4r67u6w9q11" in src or "y5s78t5v0r13" in src or "z6t89u7x1s14" in src or "a7b90v8w2x25" in src or "a8c01v9x3y26" in src or "c9d12f0e5b67" in src)

    def test_p57_references_current_count(self):
        """test_p57 must reference migration count >= 16 after P58."""
        src = (Path(__file__).parent / "test_p57_staging_goliove.py").read_text(
            encoding="utf-8"
        )
        assert ("_EXPECTED_MIGRATION_COUNT = 16" in src or
                "_EXPECTED_MIGRATION_COUNT = 17" in src or
                "_EXPECTED_MIGRATION_COUNT = 18" in src or
                "_EXPECTED_MIGRATION_COUNT = 20" in src or
                "_EXPECTED_MIGRATION_COUNT = 22" in src or
                "_EXPECTED_MIGRATION_COUNT = 23" in src or
                "_EXPECTED_MIGRATION_COUNT = 24" in src or
                "_EXPECTED_MIGRATION_COUNT = 25" in src or
                "_EXPECTED_MIGRATION_COUNT = 26" in src)
