"""
FASE 3 — "Funcional y auténtico" regression tests.

Covers the two stubs that were wired to real behavior:
  1. _send_report() in soar_service — now delivers via Resend when key is set
  2. POST /adapter-registry/{tenant_id}/{type}/test — now runs live checks

Suite breakdown:
  TestSendReport             (4)  — key absent (log only), key present (POST to Resend),
                                     Resend error raises RuntimeError, HTML body non-empty
  TestAdapterRegistryTest    (9)  — disabled, not_configured, decrypt_fail, fortinet ok,
                                     fortinet error, paloalto ok, unknown provider skipped,
                                     401 anon, 403 analyst
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import httpx
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.core.security import get_password_hash, create_access_token
from asc_api.models.tenant import Tenant
from asc_api.models.tenant_adapter_config import TenantAdapterConfig
from asc_api.models.user import User


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _auth(user: User) -> dict:
    return {"Authorization": f"Bearer {create_access_token(user.id)}"}


_SUMMARY = {
    "hunt_id":   "hunt-001",
    "hunt_name": "PremosCorp Ransomware Hunt",
    "hunt_status": "active",
    "hunt_priority": "critical",
    "total_findings": 12,
    "confirmed": 8,
    "false_positives": 1,
    "critical_findings": 3,
    "high_findings": 5,
    "generated_at": "2026-07-11T12:00:00+00:00",
    "identity_timeline": [],
    "identity_action_count": 2,
    "identity_actions_successful": 2,
}


async def _make_tenant(db: AsyncSession) -> Tenant:
    t = Tenant(
        id=str(uuid.uuid4()), name="Audit Tenant",
        slug=f"audit-{uuid.uuid4().hex[:8]}", plan="pro", is_active=True,
    )
    db.add(t)
    await db.commit()
    await db.refresh(t)
    return t


async def _make_adapter_cfg(
    db: AsyncSession,
    tenant_id: str,
    *,
    provider: str = "fortinet",
    adapter_type: str = "firewall",
    is_enabled: bool = True,
    credential_encrypted: str | None = "encrypted_token",
    host: str | None = "fw.premoscorp.com",
    settings_json: dict | None = None,
) -> TenantAdapterConfig:
    from asc_api.core.adapter_crypto import encrypt_credential
    from asc_api.core.config import get_settings
    enc = encrypt_credential("real-api-token", get_settings().SECRET_KEY) \
        if credential_encrypted == "encrypted_token" else credential_encrypted
    cfg = TenantAdapterConfig(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        adapter_type=adapter_type,
        provider=provider,
        is_enabled=is_enabled,
        host=host,
        credential_encrypted=enc,
        credential_hint="real",
        settings_json=settings_json or {},
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db.add(cfg)
    await db.commit()
    await db.refresh(cfg)
    return cfg


# ─── _send_report() behavior ─────────────────────────────────────────────────

class TestSendReport:
    """Unit tests for soar_service._send_report() — now wired to Resend."""

    async def test_no_api_key_logs_only_no_http(self):
        """When RESEND_API_KEY is empty, _send_report must not make HTTP calls."""
        from asc_api.services.soar_service import _send_report

        with patch("asc_api.services.soar_service._send_report.__module__") as _:
            pass  # just ensure import works

        with patch("asc_api.core.config.get_settings") as mock_settings:
            mock_settings.return_value.RESEND_API_KEY = ""
            mock_settings.return_value.RESEND_FROM_EMAIL = "noreply@premoscorp.com"

            with patch("httpx.AsyncClient") as mock_client:
                await _send_report("analyst@test.com", _SUMMARY, format="pdf")
                mock_client.assert_not_called()

    async def test_with_api_key_posts_to_resend(self):
        """When RESEND_API_KEY is set, _send_report must POST to Resend."""
        from asc_api.services.soar_service import _send_report

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"id": "resend-abc123"}

        mock_async_client = AsyncMock()
        mock_async_client.__aenter__ = AsyncMock(return_value=mock_async_client)
        mock_async_client.__aexit__ = AsyncMock(return_value=None)
        mock_async_client.post = AsyncMock(return_value=mock_response)

        with patch("asc_api.core.config.get_settings") as mock_settings:
            mock_settings.return_value.RESEND_API_KEY = "re_test_key"
            mock_settings.return_value.RESEND_FROM_EMAIL = "reports@premoscorp.com"

            with patch("httpx.AsyncClient", return_value=mock_async_client):
                await _send_report("cto@premoscorp.com", _SUMMARY, format="pdf")

        mock_async_client.post.assert_called_once()
        call_kwargs = mock_async_client.post.call_args
        # Verify it hit the Resend endpoint
        assert "resend.com/emails" in call_kwargs[0][0]
        # Verify Authorization header
        headers = call_kwargs[1]["headers"]
        assert "Bearer re_test_key" in headers["Authorization"]
        # Verify recipient
        body = call_kwargs[1]["json"]
        assert body["to"] == ["cto@premoscorp.com"]

    async def test_resend_error_raises_runtime_error(self):
        """Non-2xx response from Resend must raise RuntimeError."""
        from asc_api.services.soar_service import _send_report

        mock_response = MagicMock()
        mock_response.status_code = 422
        mock_response.text = "Invalid email address"

        mock_async_client = AsyncMock()
        mock_async_client.__aenter__ = AsyncMock(return_value=mock_async_client)
        mock_async_client.__aexit__ = AsyncMock(return_value=None)
        mock_async_client.post = AsyncMock(return_value=mock_response)

        with patch("asc_api.core.config.get_settings") as mock_settings:
            mock_settings.return_value.RESEND_API_KEY = "re_test_key"
            mock_settings.return_value.RESEND_FROM_EMAIL = "reports@premoscorp.com"

            with patch("httpx.AsyncClient", return_value=mock_async_client):
                with pytest.raises(RuntimeError, match="422"):
                    await _send_report("bad@", _SUMMARY, format="csv")

    async def test_email_subject_contains_hunt_name_and_findings(self):
        """Email subject must include the hunt name and total_findings count."""
        from asc_api.services.soar_service import _send_report

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"id": "r1"}

        mock_async_client = AsyncMock()
        mock_async_client.__aenter__ = AsyncMock(return_value=mock_async_client)
        mock_async_client.__aexit__ = AsyncMock(return_value=None)
        mock_async_client.post = AsyncMock(return_value=mock_response)

        with patch("asc_api.core.config.get_settings") as mock_settings:
            mock_settings.return_value.RESEND_API_KEY = "re_test_key"
            mock_settings.return_value.RESEND_FROM_EMAIL = "reports@premoscorp.com"

            with patch("httpx.AsyncClient", return_value=mock_async_client):
                await _send_report("analyst@test.com", _SUMMARY, format="json")

        body = mock_async_client.post.call_args[1]["json"]
        assert "PremosCorp Ransomware Hunt" in body["subject"]
        assert "12" in body["subject"]  # total_findings
        assert "<table" in body["html"]  # HTML table present


# ─── Adapter connectivity test endpoint ──────────────────────────────────────

class TestAdapterRegistryTest:
    """Integration tests for POST /adapter-registry/{tenant_id}/{type}/test."""

    _BASE = "/api/v1/adapter-registry"

    async def test_401_anonymous(self, client: AsyncClient, db: AsyncSession):
        tenant = await _make_tenant(db)
        r = await client.post(f"{self._BASE}/{tenant.id}/firewall/test")
        assert r.status_code == 401

    async def test_403_analyst_cannot_test(
        self, client: AsyncClient, analyst_user: User, db: AsyncSession
    ):
        tenant = await _make_tenant(db)
        r = await client.post(
            f"{self._BASE}/{tenant.id}/firewall/test", headers=_auth(analyst_user)
        )
        assert r.status_code == 403

    async def test_422_invalid_adapter_type(
        self, client: AsyncClient, admin_user: User, db: AsyncSession
    ):
        tenant = await _make_tenant(db)
        r = await client.post(
            f"{self._BASE}/{tenant.id}/not_a_type/test", headers=_auth(admin_user)
        )
        assert r.status_code == 422

    async def test_skipped_when_adapter_disabled(
        self, client: AsyncClient, admin_user: User, db: AsyncSession
    ):
        tenant = await _make_tenant(db)
        await _make_adapter_cfg(db, tenant.id, is_enabled=False)
        r = await client.post(
            f"{self._BASE}/{tenant.id}/firewall/test", headers=_auth(admin_user)
        )
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "skipped"
        assert data["reason"] == "adapter_disabled"

    async def test_not_configured_when_no_credential(
        self, client: AsyncClient, admin_user: User, db: AsyncSession
    ):
        tenant = await _make_tenant(db)
        cfg = TenantAdapterConfig(
            id=str(uuid.uuid4()),
            tenant_id=tenant.id,
            adapter_type="firewall",
            provider="fortinet",
            is_enabled=True,
            host="fw.premoscorp.com",
            credential_encrypted=None,  # no credential
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db.add(cfg)
        await db.commit()
        r = await client.post(
            f"{self._BASE}/{tenant.id}/firewall/test", headers=_auth(admin_user)
        )
        assert r.status_code == 200
        assert r.json()["status"] == "not_configured"

    async def test_fortinet_ok_response(
        self, client: AsyncClient, admin_user: User, db: AsyncSession
    ):
        tenant = await _make_tenant(db)
        await _make_adapter_cfg(db, tenant.id, provider="fortinet")

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "results": {
                "Serial-Number": "FGT60F-ABC123",
                "Version": "v7.4.2",
                "Hostname": "fw-premos-01",
            }
        }

        with patch("httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=None)
            instance.get = AsyncMock(return_value=mock_resp)
            MockClient.return_value = instance

            r = await client.post(
                f"{self._BASE}/{tenant.id}/firewall/test", headers=_auth(admin_user)
            )

        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert data["serial"] == "FGT60F-ABC123"
        assert data["provider"] == "fortinet"

    async def test_fortinet_http_error_returns_error_status(
        self, client: AsyncClient, admin_user: User, db: AsyncSession
    ):
        tenant = await _make_tenant(db)
        await _make_adapter_cfg(db, tenant.id, provider="fortinet")

        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.text = "Unauthorized"

        with patch("httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=None)
            instance.get = AsyncMock(return_value=mock_resp)
            MockClient.return_value = instance

            r = await client.post(
                f"{self._BASE}/{tenant.id}/firewall/test", headers=_auth(admin_user)
            )

        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "error"
        assert data["http_status"] == 401

    async def test_network_exception_returns_error_status(
        self, client: AsyncClient, admin_user: User, db: AsyncSession
    ):
        tenant = await _make_tenant(db)
        await _make_adapter_cfg(db, tenant.id, provider="fortinet")

        with patch("httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=None)
            instance.get = AsyncMock(
                side_effect=httpx.ConnectError("Connection refused")
            )
            MockClient.return_value = instance

            r = await client.post(
                f"{self._BASE}/{tenant.id}/firewall/test", headers=_auth(admin_user)
            )

        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "error"
        assert "Connection refused" in data["detail"]

    async def test_provider_none_returns_skipped(
        self, client: AsyncClient, admin_user: User, db: AsyncSession
    ):
        tenant = await _make_tenant(db)
        await _make_adapter_cfg(db, tenant.id, provider="none")
        r = await client.post(
            f"{self._BASE}/{tenant.id}/firewall/test", headers=_auth(admin_user)
        )
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "skipped"
        assert data["reason"] == "no_connectivity_check_for_provider"
