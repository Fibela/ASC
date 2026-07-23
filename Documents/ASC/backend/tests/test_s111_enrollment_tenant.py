"""S111.3 — enrolamiento de agente ATADO a tenant (token que embebe tenant_id)."""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from asc_api.core.specter_security import (
    generate_enrollment_token,
    generate_tenant_enrollment_token,
    verify_and_extract_tenant,
)
from asc_api.models.agent import Agent

_SECRET = "test-enrollment-secret-123"


class TestTokenConTenant:
    def test_token_con_tenant_verifica_y_extrae(self):
        tok = generate_tenant_enrollment_token(_SECRET, "tenant-A")
        valid, tid = verify_and_extract_tenant(_SECRET, tok)
        assert valid is True and tid == "tenant-A"

    def test_token_global_legacy_da_tenant_none(self):
        tok = generate_enrollment_token(_SECRET)          # sin tenant
        valid, tid = verify_and_extract_tenant(_SECRET, tok)
        assert valid is True and tid is None

    def test_tenant_manipulado_es_invalido(self):
        tok = generate_tenant_enrollment_token(_SECRET, "tenant-A")
        # cambiar la parte del tenant (b64) rompe el HMAC
        import base64
        bad_b64 = base64.urlsafe_b64encode(b"tenant-EVIL").decode().rstrip("=")
        tampered = bad_b64 + "." + tok.split(".", 1)[1]
        valid, tid = verify_and_extract_tenant(_SECRET, tampered)
        assert valid is False

    def test_secreto_vacio_es_dev_mode(self):
        valid, tid = verify_and_extract_tenant("", "lo-que-sea")
        assert valid is True and tid is None

    def test_secreto_incorrecto_rechaza(self):
        tok = generate_tenant_enrollment_token(_SECRET, "tenant-A")
        valid, _ = verify_and_extract_tenant("otro-secreto", tok)
        assert valid is False


class TestRegisterAtaTenant:
    @pytest.mark.asyncio
    async def test_register_usa_tenant_del_token_no_del_payload(self, client, db, monkeypatch):
        monkeypatch.setattr("asc_api.api.v1.endpoints.agents.settings.SPECTER_ENROLLMENT_SECRET", _SECRET)
        token = generate_tenant_enrollment_token(_SECRET, "tenant-REAL")
        host = f"h-{uuid.uuid4().hex[:8]}"
        payload = {
            "hostname": host, "os_type": "linux", "os_version": "22", "arch": "x86_64",
            "ip_address": "10.0.0.9", "public_key": "k", "specter_version": "1.0.0",
            "tenant_id": "tenant-FALSO-del-payload",   # debe IGNORARSE
        }
        r = await client.post("/api/v1/agents/register", json=payload,
                              headers={"X-Specter-Token": token})
        assert r.status_code == 200
        ag = (await db.execute(select(Agent).where(Agent.hostname == host))).scalar_one()
        assert ag.tenant_id == "tenant-REAL"           # del token, NO del payload

    @pytest.mark.asyncio
    async def test_register_token_invalido_rechaza(self, client, db, monkeypatch):
        monkeypatch.setattr("asc_api.api.v1.endpoints.agents.settings.SPECTER_ENROLLMENT_SECRET", _SECRET)
        payload = {
            "hostname": "h-x", "os_type": "linux", "os_version": "22", "arch": "x86_64",
            "ip_address": "10.0.0.9", "public_key": "k", "specter_version": "1.0.0",
        }
        r = await client.post("/api/v1/agents/register", json=payload,
                              headers={"X-Specter-Token": "token-invalido"})
        assert r.status_code == 403
