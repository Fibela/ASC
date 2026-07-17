"""
S103.7 — Regresión del barrido sistemático de IDOR por-id.

Cierra la familia completa (S103.2 webhooks/api-keys list, S103.6 SOAR/incidentes,
S103.7 el resto). Prueba E2E que un analista del tenant A no alcanza recursos del
tenant B por id, a través de los tres estilos de fix aplicados:
  - hunt: choke point get_hunt (ContextVar) — cubre lecturas y mutaciones
  - api_key: choke point _get_key_or_404 (ContextVar)
  - ioc: query inline en el endpoint (current_user.tenant_id)
"""
from __future__ import annotations

import uuid
import pytest

from asc_api.models.user import User
from asc_api.models.tenant import Tenant
from asc_api.models.hunt import Hunt
from asc_api.models.api_key import APIKey
from asc_api.models.ioc import IoC
from asc_api.core.security import create_access_token, get_password_hash


async def _analyst(db, slug: str):
    tid = str(uuid.uuid4())
    db.add(Tenant(id=tid, name=slug, slug=f"{slug}-{tid[:8]}", profile="pyme"))
    u = User(id=str(uuid.uuid4()), email=f"an-{tid[:8]}@x.com", full_name="A",
             hashed_password=get_password_hash("Xx@12345!"), role="analyst",
             is_active=True, tenant_id=tid)
    db.add(u); await db.commit()
    return tid, u, {"Authorization": f"Bearer {create_access_token(u.id, tenant_id=tid)}"}


class TestHuntIDOR:
    @pytest.mark.asyncio
    async def test_cannot_read_other_tenant_hunt(self, client, db):
        tb, ub, _ = await _analyst(db, "beta")
        h = Hunt(id=str(uuid.uuid4()), tenant_id=tb, name="Caza B", created_by=ub.email)
        db.add(h); await db.commit()
        _, _, ha = await _analyst(db, "alfa")
        r = await client.get(f"/api/v1/hunt/{h.id}", headers=ha)
        assert r.status_code == 404, "IDOR: A leyó el hunt de B"

    @pytest.mark.asyncio
    async def test_owner_reads_own_hunt(self, client, db):
        ta, ua, ha = await _analyst(db, "gamma")
        h = Hunt(id=str(uuid.uuid4()), tenant_id=ta, name="Caza A", created_by=ua.email)
        db.add(h); await db.commit()
        r = await client.get(f"/api/v1/hunt/{h.id}", headers=ha)
        assert r.status_code == 200


class TestApiKeyIDOR:
    @pytest.mark.asyncio
    async def test_cannot_read_other_tenant_api_key(self, client, db):
        tb, ub, _ = await _analyst(db, "beta")
        k = APIKey(id=str(uuid.uuid4()), tenant_id=tb, user_id=ub.id, name="k",
                   key_prefix="abcd1234", key_hash="h"*64)
        db.add(k); await db.commit()
        _, _, ha = await _analyst(db, "alfa")
        r = await client.get(f"/api/v1/api-keys/{k.id}", headers=ha)
        assert r.status_code == 404, "IDOR: A leyó la API key de B"


class TestIocIDOR:
    @pytest.mark.asyncio
    async def test_cannot_deactivate_other_tenant_ioc(self, client, db):
        tb, _, _ = await _analyst(db, "beta")
        ioc = IoC(id=str(uuid.uuid4()), tenant_id=tb, value="1.2.3.4", ioc_type="ip", source="manual")
        db.add(ioc); await db.commit()
        _, _, ha = await _analyst(db, "alfa")
        r = await client.delete(f"/api/v1/iocs/{ioc.id}", headers=ha)
        assert r.status_code == 404, "IDOR: A desactivó el IoC de B"

    @pytest.mark.asyncio
    async def test_owner_deactivates_own_ioc(self, client, db):
        ta, _, ha = await _analyst(db, "delta")
        ioc = IoC(id=str(uuid.uuid4()), tenant_id=ta, value="9.9.9.9", ioc_type="ip", source="manual")
        db.add(ioc); await db.commit()
        r = await client.delete(f"/api/v1/iocs/{ioc.id}", headers=ha)
        assert r.status_code == 200
