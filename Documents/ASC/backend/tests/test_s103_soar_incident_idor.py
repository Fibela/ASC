"""
S103.6 — Regresión de seguridad: IDOR cross-tenant en SOAR (triggers) e incidentes.

Antes: get/delete/toggle_trigger y get_incident/list_incidents consultaban por id
sin filtro de tenant. Un analista del tenant A podía leer/modificar/borrar los
triggers de automatización y los incidentes del tenant B por id.

Fix: SOAR scopea con tenant_id explícito del usuario; incidentes scopean vía el
ContextVar (ligado al usuario autenticado en deps._resolve_user, S103.2). Este
test prueba, end-to-end contra la app real, que ambos exploits están cerrados.
"""
from __future__ import annotations

import uuid
import pytest

from asc_api.models.user import User
from asc_api.models.tenant import Tenant
from asc_api.models.soar import PlaybookTrigger
from asc_api.models.incident import Incident
from asc_api.core.security import create_access_token, get_password_hash


async def _analyst(db, slug: str):
    tid = str(uuid.uuid4())
    db.add(Tenant(id=tid, name=slug, slug=f"{slug}-{tid[:8]}", profile="pyme"))
    u = User(id=str(uuid.uuid4()), email=f"an-{tid[:8]}@x.com", full_name="A",
             hashed_password=get_password_hash("Xx@12345!"), role="analyst",
             is_active=True, tenant_id=tid)
    db.add(u); await db.commit()
    return tid, u, {"Authorization": f"Bearer {create_access_token(u.id, tenant_id=tid)}"}


async def _trigger(db, tenant_id: str) -> str:
    t = PlaybookTrigger(id=str(uuid.uuid4()), tenant_id=tenant_id,
                        playbook_id="PB-1", condition_type="risk_score", condition_value="80", created_by="b@x.com")
    db.add(t); await db.commit()
    return t.id


async def _incident(db, tenant_id: str) -> str:
    inc = Incident(id=str(uuid.uuid4()), tenant_id=tenant_id, title="Brecha B",
                   created_by="b@x.com", severity="high")
    db.add(inc); await db.commit()
    return inc.id


class TestSoarTriggerIDOR:
    @pytest.mark.asyncio
    async def test_cannot_read_other_tenant_trigger(self, client, db):
        tb, _, _ = await _analyst(db, "beta")
        trig = await _trigger(db, tb)
        _, _, ha = await _analyst(db, "alfa")
        r = await client.get(f"/api/v1/soar/triggers/{trig}", headers=ha)
        assert r.status_code == 404, "IDOR: A leyó el trigger de B"

    @pytest.mark.asyncio
    async def test_cannot_delete_other_tenant_trigger(self, client, db):
        tb, _, _ = await _analyst(db, "beta")
        trig = await _trigger(db, tb)
        _, _, ha = await _analyst(db, "alfa")
        r = await client.delete(f"/api/v1/soar/triggers/{trig}", headers=ha)
        assert r.status_code == 404, "IDOR: A borró el trigger de B"

    @pytest.mark.asyncio
    async def test_cannot_toggle_other_tenant_trigger(self, client, db):
        tb, _, _ = await _analyst(db, "beta")
        trig = await _trigger(db, tb)
        _, _, ha = await _analyst(db, "alfa")
        r = await client.patch(f"/api/v1/soar/triggers/{trig}/toggle", json={"enabled": False}, headers=ha)
        assert r.status_code == 404, "IDOR: A desactivó el trigger de B"

    @pytest.mark.asyncio
    async def test_owner_can_read_own_trigger(self, client, db):
        ta, _, ha = await _analyst(db, "gamma")
        trig = await _trigger(db, ta)
        r = await client.get(f"/api/v1/soar/triggers/{trig}", headers=ha)
        assert r.status_code == 200


class TestIncidentIDOR:
    @pytest.mark.asyncio
    async def test_cannot_read_other_tenant_incident(self, client, db):
        tb, _, _ = await _analyst(db, "beta")
        inc = await _incident(db, tb)
        _, _, ha = await _analyst(db, "alfa")
        r = await client.get(f"/api/v1/incidents/{inc}", headers=ha)
        assert r.status_code == 404, "IDOR: A leyó el incidente de B"

    @pytest.mark.asyncio
    async def test_list_excludes_other_tenant_incidents(self, client, db):
        tb, _, _ = await _analyst(db, "beta")
        inc_b = await _incident(db, tb)
        _, _, ha = await _analyst(db, "alfa")
        r = await client.get("/api/v1/incidents", headers=ha)
        assert r.status_code == 200
        ids = [i.get("id") for i in (r.json() if isinstance(r.json(), list) else r.json().get("items", []))]
        assert inc_b not in ids, "FUGA: el listado de A incluyó el incidente de B"

    @pytest.mark.asyncio
    async def test_cannot_mutate_other_tenant_incident(self, client, db):
        tb, _, _ = await _analyst(db, "beta")
        inc = await _incident(db, tb)
        _, _, ha = await _analyst(db, "alfa")
        r = await client.patch(f"/api/v1/incidents/{inc}/status", json={"new_status": "contained"}, headers=ha)
        assert r.status_code in (404, 400, 422), f"IDOR: A mutó el incidente de B (status {r.status_code})"

    @pytest.mark.asyncio
    async def test_owner_can_read_own_incident(self, client, db):
        ta, _, ha = await _analyst(db, "delta")
        inc = await _incident(db, ta)
        r = await client.get(f"/api/v1/incidents/{inc}", headers=ha)
        assert r.status_code == 200
