"""S111.2 — aislamiento por tenant en /events/ingest[/bulk] + list."""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from asc_api.models.event import Event
from asc_api.models.user import User
from asc_api.core.security import create_access_token, get_password_hash


async def _mk_user(db, tenant_id, role="analyst"):
    u = User(email=f"u-{uuid.uuid4().hex[:8]}@x.com", full_name="U",
             hashed_password=get_password_hash("Xx@12345!"),
             role=role, is_active=True, tenant_id=tenant_id)
    db.add(u); await db.commit(); await db.refresh(u)
    return u


def _ev(src):
    return {"source": src, "category": "authentication", "action": "login", "host": "h", "data": {}}


class TestEventsTenantIsolation:
    @pytest.mark.asyncio
    async def test_ingest_setea_tenant_del_usuario(self, client, db):
        u = await _mk_user(db, "t-1")
        h = {"Authorization": f"Bearer {create_access_token(u.id)}"}
        r = await client.post("/api/v1/events/ingest", json=_ev("s1"), headers=h)
        assert r.status_code == 200
        ev = (await db.execute(select(Event).where(Event.id == r.json()["event_id"]))).scalar_one()
        assert ev.tenant_id == "t-1"

    @pytest.mark.asyncio
    async def test_bulk_setea_tenant(self, client, db):
        u = await _mk_user(db, "t-9")
        h = {"Authorization": f"Bearer {create_access_token(u.id)}"}
        r = await client.post("/api/v1/events/ingest/bulk", json={"events": [_ev("b1"), _ev("b2")]}, headers=h)
        assert r.status_code == 200
        rows = (await db.execute(select(Event).where(Event.source.in_(["b1", "b2"])))).scalars().all()
        assert rows and all(e.tenant_id == "t-9" for e in rows)

    @pytest.mark.asyncio
    async def test_list_no_muestra_eventos_de_otro_tenant(self, client, db):
        u1 = await _mk_user(db, "t-a")
        u2 = await _mk_user(db, "t-b")
        h1 = {"Authorization": f"Bearer {create_access_token(u1.id)}"}
        h2 = {"Authorization": f"Bearer {create_access_token(u2.id)}"}
        await client.post("/api/v1/events/ingest", json=_ev("sa"), headers=h1)
        await client.post("/api/v1/events/ingest", json=_ev("sb"), headers=h2)
        r1 = await client.get("/api/v1/events", headers=h1)
        sources = {e["source"] for e in r1.json()}
        assert "sa" in sources and "sb" not in sources   # t-a NO ve el de t-b
