"""
S103.2 — Regresión de seguridad: IDOR cross-tenant vía header X-Tenant-ID.

Vulnerabilidad (OWASP A01 · Broken Access Control): el TenantMiddleware permitía
que el header no autenticado `X-Tenant-ID` sobrescribiera el claim firmado del
JWT. Un admin del tenant A podía leer datos del tenant B con un simple header.

Fix: el tenant del contexto se deriva SOLO del principal autenticado
(claim del JWT + re-ligado en deps._resolve_user al user.tenant_id). El header
ya no influye. Este test prueba, de punta a punta contra la app real, que el
exploit está cerrado.
"""
from __future__ import annotations

import uuid
import pytest

from asc_api.models.user import User
from asc_api.models.tenant import Tenant
from asc_api.models.webhook import Webhook
from asc_api.core.security import create_access_token, get_password_hash


async def _mk_tenant_admin(db, slug: str):
    tid = str(uuid.uuid4())
    db.add(Tenant(id=tid, name=slug, slug=f"{slug}-{tid[:8]}", profile="pyme"))
    u = User(
        id=str(uuid.uuid4()), email=f"admin-{tid[:8]}@x.com", full_name="A",
        hashed_password=get_password_hash("Xx@12345!"),
        role="admin", is_active=True, tenant_id=tid,
    )
    db.add(u)
    await db.commit()
    return tid, u


async def _mk_webhook(db, tenant_id: str, user_id: str, url: str):
    wh = Webhook(
        id=str(uuid.uuid4()), url=url, secret="s" * 40, events=["alert.created"],
        user_id=user_id, tenant_id=tenant_id, is_active=True,
    )
    db.add(wh)
    await db.commit()
    return wh


class TestCrossTenantIDOR:
    @pytest.mark.asyncio
    async def test_x_tenant_id_header_cannot_leak_other_tenant_webhooks(self, client, db):
        # Tenant B con un webhook propio.
        tid_b, user_b = await _mk_tenant_admin(db, "beta")
        await _mk_webhook(db, tid_b, user_b.id, "https://beta.example/hook")

        # Tenant A (atacante), admin, con su token firmado (tenant_id=A).
        tid_a, user_a = await _mk_tenant_admin(db, "alfa")
        token_a = create_access_token(user_a.id, tenant_id=tid_a)

        # A intenta robar los webhooks de B con el header X-Tenant-ID: B.
        r = await client.get(
            "/api/v1/webhooks",
            headers={"Authorization": f"Bearer {token_a}", "X-Tenant-ID": tid_b},
        )
        assert r.status_code == 200
        urls = [w["url"] for w in r.json()]
        assert "https://beta.example/hook" not in urls, (
            "FUGA CROSS-TENANT: el header X-Tenant-ID expuso datos del tenant B"
        )
        assert urls == [], "el admin de A no debería ver ningún webhook ajeno"

    @pytest.mark.asyncio
    async def test_admin_still_sees_own_tenant_webhooks(self, client, db):
        # Control positivo: A sí ve lo suyo (el fix no rompe el caso legítimo).
        tid_a, user_a = await _mk_tenant_admin(db, "gamma")
        await _mk_webhook(db, tid_a, user_a.id, "https://gamma.example/hook")
        token_a = create_access_token(user_a.id, tenant_id=tid_a)

        r = await client.get(
            "/api/v1/webhooks",
            headers={"Authorization": f"Bearer {token_a}"},
        )
        assert r.status_code == 200
        urls = [w["url"] for w in r.json()]
        assert "https://gamma.example/hook" in urls
