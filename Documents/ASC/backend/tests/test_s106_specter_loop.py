"""
S106.1 — Prueba del loop end-to-end SPECTER → detección → alerta (+ respuesta honesta).

HALLAZGO S106: la telemetría del agente (AgentEvent) se almacenaba pero NUNCA
generaba alertas. Este test prueba el PUENTE nuevo (detect_from_agent_events)
con eventos FIRMADOS de verdad (Ed25519, como el agente real, en modo estricto):
correlación (mismas reglas) + anomalía/severidad, alertas scopeadas al tenant del
agente. Cierra con la honestidad del lado de respuesta.
"""
from __future__ import annotations

import base64
import time
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption,
)
from sqlalchemy import select

from asc_api.core.signing import sign_command
from asc_api.models.agent import Agent
from asc_api.models.alert import Alert
from asc_api.services import agent_commander as AC
from asc_api.services import neutralizer


def _keypair() -> tuple[str, str]:
    priv = Ed25519PrivateKey.generate()
    raw_priv = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    raw_pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw_priv).decode(), base64.b64encode(raw_pub).decode()


async def _mk_agent(db, pub_b64, tenant_id="tenant-aaaa", host="ws-01"):
    ag = Agent(
        id=str(uuid.uuid4()), hostname=host, os_type="windows", os_version="10",
        arch="x86_64", ip_address="10.0.0.5", public_key=pub_b64, tenant_id=tenant_id,
    )
    db.add(ag)
    await db.commit()
    await db.refresh(ag)
    return ag


def _signed(priv_b64: str, **fields) -> dict:
    ev = {"ts": time.time(), **fields}
    sig = sign_command(priv_b64, ev)   # firma sobre el canonical (sin 'signature')
    return {**ev, "signature": sig}


class TestSpecterLoop:
    @pytest.mark.asyncio
    async def test_telemetria_firmada_dispara_correlacion(self, db):
        priv, pub = _keypair()
        ag = await _mk_agent(db, pub)
        raws = [
            _signed(priv, event_type="auth", category="authentication",
                    action="login_failed", severity="info")
            for _ in range(3)
        ]
        acc, rej, accepted = await AC.ingest_events(db, ag, raws)
        assert acc == 3, "eventos firmados deben aceptarse en modo estricto"
        alert_ids = await AC.detect_from_agent_events(db, ag, accepted)
        assert alert_ids, "la telemetría de fuerza bruta DEBE generar alerta (puente S106)"
        alerts = (await db.execute(select(Alert).where(Alert.id.in_(alert_ids)))).scalars().all()
        assert any("fuerza" in a.title.lower() or "brute" in a.title.lower() for a in alerts)
        assert all(a.tenant_id == ag.tenant_id for a in alerts)

    @pytest.mark.asyncio
    async def test_evento_critico_genera_alerta_por_severidad(self, db):
        priv, pub = _keypair()
        ag = await _mk_agent(db, pub, tenant_id="tenant-bbbb", host="srv-9")
        acc, rej, accepted = await AC.ingest_events(
            db, ag, [_signed(priv, event_type="proc_exec", severity="critical")]
        )
        assert acc == 1
        alert_ids = await AC.detect_from_agent_events(db, ag, accepted)
        alerts = (await db.execute(select(Alert).where(Alert.id.in_(alert_ids)))).scalars().all()
        assert any(a.severity == "high" for a in alerts)
        assert all(a.tenant_id == "tenant-bbbb" for a in alerts)
        assert any("srv-9" in a.title for a in alerts)

    @pytest.mark.asyncio
    async def test_alertas_del_agente_scopeadas_por_tenant(self, db):
        p1, k1 = _keypair(); p2, k2 = _keypair()
        a1 = await _mk_agent(db, k1, tenant_id="t-1", host="h1")
        a2 = await _mk_agent(db, k2, tenant_id="t-2", host="h2")
        _, _, ev1 = await AC.ingest_events(db, a1, [_signed(p1, event_type="x", severity="high")])
        _, _, ev2 = await AC.ingest_events(db, a2, [_signed(p2, event_type="y", severity="high")])
        ids1 = await AC.detect_from_agent_events(db, a1, ev1)
        ids2 = await AC.detect_from_agent_events(db, a2, ev2)
        al1 = (await db.execute(select(Alert).where(Alert.id.in_(ids1)))).scalars().all()
        al2 = (await db.execute(select(Alert).where(Alert.id.in_(ids2)))).scalars().all()
        assert al1 and al2, "cada agente debe generar alertas reales"
        assert all(a.tenant_id == "t-1" for a in al1)
        assert all(a.tenant_id == "t-2" for a in al2)

    @pytest.mark.asyncio
    async def test_batch_vacio_no_crea_alertas(self, db):
        _, pub = _keypair()
        ag = await _mk_agent(db, pub, tenant_id="t-3")
        acc, rej, accepted = await AC.ingest_events(db, ag, [])
        assert (acc, rej, accepted) == (0, 0, [])
        assert await AC.detect_from_agent_events(db, ag, accepted) == []

    @pytest.mark.asyncio
    async def test_lado_respuesta_es_honesto_sin_adaptador(self):
        res = await neutralizer.block_ip("1.2.3.4")
        assert res.success is False
        assert res.simulated is True
        assert res.status == "simulated"
