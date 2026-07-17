"""
S103.5 — Endurecimiento de la ingesta de telemetría SPECTER.

Dos gaps verificados y corregidos:
  1. La firma Ed25519 no se hacía cumplir: eventos con firma inválida se
     almacenaban y contaban como aceptados; SPECTER_STRICT_SIGNATURE_MODE
     (documentado como "rechaza firma inválida") nunca se consultaba →
     inyección de telemetría spoofeada conociendo solo el ID del agente.
  2. AgentEvent no heredaba el tenant_id del agente → un tenant scoped no
     vería la telemetría de su propio agente (apply_tenant_filter: None = IS NULL).
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

from asc_api.models.agent import Agent, AgentEvent
from asc_api.core.signing import sign_command
from asc_api.services import agent_commander as AC


def _keypair() -> tuple[str, str]:
    priv = Ed25519PrivateKey.generate()
    raw_priv = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    raw_pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw_priv).decode(), base64.b64encode(raw_pub).decode()


async def _mk_agent(db, pub_b64: str, tenant_id: str | None):
    a = Agent(
        id=str(uuid.uuid4()), hostname="h", os_type="linux", os_version="U22",
        arch="x86_64", ip_address="10.0.0.9", public_key=pub_b64,
        specter_version="1.0.0", tenant_id=tenant_id,
    )
    db.add(a); await db.commit(); await db.refresh(a)
    return a


def _signed_event(priv_b64: str, event_type: str = "process") -> dict:
    ev = {"event_type": event_type, "severity": "info", "ts": time.time(), "pid": 4242}
    sig = sign_command(priv_b64, ev)          # firma sobre el _canonical (sin 'signature')
    return {**ev, "signature": sig}


def _bad_sig_event(event_type: str = "process") -> dict:
    return {"event_type": event_type, "severity": "info", "ts": time.time(), "signature": "AAAA"}


@pytest.fixture(autouse=True)
def _restore_strict():
    orig = AC.settings.SPECTER_STRICT_SIGNATURE_MODE
    yield
    AC.settings.SPECTER_STRICT_SIGNATURE_MODE = orig


class TestSignatureEnforcement:
    @pytest.mark.asyncio
    async def test_valid_signature_accepted(self, db):
        priv, pub = _keypair()
        agent = await _mk_agent(db, pub, tenant_id=str(uuid.uuid4()))
        acc, rej = await AC.ingest_events(db, agent, [_signed_event(priv)])
        assert (acc, rej) == (1, 0)
        ev = (await db.execute(select(AgentEvent).where(AgentEvent.agent_id == agent.id))).scalar_one()
        assert ev.signature_valid is True

    @pytest.mark.asyncio
    async def test_invalid_signature_stored_in_permissive_mode(self, db):
        AC.settings.SPECTER_STRICT_SIGNATURE_MODE = False
        priv, pub = _keypair()
        agent = await _mk_agent(db, pub, tenant_id=str(uuid.uuid4()))
        acc, rej = await AC.ingest_events(db, agent, [_bad_sig_event()])
        assert (acc, rej) == (1, 0)          # permisivo: se almacena
        ev = (await db.execute(select(AgentEvent).where(AgentEvent.agent_id == agent.id))).scalar_one()
        assert ev.signature_valid is False

    @pytest.mark.asyncio
    async def test_invalid_signature_REJECTED_in_strict_mode(self, db):
        AC.settings.SPECTER_STRICT_SIGNATURE_MODE = True
        priv, pub = _keypair()
        agent = await _mk_agent(db, pub, tenant_id=str(uuid.uuid4()))
        acc, rej = await AC.ingest_events(db, agent, [_bad_sig_event()])
        assert (acc, rej) == (0, 1)          # estricto: rechazado, NO almacenado
        stored = (await db.execute(select(AgentEvent).where(AgentEvent.agent_id == agent.id))).scalars().all()
        assert stored == []

    @pytest.mark.asyncio
    async def test_strict_mode_still_accepts_valid_signatures(self, db):
        AC.settings.SPECTER_STRICT_SIGNATURE_MODE = True
        priv, pub = _keypair()
        agent = await _mk_agent(db, pub, tenant_id=str(uuid.uuid4()))
        acc, rej = await AC.ingest_events(db, agent, [_signed_event(priv)])
        assert (acc, rej) == (1, 0)
