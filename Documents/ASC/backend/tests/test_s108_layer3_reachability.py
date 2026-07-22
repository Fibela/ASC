"""
S108.2 — Capa 3: red SPECTER como monitor distribuido.

Prueba la agregación de reportes de gap de conectividad (global vs localizado) y que
los eventos meta 'specter.*' se EXCLUYEN del bridge de alertas (no ensucian).
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from asc_api.models.agent import Agent, AgentEvent
from asc_api.services import agent_commander as AC
from asc_api.services.reachability import (
    CONNECTIVITY_GAP_EVENT,
    assess_distributed_reachability,
)


async def _mk_agent(db, aid, tenant):
    ag = Agent(id=aid, hostname=aid, os_type="linux", os_version="1", arch="x86_64",
               ip_address="10.0.0.1", public_key="k", tenant_id=tenant)
    db.add(ag)
    await db.commit()
    await db.refresh(ag)
    return ag


async def _gap(db, aid):
    now = datetime.now(timezone.utc)
    db.add(AgentEvent(agent_id=aid, event_type=CONNECTIVITY_GAP_EVENT,
                      data={"ticks": 3}, signature="s", ts=now, received_at=now))
    await db.commit()


class TestDistributedReachability:
    @pytest.mark.asyncio
    async def test_none_sin_reportes(self, db):
        r = await assess_distributed_reachability(db)
        assert r["classification"] == "none" and r["agents_reporting_gaps"] == 0

    @pytest.mark.asyncio
    async def test_localized_un_agente(self, db):
        await _mk_agent(db, "a1", "t-1")
        await _gap(db, "a1"); await _gap(db, "a1")   # 2 reportes, 1 agente
        r = await assess_distributed_reachability(db)
        assert r["classification"] == "localized"
        assert r["agents_reporting_gaps"] == 1 and r["total_gap_reports"] == 2

    @pytest.mark.asyncio
    async def test_global_varias_redes(self, db):
        await _mk_agent(db, "a1", "t-1"); await _mk_agent(db, "a2", "t-2")
        await _gap(db, "a1"); await _gap(db, "a2")
        r = await assess_distributed_reachability(db)
        assert r["classification"] == "global"
        assert r["agents_reporting_gaps"] == 2 and r["distinct_networks"] == 2


class TestBridgeExcludesMeta:
    @pytest.mark.asyncio
    async def test_connectivity_gap_no_genera_alerta(self, db):
        ag = await _mk_agent(db, "a9", "t-9")
        accepted = [{
            "raw": {"event_type": CONNECTIVITY_GAP_EVENT},
            "event_id": "e1", "event_type": CONNECTIVITY_GAP_EVENT,
            "severity": "info", "is_anomaly": True,   # novel → sin exclusión crearía alerta
        }]
        ids = await AC.detect_from_agent_events(db, ag, accepted)
        assert ids == []   # excluido del bridge de alertas de seguridad
