"""
Capa 3 del monitoreo de plataforma — red SPECTER como monitor distribuido (S108.2).

Cada agente SPECTER es un punto de observación desde una red independiente. Cuando un
agente pierde y luego recupera contacto con ASC, reporta el hueco vía la telemetría
FIRMADA existente (event_type='specter.connectivity_gap') — sin infra ni migración nueva.

El backend agrega esos reportes en una ventana reciente:
  - 0 agentes  → 'none'      (sin señal)
  - 1 agente   → 'localized' (probable problema de red del cliente)
  - ≥2 agentes → 'global'    (múltiples vantage points → probable caída global de ASC)

Es RETROSPECTIVO (confirma y da radio de impacto tras el hecho); la alerta EN VIVO la da
el watchdog externo (Capa 2). Aquí se responde: "¿fue ASC o fue la red de un cliente?".
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.models.agent import Agent, AgentEvent

CONNECTIVITY_GAP_EVENT = "specter.connectivity_gap"


async def assess_distributed_reachability(
    db: AsyncSession, window_minutes: int = 15
) -> dict:
    """Agrega reportes de gap de conectividad de agentes en la ventana reciente."""
    since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)

    # Agentes distintos que reportaron gap + total de reportes.
    rows = (await db.execute(
        select(AgentEvent.agent_id, func.count())
        .where(
            AgentEvent.event_type == CONNECTIVITY_GAP_EVENT,
            AgentEvent.received_at >= since,
        )
        .group_by(AgentEvent.agent_id)
    )).all()

    agent_ids = [r[0] for r in rows]
    total_reports = int(sum(r[1] for r in rows))
    n_agents = len(agent_ids)

    # Tenants distintos = redes distintas (señal más fuerte de caída global).
    n_tenants = 0
    if agent_ids:
        n_tenants = (await db.execute(
            select(func.count(func.distinct(Agent.tenant_id)))
            .where(Agent.id.in_(agent_ids))
        )).scalar_one() or 0

    if n_agents == 0:
        classification = "none"
        note = "Sin reportes de pérdida de conectividad."
    elif n_agents == 1:
        classification = "localized"
        note = "1 agente reportó pérdida — probable problema de red de ese cliente."
    else:
        classification = "global"
        note = f"{n_agents} agentes ({n_tenants} redes) reportaron pérdida — probable caída global de ASC."

    return {
        "window_minutes": window_minutes,
        "agents_reporting_gaps": n_agents,
        "distinct_networks": int(n_tenants),
        "total_gap_reports": total_reports,
        "classification": classification,   # none | localized | global
        "note": note,
    }
