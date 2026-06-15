"""
P23-F1 — Hunt Query Executor
P24-F1 — Specter Agent Live Dispatch

Dispatches a saved HuntQuery against the configured data-source adapter.
All execution is READ-ONLY (GET/POST _search, no index mutations).
Specter queries are dispatched asynchronously via agent_commander.issue_command.
Timeout: 30 seconds max per execution (ELK/Wazuh adapters).
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.models.hunt import HuntQuery

log = get_logger("asc.query_executor")

EXECUTE_TIMEOUT_S = 30
MAX_RESULTS = 200   # cap returned to API caller; full count still tracked


async def execute_hunt_query(
    db: AsyncSession,
    query_id: str,
    *,
    executed_by: str,
) -> dict:
    """
    Load a HuntQuery by ID, dispatch to the appropriate adapter, update metadata.

    Returns:
        {
            "query_id": str,
            "hunt_id": str,
            "data_source": str,
            "result_count": int,
            "total": int,
            "truncated": bool,
            "execution_ms": int,
            "results": list[dict],      # capped at MAX_RESULTS
            "success": bool,
            "error": str | None,
            # Specter-specific (async dispatch):
            "specter_command_id": str | None,
            "specter_agent_id": str | None,
            "mode": str | None,         # "specter_async" when dispatched to agent
            "note": str | None,
        }
    """
    result = await db.execute(select(HuntQuery).where(HuntQuery.id == query_id))
    query = result.scalar_one_or_none()
    if query is None:
        return {"success": False, "error": "Query not found", "query_id": query_id}

    adapter_result = await _dispatch(
        db,
        query.data_source,
        query.query_text,
        query_id=query_id,
        hunt_id=query.hunt_id,
        executed_by=executed_by,
    )

    # Update query execution metadata regardless of success
    now = datetime.now(timezone.utc)
    query.last_executed_at = now
    query.last_execution_ms = adapter_result.get("execution_ms")
    query.last_result_count = (
        adapter_result.get("result_count", 0) if adapter_result.get("success") else 0
    )
    await db.commit()

    log.info(
        "query_executed",
        query_id=query_id,
        hunt_id=query.hunt_id,
        data_source=query.data_source,
        success=adapter_result.get("success"),
        result_count=query.last_result_count,
        executed_by=executed_by,
        mode=adapter_result.get("mode", "direct"),
    )

    results = adapter_result.get("results", [])[:MAX_RESULTS]

    return {
        "query_id": query_id,
        "hunt_id": query.hunt_id,
        "data_source": query.data_source,
        "result_count": adapter_result.get("result_count", 0),
        "total": adapter_result.get("total", 0),
        "truncated": (
            adapter_result.get("truncated", False)
            or len(adapter_result.get("results", [])) > MAX_RESULTS
        ),
        "execution_ms": adapter_result.get("execution_ms", 0),
        "results": results,
        "success": adapter_result.get("success", False),
        "error": adapter_result.get("error") if not adapter_result.get("success") else None,
        "executed_at": now.isoformat(),
        # Specter async fields (None for ELK/Wazuh)
        "specter_command_id": adapter_result.get("specter_command_id"),
        "specter_agent_id": adapter_result.get("specter_agent_id"),
        "mode": adapter_result.get("mode"),
        "note": adapter_result.get("note"),
    }


async def _dispatch(
    db: AsyncSession,
    data_source: str,
    query_text: str,
    *,
    query_id: str,
    hunt_id: str,
    executed_by: str,
) -> dict:
    """Route query to the appropriate adapter with a hard timeout (non-Specter only)."""
    if data_source == "specter_agent":
        # Specter queries are fire-and-forget (agent pulls commands asynchronously).
        # No timeout wrapping here — the DB write is fast; result arrives via agent callback.
        return await _dispatch_to_specter(db, query_text, query_id=query_id, hunt_id=hunt_id, executed_by=executed_by)

    try:
        return await asyncio.wait_for(
            _call_adapter(data_source, query_text),
            timeout=EXECUTE_TIMEOUT_S,
        )
    except asyncio.TimeoutError:
        return {
            "success": False,
            "error": f"Query execution timed out after {EXECUTE_TIMEOUT_S}s",
            "result_count": 0,
            "total": 0,
            "truncated": False,
            "execution_ms": EXECUTE_TIMEOUT_S * 1000,
            "results": [],
        }
    except Exception as exc:
        log.warning("query_dispatch_error", data_source=data_source, error=str(exc))
        return {
            "success": False,
            "error": str(exc),
            "result_count": 0,
            "total": 0,
            "truncated": False,
            "execution_ms": 0,
            "results": [],
        }


async def _call_adapter(data_source: str, query_text: str) -> dict:
    """Dispatch to ELK, Wazuh, or manual adapter (all synchronous results)."""
    if data_source == "elk":
        from app.adapters.elk import ELKAdapter
        return await ELKAdapter().search_raw(query_text, limit=MAX_RESULTS)

    if data_source == "wazuh":
        from app.adapters.wazuh import WazuhAdapter
        return await WazuhAdapter().search_raw(query_text, limit=MAX_RESULTS)

    if data_source == "manual":
        return {
            "success": True,
            "result_count": 0,
            "total": 0,
            "truncated": False,
            "execution_ms": 0,
            "results": [],
            "note": "Manual queries require analyst execution outside the platform. Query saved for reference.",
        }

    return {
        "success": False,
        "error": f"Unknown data_source '{data_source}'",
        "result_count": 0,
        "total": 0,
        "truncated": False,
        "execution_ms": 0,
        "results": [],
    }


def _agent_priority_score(agent: "Agent") -> float:  # type: ignore[name-defined]
    """
    Fleet-aware agent scoring (lower = preferred).

    Criteria (descending importance):
      1. Threat level: prefer normal > elevated > critical (high threat = already busy)
      2. Recency: prefer most recently seen agent (proxy for low latency)

    Returns a float where smaller values = better candidate.
    """
    from datetime import datetime, timezone
    _THREAT_WEIGHT = {"normal": 0, "elevated": 10, "critical": 20}
    threat_penalty = _THREAT_WEIGHT.get(getattr(agent, "threat_level", "normal"), 5)
    last_seen = getattr(agent, "last_seen", None)
    if last_seen:
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)
        recency_penalty = (datetime.now(timezone.utc) - last_seen).total_seconds()
    else:
        recency_penalty = 999_999
    return threat_penalty + recency_penalty * 0.001


async def _dispatch_to_specter(
    db: AsyncSession,
    query_text: str,
    *,
    query_id: str,
    hunt_id: str,
    executed_by: str,
    broadcast: bool = False,
) -> dict:
    """
    Dispatch a log_query command to Specter agent(s).

    Fleet-aware single-agent mode (default):
      Selects the best-scoring active agent using _agent_priority_score():
      prefers low-threat, recently-seen agents. Falls back gracefully if
      all agents are at elevated/critical threat.

    Broadcast mode (broadcast=True):
      Issues the same log_query command to ALL active agents simultaneously.
      Useful for fleet-wide threat searches where local log coverage matters.
      Returns list of (agent_id, command_id) pairs.

    Execution is entirely READ-ONLY on the agent side (read_only=True in params).
    Returns immediately — results arrive when agents respond via record_command_result.
    """
    from sqlalchemy import select as _select
    from app.models.agent import Agent
    from app.services.agent_commander import issue_command

    q = await db.execute(
        _select(Agent).where(Agent.status == "active")
    )
    active_agents = list(q.scalars().all())

    if not active_agents:
        log.warning("specter_query_no_active_agent", query_id=query_id, hunt_id=hunt_id)
        return {
            "success": False,
            "error": "No active Specter agents available. Ensure at least one agent is online.",
            "result_count": 0,
            "total": 0,
            "truncated": False,
            "execution_ms": 0,
            "results": [],
        }

    params = {
        "query": query_text,
        "hunt_id": hunt_id,
        "query_id": query_id,
        "max_results": MAX_RESULTS,
        "read_only": True,
    }

    if broadcast:
        # Dispatch to ALL active agents
        commands = []
        for agent in active_agents:
            try:
                cmd = await issue_command(db, agent, "log_query", params, issued_by=executed_by)
                agent_label = getattr(agent, "hostname", None) or str(agent.id)[:8]
                commands.append({
                    "agent_id": str(agent.id),
                    "agent_label": agent_label,
                    "command_id": cmd.id,
                })
                log.info(
                    "specter_broadcast_dispatched",
                    command_id=cmd.id,
                    agent_id=str(agent.id),
                    agent_label=agent_label,
                    query_id=query_id,
                    hunt_id=hunt_id,
                )
            except Exception as exc:
                log.warning("specter_broadcast_agent_error", agent_id=str(agent.id), error=str(exc))

        return {
            "success": True,
            "result_count": 0,
            "total": 0,
            "truncated": False,
            "execution_ms": 0,
            "results": [],
            "mode": "specter_broadcast",
            "broadcast_commands": commands,
            "agents_dispatched": len(commands),
            "note": (
                f"Query broadcast to {len(commands)}/{len(active_agents)} active Specter agents. "
                "Results recorded individually as each agent responds."
            ),
        }

    # Single-agent mode: pick best-scoring agent
    best_agent = min(active_agents, key=_agent_priority_score)
    cmd = await issue_command(db, best_agent, "log_query", params, issued_by=executed_by)
    agent_label = getattr(best_agent, "hostname", None) or str(best_agent.id)[:8]

    log.info(
        "specter_query_dispatched",
        command_id=cmd.id,
        agent_id=str(best_agent.id),
        agent_label=agent_label,
        query_id=query_id,
        hunt_id=hunt_id,
        issued_by=executed_by,
        fleet_size=len(active_agents),
    )

    return {
        "success": True,
        "result_count": 0,
        "total": 0,
        "truncated": False,
        "execution_ms": 0,
        "results": [],
        "specter_command_id": cmd.id,
        "specter_agent_id": str(best_agent.id),
        "mode": "specter_async",
        "note": (
            f"Query dispatched to Specter agent '{agent_label}' "
            f"(command {cmd.id[:8]}). "
            "Results will be recorded when the agent responds. "
            "Check /api/v1/agents/commands/{command_id} for status."
        ),
    }
