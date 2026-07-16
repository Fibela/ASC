"""
SPECTER Bridge — P16 + PANL + P16.3 IAM + F1 Real Integrations

Dispatches neutralization actions to registered SPECTER agents via signed
AgentCommands.  Falls back to neutralizer.py simulation when no matching
agent is found or when the action has no SPECTER equivalent.

PANL enhancements (P16 pre-P16.3)
----------------------------------
fleet_aware_dispatch  — Broadcast orders agents by subnet proximity to target
                        so the closest agents (lowest latency) are issued first.
broadcast_batching    — Agents processed in chunks of BROADCAST_BATCH_SIZE (10)
                        to avoid overwhelming the DB with simultaneous writes and
                        prevent event-loop starvation on large fleets.
rollback_commands     — New action types routed for PANL dynamic rollback:
                          unisolate_endpoint  → "unisolate"   (AGENT_TARGETED)
                          unblock_ip          → "unblock_ip"  (BROADCAST)
                          unblock_domain      → "unblock_domain" (BROADCAST)
                          restore_file        → "restore_file" (AGENT_TARGETED)

P16.3 IAM wiring
----------------
disable_account — previously SIMULATION_ONLY, now calls iam_service.disable_account()
                  which sets User.is_active=False in the database.  Existing tokens
                  for the disabled user become invalid on the next request because
                  get_current_user filters on is_active==True.

F1 Real Integrations (FASE 1)
------------------------------
block_ip / unblock_ip / block_domain / unblock_domain
  — Now call the configured firewall adapter (Palo Alto or Fortinet) in addition
    to the SPECTER agent broadcast.  Defense-in-depth: block at both the network
    perimeter (firewall) and on each endpoint (agent).
  — If no firewall adapter is configured, falls back to SPECTER broadcast only.

disable_account
  — In addition to iam_service (ASC DB), now also calls the Active Directory
    adapter (if configured) to disable the account in the corporate directory.
  — Both operations are attempted independently; either partial success is logged.

Dispatch modes
--------------
specter    — targeted: one command issued to a specific agent.
broadcast  — one command issued to every active agent (batched, proximity-sorted).
firewall   — network-level block via Palo Alto or Fortinet adapter.
iam        — identity/access management (ASC DB + optional Active Directory).
simulation — no SPECTER agent / adapter available; neutralizer.py fallback.

Security invariants
-------------------
- Commands are Ed25519-signed by issue_command() via agent_commander.
- The bridge never touches agent credentials or private keys.
- kill_process without PID falls back to broadcast by process name (P16.2).
- Firewall adapter and AD adapter failures are non-fatal to the SPECTER broadcast
  so that partial infrastructure outages do not block all neutralization actions.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.core.audit import log_security_action
from asc_api.core.logging import get_logger
from asc_api.core.panl import subnet_proximity
from asc_api.models.agent import Agent, AgentCommand
from asc_api.services.agent_commander import issue_command
from asc_api.services.iam_service import disable_account as iam_disable_account
from asc_api.services.neutralizer import NeutralizationResult, execute_action

log = get_logger(__name__)


# ── Adapter factories (lazy — returns None if adapter not configured) ──────────

def _get_firewall_adapter():
    """Return the active firewall adapter or None if none is configured."""
    try:
        from asc_api.adapters.firewall.paloalto import PaloAltoAdapter
        from asc_api.adapters.firewall.fortinet import FortinetAdapter
        pa = PaloAltoAdapter()
        if pa.is_configured():
            return pa
        ft = FortinetAdapter()
        if ft.is_configured():
            return ft
    except Exception as exc:
        log.warning("firewall_adapter_init_error", error=str(exc))
    return None


def _get_identity_adapter():
    """Return the Active Directory adapter or None if not configured."""
    try:
        from asc_api.adapters.identity.active_directory import ActiveDirectoryAdapter
        ad = ActiveDirectoryAdapter()
        if ad.is_configured():
            return ad
    except Exception as exc:
        log.warning("identity_adapter_init_error", error=str(exc))
    return None

# ── Configuration ─────────────────────────────────────────────────────────────

BROADCAST_BATCH_SIZE: int = 10  # agents processed per batch in broadcast mode


# ── Dispatch mode ─────────────────────────────────────────────────────────────

class DispatchMode(str, Enum):
    SPECTER    = "specter"     # targeted: one specific agent
    BROADCAST  = "broadcast"   # all active agents (batched + proximity-sorted)
    IAM        = "iam"         # identity/access management via iam_service
    SIMULATION = "simulation"  # no agent found — neutralizer.py fallback


# ── Routing tables ─────────────────────────────────────────────────────────────

# Actions that target a specific host (resolved by hostname or IP)
_AGENT_TARGETED: frozenset[str] = frozenset({
    "isolate_endpoint",
    "kill_process",
    "quarantine_file",
    "remove_persistence",
    # PANL rollback reversals
    "unisolate_endpoint",
    "restore_file",
})

# Actions broadcast to all active agents
_BROADCAST_ACTIONS: frozenset[str] = frozenset({
    "block_ip",
    "block_domain",
    # PANL rollback reversals
    "unblock_ip",
    "unblock_domain",
})

# Actions handled at IAM level — P16.3: wired to iam_service.disable_account()
_IAM_ACTIONS: frozenset[str] = frozenset({
    "disable_account",
})


# ── Param mapping: neutralizer params → SPECTER command params ─────────────────

def map_specter_command(action_type: str, params: dict[str, Any]) -> tuple[str, dict] | None:
    """
    Return (command_type, specter_params) for the given neutralizer action,
    or None if the action has no SPECTER mapping (simulation-only).

    The bridge bypasses COMMAND_PARAM_SCHEMAS validation — it is trusted
    internal code.  The public API endpoint (/agents/{id}/command) enforces
    the schema for external callers.
    """
    # ── Original action types (P16.1/P16.2) ──────────────────────────────────
    if action_type == "isolate_endpoint":
        return "isolate", {}

    if action_type == "block_ip":
        ip = params.get("ip") or params.get("target")
        if not ip:
            return None
        return "block_ip", {"ip": str(ip)}

    if action_type == "block_domain":
        domain = params.get("domain") or params.get("target")
        if not domain:
            return None
        return "block_domain", {"domain": str(domain)}

    if action_type == "kill_process":
        pid = params.get("pid")
        process_name = params.get("process_name")
        if pid is not None:
            specter_params: dict[str, Any] = {"pid": int(pid)}
            if process_name:
                specter_params["process_name"] = str(process_name)
            return "kill_process", specter_params
        if process_name:
            return "kill_process_name", {"process_name": str(process_name)}
        return None

    if action_type == "quarantine_file":
        path = params.get("file_path") or params.get("path")
        if not path:
            return None
        return "quarantine_file", {"path": str(path)}

    if action_type == "remove_persistence":
        persistence_type = params.get("persistence_type", "")
        target = params.get("target", "")
        return "remove_persistence", {
            "persistence_type": str(persistence_type),
            "target":           str(target),
        }

    # ── PANL rollback action types (P16 pre-P16.3) ───────────────────────────
    if action_type == "unisolate_endpoint":
        return "unisolate", {}

    if action_type == "unblock_ip":
        ip = params.get("ip") or params.get("target")
        if not ip:
            return None
        return "unblock_ip", {"ip": str(ip)}

    if action_type == "unblock_domain":
        domain = params.get("domain") or params.get("target")
        if not domain:
            return None
        return "unblock_domain", {"domain": str(domain)}

    if action_type == "restore_file":
        path = params.get("file_path") or params.get("path")
        if not path:
            return None
        return "restore_file", {"path": str(path)}

    return None  # disable_account and unknown types → simulation


# ── Agent resolution ──────────────────────────────────────────────────────────

async def resolve_agent(
    db: AsyncSession,
    *,
    hostname: str | None = None,
    ip_address: str | None = None,
) -> Agent | None:
    """Find an active SPECTER agent by hostname or IP. Returns None if not found."""
    if hostname:
        result = await db.execute(
            select(Agent).where(
                Agent.hostname == hostname,
                Agent.status.in_(["active", "elevated", "critical"]),
            )
        )
        agent = result.scalar_one_or_none()
        if agent:
            return agent

    if ip_address:
        result = await db.execute(
            select(Agent).where(
                Agent.ip_address == ip_address,
                Agent.status.in_(["active", "elevated", "critical"]),
            )
        )
        return result.scalar_one_or_none()

    return None


async def get_all_active_agents(db: AsyncSession) -> list[Agent]:
    """Return all agents that can receive commands (active, elevated, critical)."""
    result = await db.execute(
        select(Agent).where(
            Agent.status.in_(["active", "elevated", "critical"])
        )
    )
    return list(result.scalars().all())


# ── Fleet-aware broadcast ─────────────────────────────────────────────────────

def _sort_agents_by_proximity(agents: list[Agent], target_ip: str | None) -> list[Agent]:
    """
    Sort agents by subnet proximity to the target IP (closest first).
    Agents without an IP address sort last.
    This is purely advisory — all agents receive the command, but closer
    ones act sooner due to queue ordering and poll timing.
    """
    return sorted(
        agents,
        key=lambda a: subnet_proximity(getattr(a, "ip_address", None), target_ip),
    )


async def _issue_command_safe(
    db: AsyncSession,
    agent: Agent,
    command_type: str,
    specter_params: dict[str, Any],
    issued_by: str,
) -> tuple[str, str] | None:
    """Issue a single command, returning (cmd_id, hostname) or None on error."""
    try:
        cmd = await issue_command(db, agent, command_type, specter_params, issued_by)
        return cmd.id, agent.hostname
    except Exception as exc:
        log.error(
            "specter_bridge_broadcast_error",
            agent_id=agent.id,
            hostname=agent.hostname,
            error=str(exc),
        )
        return None


async def _broadcast_batched(
    db: AsyncSession,
    agents: list[Agent],
    command_type: str,
    specter_params: dict[str, Any],
    issued_by: str,
    target_ip: str | None,
) -> tuple[list[str], list[str]]:
    """
    Issue command to agents in parallel batches of BROADCAST_BATCH_SIZE.

    Fleet-aware: agents are sorted by subnet proximity to target_ip first.
    Within each batch, commands are dispatched concurrently via asyncio.gather()
    so a slow agent does not block others in the same batch.
    Errors on individual agents are logged and skipped (partial success).

    Returns (cmd_ids, hostnames) for successfully issued commands.
    """
    sorted_agents = _sort_agents_by_proximity(agents, target_ip)
    cmd_ids: list[str] = []
    hostnames: list[str] = []

    for batch_start in range(0, len(sorted_agents), BROADCAST_BATCH_SIZE):
        batch = sorted_agents[batch_start: batch_start + BROADCAST_BATCH_SIZE]

        results = await asyncio.gather(
            *[
                _issue_command_safe(db, agent, command_type, specter_params, issued_by)
                for agent in batch
            ]
        )

        for result in results:
            if result is not None:
                cmd_id, hostname = result
                cmd_ids.append(cmd_id)
                hostnames.append(hostname)

        # Yield control between batches to avoid starving other coroutines
        if batch_start + BROADCAST_BATCH_SIZE < len(sorted_agents):
            await asyncio.sleep(0)

    return cmd_ids, hostnames


# ── Core dispatch ─────────────────────────────────────────────────────────────

class SprecterBridgeResult:
    """Extended NeutralizationResult that includes SPECTER dispatch metadata."""

    def __init__(
        self,
        *,
        success: bool,
        message: str,
        details: dict[str, Any] | None = None,
        dispatch_mode: DispatchMode = DispatchMode.SIMULATION,
        commands_issued: list[str] | None = None,
        agents_targeted: list[str] | None = None,
        simulated: bool | None = None,
    ) -> None:
        self.success = success
        self.message = message
        self.dispatch_mode = dispatch_mode
        # Honestidad (S103): simulated=True cuando nada real ocurrió. Si no se
        # indica, se deriva del modo de despacho (SIMULATION => simulado).
        self.simulated = (
            simulated if simulated is not None
            else (dispatch_mode == DispatchMode.SIMULATION)
        )
        self.status = "executed" if success else ("simulated" if self.simulated else "failed")
        self.commands_issued: list[str] = commands_issued or []
        self.agents_targeted: list[str] = agents_targeted or []
        self.details: dict[str, Any] = {
            **(details or {}),
            "dispatch_mode":   dispatch_mode,
            "simulated":       self.simulated,
            "status":          self.status,
            "commands_issued": self.commands_issued,
            "agents_targeted": self.agents_targeted,
        }


async def _execute_iam_action(
    *,
    action_type: str,
    params: dict[str, Any],
    db: AsyncSession,
    issued_by: str,
) -> "SprecterBridgeResult":
    """
    Route IAM-level actions.  F1: disable_account now calls BOTH:
      1. iam_service — disables in ASC database (prevents ASC portal login).
      2. ActiveDirectoryAdapter — disables in corporate AD (prevents network login).
    Either operation may succeed or fail independently; both are logged.
    """
    if action_type == "disable_account":
        target_email = (
            params.get("email")
            or params.get("target")
            or params.get("username")
        )
        if not target_email:
            log.warning("specter_bridge_iam_missing_email", action=action_type)
            return SprecterBridgeResult(
                success=False,
                message="disable_account requiere el parámetro 'email'",
                details={"simulation_reason": "missing_email_param"},
                dispatch_mode=DispatchMode.IAM,
            )

        # 1. ASC database — always attempted
        asc_success, asc_message = await iam_disable_account(
            target_email, db, performed_by=issued_by
        )
        log_security_action(
            "neutralize_execute",
            user_id=issued_by,
            role="system",
            resource="iam",
            resource_id=target_email,
            detail=asc_message,
            status="ok" if asc_success else "error",
        )

        # 2. Active Directory — attempted if adapter is configured (non-fatal)
        ad_result: dict | None = None
        ad_adapter = _get_identity_adapter()
        if ad_adapter is not None:
            domain = params.get("domain", "")
            username = target_email.split("@")[0]
            reason = params.get("reason", f"Disabled by ASC neutralization — initiated_by={issued_by}")
            ad_result = await ad_adapter.disable_account(username, domain, reason)
            log.info(
                "specter_bridge_ad_disable",
                username=username,
                domain=domain,
                success=ad_result.get("success"),
                error=ad_result.get("error"),
            )
            log_security_action(
                "ad_disable_account",
                user_id=issued_by,
                role="system",
                resource="active_directory",
                resource_id=target_email,
                detail=str(ad_result),
                status="ok" if ad_result.get("success") else "error",
            )

        overall_success = asc_success
        details: dict[str, Any] = {
            "asc_db": {"success": asc_success, "message": asc_message},
        }
        if ad_result is not None:
            details["active_directory"] = ad_result
        else:
            details["active_directory"] = {"success": None, "message": "adapter_not_configured"}

        return SprecterBridgeResult(
            success=overall_success,
            message=asc_message + (
                f" | AD: {'ok' if (ad_result or {}).get('success') else 'not_configured_or_failed'}"
            ),
            details=details,
            dispatch_mode=DispatchMode.IAM,
        )

    # Fallback: unknown IAM action — should not happen given _IAM_ACTIONS routing
    log.error("specter_bridge_unknown_iam_action", action=action_type)
    return SprecterBridgeResult(
        success=False,
        message=f"Acción IAM desconocida: {action_type}",
        dispatch_mode=DispatchMode.IAM,
    )


async def dispatch(
    db: AsyncSession,
    *,
    action_type: str,
    target: str,
    target_type: str,
    params: dict[str, Any],
    issued_by: str,
) -> SprecterBridgeResult:
    """
    Primary bridge entry point — called by approval._execute_immediately().

    Routing:
      1. IAM_ACTIONS     → iam_service operations (P16.3: disable_account wired).
      2. AGENT_TARGETED  → resolve agent, issue command, or fallback.
      3. BROADCAST       → issue to all active agents (batched, proximity-sorted).
    """
    now = datetime.now(timezone.utc).isoformat()

    # ── 1. IAM actions — database-level identity management ───────────────────
    if action_type in _IAM_ACTIONS:
        return await _execute_iam_action(
            action_type=action_type,
            params=params,
            db=db,
            issued_by=issued_by,
        )

    # Map to SPECTER command
    mapping = map_specter_command(action_type, params)
    if mapping is None:
        log.warning("specter_bridge_no_mapping", action=action_type, params=list(params.keys()))
        sim = await execute_action(action_type, params)
        return SprecterBridgeResult(
            success=sim.success,
            message=sim.message + " [simulation — incomplete params for SPECTER dispatch]",
            details={**sim.details, "simulation_reason": "Missing required params for SPECTER"},
            dispatch_mode=DispatchMode.SIMULATION,
        )

    command_type, specter_params = mapping

    # kill_process_name (no PID) broadcasts to all agents — analyst decision P16.2.
    effective_broadcast = action_type in _BROADCAST_ACTIONS or command_type == "kill_process_name"
    effective_targeted  = action_type in _AGENT_TARGETED and not effective_broadcast

    # ── 2. Agent-targeted dispatch ────────────────────────────────────────────
    if effective_targeted:
        hostname = (
            params.get("host")
            or params.get("hostname")
            or (target if target_type in ("host", "hostname", "endpoint") else None)
        )
        ip_addr = target if target_type == "ip" else None

        agent = await resolve_agent(db, hostname=hostname, ip_address=ip_addr)

        if agent is None:
            log.warning(
                "specter_bridge_agent_not_found",
                action=action_type, hostname=hostname, ip=ip_addr,
            )
            sim = await execute_action(action_type, params)
            return SprecterBridgeResult(
                success=sim.success,
                message=(
                    sim.message
                    + f" [simulation — no active SPECTER agent found for '{hostname or ip_addr}']"
                ),
                details={
                    **sim.details,
                    "simulation_reason": (
                        f"No active agent registered for {hostname or ip_addr!r}"
                    ),
                    "resolution_hint": (
                        "Register a SPECTER agent on the target host to enable real dispatch"
                    ),
                },
                dispatch_mode=DispatchMode.SIMULATION,
            )

        cmd = await issue_command(db, agent, command_type, specter_params, issued_by)
        log.info(
            "specter_bridge_command_issued",
            action=action_type, command_type=command_type,
            agent_id=agent.id, hostname=agent.hostname, cmd_id=cmd.id,
        )
        log_security_action(
            "specter_bridge_dispatch",
            user_id=issued_by,
            resource="agent_command",
            resource_id=cmd.id,
            detail=(
                f"action={action_type} specter_cmd={command_type} "
                f"agent={agent.hostname} target={target}"
            ),
            status="queued",
        )
        return SprecterBridgeResult(
            success=True,
            message=(
                f"SPECTER command '{command_type}' queued for agent "
                f"'{agent.hostname}' (cmd_id={cmd.id})"
            ),
            details={
                "host":          agent.hostname,
                "agent_id":      agent.id,
                "command_id":    cmd.id,
                "command_type":  command_type,
                "specter_params": specter_params,
                "queued_at":     now,
                "note": (
                    "Command is pending until agent polls. "
                    f"Poll interval: {agent.poll_interval}s."
                ),
            },
            dispatch_mode=DispatchMode.SPECTER,
            commands_issued=[cmd.id],
            agents_targeted=[agent.hostname],
        )

    # ── 3. Broadcast dispatch (batched + fleet-aware) + Firewall adapter ─────
    if effective_broadcast:
        # F1: attempt firewall adapter first (non-fatal — failure doesn't block agents)
        fw_result: dict | None = None
        fw_adapter = _get_firewall_adapter()
        if fw_adapter is not None:
            reason = params.get("reason", f"ASC neutralization — initiated_by={issued_by}")
            try:
                if action_type in ("block_ip", "unblock_ip"):
                    ip_val = (
                        params.get("ip")
                        or params.get("target")
                        or (target if target_type == "ip" else None)
                        or ""
                    )
                    direction = params.get("direction", "both")
                    if action_type == "block_ip":
                        fw_result = await fw_adapter.block_ip(ip_val, direction, reason)
                    else:
                        fw_result = await fw_adapter.unblock_ip(ip_val)

                elif action_type in ("block_domain", "unblock_domain"):
                    domain_val = (
                        params.get("domain")
                        or params.get("target")
                        or target
                        or ""
                    )
                    if action_type == "block_domain":
                        fw_result = await fw_adapter.block_domain(domain_val, reason)
                    else:
                        fw_result = await fw_adapter.unblock_domain(domain_val)

            except Exception as exc:
                log.error("specter_bridge_firewall_error", action=action_type, error=str(exc))
                fw_result = {"success": False, "error": str(exc)}

            if fw_result:
                log.info(
                    "specter_bridge_firewall_dispatch",
                    action=action_type,
                    adapter=fw_adapter.ADAPTER_NAME,
                    success=fw_result.get("success"),
                )
                log_security_action(
                    "firewall_adapter_dispatch",
                    user_id=issued_by,
                    resource="firewall",
                    resource_id=action_type,
                    detail=f"adapter={fw_adapter.ADAPTER_NAME} action={action_type} target={target} success={fw_result.get('success')}",
                    status="ok" if fw_result.get("success") else "error",
                )

        # SPECTER broadcast to all active agents (defense-in-depth)
        agents = await get_all_active_agents(db)
        cmd_ids: list[str] = []
        hostnames: list[str] = []

        if agents:
            target_ip = target if target_type == "ip" else None
            cmd_ids, hostnames = await _broadcast_batched(
                db, agents, command_type, specter_params, issued_by, target_ip
            )
            log_security_action(
                "specter_bridge_broadcast",
                user_id=issued_by,
                resource="agent_command_broadcast",
                resource_id=action_type,
                detail=(
                    f"action={action_type} specter_cmd={command_type} "
                    f"agents={len(cmd_ids)}/{len(agents)} target={target} "
                    f"batches={((len(agents) - 1) // BROADCAST_BATCH_SIZE) + 1}"
                ),
                status="queued",
            )
        else:
            log.warning("specter_bridge_no_agents_for_broadcast", action=action_type)

        # Determine overall success: firewall OR agents — either layer counts
        fw_ok = fw_result.get("success") if fw_result else None
        agent_ok = len(cmd_ids) > 0

        if fw_result is None and not agent_ok:
            # Neither firewall nor agents — full simulation fallback
            sim = await execute_action(action_type, params)
            return SprecterBridgeResult(
                success=sim.success,
                message=sim.message + " [simulation — no firewall adapter and no active SPECTER agents]",
                details={
                    **sim.details,
                    "simulation_reason": "No firewall adapter configured and fleet is empty",
                    "firewall": None,
                },
                dispatch_mode=DispatchMode.SIMULATION,
            )

        fw_detail = fw_result if fw_result else {"success": None, "message": "adapter_not_configured"}
        return SprecterBridgeResult(
            success=bool(fw_ok or agent_ok),
            message=(
                f"Firewall: {'ok' if fw_ok else ('not_configured' if fw_result is None else 'failed')} | "
                f"SPECTER broadcast: {len(cmd_ids)}/{len(agents)} agents queued"
            ),
            details={
                "firewall":        fw_detail,
                "command_type":    command_type,
                "specter_params":  specter_params,
                "agents_count":    len(cmd_ids),
                "agents_total":    len(agents),
                "batch_size":      BROADCAST_BATCH_SIZE,
                "queued_at":       now,
            },
            dispatch_mode=DispatchMode.BROADCAST,
            commands_issued=cmd_ids,
            agents_targeted=hostnames,
        )

    # ── Fallthrough (should not happen with correct routing tables) ───────────
    log.error("specter_bridge_unrouted", action=action_type)
    sim = await execute_action(action_type, params)
    return SprecterBridgeResult(
        success=sim.success,
        message=sim.message + " [simulation — action unrouted in bridge]",
        details={**sim.details, "simulation_reason": "Unrouted action type"},
        dispatch_mode=DispatchMode.SIMULATION,
    )
