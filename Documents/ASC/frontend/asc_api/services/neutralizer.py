"""
Neutralization Service — automated and analyst-initiated response actions.

This module is the FALLBACK execution path only. The primary path is
specter_bridge.dispatch() which routes actions through SPECTER agents and
real F1 adapters. This module is called only when:
  1. The bridge raises an unexpected exception (approval._execute_immediately)
  2. The action_type is not routed by the bridge (simulation fallback)

HONESTIDAD (S103): un resultado tiene un estado explícito de tres valores:
  - executed  → la acción ocurrió de verdad (success=True, simulated=False)
  - simulated → no había agente/adaptador; NO ocurrió nada real
                (success=False, simulated=True) — NO es un fallo, requiere infra
  - failed    → se intentó de verdad y falló (success=False, simulated=False)

Regla dura: una simulación NUNCA devuelve success=True. Un producto de
seguridad no puede reportar "aislé el equipo" cuando no pasó nada.

For block_ip, block_domain, and disable_account the fallback first attempts
real adapter calls (success=True, executed). Solo si el adaptador no está
configurado cae a simulación (success=False, simulated=True).

For actions that require the SPECTER agent binary (isolate_endpoint,
kill_process, quarantine_file, remove_persistence) the fallback is always a
logged simulation because those require a live agent on the endpoint.
"""
import asyncio
from datetime import datetime, timezone

from asc_api.core.logging import get_logger

log = get_logger(__name__)


class NeutralizationResult:
    """
    Resultado de una acción de neutralización con estado honesto.

    status: "executed" | "simulated" | "failed"
    simulated: True cuando nada real ocurrió (falta agente/adaptador).
    success: True SOLO cuando la acción real se ejecutó con éxito.
    """

    def __init__(
        self,
        success: bool,
        message: str,
        details: dict | None = None,
        simulated: bool = False,
        status: str | None = None,
    ):
        self.success = success
        self.simulated = simulated
        self.status = status or (
            "executed" if success else ("simulated" if simulated else "failed")
        )
        self.message = message
        self.details = details or {}
        # Los flags honestos viajan también dentro de details (persistidos en DB/UI).
        self.details.setdefault("simulated", simulated)
        self.details.setdefault("status", self.status)


def _sim(message: str, details: dict, requires: str) -> NeutralizationResult:
    """Construye un resultado simulado honesto: success=False, simulated=True."""
    details = {**details, "simulation": True, "requires": requires}
    return NeutralizationResult(
        success=False, simulated=True, status="simulated", message=message, details=details
    )


async def isolate_endpoint(host: str, reason: str = "") -> NeutralizationResult:
    """Endpoint isolation requires a live SPECTER agent — simulation fallback."""
    log.warning("neutralize_fallback_simulation", action="isolate_endpoint", host=host)
    await asyncio.sleep(0.1)
    return _sim(
        f"[SIMULATION] Endpoint {host} isolation NOT executed — requires a live SPECTER agent",
        {"host": host, "ts": datetime.now(timezone.utc).isoformat()},
        requires="specter_agent",
    )


async def block_ip(ip: str, direction: str = "both", reason: str = "") -> NeutralizationResult:
    """Attempt real firewall adapter; fall back to honest simulation if unconfigured."""
    from asc_api.adapters import get_firewall_adapter

    fw = get_firewall_adapter()
    if fw is not None:
        try:
            result = await fw.block_ip(ip, reason=reason)
            log.info("neutralize_fallback_real", action="block_ip", ip=ip, adapter=type(fw).__name__)
            return NeutralizationResult(
                success=result.get("success", True),
                simulated=False,
                message=result.get("message", f"IP {ip} blocked via {type(fw).__name__}"),
                details={"ip": ip, "direction": direction, "adapter": type(fw).__name__,
                         "blocked_at": datetime.now(timezone.utc).isoformat()},
            )
        except Exception as exc:
            log.error("neutralize_fallback_adapter_error", action="block_ip", ip=ip, error=str(exc))
            return NeutralizationResult(
                success=False, simulated=False, status="failed",
                message=f"IP {ip} block FAILED via {type(fw).__name__}: {exc}",
                details={"ip": ip, "direction": direction, "adapter": type(fw).__name__, "error": str(exc)},
            )

    log.warning("neutralize_fallback_simulation", action="block_ip", ip=ip)
    await asyncio.sleep(0.05)
    return _sim(
        f"[SIMULATION] IP {ip} block NOT executed ({direction}) — no firewall adapter configured",
        {"ip": ip, "direction": direction, "blocked_at": datetime.now(timezone.utc).isoformat()},
        requires="firewall_adapter",
    )


async def block_domain(domain: str, reason: str = "") -> NeutralizationResult:
    """Attempt real firewall adapter; fall back to honest simulation if unconfigured."""
    from asc_api.adapters import get_firewall_adapter

    fw = get_firewall_adapter()
    if fw is not None:
        try:
            result = await fw.block_domain(domain, reason=reason)
            log.info("neutralize_fallback_real", action="block_domain", domain=domain, adapter=type(fw).__name__)
            return NeutralizationResult(
                success=result.get("success", True),
                simulated=False,
                message=result.get("message", f"Domain {domain} blocked via {type(fw).__name__}"),
                details={"domain": domain, "adapter": type(fw).__name__,
                         "blocked_at": datetime.now(timezone.utc).isoformat()},
            )
        except Exception as exc:
            log.error("neutralize_fallback_adapter_error", action="block_domain", domain=domain, error=str(exc))
            return NeutralizationResult(
                success=False, simulated=False, status="failed",
                message=f"Domain {domain} block FAILED via {type(fw).__name__}: {exc}",
                details={"domain": domain, "adapter": type(fw).__name__, "error": str(exc)},
            )

    log.warning("neutralize_fallback_simulation", action="block_domain", domain=domain)
    await asyncio.sleep(0.05)
    return _sim(
        f"[SIMULATION] Domain {domain} sinkhole NOT executed — no firewall adapter configured",
        {"domain": domain, "blocked_at": datetime.now(timezone.utc).isoformat()},
        requires="firewall_adapter",
    )


async def kill_process(host: str, process_name: str, pid: int | None = None) -> NeutralizationResult:
    """Process termination requires a live SPECTER agent — simulation fallback."""
    log.warning("neutralize_fallback_simulation", action="kill_process", host=host, process=process_name)
    target = f"{process_name}(PID:{pid})" if pid else process_name
    await asyncio.sleep(0.05)
    return _sim(
        f"[SIMULATION] Process {target} termination NOT executed on {host} — requires a live SPECTER agent",
        {"host": host, "process": process_name, "pid": pid, "ts": datetime.now(timezone.utc).isoformat()},
        requires="specter_agent",
    )


async def quarantine_file(host: str, file_path: str) -> NeutralizationResult:
    """File quarantine requires a live SPECTER agent — simulation fallback."""
    log.warning("neutralize_fallback_simulation", action="quarantine_file", host=host, file=file_path)
    await asyncio.sleep(0.05)
    quarantine_path = f"C:\\Quarantine\\{file_path.replace('/', '_').replace(chr(92), '_')}"
    return _sim(
        f"[SIMULATION] File quarantine NOT executed on {host} — requires a live SPECTER agent",
        {"host": host, "original_path": file_path, "quarantine_path": quarantine_path,
         "ts": datetime.now(timezone.utc).isoformat()},
        requires="specter_agent",
    )


async def remove_persistence(host: str, persistence_type: str, target: str) -> NeutralizationResult:
    """Persistence removal requires a live SPECTER agent — simulation fallback."""
    log.warning("neutralize_fallback_simulation", action="remove_persistence", host=host)
    await asyncio.sleep(0.05)
    return _sim(
        f"[SIMULATION] Persistence removal NOT executed on {host}: {persistence_type} — requires a live SPECTER agent",
        {"host": host, "type": persistence_type, "target": target,
         "ts": datetime.now(timezone.utc).isoformat()},
        requires="specter_agent",
    )


async def disable_account(username: str, domain: str = "LOCAL") -> NeutralizationResult:
    """Attempt real AD adapter; fall back to honest simulation if unconfigured."""
    from asc_api.adapters import get_identity_adapter

    iam = get_identity_adapter()
    if iam is not None:
        try:
            result = await iam.disable_account(username, domain, reason="neutralizer_fallback")
            log.info("neutralize_fallback_real", action="disable_account", user=username, adapter=type(iam).__name__)
            return NeutralizationResult(
                success=result.get("success", True),
                simulated=False,
                message=result.get("message", f"Account {domain}\\{username} disabled via {type(iam).__name__}"),
                details={"username": username, "domain": domain, "adapter": type(iam).__name__,
                         "disabled_at": datetime.now(timezone.utc).isoformat()},
            )
        except Exception as exc:
            log.error("neutralize_fallback_adapter_error", action="disable_account", user=username, error=str(exc))
            return NeutralizationResult(
                success=False, simulated=False, status="failed",
                message=f"Account {domain}\\{username} disable FAILED via {type(iam).__name__}: {exc}",
                details={"username": username, "domain": domain, "adapter": type(iam).__name__, "error": str(exc)},
            )

    log.warning("neutralize_fallback_simulation", action="disable_account", user=username)
    await asyncio.sleep(0.05)
    return _sim(
        f"[SIMULATION] Account {domain}\\{username} disable NOT executed — no identity (AD) adapter configured",
        {"username": username, "domain": domain, "disabled_at": datetime.now(timezone.utc).isoformat()},
        requires="identity_adapter",
    )


# Dispatcher map
ACTION_HANDLERS = {
    "isolate_endpoint":   isolate_endpoint,
    "block_ip":           block_ip,
    "block_domain":       block_domain,
    "kill_process":       kill_process,
    "quarantine_file":    quarantine_file,
    "remove_persistence": remove_persistence,
    "disable_account":    disable_account,
}

RECOMMENDED_ACTIONS = {
    "critical": ["isolate_endpoint", "kill_process", "block_ip"],
    "high":     ["block_ip", "quarantine_file", "remove_persistence"],
    "medium":   ["block_domain", "block_ip"],
    "low":      ["block_domain"],
}


async def execute_action(action_type: str, params: dict) -> NeutralizationResult:
    handler = ACTION_HANDLERS.get(action_type)
    if not handler:
        return NeutralizationResult(
            success=False, simulated=False, status="failed",
            message=f"Unknown action: {action_type}",
        )
    try:
        return await handler(**params)
    except Exception as e:
        log.error("neutralize_action_failed", action=action_type, error=str(e))
        return NeutralizationResult(
            success=False, simulated=False, status="failed", message=str(e)
        )
