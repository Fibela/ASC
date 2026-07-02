"""
Neutralization Service — automated and analyst-initiated response actions.

This module is the FALLBACK execution path only. The primary path is
specter_bridge.dispatch() which routes actions through SPECTER agents and
real F1 adapters. This module is called only when:
  1. The bridge raises an unexpected exception (approval._execute_immediately)
  2. The action_type is not routed by the bridge (simulation fallback)

For block_ip, block_domain, and disable_account the fallback now also
attempts real adapter calls before returning a simulated result, so a
bridge failure does not silently mask the neutralization.

For actions that require the SPECTER agent binary (isolate_endpoint,
kill_process, quarantine_file, remove_persistence) the fallback remains
a logged simulation because those require a live agent on the endpoint.
"""
import asyncio
from datetime import datetime, timezone

from asc_api.core.logging import get_logger

log = get_logger(__name__)


class NeutralizationResult:
    def __init__(self, success: bool, message: str, details: dict | None = None):
        self.success = success
        self.message = message
        self.details = details or {}


async def isolate_endpoint(host: str, reason: str = "") -> NeutralizationResult:
    """Endpoint isolation requires a live SPECTER agent — simulation fallback."""
    log.warning("neutralize_fallback_simulation", action="isolate_endpoint", host=host)
    await asyncio.sleep(0.1)
    return NeutralizationResult(
        success=True,
        message=f"[SIMULATION] Endpoint {host} isolation logged — SPECTER agent required for real execution",
        details={"host": host, "simulation": True, "ts": datetime.now(timezone.utc).isoformat()},
    )


async def block_ip(ip: str, direction: str = "both", reason: str = "") -> NeutralizationResult:
    """Attempt real firewall adapter; fall back to simulation if unconfigured."""
    from asc_api.adapters import get_firewall_adapter

    fw = get_firewall_adapter()
    if fw is not None:
        try:
            result = await fw.block_ip(ip, reason=reason)
            log.info("neutralize_fallback_real", action="block_ip", ip=ip, adapter=type(fw).__name__)
            return NeutralizationResult(
                success=result.get("success", True),
                message=result.get("message", f"IP {ip} blocked via {type(fw).__name__}"),
                details={"ip": ip, "direction": direction, "adapter": type(fw).__name__,
                         "blocked_at": datetime.now(timezone.utc).isoformat()},
            )
        except Exception as exc:
            log.error("neutralize_fallback_adapter_error", action="block_ip", ip=ip, error=str(exc))

    log.warning("neutralize_fallback_simulation", action="block_ip", ip=ip)
    await asyncio.sleep(0.05)
    return NeutralizationResult(
        success=True,
        message=f"[SIMULATION] IP {ip} blocked ({direction})",
        details={"ip": ip, "direction": direction, "simulation": True,
                 "blocked_at": datetime.now(timezone.utc).isoformat()},
    )


async def block_domain(domain: str, reason: str = "") -> NeutralizationResult:
    """Attempt real firewall adapter; fall back to simulation if unconfigured."""
    from asc_api.adapters import get_firewall_adapter

    fw = get_firewall_adapter()
    if fw is not None:
        try:
            result = await fw.block_domain(domain, reason=reason)
            log.info("neutralize_fallback_real", action="block_domain", domain=domain, adapter=type(fw).__name__)
            return NeutralizationResult(
                success=result.get("success", True),
                message=result.get("message", f"Domain {domain} blocked via {type(fw).__name__}"),
                details={"domain": domain, "adapter": type(fw).__name__,
                         "blocked_at": datetime.now(timezone.utc).isoformat()},
            )
        except Exception as exc:
            log.error("neutralize_fallback_adapter_error", action="block_domain", domain=domain, error=str(exc))

    log.warning("neutralize_fallback_simulation", action="block_domain", domain=domain)
    await asyncio.sleep(0.05)
    return NeutralizationResult(
        success=True,
        message=f"[SIMULATION] Domain {domain} added to sinkhole",
        details={"domain": domain, "simulation": True,
                 "blocked_at": datetime.now(timezone.utc).isoformat()},
    )


async def kill_process(host: str, process_name: str, pid: int | None = None) -> NeutralizationResult:
    """Process termination requires a live SPECTER agent — simulation fallback."""
    log.warning("neutralize_fallback_simulation", action="kill_process", host=host, process=process_name)
    target = f"{process_name}(PID:{pid})" if pid else process_name
    await asyncio.sleep(0.05)
    return NeutralizationResult(
        success=True,
        message=f"[SIMULATION] Process {target} termination logged on {host} — SPECTER agent required",
        details={"host": host, "process": process_name, "pid": pid, "simulation": True,
                 "killed_at": datetime.now(timezone.utc).isoformat()},
    )


async def quarantine_file(host: str, file_path: str) -> NeutralizationResult:
    """File quarantine requires a live SPECTER agent — simulation fallback."""
    log.warning("neutralize_fallback_simulation", action="quarantine_file", host=host, file=file_path)
    await asyncio.sleep(0.05)
    quarantine_path = f"C:\\Quarantine\\{file_path.replace('/', '_').replace(chr(92), '_')}"
    return NeutralizationResult(
        success=True,
        message=f"[SIMULATION] File quarantine logged on {host} — SPECTER agent required",
        details={"host": host, "original_path": file_path, "quarantine_path": quarantine_path,
                 "simulation": True, "quarantined_at": datetime.now(timezone.utc).isoformat()},
    )


async def remove_persistence(host: str, persistence_type: str, target: str) -> NeutralizationResult:
    """Persistence removal requires a live SPECTER agent — simulation fallback."""
    log.warning("neutralize_fallback_simulation", action="remove_persistence", host=host)
    await asyncio.sleep(0.05)
    return NeutralizationResult(
        success=True,
        message=f"[SIMULATION] Persistence removal logged on {host}: {persistence_type} — SPECTER agent required",
        details={"host": host, "type": persistence_type, "target": target, "simulation": True,
                 "removed_at": datetime.now(timezone.utc).isoformat()},
    )


async def disable_account(username: str, domain: str = "LOCAL") -> NeutralizationResult:
    """Attempt real AD adapter; fall back to simulation if unconfigured."""
    from asc_api.adapters import get_identity_adapter

    iam = get_identity_adapter()
    if iam is not None:
        try:
            result = await iam.disable_account(username, domain, reason="neutralizer_fallback")
            log.info("neutralize_fallback_real", action="disable_account", user=username, adapter=type(iam).__name__)
            return NeutralizationResult(
                success=result.get("success", True),
                message=result.get("message", f"Account {domain}\\{username} disabled via {type(iam).__name__}"),
                details={"username": username, "domain": domain, "adapter": type(iam).__name__,
                         "disabled_at": datetime.now(timezone.utc).isoformat()},
            )
        except Exception as exc:
            log.error("neutralize_fallback_adapter_error", action="disable_account", user=username, error=str(exc))

    log.warning("neutralize_fallback_simulation", action="disable_account", user=username)
    await asyncio.sleep(0.05)
    return NeutralizationResult(
        success=True,
        message=f"[SIMULATION] Account {domain}\\{username} disable logged — AD adapter required",
        details={"username": username, "domain": domain, "simulation": True,
                 "disabled_at": datetime.now(timezone.utc).isoformat()},
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
        return NeutralizationResult(success=False, message=f"Unknown action: {action_type}")
    try:
        return await handler(**params)
    except Exception as e:
        log.error("neutralize_action_failed", action=action_type, error=str(e))
        return NeutralizationResult(success=False, message=str(e))
