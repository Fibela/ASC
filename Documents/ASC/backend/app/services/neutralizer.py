"""
Neutralization Service — automated and analyst-initiated response actions.
"""
import asyncio
from datetime import datetime, timezone
from app.core.logging import get_logger

log = get_logger(__name__)


class NeutralizationResult:
    def __init__(self, success: bool, message: str, details: dict | None = None):
        self.success = success
        self.message = message
        self.details = details or {}


async def isolate_endpoint(host: str, reason: str = "") -> NeutralizationResult:
    """Simulate endpoint isolation via EDR agent API."""
    log.info("neutralize_isolate_endpoint", host=host, reason=reason)
    await asyncio.sleep(0.1)  # EDR API call placeholder
    return NeutralizationResult(
        success=True,
        message=f"Endpoint {host} isolated from network",
        details={"host": host, "isolation_time": datetime.now(timezone.utc).isoformat(), "rollback": "re-enable NIC or EDR unblock"},
    )


async def block_ip(ip: str, direction: str = "both", reason: str = "") -> NeutralizationResult:
    """Add IP to firewall blocklist via API."""
    log.info("neutralize_block_ip", ip=ip, direction=direction)
    await asyncio.sleep(0.05)
    return NeutralizationResult(
        success=True,
        message=f"IP {ip} blocked ({direction})",
        details={"ip": ip, "direction": direction, "blocked_at": datetime.now(timezone.utc).isoformat()},
    )


async def block_domain(domain: str, reason: str = "") -> NeutralizationResult:
    """Add domain to DNS sinkhole / proxy blocklist."""
    log.info("neutralize_block_domain", domain=domain)
    await asyncio.sleep(0.05)
    return NeutralizationResult(
        success=True,
        message=f"Domain {domain} added to sinkhole",
        details={"domain": domain, "blocked_at": datetime.now(timezone.utc).isoformat()},
    )


async def kill_process(host: str, process_name: str, pid: int | None = None) -> NeutralizationResult:
    """Terminate malicious process via EDR."""
    log.info("neutralize_kill_process", host=host, process=process_name, pid=pid)
    target = f"{process_name}(PID:{pid})" if pid else process_name
    await asyncio.sleep(0.05)
    return NeutralizationResult(
        success=True,
        message=f"Process {target} terminated on {host}",
        details={"host": host, "process": process_name, "pid": pid, "killed_at": datetime.now(timezone.utc).isoformat()},
    )


async def quarantine_file(host: str, file_path: str) -> NeutralizationResult:
    """Move file to quarantine via EDR."""
    log.info("neutralize_quarantine_file", host=host, file=file_path)
    await asyncio.sleep(0.05)
    quarantine_path = f"C:\\Quarantine\\{file_path.replace('/', '_').replace('\\', '_')}"
    return NeutralizationResult(
        success=True,
        message=f"File quarantined on {host}",
        details={"host": host, "original_path": file_path, "quarantine_path": quarantine_path, "quarantined_at": datetime.now(timezone.utc).isoformat()},
    )


async def remove_persistence(host: str, persistence_type: str, target: str) -> NeutralizationResult:
    """Remove registry run key, scheduled task, or startup entry."""
    log.info("neutralize_remove_persistence", host=host, type=persistence_type, target=target)
    await asyncio.sleep(0.05)
    return NeutralizationResult(
        success=True,
        message=f"Persistence mechanism removed on {host}: {persistence_type} -> {target}",
        details={"host": host, "type": persistence_type, "target": target, "removed_at": datetime.now(timezone.utc).isoformat()},
    )


async def disable_account(username: str, domain: str = "LOCAL") -> NeutralizationResult:
    """Disable compromised user account via AD/local policy."""
    log.info("neutralize_disable_account", user=username, domain=domain)
    await asyncio.sleep(0.05)
    return NeutralizationResult(
        success=True,
        message=f"Account {domain}\\{username} disabled",
        details={"username": username, "domain": domain, "disabled_at": datetime.now(timezone.utc).isoformat()},
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
