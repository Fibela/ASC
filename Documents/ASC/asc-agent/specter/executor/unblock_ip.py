"""
SPECTER Executor — unblock_ip command.

Removes a specific IP block rule previously created by block_ip.py.
Identifies rules by the IP address and the "SPECTER block" comment prefix.

Platform support:
  Linux  : iptables -D (requires root / CAP_NET_ADMIN)
  Windows: netsh advfirewall firewall delete rule (requires Administrator)
"""

import platform
import subprocess
from typing import Any

_RULE_PREFIX = "SPECTER block"


def execute(params: dict[str, Any]) -> dict[str, Any]:
    """
    Params:
      ip        (str)  — IP address to unblock (REQUIRED)
      direction (str)  — "inbound" | "outbound" | "both" (default: "both")

    Returns result dict with success, message, ip, platform.
    """
    ip = params.get("ip", "").strip()
    direction = params.get("direction", "both").lower()

    if not ip:
        return {"success": False, "message": "Missing required param: ip"}

    system = platform.system().lower()

    if system == "linux":
        return _unblock_linux(ip, direction)
    elif system == "windows":
        return _unblock_windows(ip, direction)
    else:
        return {"success": False, "message": f"Unsupported OS for unblock_ip: {system}"}


def _run(cmd: list[str]) -> tuple[bool, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            return True, r.stdout.strip() or "OK"
        return False, (r.stderr or r.stdout).strip()
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except FileNotFoundError as e:
        return False, f"Command not found: {e}"


def _unblock_linux(ip: str, direction: str) -> dict[str, Any]:
    """
    Remove iptables rules for the specified IP.
    Matches rules containing the IP regardless of rule number position.
    Uses `iptables -D` with the exact rule spec to avoid line-number issues.
    """
    results = []
    success = True

    if direction in ("inbound", "both"):
        ok, msg = _run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP",
                         "-m", "comment", "--comment", f"{_RULE_PREFIX} {ip}"])
        results.append(f"INPUT: {'removed' if ok else msg}")
        success = success and ok

    if direction in ("outbound", "both"):
        ok, msg = _run(["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP",
                         "-m", "comment", "--comment", f"{_RULE_PREFIX} {ip}"])
        results.append(f"OUTPUT: {'removed' if ok else msg}")
        success = success and ok

    return {
        "success":   success,
        "message":   " | ".join(results),
        "ip":        ip,
        "platform":  "linux",
        "direction": direction,
    }


def _unblock_windows(ip: str, direction: str) -> dict[str, Any]:
    """
    Remove netsh advfirewall rules created by block_ip.py.
    Rule names follow the pattern: SPECTER-BLOCK-{ip}-in / SPECTER-BLOCK-{ip}-out
    """
    results = []
    success = True
    rule_name = f"SPECTER-BLOCK-{ip}"

    dirs = []
    if direction in ("inbound", "both"):
        dirs.append("in")
    if direction in ("outbound", "both"):
        dirs.append("out")

    for d in dirs:
        full_name = f"{rule_name}-{d}"
        ok, msg = _run(["netsh", "advfirewall", "firewall", "delete",
                         "rule", f"name={full_name}"])
        results.append(f"{d}: {'removed' if ok else msg}")
        success = success and ok

    return {
        "success":   success,
        "message":   " | ".join(results),
        "ip":        ip,
        "platform":  "windows",
        "direction": direction,
    }
