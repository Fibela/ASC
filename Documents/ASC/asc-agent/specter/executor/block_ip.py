"""
SPECTER Executor — block_ip command.

Adds a DROP rule for the given IP using the native OS firewall.
  Linux:   iptables -I INPUT/OUTPUT 1 -s/-d <ip> -j DROP
  Windows: netsh advfirewall firewall add rule ...

Platform detection is automatic. No vendor dependency.
"""

import platform
import subprocess
from typing import Any


def execute(params: dict[str, Any]) -> dict[str, Any]:
    """
    Params:
      ip        (str)  — IP address to block
      direction (str)  — "inbound" | "outbound" | "both" (default: "both")
      comment   (str)  — optional rule description

    Returns result dict with success, message, ip, platform.
    """
    ip = params.get("ip", "").strip()
    direction = params.get("direction", "both").lower()
    comment = params.get("comment", f"SPECTER block {ip}")

    if not ip:
        return {"success": False, "message": "Missing required param: ip"}

    system = platform.system().lower()

    if system == "linux":
        return _block_linux(ip, direction, comment)
    elif system == "windows":
        return _block_windows(ip, direction, comment)
    else:
        return {"success": False, "message": f"Unsupported OS for block_ip: {system}", "ip": ip}


def _run(cmd: list[str]) -> tuple[bool, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            return True, r.stdout.strip()
        return False, (r.stderr or r.stdout).strip()
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except FileNotFoundError as e:
        return False, f"Command not found: {e}"


def _block_linux(ip: str, direction: str, comment: str) -> dict[str, Any]:
    results = []
    success = True

    if direction in ("inbound", "both"):
        ok, msg = _run(["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP",
                         "-m", "comment", "--comment", comment])
        results.append(f"INPUT: {msg}")
        success = success and ok

    if direction in ("outbound", "both"):
        ok, msg = _run(["iptables", "-I", "OUTPUT", "1", "-d", ip, "-j", "DROP",
                         "-m", "comment", "--comment", comment])
        results.append(f"OUTPUT: {msg}")
        success = success and ok

    return {
        "success":   success,
        "message":   " | ".join(results),
        "ip":        ip,
        "platform":  "linux",
        "direction": direction,
    }


def _block_windows(ip: str, direction: str, comment: str) -> dict[str, Any]:
    results = []
    success = True
    rule_name = f"SPECTER-BLOCK-{ip}"

    dirs = []
    if direction in ("inbound", "both"):
        dirs.append("in")
    if direction in ("outbound", "both"):
        dirs.append("out")

    for d in dirs:
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}-{d}",
            f"dir={d}",
            "action=block",
            "protocol=any",
            f"remoteip={ip}",
            "enable=yes",
            f"description={comment}",
        ]
        ok, msg = _run(cmd)
        results.append(f"{d}: {msg}")
        success = success and ok

    return {
        "success":   success,
        "message":   " | ".join(results),
        "ip":        ip,
        "platform":  "windows",
        "direction": direction,
    }
