"""
SPECTER Executor — isolate_endpoint command.

Isolates the endpoint by blocking ALL inbound/outbound traffic except:
  1. Loopback (127.0.0.1/::1) — required for local processes
  2. ASC backend connection — preserves the command channel so the agent
     can still receive the 'unisolate' command to undo isolation.
  3. Established/related connections already open at isolation time
     (Linux only, via iptables conntrack).

All SPECTER isolation rules are tagged with the comment "SPECTER-ISOLATE"
so unisolate.py can safely remove them without touching pre-existing rules.

Platform support:
  Linux  : iptables (requires root / CAP_NET_ADMIN)
  Windows: netsh advfirewall (requires Administrator)

Security note:
  This executor has NO offensive capability. It only restricts the network
  of the host it runs on — no code is sent to external systems.
"""

import os
import platform
import subprocess
from typing import Any

_RULE_TAG = "SPECTER-ISOLATE"


def execute(params: dict[str, Any]) -> dict[str, Any]:
    """
    Params:
      asc_server_ip (str)  — IP of the ASC backend to preserve (REQUIRED)
      asc_server_port (int)— ASC backend port to preserve (default: 443)
      comment (str)        — optional label for audit trail

    Returns result dict with success, message, platform, rules_applied.
    """
    asc_ip = params.get("asc_server_ip", "").strip()
    asc_port = int(params.get("asc_server_port", 443))
    comment = params.get("comment", f"{_RULE_TAG}: ASC endpoint isolation")

    if not asc_ip:
        # Fallback: try to derive from SPECTER_BACKEND_URL env var
        backend_url = os.environ.get("SPECTER_BACKEND_URL", "")
        if backend_url:
            import urllib.parse
            parsed = urllib.parse.urlparse(backend_url)
            asc_ip = parsed.hostname or ""

    if not asc_ip:
        return {
            "success": False,
            "message": "Missing required param: asc_server_ip (and SPECTER_BACKEND_URL not set)",
        }

    system = platform.system().lower()

    if system == "linux":
        return _isolate_linux(asc_ip, asc_port, comment)
    elif system == "windows":
        return _isolate_windows(asc_ip, asc_port, comment)
    else:
        return {"success": False, "message": f"Unsupported OS for isolate_endpoint: {system}"}


def _run(cmd: list[str]) -> tuple[bool, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if r.returncode == 0:
            return True, r.stdout.strip() or "OK"
        return False, (r.stderr or r.stdout).strip()
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except FileNotFoundError as e:
        return False, f"Command not found: {e}"


def _isolate_linux(asc_ip: str, asc_port: int, comment: str) -> dict[str, Any]:
    """
    iptables isolation strategy:
      1. Allow loopback (INSERT at top of INPUT/OUTPUT)
      2. Allow ESTABLISHED/RELATED (preserves current ASC TCP session)
      3. Allow traffic to/from asc_ip:asc_port explicitly
      4. DROP all other INPUT and OUTPUT

    All rules tagged with --comment SPECTER-ISOLATE for clean removal.
    """
    rules_applied: list[str] = []
    errors: list[str] = []

    def apply(cmd: list[str], label: str) -> None:
        ok, msg = _run(cmd)
        if ok:
            rules_applied.append(label)
        else:
            errors.append(f"{label}: {msg}")

    # Allow loopback
    apply(["iptables", "-I", "INPUT", "1", "-i", "lo", "-j", "ACCEPT",
           "-m", "comment", "--comment", _RULE_TAG], "loopback-in")
    apply(["iptables", "-I", "OUTPUT", "1", "-o", "lo", "-j", "ACCEPT",
           "-m", "comment", "--comment", _RULE_TAG], "loopback-out")

    # Allow ESTABLISHED/RELATED (keeps current ASC TCP session alive)
    apply(["iptables", "-I", "INPUT", "2", "-m", "state",
           "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT",
           "-m", "comment", "--comment", _RULE_TAG], "established-in")
    apply(["iptables", "-I", "OUTPUT", "2", "-m", "state",
           "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT",
           "-m", "comment", "--comment", _RULE_TAG], "established-out")

    # Allow explicit ASC server traffic
    apply(["iptables", "-I", "INPUT", "3", "-s", asc_ip, "-p", "tcp",
           "--sport", str(asc_port), "-j", "ACCEPT",
           "-m", "comment", "--comment", _RULE_TAG], f"asc-in-{asc_ip}")
    apply(["iptables", "-I", "OUTPUT", "3", "-d", asc_ip, "-p", "tcp",
           "--dport", str(asc_port), "-j", "ACCEPT",
           "-m", "comment", "--comment", _RULE_TAG], f"asc-out-{asc_ip}")

    # DROP everything else (append — runs after ACCEPT rules above)
    apply(["iptables", "-A", "INPUT", "-j", "DROP",
           "-m", "comment", "--comment", _RULE_TAG], "drop-all-in")
    apply(["iptables", "-A", "OUTPUT", "-j", "DROP",
           "-m", "comment", "--comment", _RULE_TAG], "drop-all-out")

    success = len(errors) == 0
    return {
        "success":       success,
        "message":       f"{len(rules_applied)} rules applied" + (f"; errors: {errors}" if errors else ""),
        "platform":      "linux",
        "rules_applied": rules_applied,
        "errors":        errors,
        "asc_server_ip": asc_ip,
    }


def _isolate_windows(asc_ip: str, asc_port: int, comment: str) -> dict[str, Any]:
    """
    netsh advfirewall strategy:
      1. Block all inbound/outbound (two rules)
      2. Allow loopback explicitly
      3. Allow traffic to/from asc_ip:asc_port
      (Allow rules take precedence over block rules when evaluated top-down)

    Windows firewall evaluates rules in this order: explicit Allow > explicit Block.
    """
    rules_applied: list[str] = []
    errors: list[str] = []

    def apply(cmd: list[str], label: str) -> None:
        ok, msg = _run(cmd)
        if ok:
            rules_applied.append(label)
        else:
            errors.append(f"{label}: {msg}")

    base = ["netsh", "advfirewall", "firewall", "add", "rule"]

    # Allow loopback
    apply(base + [f"name={_RULE_TAG}-loopback-in", "dir=in", "action=allow",
                  "remoteip=127.0.0.1", "enable=yes"], "loopback-in")
    apply(base + [f"name={_RULE_TAG}-loopback-out", "dir=out", "action=allow",
                  "remoteip=127.0.0.1", "enable=yes"], "loopback-out")

    # Allow ASC server traffic
    apply(base + [f"name={_RULE_TAG}-asc-in", "dir=in", "action=allow",
                  f"remoteip={asc_ip}", "protocol=tcp",
                  f"remoteport={asc_port}", "enable=yes"], f"asc-in-{asc_ip}")
    apply(base + [f"name={_RULE_TAG}-asc-out", "dir=out", "action=allow",
                  f"remoteip={asc_ip}", "protocol=tcp",
                  f"remoteport={asc_port}", "enable=yes"], f"asc-out-{asc_ip}")

    # Block all other traffic
    apply(base + [f"name={_RULE_TAG}-block-all-in", "dir=in", "action=block",
                  "remoteip=any", "protocol=any", "enable=yes"], "block-all-in")
    apply(base + [f"name={_RULE_TAG}-block-all-out", "dir=out", "action=block",
                  "remoteip=any", "protocol=any", "enable=yes"], "block-all-out")

    success = len(errors) == 0
    return {
        "success":       success,
        "message":       f"{len(rules_applied)} rules applied" + (f"; errors: {errors}" if errors else ""),
        "platform":      "windows",
        "rules_applied": rules_applied,
        "errors":        errors,
        "asc_server_ip": asc_ip,
    }
