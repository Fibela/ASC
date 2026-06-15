"""
SPECTER Executor — unisolate command.

Removes all iptables/netsh rules previously created by isolate_endpoint.py.
Identifies rules by the "SPECTER-ISOLATE" comment tag — never touches
pre-existing rules that were present before isolation.

Platform support:
  Linux  : iptables -D (requires root / CAP_NET_ADMIN)
  Windows: netsh advfirewall firewall delete rule (requires Administrator)
"""

import platform
import subprocess
from typing import Any

_RULE_TAG = "SPECTER-ISOLATE"


def execute(params: dict[str, Any]) -> dict[str, Any]:
    """
    Params:
      (none required — finds all SPECTER-ISOLATE rules automatically)
      dry_run (bool) — if True, report what would be removed without acting

    Returns result dict with success, message, platform, rules_removed.
    """
    dry_run = bool(params.get("dry_run", False))
    system = platform.system().lower()

    if system == "linux":
        return _unisolate_linux(dry_run)
    elif system == "windows":
        return _unisolate_windows(dry_run)
    else:
        return {"success": False, "message": f"Unsupported OS for unisolate: {system}"}


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


def _unisolate_linux(dry_run: bool) -> dict[str, Any]:
    """
    Find and delete all iptables rules with comment SPECTER-ISOLATE.

    Strategy: list all rules with --line-numbers, grep for SPECTER-ISOLATE,
    delete by rule number (highest first to avoid index shifting).
    """
    rules_removed: list[str] = []
    errors: list[str] = []

    for chain in ("INPUT", "OUTPUT"):
        # Get rule list with line numbers
        ok, output = _run(["iptables", "-L", chain, "--line-numbers", "-n"])
        if not ok:
            errors.append(f"list {chain}: {output}")
            continue

        # Collect line numbers of SPECTER-ISOLATE rules (descending to delete safely)
        tagged_lines = []
        for line in output.splitlines():
            if _RULE_TAG in line:
                parts = line.split()
                if parts and parts[0].isdigit():
                    tagged_lines.append(int(parts[0]))

        tagged_lines.sort(reverse=True)

        for num in tagged_lines:
            label = f"{chain}#{num}"
            if dry_run:
                rules_removed.append(f"[dry-run] would delete {label}")
            else:
                ok, msg = _run(["iptables", "-D", chain, str(num)])
                if ok:
                    rules_removed.append(label)
                else:
                    errors.append(f"delete {label}: {msg}")

    success = len(errors) == 0
    return {
        "success":       success,
        "message":       f"{len(rules_removed)} rules {'would be ' if dry_run else ''}removed"
                         + (f"; errors: {errors}" if errors else ""),
        "platform":      "linux",
        "rules_removed": rules_removed,
        "errors":        errors,
        "dry_run":       dry_run,
    }


def _unisolate_windows(dry_run: bool) -> dict[str, Any]:
    """
    Delete all netsh advfirewall rules whose name starts with SPECTER-ISOLATE.
    """
    rules_removed: list[str] = []
    errors: list[str] = []

    # List all rules matching our tag
    ok, output = _run(["netsh", "advfirewall", "firewall", "show", "rule",
                        f"name={_RULE_TAG}", "verbose"])

    if not ok or "No rules match" in output:
        return {
            "success": True,
            "message": "No SPECTER-ISOLATE rules found — endpoint already unisolated",
            "platform": "windows",
            "rules_removed": [],
        }

    # Extract rule names
    rule_names = []
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("Rule Name:"):
            name = stripped.split(":", 1)[1].strip()
            if name.startswith(_RULE_TAG):
                rule_names.append(name)

    for name in rule_names:
        if dry_run:
            rules_removed.append(f"[dry-run] would delete: {name}")
        else:
            ok, msg = _run(["netsh", "advfirewall", "firewall", "delete",
                             "rule", f"name={name}"])
            if ok:
                rules_removed.append(name)
            else:
                errors.append(f"delete {name}: {msg}")

    success = len(errors) == 0
    return {
        "success":       success,
        "message":       f"{len(rules_removed)} rules {'would be ' if dry_run else ''}removed"
                         + (f"; errors: {errors}" if errors else ""),
        "platform":      "windows",
        "rules_removed": rules_removed,
        "errors":        errors,
        "dry_run":       dry_run,
    }
