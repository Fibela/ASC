"""
SPECTER Executor — unblock_domain command.

Removes a domain block previously applied by block_domain (hosts file method).
Both block and unblock operate on the OS hosts file — no external tools needed.

Hosts file locations:
  Linux / macOS : /etc/hosts
  Windows       : C:\\Windows\\System32\\drivers\\etc\\hosts

The block_domain companion executor (not yet in asc-agent) writes:
  0.0.0.0  <domain>   # SPECTER-BLOCK

This executor removes all lines tagged with "# SPECTER-BLOCK" for the
specified domain. Lines NOT tagged by SPECTER are never touched.

Security note:
  Hosts file modification requires root (Linux) or Administrator (Windows).
  Only removes lines containing the exact domain and the SPECTER-BLOCK tag.
"""

import platform
import re
from pathlib import Path
from typing import Any

_HOSTS_LINUX   = Path("/etc/hosts")
_HOSTS_WINDOWS = Path(r"C:\Windows\System32\drivers\etc\hosts")
_TAG           = "SPECTER-BLOCK"


def execute(params: dict[str, Any]) -> dict[str, Any]:
    """
    Params:
      domain (str) — domain name to unblock (REQUIRED)

    Returns result dict with success, message, domain, lines_removed.
    """
    domain = params.get("domain", "").strip().lower()
    if not domain:
        return {"success": False, "message": "Missing required param: domain"}

    # Basic domain validation — prevent path traversal / injection
    if not re.match(r"^[a-z0-9][a-z0-9.\-]{0,253}$", domain):
        return {"success": False, "message": f"Invalid domain format: {domain}"}

    system = platform.system().lower()
    hosts_path = _HOSTS_LINUX if system != "windows" else _HOSTS_WINDOWS

    return _remove_from_hosts(domain, hosts_path)


def _remove_from_hosts(domain: str, hosts_path: Path) -> dict[str, Any]:
    """Remove all SPECTER-BLOCK lines for this domain from the hosts file."""
    if not hosts_path.exists():
        return {"success": False, "message": f"Hosts file not found: {hosts_path}"}

    try:
        original = hosts_path.read_text(encoding="utf-8", errors="replace")
    except PermissionError:
        return {"success": False, "message": f"Permission denied reading {hosts_path} (requires root/Administrator)"}

    lines      = original.splitlines(keepends=True)
    kept       = []
    removed    = 0

    for line in lines:
        # Match: 0.0.0.0  <domain>  # SPECTER-BLOCK (with optional extra comment)
        is_block = (
            _TAG in line
            and re.search(r"\b" + re.escape(domain) + r"\b", line)
        )
        if is_block:
            removed += 1
        else:
            kept.append(line)

    if removed == 0:
        return {
            "success":       True,
            "message":       f"No SPECTER-BLOCK entries found for {domain} — already unblocked",
            "domain":        domain,
            "lines_removed": 0,
        }

    new_content = "".join(kept)

    try:
        hosts_path.write_text(new_content, encoding="utf-8")
    except PermissionError:
        return {
            "success": False,
            "message": f"Permission denied writing {hosts_path} (requires root/Administrator)",
        }

    return {
        "success":       True,
        "message":       f"Removed {removed} SPECTER-BLOCK line(s) for {domain}",
        "domain":        domain,
        "lines_removed": removed,
        "hosts_path":    str(hosts_path),
    }
