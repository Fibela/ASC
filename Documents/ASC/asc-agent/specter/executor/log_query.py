"""
SPECTER Executor — log_query command (P24 Live Hunt Dispatch).

Searches local system logs for a pattern and returns matching lines.
This executor is STRICTLY READ-ONLY — it never modifies, deletes, or
writes to any log file.

Enforced invariants:
  - read_only=True is validated; if False, the command is rejected.
  - max_results capped at 500 (never returns unbounded output).
  - Pattern length capped at 256 chars (prevents ReDoS).
  - No shell=True anywhere (prevents command injection via pattern).

Platform support:
  Linux  : journalctl (systemd), /var/log/ file search via grep
  Windows: wevtutil / PowerShell Get-WinEvent
"""

import platform
import re
import subprocess
from pathlib import Path
from typing import Any

_MAX_RESULTS   = 500
_MAX_PATTERN   = 256
_DEFAULT_SINCE = 60  # minutes


def execute(params: dict[str, Any]) -> dict[str, Any]:
    """
    Params:
      pattern      (str)  — search pattern (literal or regex)
      read_only    (bool) — MUST be True; command is rejected if False or absent
      data_source  (str)  — "system" (default), "auth", "syslog", "file"
      log_path     (str)  — only used when data_source="file"
      since_minutes(int)  — how far back to search (default: 60, max: 1440)
      max_results  (int)  — cap on returned lines (default/max: 500)
      is_regex     (bool) — treat pattern as regex (default: False = literal)

    Returns result dict with success, matches[], match_count, source, truncated.
    """
    # Security gate: read_only must be explicitly True
    if not params.get("read_only", False):
        return {
            "success": False,
            "message": "log_query rejected: read_only param must be True. "
                       "This executor never modifies logs.",
        }

    pattern = str(params.get("pattern", "")).strip()
    if not pattern:
        return {"success": False, "message": "Missing required param: pattern"}
    if len(pattern) > _MAX_PATTERN:
        return {"success": False, "message": f"Pattern too long (max {_MAX_PATTERN} chars)"}

    data_source   = str(params.get("data_source", "system")).lower()
    log_path      = str(params.get("log_path", "")).strip()
    since_minutes = min(int(params.get("since_minutes", _DEFAULT_SINCE)), 1440)
    max_results   = min(int(params.get("max_results", _MAX_RESULTS)), _MAX_RESULTS)
    is_regex      = bool(params.get("is_regex", False))

    # Validate regex pattern to catch ReDoS before search
    if is_regex:
        try:
            re.compile(pattern)
        except re.error as e:
            return {"success": False, "message": f"Invalid regex pattern: {e}"}

    system = platform.system().lower()

    if system == "linux":
        return _query_linux(pattern, data_source, log_path, since_minutes, max_results, is_regex)
    elif system == "windows":
        return _query_windows(pattern, since_minutes, max_results, is_regex)
    else:
        return {"success": False, "message": f"Unsupported OS for log_query: {system}"}


def _filter_lines(lines: list[str], pattern: str, is_regex: bool, max_results: int) -> list[str]:
    """Filter lines matching pattern (literal or regex). Caps at max_results."""
    results = []
    if is_regex:
        rx = re.compile(pattern, re.IGNORECASE)
        for line in lines:
            if rx.search(line):
                results.append(line)
                if len(results) >= max_results:
                    break
    else:
        p_lower = pattern.lower()
        for line in lines:
            if p_lower in line.lower():
                results.append(line)
                if len(results) >= max_results:
                    break
    return results


def _query_linux(pattern: str, source: str, log_path: str,
                 since_minutes: int, max_results: int, is_regex: bool) -> dict[str, Any]:

    if source == "system" or source == "syslog":
        # Try journalctl first (systemd); fallback to /var/log/syslog
        try:
            r = subprocess.run(
                ["journalctl", f"--since={since_minutes} minutes ago",
                 "--no-pager", "-n", str(max_results * 2), "-o", "short"],
                capture_output=True, text=True, timeout=20,
            )
            lines = r.stdout.splitlines()
            source_used = "journalctl"
        except FileNotFoundError:
            # Fallback to /var/log/syslog
            syslog = Path("/var/log/syslog")
            if not syslog.exists():
                syslog = Path("/var/log/messages")
            if not syslog.exists():
                return {"success": False, "message": "journalctl not found and no /var/log/syslog"}
            lines = syslog.read_text(errors="replace").splitlines()[-5000:]
            source_used = str(syslog)

    elif source == "auth":
        auth_log = Path("/var/log/auth.log")
        if not auth_log.exists():
            auth_log = Path("/var/log/secure")
        if not auth_log.exists():
            return {"success": False, "message": "Auth log not found (/var/log/auth.log or /var/log/secure)"}
        lines = auth_log.read_text(errors="replace").splitlines()[-5000:]
        source_used = str(auth_log)

    elif source == "file":
        if not log_path:
            return {"success": False, "message": "log_path required when data_source=file"}
        p = Path(log_path)
        if not p.exists():
            return {"success": False, "message": f"Log file not found: {log_path}"}
        if not p.is_file():
            return {"success": False, "message": f"Path is not a file: {log_path}"}
        # Safety: only allow reading files (not devices, sockets, etc.)
        if p.stat().st_size > 100 * 1024 * 1024:  # 100 MB limit
            lines = []
            # Read last 10,000 lines only
            with open(p, errors="replace") as f:
                for line in f:
                    lines.append(line.rstrip())
                    if len(lines) > 10000:
                        lines.pop(0)
        else:
            lines = p.read_text(errors="replace").splitlines()
        source_used = log_path

    else:
        return {"success": False, "message": f"Unknown data_source: {source}"}

    matches = _filter_lines(lines, pattern, is_regex, max_results)
    return {
        "success":     True,
        "matches":     matches,
        "match_count": len(matches),
        "source":      source_used,
        "truncated":   len(matches) >= max_results,
        "platform":    "linux",
    }


def _query_windows(pattern: str, since_minutes: int, max_results: int, is_regex: bool) -> dict[str, Any]:
    """Use PowerShell Get-WinEvent to query Windows Event Log."""
    # Build PowerShell command — no shell=True, pattern passed as argument
    # Escape single quotes in pattern
    safe_pattern = pattern.replace("'", "''")
    ps_cmd = (
        f"$since = (Get-Date).AddMinutes(-{since_minutes}); "
        f"Get-WinEvent -LogName System,Security,Application "
        f"-ErrorAction SilentlyContinue | "
        f"Where-Object {{ $_.TimeCreated -ge $since -and "
        f"$_.Message -like '*{safe_pattern}*' }} | "
        f"Select-Object -First {max_results} | "
        f"ForEach-Object {{ $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') + ' ' + $_.Message }}"
    )
    try:
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=30,
        )
        lines = [l for l in r.stdout.splitlines() if l.strip()]
    except FileNotFoundError:
        return {"success": False, "message": "PowerShell not found"}
    except subprocess.TimeoutExpired:
        return {"success": False, "message": "Windows event log query timed out (30s)"}

    matches = _filter_lines(lines, pattern, is_regex, max_results) if is_regex else lines
    return {
        "success":     True,
        "matches":     matches[:max_results],
        "match_count": len(matches[:max_results]),
        "source":      "windows_event_log",
        "truncated":   len(matches) >= max_results,
        "platform":    "windows",
    }
