"""
SPECTER Executor — kill_process command.

Terminates a process by PID with SIGTERM (graceful), then SIGKILL after timeout.
Platform-aware: uses psutil for cross-platform compatibility.
"""

import time
from typing import Any

import psutil


def execute(params: dict[str, Any]) -> dict[str, Any]:
    """
    Params:
      pid  (int)   — process ID to terminate
      name (str)   — expected process name (safety check — refuses if mismatch)
      force (bool) — skip name check (default False)

    Returns result dict with success, message, pid.
    """
    pid = params.get("pid")
    expected_name = params.get("name", "")
    force = params.get("force", False)

    if not pid:
        return {"success": False, "message": "Missing required param: pid"}

    try:
        proc = psutil.Process(int(pid))
    except psutil.NoSuchProcess:
        return {"success": False, "message": f"PID {pid} does not exist.", "pid": pid}
    except ValueError:
        return {"success": False, "message": f"Invalid PID: {pid}"}

    # Safety check: verify process name matches expectation
    if expected_name and not force:
        try:
            actual_name = proc.name()
        except psutil.AccessDenied:
            actual_name = ""
        if expected_name.lower() not in actual_name.lower():
            return {
                "success": False,
                "message": f"Process name mismatch: expected '{expected_name}', got '{actual_name}'. Use force=true to override.",
                "pid": pid,
            }

    try:
        proc.terminate()           # SIGTERM
        try:
            proc.wait(timeout=5)
        except psutil.TimeoutExpired:
            proc.kill()            # SIGKILL
            proc.wait(timeout=3)
        return {"success": True, "message": f"Process {pid} terminated.", "pid": pid}
    except psutil.NoSuchProcess:
        return {"success": True, "message": f"Process {pid} already gone.", "pid": pid}
    except psutil.AccessDenied as e:
        return {"success": False, "message": f"Access denied terminating PID {pid}: {e}", "pid": pid}
