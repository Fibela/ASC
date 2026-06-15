"""
SPECTER Process Collector — monitors running processes via psutil.

Emits:
  process_start — new process not seen in previous snapshot
  process_end   — process that was in previous snapshot but is gone
"""

import time
from typing import Any

import psutil


def _proc_info(proc: psutil.Process) -> dict[str, Any] | None:
    """Extract safe process metadata. Returns None if process is gone."""
    try:
        with proc.oneshot():
            return {
                "pid":        proc.pid,
                "name":       proc.name(),
                "exe":        proc.exe() if proc.exe() else "",
                "cmdline":    " ".join(proc.cmdline()[:32]),
                "username":   proc.username(),
                "status":     proc.status(),
                "create_time": proc.create_time(),
            }
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None


class ProcessCollector:
    """
    Compares process snapshots between polls and yields delta events.
    Keeps a PID→create_time dict to differentiate PID reuse from new processes.
    """

    def __init__(self) -> None:
        self._known: dict[int, float] = {}  # pid → create_time

    def collect(self) -> list[dict[str, Any]]:
        """
        Snapshot current processes, diff against last snapshot.
        Returns a list of event dicts (process_start / process_end).
        """
        current: dict[int, float] = {}
        current_info: dict[int, dict] = {}
        events: list[dict[str, Any]] = []

        for proc in psutil.process_iter():
            info = _proc_info(proc)
            if info is None:
                continue
            current[info["pid"]] = info["create_time"]
            current_info[info["pid"]] = info

        now = time.time()

        # Detect new processes
        for pid, create_time in current.items():
            if pid not in self._known or self._known[pid] != create_time:
                events.append({
                    "event_type": "process_start",
                    "severity":   "info",
                    "ts":         now,
                    **current_info[pid],
                })

        # Detect ended processes
        for pid, create_time in self._known.items():
            if pid not in current:
                events.append({
                    "event_type": "process_end",
                    "severity":   "info",
                    "ts":         now,
                    "pid":        pid,
                })

        self._known = current
        return events

    def reset(self) -> None:
        self._known = {}
