"""
SPECTER Network Collector — monitors active TCP/UDP connections via psutil.

Emits:
  net_connect — new outbound connection not seen in previous snapshot
  net_listen  — new listening port not seen in previous snapshot
"""

import socket
import time
from typing import Any

import psutil


def _conn_key(c: Any) -> tuple:
    """Hashable key for a connection."""
    laddr = (c.laddr.ip, c.laddr.port) if c.laddr else ("", 0)
    raddr = (c.raddr.ip, c.raddr.port) if c.raddr else ("", 0)
    return (c.type, laddr, raddr, c.status)


def _conn_dict(c: Any, now: float) -> dict[str, Any]:
    return {
        "event_type":  "net_listen" if c.status == "LISTEN" else "net_connect",
        "severity":    "info",
        "ts":          now,
        "proto":       "tcp" if c.type == socket.SOCK_STREAM else "udp",
        "local_ip":    c.laddr.ip   if c.laddr else "",
        "local_port":  c.laddr.port if c.laddr else 0,
        "remote_ip":   c.raddr.ip   if c.raddr else "",
        "remote_port": c.raddr.port if c.raddr else 0,
        "status":      c.status,
        "pid":         c.pid or 0,
    }


class NetworkCollector:
    """
    Diffs network connections between polls.
    Ignores loopback connections (127.x.x.x, ::1) to reduce noise.
    """

    def __init__(self) -> None:
        self._known: set[tuple] = set()

    def collect(self) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        now = time.time()
        current: set[tuple] = set()

        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            return []

        for c in conns:
            # Skip loopback
            if c.laddr and c.laddr.ip.startswith("127."):
                continue
            if c.laddr and c.laddr.ip == "::1":
                continue

            key = _conn_key(c)
            current.add(key)
            if key not in self._known:
                events.append(_conn_dict(c, now))

        self._known = current
        return events

    def reset(self) -> None:
        self._known = set()
