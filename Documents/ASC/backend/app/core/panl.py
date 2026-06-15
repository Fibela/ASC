"""
PANL — Premos Adaptive Neutralization Layer (P16 pre-P16.3)

Five integrated defense components:

  AdaptiveSeverity   — upgrades threat severity in real time based on endpoint
                       criticality, active threat-intel, and behavioral context.
  BehavioralThrottle — sliding-window detector for suspicious analyst patterns
                       (e.g. 10 identical destructive actions in 60 seconds).
  MultiSigPolicy     — determines how many distinct analyst approvals are required
                       per severity/action-type (CRITICAL → 2 signatures).
  FleetProximity     — subnet-proximity scorer used by the bridge to sort agents
                       nearest to a target for fleet-aware dispatch.
  RateLimit          — per-user sliding window for POST /neutralize/ requests.

Security invariants
-------------------
- Severity is NEVER downgraded — only upgraded.
- Throttle blocks are logged as security audit events.
- MultiSig forbids both self-approval and duplicate-approver signatures.
- FleetProximity is purely advisory; the bridge still dispatches to ALL agents
  in broadcast mode, but prioritises closest ones for lower latency.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any

from app.core.audit import log_security_action
from app.core.logging import get_logger

log = get_logger(__name__)


# ── Adaptive Severity ─────────────────────────────────────────────────────────

_SEVERITY_RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_RANK_TO_SEVERITY: dict[int, str] = {v: k for k, v in _SEVERITY_RANK.items()}

# Each rule: (context_field, upgrade_steps)
# Steps accumulate — "critical_infra + ransomware_indicator" can push low → critical.
UPGRADE_RULES: list[tuple[str, int]] = [
    ("endpoint_is_critical_infrastructure", 1),
    ("active_threat_intel_match",           1),
    ("multiple_recent_alerts",              1),   # >3 alerts on this target in 1 h
    ("known_lateral_movement",              2),
    ("ransomware_indicator",                2),
]


@dataclass
class AdaptiveContext:
    """
    Real-time threat context injected at the point of action request.

    Populate from alert metadata, asset inventory, and threat-intel feeds.
    All fields default False — safe to call with an empty context.
    """
    endpoint_is_critical_infrastructure: bool = False
    active_threat_intel_match: bool = False
    multiple_recent_alerts: bool = False
    known_lateral_movement: bool = False
    ransomware_indicator: bool = False
    # Agent labels such as ["critical_infrastructure", "domain_controller"]
    agent_labels: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AdaptiveContext:
        return cls(
            endpoint_is_critical_infrastructure=bool(
                data.get("endpoint_is_critical_infrastructure")
            ),
            active_threat_intel_match=bool(data.get("active_threat_intel_match")),
            multiple_recent_alerts=bool(data.get("multiple_recent_alerts")),
            known_lateral_movement=bool(data.get("known_lateral_movement")),
            ransomware_indicator=bool(data.get("ransomware_indicator")),
            agent_labels=list(data.get("agent_labels", [])),
        )


def adapt_severity(base_severity: str, context: AdaptiveContext) -> str:
    """
    Return the effective severity after applying PANL upgrade rules.

    Rules are applied cumulatively; the result is capped at "critical".
    Severity is never downgraded — if base is already "critical" nothing changes.
    """
    base = base_severity.lower()
    rank = _SEVERITY_RANK.get(base, 1)  # unknown → treat as medium

    # Agent label → context flag promotion
    if "critical_infrastructure" in context.agent_labels:
        context.endpoint_is_critical_infrastructure = True
    if "domain_controller" in context.agent_labels:
        context.endpoint_is_critical_infrastructure = True

    triggered: list[str] = []
    for flag, steps in UPGRADE_RULES:
        if getattr(context, flag, False):
            rank = min(rank + steps, 3)
            triggered.append(flag)

    adapted = _RANK_TO_SEVERITY[rank]

    if adapted != base:
        log.info(
            "panl_severity_upgrade",
            base=base,
            adapted=adapted,
            triggered_rules=triggered,
        )

    return adapted


# ── Multi-Signature Policy ────────────────────────────────────────────────────

def required_approvals_for(severity: str, action_type: str) -> int:
    """
    Return the minimum number of distinct analyst approvals required.

    CRITICAL  → 2 (Ed25519-authenticated dual-signature via JWT bearer tokens)
    HIGH or always-require types → 1
    Others    → 0 (immediate execution — no HitL gate)
    """
    # Lazy import to avoid circular import (approval.py imports panl.py)
    from app.services.approval import ALWAYS_REQUIRE_APPROVAL, APPROVAL_SEVERITIES

    s = severity.lower()
    if s == "critical":
        return 2
    if s in APPROVAL_SEVERITIES or action_type in ALWAYS_REQUIRE_APPROVAL:
        return 1
    return 0


# ── Behavioral Throttle ───────────────────────────────────────────────────────

class BehavioralThrottle:
    """
    Per-(user, action_type) sliding-window counter.

    Detects insider-threat and fat-finger scenarios:
      - Same analyst blocks 10+ IPs in 60 s     → throttle
      - Same analyst isolates 10+ endpoints      → throttle
      - Scripted / automated mass-action spree   → throttle

    On throttle: raises ValueError (endpoint converts to HTTP 429) and logs
    a SECURITY_AUDIT event so SOC leadership can investigate.
    """

    WINDOW_SECONDS: int = 60
    THRESHOLD: int = 10

    def __init__(self) -> None:
        self._buckets: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def _key(self, user: str, action_type: str) -> str:
        return f"{user}:{action_type}"

    def check(self, user: str, action_type: str) -> bool:
        """Record event. Returns True if allowed, False if throttled."""
        key = self._key(user, action_type)
        now = time.time()
        cutoff = now - self.WINDOW_SECONDS

        with self._lock:
            ts = [t for t in self._buckets.get(key, []) if t > cutoff]
            if len(ts) >= self.THRESHOLD:
                self._buckets[key] = ts
                return False
            ts.append(now)
            self._buckets[key] = ts
            return True

    def count(self, user: str, action_type: str) -> int:
        """Current event count in the sliding window (without recording)."""
        key = self._key(user, action_type)
        now = time.time()
        cutoff = now - self.WINDOW_SECONDS
        with self._lock:
            return len([t for t in self._buckets.get(key, []) if t > cutoff])

    def reset(self, user: str, action_type: str) -> None:
        """Clear counters for this (user, action_type) — used in tests and admin ops."""
        with self._lock:
            self._buckets.pop(self._key(user, action_type), None)

    def reset_all(self) -> None:
        with self._lock:
            self._buckets.clear()


behavioral_throttle = BehavioralThrottle()


def check_behavioral_throttle(user: str, action_type: str) -> None:
    """
    Enforce behavioral throttle. Raises ValueError if the analyst has exceeded
    THRESHOLD identical action_types in the sliding window.

    The caller (request_action) converts ValueError to HTTP 429.
    """
    if not behavioral_throttle.check(user, action_type):
        count = behavioral_throttle.count(user, action_type)
        log_security_action(
            "panl_behavioral_throttle_triggered",
            user_id=user,
            role="system",
            resource="neutralization",
            detail=(
                f"Throttled: {count}+ '{action_type}' actions in "
                f"{BehavioralThrottle.WINDOW_SECONDS}s — suspicious analyst pattern"
            ),
            status="blocked",
        )
        raise ValueError(
            f"Behavioral throttle: too many '{action_type}' requests in "
            f"{BehavioralThrottle.WINDOW_SECONDS}s. "
            "If this is a legitimate mass-action, contact your supervisor to reset the counter."
        )


# ── Fleet Proximity (fleet-aware dispatch) ────────────────────────────────────

def subnet_proximity(agent_ip: str | None, target_ip: str | None) -> int:
    """
    Return a proximity score between an agent's IP and a target IP.

    Lower score = closer to the target (preferred for fleet-aware dispatch).

    Score  Meaning
    -----  -------
    0      Same host (/32)
    1      Same /24 subnet
    2      Same /16 subnet
    3      Same /8  subnet
    4      Different /8 (or non-IP target)
    """
    if not agent_ip or not target_ip:
        return 4
    try:
        a = [int(x) for x in agent_ip.strip().split(".")]
        t = [int(x) for x in target_ip.strip().split(".")]
        if len(a) != 4 or len(t) != 4:
            return 4
        if a == t:
            return 0
        if a[:3] == t[:3]:
            return 1
        if a[:2] == t[:2]:
            return 2
        if a[:1] == t[:1]:
            return 3
        return 4
    except (ValueError, AttributeError):
        return 4


# ── Request Rate Limiter ──────────────────────────────────────────────────────

class RequestRateLimiter:
    """
    Per-user sliding-window rate limiter for POST /neutralize/.

    Default: 20 requests per 60-second window.
    Separate from BehavioralThrottle — this catches pure volume (any action mix),
    while BehavioralThrottle catches repeated identical action types.
    """

    WINDOW_SECONDS: int = 60
    MAX_REQUESTS: int = 20

    def __init__(self) -> None:
        self._buckets: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def is_allowed(self, user: str) -> bool:
        now = time.time()
        cutoff = now - self.WINDOW_SECONDS
        with self._lock:
            ts = [t for t in self._buckets.get(user, []) if t > cutoff]
            if len(ts) >= self.MAX_REQUESTS:
                self._buckets[user] = ts
                return False
            ts.append(now)
            self._buckets[user] = ts
            return True

    def reset(self, user: str) -> None:
        with self._lock:
            self._buckets.pop(user, None)

    def reset_all(self) -> None:
        with self._lock:
            self._buckets.clear()


request_rate_limiter = RequestRateLimiter()
