"""
SPECTER Security — P14 Barriers, Filters, and Traps.

PremosCorp proprietary defense layers for the SPECTER agent network:

  Barrier 1 — Enrollment token (HMAC-SHA256, 1-hour rolling window)
  Barrier 2 — HTTPS enforcement (agent side, enforced via communicator)
  Filter 1  — Command param schema allowlist per command type
  Filter 2  — Shell injection metacharacter detection
  Filter 3  — Event rate limiter (sliding window, per agent)
  Trap 1    — Honeypot endpoint trigger logger
  Trap 2    — Suspicious registration frequency detector
  Trap 3    — Canary ping (Ed25519 proof-of-private-key liveness check)
"""

import hashlib
import hmac
import math
import re
import threading
import time
from typing import Any

from app.core.audit import log_security_action


# ── Enrollment token — HMAC-SHA256, 1-hour rolling window ─────────────────────

_ENROLL_PREFIX = "SPECTER-ENROLL-PREMOSCORP"


def _current_window() -> int:
    """Return the current 1-hour time window index."""
    return math.floor(time.time() / 3600)


def _hmac_hex(secret: str, message: str) -> str:
    return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()


def generate_enrollment_token(secret: str, window_offset: int = 0) -> str:
    """
    Generate an enrollment token for the given time window (default: current hour).

    Tokens are valid for ~1 hour. Distribute this token to agents via
    the SPECTER_ENROLLMENT_TOKEN environment variable.

    Usage (admin):
        python -c "from app.core.specter_security import generate_enrollment_token; \\
                   print(generate_enrollment_token('your-secret'))"
    """
    msg = f"{_ENROLL_PREFIX}:{_current_window() + window_offset}"
    return _hmac_hex(secret, msg)


def verify_enrollment_token(secret: str, token: str) -> bool:
    """
    Verify an agent enrollment token.

    Accepts current window or the previous window to tolerate up to ~1 hour of
    clock skew between agent boot time and backend verification time.

    Returns True unconditionally when secret is empty (dev mode — no guard
    configured, all agents allowed to register).
    """
    if not secret:
        return True  # dev mode: secret not configured → open registration
    if not token:
        return False
    valid = {generate_enrollment_token(secret, offset) for offset in (0, -1)}
    return any(hmac.compare_digest(token, t) for t in valid)


# ── Command param schema allowlist ─────────────────────────────────────────────

COMMAND_PARAM_SCHEMAS: dict[str, dict[str, type]] = {
    # Strict schemas used by the public POST /agents/{id}/command endpoint.
    # Keys listed here are REQUIRED. Optional extras go in COMMAND_EXTRA_PARAMS.
    # Internal bridge calls issue_command() directly and bypass this validation.
    "kill_process":       {"pid": int},
    "kill_process_name":  {"process_name": str},   # bridge-issued: kill by name (broadcast)
    "block_ip":           {"ip": str},
    "block_domain":       {"domain": str},          # P16.2 — DNS sinkhole / hosts file
    "quarantine_file":    {"path": str},
    "remove_persistence": {"persistence_type": str, "target": str},  # P16.2 — registry/cron/startup
    "isolate":            {},
    "unisolate":          {},
    "collect_snapshot":   {},
    "canary_ping":        {"nonce": str},
    # PANL rollback command types (P16 pre-P16.3)
    "unblock_ip":         {"ip": str},
    "unblock_domain":     {"domain": str},
    "restore_file":       {"path": str},
    # P35 new executors
    "isolate_endpoint":   {"asc_server_ip": str},
    "log_query":          {"pattern": str, "read_only": bool},
}

# Optional params allowed per command type (whitelist — not required but accepted).
# The strict validator rejects any key not in schema OR in this set.
COMMAND_EXTRA_PARAMS: dict[str, set[str]] = {
    "isolate_endpoint": {"asc_server_port", "comment"},
    "unisolate":        {"dry_run"},
    "unblock_ip":       {"direction"},
    "log_query":        {"data_source", "log_path", "since_minutes", "max_results", "is_regex"},
}


def validate_command_params(command_type: str, params: dict[str, Any]) -> list[str]:
    """
    Validate command params against the per-type allowlist schema.
    Returns a list of validation errors (empty list = params are valid).

    Required params are listed in COMMAND_PARAM_SCHEMAS[command_type].
    Optional extras are listed in COMMAND_EXTRA_PARAMS[command_type].
    Any key not in either set is rejected as unexpected.
    """
    if command_type not in COMMAND_PARAM_SCHEMAS:
        return [f"Unknown command_type: {command_type!r}"]

    schema = COMMAND_PARAM_SCHEMAS[command_type]
    extras = COMMAND_EXTRA_PARAMS.get(command_type, set())
    errors: list[str] = []

    for key, expected_type in schema.items():
        if key not in params:
            errors.append(f"Missing required param: {key!r}")
        elif not isinstance(params[key], expected_type):
            errors.append(
                f"Param {key!r}: expected {expected_type.__name__}, "
                f"got {type(params[key]).__name__}"
            )

    unknown = set(params.keys()) - set(schema.keys()) - extras
    if unknown:
        errors.append(f"Unexpected params: {sorted(unknown)}")

    return errors


# ── Shell injection detection ──────────────────────────────────────────────────

_INJECTION_RE = re.compile(r"[;&|`$(){}<>\[\]\n\r\\]")


def check_injection(params: dict[str, Any]) -> list[str]:
    """
    Scan string param values for shell metacharacters.
    Returns a list of flagged param keys (empty list = clean).
    """
    flagged: list[str] = []
    for key, value in params.items():
        if isinstance(value, str) and _INJECTION_RE.search(value):
            flagged.append(key)
    return flagged


# ── Sliding-window rate limiter ────────────────────────────────────────────────

class SprecterRateLimiter:
    """
    Thread-safe sliding-window rate limiter for SPECTER telemetry ingestion.

    Default: 200 events per 30-second window per agent (configurable via
    SPECTER_MAX_EVENTS_PER_WINDOW and SPECTER_RATE_WINDOW_SECONDS settings).
    """

    def __init__(self, max_requests: int, window_seconds: int) -> None:
        self._max = max_requests
        self._window = window_seconds
        self._buckets: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def is_allowed(self, key: str) -> bool:
        """Return True if within limit, False if throttled."""
        now = time.time()
        cutoff = now - self._window
        with self._lock:
            ts = [t for t in self._buckets.get(key, []) if t > cutoff]
            if len(ts) >= self._max:
                self._buckets[key] = ts
                return False
            ts.append(now)
            self._buckets[key] = ts
            return True

    def reset(self, key: str) -> None:
        """Clear rate limit state for a key (used in testing and admin ops)."""
        with self._lock:
            self._buckets.pop(key, None)

    def reset_all(self) -> None:
        """Clear all rate limit state."""
        with self._lock:
            self._buckets.clear()


# ── Suspicious registration tracker ───────────────────────────────────────────

class _RegistrationTracker:
    """Track registration frequency per hostname to detect rapid re-registration."""

    def __init__(self, max_per_hour: int = 5) -> None:
        self._max = max_per_hour
        self._records: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def is_suspicious(self, hostname: str) -> bool:
        """Record an attempt and return True if the frequency is suspicious."""
        now = time.time()
        cutoff = now - 3600
        with self._lock:
            ts = [t for t in self._records.get(hostname, []) if t > cutoff]
            ts.append(now)
            self._records[hostname] = ts
            return len(ts) > self._max


_reg_tracker = _RegistrationTracker()


def check_suspicious_registration(hostname: str, client_ip: str) -> bool:
    """
    Return True if registration frequency for this hostname is suspicious.
    Always emits a security audit event when suspicious — never blocks registration
    (agents need self-healing re-registration; blocking would cause availability issues).
    """
    if _reg_tracker.is_suspicious(hostname):
        log_security_action(
            "specter_suspicious_registration",
            user_id="agent",
            role="agent",
            resource="agent_registration",
            resource_id=hostname,
            detail=f"rapid re-registration detected hostname={hostname} ip={client_ip}",
        )
        return True
    return False


# ── Honeypot trigger logger ────────────────────────────────────────────────────

def log_honeypot_trigger(endpoint: str, client_ip: str, headers: dict) -> None:
    """
    Log access to a honeypot endpoint — signals active reconnaissance or scanning.
    Legitimate SPECTER agents never call these paths.
    """
    ua = str(headers.get("user-agent", "unknown"))[:120]
    log_security_action(
        "specter_honeypot_triggered",
        user_id="unknown",
        role="unknown",
        resource="honeypot",
        resource_id=endpoint,
        detail=f"ip={client_ip} ua={ua}",
    )
