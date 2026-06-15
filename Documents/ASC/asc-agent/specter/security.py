"""
SPECTER Agent Security — P14 agent-side barriers and traps.

Protections implemented at the agent runtime level:

  is_command_fresh()      — Reject replayed or stale commands (window=300s)
  validate_command()      — Verify required fields and timestamp freshness
  check_param_injection() — Detect shell metacharacters in command params
  handle_canary_ping()    — Sign nonce with private key (proof-of-identity)
  enforce_https()         — Warn (or raise) when backend URL is not HTTPS
"""

import re
import time
import warnings
from typing import Any

from specter.identity import sign_event

_INJECTION_RE = re.compile(r"[;&|`$(){}<>\[\]\n\r\\]")
_REQUIRED_CMD_FIELDS = {"id", "command_type", "params"}

# Maximum age of a command before it is considered a replay attempt.
_FRESHNESS_WINDOW_SECONDS = 300

# Allow up to 60 seconds of future skew (clock drift between agent and backend).
_FUTURE_SKEW_SECONDS = 60


def is_command_fresh(cmd: dict[str, Any], window_seconds: int = _FRESHNESS_WINDOW_SECONDS) -> bool:
    """
    Return True if the command's timestamp falls within the accepted window.

    Commands older than window_seconds or without a valid 'ts' field are rejected
    as potential replay attacks. Commands up to _FUTURE_SKEW_SECONDS in the future
    are accepted to tolerate clock drift.
    """
    ts = cmd.get("ts")
    if ts is None:
        return False
    try:
        age = time.time() - float(ts)
        return -_FUTURE_SKEW_SECONDS <= age <= window_seconds
    except (ValueError, TypeError):
        return False


def validate_command(cmd: dict[str, Any]) -> tuple[bool, str]:
    """
    Validate a command received from the backend before execution.

    Returns (valid: bool, reason: str).
    valid=True means the command passed all checks and is safe to dispatch.
    """
    missing = _REQUIRED_CMD_FIELDS - set(cmd.keys())
    if missing:
        return False, f"Missing required fields: {sorted(missing)}"

    if not isinstance(cmd.get("command_type"), str):
        return False, "command_type must be a string"

    if not isinstance(cmd.get("params"), dict):
        return False, "params must be a dict"

    if not is_command_fresh(cmd):
        return False, f"Command is stale or has invalid timestamp (ts={cmd.get('ts')})"

    return True, "ok"


def check_param_injection(params: dict[str, Any]) -> list[str]:
    """
    Scan string param values for shell metacharacters that could enable injection.

    Returns a list of flagged param keys. An empty list means no injection detected.
    Checked characters: ; & | ` $ ( ) { } < > [ ] newline carriage-return backslash
    """
    flagged: list[str] = []
    for key, value in params.items():
        if isinstance(value, str) and _INJECTION_RE.search(value):
            flagged.append(key)
    return flagged


def handle_canary_ping(priv_key: str, params: dict[str, Any]) -> dict[str, Any]:
    """
    Respond to a canary_ping command by signing the nonce with our Ed25519 private key.

    The ASC backend verifies this signature against the registered public key,
    confirming that this agent still holds the original private key (detecting
    credential theft or agent impersonation).

    Returns: {"pong": "<base64-signature>", "nonce": "<original-nonce>"}
    """
    nonce = params.get("nonce", "")
    pong_sig = sign_event(priv_key, {"nonce": nonce})
    return {"pong": pong_sig, "nonce": nonce}


def enforce_https(url: str, strict: bool = False) -> None:
    """
    Verify that the backend URL uses HTTPS (TLS-encrypted transport).

    In production all SPECTER telemetry MUST be encrypted. This function:
      strict=False (default) — emits a Python warning (non-fatal, allows HTTP in dev)
      strict=True            — raises RuntimeError, preventing agent startup over HTTP

    Set SPECTER_STRICT_HTTPS=true env var in SprecterAgent to enable strict mode.
    """
    if not url.lower().startswith("https://"):
        msg = (
            f"[SPECTER-GUARD] Backend URL is not HTTPS: {url!r}. "
            "Telemetry will be transmitted in cleartext. "
            "Set backend URL to https:// in production."
        )
        if strict:
            raise RuntimeError(msg)
        warnings.warn(msg, stacklevel=3)
