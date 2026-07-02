"""
ASC Audit Logger — structured trail for security-relevant events.

All audit events are emitted on the 'asc.audit' structlog channel with
log-level INFO so they appear in every environment (not suppressed by
DEBUG-only filters).

Design constraints:
  • No passwords, tokens, or credential values are ever passed to these
    functions — callers are responsible for not forwarding secrets.
  • user_id accepts Optional[str] so unauthenticated events (e.g. failed
    login before a user object is resolved) can still be recorded.
  • Every event includes a UTC timestamp so the audit trail is self-
    contained even if log aggregation reorders entries.
"""

from datetime import datetime, timezone
from typing import Optional

import structlog

_audit = structlog.get_logger("asc.audit")


def log_auth_event(
    action: str,
    *,
    user_id: Optional[str] = None,
    email: Optional[str] = None,
    detail: Optional[str] = None,
) -> None:
    """
    Record an authentication lifecycle event.

    action — one of: login_success, login_failure, logout, token_refresh,
              user_created, user_deactivated
    """
    _audit.info(
        "auth_event",
        action=action,
        user_id=str(user_id) if user_id is not None else None,
        email=email,
        detail=detail,
        ts=datetime.now(timezone.utc).isoformat(),
    )


def log_iam_event(
    action: str,
    *,
    performed_by: str,
    target_user: str,
    detail: Optional[str] = None,
) -> None:
    """
    Record an IAM lifecycle event.

    action — one of: account_locked, account_unlocked, account_disabled,
              account_enabled, force_reset_set, password_changed, token_revoked,
              signing_keys_rotated
    """
    _audit.info(
        "iam_event",
        action=action,
        performed_by=performed_by,
        target_user=target_user,
        detail=detail,
        ts=datetime.now(timezone.utc).isoformat(),
    )


def log_security_action(
    action: str,
    *,
    user_id: Optional[str] = None,
    role: Optional[str] = None,
    resource: Optional[str] = None,
    resource_id: Optional[str] = None,
    detail: Optional[str] = None,
    status: str = "ok",
    # Flexible alias parameters accepted by incident_service.py and other callers
    actor: Optional[str] = None,
    **extra,
) -> None:
    """
    Record a security-significant operation (playbook, neutralize, adapter call).

    action   — e.g. playbook_trigger, playbook_approve, playbook_abort,
                     neutralize_execute, adapter_test, adapter_push, adapter_pull
    resource — e.g. playbook, neutralization, adapter
    status   — "ok" | "error"

    Accepts `actor` as a flexible alias for `user_id` (used by incident_service).
    Extra kwargs are logged as-is for forward compatibility.
    """
    effective_user = user_id or actor or "system"
    _audit.info(
        "security_action",
        action=action,
        user_id=str(effective_user),
        role=role or "service",
        resource=resource or "internal",
        resource_id=resource_id,
        status=status,
        detail=detail,
        ts=datetime.now(timezone.utc).isoformat(),
    )
