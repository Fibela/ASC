"""
IAM Service — P16.3 PremosCorp Identity and Access Management.

Provides the core account lifecycle operations used by both the admin
REST API (iam.py endpoint) and the SPECTER bridge (disable_account
neutralization action now wired for real instead of simulation).

All operations:
  - Accept an AsyncSession so callers own the transaction lifecycle.
  - Return (success: bool, message: str) — callers decide HTTP mapping.
  - Emit structured audit entries via log_iam_event.
  - Never raise on "not found" — return (False, reason) instead so
    callers can decide between 404 and silent-pass semantics.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.core.audit import log_iam_event
from asc_api.core.logging import get_logger
from asc_api.models.user import User

log = get_logger(__name__)


# ── Account lifecycle ─────────────────────────────────────────────────────────

async def disable_account(
    target_email: str,
    db: AsyncSession,
    *,
    performed_by: str = "system",
) -> tuple[bool, str]:
    """
    Deactivate a user account (is_active → False).

    Existing tokens become invalid on the next request because get_current_user
    filters on is_active == True.  No explicit token revocation is needed — the
    DB check already acts as a hard gate.
    """
    result = await db.execute(select(User).where(User.email == target_email))
    user = result.scalar_one_or_none()
    if not user:
        return False, f"Usuario no encontrado: {target_email}"
    if not user.is_active:
        return True, f"Usuario ya estaba desactivado: {target_email}"

    user.is_active = False
    await db.commit()

    log_iam_event(
        "account_disabled",
        performed_by=performed_by,
        target_user=target_email,
    )
    log.info("iam_account_disabled", email=target_email, performed_by=performed_by)
    return True, f"Cuenta desactivada: {target_email}"


async def enable_account(
    target_email: str,
    db: AsyncSession,
    *,
    performed_by: str = "system",
) -> tuple[bool, str]:
    """Re-activate a previously disabled account."""
    result = await db.execute(select(User).where(User.email == target_email))
    user = result.scalar_one_or_none()
    if not user:
        return False, f"Usuario no encontrado: {target_email}"
    if user.is_active:
        return True, f"Usuario ya estaba activo: {target_email}"

    user.is_active = True
    await db.commit()

    log_iam_event(
        "account_enabled",
        performed_by=performed_by,
        target_user=target_email,
    )
    log.info("iam_account_enabled", email=target_email, performed_by=performed_by)
    return True, f"Cuenta activada: {target_email}"


async def lock_account(
    target_email: str,
    db: AsyncSession,
    *,
    performed_by: str = "system",
    minutes: int = 15,
) -> tuple[bool, str]:
    """
    Temporarily lock an account.

    Locked users cannot log in and their active tokens are rejected at the
    is_locked check in get_current_user.  The lock expires automatically after
    `minutes` minutes — no cleanup job is needed.
    """
    result = await db.execute(select(User).where(User.email == target_email))
    user = result.scalar_one_or_none()
    if not user:
        return False, f"Usuario no encontrado: {target_email}"

    locked_until = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    user.locked_until = locked_until
    await db.commit()

    log_iam_event(
        "account_locked",
        performed_by=performed_by,
        target_user=target_email,
        detail=f"Manual lock por {minutes}min — por {performed_by}",
    )
    log.info(
        "iam_account_locked",
        email=target_email,
        performed_by=performed_by,
        locked_until=locked_until.isoformat(),
    )
    return True, f"Cuenta bloqueada hasta {locked_until.isoformat()}"


async def unlock_account(
    target_email: str,
    db: AsyncSession,
    *,
    performed_by: str = "system",
) -> tuple[bool, str]:
    """Remove an active lock and reset the failed-attempt counter."""
    result = await db.execute(select(User).where(User.email == target_email))
    user = result.scalar_one_or_none()
    if not user:
        return False, f"Usuario no encontrado: {target_email}"

    user.locked_until = None
    user.failed_login_attempts = 0
    await db.commit()

    log_iam_event(
        "account_unlocked",
        performed_by=performed_by,
        target_user=target_email,
    )
    log.info("iam_account_unlocked", email=target_email, performed_by=performed_by)
    return True, f"Bloqueo eliminado para: {target_email}"


async def set_force_password_reset(
    target_email: str,
    db: AsyncSession,
    *,
    performed_by: str = "system",
) -> tuple[bool, str]:
    """
    Mark an account so the user must change their password before doing anything.

    The flag blocks all endpoints (via get_current_user) except
    POST /auth/change-password (which uses get_current_user_allow_reset).
    """
    result = await db.execute(select(User).where(User.email == target_email))
    user = result.scalar_one_or_none()
    if not user:
        return False, f"Usuario no encontrado: {target_email}"

    user.force_password_reset = True
    await db.commit()

    log_iam_event(
        "force_reset_set",
        performed_by=performed_by,
        target_user=target_email,
    )
    log.info("iam_force_reset_set", email=target_email, performed_by=performed_by)
    return True, f"Reset de contraseña requerido para: {target_email}"


async def get_user_iam_status(
    target_email: str,
    db: AsyncSession,
) -> Optional[dict]:
    """Return IAM status dict for a user, or None if not found."""
    result = await db.execute(select(User).where(User.email == target_email))
    user = result.scalar_one_or_none()
    if not user:
        return None
    return {
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role,
        "is_active": user.is_active,
        "is_locked": user.is_locked,
        "locked_until": user.locked_until.isoformat() if user.locked_until else None,
        "failed_login_attempts": user.failed_login_attempts,
        "force_password_reset": user.force_password_reset,
        "last_login": user.last_login.isoformat() if user.last_login else None,
    }
