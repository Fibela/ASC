"""
P54 — Per-Plan Resource Caps.

Enforces tenant-level limits on users and API keys based on the tenant's plan.
Called before any resource-creation endpoint to give a clear 403 before the DB
write, avoiding partial state on cap exceeded.

Plan defaults (can be overridden per-tenant via tenant.max_* columns):
  free:       5 users,  3 api_keys per user
  pro:        50 users, 20 api_keys per user
  enterprise: unlimited (None)
"""

from __future__ import annotations

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException

from app.models.user import User
from app.models.api_key import APIKey
from app.models.tenant import Tenant

# ── Plan defaults ─────────────────────────────────────────────────────────────

PLAN_DEFAULTS: dict[str, dict[str, int | None]] = {
    "free":       {"max_users": 5,    "max_api_keys_per_user": 3},
    "pro":        {"max_users": 50,   "max_api_keys_per_user": 20},
    "enterprise": {"max_users": None, "max_api_keys_per_user": None},
}

_UNKNOWN_PLAN_DEFAULT: dict[str, int | None] = {"max_users": 5, "max_api_keys_per_user": 3}


def _resolve_cap(tenant: Tenant, key: str) -> int | None:
    """Return effective cap: tenant column wins over plan default."""
    column_val: int | None = getattr(tenant, key, None)
    if column_val is not None:
        return column_val
    plan_defaults = PLAN_DEFAULTS.get(tenant.plan, _UNKNOWN_PLAN_DEFAULT)
    return plan_defaults.get(key)


# ── Enforcement functions ─────────────────────────────────────────────────────

async def enforce_user_cap(tenant: Tenant, db: AsyncSession) -> None:
    """Raise HTTP 403 if adding another user would exceed the tenant's user cap.

    Call this BEFORE creating a new user record.
    """
    cap = _resolve_cap(tenant, "max_users")
    if cap is None:
        return  # enterprise — unlimited

    result = await db.execute(
        select(func.count()).where(
            User.tenant_id == tenant.id,
            User.is_active == True,  # noqa: E712
        )
    )
    current_count: int = result.scalar_one()
    if current_count >= cap:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "user_cap_exceeded",
                "message": f"Plan '{tenant.plan}' allows a maximum of {cap} active users. "
                           f"Current count: {current_count}. Upgrade your plan to add more users.",
                "current": current_count,
                "cap": cap,
                "plan": tenant.plan,
            },
        )


async def enforce_api_key_cap(tenant: Tenant, user_id: str, db: AsyncSession) -> None:
    """Raise HTTP 403 if adding another API key would exceed the per-user cap.

    Call this BEFORE creating a new API key record.
    """
    cap = _resolve_cap(tenant, "max_api_keys_per_user")
    if cap is None:
        return  # enterprise — unlimited

    result = await db.execute(
        select(func.count()).where(
            APIKey.user_id == user_id,
            APIKey.is_active == True,  # noqa: E712
        )
    )
    current_count: int = result.scalar_one()
    if current_count >= cap:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "api_key_cap_exceeded",
                "message": f"Plan '{tenant.plan}' allows a maximum of {cap} active API keys per user. "
                           f"Current count: {current_count}. Upgrade your plan to create more keys.",
                "current": current_count,
                "cap": cap,
                "plan": tenant.plan,
            },
        )
