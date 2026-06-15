"""
P40 — API Key Management  (Toque Premos aplicado)
==================================================
Endpoints for creating, listing, rotating, and revoking API keys.

Toque Premos design guarantees:
  - Autenticidad forense: raw key NEVER stored. Only an HMAC-SHA256 digest
    (keyed with the app SECRET_KEY) is persisted — unforgeable without the
    application secret even if the database is compromised.
  - One-time reveal: raw key returned exactly once (creation / rotation).
  - Scopes adaptativos: JSON-flexible permission list per key, validated at
    creation and enforceable at any endpoint via `require_api_key_scope()`.
  - Ledger Premos: every key lifecycle event (create, rotate, revoke) is
    emitted to the structured audit channel (asc.audit) with key_prefix,
    owner, scopes, and UTC timestamp — providing a tamper-evident trail.

Key format: asc_<8-char prefix>_<40-char random hex>
"""

import hashlib
import hmac as _hmac
import secrets
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_current_admin
from app.core.api_key_rate_limit import api_key_limiter
from app.core.audit import log_security_action
from app.core.config import get_settings
from app.core.plan_caps import enforce_api_key_cap
from app.core.tenant_context import get_tenant_id
from app.db.session import get_db
from app.db.tenant_filter import apply_tenant_filter
from app.models.api_key import APIKey
from app.models.tenant import Tenant
from app.models.user import User

router = APIRouter(prefix="/api-keys", tags=["API Keys"])
_settings = get_settings()

# ── Constants ─────────────────────────────────────────────────────────────────

_PREFIX_LEN = 8
_SECRET_LEN = 40   # hex chars from secrets.token_hex(20) → 40 hex chars
_MAX_KEYS_PER_USER = 20

VALID_SCOPES = frozenset({"read", "write", "admin"})


# ── Helpers ───────────────────────────────────────────────────────────────────

def _generate_raw_key() -> str:
    """Return a new raw API key: asc_<prefix8>_<random40>"""
    prefix = secrets.token_hex(4)      # 8 hex chars
    body = secrets.token_hex(20)       # 40 hex chars
    return f"asc_{prefix}_{body}"


def _hash_key(raw_key: str) -> str:
    """
    HMAC-SHA256 keyed digest of the raw key.

    Using the app SECRET_KEY as the HMAC secret means the stored hash is
    cryptographically bound to this specific ASC instance. Even if an attacker
    obtains the raw_key from a client, they cannot verify it against a stolen
    DB row without also knowing the SECRET_KEY.  Plain SHA-256 would allow
    offline brute-force; HMAC-SHA256 prevents it.
    """
    mac = _hmac.new(
        _settings.SECRET_KEY.encode(),
        raw_key.encode(),
        hashlib.sha256,
    )
    return mac.hexdigest()


def _prefix_of(raw_key: str) -> str:
    """Return the 8-char prefix portion (the segment between the two underscores)."""
    return raw_key.split("_")[1]


# ── Schemas ───────────────────────────────────────────────────────────────────

class APIKeyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    scopes: list[str] = Field(default=["read"])
    expires_at: datetime | None = None


class APIKeyResponse(BaseModel):
    id: str
    name: str
    key_prefix: str
    user_id: str
    scopes: list[str]
    expires_at: datetime | None
    last_used_at: datetime | None
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class APIKeyCreated(APIKeyResponse):
    raw_key: str  # only present on creation/rotation — never stored


class APIKeyPatch(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=100)
    expires_at: datetime | None = None
    is_active: bool | None = None


class RateLimitStatus(BaseModel):
    """P41 — Current rate limit usage for an API key."""
    key_prefix: str
    limit_per_minute: int
    limit_per_hour: int
    count_minute: int       # requests in the current minute window
    count_hour: int         # requests in the current hour window
    remaining_minute: int
    remaining_hour: int
    backend: str            # 'redis' or 'memory'


# ── Helpers (DB) ──────────────────────────────────────────────────────────────

async def _get_key_or_404(key_id: str, db: AsyncSession) -> APIKey:
    result = await db.execute(select(APIKey).where(APIKey.id == key_id))
    key = result.scalar_one_or_none()
    if not key:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key no encontrada")
    return key


def _validate_scopes(scopes: list[str]) -> None:
    invalid = [s for s in scopes if s not in VALID_SCOPES]
    if invalid:
        raise HTTPException(
            status_code=422,
            detail=f"Scopes inválidos: {invalid}. Válidos: {sorted(VALID_SCOPES)}",
        )


# ── Ledger Premos helpers ─────────────────────────────────────────────────────

def _ledger_create(user: User, key: APIKey) -> None:
    """Emit Ledger Premos entry for key creation."""
    log_security_action(
        "api_key_created",
        user_id=user.id,
        role=user.role,
        resource="api_key",
        resource_id=key.id,
        detail=(
            f"name={key.name!r} prefix=asc_{key.key_prefix}… "
            f"scopes={key.scopes} "
            f"expires_at={key.expires_at.isoformat() if key.expires_at else 'never'}"
        ),
    )


def _ledger_rotate(user: User, key: APIKey, old_prefix: str) -> None:
    """Emit Ledger Premos entry for key rotation."""
    log_security_action(
        "api_key_rotated",
        user_id=user.id,
        role=user.role,
        resource="api_key",
        resource_id=key.id,
        detail=f"old_prefix=asc_{old_prefix}… new_prefix=asc_{key.key_prefix}…",
    )


def _ledger_revoke(user: User, key_id: str, key_prefix: str) -> None:
    """Emit Ledger Premos entry for key revocation."""
    log_security_action(
        "api_key_revoked",
        user_id=user.id,
        role=user.role,
        resource="api_key",
        resource_id=key_id,
        detail=f"prefix=asc_{key_prefix}…",
    )


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/", response_model=APIKeyCreated, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    payload: APIKeyCreate,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """
    Create a new API key for the authenticated user.

    The raw key is returned **once** in this response and cannot be retrieved again.
    Only the HMAC-SHA256 digest is stored (Toque Premos — autenticidad forense).
    """
    _validate_scopes(payload.scopes)

    # P54: enforce per-plan api_key cap before any DB write.
    if current_user.tenant_id:
        tenant_result = await db.execute(
            select(Tenant).where(Tenant.id == current_user.tenant_id)
        )
        tenant = tenant_result.scalar_one_or_none()
        if tenant:
            await enforce_api_key_cap(tenant, current_user.id, db)

    raw = _generate_raw_key()
    key = APIKey(
        name=payload.name,
        key_prefix=_prefix_of(raw),
        key_hash=_hash_key(raw),
        user_id=current_user.id,
        scopes=payload.scopes,
        expires_at=payload.expires_at,
        tenant_id=get_tenant_id(),  # P51: auto-assign from request context
    )
    db.add(key)
    await db.commit()
    await db.refresh(key)

    # Ledger Premos — forensic audit trail
    _ledger_create(current_user, key)

    return APIKeyCreated(
        id=key.id,
        name=key.name,
        key_prefix=key.key_prefix,
        user_id=key.user_id,
        scopes=key.scopes,
        expires_at=key.expires_at,
        last_used_at=key.last_used_at,
        is_active=key.is_active,
        created_at=key.created_at,
        raw_key=raw,
    )


@router.get("/", response_model=list[APIKeyResponse])
async def list_api_keys(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """
    List API keys.
    - Owners see only their own keys (within their tenant).
    - Admins see all keys within their tenant.
    P51: all queries scoped to the request's tenant via apply_tenant_filter().
    """
    if current_user.role == "admin":
        stmt = apply_tenant_filter(
            select(APIKey).order_by(APIKey.created_at.desc()), APIKey
        )
    else:
        stmt = apply_tenant_filter(
            select(APIKey)
            .where(APIKey.user_id == current_user.id)
            .order_by(APIKey.created_at.desc()),
            APIKey,
        )
    result = await db.execute(stmt)
    return result.scalars().all()


@router.get("/{key_id}", response_model=APIKeyResponse)
async def get_api_key(
    key_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """Get a single API key by ID."""
    key = await _get_key_or_404(key_id, db)
    if current_user.role != "admin" and key.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No autorizado")
    return key


@router.patch("/{key_id}", response_model=APIKeyResponse)
async def update_api_key(
    key_id: str,
    payload: APIKeyPatch,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """Update name, expiry, or active status of an API key."""
    key = await _get_key_or_404(key_id, db)
    if current_user.role != "admin" and key.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No autorizado")

    if payload.name is not None:
        key.name = payload.name
    if payload.expires_at is not None:
        key.expires_at = payload.expires_at
    if payload.is_active is not None:
        key.is_active = payload.is_active

    await db.commit()
    await db.refresh(key)
    return key


@router.delete("/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_api_key(
    key_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """Permanently delete (revoke) an API key. Emits Ledger Premos entry."""
    key = await _get_key_or_404(key_id, db)
    if current_user.role != "admin" and key.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No autorizado")

    key_prefix = key.key_prefix
    await db.delete(key)
    await db.commit()

    # Ledger Premos — forensic audit trail
    _ledger_revoke(current_user, key_id, key_prefix)


@router.post("/{key_id}/rotate", response_model=APIKeyCreated, status_code=status.HTTP_200_OK)
async def rotate_api_key(
    key_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """
    Rotate an API key: generate a new raw key, update the HMAC-SHA256 digest and prefix.
    Returns the new raw key once — store it securely.
    The key ID, name, scopes, and expiry are preserved.
    Emits Ledger Premos entry recording old and new prefix.
    """
    key = await _get_key_or_404(key_id, db)
    if current_user.role != "admin" and key.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No autorizado")

    old_prefix = key.key_prefix
    raw = _generate_raw_key()
    key.key_prefix = _prefix_of(raw)
    key.key_hash = _hash_key(raw)
    key.last_used_at = None  # reset usage tracker after rotation
    key.is_active = True     # re-activate if it was soft-deactivated

    await db.commit()
    await db.refresh(key)

    # Ledger Premos — forensic audit trail
    _ledger_rotate(current_user, key, old_prefix)

    return APIKeyCreated(
        id=key.id,
        name=key.name,
        key_prefix=key.key_prefix,
        user_id=key.user_id,
        scopes=key.scopes,
        expires_at=key.expires_at,
        last_used_at=key.last_used_at,
        is_active=key.is_active,
        created_at=key.created_at,
        raw_key=raw,
    )


@router.get("/admin/all", response_model=list[APIKeyResponse])
async def admin_list_all_keys(
    _: Annotated[User, Depends(get_current_admin)],
    db: AsyncSession = Depends(get_db),
):
    """Admin-only: list all API keys across all users within the current tenant."""
    stmt = apply_tenant_filter(
        select(APIKey).order_by(APIKey.created_at.desc()), APIKey
    )
    result = await db.execute(stmt)
    return result.scalars().all()


@router.get("/{key_id}/rate-limit-status", response_model=RateLimitStatus)
async def get_rate_limit_status(
    key_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """
    P41 — Return current rate limit usage for an API key.

    Shows how many requests have been made in the current minute and hour
    windows, and how many remain. Available to the key owner or any admin.
    """
    key = await _get_key_or_404(key_id, db)
    if current_user.role != "admin" and key.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No autorizado")

    count_m = await api_key_limiter.get_status(key.key_prefix, 60)
    count_h = await api_key_limiter.get_status(key.key_prefix, 3600)
    lpm = _settings.RATE_LIMIT_API_KEY_PER_MINUTE
    lph = _settings.RATE_LIMIT_API_KEY_PER_HOUR

    return RateLimitStatus(
        key_prefix=key.key_prefix,
        limit_per_minute=lpm,
        limit_per_hour=lph,
        count_minute=count_m,
        count_hour=count_h,
        remaining_minute=max(0, lpm - count_m),
        remaining_hour=max(0, lph - count_h),
        backend=api_key_limiter.mode,
    )


@router.post("/{key_id}/rate-limit-reset", status_code=status.HTTP_204_NO_CONTENT)
async def reset_rate_limit(
    key_id: str,
    current_user: Annotated[User, Depends(get_current_admin)],
    db: AsyncSession = Depends(get_db),
):
    """
    P41 — Admin-only: reset all rate limit counters for an API key.

    Clears both the per-minute and per-hour sliding windows.
    Emits a Ledger Premos entry for the reset action.
    Useful when a legitimate burst was incorrectly throttled or after key rotation.
    """
    key = await _get_key_or_404(key_id, db)
    await api_key_limiter.reset_for_prefix_all(key.key_prefix)
    log_security_action(
        "api_key_rate_limit_reset",
        user_id=current_user.id,
        role=current_user.role,
        resource="api_key",
        resource_id=key_id,
        detail=f"prefix=asc_{key.key_prefix}… rate limit counters cleared by admin",
    )
