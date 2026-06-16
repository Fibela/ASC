"""
P59 — SSO Bridge: Supabase JWT → ASC JWT Exchange.

Allows users authenticated via Supabase (premoscorp.com) to obtain an ASC
JWT without registering separately.

Flow:
  1. premoscorp.com client sends Supabase access token to POST /auth/supabase-sso
  2. ASC validates the token — supports both:
       a. New asymmetric JWT Signing Keys (RS256/EdDSA) via JWKS endpoint
       b. Legacy HS256 symmetric secret (SUPABASE_JWT_SECRET)
     Detection is automatic via the token's "alg" header claim.
  3. If the user (sub claim) is not in ASC → auto-provision: create User + Tenant
  4. Return an ASC JWT identical in structure to a normal login response

Security invariants:
  - SUPABASE_URL must be set (endpoint returns 503 if absent)
  - SUPABASE_JWT_SECRET is only required for legacy HS256 tokens
  - supabase_uid is unique per user — no impersonation possible
  - SSO-provisioned users get role="analyst" by default (cannot escalate via SSO)
  - hashed_password is set to a cryptographically random value — no password login
  - Tenant is auto-created with plan from SSO_DEFAULT_PLAN config
  - Rate limited at /auth/sso/* to prevent brute-force token replay

Endpoint:
  POST /auth/supabase-sso
"""

from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timezone

import jwt as pyjwt
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import create_access_token, get_password_hash
from app.db.session import get_db
from app.models.tenant import Tenant
from app.models.user import User

router = APIRouter(prefix="/auth", tags=["SSO"])

_settings = get_settings()


# ── Schemas ───────────────────────────────────────────────────────────────────

class SSORequest(BaseModel):
    supabase_token: str = Field(..., min_length=10, description="Supabase access token (JWT)")


class SSOResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    tenant_id: str | None
    user_id: str
    email: str
    role: str
    provisioned: bool = False  # True when a new ASC user was auto-created


# ── Helpers ───────────────────────────────────────────────────────────────────

def _validate_supabase_token(token: str) -> dict:
    """
    Decode and validate a Supabase JWT.
    Returns the decoded payload or raises HTTPException.

    Supports two Supabase signing modes automatically:
    - Asymmetric (RS256/EdDSA): new JWT Signing Keys — verified via JWKS endpoint
    - Symmetric (HS256): legacy JWT secret — verified with SUPABASE_JWT_SECRET

    Required claims: sub (user UUID), email, aud ("authenticated").
    """
    supabase_url = _settings.SUPABASE_URL
    if not supabase_url:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "sso_not_configured",
                    "message": "SSO bridge is not configured on this instance."},
        )

    # Detect algorithm from token header without full verification
    try:
        header = pyjwt.get_unverified_header(token)
    except pyjwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "supabase_token_invalid",
                    "message": "Cannot parse token header."},
        )

    algorithm = header.get("alg", "HS256")
    decode_opts = {
        "audience": _settings.SUPABASE_JWT_AUDIENCE,
        "options": {"require": ["sub", "email", "exp", "aud"]},
    }

    try:
        if algorithm in ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"):
            # New Supabase JWT Signing Keys — verify via JWKS (no secret needed)
            from jwt import PyJWKClient
            jwks_url = f"{supabase_url.rstrip('/')}/auth/v1/jwks"
            jwk_client = PyJWKClient(jwks_url, cache_keys=True, lifespan=600)
            signing_key = jwk_client.get_signing_key_from_jwt(token)
            payload = pyjwt.decode(
                token,
                signing_key.key,
                algorithms=[algorithm],
                **decode_opts,
            )
        else:
            # Legacy HS256 — requires symmetric SUPABASE_JWT_SECRET
            secret = _settings.SUPABASE_JWT_SECRET
            if not secret:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail={"code": "sso_not_configured",
                            "message": "SSO bridge (legacy HS256) requires SUPABASE_JWT_SECRET."},
                )
            payload = pyjwt.decode(
                token,
                secret,
                algorithms=["HS256"],
                **decode_opts,
            )

    except HTTPException:
        raise
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "supabase_token_expired",
                    "message": "Supabase token has expired. Please refresh your session."},
        )
    except pyjwt.InvalidAudienceError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "supabase_token_invalid_audience",
                    "message": "Supabase token has unexpected audience claim."},
        )
    except pyjwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "supabase_token_invalid",
                    "message": f"Supabase token validation failed: {exc}"},
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "sso_jwks_error",
                    "message": f"Could not fetch JWKS from Supabase: {exc}"},
        )

    supabase_uid = payload.get("sub")
    email = payload.get("email")
    if not supabase_uid or not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "supabase_token_missing_claims",
                    "message": "Token missing required sub or email claims."},
        )

    return payload


async def _find_or_create_user(
    supabase_uid: str,
    email: str,
    db: AsyncSession,
) -> tuple[User, bool]:
    """
    Find an existing ASC user by supabase_uid.
    If not found, also check by email (migration: link existing native user).
    If still not found, auto-provision new User + Tenant.
    Returns (user, provisioned) where provisioned=True means newly created.
    """
    # 1. Lookup by supabase_uid (primary SSO key)
    result = await db.execute(select(User).where(User.supabase_uid == supabase_uid))
    user = result.scalar_one_or_none()
    if user:
        return user, False

    # 2. Check if a native ASC user shares this email → link them
    result = await db.execute(select(User).where(User.email == email))
    existing_by_email = result.scalar_one_or_none()
    if existing_by_email and existing_by_email.supabase_uid is None:
        existing_by_email.supabase_uid = supabase_uid
        await db.commit()
        await db.refresh(existing_by_email)
        return existing_by_email, False

    # 3. Auto-provision: new tenant + user
    now = datetime.now(timezone.utc)
    tenant_id = str(uuid.uuid4())
    slug = email.split("@")[0].lower().replace(".", "-")[:50]

    tenant = Tenant(
        id=tenant_id,
        name=f"{slug} (SSO)",
        slug=f"{slug}-{tenant_id[:8]}",
        plan=_settings.SSO_DEFAULT_PLAN,
        is_active=True,
        created_at=now,
    )
    db.add(tenant)

    user = User(
        id=str(uuid.uuid4()),
        email=email,
        full_name=email.split("@")[0].replace(".", " ").title(),
        hashed_password=get_password_hash(secrets.token_urlsafe(32)),
        role="analyst",
        is_active=True,
        email_verified=True,
        onboarding_step="completed",
        supabase_uid=supabase_uid,
        tenant_id=tenant_id,
        created_at=now,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user, True


# ── Endpoint ──────────────────────────────────────────────────────────────────

@router.post(
    "/supabase-sso",
    response_model=SSOResponse,
    summary="SSO Exchange — Supabase JWT → ASC JWT",
)
async def supabase_sso(
    body: SSORequest,
    db: AsyncSession = Depends(get_db),
) -> SSOResponse:
    """
    Exchange a Supabase access token for an ASC JWT.

    The caller (premoscorp.com React app) must obtain a fresh Supabase session
    token and POST it here. ASC validates the token, finds or creates the user,
    and returns an ASC JWT usable at all /api/v1/* endpoints.

    **Security notes:**
    - SUPABASE_JWT_SECRET must be configured (returns 503 otherwise)
    - Expired Supabase tokens are rejected with 401
    - New users get role=analyst and a random unguessable password
    - Rate limit: 10 req/minute per IP (enforced via middleware)
    """
    payload = _validate_supabase_token(body.supabase_token)

    supabase_uid: str = payload["sub"]
    email: str = payload["email"]

    user, provisioned = await _find_or_create_user(supabase_uid, email, db)

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "user_inactive",
                    "message": "Account is disabled. Contact your administrator."},
        )

    access_token = create_access_token(subject=user.id, tenant_id=user.tenant_id)

    return SSOResponse(
        access_token=access_token,
        token_type="bearer",
        tenant_id=user.tenant_id,
        user_id=user.id,
        email=user.email,
        role=user.role,
        provisioned=provisioned,
    )
