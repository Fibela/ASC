"""
P53 — Onboarding Flow (self-service tenant registration + email verification).

Endpoints:
  POST /onboarding/register          — create tenant + admin user, send verification email
  POST /onboarding/verify-email      — validate token, mark email_verified=True
  GET  /onboarding/status            — return current onboarding_step for the authed user
  POST /onboarding/complete          — advance step from pending_setup → completed

Onboarding wizard steps:
  pending_email   → pending_setup → completed

Security:
  - Raw verification token never stored in DB; only SHA-256(token) is persisted.
  - Token expires after EMAIL_VERIFICATION_EXPIRE_HOURS (default 24 h).
  - /verify-email is public (no auth) — user only has the token, not a JWT yet.
  - /status and /complete require a valid JWT (authenticated user).
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.audit import log_security_action
from app.core.config import get_settings
from app.db.session import get_db
from app.models.tenant import Tenant
from app.models.user import User

router = APIRouter(prefix="/onboarding", tags=["Onboarding"])
_settings = get_settings()

# ── Helpers ───────────────────────────────────────────────────────────────────

def _token_hash(raw_token: str) -> str:
    """SHA-256 hex digest — raw token is never stored in the DB."""
    return hashlib.sha256(raw_token.encode()).hexdigest()


def _make_verification_token() -> tuple[str, str, datetime]:
    """Return (raw_token, token_hash, expires_at)."""
    raw = secrets.token_urlsafe(32)
    hashed = _token_hash(raw)
    expires = datetime.now(timezone.utc) + timedelta(
        hours=_settings.EMAIL_VERIFICATION_EXPIRE_HOURS
    )
    return raw, hashed, expires


def _send_verification_email(email: str, raw_token: str) -> None:
    """
    Stub email sender for P53. In production: replace with SES / SendGrid call.

    The verification URL would be:
        https://app.premoscorp.com/verify-email?token={raw_token}
    """
    # Avoid logging the raw token in audit records; just note it was sent.
    log_security_action(
        "email_verification_sent",
        user_id=None,
        extra={"email": email, "token_prefix": raw_token[:8] + "…"},
    )


# ── Schemas ───────────────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    tenant_name: str = Field(..., min_length=2, max_length=255)
    tenant_slug: str = Field(..., min_length=3, max_length=100, pattern=r"^[a-z0-9][a-z0-9-]{1,98}[a-z0-9]$")
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)
    full_name: str = Field(..., min_length=1, max_length=255)


class RegisterResponse(BaseModel):
    tenant_id: str
    user_id: str
    email: str
    onboarding_step: str
    message: str


class VerifyEmailRequest(BaseModel):
    token: str = Field(..., min_length=10)


class VerifyEmailResponse(BaseModel):
    email_verified: bool
    onboarding_step: str
    message: str


class OnboardingStatusResponse(BaseModel):
    user_id: str
    email: str
    email_verified: bool
    onboarding_step: str


class CompleteOnboardingResponse(BaseModel):
    onboarding_step: str
    message: str


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register(
    payload: RegisterRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Self-service tenant registration.

    Creates a new Tenant + admin User in a single transaction.
    The new user starts with email_verified=False and onboarding_step='pending_email'.
    A verification token is generated and would be emailed to the user (stub in P53).

    On success: returns tenant_id and user_id. Login is blocked until email is verified.
    """
    # Check slug uniqueness
    existing_slug = await db.execute(
        select(Tenant).where(Tenant.slug == payload.tenant_slug)
    )
    if existing_slug.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "slug_taken", "message": f"El slug '{payload.tenant_slug}' ya está en uso."},
        )

    # Check email uniqueness
    existing_email = await db.execute(
        select(User).where(User.email == payload.email)
    )
    if existing_email.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "email_taken", "message": "El email ya está registrado."},
        )

    # Create tenant
    tenant = Tenant(
        name=payload.tenant_name,
        slug=payload.tenant_slug,
        plan="free",
        contact_email=payload.email,
    )
    db.add(tenant)
    await db.flush()  # populate tenant.id before referencing it in User

    # Hash password — import here to avoid circular deps at module level
    from app.core.security import get_password_hash  # noqa: PLC0415
    raw_token, token_hash, expires_at = _make_verification_token()

    user = User(
        email=payload.email,
        full_name=payload.full_name,
        hashed_password=get_password_hash(payload.password),
        role="admin",
        tenant_id=tenant.id,
        # P53 onboarding fields
        email_verified=False,
        email_verification_token=token_hash,
        email_verification_expires_at=expires_at,
        onboarding_step="pending_email",
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    _send_verification_email(payload.email, raw_token)

    log_security_action(
        "tenant.registered",
        user_id=user.id,
        extra={"tenant_id": tenant.id, "slug": tenant.slug, "plan": tenant.plan},
    )

    return RegisterResponse(
        tenant_id=tenant.id,
        user_id=user.id,
        email=user.email,
        onboarding_step=user.onboarding_step,
        message="Tenant creado. Revisa tu email para verificar tu cuenta.",
    )


@router.post("/verify-email", response_model=VerifyEmailResponse)
async def verify_email(
    payload: VerifyEmailRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Validate the email verification token and activate the account.

    Public endpoint — called by clicking the link in the verification email.
    Looks up the SHA-256 hash of the submitted token in the DB.
    On success: sets email_verified=True, advances step to 'pending_setup',
    clears the token fields.
    """
    token_hash = _token_hash(payload.token)
    result = await db.execute(
        select(User).where(User.email_verification_token == token_hash)
    )
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "invalid_token", "message": "Token de verificación inválido o ya utilizado."},
        )

    now = datetime.now(timezone.utc)
    if user.email_verification_expires_at and now > user.email_verification_expires_at:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "token_expired", "message": "El token de verificación ha expirado. Solicita uno nuevo."},
        )

    user.email_verified = True
    user.email_verification_token = None
    user.email_verification_expires_at = None
    user.onboarding_step = "pending_setup"

    await db.commit()
    await db.refresh(user)

    log_security_action(
        "email.verified",
        user_id=user.id,
        extra={"tenant_id": user.tenant_id},
    )

    return VerifyEmailResponse(
        email_verified=True,
        onboarding_step=user.onboarding_step,
        message="Email verificado correctamente. Ya puedes iniciar sesión.",
    )


@router.get("/status", response_model=OnboardingStatusResponse)
async def onboarding_status(
    current_user: User = Depends(get_current_user),
):
    """Return the current onboarding state for the authenticated user."""
    return OnboardingStatusResponse(
        user_id=current_user.id,
        email=current_user.email,
        email_verified=getattr(current_user, "email_verified", True),
        onboarding_step=getattr(current_user, "onboarding_step", "completed"),
    )


@router.post("/complete", response_model=CompleteOnboardingResponse)
async def complete_onboarding(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Advance onboarding step from 'pending_setup' to 'completed'.

    Called by the frontend wizard after the user fills in initial config.
    Idempotent: calling on an already-completed user is a no-op.
    """
    step = getattr(current_user, "onboarding_step", "completed")

    if step == "completed":
        return CompleteOnboardingResponse(
            onboarding_step="completed",
            message="El onboarding ya estaba completado.",
        )

    if step == "pending_email":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "email_not_verified", "message": "Debes verificar tu email antes de completar el onboarding."},
        )

    current_user.onboarding_step = "completed"
    await db.commit()

    log_security_action(
        "onboarding.completed",
        user_id=current_user.id,
        extra={"tenant_id": current_user.tenant_id},
    )

    return CompleteOnboardingResponse(
        onboarding_step="completed",
        message="Onboarding completado exitosamente.",
    )
