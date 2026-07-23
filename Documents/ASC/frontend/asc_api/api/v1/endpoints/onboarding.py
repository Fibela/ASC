"""
P53 + FASE2.3 — Onboarding Flow.

Endpoints:
  POST /onboarding/register          — create tenant + admin user, send verification email
  POST /onboarding/verify-email      — validate token, mark email_verified=True
  GET  /onboarding/status            — return current onboarding_step for the authed user
  POST /onboarding/complete          — advance step from pending_setup → completed
  POST /onboarding/sso-complete      — SSO users: optionally rename tenant, advance sso_welcome → completed

Onboarding wizard steps:
  Native:  pending_email → pending_setup → completed
  SSO:     sso_welcome → completed  (via /onboarding/sso-complete)

Security:
  - Raw verification token never stored in DB; only SHA-256(token) is persisted.
  - Token expires after EMAIL_VERIFICATION_EXPIRE_HOURS (default 24 h).
  - /verify-email is public (no auth) — user only has the token, not a JWT yet.
  - /status, /complete, and /sso-complete require a valid JWT (authenticated user).
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.api.deps import get_current_user
from asc_api.core.audit import log_security_action
from asc_api.core.config import get_settings
from asc_api.core.rate_limit import limiter
from asc_api.db.session import get_db
from asc_api.models.tenant import Tenant
from asc_api.models.user import User

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
    expires = datetime.now(UTC) + timedelta(hours=_settings.EMAIL_VERIFICATION_EXPIRE_HOURS)
    return raw, hashed, expires


async def _send_verification_email(email: str, raw_token: str) -> None:
    """Send email verification link via Resend if API key is configured; log only otherwise."""
    verify_url = f"https://asc.premoscorp.com/verify-email?token={raw_token}"
    log_security_action(
        "email_verification_sent",
        user_id=None,
        extra={"email": email, "token_prefix": raw_token[:8] + "…"},
    )
    api_key = _settings.RESEND_API_KEY
    if not api_key:
        return  # dev/test: verification link is in server logs only

    try:
        import httpx

        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(
                "https://api.resend.com/emails",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={
                    "from": _settings.RESEND_FROM_EMAIL,
                    "to": [email],
                    "subject": "Verifica tu email — ASC PremosCorp",
                    "html": (
                        f"<p>Haz clic en el siguiente enlace para verificar tu cuenta:</p>"
                        f"<p><a href='{verify_url}'>{verify_url}</a></p>"
                        f"<p>Este enlace expira en {_settings.EMAIL_VERIFICATION_EXPIRE_HOURS} horas.</p>"
                    ),
                },
            )
    except Exception:  # nosec B110 — email delivery failure is non-fatal; user can request resend
        log_security_action(
            "email_verification_send_failed",
            user_id=None,
            extra={"email": email},
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
@limiter.limit(_settings.RATE_LIMIT_REGISTER)
async def register(
    request: Request,
    payload: RegisterRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Self-service tenant registration.

    Creates a new Tenant + admin User in a single transaction.
    The new user starts with email_verified=False and onboarding_step='pending_email'.
    A verification token is generated and emailed to the user via Resend when
    RESEND_API_KEY is configured; otherwise the verification link is logged
    server-side (dev/test).  See _send_verification_email.

    On success: returns tenant_id and user_id. Login is blocked until email is
    verified — enforced by the email_verified gate in deps._resolve_user (runs on
    every authenticated request; unverified users get 403 email_verification_required).
    """
    # Check slug uniqueness
    existing_slug = await db.execute(select(Tenant).where(Tenant.slug == payload.tenant_slug))
    if existing_slug.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "slug_taken", "message": f"El slug '{payload.tenant_slug}' ya está en uso."},
        )

    # Check email uniqueness
    existing_email = await db.execute(select(User).where(User.email == payload.email))
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
    from asc_api.core.security import get_password_hash

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

    await _send_verification_email(payload.email, raw_token)

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
    result = await db.execute(select(User).where(User.email_verification_token == token_hash))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "invalid_token", "message": "Token de verificación inválido o ya utilizado."},
        )

    now = datetime.now(UTC)
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
            detail={
                "code": "email_not_verified",
                "message": "Debes verificar tu email antes de completar el onboarding.",
            },
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


# ── FASE 2.3 — SSO Onboarding wizard completion ───────────────────────────────


class SSOCompleteRequest(BaseModel):
    tenant_name: str | None = Field(None, min_length=2, max_length=255)


class SSOCompleteResponse(BaseModel):
    onboarding_step: str
    tenant_name: str | None
    message: str


@router.post("/sso-complete", response_model=SSOCompleteResponse)
async def sso_complete_onboarding(
    payload: SSOCompleteRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Advance an SSO-provisioned user from onboarding_step='sso_welcome' to 'completed'.

    Optionally renames the auto-generated tenant ('{slug} (SSO)') to a human-readable name.
    Safe to call on already-completed users (idempotent).

    Called by the first-time wizard on the frontend after an SSO user
    configures their workspace.
    """
    step = getattr(current_user, "onboarding_step", "completed")

    tenant_name_out: str | None = None

    # Update tenant name if provided (and user has a tenant)
    if payload.tenant_name and current_user.tenant_id:
        tenant_result = await db.execute(select(Tenant).where(Tenant.id == current_user.tenant_id))
        tenant = tenant_result.scalar_one_or_none()
        if tenant:
            tenant.name = payload.tenant_name
            tenant_name_out = payload.tenant_name

    if step == "completed":
        await db.commit()
        return SSOCompleteResponse(
            onboarding_step="completed",
            tenant_name=tenant_name_out,
            message="Configuración guardada.",
        )

    if step not in ("sso_welcome", "pending_setup"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "invalid_onboarding_step",
                "message": f"Este endpoint es solo para usuarios SSO (paso actual: {step}).",
            },
        )

    current_user.onboarding_step = "completed"
    await db.commit()

    log_security_action(
        "onboarding.sso_completed",
        user_id=current_user.id,
        extra={"tenant_id": current_user.tenant_id, "tenant_name": tenant_name_out},
    )

    return SSOCompleteResponse(
        onboarding_step="completed",
        tenant_name=tenant_name_out,
        message="¡Bienvenido a ASC! Tu workspace está listo.",
    )
