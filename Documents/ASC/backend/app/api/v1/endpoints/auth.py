from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, HTTPException, Depends, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
import uuid

from asc_api.db.session import get_db
from asc_api.models.user import User
from asc_api.core.security import (
    verify_password, get_password_hash, validate_password_strength,
    create_access_token, create_refresh_token, verify_token,
    decode_token_payload, REFRESH_EXPIRE_DAYS,
)
from asc_api.core.signing import (
    generate_analyst_keypair, encrypt_analyst_private_key,
)
from asc_api.core.jwt_blacklist import jwt_blacklist
from asc_api.core.config import get_settings
from asc_api.core.audit import log_auth_event, log_iam_event
from asc_api.core.rate_limit import limiter
from asc_api.api.deps import (
    get_current_user, get_current_user_allow_reset, get_current_admin,
)
from pydantic import BaseModel, Field, field_validator

router = APIRouter(prefix="/auth", tags=["Auth"])
settings = get_settings()

VALID_ROLES = {"admin", "analyst", "viewer"}

# Constant-time sentinel: ensures verify_password() is called even when the
# user is not found or inactive, preventing a timing side-channel that would
# let an attacker distinguish "user exists" from "user doesn't exist".
# bcrypt takes ~100 ms — skipping the call for non-existent users leaks this.
_TIMING_SENTINEL_HASH: str = get_password_hash("asc-timing-mitigation-sentinel-v1")


# ── Request / response schemas ────────────────────────────────────────────────

class LoginRequest(BaseModel):
    email: str
    password: str


class RegisterRequest(BaseModel):
    email: str
    password: str = Field(..., max_length=4096)
    full_name: str
    role: str = "analyst"


class RefreshRequest(BaseModel):
    refresh_token: str


class ChangePasswordRequest(BaseModel):
    current_password: str | None = None   # optional when force_password_reset=True
    new_password: str

    @field_validator("new_password")
    @classmethod
    def password_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("La nueva contraseña no puede estar vacía")
        return v


class UpdateUserRequest(BaseModel):
    role: str | None = None
    full_name: str | None = None
    force_password_reset: bool | None = None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _provision_signing_keys(user: User) -> None:
    """Generate and store an Ed25519 keypair for the user at account creation."""
    priv_b64, pub_b64 = generate_analyst_keypair()
    user.signing_public_key = pub_b64
    user.signing_private_key_enc = encrypt_analyst_private_key(priv_b64, settings.SECRET_KEY)


def _token_response(user: User) -> dict:
    return {
        "access_token":  create_access_token(user.id),
        "refresh_token": create_refresh_token(user.id),
        "token_type":    "bearer",  # nosec B105
        "expires_in":    settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "role":          user.role,
    }


def _user_dict(user: User) -> dict:
    return {
        "id":                   user.id,
        "email":                user.email,
        "full_name":            user.full_name,
        "role":                 user.role,
        "is_active":            user.is_active,
        "is_locked":            user.is_locked,
        "locked_until":         user.locked_until.isoformat() if user.locked_until else None,
        "failed_login_attempts": user.failed_login_attempts,
        "force_password_reset": user.force_password_reset,
        "last_login":           user.last_login.isoformat() if user.last_login else None,
        "created_at":           user.created_at.isoformat() if user.created_at else None,
    }


# ── Login ─────────────────────────────────────────────────────────────────────

@router.post("/login", summary="Autenticar usuario y obtener tokens JWT")
@limiter.limit(settings.RATE_LIMIT_LOGIN)
async def login(request: Request, payload: LoginRequest, db: AsyncSession = Depends(get_db)):
    # Find user regardless of is_active to give specific "inactive" vs "not found" treatment
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        # Always run bcrypt even for missing/inactive users to prevent timing
        # side-channel. Without this call the ~100 ms bcrypt delay is absent
        # for non-existent accounts — measurable by an attacker.
        verify_password(payload.password, _TIMING_SENTINEL_HASH)
        log_auth_event("login_failure", email=payload.email, detail="not_found_or_inactive")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciales inválidas"
        )

    # Account lock check — give explicit message so user knows to contact admin
    if user.is_locked:
        log_auth_event("login_failure", email=payload.email, detail="account_locked")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Cuenta bloqueada hasta {user.locked_until.isoformat()}. Contacta a un administrador.",
        )

    # Password verification
    if not verify_password(payload.password, user.hashed_password):
        user.failed_login_attempts = (user.failed_login_attempts or 0) + 1

        if user.failed_login_attempts >= settings.ACCOUNT_LOCK_THRESHOLD:
            user.locked_until = datetime.now(timezone.utc) + timedelta(
                minutes=settings.ACCOUNT_LOCK_MINUTES
            )
            log_iam_event(
                "account_locked",
                performed_by="system",
                target_user=user.email,
                detail=(
                    f"Auto-lock tras {user.failed_login_attempts} intentos fallidos — "
                    f"hasta {user.locked_until.isoformat()}"
                ),
            )

        await db.commit()
        log_auth_event("login_failure", email=payload.email, detail="invalid_password")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciales inválidas"
        )

    # Successful login — reset counters
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login = datetime.now(timezone.utc)
    await db.commit()

    log_auth_event("login_success", user_id=str(user.id), email=user.email, detail=user.role)

    resp = _token_response(user)
    if user.force_password_reset:
        resp["force_password_reset"] = True
    return resp


# ── Register (bootstrap only) ─────────────────────────────────────────────────

@router.post("/register", status_code=status.HTTP_201_CREATED, summary="Registrar nuevo usuario")
@limiter.limit(settings.RATE_LIMIT_REGISTER)
async def register(request: Request, payload: RegisterRequest, db: AsyncSession = Depends(get_db)):
    total = (await db.execute(select(func.count()).select_from(User))).scalar()

    if total > 0:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="El registro está restringido. Contacta a un administrador.",
        )

    existing = await db.execute(select(User).where(User.email == payload.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email ya registrado")

    user = User(
        id=str(uuid.uuid4()),
        email=payload.email,
        full_name=payload.full_name,
        hashed_password=get_password_hash(payload.password),
        role="admin",  # first user is always admin
    )
    _provision_signing_keys(user)
    db.add(user)
    await db.commit()
    log_auth_event("user_created", user_id=str(user.id), email=user.email, detail="bootstrap_admin")
    return {"id": user.id, "email": user.email, "role": user.role, "message": "Usuario creado correctamente"}


# ── Admin: create user ────────────────────────────────────────────────────────

@router.post("/users", status_code=status.HTTP_201_CREATED, summary="Admin: crear usuario adicional")
async def create_user(
    payload: RegisterRequest,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin),
):
    existing = await db.execute(select(User).where(User.email == payload.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email ya registrado")

    role = payload.role if payload.role in VALID_ROLES else "analyst"
    user = User(
        id=str(uuid.uuid4()),
        email=payload.email,
        full_name=payload.full_name,
        hashed_password=get_password_hash(payload.password),
        role=role,
    )
    _provision_signing_keys(user)
    db.add(user)
    await db.commit()
    log_auth_event("user_created", user_id=str(user.id), email=user.email, detail=f"by_admin:{admin.email}")
    return {"id": user.id, "email": user.email, "role": user.role}


# ── Admin: list + update users ────────────────────────────────────────────────

@router.get("/users", summary="Admin: listar todos los usuarios")
async def list_users(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_admin),
):
    result = await db.execute(select(User).order_by(User.created_at))
    users = result.scalars().all()
    return [_user_dict(u) for u in users]


@router.patch("/users/{user_id}", summary="Admin: actualizar rol o flags de usuario")
async def update_user(
    user_id: str,
    payload: UpdateUserRequest,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado")

    if payload.role is not None:
        if payload.role not in VALID_ROLES:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Rol inválido: {payload.role}")
        user.role = payload.role

    if payload.full_name is not None:
        user.full_name = payload.full_name

    if payload.force_password_reset is not None:
        user.force_password_reset = payload.force_password_reset
        if payload.force_password_reset:
            log_iam_event("force_reset_set", performed_by=admin.email, target_user=user.email)

    await db.commit()
    return _user_dict(user)


# ── Refresh ───────────────────────────────────────────────────────────────────

@router.post("/refresh", summary="Renovar access token usando refresh token")
@limiter.limit(settings.RATE_LIMIT_REFRESH)
async def refresh(request: Request, payload: RefreshRequest, db: AsyncSession = Depends(get_db)):
    # Check refresh token blacklist
    ref_payload = decode_token_payload(payload.refresh_token)
    ref_jti = ref_payload.get("jti")
    if ref_jti and await jwt_blacklist.is_revoked(ref_jti, db):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token revocado. Inicia sesión nuevamente.",
        )

    user_id = verify_token(payload.refresh_token, token_type="refresh")  # nosec B106
    result = await db.execute(
        select(User).where(User.id == user_id, User.is_active == True)
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido")

    if user.is_locked:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Cuenta bloqueada hasta {user.locked_until.isoformat()}",
        )

    # Revoke the old refresh token (rotation)
    if ref_jti:
        from datetime import datetime as _dt
        expires_at = _dt.fromtimestamp(ref_payload.get("exp", 0), tz=timezone.utc)
        await jwt_blacklist.revoke(
            ref_jti, expires_at, db, revoked_by=user.email, reason="token_rotation"
        )

    log_auth_event("token_refresh", user_id=str(user.id), email=user.email)
    return _token_response(user)


# ── Logout ────────────────────────────────────────────────────────────────────

@router.post("/logout", summary="Revocar token de acceso actual")
async def logout(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_allow_reset),
):
    """
    Blacklist the current access token's JTI so it cannot be reused.
    The client must discard both the access and refresh tokens.
    """
    auth_header = request.headers.get("authorization", "")
    token = auth_header.removeprefix("Bearer ").removeprefix("bearer ").strip()
    payload = decode_token_payload(token)
    jti = payload.get("jti")

    if jti:
        from datetime import datetime as _dt
        expires_at = _dt.fromtimestamp(payload.get("exp", 0), tz=timezone.utc)
        await jwt_blacklist.revoke(
            jti, expires_at, db,
            revoked_by=current_user.email,
            reason="logout",
        )
        log_iam_event("token_revoked", performed_by=current_user.email, target_user=current_user.email, detail="logout")

    log_auth_event("logout", user_id=str(current_user.id), email=current_user.email)
    return {"message": "Sesión cerrada correctamente"}


# ── Change password ───────────────────────────────────────────────────────────

@router.post("/change-password", summary="Cambiar contraseña (requerido si force_password_reset=True)")
@limiter.limit(settings.RATE_LIMIT_CHANGE_PASSWORD)
async def change_password(
    request: Request,
    payload: ChangePasswordRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user_allow_reset),
):
    """
    Change the authenticated user's password.

    - If force_password_reset is True, current_password is optional.
    - Otherwise current_password must be provided and correct.
    - New password must meet strength requirements.
    - Current token is revoked after success — client must re-login.
    """
    # Validate current password when not in forced reset
    if not current_user.force_password_reset:
        if not payload.current_password:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="current_password requerido cuando no hay reset forzado",
            )
        if not verify_password(payload.current_password, current_user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Contraseña actual incorrecta",
            )

    # Strength validation
    errors = validate_password_strength(payload.new_password)
    if errors:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"message": "Contraseña demasiado débil", "rules": errors},
        )

    # Reject reuse of current password
    if verify_password(payload.new_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="La nueva contraseña no puede ser igual a la anterior",
        )

    # Update password and clear reset flag
    current_user.hashed_password = get_password_hash(payload.new_password)
    current_user.force_password_reset = False
    await db.commit()

    # Revoke current access token — force fresh login with new credentials
    auth_header = request.headers.get("authorization", "")
    token = auth_header.removeprefix("Bearer ").removeprefix("bearer ").strip()
    token_payload = decode_token_payload(token)
    jti = token_payload.get("jti")
    if jti:
        from datetime import datetime as _dt
        expires_at = _dt.fromtimestamp(token_payload.get("exp", 0), tz=timezone.utc)
        await jwt_blacklist.revoke(
            jti, expires_at, db,
            revoked_by=current_user.email,
            reason="password_changed",
        )

    log_iam_event("password_changed", performed_by=current_user.email, target_user=current_user.email)
    log_auth_event("password_changed", user_id=str(current_user.id), email=current_user.email)
    return {"message": "Contraseña cambiada correctamente. Inicia sesión con tus nuevas credenciales."}


# ── Me ────────────────────────────────────────────────────────────────────────

@router.post("/users/{user_id}/unlock", summary="Admin: desbloquear cuenta de usuario")
async def unlock_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin),
):
    """
    Reset account lockout: clears locked_until and failed_login_attempts.
    Only admins can call this endpoint.
    """
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado")

    if not user.is_locked:
        return {"message": "La cuenta no está bloqueada", "user": _user_dict(user)}

    user.locked_until = None
    user.failed_login_attempts = 0
    await db.commit()

    log_iam_event(
        "account_unlocked",
        performed_by=admin.email,
        target_user=user.email,
        detail="manual_admin_unlock",
    )
    return {"message": "Cuenta desbloqueada correctamente", "user": _user_dict(user)}


# ── Me ────────────────────────────────────────────────────────────────────────

@router.get("/me", summary="Perfil del usuario autenticado")
async def me(current_user: User = Depends(get_current_user)):
    return _user_dict(current_user)
