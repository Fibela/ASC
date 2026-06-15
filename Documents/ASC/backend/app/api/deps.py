import hashlib
import hmac as _hmac
from datetime import datetime, timezone
from typing import Callable

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.config import get_settings
from app.db.session import get_db
from app.models.user import User
from app.models.api_key import APIKey
from app.core.security import verify_token, decode_token_payload
from app.core.jwt_blacklist import jwt_blacklist

bearer_scheme = HTTPBearer(auto_error=True)
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
_settings = get_settings()


def _hmac_key_hash(raw_key: str) -> str:
    """
    HMAC-SHA256 keyed digest — must match _hash_key() in api_keys.py.
    Kept here (instead of importing from endpoints) to avoid circular imports.
    Using the app SECRET_KEY as the HMAC secret binds the stored hash to this
    specific ASC instance (Toque Premos — autenticidad forense).
    """
    mac = _hmac.new(
        _settings.SECRET_KEY.encode(),
        raw_key.encode(),
        hashlib.sha256,
    )
    return mac.hexdigest()


async def _resolve_user(
    token: str,
    db: AsyncSession,
    *,
    check_force_reset: bool = True,
) -> User:
    """
    Shared auth resolution used by all deps variants.

    Steps:
      1. Verify JWT signature and claims.
      2. Check JTI against the blacklist (L1 then L2).
      3. Load user from DB, assert is_active.
      4. Assert account is not time-locked.
      5. If check_force_reset: reject when force_password_reset is True.
    """
    user_id = verify_token(token, token_type="access")  # nosec B106

    payload = decode_token_payload(token)
    jti = payload.get("jti")
    if jti and await jwt_blacklist.is_revoked(jti, db):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token revocado. Inicia sesión nuevamente.",
        )

    result = await db.execute(
        select(User).where(User.id == user_id, User.is_active == True)
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario no encontrado o inactivo",
        )

    if user.is_locked:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Cuenta bloqueada hasta {user.locked_until.isoformat()}",
        )

    if check_force_reset and user.force_password_reset:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="password_reset_required",
        )

    return user


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    return await _resolve_user(credentials.credentials, db, check_force_reset=True)


async def get_current_user_allow_reset(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Like get_current_user but bypasses the force_password_reset gate.
    Used exclusively by POST /auth/change-password so the user can satisfy
    the reset requirement even though all other endpoints are blocked.
    """
    return await _resolve_user(credentials.credentials, db, check_force_reset=False)


async def get_analyst_or_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role not in ("admin", "analyst"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Se requiere rol analyst o admin",
        )
    return current_user


async def get_current_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Se requiere rol admin",
        )
    return current_user


async def get_user_from_api_key(
    request: Request,
    raw_key: str | None = Security(_api_key_header),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Resolve the owner User from an X-API-Key header (Toque Premos auth path).

    Validates: key exists (HMAC-SHA256 match), is_active, not expired,
    then touches last_used_at and stores the key's scopes in request.state
    for downstream scope enforcement via require_api_key_scope().

    Raises 401 on any failure — callers cannot distinguish missing vs. invalid.
    """
    if not raw_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="X-API-Key header requerido",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # HMAC-SHA256 (Toque Premos) — must match _hash_key() in api_keys.py
    key_hash = _hmac_key_hash(raw_key)
    result = await db.execute(select(APIKey).where(APIKey.key_hash == key_hash))
    api_key = result.scalar_one_or_none()

    if not api_key or not api_key.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key inválida o revocada",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    if api_key.expires_at and datetime.now(timezone.utc) > api_key.expires_at:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key expirada",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # Load the owner user
    user_result = await db.execute(
        select(User).where(User.id == api_key.user_id, User.is_active == True)
    )
    user = user_result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario propietario de la API key inactivo o eliminado",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # Scopes adaptativos — store on request.state for require_api_key_scope()
    request.state.api_key_scopes = list(api_key.scopes or [])

    # Touch last_used_at (fire-and-forget style — non-critical)
    api_key.last_used_at = datetime.now(timezone.utc)
    await db.commit()

    return user


def require_api_key_scope(scope: str) -> Callable:
    """
    Scopes adaptativos (Toque Premos) — dep factory for scope-gated endpoints.

    Usage example:
        @router.get("/secure-data")
        async def secure_data(
            user: User = Depends(require_api_key_scope("write")),
        ):
            ...

    When the caller authenticated via X-API-Key:
      - Checks request.state.api_key_scopes contains `scope`.
      - Raises 403 if the scope is absent.
    When the caller authenticated via JWT (no api_key_scopes on request.state):
      - Passes through — JWT-authenticated users have full role-based access.
    """
    async def _check(
        request: Request,
        user: User = Depends(get_user_from_api_key),
    ) -> User:
        scopes: list[str] = getattr(request.state, "api_key_scopes", [])
        if scope not in scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Scope '{scope}' requerido para esta operación. Llaves disponibles: {scopes}",
            )
        return user

    return _check
