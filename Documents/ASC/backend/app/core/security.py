from datetime import datetime, timedelta, timezone
from typing import Any, Literal
import uuid
import bcrypt
import jwt
from jwt.exceptions import PyJWTError
from fastapi import HTTPException, status
from app.core.config import get_settings

settings = get_settings()

ALGORITHM = "HS256"
REFRESH_EXPIRE_DAYS = 7

# Minimum password requirements (enforced in change-password; not at register
# for bootstrap compatibility — admins must use strong passwords by policy).
PASSWORD_MIN_LENGTH = 12
PASSWORD_REQUIRE_UPPERCASE = True
PASSWORD_REQUIRE_DIGIT = True
PASSWORD_REQUIRE_SPECIAL = True
_SPECIAL_CHARS = set("!@#$%^&*()-_=+[]{}|;:',.<>?/`~")


def validate_password_strength(password: str) -> list[str]:
    """
    Return a list of violated rules.  Empty list → password is acceptable.
    Rules: min length, at least one uppercase, one digit, one special character.
    """
    errors: list[str] = []
    if len(password) < PASSWORD_MIN_LENGTH:
        errors.append(f"Mínimo {PASSWORD_MIN_LENGTH} caracteres")
    if PASSWORD_REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
        errors.append("Debe contener al menos una letra mayúscula")
    if PASSWORD_REQUIRE_DIGIT and not any(c.isdigit() for c in password):
        errors.append("Debe contener al menos un número")
    if PASSWORD_REQUIRE_SPECIAL and not any(c in _SPECIAL_CHARS for c in password):
        errors.append("Debe contener al menos un carácter especial (!@#$%^&*...)")
    return errors


def create_access_token(
    subject: str | Any,
    expires_delta: timedelta | None = None,
    *,
    tenant_id: str | None = None,
) -> str:
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    jti = str(uuid.uuid4())
    payload: dict[str, Any] = {
        "exp": expire,
        "sub": str(subject),
        "type": "access",
        "jti": jti,
    }
    if tenant_id is not None:
        payload["tenant_id"] = tenant_id
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(subject: str | Any) -> str:
    expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_EXPIRE_DAYS)
    jti = str(uuid.uuid4())
    return jwt.encode(
        {"exp": expire, "sub": str(subject), "type": "refresh", "jti": jti},
        settings.SECRET_KEY,
        algorithm=ALGORITHM,
    )


def verify_token(token: str, token_type: Literal["access", "refresh"] = "access") -> str:  # nosec B107
    """
    Decode token signature and claims, returning the subject (user_id).
    Does NOT check the JWT blacklist — callers must check separately.
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
        sub: str = payload.get("sub")
        typ: str = payload.get("type", "access")
        if sub is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido")
        if typ != token_type:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Se esperaba token de tipo '{token_type}'",
            )
        return sub
    except PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expirado o inválido"
        )


def decode_token_payload(token: str) -> dict:
    """
    Return the raw decoded payload without raising on failure.
    Used to extract jti for blacklist checks before the main verify_token call.
    """
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
    except PyJWTError:
        return {}


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
