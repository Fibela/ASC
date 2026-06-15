"""
P58 — Fernet encryption helpers for adapter credentials.

Key derivation: SHA-256(SECRET_KEY) → 32 bytes → base64url → Fernet key.
This gives AES-128-CBC + HMAC-SHA256 with a key derived from the app secret.

FASE 6 migration path: replace encrypt/decrypt with Vault read/write calls;
the API surface (str → str) stays the same.
"""

import base64
import hashlib
from cryptography.fernet import Fernet, InvalidToken


def _derive_fernet_key(secret_key: str) -> bytes:
    raw = hashlib.sha256(secret_key.encode()).digest()  # 32 bytes
    return base64.urlsafe_b64encode(raw)                # Fernet expects URL-safe b64


def encrypt_credential(credential: str, secret_key: str) -> str:
    """Encrypt a credential string. Returns a Fernet token (URL-safe base64)."""
    f = Fernet(_derive_fernet_key(secret_key))
    return f.encrypt(credential.encode()).decode()


def decrypt_credential(token: str, secret_key: str) -> str:
    """Decrypt a Fernet token back to the original credential string."""
    f = Fernet(_derive_fernet_key(secret_key))
    try:
        return f.decrypt(token.encode()).decode()
    except InvalidToken as exc:
        raise ValueError("Invalid or tampered credential token") from exc


def credential_hint(credential: str) -> str:
    """Return first 4 chars + **** for safe display (never the full value)."""
    if not credential:
        return ""
    prefix = credential[:4]
    return f"{prefix}****"
