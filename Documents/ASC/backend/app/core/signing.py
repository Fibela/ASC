"""
ASC Signing Utilities — Ed25519 for SPECTER + per-analyst approval signing.

SPECTER commands
----------------
Backend signs commands  → SPECTER agent verifies before executing.
SPECTER agent signs telemetry → backend verifies before storing.

Per-analyst signing (P16.3 deuda técnica)
------------------------------------------
Each analyst has an Ed25519 keypair generated at account creation.
The public key is stored in plaintext; the private key is stored encrypted
with a Fernet key derived from the app SECRET_KEY.

When an analyst approves a HitL action, the server signs:
  "APPROVAL:{action_id}:{approved_by}:{approved_at}"
with the analyst's private key and stores the signature in approvals_log.

This provides server-side non-repudiation: even an admin cannot forge an
approval signature without access to the analyst's encrypted private key
AND the app SECRET_KEY.

Limitation: keys are server-stored, not client-stored.  True hardware-backed
non-repudiation (YubiKey / WebAuthn) is a P17+ enhancement.

No external service dependency: pure cryptography library (PyJWT + cryptography package).
"""

import base64
import json
import time
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

# Static salt — namespaces the Fernet key derivation.
# Not a password-hash salt: the secret is SECRET_KEY, not user input.
_KEYSTORE_SALT = b"asc-analyst-keystore-v1"


def _derive_fernet_key(secret: str) -> bytes:
    """
    Derive a Fernet-compatible 32-byte key from the app SECRET_KEY.
    Deterministic given the same SECRET_KEY — allows decryption after restarts.
    PBKDF2: 100,000 iterations of SHA-256.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_KEYSTORE_SALT,
        iterations=100_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(secret.encode()))

# ── Key generation ─────────────────────────────────────────────────────────────

def generate_keypair() -> tuple[str, str]:
    """
    Generate an Ed25519 keypair for SPECTER backend command signing.

    Returns (private_key_b64, public_key_b64) — raw bytes, base64-encoded.
    Store private_key_b64 in SPECTER_SIGNING_PRIVATE_KEY env var.
    Distribute public_key_b64 to agents so they can verify commands.
    """
    key = Ed25519PrivateKey.generate()
    priv_bytes = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub_bytes = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(priv_bytes).decode(), base64.b64encode(pub_bytes).decode()


# ── Signing ────────────────────────────────────────────────────────────────────

def _canonical(payload: dict[str, Any]) -> bytes:
    """Deterministic JSON serialisation for signing. Sorted keys, no spaces."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def sign_command(private_key_b64: str, payload: dict[str, Any]) -> str:
    """
    Sign a command payload with the backend Ed25519 private key.
    Returns base64-encoded signature.

    The payload MUST include a 'ts' field (Unix timestamp) to prevent replays.
    """
    priv_bytes = base64.b64decode(private_key_b64)
    key = Ed25519PrivateKey.from_private_bytes(priv_bytes)
    sig = key.sign(_canonical(payload))
    return base64.b64encode(sig).decode()


# ── Verification ───────────────────────────────────────────────────────────────

def verify_agent_event(public_key_b64: str, payload: dict[str, Any], signature_b64: str) -> bool:
    """
    Verify a telemetry event signed by a SPECTER agent.
    Returns True only if the signature is cryptographically valid.
    Never raises — returns False on any failure.
    """
    try:
        pub_bytes = base64.b64decode(public_key_b64)
        pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        sig = base64.b64decode(signature_b64)
        pub_key.verify(sig, _canonical(payload))
        return True
    except (InvalidSignature, Exception):
        return False


def verify_command(public_key_b64: str, payload: dict[str, Any], signature_b64: str) -> bool:
    """
    Verify a command signed by the ASC backend (used by the SPECTER agent).
    Same mechanics as verify_agent_event — symmetric design.
    """
    return verify_agent_event(public_key_b64, payload, signature_b64)


# ── Replay protection ──────────────────────────────────────────────────────────

REPLAY_WINDOW_SECONDS = 120


def is_fresh(ts: float, window: int = REPLAY_WINDOW_SECONDS) -> bool:
    """
    Reject payloads older than `window` seconds.
    Prevents replay attacks where a captured signed payload is re-submitted.
    """
    return abs(time.time() - ts) <= window


# ── Per-analyst keystore (P16.3) ───────────────────────────────────────────────

def generate_analyst_keypair() -> tuple[str, str]:
    """
    Generate an Ed25519 keypair for a new analyst account.
    Returns (private_key_b64, public_key_b64) — raw bytes, base64-encoded.
    The private key must be encrypted with encrypt_analyst_private_key() before storage.
    """
    key = Ed25519PrivateKey.generate()
    priv_bytes = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub_bytes = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(priv_bytes).decode(), base64.b64encode(pub_bytes).decode()


def encrypt_analyst_private_key(private_key_b64: str, app_secret: str) -> str:
    """
    Encrypt an analyst's Ed25519 private key using Fernet (AES-128-CBC + HMAC-SHA256).
    The encryption key is derived from the app SECRET_KEY via PBKDF2.
    Returns base64url-encoded ciphertext safe for database storage.
    """
    f = Fernet(_derive_fernet_key(app_secret))
    return f.encrypt(private_key_b64.encode()).decode()


def decrypt_analyst_private_key(encrypted_b64: str, app_secret: str) -> str:
    """
    Decrypt an analyst's stored private key.
    Raises ValueError on decryption failure (wrong key or corrupted data).
    """
    try:
        f = Fernet(_derive_fernet_key(app_secret))
        return f.decrypt(encrypted_b64.encode()).decode()
    except (InvalidToken, Exception) as exc:
        raise ValueError(f"Failed to decrypt analyst private key: {exc}") from exc


def sign_approval(
    private_key_b64: str,
    action_id: str,
    approved_by: str,
    approved_at: str,
) -> str:
    """
    Sign an approval event with the analyst's Ed25519 private key.

    Canonical message: "APPROVAL:{action_id}:{approved_by}:{approved_at}"
    Returns base64-encoded signature.

    The approved_at string must be the exact ISO timestamp stored in approvals_log
    so the signature can be re-verified later without ambiguity.
    """
    priv_bytes = base64.b64decode(private_key_b64)
    key = Ed25519PrivateKey.from_private_bytes(priv_bytes)
    message = f"APPROVAL:{action_id}:{approved_by}:{approved_at}".encode()
    return base64.b64encode(key.sign(message)).decode()


def verify_approval_signature(
    public_key_b64: str,
    action_id: str,
    approved_by: str,
    approved_at: str,
    signature_b64: str,
) -> bool:
    """
    Verify an approval signature against the analyst's public key.
    Returns True only if the signature is cryptographically valid.
    Never raises — returns False on any failure.
    """
    try:
        pub_bytes = base64.b64decode(public_key_b64)
        pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        message = f"APPROVAL:{action_id}:{approved_by}:{approved_at}".encode()
        pub_key.verify(base64.b64decode(signature_b64), message)
        return True
    except (InvalidSignature, Exception):
        return False
