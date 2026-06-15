"""
Premos Forensic Neutralization (PFN) — P19.3

Every neutralization action that successfully executes through _execute_immediately()
receives a ForensicEntry in the forensic_ledger table.

The entry contains:
  - canonical_data: deterministic JSON snapshot of the action at execution time
  - hash_sha3_512: SHA3-512 hex digest of that snapshot
  - signature_ed25519: Ed25519 signature of the hash, signed with the approving
    analyst's private key (decrypted from the keystore using the app SECRET_KEY)

This gives PremosCorp-native cryptographic proof for audit: the action was real,
approved by a specific analyst, executed at a specific time, and has not been altered.

Verification is self-contained: recompute SHA3-512 from canonical_data and verify
the signature against the analyst's stored public key — no external service needed.
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.signing import decrypt_analyst_private_key
from app.models.forensic_entry import ForensicEntry
from app.models.neutralization import NeutralizationAction
from app.models.user import User

log = get_logger("asc.pfn")


# ── Canonical data ─────────────────────────────────────────────────────────────

def _build_canonical(action: NeutralizationAction, approved_by_email: str) -> dict:
    """
    Build the deterministic dict that will be hashed.

    Only stable, non-mutable fields are included so the hash remains valid
    even if action.result is later updated for metadata purposes.
    """
    return {
        "action_id":    action.id,
        "action_type":  action.action_type,
        "target":       action.target,
        "target_type":  action.target_type,
        "severity":     action.severity,
        "approved_by":  approved_by_email,
        "approved_at":  (
            action.approved_at.isoformat()
            if action.approved_at
            else datetime.now(timezone.utc).isoformat()
        ),
        "executed_at":  (
            action.executed_at.isoformat()
            if action.executed_at
            else datetime.now(timezone.utc).isoformat()
        ),
        "params":       action.params,
        "pfn_version":  "1",
    }


def _compute_hash(canonical: dict) -> str:
    """SHA3-512 hex digest of the deterministic JSON serialisation."""
    payload = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha3_512(payload).hexdigest()


# ── Sign / verify ──────────────────────────────────────────────────────────────

def _sign_hash(hash_hex: str, private_key_b64: str) -> str:
    """Ed25519 sign the hash (as UTF-8 bytes). Returns base64-encoded signature."""
    priv_bytes = base64.b64decode(private_key_b64)
    key = Ed25519PrivateKey.from_private_bytes(priv_bytes)
    sig = key.sign(hash_hex.encode())
    return base64.b64encode(sig).decode()


def _verify_signature(hash_hex: str, signature_b64: str, public_key_b64: str) -> bool:
    """Verify an Ed25519 signature against the analyst's public key. Never raises."""
    try:
        pub_bytes = base64.b64decode(public_key_b64)
        pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        sig = base64.b64decode(signature_b64)
        pub_key.verify(sig, hash_hex.encode())
        return True
    except (InvalidSignature, Exception):
        return False


# ── Core API ───────────────────────────────────────────────────────────────────

async def create_forensic_entry(
    db: AsyncSession,
    action: NeutralizationAction,
    approver: User,
) -> ForensicEntry | None:
    """
    Generate and persist a forensic ledger entry for a completed action.

    Returns the saved ForensicEntry, or None if the approver has no signing key
    (e.g. automated actions with no real approver). Errors are logged and swallowed
    so a PFN failure never aborts the neutralization result.
    """
    if not approver.signing_private_key_enc or not approver.signing_public_key:
        log.warning(
            "pfn_no_signing_key",
            action_id=action.id,
            approver=approver.email,
        )
        return None

    try:
        settings = get_settings()
        priv_key_b64 = decrypt_analyst_private_key(
            approver.signing_private_key_enc, settings.SECRET_KEY
        )

        canonical = _build_canonical(action, approver.email)
        hash_hex = _compute_hash(canonical)
        signature = _sign_hash(hash_hex, priv_key_b64)

        entry = ForensicEntry(
            action_id=action.id,
            action_type=action.action_type,
            target=action.target,
            canonical_data=canonical,
            hash_sha3_512=hash_hex,
            signature_ed25519=signature,
            signed_by_email=approver.email,
            signed_by_user_id=str(approver.id),
            signed_at=datetime.now(timezone.utc),
        )
        db.add(entry)
        await db.commit()
        await db.refresh(entry)

        log.info(
            "pfn_entry_created",
            entry_id=entry.id,
            action_id=action.id,
            signed_by=approver.email,
        )
        return entry

    except Exception as exc:
        log.error("pfn_create_error", action_id=action.id, error=str(exc))
        await db.rollback()
        return None


async def verify_forensic_entry(
    db: AsyncSession,
    entry: ForensicEntry,
    approver_public_key_b64: str,
) -> bool:
    """
    Cryptographically verify a ledger entry.

    Recomputes SHA3-512 from canonical_data and checks the Ed25519 signature.
    Updates entry.verified and entry.last_verified_at on success.
    Returns True only if both the hash and the signature are valid.
    """
    # Recompute hash from stored canonical data
    recomputed = _compute_hash(entry.canonical_data)
    if recomputed != entry.hash_sha3_512:
        log.warning(
            "pfn_hash_mismatch",
            entry_id=entry.id,
            stored=entry.hash_sha3_512[:16],
            recomputed=recomputed[:16],
        )
        return False

    valid_sig = _verify_signature(
        entry.hash_sha3_512, entry.signature_ed25519, approver_public_key_b64
    )

    if valid_sig:
        entry.verified = True
        entry.last_verified_at = datetime.now(timezone.utc)
        await db.commit()

    log.info(
        "pfn_verify_result",
        entry_id=entry.id,
        valid=valid_sig,
    )
    return valid_sig


async def get_entry_by_action(
    db: AsyncSession, action_id: str
) -> ForensicEntry | None:
    result = await db.execute(
        select(ForensicEntry).where(ForensicEntry.action_id == action_id)
    )
    return result.scalar_one_or_none()


async def get_entry_by_id(
    db: AsyncSession, entry_id: str
) -> ForensicEntry | None:
    result = await db.execute(
        select(ForensicEntry).where(ForensicEntry.id == entry_id)
    )
    return result.scalar_one_or_none()


async def list_entries(
    db: AsyncSession, limit: int = 100, offset: int = 0
) -> list[ForensicEntry]:
    result = await db.execute(
        select(ForensicEntry)
        .order_by(ForensicEntry.signed_at.desc())
        .limit(limit)
        .offset(offset)
    )
    return list(result.scalars().all())
