"""
PIDS — Premos Identity-Driven SOAR Service — P26

Signs every IAM enforcement action with Ed25519 + SHA3-512 to produce a
tamper-evident forensic token at creation time.

Signing key precedence:
  1. PIDS_SIGNING_PRIVATE_KEY env var (dedicated PIDS key)
  2. SPECTER_SIGNING_PRIVATE_KEY env var (shared system key)
  3. Absent key → signature stored as None; SHA3-512 hash still valid

Verification uses the corresponding public key env var
(PIDS_SIGNING_PUBLIC_KEY or SPECTER_SIGNING_PUBLIC_KEY).

All operations are async-safe: no shared mutable state.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import and_, asc, desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.models.identity_action import IdentityAction

log = get_logger("asc.pids")

_VALID_ACTION_TYPES = frozenset({
    "disable_account",
    "enable_account",
    "force_password_reset",
    "quarantine_account",
    "enrich_user",
})


# ── Cryptographic primitives ───────────────────────────────────────────────────

def _build_canonical(action: IdentityAction) -> dict[str, Any]:
    """Deterministic canonical dict bound to every immutable field of an action."""
    return {
        "pids_version": "1",
        "action_id": action.id,
        "action_type": action.action_type,
        "username": action.username,
        "domain": action.domain,
        "reason": action.reason,
        "hunt_id": action.hunt_id,
        "finding_id": action.finding_id,
        "trigger_id": action.trigger_id,
        "playbook_run_id": action.playbook_run_id,
        "success": action.success,
        "result_detail": action.result_detail,
        "initiated_by": action.initiated_by,
        "executed_at": action.executed_at.isoformat() if action.executed_at else None,
    }


def _compute_hash(canonical: dict[str, Any]) -> str:
    """SHA3-512 of the deterministic JSON serialization."""
    payload = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha3_512(payload).hexdigest()


def _sign_hash(hash_hex: str) -> str | None:
    """
    Ed25519 sign hash_hex using the configured private key.
    Returns base64-encoded signature, or None if no key is configured.
    """
    key_b64 = os.getenv("PIDS_SIGNING_PRIVATE_KEY") or os.getenv("SPECTER_SIGNING_PRIVATE_KEY")
    if not key_b64:
        return None
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        raw = base64.b64decode(key_b64)
        private_key = Ed25519PrivateKey.from_private_bytes(raw)
        sig = private_key.sign(hash_hex.encode())
        return base64.b64encode(sig).decode()
    except Exception as exc:
        log.warning("pids_sign_failed", error=str(exc))
        return None


def _verify_signature(hash_hex: str, signature_b64: str) -> bool | None:
    """
    Verify Ed25519 signature against the configured public key.
    Returns True/False when key is configured, None otherwise.
    """
    pub_b64 = os.getenv("PIDS_SIGNING_PUBLIC_KEY") or os.getenv("SPECTER_SIGNING_PUBLIC_KEY")
    if not pub_b64:
        return None
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
        pub_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64))
        pub_key.verify(base64.b64decode(signature_b64), hash_hex.encode())
        return True
    except Exception:
        return False


# ── Core service ───────────────────────────────────────────────────────────────

async def create_identity_action(
    db: AsyncSession,
    *,
    action_type: str,
    username: str,
    domain: str = "corp.local",
    reason: str,
    hunt_id: str | None = None,
    finding_id: str | None = None,
    trigger_id: str | None = None,
    playbook_run_id: str | None = None,
    success: bool = False,
    result_detail: str | None = None,
    initiated_by: str = "soar_auto",
) -> IdentityAction:
    """
    Create and forensically sign an IdentityAction record.

    The SHA3-512 hash is computed over all immutable action fields before
    the record is persisted, so the stored hash is canonical at write time.
    Ed25519 signature is added if a signing key is available.
    """
    if action_type not in _VALID_ACTION_TYPES:
        raise ValueError(
            f"Invalid action_type '{action_type}'. Valid: {sorted(_VALID_ACTION_TYPES)}"
        )

    now = datetime.now(timezone.utc)
    action = IdentityAction(
        id=str(uuid.uuid4()),
        action_type=action_type,
        username=username,
        domain=domain,
        reason=reason,
        hunt_id=hunt_id,
        finding_id=finding_id,
        trigger_id=trigger_id,
        playbook_run_id=playbook_run_id,
        success=success,
        result_detail=result_detail,
        initiated_by=initiated_by,
        signed_by_email=initiated_by,
        executed_at=now,
    )

    canonical = _build_canonical(action)
    hash_hex = _compute_hash(canonical)
    signature = _sign_hash(hash_hex)

    action.hash_sha3_512 = hash_hex
    action.signature_ed25519 = signature
    action.signed_at = now

    db.add(action)
    await db.commit()
    await db.refresh(action)

    log.info(
        "pids_action_created",
        action_id=action.id,
        action_type=action_type,
        username=username,
        domain=domain,
        success=success,
        hash_prefix=hash_hex[:16],
        signed=signature is not None,
    )

    return action


async def verify_identity_action(db: AsyncSession, action_id: str) -> dict:
    """
    Re-compute the canonical hash and verify it matches the stored value.
    Also verifies the Ed25519 signature if a public key is configured.

    A hash_match=True with signature_ok=None means the hash is intact but
    no public key is available for signature verification.
    """
    result = await db.execute(
        select(IdentityAction).where(IdentityAction.id == action_id)
    )
    action = result.scalar_one_or_none()
    if action is None:
        return {"verified": False, "error": "IdentityAction not found", "action_id": action_id}

    canonical = _build_canonical(action)
    computed_hash = _compute_hash(canonical)
    hash_match = computed_hash == action.hash_sha3_512

    signature_ok: bool | None = None
    if action.signature_ed25519 and action.hash_sha3_512:
        signature_ok = _verify_signature(action.hash_sha3_512, action.signature_ed25519)

    return {
        "action_id": action_id,
        "verified": hash_match,
        "hash_match": hash_match,
        "signature_ok": signature_ok,
        "stored_hash": action.hash_sha3_512,
        "computed_hash": computed_hash,
        "signed_at": action.signed_at.isoformat() if action.signed_at else None,
        "signed_by": action.signed_by_email,
        "action_type": action.action_type,
        "username": action.username,
    }


async def get_identity_action(db: AsyncSession, action_id: str) -> dict | None:
    result = await db.execute(
        select(IdentityAction).where(IdentityAction.id == action_id)
    )
    action = result.scalar_one_or_none()
    return _action_to_dict(action) if action else None


async def list_identity_actions(
    db: AsyncSession,
    *,
    username: str | None = None,
    action_type: str | None = None,
    hunt_id: str | None = None,
    success: bool | None = None,
    limit: int = 100,
) -> list[dict]:
    filters: list = []
    if username:
        filters.append(IdentityAction.username == username)
    if action_type:
        filters.append(IdentityAction.action_type == action_type)
    if hunt_id:
        filters.append(IdentityAction.hunt_id == hunt_id)
    if success is not None:
        filters.append(IdentityAction.success.is_(success))

    stmt = select(IdentityAction).order_by(desc(IdentityAction.executed_at)).limit(limit)
    if filters:
        stmt = stmt.where(and_(*filters))

    result = await db.execute(stmt)
    return [_action_to_dict(a) for a in result.scalars().all()]


async def get_identity_timeline(db: AsyncSession, hunt_id: str) -> list[dict]:
    """Chronological identity actions for a hunt — forward order for forensic timeline."""
    stmt = (
        select(IdentityAction)
        .where(IdentityAction.hunt_id == hunt_id)
        .order_by(asc(IdentityAction.executed_at))
    )
    result = await db.execute(stmt)
    return [_action_to_dict(a) for a in result.scalars().all()]


async def get_pids_summary(db: AsyncSession, hunt_id: str | None = None) -> dict:
    """
    Aggregated PIDS statistics.

    If hunt_id is provided, statistics are scoped to that hunt.
    Returns total/successful/failed action counts, success rate, and 24h activity.
    """
    cutoff_24h = datetime.now(timezone.utc) - timedelta(hours=24)
    base_filter: list = []
    if hunt_id:
        base_filter.append(IdentityAction.hunt_id == hunt_id)

    total_stmt = select(func.count()).select_from(IdentityAction)
    if base_filter:
        total_stmt = total_stmt.where(and_(*base_filter))
    total = (await db.execute(total_stmt)).scalar() or 0

    success_stmt = select(func.count()).select_from(IdentityAction).where(
        and_(*base_filter, IdentityAction.success.is_(True))
    )
    successful = (await db.execute(success_stmt)).scalar() or 0

    recent_stmt = select(func.count()).select_from(IdentityAction).where(
        and_(*base_filter, IdentityAction.executed_at >= cutoff_24h)
    )
    recent_24h = (await db.execute(recent_stmt)).scalar() or 0

    return {
        "hunt_id": hunt_id,
        "total_actions": total,
        "successful_actions": successful,
        "failed_actions": total - successful,
        "success_rate_pct": round(successful / total * 100, 1) if total > 0 else 0.0,
        "actions_24h": recent_24h,
    }


# ── Serialization ──────────────────────────────────────────────────────────────

def _action_to_dict(action: IdentityAction) -> dict:
    return {
        "id": action.id,
        "action_type": action.action_type,
        "username": action.username,
        "domain": action.domain,
        "reason": action.reason,
        "hunt_id": action.hunt_id,
        "finding_id": action.finding_id,
        "trigger_id": action.trigger_id,
        "playbook_run_id": action.playbook_run_id,
        "success": action.success,
        "result_detail": action.result_detail,
        "hash_sha3_512": action.hash_sha3_512,
        "signature_ed25519": action.signature_ed25519,
        "signed_at": action.signed_at.isoformat() if action.signed_at else None,
        "signed_by_email": action.signed_by_email,
        "initiated_by": action.initiated_by,
        "executed_at": action.executed_at.isoformat() if action.executed_at else None,
    }
