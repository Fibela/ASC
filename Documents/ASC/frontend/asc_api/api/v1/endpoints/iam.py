"""
IAM Admin Endpoints — P16.3 PremosCorp Identity and Access Management.

All endpoints require admin role.  They expose the iam_service operations
over REST so SOC administrators can manage accounts without direct DB access.

Endpoints
---------
GET  /iam/users/{email}/status   — full IAM status for a user
POST /iam/users/{email}/lock     — manually lock (optional minutes param)
POST /iam/users/{email}/unlock   — remove lock + reset attempt counter
POST /iam/users/{email}/disable  — deactivate account
POST /iam/users/{email}/enable   — reactivate account
POST /iam/users/{email}/force-reset — require password change on next access
DELETE /iam/tokens/purge         — clean up expired revoked_tokens rows
"""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.api.deps import get_current_admin
from asc_api.core.audit import log_iam_event
from asc_api.core.config import get_settings
from asc_api.core.jwt_blacklist import jwt_blacklist
from asc_api.core.signing import (
    encrypt_analyst_private_key,
    generate_analyst_keypair,
    verify_approval_signature,
)
from asc_api.db.session import get_db
from asc_api.models.neutralization import NeutralizationAction
from asc_api.models.user import User
from asc_api.services.iam_service import (
    disable_account,
    enable_account,
    get_user_iam_status,
    lock_account,
    set_force_password_reset,
    unlock_account,
)

router = APIRouter(prefix="/iam", tags=["IAM"])


class LockRequest(BaseModel):
    minutes: int = 15


# ── User IAM status ───────────────────────────────────────────────────────────


@router.get("/users/{email}/status", summary="IAM: estado completo de cuenta")
async def user_iam_status(
    email: str,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin),
):
    data = await get_user_iam_status(email, db, tenant_id=admin.tenant_id)
    if not data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado")
    return data


# ── Lock / unlock ─────────────────────────────────────────────────────────────


@router.post("/users/{email}/lock", summary="IAM: bloquear cuenta")
async def lock_user(
    email: str,
    payload: LockRequest = LockRequest(),
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin),
):
    success, message = await lock_account(
        email, db, performed_by=admin.email, minutes=payload.minutes, tenant_id=admin.tenant_id
    )
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=message)
    return {"message": message}


@router.post("/users/{email}/unlock", summary="IAM: desbloquear cuenta")
async def unlock_user(
    email: str,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin),
):
    success, message = await unlock_account(email, db, performed_by=admin.email, tenant_id=admin.tenant_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=message)
    return {"message": message}


# ── Disable / enable ──────────────────────────────────────────────────────────


@router.post("/users/{email}/disable", summary="IAM: desactivar cuenta")
async def disable_user(
    email: str,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin),
):
    # Prevent self-deactivation
    if email == admin.email:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="No puedes desactivar tu propia cuenta",
        )
    success, message = await disable_account(email, db, performed_by=admin.email, tenant_id=admin.tenant_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=message)
    return {"message": message}


@router.post("/users/{email}/enable", summary="IAM: reactivar cuenta")
async def enable_user(
    email: str,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin),
):
    success, message = await enable_account(email, db, performed_by=admin.email, tenant_id=admin.tenant_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=message)
    return {"message": message}


# ── Force password reset ──────────────────────────────────────────────────────


@router.post("/users/{email}/force-reset", summary="IAM: forzar reset de contraseña")
async def force_reset_user(
    email: str,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin),
):
    success, message = await set_force_password_reset(email, db, performed_by=admin.email, tenant_id=admin.tenant_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=message)
    return {"message": message}


# ── Token blacklist maintenance ───────────────────────────────────────────────


@router.delete("/tokens/purge", summary="IAM: purgar tokens revocados expirados")
async def purge_expired_tokens(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_admin),
):
    """
    Remove expired entries from the revoked_tokens table and evict them from
    the in-process L1 cache.  Safe to call any time; typically run via Celery
    periodic task or admin dashboard maintenance action.
    """
    purged = await jwt_blacklist.purge_expired(db)
    return {
        "purged": purged,
        "l1_cache_size": jwt_blacklist.local_size,
        "message": f"{purged} token(s) expirado(s) eliminado(s)",
    }


# ── Ed25519 key rotation ──────────────────────────────────────────────────────


@router.post("/users/{email}/rotate-keys", summary="IAM: rotar claves Ed25519 del analista")
async def rotate_analyst_keys(
    email: str,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin),
):
    """
    Generate a new Ed25519 keypair for the user and replace the stored keys.

    Existing approval signatures (stored in approvals_log with the OLD public key)
    remain verifiable because each approvals_log entry embeds the public key used
    at the time of signing.  Only future approvals will use the new key.

    Use this after a suspected key compromise or as part of a periodic rotation policy.
    """
    settings = get_settings()
    result = await db.execute(select(User).where(User.email == email, User.tenant_id == admin.tenant_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado")

    priv_b64, pub_b64 = generate_analyst_keypair()
    user.signing_public_key = pub_b64
    user.signing_private_key_enc = encrypt_analyst_private_key(priv_b64, settings.SECRET_KEY)
    await db.commit()

    log_iam_event(
        "signing_keys_rotated",
        performed_by=admin.email,
        target_user=email,
        detail="Ed25519 keypair replaced — old signatures still valid via embedded public_key",
    )
    return {
        "message": f"Claves Ed25519 rotadas para {email}",
        "public_key": pub_b64,
    }


# ── Approval signature verification ──────────────────────────────────────────


@router.get(
    "/actions/{action_id}/verify-signatures",
    summary="IAM: verificar firmas criptográficas de aprobaciones",
)
async def verify_action_signatures(
    action_id: str,
    db: AsyncSession = Depends(get_db),
    current_admin: User = Depends(get_current_admin),
):
    """
    Cryptographically verify all approval signatures in an action's approvals_log.

    Each log entry that contains a 'signature' and 'public_key' is verified
    independently.  Entries without a signature (created before P16.3 or on
    accounts without keys) are reported as 'unsigned'.

    Returns a per-entry verification report plus an overall verdict.
    """
    result = await db.execute(
        select(NeutralizationAction).where(
            NeutralizationAction.id == action_id,
            NeutralizationAction.tenant_id == current_admin.tenant_id,
        )
    )
    action = result.scalar_one_or_none()
    if not action:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Acción no encontrada")

    log = action.approvals_log or []
    entries = []
    all_signed = True
    all_valid = True

    for entry in log:
        sig = entry.get("signature")
        pub = entry.get("public_key")
        approved_by = entry.get("approved_by", "")
        approved_at = entry.get("approved_at", "")

        if not sig or not pub:
            entries.append(
                {
                    "approved_by": approved_by,
                    "approved_at": approved_at,
                    "status": "unsigned",
                    "valid": None,
                }
            )
            all_signed = False
            continue

        valid = verify_approval_signature(pub, action_id, approved_by, approved_at, sig)
        if not valid:
            all_valid = False
        entries.append(
            {
                "approved_by": approved_by,
                "approved_at": approved_at,
                "status": "valid" if valid else "invalid",
                "valid": valid,
                "public_key_prefix": pub[:16] + "...",
            }
        )

    verdict = (
        "all_valid"
        if (all_signed and all_valid)
        else ("partial_unsigned" if (not all_signed and all_valid) else "invalid")
    )

    return {
        "action_id": action_id,
        "action_type": action.action_type,
        "approvals_count": len(log),
        "verdict": verdict,
        "entries": entries,
    }
