"""
Premos Forensic Neutralization (PFN) API — P19.3 / P21-F2 rate limiting added.

Endpoints
---------
GET  /forensic/actions/{action_id}         — forensic proof for a neutralization action
POST /forensic/actions/{action_id}/verify  — cryptographically verify the proof
GET  /forensic/ledger                      — admin-only full ledger listing
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.api.deps import get_current_admin, get_current_user
from asc_api.core.config import get_settings
from asc_api.core.rate_limit import limiter
from asc_api.db.session import get_db
from asc_api.models.forensic_entry import ForensicEntry
from asc_api.models.neutralization import NeutralizationAction
from asc_api.models.user import User
from asc_api.services.pfn import (
    get_entry_by_action,
    verify_forensic_entry,
)

router = APIRouter(prefix="/forensic", tags=["Forensic (PFN)"])
_s = get_settings()


def _entry_dict(entry: ForensicEntry) -> dict:
    return {
        "id": entry.id,
        "action_id": entry.action_id,
        "action_type": entry.action_type,
        "target": entry.target,
        "hash_sha3_512": entry.hash_sha3_512,
        "signature_ed25519": entry.signature_ed25519,
        "signed_by_email": entry.signed_by_email,
        "signed_by_user_id": entry.signed_by_user_id,
        "signed_at": entry.signed_at.isoformat() if entry.signed_at else None,
        "verified": entry.verified,
        "last_verified_at": (entry.last_verified_at.isoformat() if entry.last_verified_at else None),
        "canonical_data": entry.canonical_data,
    }


@router.get(
    "/actions/{action_id}",
    summary="Obtener prueba forense de una acción de neutralización",
)
@limiter.limit(_s.RATE_LIMIT_FORENSIC)
async def get_forensic_proof(
    request: Request,
    action_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    tenant_check = await db.execute(
        select(NeutralizationAction).where(
            NeutralizationAction.id == action_id,
            NeutralizationAction.tenant_id == current_user.tenant_id,
        )
    )
    if not tenant_check.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No hay entrada forense para la acción {action_id}. "
            "La acción puede no haberse ejecutado aún o no tener aprobador asignado.",
        )
    entry = await get_entry_by_action(db, action_id)
    if not entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No hay entrada forense para la acción {action_id}. "
            "La acción puede no haberse ejecutado aún o no tener aprobador asignado.",
        )
    return _entry_dict(entry)


@router.post(
    "/actions/{action_id}/verify",
    summary="Verificar criptográficamente la prueba forense de una acción",
)
@limiter.limit(_s.RATE_LIMIT_FORENSIC)
async def verify_forensic_proof(
    request: Request,
    action_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Recomputes SHA3-512 from stored canonical_data and verifies the Ed25519 signature
    against the signing analyst's public key.
    """
    tenant_check = await db.execute(
        select(NeutralizationAction).where(
            NeutralizationAction.id == action_id,
            NeutralizationAction.tenant_id == current_user.tenant_id,
        )
    )
    if not tenant_check.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No hay entrada forense para la acción {action_id}.",
        )
    entry = await get_entry_by_action(db, action_id)
    if not entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No hay entrada forense para la acción {action_id}.",
        )

    result = await db.execute(select(User).where(User.id == entry.signed_by_user_id))
    approver = result.scalar_one_or_none()
    if not approver or not approver.signing_public_key:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="El usuario firmante ya no existe o no tiene clave pública almacenada.",
        )

    valid = await verify_forensic_entry(db, entry, approver.signing_public_key)

    return {
        "action_id": action_id,
        "entry_id": entry.id,
        "valid": valid,
        "hash_sha3_512": entry.hash_sha3_512,
        "signed_by": entry.signed_by_email,
        "signed_at": entry.signed_at.isoformat() if entry.signed_at else None,
        "verified_at": entry.last_verified_at.isoformat() if entry.last_verified_at else None,
        "message": "Prueba forense válida." if valid else "ADVERTENCIA: la prueba forense no es válida.",
    }


@router.get(
    "/ledger",
    summary="Admin: listar el ledger forense completo",
)
@limiter.limit(_s.RATE_LIMIT_FORENSIC)
async def list_forensic_ledger(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_admin: User = Depends(get_current_admin),
):
    result = await db.execute(
        select(ForensicEntry)
        .join(NeutralizationAction, ForensicEntry.action_id == NeutralizationAction.id)
        .where(NeutralizationAction.tenant_id == current_admin.tenant_id)
        .order_by(ForensicEntry.signed_at.desc())
        .limit(limit)
        .offset(offset)
    )
    entries = list(result.scalars().all())
    total_result = await db.execute(
        select(func.count(ForensicEntry.id))
        .join(NeutralizationAction, ForensicEntry.action_id == NeutralizationAction.id)
        .where(NeutralizationAction.tenant_id == current_admin.tenant_id)
    )
    total = total_result.scalar_one()
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "entries": [_entry_dict(e) for e in entries],
    }
