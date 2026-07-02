"""
PCDI — Premos Cross-Domain Intelligence API (P24)

Endpoints
---------
POST  /pcdi/score/{finding_id}           — adaptive threat score for a finding
GET   /pcdi/correlate/{hunt_id}          — PANL + TI cross-domain correlation map
POST  /pcdi/sign-report/{hunt_id}        — cryptographically sign a hunt report
GET   /pcdi/signed-reports               — list signed reports (optionally filtered by hunt)
GET   /pcdi/signed-reports/{report_id}   — retrieve one signed report
POST  /pcdi/signed-reports/{report_id}/verify — verify report integrity

All endpoints require analyst or admin role.
Report signing uses the authenticated user's stored Ed25519 private key (PFN infra).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.api.deps import get_analyst_or_admin
from asc_api.core.config import get_settings
from asc_api.core.rate_limit import limiter
from asc_api.core.signing import decrypt_analyst_private_key
from asc_api.db.session import get_db
from asc_api.models.user import User
from asc_api.services import pcdi_service as svc
from asc_api.services.hunt_service import generate_report

router = APIRouter(prefix="/pcdi", tags=["pcdi"])
_s = get_settings()


# ── Pydantic schemas ───────────────────────────────────────────────────────────

class SignReportRequest(BaseModel):
    """
    Optional override fields for signing.
    The report is auto-generated from the hunt; override only if pre-generated.
    """
    report_data: dict | None = Field(
        None,
        description="Pre-generated report JSON. If omitted, auto-generated from hunt.",
    )
    adaptive_score: int | None = Field(
        None, ge=0, le=100,
        description="Optional overall PCDI score to embed in the signed report.",
    )


class VerifyReportRequest(BaseModel):
    public_key_b64: str = Field(
        ...,
        description="Base64-encoded Ed25519 public key to verify the report signature.",
    )


# ── 1. Adaptive Scoring ────────────────────────────────────────────────────────

@router.post("/score/{finding_id}", summary="Compute PCDI adaptive threat score")
@limiter.limit("30/minute")
async def compute_score(
    request: Request,
    finding_id: str,
    current_user: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Compute a dynamic threat score (0-100) for a hunt finding by combining:
    - Finding severity (base)
    - TI indicator matches
    - PANL action history for the same target
    - Active hunt context and confirmation status

    Scores ≥ 80 trigger a 'critical' adapted severity regardless of original.
    """
    result = await svc.compute_adaptive_score(db, finding_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


# ── 2. Cross-Domain Correlation ────────────────────────────────────────────────

@router.get("/correlate/{hunt_id}", summary="PANL + TI cross-domain correlation for a hunt")
@limiter.limit("20/minute")
async def correlate(
    request: Request,
    hunt_id: str,
    current_user: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Link all findings in a hunt to:
    - PANL neutralization actions on matching targets
    - TI indicator records matching finding indicators

    Returns a full correlation map with action types, statuses, and match confidence.
    """
    result = await svc.correlate_hunt_with_panl(db, hunt_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


# ── 3. Sign Hunt Report ────────────────────────────────────────────────────────

@router.post("/sign-report/{hunt_id}", status_code=201, summary="Sign hunt report with SHA3-512 + Ed25519")
@limiter.limit("10/minute")
async def sign_report(
    request: Request,
    hunt_id: str,
    body: SignReportRequest = SignReportRequest(),
    current_user: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Generate (or use provided) a hunt report and sign it cryptographically:
    1. SHA3-512 hash of deterministic JSON canonical form
    2. Ed25519 signature using the authenticated analyst's stored key

    The signed report is persisted in pcdi_signed_reports and returned.
    The signature can be independently verified offline using the analyst's public key.

    Requires the authenticated user to have a registered Ed25519 signing key pair.
    """
    if not current_user.signing_private_key_enc:
        raise HTTPException(
            status_code=422,
            detail=(
                "Your account has no registered signing key. "
                "Ask an admin to generate your Ed25519 key pair via IAM."
            ),
        )

    # Auto-generate report if not provided
    report_data = body.report_data
    if report_data is None:
        report_data = await generate_report(db, hunt_id)
        if report_data is None:
            raise HTTPException(status_code=404, detail="Hunt not found")

    try:
        priv_key_b64 = decrypt_analyst_private_key(
            current_user.signing_private_key_enc, _s.SECRET_KEY
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to decrypt signing key: {exc}") from exc

    signed = await svc.sign_hunt_report(
        db,
        hunt_id,
        report_data,
        signed_by_email=current_user.email,
        signed_by_user_id=str(current_user.id),
        private_key_b64=priv_key_b64,
        adaptive_score=body.adaptive_score,
    )
    return signed


# ── 4. List Signed Reports ─────────────────────────────────────────────────────

@router.get("/signed-reports", summary="List PCDI signed hunt reports")
@limiter.limit("30/minute")
async def list_signed_reports(
    request: Request,
    hunt_id: str | None = Query(None, description="Filter by hunt ID"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """List stored signed reports, optionally filtered by hunt."""
    reports = await svc.list_signed_reports(db, hunt_id=hunt_id, limit=limit, offset=offset)
    return {"total": len(reports), "reports": reports}


# ── 5. Get Single Signed Report ────────────────────────────────────────────────

@router.get("/signed-reports/{report_id}", summary="Get a PCDI signed report by ID")
@limiter.limit("30/minute")
async def get_signed_report(
    request: Request,
    report_id: str,
    current_user: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Retrieve a single signed report including full canonical_data."""
    report = await svc.get_signed_report(db, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Signed report not found")
    return report


# ── 6. Verify Report Integrity ────────────────────────────────────────────────

@router.post("/signed-reports/{report_id}/verify", summary="Verify PCDI report integrity")
@limiter.limit("20/minute")
async def verify_report(
    request: Request,
    report_id: str,
    body: VerifyReportRequest,
    current_user: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Verify the integrity of a stored signed report by:
    1. Recomputing SHA3-512 from stored canonical_data and comparing to stored hash
    2. Verifying the Ed25519 signature against the provided public key

    Returns verification result with per-step details.
    """
    result = await svc.verify_signed_report(db, report_id, body.public_key_b64)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


# ── 7. Forensic Timeline ───────────────────────────────────────────────────────

@router.get("/forensic-timeline/{hunt_id}", summary="Cryptographic forensic timeline for a hunt")
@limiter.limit("20/minute")
async def forensic_timeline(
    request: Request,
    hunt_id: str,
    current_user: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Build a complete cryptographic forensic timeline for a hunt.

    Collects all temporal events (hunt lifecycle, queries, findings, PANL
    actions, signed reports) sorted chronologically and linked by chain hashes.

    Each event carries:
      - sequence: ordinal position in the timeline
      - entry_hash: SHA3-512(event_data + prev_hash)
      - prev_hash: hash of the preceding entry (genesis seed for first entry)

    The chain_root_hash covers the entire timeline — any alteration of a past
    event invalidates all subsequent hashes, making tampering detectable.
    """
    result = await svc.build_forensic_timeline(db, hunt_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result
