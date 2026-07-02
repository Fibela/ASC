"""
SPECTER Honeypot API — P14.5 Canary Callbacks & Evidence Reports.

Endpoint map:
  GET  /c/{token}            — Canary callback (fingerprints attacker on access)
  GET  /honeypot/tokens      — List active canary tokens (admin only)
  GET  /honeypot/reports     — List evidence reports (admin only)
  GET  /honeypot/token/{id}  — Detail + accesses for one token (admin only)
  GET  /honeypot/report/{id} — Full signed evidence report (admin only)

Evidence reports and canary token accesses are persisted to PostgreSQL.
Previously stored only in-memory — lost on every restart/redeploy.
"""

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from asc_api.api.deps import get_current_admin
from asc_api.core.config import get_settings
from asc_api.core.honeypot import (
    AttackerFingerprint,
    CanaryToken,
    canary_store,
    fingerprint_request,
    generate_evidence_report,
    lookup_ip_reputation,
)
from asc_api.core.audit import log_security_action
from asc_api.db.session import get_db
from asc_api.models.honeypot import HoneypotToken, HoneypotTokenAccess, HoneypotEvidenceReport
from asc_api.models.user import User

router = APIRouter(tags=["SPECTER Honeypot"])
settings = get_settings()


# ── Canary Callback ────────────────────────────────────────────────────────────

@router.get("/c/{token_id}", include_in_schema=False)
async def canary_callback(
    token_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Canary token callback endpoint.

    Triggered when an attacker uses a URL embedded in decoy content.
    Silently fingerprints the caller and generates an evidence report.
    Returns a generic 404 body so the attacker cannot detect the trap.
    """
    client_ip = request.client.host if request.client else "unknown"
    headers = dict(request.headers)

    fp = fingerprint_request(client_ip, headers)

    # Record access in in-memory store (fast path) and persist to DB
    token = canary_store.record_access(token_id, client_ip, headers)

    if token:
        log_security_action(
            "specter_canary_token_accessed",
            user_id="attacker",
            role="unknown",
            resource="canary_token",
            resource_id=token_id,
            detail=(
                f"ip={client_ip} "
                f"ua={fp.user_agent[:60]} "
                f"endpoint={token.endpoint} "
                f"access_count={token.access_count}"
            ),
        )

        # Persist access to DB
        access_row = HoneypotTokenAccess(
            id=str(uuid.uuid4()),
            token_id=token_id,
            ts=datetime.now(timezone.utc),
            client_ip=client_ip,
            user_agent=fp.user_agent,
            referer=fp.referer,
            headers_snapshot={k: v[:128] for k, v in headers.items()},
        )
        db.add(access_row)

        try:
            ip_rep = await lookup_ip_reputation(
                client_ip,
                abuseipdb_key=settings.ABUSEIPDB_API_KEY,
            )
        except Exception:
            ip_rep = {}

        report = generate_evidence_report(
            event_type="canary_token_accessed",
            fingerprint=fp,
            token=token,
            ip_reputation=ip_rep,
            secret_key=settings.SECRET_KEY,
            additional_context={
                "trigger": "attacker accessed embedded canary URL from decoy content",
                "decoy_source_endpoint": token.endpoint,
                "canary_label": token.label,
            },
        )

        # Persist evidence report to DB
        ev_row = HoneypotEvidenceReport(
            report_id=report["report_id"],
            token_id=token_id,
            event_type="canary_token_accessed",
            attacker_ip=client_ip,
            severity=report["report"]["incident_summary"]["severity"],
            generated_at=datetime.now(timezone.utc),
            report_json=report["report"],
            signature=report["signature"],
            fingerprint_hash=fp.fingerprint_hash,
        )
        db.add(ev_row)
        await db.commit()

    raise HTTPException(status_code=404, detail="Not found")


# ── Admin: Canary Token Management ────────────────────────────────────────────

@router.get("/honeypot/tokens", summary="List active canary tokens (admin)")
async def list_canary_tokens(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_admin),
) -> dict:
    """Return all canary tokens with their access statistics from the DB."""
    result = await db.execute(
        select(HoneypotToken).order_by(desc(HoneypotToken.created_at))
    )
    db_tokens = result.scalars().all()

    return {
        "total": len(db_tokens),
        "tokens": [
            {
                "token_id":     t.token_id,
                "endpoint":     t.endpoint,
                "label":        t.label,
                "created_at":   t.created_at.isoformat(),
                "access_count": len(t.accesses),
                "first_access": t.accesses[0].ts.isoformat() if t.accesses else None,
                "last_access":  t.accesses[-1].ts.isoformat() if t.accesses else None,
                "accesses": [
                    {
                        "ts":         a.ts.isoformat(),
                        "client_ip":  a.client_ip,
                        "user_agent": a.user_agent,
                        "referer":    a.referer,
                    }
                    for a in t.accesses
                ],
            }
            for t in db_tokens
        ],
    }


@router.get("/honeypot/token/{token_id}", summary="Canary token detail (admin)")
async def get_canary_token(
    token_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_admin),
) -> dict:
    """Return full detail and access log for a single canary token."""
    result = await db.execute(
        select(HoneypotToken).where(HoneypotToken.token_id == token_id)
    )
    token = result.scalar_one_or_none()
    if not token:
        raise HTTPException(status_code=404, detail="Canary token not found")

    return {
        "token_id":     token.token_id,
        "endpoint":     token.endpoint,
        "label":        token.label,
        "created_at":   token.created_at.isoformat(),
        "access_count": len(token.accesses),
        "accesses": [
            {
                "ts":               a.ts.isoformat(),
                "client_ip":        a.client_ip,
                "user_agent":       a.user_agent,
                "referer":          a.referer,
                "headers_snapshot": a.headers_snapshot,
            }
            for a in token.accesses
        ],
    }


@router.get("/honeypot/reports", summary="List evidence reports (admin)")
async def list_evidence_reports(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_admin),
) -> dict:
    """Return all generated evidence reports with their HMAC signatures."""
    result = await db.execute(
        select(HoneypotEvidenceReport).order_by(desc(HoneypotEvidenceReport.generated_at))
    )
    reports = result.scalars().all()

    return {
        "total": len(reports),
        "reports": [
            {
                "report_id":       r.report_id,
                "event_type":      r.event_type,
                "attacker_ip":     r.attacker_ip,
                "severity":        r.severity,
                "generated_at":    r.generated_at.isoformat(),
                "canary_accesses": r.report_json.get("canary_evidence", {}).get("access_count", 0)
                                   if r.report_json.get("canary_evidence") else 0,
                "signature":       r.signature,
            }
            for r in reports
        ],
    }


@router.get("/honeypot/report/{report_id}", summary="Full evidence report (admin)")
async def get_evidence_report(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_admin),
) -> dict:
    """
    Return the full signed evidence report for a specific incident.

    The complete report includes: attacker fingerprint, IP reputation,
    canary access chain, legal notice, and HMAC-SHA256 signature.
    Suitable for direct submission to authorities.
    """
    result = await db.execute(
        select(HoneypotEvidenceReport).where(HoneypotEvidenceReport.report_id == report_id)
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    return {
        "report_id": report.report_id,
        "report":    report.report_json,
        "signature": report.signature,
    }
