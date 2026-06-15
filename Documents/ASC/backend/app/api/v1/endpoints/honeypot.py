"""
SPECTER Honeypot API — P14.5 Canary Callbacks & Evidence Reports.

Endpoint map:
  GET  /c/{token}            — Canary callback (fingerprints attacker on access)
  GET  /honeypot/tokens      — List active canary tokens (admin only)
  GET  /honeypot/reports     — Stream evidence reports (admin only)
  GET  /honeypot/token/{id}  — Detail + accesses for one token (admin only)

The /c/{token} endpoint is intentionally sparse — it returns a benign 404
so the attacker cannot distinguish it from a broken link. The real action
(fingerprinting + evidence generation) happens silently server-side.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request

from app.api.deps import get_current_admin
from app.core.config import get_settings
from app.core.honeypot import (
    AttackerFingerprint,
    CanaryToken,
    canary_store,
    fingerprint_request,
    generate_evidence_report,
    lookup_ip_reputation,
)
from app.core.audit import log_security_action
from app.models.user import User

router = APIRouter(tags=["SPECTER Honeypot"])
settings = get_settings()

# In-memory evidence report store (production: persist to DB/S3)
_evidence_reports: list[dict] = []


# ── Canary Callback ────────────────────────────────────────────────────────────

@router.get("/c/{token_id}", include_in_schema=False)
async def canary_callback(token_id: str, request: Request) -> dict:
    """
    Canary token callback endpoint.

    Triggered when an attacker uses a URL embedded in decoy content.
    Silently fingerprints the caller and generates an evidence report.
    Returns a generic 404 body so the attacker cannot detect the trap.
    """
    client_ip = request.client.host if request.client else "unknown"
    headers = dict(request.headers)

    # Fingerprint the caller
    fp = fingerprint_request(client_ip, headers)

    # Record canary access
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

        # Async IP reputation lookup (best-effort, non-blocking errors)
        try:
            ip_rep = await lookup_ip_reputation(
                client_ip,
                abuseipdb_key=settings.ABUSEIPDB_API_KEY,
            )
        except Exception:
            ip_rep = {}

        # Generate signed evidence report
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
        _evidence_reports.append(report)

    # Return a generic 404 — attacker cannot distinguish from broken link
    raise HTTPException(status_code=404, detail="Not found")


# ── Admin: Canary Token Management ────────────────────────────────────────────

@router.get("/honeypot/tokens", summary="List active canary tokens (admin)")
async def list_canary_tokens(
    _: User = Depends(get_current_admin),
) -> dict:
    """Return all active canary tokens and their access statistics."""
    tokens = canary_store.list_all()
    return {
        "total":  len(tokens),
        "tokens": [
            {
                "token_id":     t.token_id,
                "endpoint":     t.endpoint,
                "label":        t.label,
                "created_at":   t.created_at,
                "access_count": t.access_count,
                "first_access": t.first_access,
                "last_access":  t.last_access,
                "accesses": [
                    {
                        "ts":         a.ts,
                        "client_ip":  a.client_ip,
                        "user_agent": a.user_agent,
                        "referer":    a.referer,
                    }
                    for a in t.accesses
                ],
            }
            for t in tokens
        ],
    }


@router.get("/honeypot/token/{token_id}", summary="Canary token detail (admin)")
async def get_canary_token(
    token_id: str,
    _: User = Depends(get_current_admin),
) -> dict:
    """Return full detail and access log for a single canary token."""
    token = canary_store.get(token_id)
    if not token:
        raise HTTPException(status_code=404, detail="Canary token not found")
    return {
        "token_id":     token.token_id,
        "endpoint":     token.endpoint,
        "label":        token.label,
        "created_at":   token.created_at,
        "access_count": token.access_count,
        "accesses": [
            {
                "ts":              a.ts,
                "client_ip":       a.client_ip,
                "user_agent":      a.user_agent,
                "referer":         a.referer,
                "headers_snapshot": a.headers_snapshot,
            }
            for a in token.accesses
        ],
    }


@router.get("/honeypot/reports", summary="List evidence reports (admin)")
async def list_evidence_reports(
    _: User = Depends(get_current_admin),
) -> dict:
    """
    Return all generated evidence reports with their HMAC signatures.

    Reports are signed — the 'signature' field can be used to verify
    integrity before submitting to law enforcement or CERT.
    """
    return {
        "total":   len(_evidence_reports),
        "reports": [
            {
                "report_id":  r["report_id"],
                "event_type": r["report"]["event_type"],
                "attacker_ip": r["report"]["incident_summary"]["attacker_ip"],
                "severity":   r["report"]["incident_summary"]["severity"],
                "generated_at": r["report"]["generated_at"],
                "canary_accesses": r["report"].get("canary_evidence", {}).get("access_count", 0) if r["report"].get("canary_evidence") else 0,
                "signature":  r["signature"],
            }
            for r in _evidence_reports
        ],
    }


@router.get("/honeypot/report/{report_id}", summary="Full evidence report (admin)")
async def get_evidence_report(
    report_id: str,
    _: User = Depends(get_current_admin),
) -> dict:
    """
    Return the full signed evidence report for a specific incident.

    The complete report includes: attacker fingerprint, IP reputation,
    canary access chain, legal notice, and HMAC-SHA256 signature.
    Suitable for direct submission to authorities.
    """
    for r in _evidence_reports:
        if r["report_id"] == report_id:
            return r
    raise HTTPException(status_code=404, detail="Report not found")
