"""
PCDI — Premos Cross-Domain Intelligence Service (P24)

Implements the three pillars of PCDI:

  1. Adaptive Scoring — combines TI severity, hunt context, and PANL history
     to produce a dynamic threat score (0-100) that auto-escalates severity.

  2. Cross-Domain Correlation — links hunt findings to PANL neutralization
     actions targeting the same indicator/host/IP, and to TI indicator records,
     producing a unified correlation map.

  3. Cryptographic Hunt Report Signing — uses SHA3-512 + Ed25519 (PFN infra)
     to create tamper-evident, verifiable signed copies of hunt reports.

All operations are READ-ONLY with respect to production data except for:
  - PCDISignedReport persistence (sign_hunt_report)
  - verified flag update (verify_signed_report)
"""
from __future__ import annotations

import base64
import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.models.hunt import Hunt, HuntFinding
from app.models.neutralization import NeutralizationAction
from app.models.pcdi import PCDISignedReport
from app.models.threat_intel import ThreatIntelIndicator

log = get_logger("asc.pcdi")

# ── Scoring constants ──────────────────────────────────────────────────────────

_SEV_BASE: dict[str, int] = {
    "critical": 80,
    "high": 60,
    "medium": 40,
    "low": 20,
    "info": 5,
}

_PANL_BOOST_BY_TYPE: dict[str, int] = {
    "isolate_endpoint":   15,
    "block_ip":           10,
    "block_domain":       10,
    "kill_process":        8,
    "delete_file":         5,
    "remove_persistence":  5,
    "disable_account":     8,
    "quarantine_file":     5,
}

_PANL_STATUS_MULTIPLIER: dict[str, float] = {
    "completed":       1.0,
    "executing":       0.9,
    "approved":        0.7,
    "pending_approval": 0.3,
}

_CONFIRMED_FINDING_BOOST = 10
_ACTIVE_HUNT_BOOST = 5
_TI_MATCH_BOOST = 8


# ── 1. Adaptive Scoring ────────────────────────────────────────────────────────

async def compute_adaptive_score(db: AsyncSession, finding_id: str) -> dict:
    """
    Compute a PCDI adaptive threat score (0-100) for a specific finding.

    Score components:
      - Base from finding severity
      - TI indicator match boost
      - PANL action history for same target
      - Confirmation status and active hunt context

    Returns adaptive score, recommendation, and contributing signals.
    """
    result = await db.execute(
        select(HuntFinding).where(HuntFinding.id == finding_id)
    )
    finding = result.scalar_one_or_none()
    if finding is None:
        return {"error": "Finding not found", "finding_id": finding_id}

    # Load parent hunt
    hunt_result = await db.execute(
        select(Hunt).where(Hunt.id == finding.hunt_id)
    )
    hunt = hunt_result.scalar_one_or_none()

    score = _SEV_BASE.get(finding.severity, 20)
    signals: list[dict] = [
        {"source": "severity", "value": finding.severity, "contribution": score}
    ]

    # Active hunt boost
    if hunt and hunt.status == "active":
        score += _ACTIVE_HUNT_BOOST
        signals.append({"source": "active_hunt", "value": True, "contribution": _ACTIVE_HUNT_BOOST})

    # Confirmed finding boost
    if finding.is_confirmed:
        score += _CONFIRMED_FINDING_BOOST
        signals.append({"source": "confirmed_finding", "value": True, "contribution": _CONFIRMED_FINDING_BOOST})

    # TI indicator match
    ti_matches: list[dict] = []
    if finding.indicator_value:
        ti_result = await db.execute(
            select(ThreatIntelIndicator).where(
                ThreatIntelIndicator.value == finding.indicator_value
            )
        )
        ti_matches_raw = list(ti_result.scalars().all())
        for ti in ti_matches_raw:
            boost = min(_TI_MATCH_BOOST, _SEV_BASE.get(ti.severity or "info", 5))
            score += boost
            ti_matches.append({
                "indicator_id": ti.id,
                "value": ti.value,
                "severity": ti.severity,
                "source": ti.source,
                "contribution": boost,
            })
        if ti_matches_raw:
            signals.append({"source": "ti_indicator_matches", "value": len(ti_matches_raw), "contribution": sum(m["contribution"] for m in ti_matches)})

    # PANL action history for the same target
    panl_signals: list[dict] = []
    if finding.indicator_value or finding.affected_host:
        filter_values = [v for v in (finding.indicator_value, finding.affected_host) if v]
        panl_result = await db.execute(
            select(NeutralizationAction)
            .where(NeutralizationAction.target.in_(filter_values))
            .order_by(NeutralizationAction.created_at.desc())
            .limit(10)
        )
        panl_actions = list(panl_result.scalars().all())
        for action in panl_actions:
            type_boost = _PANL_BOOST_BY_TYPE.get(action.action_type, 5)
            status_mult = _PANL_STATUS_MULTIPLIER.get(action.status, 0.5)
            boost = int(type_boost * status_mult)
            score += boost
            panl_signals.append({
                "action_id": action.id,
                "action_type": action.action_type,
                "status": action.status,
                "target": action.target,
                "contribution": boost,
            })
        if panl_signals:
            signals.append({"source": "panl_history", "value": len(panl_signals), "contribution": sum(p["contribution"] for p in panl_signals)})

    # Cap at 100
    score = min(100, score)

    # Derive adapted severity
    adapted_severity = _score_to_severity(score)

    recommendation = _score_to_recommendation(score, finding.severity, adapted_severity)

    log.info(
        "pcdi_score_computed",
        finding_id=finding_id,
        hunt_id=finding.hunt_id,
        raw_severity=finding.severity,
        adapted_severity=adapted_severity,
        score=score,
        ti_matches=len(ti_matches),
        panl_matches=len(panl_signals),
    )

    return {
        "finding_id": finding_id,
        "hunt_id": finding.hunt_id,
        "indicator_value": finding.indicator_value,
        "original_severity": finding.severity,
        "adaptive_score": score,
        "adapted_severity": adapted_severity,
        "severity_escalated": _SEV_BASE.get(adapted_severity, 0) > _SEV_BASE.get(finding.severity, 0),
        "recommendation": recommendation,
        "signals": signals,
        "ti_matches": ti_matches,
        "panl_correlations": panl_signals,
        "scored_at": datetime.now(timezone.utc).isoformat(),
    }


def _score_to_severity(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "info"


def _score_to_recommendation(score: int, original: str, adapted: str) -> str:
    if score >= 90:
        return "IMMEDIATE ACTION REQUIRED — Isolate affected systems and escalate to CISO."
    if score >= 75:
        return "High-confidence threat — Trigger PANL isolation and open critical incident."
    if score >= 60:
        return "Significant threat — Review PANL block actions and escalate if confirmed."
    if score >= 40:
        return "Moderate threat — Enrich with additional TI and monitor closely."
    if score >= 20:
        return "Low threat — Continue passive monitoring."
    return "Informational — No immediate action required."


# ── 2. Cross-Domain Correlation ────────────────────────────────────────────────

async def correlate_hunt_with_panl(db: AsyncSession, hunt_id: str) -> dict:
    """
    Correlate all findings in a hunt with PANL neutralization actions.

    Matches on indicator_value, affected_host, or affected_user vs
    NeutralizationAction.target. Returns a correlation map with match confidence.
    """
    hunt_result = await db.execute(select(Hunt).where(Hunt.id == hunt_id))
    hunt = hunt_result.scalar_one_or_none()
    if hunt is None:
        return {"error": "Hunt not found", "hunt_id": hunt_id}

    findings_result = await db.execute(
        select(HuntFinding).where(HuntFinding.hunt_id == hunt_id)
    )
    findings = list(findings_result.scalars().all())

    # Gather all unique target values from findings
    target_values: set[str] = set()
    for f in findings:
        for v in (f.indicator_value, f.affected_host, f.affected_user):
            if v:
                target_values.add(v)

    correlations: list[dict] = []
    panl_summary: dict[str, int] = {}

    if target_values:
        panl_result = await db.execute(
            select(NeutralizationAction)
            .where(NeutralizationAction.target.in_(list(target_values)))
            .order_by(NeutralizationAction.created_at.desc())
            .limit(50)
        )
        panl_actions = list(panl_result.scalars().all())

        for action in panl_actions:
            matched_findings = [
                f.id for f in findings
                if action.target in (f.indicator_value, f.affected_host, f.affected_user)
            ]
            correlations.append({
                "action_id": action.id,
                "action_type": action.action_type,
                "status": action.status,
                "severity": action.severity,
                "target": action.target,
                "target_type": action.target_type,
                "executed_at": action.executed_at.isoformat() if action.executed_at else None,
                "matched_finding_ids": matched_findings,
                "match_count": len(matched_findings),
            })
            panl_summary[action.action_type] = panl_summary.get(action.action_type, 0) + 1

    # TI correlations
    ti_correlations: list[dict] = []
    if target_values:
        ti_result = await db.execute(
            select(ThreatIntelIndicator).where(
                ThreatIntelIndicator.value.in_(list(target_values))
            ).limit(50)
        )
        ti_indicators = list(ti_result.scalars().all())
        for ti in ti_indicators:
            matched_findings = [
                f.id for f in findings if f.indicator_value == ti.value
            ]
            ti_correlations.append({
                "indicator_id": ti.id,
                "value": ti.value,
                "type": ti.type,
                "severity": ti.severity,
                "source": ti.source,
                "matched_finding_ids": matched_findings,
            })

    log.info(
        "pcdi_correlation_computed",
        hunt_id=hunt_id,
        findings_count=len(findings),
        panl_correlations=len(correlations),
        ti_correlations=len(ti_correlations),
    )

    return {
        "hunt_id": hunt_id,
        "hunt_name": hunt.name,
        "findings_analyzed": len(findings),
        "target_values_searched": len(target_values),
        "panl_correlations": correlations,
        "panl_action_summary": panl_summary,
        "ti_correlations": ti_correlations,
        "total_panl_matches": len(correlations),
        "total_ti_matches": len(ti_correlations),
        "correlated_at": datetime.now(timezone.utc).isoformat(),
    }


# ── 3. Cryptographic Hunt Report Signing ──────────────────────────────────────

def _compute_report_hash(canonical: dict) -> str:
    """SHA3-512 hex digest of deterministic JSON serialisation."""
    payload = json.dumps(canonical, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha3_512(payload).hexdigest()


def _sign_report_hash(hash_hex: str, private_key_b64: str) -> str:
    """Ed25519 sign the hash. Returns base64-encoded signature."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv_bytes = base64.b64decode(private_key_b64)
    key = Ed25519PrivateKey.from_private_bytes(priv_bytes)
    sig = key.sign(hash_hex.encode())
    return base64.b64encode(sig).decode()


def _verify_report_signature(hash_hex: str, signature_b64: str, public_key_b64: str) -> bool:
    """Verify Ed25519 signature. Never raises."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
        pub_bytes = base64.b64decode(public_key_b64)
        pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        sig = base64.b64decode(signature_b64)
        pub_key.verify(sig, hash_hex.encode())
        return True
    except Exception:
        return False


async def sign_hunt_report(
    db: AsyncSession,
    hunt_id: str,
    report_data: dict,
    *,
    signed_by_email: str,
    signed_by_user_id: str | None = None,
    private_key_b64: str,
    adaptive_score: int | None = None,
) -> dict:
    """
    Cryptographically sign a hunt report and store it in pcdi_signed_reports.

    The canonical_data includes the full report_data plus PCDI metadata.
    Returns the stored PCDISignedReport serialized as a dict.
    """
    hunt_result = await db.execute(select(Hunt).where(Hunt.id == hunt_id))
    hunt = hunt_result.scalar_one_or_none()

    canonical: dict[str, Any] = {
        "pcdi_version": "1",
        "hunt_id": hunt_id,
        "hunt_name": hunt.name if hunt else None,
        "signed_by": signed_by_email,
        "signed_at": datetime.now(timezone.utc).isoformat(),
        "report": report_data,
    }

    hash_hex = _compute_report_hash(canonical)
    signature = _sign_report_hash(hash_hex, private_key_b64)

    entry = PCDISignedReport(
        id=str(uuid.uuid4()),
        hunt_id=hunt_id,
        hunt_name=hunt.name if hunt else None,
        canonical_data=canonical,
        hash_sha3_512=hash_hex,
        signature_ed25519=signature,
        signed_by_email=signed_by_email,
        signed_by_user_id=signed_by_user_id,
        signed_at=datetime.now(timezone.utc),
        verified=False,
        pcdi_version="1",
        adaptive_score=adaptive_score,
    )
    db.add(entry)
    await db.commit()
    await db.refresh(entry)

    log.info(
        "pcdi_report_signed",
        report_id=entry.id,
        hunt_id=hunt_id,
        signed_by=signed_by_email,
        hash_prefix=hash_hex[:16],
    )

    return _signed_report_to_dict(entry)


async def verify_signed_report(
    db: AsyncSession,
    report_id: str,
    public_key_b64: str,
) -> dict:
    """
    Verify the integrity of a stored signed report.

    Recomputes SHA3-512 from canonical_data and checks the Ed25519 signature.
    Updates the verified flag on success.
    """
    result = await db.execute(
        select(PCDISignedReport).where(PCDISignedReport.id == report_id)
    )
    entry = result.scalar_one_or_none()
    if entry is None:
        return {"error": "Signed report not found", "report_id": report_id}

    recomputed_hash = _compute_report_hash(entry.canonical_data)
    hash_valid = recomputed_hash == entry.hash_sha3_512

    sig_valid = _verify_report_signature(entry.hash_sha3_512, entry.signature_ed25519, public_key_b64)

    overall_valid = hash_valid and sig_valid

    if overall_valid:
        entry.verified = True
        entry.last_verified_at = datetime.now(timezone.utc)
        await db.commit()

    log.info(
        "pcdi_report_verified",
        report_id=report_id,
        hash_valid=hash_valid,
        sig_valid=sig_valid,
        overall=overall_valid,
    )

    return {
        "report_id": report_id,
        "hunt_id": entry.hunt_id,
        "verified": overall_valid,
        "hash_valid": hash_valid,
        "signature_valid": sig_valid,
        "signed_by": entry.signed_by_email,
        "signed_at": entry.signed_at.isoformat(),
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "details": {
            "stored_hash_prefix": entry.hash_sha3_512[:16],
            "recomputed_hash_prefix": recomputed_hash[:16],
            "hash_match": hash_valid,
        },
    }


async def list_signed_reports(
    db: AsyncSession,
    hunt_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict]:
    """List stored signed reports, optionally filtered by hunt_id."""
    q = select(PCDISignedReport).order_by(PCDISignedReport.signed_at.desc())
    if hunt_id:
        q = q.where(PCDISignedReport.hunt_id == hunt_id)
    q = q.limit(limit).offset(offset)
    result = await db.execute(q)
    entries = list(result.scalars().all())
    return [_signed_report_to_dict(e) for e in entries]


async def get_signed_report(db: AsyncSession, report_id: str) -> dict | None:
    """Fetch a single signed report by ID."""
    result = await db.execute(
        select(PCDISignedReport).where(PCDISignedReport.id == report_id)
    )
    entry = result.scalar_one_or_none()
    return _signed_report_to_dict(entry) if entry else None


def _signed_report_to_dict(entry: PCDISignedReport) -> dict:
    return {
        "id": entry.id,
        "hunt_id": entry.hunt_id,
        "hunt_name": entry.hunt_name,
        "hash_sha3_512": entry.hash_sha3_512,
        "hash_prefix": entry.hash_sha3_512[:16] + "...",
        "signature_ed25519": entry.signature_ed25519,
        "signed_by_email": entry.signed_by_email,
        "signed_by_user_id": entry.signed_by_user_id,
        "signed_at": entry.signed_at.isoformat() if entry.signed_at else None,
        "verified": entry.verified,
        "last_verified_at": entry.last_verified_at.isoformat() if entry.last_verified_at else None,
        "pcdi_version": entry.pcdi_version,
        "adaptive_score": entry.adaptive_score,
    }


# ── 4. Forensic Timeline ───────────────────────────────────────────────────────

_GENESIS_SEED = "GENESIS:pcdi-forensic-timeline:v1"


async def build_forensic_timeline(db: AsyncSession, hunt_id: str) -> dict:
    """
    Build a cryptographic forensic timeline for a hunt.

    Collects all timestamped events related to the hunt:
      - Hunt lifecycle (created, started, completed)
      - HuntQuery creation and execution
      - HuntFinding creation and confirmation
      - PANL neutralization actions on matching targets
      - PCDI signed reports

    Events are sorted chronologically and linked with chain hashes:
    each entry's SHA3-512 is computed over (event_data + prev_hash),
    forming a tamper-evident chronological chain. Any post-hoc alteration
    of an event invalidates all subsequent hashes.

    Returns the ordered timeline, chain root hash, and integrity status.
    """
    from app.models.hunt import HuntQuery

    hunt_result = await db.execute(select(Hunt).where(Hunt.id == hunt_id))
    hunt = hunt_result.scalar_one_or_none()
    if hunt is None:
        return {"error": "Hunt not found", "hunt_id": hunt_id}

    raw_events: list[dict] = []

    # ── Hunt lifecycle events ─────────────────────────────────────────────────
    raw_events.append({
        "event_type": "hunt_created",
        "ts": _iso(hunt.created_at),
        "actor": hunt.created_by,
        "data": {
            "hunt_name": hunt.name,
            "priority": hunt.priority,
            "scope": hunt.scope,
            "mitre_technique": hunt.mitre_technique,
        },
    })
    if hunt.started_at:
        raw_events.append({
            "event_type": "hunt_started",
            "ts": _iso(hunt.started_at),
            "actor": hunt.assigned_to or hunt.created_by,
            "data": {"status": "active"},
        })
    if hunt.completed_at:
        raw_events.append({
            "event_type": "hunt_completed",
            "ts": _iso(hunt.completed_at),
            "actor": hunt.assigned_to or hunt.created_by,
            "data": {
                "status": hunt.status,
                "findings_count": hunt.findings_count,
                "true_positive_count": hunt.true_positive_count,
                "conclusion": hunt.conclusion,
            },
        })

    # ── HuntQuery events ──────────────────────────────────────────────────────
    queries_result = await db.execute(
        select(HuntQuery).where(HuntQuery.hunt_id == hunt_id)
        .order_by(HuntQuery.created_at)
    )
    for q in queries_result.scalars().all():
        raw_events.append({
            "event_type": "query_created",
            "ts": _iso(q.created_at),
            "actor": q.created_by,
            "data": {"query_id": q.id, "query_name": q.name, "data_source": q.data_source},
        })
        if q.last_executed_at:
            raw_events.append({
                "event_type": "query_executed",
                "ts": _iso(q.last_executed_at),
                "actor": q.created_by,
                "data": {
                    "query_id": q.id,
                    "query_name": q.name,
                    "data_source": q.data_source,
                    "result_count": q.last_result_count,
                    "execution_ms": q.last_execution_ms,
                },
            })

    # ── HuntFinding events ────────────────────────────────────────────────────
    findings_result = await db.execute(
        select(HuntFinding).where(HuntFinding.hunt_id == hunt_id)
        .order_by(HuntFinding.created_at)
    )
    findings = list(findings_result.scalars().all())
    target_values: set[str] = set()

    for f in findings:
        raw_events.append({
            "event_type": "finding_created",
            "ts": _iso(f.created_at),
            "actor": f.created_by,
            "data": {
                "finding_id": f.id,
                "title": f.title,
                "severity": f.severity,
                "indicator_value": f.indicator_value,
                "affected_host": f.affected_host,
                "data_source": f.data_source,
            },
        })
        if f.is_confirmed:
            raw_events.append({
                "event_type": "finding_confirmed",
                "ts": _iso(f.updated_at),
                "actor": f.created_by,
                "data": {
                    "finding_id": f.id,
                    "severity": f.severity,
                    "indicator_value": f.indicator_value,
                },
            })
        if f.is_false_positive:
            raw_events.append({
                "event_type": "finding_false_positive",
                "ts": _iso(f.updated_at),
                "actor": f.created_by,
                "data": {"finding_id": f.id, "indicator_value": f.indicator_value},
            })
        for v in (f.indicator_value, f.affected_host, f.affected_user):
            if v:
                target_values.add(v)

    # ── PANL neutralization events ────────────────────────────────────────────
    if target_values:
        panl_result = await db.execute(
            select(NeutralizationAction)
            .where(NeutralizationAction.target.in_(list(target_values)))
            .order_by(NeutralizationAction.created_at)
            .limit(100)
        )
        for action in panl_result.scalars().all():
            raw_events.append({
                "event_type": "panl_action_created",
                "ts": _iso(action.created_at),
                "actor": action.initiated_by or "system",
                "data": {
                    "action_id": action.id,
                    "action_type": action.action_type,
                    "target": action.target,
                    "severity": action.severity,
                    "status": action.status,
                    "automated": action.automated,
                },
            })
            if action.executed_at:
                raw_events.append({
                    "event_type": "panl_action_executed",
                    "ts": _iso(action.executed_at),
                    "actor": action.approved_by or action.initiated_by or "system",
                    "data": {
                        "action_id": action.id,
                        "action_type": action.action_type,
                        "target": action.target,
                        "status": action.status,
                    },
                })

    # ── PCDI signed report events ─────────────────────────────────────────────
    reports_result = await db.execute(
        select(PCDISignedReport).where(PCDISignedReport.hunt_id == hunt_id)
        .order_by(PCDISignedReport.signed_at)
    )
    for rpt in reports_result.scalars().all():
        raw_events.append({
            "event_type": "report_signed",
            "ts": _iso(rpt.signed_at),
            "actor": rpt.signed_by_email,
            "data": {
                "report_id": rpt.id,
                "hash_prefix": rpt.hash_sha3_512[:16] + "...",
                "pcdi_version": rpt.pcdi_version,
                "adaptive_score": rpt.adaptive_score,
            },
        })
        if rpt.last_verified_at:
            raw_events.append({
                "event_type": "report_verified",
                "ts": _iso(rpt.last_verified_at),
                "actor": rpt.signed_by_email,
                "data": {"report_id": rpt.id, "verified": rpt.verified},
            })

    # ── Sort and build chain hashes ───────────────────────────────────────────
    raw_events.sort(key=lambda e: e["ts"])

    chained: list[dict] = []
    prev_hash = _compute_report_hash({"seed": _GENESIS_SEED, "hunt_id": hunt_id})

    for idx, event in enumerate(raw_events):
        entry_payload = {**event, "sequence": idx, "prev_hash": prev_hash}
        entry_hash = _compute_report_hash(entry_payload)
        chained.append({
            **event,
            "sequence": idx,
            "prev_hash": prev_hash,
            "entry_hash": entry_hash,
        })
        prev_hash = entry_hash

    chain_root = prev_hash if chained else _compute_report_hash({"seed": _GENESIS_SEED, "hunt_id": hunt_id, "empty": True})

    log.info(
        "pcdi_forensic_timeline_built",
        hunt_id=hunt_id,
        event_count=len(chained),
        chain_root=chain_root[:16],
    )

    return {
        "hunt_id": hunt_id,
        "hunt_name": hunt.name,
        "event_count": len(chained),
        "chain_root_hash": chain_root,
        "chain_root_prefix": chain_root[:16] + "...",
        "genesis_seed": _GENESIS_SEED,
        "timeline": chained,
        "built_at": datetime.now(timezone.utc).isoformat(),
    }


def _iso(dt: datetime | None) -> str:
    """Normalize datetime to UTC ISO-8601 string."""
    if dt is None:
        return datetime.now(timezone.utc).isoformat()
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()
