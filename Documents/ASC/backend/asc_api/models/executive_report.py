"""
Executive Report Model — P29-B / PIIL

Stores generated executive KPI reports with:
- Period-based KPI snapshots (MTTD, MTTC, MTTR, SLA breach, campaign counts)
- SHA3-512 hash of the canonical report payload
- Ed25519 signature from the Premos backend signing key (SPECTER_SIGNING_PRIVATE_KEY)
- Verification status + public key fingerprint for auditors

The combination of SHA3-512 + Ed25519 provides the PIIL Executive Authenticity
guarantee: any tampering with the report data invalidates the signature, and the
signature can be verified offline with only the Premos public key.

Report types
------------
  period_kpi     — MTTD/MTTC/MTTR/SLA aggregated over a calendar period
  campaign_brief — Active campaign summary for a given date range
  sla_breach     — SLA breach details report (incidents + entity breakdown)
  full_executive — Combined report (all pillars: incidents, hunting, TI, SOAR)
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from asc_api.db.base import Base

REPORT_TYPES = frozenset({
    "period_kpi",
    "campaign_brief",
    "sla_breach",
    "full_executive",
})

REPORT_PERIODS = frozenset({
    "daily", "weekly", "monthly", "quarterly", "custom",
})


class ExecutiveReport(Base):
    """
    Signed executive intelligence report.

    Generated on demand or via scheduled Celery task. Each report is
    cryptographically sealed at creation — the hash + signature cannot be
    regenerated without the Premos private key.

    Verification workflow:
      1. Recompute SHA3-512 of canonical_data
      2. Compare with hash_sha3_512 (tamper check)
      3. Verify signature_ed25519 against SPECTER_SIGNING_PUBLIC_KEY
    """

    __tablename__ = "executive_reports"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )

    # Report metadata
    # S105.2 — aislamiento multi-tenant. NULL = reporte global (modo single-tenant).
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    report_type: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    period: Mapped[str] = mapped_column(String(20), nullable=False, default="custom")
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    generated_by: Mapped[str] = mapped_column(String(256), nullable=False)

    # Time window for KPI calculation
    period_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    period_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # ── KPI summary (top-level, queryable columns) ────────────────────────────
    total_incidents: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    closed_incidents: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    sla_breach_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    campaign_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    avg_mttd_minutes: Mapped[float | None] = mapped_column(Float, nullable=True)
    avg_mttc_minutes: Mapped[float | None] = mapped_column(Float, nullable=True)
    avg_mttr_minutes: Mapped[float | None] = mapped_column(Float, nullable=True)

    # ── Full payload (JSON) ───────────────────────────────────────────────────
    # Canonical dict that was hashed — self-contained for offline verification
    canonical_data: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    # ── PIIL Forensic Seal ────────────────────────────────────────────────────
    # SHA3-512 hex digest (128 chars) of json.dumps(canonical_data, sort_keys=True)
    hash_sha3_512: Mapped[str] = mapped_column(String(128), nullable=False)

    # Ed25519 signature of hash_sha3_512.encode() — base64-encoded
    # Signed with SPECTER_SIGNING_PRIVATE_KEY (same key used for agent commands)
    signature_ed25519: Mapped[str] = mapped_column(Text, nullable=False)

    # Public key fingerprint (first 16 chars of SHA3-512 of the public key bytes)
    # Allows auditors to verify which Premos key was used without storing the full key
    pubkey_fingerprint: Mapped[str] = mapped_column(String(32), nullable=False, default="")

    # Verification cache
    signature_valid: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    last_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    def compute_hash(self) -> str:
        """Recompute SHA3-512 of canonical_data for tamper verification."""
        payload = json.dumps(self.canonical_data, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha3_512(payload).hexdigest()

    def is_hash_valid(self) -> bool:
        """Return True if stored hash matches current canonical_data."""
        return self.hash_sha3_512 == self.compute_hash()
