"""
PCDI — Premos Cross-Domain Intelligence (P24)

Stores cryptographically signed hunt reports.  Each entry contains:
  - canonical_data:  deterministic JSON snapshot of the full report
  - hash_sha3_512:   SHA3-512 hex digest of the snapshot
  - signature_ed25519: Ed25519 signature of the hash (signed by the requesting analyst)

Supports offline verification: recompute the hash from canonical_data and verify
the signature against the analyst's stored public key.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Index, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class PCDISignedReport(Base):
    __tablename__ = "pcdi_signed_reports"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )

    # Reference to the hunt session (not a FK — hunts can be archived/deleted)
    hunt_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    hunt_name: Mapped[str | None] = mapped_column(String(256), nullable=True)

    # Full report snapshot (what was signed)
    canonical_data: Mapped[dict] = mapped_column(JSON, nullable=False)

    # Cryptographic proof
    hash_sha3_512: Mapped[str] = mapped_column(String(128), nullable=False)
    signature_ed25519: Mapped[str] = mapped_column(Text, nullable=False)

    # Who signed and when
    signed_by_email: Mapped[str] = mapped_column(String(256), nullable=False)
    signed_by_user_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    signed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.utcnow().replace(tzinfo=__import__("datetime").timezone.utc),
    )

    # Verification state
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    last_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # PCDI metadata
    pcdi_version: Mapped[str] = mapped_column(String(10), nullable=False, default="1")
    adaptive_score: Mapped[int | None] = mapped_column(
        __import__("sqlalchemy").Integer, nullable=True
    )

    __table_args__ = (
        Index("ix_pcdi_hunt_id", "hunt_id"),
        Index("ix_pcdi_signed_by", "signed_by_email"),
        Index("ix_pcdi_signed_at", "signed_at"),
    )
