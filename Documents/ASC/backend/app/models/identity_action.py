"""
IdentityAction — P26 PIDS Data Model

Records every IAM action executed by SOAR or manually, with a cryptographic
forensic token (SHA3-512 + Ed25519) bound to the action at creation time.

Action types:
  disable_account       — Set userAccountControl |= UF_ACCOUNTDISABLE in AD
  enable_account        — Clear UF_ACCOUNTDISABLE flag
  force_password_reset  — Set pwdLastSet = 0 (user must change at next login)
  quarantine_account    — Move user to quarantine OU via LDAP modifyDN
  enrich_user           — Read-only: collect user attributes for context enrichment

Each action carries:
  - Linkage to hunt / finding / SOAR trigger / playbook run (all nullable)
  - Execution result: success + result_detail
  - Forensic token: SHA3-512 hash of canonical action data + Ed25519 signature
    signed with PIDS_SIGNING_PRIVATE_KEY (falls back to SPECTER_SIGNING_PRIVATE_KEY)
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from asc_api.db.base import Base


class IdentityAction(Base):
    """Forensically-signed record of every IAM enforcement action."""

    __tablename__ = "identity_actions"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )

    # Action classification
    action_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # disable_account | enable_account | force_password_reset | quarantine_account | enrich_user

    # Target identity
    username: Mapped[str] = mapped_column(String(256), nullable=False)
    domain: Mapped[str] = mapped_column(String(256), nullable=False, default="corp.local")
    reason: Mapped[str] = mapped_column(Text, nullable=False)

    # Context linkage (all nullable — action may be standalone)
    hunt_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    finding_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    trigger_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    playbook_run_id: Mapped[str | None] = mapped_column(String(36), nullable=True)

    # Execution result
    success: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    result_detail: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Forensic token
    hash_sha3_512: Mapped[str | None] = mapped_column(
        String(128), nullable=True
    )  # hex-encoded 512-bit hash
    signature_ed25519: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )  # base64-encoded Ed25519 signature; None if signing key not configured
    signed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    signed_by_email: Mapped[str] = mapped_column(
        String(256), nullable=False, default="soar_auto"
    )

    # Audit
    initiated_by: Mapped[str] = mapped_column(
        String(256), nullable=False
    )  # analyst email or "soar_auto"
    executed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        Index("ix_ia_username", "username"),
        Index("ix_ia_action_type", "action_type"),
        Index("ix_ia_hunt_id", "hunt_id"),
        Index("ix_ia_executed_at", "executed_at"),
        Index("ix_ia_success", "success"),
    )
