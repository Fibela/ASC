import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from asc_api.db.base import Base


class ForensicEntry(Base):
    """
    Premos Forensic Neutralization (PFN) ledger entry.

    Every successfully executed neutralization action produces one entry here.
    The entry contains a SHA3-512 hash of the canonical action data, signed
    with the approving analyst's Ed25519 private key — providing cryptographic
    proof that the action was real, approved, and unaltered.

    Verification: recompute SHA3-512 from canonical_data, then verify
    signature_ed25519 against the analyst's stored public key.
    """

    __tablename__ = "forensic_ledger"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # Link to the neutralization action (kept even if action is later deleted)
    action_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    action_type: Mapped[str] = mapped_column(String(50), nullable=False)
    target: Mapped[str] = mapped_column(String(512), nullable=False)

    # The exact JSON dict that was hashed — stored so verification is self-contained
    canonical_data: Mapped[dict] = mapped_column(JSON, nullable=False)

    # SHA3-512 hex digest (128 hex chars) of json.dumps(canonical_data, sort_keys=True)
    hash_sha3_512: Mapped[str] = mapped_column(String(128), nullable=False)

    # Ed25519 signature of hash_sha3_512.encode() — base64-encoded
    signature_ed25519: Mapped[str] = mapped_column(Text, nullable=False)

    # Analyst who approved (and therefore signed) the action
    signed_by_email: Mapped[str] = mapped_column(String(256), nullable=False)
    signed_by_user_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    signed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

    # Set to True on first successful verify; serves as a quick cache
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    last_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
