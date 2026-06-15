import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Boolean, DateTime, Integer
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), default="analyst")  # admin, analyst, viewer
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # ── P16.3 IAM fields ──────────────────────────────────────────────────────

    # Brute-force lock: auto-set when failed_login_attempts reaches threshold
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Admin-initiated password reset flag — blocks all endpoints except change-password
    force_password_reset: Mapped[bool] = mapped_column(Boolean, default=False)

    # ── P16.3 per-analyst Ed25519 signing keys ────────────────────────────────

    # Raw Ed25519 public key (base64) — stored in plaintext for verification
    signing_public_key: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Fernet-encrypted Ed25519 private key (base64url ciphertext)
    # Encryption key derived from app SECRET_KEY via PBKDF2 — see signing.py
    signing_private_key_enc: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # ── P47 Multi-tenancy ─────────────────────────────────────────────────────
    # NULL = default single-tenant mode (PremosCorp own deployment)
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)

    # ── P53 Onboarding / Email Verification ───────────────────────────────────
    # True = verified (default for legacy users and internal registrations).
    # False = pending verification (set by POST /onboarding/register).
    email_verified: Mapped[bool] = mapped_column(Boolean, default=True)
    # SHA-256 hash of the one-time verification token (raw token sent via email).
    email_verification_token: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Token expiry — None when already verified or never set.
    email_verification_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Wizard step: pending_email → pending_setup → completed
    onboarding_step: Mapped[str] = mapped_column(String(50), default="completed")

    @property
    def is_locked(self) -> bool:
        """True when the account has an active time-based lock."""
        if self.locked_until is None:
            return False
        return datetime.now(timezone.utc) < self.locked_until
