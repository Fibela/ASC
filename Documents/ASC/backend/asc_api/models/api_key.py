import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Boolean, DateTime, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from asc_api.db.base import Base


class APIKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    # Human-readable label set by the owner
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    # First 8 chars of the raw key — safe to display, never enough to authenticate
    key_prefix: Mapped[str] = mapped_column(String(8), nullable=False, index=True)
    # SHA-256 hex digest of the full raw key
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    # Owner of this key
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Optional scope list e.g. ["read"] or ["read", "write"]
    scopes: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    # Optional expiry — None means no expiry
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Updated on each successful authentication
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Soft-revoke without deleting the row
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # P47 Multi-tenancy — NULL = single-tenant / default deployment
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)

    # Lazy relationship — only used if caller explicitly loads it
    owner = relationship("User", lazy="noload")

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at
