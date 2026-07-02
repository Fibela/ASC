import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, Index
from sqlalchemy.orm import Mapped, mapped_column
from asc_api.db.base import Base


class RevokedToken(Base):
    """
    Persistent JWT blacklist entry.

    Each revoked JTI is stored here so token revocation survives server
    restarts and works across multiple gunicorn workers.  The jwt_blacklist
    module keeps an in-process L1 cache to avoid a DB round-trip on every
    authenticated request when the JTI is already known to be revoked.

    Cleanup: call jwt_blacklist.purge_expired() at startup or via a scheduled
    Celery task — entries past expires_at are no longer useful.
    """

    __tablename__ = "revoked_tokens"
    __table_args__ = (
        Index("ix_revoked_tokens_expires_at", "expires_at"),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    jti: Mapped[str] = mapped_column(String(36), nullable=False, unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    revoked_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reason: Mapped[str | None] = mapped_column(String(100), nullable=True)
