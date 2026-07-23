import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, BigInteger, DateTime, Float, String
from sqlalchemy.orm import Mapped, mapped_column

from asc_api.db.base import Base


class Artifact(Base):
    __tablename__ = "artifacts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    filename: Mapped[str] = mapped_column(String(512), nullable=False)
    file_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    size_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    md5: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    sha1: Mapped[str | None] = mapped_column(String(40), nullable=True)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    analysis_status: Mapped[str] = mapped_column(
        String(30), default="pending"
    )  # pending, analyzing, clean, suspicious, malicious
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    verdict: Mapped[str | None] = mapped_column(String(30), nullable=True)  # clean, suspicious, malicious
    analysis_result: Mapped[dict] = mapped_column(JSON, default=dict)
    matched_iocs: Mapped[list] = mapped_column(JSON, default=list)
    yara_matches: Mapped[list] = mapped_column(JSON, default=list)
    vt_result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    submitted_by: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    submitted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    analyzed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # SEC-6: tenant isolation — added to prevent cross-tenant artifact access
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
