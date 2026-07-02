import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, Integer, Text, JSON, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from asc_api.db.base import Base


class HoneypotToken(Base):
    """
    Persistent canary token registry.
    Backed by DB so tokens survive restarts/redeploys.
    """
    __tablename__ = "honeypot_tokens"
    __table_args__ = (
        Index("ix_honeypot_tokens_created_at", "created_at"),
    )

    token_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    endpoint: Mapped[str] = mapped_column(String(256), nullable=False)
    label: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    accesses: Mapped[list["HoneypotTokenAccess"]] = relationship(
        "HoneypotTokenAccess", back_populates="token", lazy="selectin"
    )
    evidence_reports: Mapped[list["HoneypotEvidenceReport"]] = relationship(
        "HoneypotEvidenceReport", back_populates="token", lazy="select"
    )


class HoneypotTokenAccess(Base):
    """Single access event recorded when a canary token callback fires."""
    __tablename__ = "honeypot_token_accesses"
    __table_args__ = (
        Index("ix_honeypot_accesses_token_id", "token_id"),
        Index("ix_honeypot_accesses_ts", "ts"),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    token_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("honeypot_tokens.token_id", ondelete="CASCADE"), nullable=False
    )
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    client_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    user_agent: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    referer: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    headers_snapshot: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    token: Mapped["HoneypotToken"] = relationship("HoneypotToken", back_populates="accesses")


class HoneypotEvidenceReport(Base):
    """
    Tamper-evident forensic evidence report, persisted to DB.
    Previously stored only in-memory — lost on restart/redeploy.
    """
    __tablename__ = "honeypot_evidence_reports"
    __table_args__ = (
        Index("ix_honeypot_evidence_generated_at", "generated_at"),
        Index("ix_honeypot_evidence_attacker_ip", "attacker_ip"),
    )

    report_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    token_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("honeypot_tokens.token_id", ondelete="SET NULL"), nullable=True
    )
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    attacker_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    # Full signed report payload
    report_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    signature: Mapped[str] = mapped_column(Text, nullable=False)
    fingerprint_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")

    token: Mapped["HoneypotToken | None"] = relationship(
        "HoneypotToken", back_populates="evidence_reports"
    )
