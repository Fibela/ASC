import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from asc_api.db.base import Base


class IoC(Base):
    __tablename__ = "iocs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    value: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    ioc_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # hash_md5, hash_sha256, ip, domain, url, mutex, yara_rule
    threat_type: Mapped[str] = mapped_column(String(100), nullable=True)  # ransomware, trojan, apt, c2, phishing
    confidence: Mapped[float] = mapped_column(default=0.0)  # 0.0 - 1.0
    severity: Mapped[str] = mapped_column(String(20), default="medium")
    source: Mapped[str] = mapped_column(String(100), nullable=False)  # internal, virustotal, otx, abuseipdb
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    ttps: Mapped[list] = mapped_column(JSON, default=list)  # MITRE ATT&CK TTPs
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    hit_count: Mapped[int] = mapped_column(default=0)
