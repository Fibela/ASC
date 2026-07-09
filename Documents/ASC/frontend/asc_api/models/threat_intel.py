import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, Text, JSON, Boolean, Float, Integer, Index
from sqlalchemy.orm import Mapped, mapped_column
from asc_api.db.base import Base


class ThreatIntelIndicator(Base):
    """
    PremosCorp Threat Intelligence — local indicator database.

    Stores IOC-style indicators ingested from internal analysts or bulk-imported
    from external feeds (MISP, OpenCTI, TAXII, manual CSV).  Separate from the
    operational IoC table (iocs) which tracks live detections; this table is the
    *authoritative reference corpus* used to enrich alerts, IoC hits, and analysis.

    Indicator types: ip, domain, url, hash_md5, hash_sha1, hash_sha256,
                     email, file_path, mutex, registry_key, asn, cidr, cve
    """
    __tablename__ = "threat_intel_indicators"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    # Core indicator fields
    indicator_type: Mapped[str] = mapped_column(String(50), nullable=False)
    value: Mapped[str] = mapped_column(String(1024), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")
    confidence: Mapped[float] = mapped_column(Float, default=0.5)

    # Attribution & classification
    threat_actor: Mapped[str | None] = mapped_column(String(200), nullable=True)
    malware_family: Mapped[str | None] = mapped_column(String(200), nullable=True)
    campaign: Mapped[str | None] = mapped_column(String(200), nullable=True)
    ttps: Mapped[list] = mapped_column(JSON, default=list)       # MITRE ATT&CK IDs
    tags: Mapped[list] = mapped_column(JSON, default=list)

    # Provenance
    source: Mapped[str] = mapped_column(String(200), nullable=False, default="internal")
    source_reference: Mapped[str | None] = mapped_column(Text, nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Lifecycle
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)

    # Enrichment stats
    hit_count: Mapped[int] = mapped_column(Integer, default=0)
    last_hit_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Authorship
    created_by: Mapped[str] = mapped_column(String(256), nullable=False, default="system")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        Index("ix_ti_value", "value"),
        Index("ix_ti_type_value", "indicator_type", "value"),
        Index("ix_ti_active", "active"),
        Index("ix_ti_severity", "severity"),
    )
