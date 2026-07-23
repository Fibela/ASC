from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from asc_api.db.base import Base


class Hunt(Base):
    """Threat-hunting session — tracks the analyst's investigation lifecycle."""

    __tablename__ = "hunt_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    hypothesis: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Workflow: draft → active → completed | archived
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="draft")

    # ATT&CK
    mitre_technique: Mapped[str | None] = mapped_column(String(20), nullable=True)  # e.g. T1055
    mitre_tactic: Mapped[str | None] = mapped_column(String(100), nullable=True)  # e.g. defense-evasion

    # Scope / priority
    scope: Mapped[str] = mapped_column(String(50), nullable=False, default="all")  # host | network | cloud | all
    priority: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")

    # Personnel
    created_by: Mapped[str] = mapped_column(String(256), nullable=False)
    assigned_to: Mapped[str | None] = mapped_column(String(256), nullable=True)

    # Timing
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.utcnow().replace(tzinfo=__import__("datetime").timezone.utc),
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.utcnow().replace(tzinfo=__import__("datetime").timezone.utc),
        onupdate=lambda: datetime.utcnow().replace(tzinfo=__import__("datetime").timezone.utc),
    )

    # Outcome
    conclusion: Mapped[str | None] = mapped_column(Text, nullable=True)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    true_positive_count: Mapped[int] = mapped_column(Integer, default=0)

    # Tags (JSON list of strings)
    tags: Mapped[list] = mapped_column(JSON, default=list)

    # Relationships
    findings: Mapped[list[HuntFinding]] = relationship(
        "HuntFinding", back_populates="hunt", cascade="all, delete-orphan", lazy="select"
    )
    queries: Mapped[list[HuntQuery]] = relationship(
        "HuntQuery", back_populates="hunt", cascade="all, delete-orphan", lazy="select"
    )

    __table_args__ = (
        Index("ix_hunt_status", "status"),
        Index("ix_hunt_priority", "priority"),
        Index("ix_hunt_created_by", "created_by"),
        Index("ix_hunt_mitre", "mitre_technique"),
    )


class HuntFinding(Base):
    """Individual finding discovered during a hunt session."""

    __tablename__ = "hunt_findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    hunt_id: Mapped[str] = mapped_column(String(36), ForeignKey("hunt_sessions.id", ondelete="CASCADE"), nullable=False)

    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")

    # Observable
    indicator_value: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    indicator_type: Mapped[str | None] = mapped_column(String(50), nullable=True)

    # Context
    affected_host: Mapped[str | None] = mapped_column(String(256), nullable=True)
    affected_user: Mapped[str | None] = mapped_column(String(256), nullable=True)
    data_source: Mapped[str | None] = mapped_column(String(100), nullable=True)  # elk | wazuh | specter_agent

    # ATT&CK at finding level
    mitre_technique: Mapped[str | None] = mapped_column(String(20), nullable=True)
    mitre_tactic: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Evidence (raw JSON payload from query result or analyst notes)
    evidence: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # Verdict
    is_confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    is_false_positive: Mapped[bool] = mapped_column(Boolean, default=False)
    analyst_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_by: Mapped[str] = mapped_column(String(256), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.utcnow().replace(tzinfo=__import__("datetime").timezone.utc),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.utcnow().replace(tzinfo=__import__("datetime").timezone.utc),
        onupdate=lambda: datetime.utcnow().replace(tzinfo=__import__("datetime").timezone.utc),
    )

    hunt: Mapped[Hunt] = relationship("Hunt", back_populates="findings")

    __table_args__ = (
        Index("ix_hf_hunt_id", "hunt_id"),
        Index("ix_hf_severity", "severity"),
        Index("ix_hf_confirmed", "is_confirmed"),
    )


class HuntQuery(Base):
    """Saved search/query used within a hunt session."""

    __tablename__ = "hunt_queries"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    hunt_id: Mapped[str] = mapped_column(String(36), ForeignKey("hunt_sessions.id", ondelete="CASCADE"), nullable=False)

    name: Mapped[str] = mapped_column(String(256), nullable=False)
    query_text: Mapped[str] = mapped_column(Text, nullable=False)
    data_source: Mapped[str] = mapped_column(
        String(100), nullable=False, default="elk"
    )  # elk | wazuh | specter_agent | manual
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Execution metadata (populated when query is run)
    last_executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_result_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_execution_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    created_by: Mapped[str] = mapped_column(String(256), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.utcnow().replace(tzinfo=__import__("datetime").timezone.utc),
    )

    hunt: Mapped[Hunt] = relationship("Hunt", back_populates="queries")

    __table_args__ = (
        Index("ix_hq_hunt_id", "hunt_id"),
        Index("ix_hq_data_source", "data_source"),
    )
