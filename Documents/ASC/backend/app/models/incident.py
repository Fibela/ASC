from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, DateTime, Float, ForeignKey, Index, Integer, JSON, String, Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from asc_api.db.base import Base

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

INCIDENT_STATUSES = frozenset({
    "detected",       # Initial — just created
    "triaged",        # Under analysis (NIST: Detection/Analysis)
    "contained",      # Threat contained (NIST: Containment)
    "eradicated",     # Root cause removed (NIST: Eradication)
    "recovered",      # Systems restored (NIST: Recovery)
    "post_incident",  # Lessons-learned phase (NIST: Post-Incident Activity)
    "closed",         # Formally closed
    "dismissed",      # False positive — closed without action
})

# Valid state machine transitions
VALID_TRANSITIONS: dict[str, set[str]] = {
    "detected":      {"triaged", "dismissed"},
    "triaged":       {"contained", "dismissed"},
    "contained":     {"eradicated", "triaged"},   # allow rollback to triaged
    "eradicated":    {"recovered", "contained"},
    "recovered":     {"post_incident", "eradicated"},
    "post_incident": {"closed"},
    "closed":        set(),
    "dismissed":     set(),
}

INCIDENT_TYPES = frozenset({
    "malware", "ransomware", "phishing", "data_breach", "insider_threat",
    "apt", "ddos", "credential_abuse", "lateral_movement",
    "supply_chain", "vulnerability_exploit", "other",
})

LINK_ENTITY_TYPES = frozenset({
    "alert", "cluster", "hunt", "finding",
    "identity_action", "panl_action", "playbook_run",
})

TIMELINE_EVENT_TYPES = frozenset({
    "created", "status_change", "assignment", "phase_transition",
    "link_added", "link_removed", "note_added", "sla_warning", "closed",
})

# NIST 800-61 phase derived from status
NIST_PHASE: dict[str, str] = {
    "detected":      "detection_analysis",
    "triaged":       "detection_analysis",
    "contained":     "containment",
    "eradicated":    "eradication",
    "recovered":     "recovery",
    "post_incident": "post_incident_activity",
    "closed":        "post_incident_activity",
    "dismissed":     "post_incident_activity",
}

# SLA targets in minutes per severity
DEFAULT_SLA_MINUTES: dict[str, int] = {
    "critical": 60,
    "high":     240,
    "medium":   1440,
    "low":      10080,
    "info":     43200,
}


class Incident(Base):
    """
    Formal incident record — NIST 800-61 lifecycle.

    Aggregates alerts, correlation clusters, hunt sessions, identity actions,
    PANL neutralizations, and playbook runs into a single tracked entity with
    a defined status machine and forensic audit trail.
    """

    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )

    # Core identity
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    incident_type: Mapped[str] = mapped_column(String(50), nullable=False, default="other")

    # Status + NIST phase
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="detected")
    nist_phase: Mapped[str] = mapped_column(String(50), nullable=False,
                                              default="detection_analysis")

    # Risk + severity
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    # Personnel
    created_by: Mapped[str] = mapped_column(String(256), nullable=False)
    assigned_to: Mapped[str | None] = mapped_column(String(256), nullable=True)

    # MITRE ATT&CK
    mitre_tactics: Mapped[list] = mapped_column(JSON, default=list)
    mitre_techniques: Mapped[list] = mapped_column(JSON, default=list)
    tags: Mapped[list] = mapped_column(JSON, default=list)

    # Outcome + lessons
    executive_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    lessons_learned: Mapped[str | None] = mapped_column(Text, nullable=True)
    root_cause: Mapped[str | None] = mapped_column(Text, nullable=True)
    false_positive: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # SLA tracking
    sla_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=240)
    sla_breach: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Timing metrics (NIST KPIs)
    detected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    triaged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    contained_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    eradicated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    recovered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Computed KPIs (populated on close)
    mttd_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)  # detect→triage
    mttc_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)  # detect→contain
    mttr_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)  # detect→recover

    # Forensic integrity (computed on close)
    forensic_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # P47 Multi-tenancy — NULL = single-tenant / default deployment
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)

    links: Mapped[list["IncidentLink"]] = relationship(
        "IncidentLink", back_populates="incident",
        cascade="all, delete-orphan", lazy="select",
    )
    timeline: Mapped[list["IncidentTimeline"]] = relationship(
        "IncidentTimeline", back_populates="incident",
        cascade="all, delete-orphan", lazy="select",
        order_by="IncidentTimeline.created_at",
    )

    __table_args__ = (
        Index("ix_inc_status", "status"),
        Index("ix_inc_severity", "severity"),
        Index("ix_inc_incident_type", "incident_type"),
        Index("ix_inc_assigned_to", "assigned_to"),
        Index("ix_inc_created_at", "created_at"),
        Index("ix_inc_sla_breach", "sla_breach"),
    )

    def compute_forensic_hash(self) -> str:
        canonical = {
            "id": self.id,
            "title": self.title,
            "incident_type": self.incident_type,
            "status": self.status,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "created_by": self.created_by,
            "mitre_tactics": sorted(self.mitre_tactics or []),
            "mitre_techniques": sorted(self.mitre_techniques or []),
            "mttd_minutes": self.mttd_minutes,
            "mttc_minutes": self.mttc_minutes,
            "mttr_minutes": self.mttr_minutes,
            "sla_breach": self.sla_breach,
            "false_positive": self.false_positive,
            "detected_at": self.detected_at.isoformat() if self.detected_at else None,
            "closed_at": self.closed_at.isoformat() if self.closed_at else None,
        }
        payload = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha3_512(payload).hexdigest()


class IncidentLink(Base):
    """
    Cross-domain link from an incident to a related entity.

    Uses UUID string references (no FK) to avoid circular dependencies
    across domain models — same pattern as CorrelationSignal.
    """

    __tablename__ = "incident_links"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    incident_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )

    # entity_type: alert | cluster | hunt | finding | identity_action | panl_action | playbook_run
    entity_type: Mapped[str] = mapped_column(String(50), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(36), nullable=False)

    # Optional label / note at link time
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    added_by: Mapped[str] = mapped_column(String(256), nullable=False, default="system")

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    incident: Mapped["Incident"] = relationship("Incident", back_populates="links")

    __table_args__ = (
        Index("ix_il_incident_id", "incident_id"),
        Index("ix_il_entity_type", "entity_type"),
        Index("ix_il_entity_id", "entity_id"),
    )


class IncidentTimeline(Base):
    """
    Immutable audit event within an incident.

    Every status transition, assignment change, link addition, and analyst
    note is recorded here in chronological order, forming the forensic
    activity log for the incident.
    """

    __tablename__ = "incident_timeline"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    incident_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )

    # Event classification
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)

    # Who triggered this event
    actor: Mapped[str] = mapped_column(String(256), nullable=False, default="system")

    # Structured detail (prev_status/new_status, entity_id, note text, etc.)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    incident: Mapped["Incident"] = relationship("Incident", back_populates="timeline")

    __table_args__ = (
        Index("ix_it_incident_id", "incident_id"),
        Index("ix_it_event_type", "event_type"),
        Index("ix_it_created_at", "created_at"),
    )
