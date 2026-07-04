from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from asc_api.db.base import Base

# ---------------------------------------------------------------------------
# Pivot types — define HOW signals are grouped
# ---------------------------------------------------------------------------
PIVOT_TYPES = frozenset({
    "host_pivot",
    "identity_pivot",
    "ip_pivot",
    "domain_pivot",
    "ttp_pivot",
})

# Signal types — enumerate WHICH domain the signal comes from
SIGNAL_TYPES = frozenset({
    "event",
    "alert",
    "finding",
    "identity_action",
    "panl_action",
    "ti_indicator",
    "agent_command",
})

CLUSTER_STATUSES = frozenset({"active", "resolved", "dismissed"})


class CorrelationRule(Base):
    """Defines a pivot-based clustering rule for the Correlation Engine."""

    __tablename__ = "correlation_rules"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False, unique=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Pivot strategy
    pivot_type: Mapped[str] = mapped_column(String(50), nullable=False)

    # Thresholds
    min_signals: Mapped[int] = mapped_column(Integer, nullable=False, default=2)
    time_window_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    severity_threshold: Mapped[str] = mapped_column(String(20), nullable=False, default="low")

    # Lifecycle
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    clusters: Mapped[list["CorrelationCluster"]] = relationship(
        "CorrelationCluster", back_populates="rule", cascade="all, delete-orphan", lazy="select"
    )

    __table_args__ = (
        Index("ix_cr_pivot_type", "pivot_type"),
        Index("ix_cr_enabled", "enabled"),
    )


class CorrelationCluster(Base):
    """
    Detected threat group — aggregates signals that share a common pivot value.

    A cluster becomes a *campaign* when its signals span 3+ distinct signal_type
    domains (e.g. event + identity_action + panl_action), suggesting coordinated
    multi-stage attacker activity.
    """

    __tablename__ = "correlation_clusters"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    rule_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("correlation_rules.id", ondelete="CASCADE"), nullable=False
    )

    # The shared value that groups these signals (e.g. "ws-001", "jdoe", "10.0.0.5")
    cluster_key: Mapped[str] = mapped_column(String(512), nullable=False)
    cluster_type: Mapped[str] = mapped_column(String(50), nullable=False)  # mirrors pivot_type

    # Aggregated stats
    signal_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="low")
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    # Timeline
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False,
                                                  default=lambda: datetime.now(timezone.utc))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False,
                                                 default=lambda: datetime.now(timezone.utc))

    # Lifecycle: active → resolved | dismissed
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="active")

    # Campaign detection
    is_campaign: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    campaign_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    distinct_signal_domains: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Analyst
    analyst_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    assigned_to: Mapped[str | None] = mapped_column(String(256), nullable=True)

    # Forensic integrity
    forensic_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Extended metadata (MITRE, raw pivot context)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    rule: Mapped["CorrelationRule"] = relationship("CorrelationRule", back_populates="clusters")
    signals: Mapped[list["CorrelationSignal"]] = relationship(
        "CorrelationSignal", back_populates="cluster", cascade="all, delete-orphan", lazy="select"
    )

    __table_args__ = (
        Index("ix_cc_rule_id", "rule_id"),
        Index("ix_cc_cluster_key", "cluster_key"),
        Index("ix_cc_status", "status"),
        Index("ix_cc_is_campaign", "is_campaign"),
        Index("ix_cc_last_seen", "last_seen"),
        Index("ix_cc_severity", "severity"),
    )

    def compute_forensic_hash(self) -> str:
        canonical = {
            "id": self.id,
            "rule_id": self.rule_id,
            "cluster_key": self.cluster_key,
            "cluster_type": self.cluster_type,
            "signal_count": self.signal_count,
            "severity": self.severity,
            "is_campaign": self.is_campaign,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }
        payload = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha3_512(payload).hexdigest()


class CorrelationSignal(Base):
    """
    Individual signal contributing to a CorrelationCluster.

    Each signal references one originating domain record (event, alert, finding, etc.)
    by its UUID and signal_type, keeping FK-free cross-domain linkage while preserving
    forensic traceability.
    """

    __tablename__ = "correlation_signals"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    cluster_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("correlation_clusters.id", ondelete="CASCADE"), nullable=False
    )

    # Origin domain
    signal_type: Mapped[str] = mapped_column(String(50), nullable=False)
    signal_id: Mapped[str] = mapped_column(String(36), nullable=False)

    # The pivot value that triggered inclusion (e.g. "ws-001" for host_pivot)
    pivot_value: Mapped[str] = mapped_column(String(512), nullable=False)

    # Attributes inherited from source record
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="low")
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Extra context from source record (host, user, action_type, ttp, etc.)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    cluster: Mapped["CorrelationCluster"] = relationship(
        "CorrelationCluster", back_populates="signals"
    )

    __table_args__ = (
        Index("ix_cs_cluster_id", "cluster_id"),
        Index("ix_cs_signal_type", "signal_type"),
        Index("ix_cs_signal_id", "signal_id"),
        Index("ix_cs_pivot_value", "pivot_value"),
        Index("ix_cs_timestamp", "timestamp"),
    )
