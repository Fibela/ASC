"""
SPECTER Agent data models — P13.

Three tables:
  agents        — registered SPECTER endpoints (one row per host)
  agent_events  — telemetry stream (process, network, file events)
  agent_commands— commands issued from ASC to SPECTER agents
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, Integer, JSON, String, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Agent(Base):
    __tablename__ = "agents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True,
                                    default=lambda: str(uuid.uuid4()))
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    os_type: Mapped[str] = mapped_column(String(20), nullable=False)    # windows, linux, macos
    os_version: Mapped[str] = mapped_column(String(128), nullable=False)
    arch: Mapped[str] = mapped_column(String(16), nullable=False)       # x86_64, arm64
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False) # IPv4 or IPv6
    public_key: Mapped[str] = mapped_column(Text, nullable=False)       # Ed25519 raw key, base64
    specter_version: Mapped[str] = mapped_column(String(20), nullable=False, default="1.0.0")

    # Status / threat posture
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    # active | inactive | isolated | compromised
    threat_level: Mapped[str] = mapped_column(String(20), nullable=False, default="normal")
    # normal | elevated | critical
    poll_interval: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    # seconds — backend adjusts based on threat_level

    # Lifecycle timestamps
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    # Metadata
    labels: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    # e.g. {"department": "finance", "owner": "john@premoscorp.com"}
    total_events: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class AgentEvent(Base):
    __tablename__ = "agent_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True,
                                    default=lambda: str(uuid.uuid4()))
    agent_id: Mapped[str] = mapped_column(String(36), ForeignKey("agents.id"), nullable=False)

    # Event classification
    event_type: Mapped[str] = mapped_column(String(40), nullable=False)
    # process_start | process_end | net_connect | net_listen | file_write | file_delete | anomaly
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="info")
    # info | low | medium | high | critical

    # Signed payload from agent
    data: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    signature: Mapped[str] = mapped_column(Text, nullable=False)     # Ed25519 sig, base64
    signature_valid: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Behavioral anomaly flag (set by backend after signature verification)
    is_anomaly: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Timestamps
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # timestamp from the agent (when the event occurred on the endpoint)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class AgentCommand(Base):
    __tablename__ = "agent_commands"

    id: Mapped[str] = mapped_column(String(36), primary_key=True,
                                    default=lambda: str(uuid.uuid4()))
    agent_id: Mapped[str] = mapped_column(String(36), ForeignKey("agents.id"), nullable=False)

    # What to do
    command_type: Mapped[str] = mapped_column(String(40), nullable=False)
    # kill_process | block_ip | quarantine_file | isolate | unisolate | collect_snapshot
    params: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    # Backend Ed25519 signature over {id, agent_id, command_type, params, ts}
    # Agent MUST verify this before executing.
    signature: Mapped[str] = mapped_column(Text, nullable=False)

    # Lifecycle
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    # pending | delivered | executing | completed | failed | cancelled
    issued_by: Mapped[str] = mapped_column(String(36), nullable=False)  # user_id
    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Result from agent
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(String(512), nullable=True)
