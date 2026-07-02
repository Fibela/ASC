"""
P42 — Webhook model.

Webhooks allow external systems to receive real-time ASC events via HTTP POST.
Each webhook has a signing secret (stored in plaintext — it is a signing key,
not an authentication credential) that recipients use to verify payload integrity
via HMAC-SHA256.

Secret lifecycle (Toque Premos)
--------------------------------
The raw secret is returned ONCE at registration.  After that, callers can only
see/update the URL, events list, and active status — never the secret.  This
mirrors the API key pattern but with plaintext storage (required so the backend
can sign outgoing payloads).

Delivery tracking
-----------------
failure_count: incremented on every delivery failure; reset to 0 on success.
last_triggered_at: updated after every delivery attempt (success or failure).
Auto-deactivation is a policy decision deferred to the delivery layer.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, DateTime, ForeignKey, Integer, JSON, String,
)
from sqlalchemy.orm import Mapped, mapped_column

from asc_api.db.base import Base

# Supported event types (subset exposed at P42; expand in future sprints)
VALID_WEBHOOK_EVENTS = frozenset({
    "incident.created",
    "incident.updated",
    "incident.resolved",
    "alert.critical",
    "alert.high",
    "playbook.executed",
    "api_key.rate_limited",
    "test",            # synthetic event from the /test endpoint
})

_MAX_WEBHOOKS_PER_USER = 10


class Webhook(Base):
    __tablename__ = "webhooks"

    id: Mapped[str] = mapped_column(
        String,
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    # Raw signing secret — 64 hex chars (32 random bytes).
    # Shown once at registration; required in plaintext to sign outgoing payloads.
    secret: Mapped[str] = mapped_column(String(64), nullable=False)
    # JSON list of event type strings from VALID_WEBHOOK_EVENTS
    events: Mapped[list] = mapped_column(JSON, default=list)
    description: Mapped[str | None] = mapped_column(String(500), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    user_id: Mapped[str] = mapped_column(
        String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )
    last_triggered_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Consecutive failures; reset to 0 on successful delivery
    failure_count: Mapped[int] = mapped_column(Integer, default=0)
    # P47 Multi-tenancy — NULL = single-tenant / default deployment
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
