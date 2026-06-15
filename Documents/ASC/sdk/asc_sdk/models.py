"""Client-side Pydantic response models — mirrors ASC backend schemas.

All models use extra="allow" so that new API fields added server-side
do not break older SDK versions.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class _FlexModel(BaseModel):
    model_config = ConfigDict(extra="allow", from_attributes=True)


class Incident(_FlexModel):
    id: str
    title: str
    severity: str
    status: str
    created_at: datetime
    description: str | None = None
    assigned_to: str | None = None
    updated_at: datetime | None = None
    resolved_at: datetime | None = None
    source: str | None = None


class Alert(_FlexModel):
    id: str
    severity: str
    status: str
    created_at: datetime
    description: str | None = None
    source: str | None = None


class Event(_FlexModel):
    id: str
    event_type: str
    created_at: datetime
    severity: str | None = None
    source: str | None = None
    data: dict[str, Any] = {}


class APIKey(_FlexModel):
    id: str
    name: str
    key_prefix: str
    scopes: list[str]
    is_active: bool
    created_at: datetime | None = None
    expires_at: datetime | None = None
    last_used_at: datetime | None = None
    user_id: str | None = None


class APIKeyCreated(APIKey):
    """Returned once at creation — includes the raw API key."""
    raw_key: str


class Webhook(_FlexModel):
    id: str
    url: str
    events: list[str]
    is_active: bool
    user_id: str
    created_at: datetime
    description: str | None = None
    last_triggered_at: datetime | None = None
    failure_count: int = 0


class WebhookCreated(Webhook):
    """Returned once at registration — includes the raw signing secret."""
    secret: str
    signing_note: str


class WebhookTestResult(_FlexModel):
    success: bool
    status_code: int | None
    latency_ms: float
    error: str | None = None


class RateLimitStatus(_FlexModel):
    key_prefix: str
    limit_per_minute: int
    limit_per_hour: int
    count_minute: int
    count_hour: int
    remaining_minute: int
    remaining_hour: int
    backend: str
