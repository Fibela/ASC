"""
P42 â€” Webhook Support  (Toque Premos aplicado)
================================================
Endpoints for registering, managing, and testing outbound webhooks.

Toque Premos design guarantees:
  - One-time secret reveal: the raw signing secret is returned ONCE at registration
    and is NEVER included in list/get responses.  This mirrors the API key pattern.
  - HMAC-SHA256 payload signing: every outgoing delivery carries an
    X-ASC-Signature header; recipients can verify authenticity without
    storing ASC credentials.
  - Ledger Premos: create/delete/test events emitted to asc.audit.
  - Secret never logged: the signing secret is excluded from all log fields.

Webhook URL format: http(s)://hostname/path
Supported events: see VALID_WEBHOOK_EVENTS in models/webhook.py

Registration cap: 10 active webhooks per user.
"""

import secrets
import uuid as _uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.api.deps import get_current_user, get_current_admin
from asc_api.core.audit import log_security_action
from asc_api.core.tenant_context import get_tenant_id
from asc_api.core.webhook_dispatcher import deliver_to_url
from asc_api.db.session import get_db
from asc_api.db.tenant_filter import apply_tenant_filter
from asc_api.models.webhook import Webhook, VALID_WEBHOOK_EVENTS, _MAX_WEBHOOKS_PER_USER
from asc_api.models.user import User

router = APIRouter(prefix="/webhooks", tags=["Webhooks"])

_SIGNING_NOTE = (
    "Verify deliveries: "
    "import hmac, hashlib; "
    "expected = 'sha256=' + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest(); "
    "assert hmac.compare_digest(expected, request.headers['X-ASC-Signature'])"
)


# â”€â”€ Schemas â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class WebhookCreate(BaseModel):
    url: str = Field(..., max_length=2048)
    events: list[str] = Field(..., min_length=1)
    description: str | None = Field(None, max_length=500)

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        from urllib.parse import urlparse
        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https"):
            raise ValueError("URL must use http:// or https://")
        if not parsed.netloc:
            raise ValueError("URL must have a valid hostname")
        return v

    @field_validator("events")
    @classmethod
    def validate_events(cls, v: list[str]) -> list[str]:
        invalid = [e for e in v if e not in VALID_WEBHOOK_EVENTS]
        if invalid:
            raise ValueError(
                f"Invalid events: {invalid}. Valid: {sorted(VALID_WEBHOOK_EVENTS)}"
            )
        return list(set(v))  # deduplicate


class WebhookResponse(BaseModel):
    id: str
    url: str
    events: list[str]
    description: str | None
    is_active: bool
    user_id: str
    created_at: datetime
    last_triggered_at: datetime | None
    failure_count: int

    model_config = {"from_attributes": True}


class WebhookCreated(WebhookResponse):
    """Returned ONCE at creation â€” includes the raw signing secret."""
    secret: str
    signing_note: str


class WebhookPatch(BaseModel):
    url: str | None = Field(None, max_length=2048)
    events: list[str] | None = None
    is_active: bool | None = None
    description: str | None = Field(None, max_length=500)

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str | None) -> str | None:
        if v is None:
            return v
        from urllib.parse import urlparse
        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https"):
            raise ValueError("URL must use http:// or https://")
        if not parsed.netloc:
            raise ValueError("URL must have a valid hostname")
        return v

    @field_validator("events")
    @classmethod
    def validate_events(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        invalid = [e for e in v if e not in VALID_WEBHOOK_EVENTS]
        if invalid:
            raise ValueError(
                f"Invalid events: {invalid}. Valid: {sorted(VALID_WEBHOOK_EVENTS)}"
            )
        return list(set(v))


class WebhookTestResult(BaseModel):
    success: bool
    status_code: int | None
    latency_ms: float
    error: str | None


# â”€â”€ DB helper â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

async def _get_webhook_or_404(webhook_id: str, db: AsyncSession) -> Webhook:
    result = await db.execute(select(Webhook).where(Webhook.id == webhook_id))
    wh = result.scalar_one_or_none()
    if not wh:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook no encontrado")
    return wh


def _assert_owner_or_admin(wh: Webhook, user: User) -> None:
    if user.role != "admin" and wh.user_id != user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No autorizado")


# â”€â”€ Endpoints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@router.post("", response_model=WebhookCreated, status_code=status.HTTP_201_CREATED)
async def register_webhook(
    payload: WebhookCreate,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """
    Register a new webhook.

    The signing secret is returned **once** in this response â€” store it securely.
    Subsequent GET/list responses will never include the secret.

    To verify deliveries: compute HMAC-SHA256(secret, body) and compare to
    the X-ASC-Signature header.
    """
    # Enforce per-user cap
    count_result = await db.execute(
        select(Webhook).where(Webhook.user_id == current_user.id, Webhook.is_active == True)
    )
    active = count_result.scalars().all()
    if len(active) >= _MAX_WEBHOOKS_PER_USER:
        raise HTTPException(
            status_code=422,
            detail=f"LÃ­mite de {_MAX_WEBHOOKS_PER_USER} webhooks activos por usuario alcanzado",
        )

    raw_secret = secrets.token_hex(32)  # 64 hex chars
    now = datetime.now(timezone.utc)
    wh = Webhook(
        id=str(_uuid.uuid4()),
        url=payload.url,
        secret=raw_secret,
        events=payload.events,
        description=payload.description,
        user_id=current_user.id,
        is_active=True,
        failure_count=0,
        created_at=now,
        tenant_id=get_tenant_id(),  # P51: auto-assign from request context
    )
    db.add(wh)
    await db.commit()
    await db.refresh(wh)

    log_security_action(
        "webhook_created",
        user_id=current_user.id,
        role=current_user.role,
        resource="webhook",
        resource_id=wh.id,
        detail=f"url={wh.url!r} events={wh.events}",
    )

    return WebhookCreated(
        id=wh.id,
        url=wh.url,
        events=wh.events,
        description=wh.description,
        is_active=wh.is_active,
        user_id=wh.user_id,
        created_at=wh.created_at,
        last_triggered_at=wh.last_triggered_at,
        failure_count=wh.failure_count,
        secret=raw_secret,
        signing_note=_SIGNING_NOTE,
    )


@router.get("", response_model=list[WebhookResponse])
async def list_webhooks(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """
    List webhooks. Owners see only their own; admins see all within their tenant.
    The signing secret is NOT included in list responses.
    P51: all queries scoped to the request's tenant via apply_tenant_filter().
    """
    if current_user.role == "admin":
        stmt = apply_tenant_filter(
            select(Webhook).order_by(Webhook.created_at.desc()), Webhook
        )
    else:
        stmt = apply_tenant_filter(
            select(Webhook)
            .where(Webhook.user_id == current_user.id)
            .order_by(Webhook.created_at.desc()),
            Webhook,
        )
    result = await db.execute(stmt)
    return result.scalars().all()


@router.get("/{webhook_id}", response_model=WebhookResponse)
async def get_webhook(
    webhook_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """Get a single webhook by ID. Secret is not included."""
    wh = await _get_webhook_or_404(webhook_id, db)
    _assert_owner_or_admin(wh, current_user)
    return wh


@router.patch("/{webhook_id}", response_model=WebhookResponse)
async def update_webhook(
    webhook_id: str,
    payload: WebhookPatch,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """Update webhook URL, events list, active status, or description."""
    wh = await _get_webhook_or_404(webhook_id, db)
    _assert_owner_or_admin(wh, current_user)

    if payload.url is not None:
        wh.url = payload.url
    if payload.events is not None:
        wh.events = payload.events
    if payload.is_active is not None:
        wh.is_active = payload.is_active
    if payload.description is not None:
        wh.description = payload.description

    await db.commit()
    await db.refresh(wh)
    return wh


@router.delete("/{webhook_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_webhook(
    webhook_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """Permanently delete a webhook. Emits Ledger Premos entry."""
    wh = await _get_webhook_or_404(webhook_id, db)
    _assert_owner_or_admin(wh, current_user)
    webhook_url = wh.url

    await db.delete(wh)
    await db.commit()

    log_security_action(
        "webhook_deleted",
        user_id=current_user.id,
        role=current_user.role,
        resource="webhook",
        resource_id=webhook_id,
        detail=f"url={webhook_url!r}",
    )


@router.post("/{webhook_id}/test", response_model=WebhookTestResult)
async def test_webhook(
    webhook_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
):
    """
    Send a signed test payload to the webhook URL.

    Returns delivery result (status code, latency, success flag).
    The secret is used to sign the payload but never returned.
    """
    wh = await _get_webhook_or_404(webhook_id, db)
    _assert_owner_or_admin(wh, current_user)

    test_payload = {
        "event": "test",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": {
            "message": "ASC PremosCorp webhook test delivery",
            "webhook_id": wh.id,
            "triggered_by": current_user.id,
        },
    }

    success, status_code, latency_ms, error = await deliver_to_url(
        wh.url, wh.secret, "test", test_payload
    )

    # Update stats
    wh.last_triggered_at = datetime.now(timezone.utc)
    if success:
        wh.failure_count = 0
    else:
        wh.failure_count += 1
    await db.commit()

    log_security_action(
        "webhook_test",
        user_id=current_user.id,
        role=current_user.role,
        resource="webhook",
        resource_id=webhook_id,
        detail=f"url={wh.url!r} success={success} status_code={status_code} latency_ms={latency_ms}",
    )

    return WebhookTestResult(
        success=success,
        status_code=status_code,
        latency_ms=latency_ms,
        error=error,
    )


@router.get("/admin/all", response_model=list[WebhookResponse])
async def admin_list_all_webhooks(
    _: Annotated[User, Depends(get_current_admin)],
    db: AsyncSession = Depends(get_db),
):
    """Admin-only: list all webhooks across all users within the current tenant."""
    stmt = apply_tenant_filter(
        select(Webhook).order_by(Webhook.created_at.desc()), Webhook
    )
    result = await db.execute(stmt)
    return result.scalars().all()
