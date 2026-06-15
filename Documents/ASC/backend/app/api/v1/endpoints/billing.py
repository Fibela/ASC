"""
P55 — Billing / Metering endpoints.

Endpoints:
  GET  /billing/usage                   — current tenant monthly usage summary
  GET  /billing/usage/{tenant_id}       — admin: usage for a specific tenant
  POST /billing/snapshot                — admin: trigger manual usage snapshot
  POST /billing/stripe/webhook          — Stripe webhook receiver (sig-validated stub)

UsageRecord is a monthly snapshot (YYYY-MM) per tenant per resource_type.
Re-running snapshot for the same period+resource is an upsert (ON CONFLICT DO UPDATE).
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_admin, get_current_user
from app.core.audit import log_security_action
from app.core.config import get_settings
from app.db.session import get_db
from app.models.alert import Alert
from app.models.api_key import APIKey
from app.models.incident import Incident
from app.models.tenant import Tenant
from app.models.usage_record import UsageRecord
from app.models.user import User
from app.models.webhook import Webhook

router = APIRouter(prefix="/billing", tags=["Billing"])
_settings = get_settings()

# ── Resource types ─────────────────────────────────────────────────────────────

RESOURCE_TYPES = ("users", "alerts", "api_keys", "webhooks", "incidents")


# ── Schemas ───────────────────────────────────────────────────────────────────

class UsageSummaryItem(BaseModel):
    resource_type: str
    count: int
    period: str


class UsageSummaryResponse(BaseModel):
    tenant_id: str
    period: str
    items: list[UsageSummaryItem]


class SnapshotResponse(BaseModel):
    tenant_id: str
    period: str
    records_written: int
    items: list[UsageSummaryItem]


class WebhookAckResponse(BaseModel):
    received: bool


# ── Helpers ───────────────────────────────────────────────────────────────────

def _current_period() -> str:
    """Return current billing period in YYYY-MM format."""
    return datetime.now(timezone.utc).strftime("%Y-%m")


async def _count_resource(resource: str, tenant_id: str, db: AsyncSession) -> int:
    """Count active records for a resource type within a tenant."""
    if resource == "users":
        result = await db.execute(
            select(func.count()).where(
                User.tenant_id == tenant_id,
                User.is_active == True,  # noqa: E712
            )
        )
    elif resource == "alerts":
        result = await db.execute(
            select(func.count()).where(Alert.tenant_id == tenant_id)
        )
    elif resource == "api_keys":
        result = await db.execute(
            select(func.count()).where(
                APIKey.tenant_id == tenant_id,
                APIKey.is_active == True,  # noqa: E712
            )
        )
    elif resource == "webhooks":
        result = await db.execute(
            select(func.count()).where(
                Webhook.tenant_id == tenant_id,
                Webhook.is_active == True,  # noqa: E712
            )
        )
    elif resource == "incidents":
        result = await db.execute(
            select(func.count()).where(Incident.tenant_id == tenant_id)
        )
    else:
        return 0
    return result.scalar_one()


async def _upsert_usage_record(
    tenant_id: str,
    period: str,
    resource_type: str,
    count: int,
    db: AsyncSession,
) -> None:
    """Insert or update a usage record (PostgreSQL upsert)."""
    import uuid  # local to avoid polluting module namespace
    stmt = pg_insert(UsageRecord).values(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        period=period,
        resource_type=resource_type,
        count=count,
        recorded_at=datetime.now(timezone.utc),
    ).on_conflict_do_update(
        constraint="uq_usage_tenant_period_resource",
        set_={"count": count, "recorded_at": datetime.now(timezone.utc)},
    )
    await db.execute(stmt)


async def _get_tenant_or_404(tenant_id: str, db: AsyncSession) -> Tenant:
    result = await db.execute(select(Tenant).where(Tenant.id == tenant_id))
    tenant = result.scalar_one_or_none()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant no encontrado")
    return tenant


def _verify_stripe_signature(payload_bytes: bytes, sig_header: str, secret: str) -> bool:
    """
    Validate a Stripe webhook signature (simplified version of stripe-python).

    Stripe sends:  Stripe-Signature: t=<timestamp>,v1=<hmac_hex>
    We verify:     HMAC-SHA256(secret, f"{timestamp}.{payload}") == v1
    """
    try:
        parts = {kv.split("=")[0]: kv.split("=")[1] for kv in sig_header.split(",")}
        timestamp = parts["t"]
        expected = parts["v1"]
    except (KeyError, IndexError, ValueError):
        return False

    signed_payload = f"{timestamp}.".encode() + payload_bytes
    mac = hmac.new(secret.encode(), signed_payload, hashlib.sha256)
    computed = mac.hexdigest()
    return hmac.compare_digest(computed, expected)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/usage", response_model=UsageSummaryResponse)
async def get_my_usage(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Return the latest stored usage snapshot for the current tenant.

    Shows the most recent UsageRecord per resource_type.
    If no snapshot has been taken, returns counts of 0.
    """
    tenant_id = current_user.tenant_id
    if not tenant_id:
        raise HTTPException(
            status_code=400,
            detail="Usuario sin tenant asignado",
        )

    period = _current_period()
    result = await db.execute(
        select(UsageRecord).where(
            UsageRecord.tenant_id == tenant_id,
            UsageRecord.period == period,
        )
    )
    records = result.scalars().all()
    record_map = {r.resource_type: r.count for r in records}

    items = [
        UsageSummaryItem(resource_type=rt, count=record_map.get(rt, 0), period=period)
        for rt in RESOURCE_TYPES
    ]
    return UsageSummaryResponse(tenant_id=tenant_id, period=period, items=items)


@router.get("/usage/{tenant_id}", response_model=UsageSummaryResponse)
async def get_tenant_usage(
    tenant_id: str,
    _: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """Admin: return usage snapshot for any tenant by ID."""
    await _get_tenant_or_404(tenant_id, db)

    period = _current_period()
    result = await db.execute(
        select(UsageRecord).where(
            UsageRecord.tenant_id == tenant_id,
            UsageRecord.period == period,
        )
    )
    records = result.scalars().all()
    record_map = {r.resource_type: r.count for r in records}

    items = [
        UsageSummaryItem(resource_type=rt, count=record_map.get(rt, 0), period=period)
        for rt in RESOURCE_TYPES
    ]
    return UsageSummaryResponse(tenant_id=tenant_id, period=period, items=items)


@router.post("/snapshot", response_model=SnapshotResponse)
async def take_snapshot(
    _: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """
    Admin: take a live usage snapshot for the admin's own tenant.

    Counts current active resources and upserts UsageRecord rows for the current
    billing period. Idempotent — safe to call multiple times per period.
    """
    admin_result = await db.execute(select(User).where(User.id == _.__class__))  # type: ignore[attr-defined]
    # Re-fetch admin from dependency via the passed user object
    admin_user: User = _
    tenant_id = admin_user.tenant_id
    if not tenant_id:
        raise HTTPException(status_code=400, detail="Admin sin tenant asignado")

    period = _current_period()
    items: list[UsageSummaryItem] = []

    for rt in RESOURCE_TYPES:
        count = await _count_resource(rt, tenant_id, db)
        await _upsert_usage_record(tenant_id, period, rt, count, db)
        items.append(UsageSummaryItem(resource_type=rt, count=count, period=period))

    await db.commit()

    log_security_action(
        "billing.snapshot_taken",
        user_id=admin_user.id,
        extra={"tenant_id": tenant_id, "period": period, "records": len(items)},
    )

    return SnapshotResponse(
        tenant_id=tenant_id,
        period=period,
        records_written=len(items),
        items=items,
    )


@router.post(
    "/stripe/webhook",
    response_model=WebhookAckResponse,
    status_code=status.HTTP_200_OK,
)
async def stripe_webhook(
    request: Request,
    stripe_signature: str | None = Header(None, alias="Stripe-Signature"),
    db: AsyncSession = Depends(get_db),
):
    """
    Stripe webhook receiver (P55 stub).

    When STRIPE_WEBHOOK_SECRET is configured, validates the Stripe-Signature header
    using HMAC-SHA256 (mirrors stripe-python's construct_event logic).
    When the secret is empty (dev/test), signature validation is skipped.

    Currently handles: customer.subscription.updated, customer.subscription.deleted.
    All other event types are acknowledged (200) without action.
    """
    payload_bytes = await request.body()

    # Signature validation (skipped in dev when secret is empty)
    if _settings.STRIPE_WEBHOOK_SECRET:
        if not stripe_signature:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Missing Stripe-Signature header",
            )
        if not _verify_stripe_signature(
            payload_bytes, stripe_signature, _settings.STRIPE_WEBHOOK_SECRET
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid Stripe webhook signature",
            )

    import json  # noqa: PLC0415
    try:
        event = json.loads(payload_bytes)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    event_type = event.get("type", "")
    log_security_action(
        "stripe.webhook_received",
        user_id=None,
        extra={"event_type": event_type, "event_id": event.get("id", "")},
    )

    # Handle subscription updates — update tenant's subscription ID
    if event_type in ("customer.subscription.updated", "customer.subscription.deleted"):
        subscription = event.get("data", {}).get("object", {})
        stripe_customer_id = subscription.get("customer")
        stripe_sub_id = subscription.get("id")
        new_status = subscription.get("status")

        if stripe_customer_id:
            result = await db.execute(
                select(Tenant).where(Tenant.stripe_customer_id == stripe_customer_id)
            )
            tenant = result.scalar_one_or_none()
            if tenant:
                if event_type == "customer.subscription.deleted":
                    tenant.stripe_subscription_id = None
                    tenant.plan = "free"
                else:
                    tenant.stripe_subscription_id = stripe_sub_id
                    if new_status == "active":
                        tenant.plan = "pro"
                await db.commit()

    return WebhookAckResponse(received=True)
