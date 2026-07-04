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
import secrets
import uuid
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.api.deps import get_current_admin, get_current_user
from asc_api.core.audit import log_security_action
from asc_api.core.config import get_settings
from asc_api.core.security import get_password_hash
from asc_api.db.session import get_db
from asc_api.models.alert import Alert
from asc_api.models.api_key import APIKey
from asc_api.models.incident import Incident
from asc_api.models.tenant import Tenant
from asc_api.models.usage_record import UsageRecord
from asc_api.models.user import User
from asc_api.models.webhook import Webhook

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


class PlanFeatures(BaseModel):
    max_users: int | None
    max_api_keys_per_user: int | None
    siem_integration: bool
    threat_hunting: bool
    executive_reports: bool
    soar_playbooks: bool
    support: str


class PlanInfo(BaseModel):
    id: str
    name: str
    price_usd: int | None  # None = contact sales
    billing_period: str
    features: PlanFeatures


class PlansResponse(BaseModel):
    plans: list[PlanInfo]


class SubscriptionResponse(BaseModel):
    plan: str
    stripe_customer_id: str | None
    stripe_subscription_id: str | None
    is_active: bool


class CheckoutRequest(BaseModel):
    plan: str  # "pro" | "enterprise"


class CheckoutResponse(BaseModel):
    checkout_url: str


class PortalResponse(BaseModel):
    portal_url: str


_PLANS: list[dict] = [
    {
        "id": "free",
        "name": "Free",
        "price_usd": 0,
        "billing_period": "month",
        "features": {
            "max_users": 5,
            "max_api_keys_per_user": 3,
            "siem_integration": False,
            "threat_hunting": False,
            "executive_reports": False,
            "soar_playbooks": False,
            "support": "community",
        },
    },
    {
        "id": "pro",
        "name": "Pro",
        "price_usd": 299,
        "billing_period": "month",
        "features": {
            "max_users": 50,
            "max_api_keys_per_user": 20,
            "siem_integration": True,
            "threat_hunting": True,
            "executive_reports": True,
            "soar_playbooks": True,
            "support": "email (24 h SLA)",
        },
    },
    {
        "id": "enterprise",
        "name": "Enterprise",
        "price_usd": None,
        "billing_period": "month",
        "features": {
            "max_users": None,
            "max_api_keys_per_user": None,
            "siem_integration": True,
            "threat_hunting": True,
            "executive_reports": True,
            "soar_playbooks": True,
            "support": "24/7 dedicated",
        },
    },
]


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


# ── P60 — Stripe Checkout Auto-Provisioning ──────────────────────────────────

async def _provision_stripe_customer(
    customer_email: str,
    stripe_customer_id: str,
    stripe_subscription_id: str | None,
    checkout_session_id: str | None,
    db: AsyncSession,
) -> tuple[Tenant, bool]:
    """
    Find or create a Tenant for a Stripe customer.

    Resolution order:
      1. Idempotency: if checkout_session_id already stored → return existing
      2. Lookup by stripe_customer_id → update plan / subscription
      3. Lookup by user email → link their tenant to Stripe
      4. Auto-provision: new Tenant (plan from STRIPE_PROVISIONING_PLAN) +
         admin User with cryptographically random password

    Returns (tenant, provisioned) where provisioned=True only for new tenants.
    """
    # 0. Idempotency guard
    if checkout_session_id:
        result = await db.execute(
            select(Tenant).where(Tenant.stripe_checkout_session_id == checkout_session_id)
        )
        existing = result.scalar_one_or_none()
        if existing:
            return existing, False

    # 1. Lookup by stripe_customer_id
    if stripe_customer_id:
        result = await db.execute(
            select(Tenant).where(Tenant.stripe_customer_id == stripe_customer_id)
        )
        tenant = result.scalar_one_or_none()
        if tenant:
            tenant.plan = _settings.STRIPE_PROVISIONING_PLAN
            if stripe_subscription_id:
                tenant.stripe_subscription_id = stripe_subscription_id
            if checkout_session_id:
                tenant.stripe_checkout_session_id = checkout_session_id
            await db.commit()
            return tenant, False

    # 2. Lookup by email → link existing ASC user's tenant
    result = await db.execute(select(User).where(User.email == customer_email))
    existing_user = result.scalar_one_or_none()
    if existing_user and existing_user.tenant_id:
        result = await db.execute(
            select(Tenant).where(Tenant.id == existing_user.tenant_id)
        )
        tenant = result.scalar_one_or_none()
        if tenant:
            tenant.stripe_customer_id = stripe_customer_id
            tenant.plan = _settings.STRIPE_PROVISIONING_PLAN
            tenant.contact_email = customer_email
            if stripe_subscription_id:
                tenant.stripe_subscription_id = stripe_subscription_id
            if checkout_session_id:
                tenant.stripe_checkout_session_id = checkout_session_id
            await db.commit()
            return tenant, False

    # 3. Auto-provision: new Tenant + admin User
    now = datetime.now(timezone.utc)
    tenant_id = str(uuid.uuid4())
    slug = customer_email.split("@")[0].lower().replace(".", "-")[:50]

    tenant = Tenant(
        id=tenant_id,
        name=f"{slug} (Stripe)",
        slug=f"{slug}-{tenant_id[:8]}",
        plan=_settings.STRIPE_PROVISIONING_PLAN,
        is_active=True,
        contact_email=customer_email,
        stripe_customer_id=stripe_customer_id,
        stripe_subscription_id=stripe_subscription_id,
        stripe_checkout_session_id=checkout_session_id,
        created_at=now,
    )
    db.add(tenant)

    user = User(
        id=str(uuid.uuid4()),
        email=customer_email,
        full_name=customer_email.split("@")[0].replace(".", " ").title(),
        hashed_password=get_password_hash(secrets.token_urlsafe(32)),
        role="admin",
        is_active=True,
        email_verified=True,
        onboarding_step="completed",
        tenant_id=tenant_id,
        created_at=now,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return tenant, True


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/plans", response_model=PlansResponse)
async def list_plans():
    """Return available ASC subscription plans. No authentication required."""
    return PlansResponse(plans=[PlanInfo(**p) for p in _PLANS])


@router.get("/subscription", response_model=SubscriptionResponse)
async def get_subscription(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return the current tenant's active plan and Stripe subscription status."""
    result = await db.execute(select(Tenant).where(Tenant.id == current_user.tenant_id))
    tenant = result.scalar_one_or_none()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant no encontrado")
    return SubscriptionResponse(
        plan=tenant.plan,
        stripe_customer_id=tenant.stripe_customer_id,
        stripe_subscription_id=tenant.stripe_subscription_id,
        is_active=tenant.is_active,
    )


@router.post("/checkout", response_model=CheckoutResponse)
async def create_checkout_session(
    body: CheckoutRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Create a Stripe Checkout session for the requested plan.

    Returns a redirect URL — the frontend should redirect the user there.
    Stripe calls POST /billing/stripe/webhook on completion to provision the plan.
    """
    if not _settings.STRIPE_SECRET_KEY:
        raise HTTPException(status_code=503, detail="Stripe billing no está configurado")

    price_id_map = {
        "pro": _settings.STRIPE_PRICE_PRO,
        "enterprise": _settings.STRIPE_PRICE_ENTERPRISE,
    }
    price_id = price_id_map.get(body.plan, "")
    if not price_id:
        raise HTTPException(
            status_code=400,
            detail=f"Plan '{body.plan}' no disponible para self-serve checkout. Contacta ventas.",
        )

    result = await db.execute(select(Tenant).where(Tenant.id == current_user.tenant_id))
    tenant = result.scalar_one_or_none()

    payload: dict = {
        "mode": "subscription",
        "line_items[0][price]": price_id,
        "line_items[0][quantity]": "1",
        "success_url": _settings.STRIPE_SUCCESS_URL,
        "cancel_url": _settings.STRIPE_CANCEL_URL,
        "metadata[tenant_id]": str(current_user.tenant_id),
        "metadata[user_id]": str(current_user.id),
    }
    # Pre-fill email / link to existing Stripe customer if available
    if tenant and tenant.stripe_customer_id:
        payload["customer"] = tenant.stripe_customer_id
    else:
        payload["customer_email"] = current_user.email

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                "https://api.stripe.com/v1/checkout/sessions",
                auth=(_settings.STRIPE_SECRET_KEY, ""),
                data=payload,
            )
        if resp.status_code != 200:
            log_security_action(
                "stripe.checkout_error",
                user_id=str(current_user.id),
                extra={"status": resp.status_code, "body": resp.text[:500]},
            )
            raise HTTPException(status_code=502, detail="Error al crear sesión de pago con Stripe")
        session = resp.json()
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail=f"No se pudo conectar con Stripe: {exc}")

    log_security_action(
        "stripe.checkout_created",
        user_id=str(current_user.id),
        extra={"plan": body.plan, "session_id": session.get("id", "")},
    )
    return CheckoutResponse(checkout_url=session["url"])


@router.post("/portal", response_model=PortalResponse)
async def create_portal_session(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Create a Stripe Customer Portal session for the current tenant.

    The portal lets customers manage their subscription, update payment info, and cancel.
    Requires the tenant to have a stripe_customer_id (i.e. they've paid at least once).
    """
    if not _settings.STRIPE_SECRET_KEY:
        raise HTTPException(status_code=503, detail="Stripe billing no está configurado")

    result = await db.execute(select(Tenant).where(Tenant.id == current_user.tenant_id))
    tenant = result.scalar_one_or_none()
    if not tenant or not tenant.stripe_customer_id:
        raise HTTPException(
            status_code=400,
            detail="No existe una suscripción activa asociada a este tenant",
        )

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                "https://api.stripe.com/v1/billing_portal/sessions",
                auth=(_settings.STRIPE_SECRET_KEY, ""),
                data={
                    "customer": tenant.stripe_customer_id,
                    "return_url": _settings.STRIPE_SUCCESS_URL,
                },
            )
        if resp.status_code != 200:
            raise HTTPException(status_code=502, detail="Error al abrir portal de Stripe")
        portal = resp.json()
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail=f"No se pudo conectar con Stripe: {exc}")

    return PortalResponse(portal_url=portal["url"])


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

    # ── P60: checkout.session.completed → provision / upgrade tenant ──────────
    if event_type == "checkout.session.completed":
        session = event.get("data", {}).get("object", {})
        customer_email: str = (
            session.get("customer_email")
            or session.get("customer_details", {}).get("email", "")
        )
        stripe_customer_id: str = session.get("customer", "")
        stripe_subscription_id: str | None = session.get("subscription")
        checkout_session_id: str = session.get("id", "")

        # Optional product filter: skip if a product ID is configured and doesn't match
        product_id_filter = _settings.STRIPE_SEGURIDAD_PRODUCT_ID
        if product_id_filter:
            metadata = session.get("metadata", {})
            if metadata.get("product_id") != product_id_filter:
                return WebhookAckResponse(received=True)

        if customer_email and stripe_customer_id:
            tenant, provisioned = await _provision_stripe_customer(
                customer_email,
                stripe_customer_id,
                stripe_subscription_id,
                checkout_session_id,
                db,
            )
            log_security_action(
                "stripe.tenant_provisioned" if provisioned else "stripe.tenant_upgraded",
                user_id=None,
                extra={
                    "tenant_id": tenant.id,
                    "stripe_customer_id": stripe_customer_id,
                    "plan": _settings.STRIPE_PROVISIONING_PLAN,
                    "provisioned": provisioned,
                },
            )

    # ── P60: customer.subscription.created → link subscription to tenant ──────
    elif event_type == "customer.subscription.created":
        subscription = event.get("data", {}).get("object", {})
        stripe_customer_id = subscription.get("customer", "")
        stripe_sub_id = subscription.get("id")
        sub_status = subscription.get("status")

        if stripe_customer_id and sub_status == "active":
            result = await db.execute(
                select(Tenant).where(Tenant.stripe_customer_id == stripe_customer_id)
            )
            tenant = result.scalar_one_or_none()
            if tenant:
                tenant.stripe_subscription_id = stripe_sub_id
                tenant.plan = _settings.STRIPE_PROVISIONING_PLAN
                await db.commit()

    # ── P55: subscription updated / deleted ───────────────────────────────────
    elif event_type in ("customer.subscription.updated", "customer.subscription.deleted"):
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
