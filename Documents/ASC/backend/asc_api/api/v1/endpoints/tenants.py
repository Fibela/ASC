"""
P52 — Tenant Management API
============================
CRUD endpoints for managing tenants in the ASC SaaS multi-tenant platform.

Security model:
  - All write + admin-list operations require role=admin (system-level admin).
  - GET /tenants/me is available to any authenticated user (returns own tenant).
  - Slug: URL-safe identifier — must be lowercase alphanumeric + hyphens, 3-100 chars.
  - Soft delete only: deactivating a tenant sets is_active=False but preserves ALL data.
    Physical deletion requires a separate manual DB operation with business approval.
  - Plan changes are audit-logged with reason field.
  - Stats endpoint returns live resource counts (not cached) — admin only.

Bug#Gap-1 fix (P52):
  get_user_from_api_key() in deps.py did not set tenant context. Users authenticating
  via API key would always get tenant_id=None regardless of their user.tenant_id.
  This is fixed by calling set_tenant_id(user.tenant_id) in get_user_from_api_key.

Endpoints:
  POST   /tenants                          — create tenant (admin)
  GET    /tenants                          — list tenants with pagination (admin)
  GET    /tenants/me                       — get caller's own tenant (any auth user)
  GET    /tenants/{tenant_id}              — get tenant by ID (admin)
  GET    /tenants/{tenant_id}/stats        — resource counts for tenant (admin)
  PATCH  /tenants/{tenant_id}             — update name/contact/plan/limits (admin)
  POST   /tenants/{tenant_id}/activate    — reactivate tenant (admin)
  POST   /tenants/{tenant_id}/deactivate  — soft-deactivate tenant (admin)
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Literal, Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.api.deps import get_current_admin, get_current_user
from asc_api.core.audit import log_security_action
from asc_api.core.tenant_context import get_tenant_id
from asc_api.db.session import get_db
from asc_api.models.alert import Alert
from asc_api.models.api_key import APIKey
from asc_api.models.incident import Incident
from asc_api.models.tenant import Tenant
from asc_api.models.user import User
from asc_api.models.webhook import Webhook

router = APIRouter(prefix="/tenants", tags=["Tenants"])

_SLUG_RE = re.compile(r'^[a-z0-9][a-z0-9-]{1,98}[a-z0-9]$')
_VALID_PLANS: frozenset[str] = frozenset({"free", "pro", "enterprise"})

# ── Schemas ───────────────────────────────────────────────────────────────────


class TenantCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=255,
                      description="Human-readable organization name")
    slug: str = Field(..., min_length=3, max_length=100,
                      description="URL-safe identifier: lowercase letters, digits, hyphens only")
    plan: Literal["free", "pro", "enterprise"] = "free"
    contact_email: EmailStr | None = None
    max_users: int | None = Field(None, ge=1, le=50000,
                                  description="Max active users (None = unlimited)")
    max_api_keys_per_user: int | None = Field(None, ge=1, le=500,
                                               description="Max API keys per user (None = unlimited)")

    @field_validator("slug")
    @classmethod
    def validate_slug(cls, v: str) -> str:
        if not _SLUG_RE.match(v):
            raise ValueError(
                "slug must be 3-100 characters: lowercase letters, digits, and hyphens only. "
                "Must start and end with a letter or digit."
            )
        return v


class TenantUpdate(BaseModel):
    name: str | None = Field(None, min_length=2, max_length=255)
    contact_email: EmailStr | None = None
    max_users: int | None = Field(None, ge=1, le=50000)
    max_api_keys_per_user: int | None = Field(None, ge=1, le=500)


class TenantPlanChange(BaseModel):
    plan: Literal["free", "pro", "enterprise"]
    reason: str = Field(..., min_length=5, max_length=500,
                        description="Business reason for plan change (audit log)")


class TenantRead(BaseModel):
    id: str
    name: str
    slug: str
    plan: str
    is_active: bool
    created_at: datetime
    contact_email: str | None
    max_users: int | None
    max_api_keys_per_user: int | None

    model_config = {"from_attributes": True}


class TenantStats(BaseModel):
    tenant_id: str
    user_count: int
    alert_count: int
    api_key_count: int
    webhook_count: int
    incident_count: int


class TenantListResponse(BaseModel):
    items: list[TenantRead]
    total: int
    page: int
    page_size: int


# ── Helpers ───────────────────────────────────────────────────────────────────


async def _get_tenant_or_404(tenant_id: str, db: AsyncSession) -> Tenant:
    result = await db.execute(select(Tenant).where(Tenant.id == tenant_id))
    tenant = result.scalar_one_or_none()
    if tenant is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail=f"Tenant '{tenant_id}' no encontrado")
    return tenant


async def _assert_slug_unique(slug: str, db: AsyncSession, exclude_id: str | None = None) -> None:
    stmt = select(Tenant).where(Tenant.slug == slug)
    if exclude_id:
        stmt = stmt.where(Tenant.id != exclude_id)
    result = await db.execute(stmt)
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"El slug '{slug}' ya está en uso por otro tenant",
        )


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.post("", response_model=TenantRead, status_code=status.HTTP_201_CREATED)
async def create_tenant(
    body: TenantCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
) -> TenantRead:
    """Create a new tenant. Only system admins can create tenants."""
    await _assert_slug_unique(body.slug, db)

    tenant = Tenant(
        id=str(uuid.uuid4()),
        name=body.name,
        slug=body.slug,
        plan=body.plan,
        contact_email=body.contact_email,
        max_users=body.max_users,
        max_api_keys_per_user=body.max_api_keys_per_user,
        is_active=True,
        created_at=datetime.now(timezone.utc),
    )
    db.add(tenant)
    await db.commit()
    await db.refresh(tenant)

    log_security_action(
        "tenant.created",
        user_id=current_user.id,
        extra={
            "tenant_id": tenant.id,
            "slug": tenant.slug,
            "plan": tenant.plan,
        },
    )
    return TenantRead.model_validate(tenant)


@router.get("", response_model=TenantListResponse)
async def list_tenants(
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
    plan: Annotated[str | None, Query(description="Filter by plan: free|pro|enterprise")] = None,
    active_only: Annotated[bool, Query()] = False,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
) -> TenantListResponse:
    """List all tenants with optional filtering and pagination. Admin only."""
    stmt = select(Tenant)
    if plan is not None:
        if plan not in _VALID_PLANS:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"plan inválido: {plan!r}. Valores válidos: {sorted(_VALID_PLANS)}",
            )
        stmt = stmt.where(Tenant.plan == plan)
    if active_only:
        stmt = stmt.where(Tenant.is_active == True)  # noqa: E712

    # Count before pagination
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = (await db.execute(count_stmt)).scalar_one()

    offset = (page - 1) * page_size
    stmt = stmt.order_by(Tenant.created_at.desc()).offset(offset).limit(page_size)
    result = await db.execute(stmt)
    tenants = result.scalars().all()

    return TenantListResponse(
        items=[TenantRead.model_validate(t) for t in tenants],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/me", response_model=TenantRead)
async def get_my_tenant(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> TenantRead:
    """
    Return the tenant of the currently authenticated user.
    Available to any authenticated user (not admin-only).
    Returns 404 if the user is in single-tenant mode (tenant_id IS NULL).
    """
    tid = current_user.tenant_id or get_tenant_id()
    if tid is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Este usuario no pertenece a ningún tenant (modo single-tenant)",
        )
    return TenantRead.model_validate(await _get_tenant_or_404(tid, db))


@router.get("/{tenant_id}", response_model=TenantRead)
async def get_tenant(
    tenant_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
) -> TenantRead:
    """Get a tenant by ID. Admin only."""
    return TenantRead.model_validate(await _get_tenant_or_404(tenant_id, db))


@router.get("/{tenant_id}/stats", response_model=TenantStats)
async def get_tenant_stats(
    tenant_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
) -> TenantStats:
    """
    Return live resource counts for a tenant.
    Counts users, alerts, api_keys, webhooks, and incidents scoped to this tenant.
    Admin only.
    """
    # Verify tenant exists
    await _get_tenant_or_404(tenant_id, db)

    async def _count(model, col_attr) -> int:
        result = await db.execute(
            select(func.count()).where(col_attr == tenant_id)
        )
        return result.scalar_one()

    user_count     = await _count(User,     User.tenant_id)
    alert_count    = await _count(Alert,    Alert.tenant_id)
    api_key_count  = await _count(APIKey,   APIKey.tenant_id)
    webhook_count  = await _count(Webhook,  Webhook.tenant_id)
    incident_count = await _count(Incident, Incident.tenant_id)

    return TenantStats(
        tenant_id=tenant_id,
        user_count=user_count,
        alert_count=alert_count,
        api_key_count=api_key_count,
        webhook_count=webhook_count,
        incident_count=incident_count,
    )


@router.patch("/{tenant_id}", response_model=TenantRead)
async def update_tenant(
    tenant_id: str,
    body: TenantUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
) -> TenantRead:
    """
    Update tenant metadata (name, contact_email, resource limits).
    For plan changes use PATCH /tenants/{id}/plan to enforce audit trail.
    Admin only.
    """
    tenant = await _get_tenant_or_404(tenant_id, db)

    changed: dict = {}
    if body.name is not None and body.name != tenant.name:
        tenant.name = body.name
        changed["name"] = body.name
    if body.contact_email is not None and body.contact_email != tenant.contact_email:
        tenant.contact_email = body.contact_email
        changed["contact_email"] = body.contact_email
    if body.max_users is not None and body.max_users != tenant.max_users:
        tenant.max_users = body.max_users
        changed["max_users"] = body.max_users
    if body.max_api_keys_per_user is not None and body.max_api_keys_per_user != tenant.max_api_keys_per_user:
        tenant.max_api_keys_per_user = body.max_api_keys_per_user
        changed["max_api_keys_per_user"] = body.max_api_keys_per_user

    if changed:
        await db.commit()
        await db.refresh(tenant)
        log_security_action(
            "tenant.updated",
            user_id=current_user.id,
            extra={"tenant_id": tenant_id, "changes": changed},
        )

    return TenantRead.model_validate(tenant)


@router.patch("/{tenant_id}/plan", response_model=TenantRead)
async def change_tenant_plan(
    tenant_id: str,
    body: TenantPlanChange,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
) -> TenantRead:
    """
    Change a tenant's subscription plan.
    Requires a reason field (audit trail requirement).
    Admin only.
    """
    tenant = await _get_tenant_or_404(tenant_id, db)
    old_plan = tenant.plan

    if old_plan == body.plan:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"El tenant ya está en el plan '{body.plan}'",
        )

    tenant.plan = body.plan
    await db.commit()
    await db.refresh(tenant)

    log_security_action(
        "tenant.plan_changed",
        user_id=current_user.id,
        extra={
            "tenant_id": tenant_id,
            "old_plan": old_plan,
            "new_plan": body.plan,
            "reason": body.reason,
        },
    )
    return TenantRead.model_validate(tenant)


@router.post("/{tenant_id}/activate", response_model=TenantRead)
async def activate_tenant(
    tenant_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
) -> TenantRead:
    """Reactivate a previously deactivated tenant. Admin only."""
    tenant = await _get_tenant_or_404(tenant_id, db)

    if tenant.is_active:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="El tenant ya está activo",
        )

    tenant.is_active = True
    await db.commit()
    await db.refresh(tenant)

    log_security_action(
        "tenant.activated",
        user_id=current_user.id,
        extra={"tenant_id": tenant_id, "slug": tenant.slug},
    )
    return TenantRead.model_validate(tenant)


@router.post("/{tenant_id}/deactivate", response_model=TenantRead)
async def deactivate_tenant(
    tenant_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
) -> TenantRead:
    """
    Soft-deactivate a tenant (sets is_active=False).
    All tenant data is preserved. Tenant users can no longer authenticate.
    This action is reversible via POST /tenants/{id}/activate.
    Admin only.
    """
    tenant = await _get_tenant_or_404(tenant_id, db)

    if not tenant.is_active:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="El tenant ya está inactivo",
        )

    tenant.is_active = False
    await db.commit()
    await db.refresh(tenant)

    log_security_action(
        "tenant.deactivated",
        user_id=current_user.id,
        extra={"tenant_id": tenant_id, "slug": tenant.slug},
    )
    return TenantRead.model_validate(tenant)
