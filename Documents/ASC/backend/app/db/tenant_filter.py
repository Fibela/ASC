"""
P51 — Tenant Query Filter
==========================
Applies tenant isolation to SQLAlchemy SELECT statements.

Strict isolation model:
  - tenant_id = None  (single-tenant mode) → WHERE model.tenant_id IS NULL
  - tenant_id = "xyz" (multi-tenant mode)  → WHERE model.tenant_id = "xyz"

No cross-tenant fallback to NULL records: once a request carries a tenant_id,
it sees ONLY its own rows. NULL rows (single-tenant legacy data) are invisible
to scoped tenants, preventing data bleed across organizational boundaries.

Usage:
    from app.db.tenant_filter import apply_tenant_filter

    stmt = select(APIKey).where(APIKey.user_id == user.id)
    stmt = apply_tenant_filter(stmt, APIKey)
    result = await db.execute(stmt)
"""

from sqlalchemy import Select

from app.core.tenant_context import get_tenant_id


def apply_tenant_filter(stmt: Select, model) -> Select:
    """
    Append a tenant-scoping WHERE clause to *stmt*.

    The model must have a `tenant_id` mapped column (added in P47).
    Call this immediately before executing the statement so the ContextVar
    reflects the current request's tenant, not a stale outer scope.
    """
    tid = get_tenant_id()
    if tid is None:
        return stmt.where(model.tenant_id.is_(None))
    return stmt.where(model.tenant_id == tid)
