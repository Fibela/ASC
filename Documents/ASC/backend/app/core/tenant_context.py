"""
P51 — Tenant Context (ContextVar)
===================================
Per-request tenant isolation via asyncio ContextVar.

ContextVar is asyncio-safe: each coroutine (and every concurrent request)
gets its own copy of the variable, so concurrent requests never share state.
The value is set by TenantMiddleware at the start of each request and cleared
in the finally block after the response is sent.

Usage in endpoint or service code:
    from asc_api.core.tenant_context import get_tenant_id
    tid = get_tenant_id()   # str | None
"""

from contextvars import ContextVar

_tenant_id: ContextVar[str | None] = ContextVar("tenant_id", default=None)


def set_tenant_id(tid: str | None) -> None:
    _tenant_id.set(tid)


def get_tenant_id() -> str | None:
    return _tenant_id.get()
