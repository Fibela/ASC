"""
P51 — Tenant Middleware
========================
Resolves the current tenant from each request and stores it in the
per-request ContextVar so that query helpers can filter data accordingly.

Resolution order (first match wins):
  1. JWT claim   — `tenant_id` field in the Bearer token payload
  2. X-Tenant-ID — explicit header (reserved for admin/internal tooling)

If neither source provides a tenant ID, the request is treated as
single-tenant (tenant_id = None), which matches pre-P51 behavior.

Security notes:
  - X-Tenant-ID is NOT validated against a tenant table here — callers that
    need strict header validation must do so in their own dependencies.
  - An invalid or expired JWT causes silent fallback to None, not a 401.
    The actual auth gate lives in get_current_user() / _resolve_user() inside
    deps.py. Middleware only extracts context; it does not reject requests.
  - The ContextVar is reset to None in the finally block so connection-pool
    goroutine reuse never leaks a previous request's tenant.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from asc_api.core.security import decode_token_payload
from asc_api.core.tenant_context import set_tenant_id


class TenantMiddleware(BaseHTTPMiddleware):
    """Extract tenant_id from JWT or X-Tenant-ID header and store in ContextVar."""

    async def dispatch(self, request: Request, call_next) -> Response:
        tenant_id: str | None = None

        # 1. Try JWT Bearer token first
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[len("Bearer ") :]
            payload = decode_token_payload(token)
            tenant_id = payload.get("tenant_id") or None

        # SECURITY (S103.2): el tenant del contexto se deriva SOLO del claim
        # firmado del JWT. El header X-Tenant-ID (entrada no autenticada, previa
        # al gate de auth) ya NO puede sobrescribir el tenant — antes permitía a
        # un admin del tenant A leer datos del tenant B con un simple header
        # (IDOR cross-tenant, OWASP A01). deps._resolve_user además re-liga el
        # contexto al tenant del usuario autenticado como defensa en profundidad.
        # Si en el futuro se requiere impersonación cross-tenant para tooling
        # interno, debe implementarse como dependencia explícita con chequeo de
        # rol y auditoría — nunca como un header de confianza.
        set_tenant_id(tenant_id)
        try:
            return await call_next(request)
        finally:
            set_tenant_id(None)
