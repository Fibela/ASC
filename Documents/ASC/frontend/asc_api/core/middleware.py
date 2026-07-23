"""
ASC Middleware Stack — P17 Hardening / P39 Observability / P41 Rate Limiting.

Middleware classes (added to app in main.py — last added = outermost = runs first):
  SecurityHeadersMiddleware    — HSTS, X-Frame-Options, CSP, etc.
  BodySizeLimitMiddleware      — 413 on oversized request bodies
  RequestContextMiddleware     — X-Request-ID + structured access log + Prometheus metrics
  ApiKeyRateLimitMiddleware    — P41: sliding window per-API-key rate limiting
"""

import time
import uuid

import structlog
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from asc_api.core.api_key_rate_limit import api_key_limiter
from asc_api.core.audit import log_security_action

# Prometheus metrics — imported lazily to avoid test-import ordering issues
try:
    from asc_api.core.metrics_registry import HTTP_DURATION, HTTP_REQUESTS, _normalize_path

    _METRICS_ENABLED = True
except Exception:  # pragma: no cover
    _METRICS_ENABLED = False

_log = structlog.get_logger("asc.request")


# ── Security Headers ──────────────────────────────────────────────────────────


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Inject security-hardening HTTP response headers on every response.

    HSTS is only set when DEBUG=False — localhost dev sessions must not be
    HSTS-pinned (impossible to undo without browser clearing).

    CSP is tuned for a pure API: default-src 'none' allows nothing by default.
    Clients serving HTML/JS (Next.js) manage their own CSP via next.config.js.
    """

    def __init__(self, app, *, debug: bool = False) -> None:
        super().__init__(app)
        self._debug = debug

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        h = response.headers
        h["X-Content-Type-Options"] = "nosniff"
        h["X-Frame-Options"] = "DENY"
        h["X-XSS-Protection"] = "1; mode=block"
        h["Referrer-Policy"] = "strict-origin-when-cross-origin"
        h["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        h["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        if not self._debug:
            h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        return response


# ── Body Size Limit ───────────────────────────────────────────────────────────


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """
    Reject requests whose Content-Length exceeds max_bytes with HTTP 413.

    Protects against payload-bombing: a client sending a 500 MB body to a
    JSON endpoint would otherwise consume memory before FastAPI's parser
    could respond.  Checked at header level — no body is read.
    """

    def __init__(self, app, *, max_bytes: int) -> None:
        super().__init__(app)
        self._max = max_bytes

    async def dispatch(self, request: Request, call_next) -> Response:
        cl = request.headers.get("content-length")
        if cl is not None:
            try:
                if int(cl) > self._max:
                    limit_mb = self._max // (1024 * 1024)
                    return JSONResponse(
                        status_code=413,
                        content={"detail": f"Request body too large. Maximum allowed: {limit_mb} MB."},
                    )
            except ValueError:
                pass  # malformed Content-Length — let FastAPI handle it
        return await call_next(request)


# ── Request Context ───────────────────────────────────────────────────────────


class RequestContextMiddleware(BaseHTTPMiddleware):
    """
    Starlette middleware that:
      1. Reads (or generates) X-Request-ID.
      2. Clears and re-binds structlog contextvars for the request scope.
      3. Calls the next handler and writes back X-Request-ID to the response.
      4. Logs method / path / status_code / duration_ms on every completed request.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        start = time.monotonic()

        # Bind request_id into structlog contextvars so all downstream
        # log statements automatically include it — no manual passing needed.
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)

        try:
            response = await call_next(request)
        except Exception as exc:
            duration_ms = round((time.monotonic() - start) * 1000, 1)
            _log.error(
                "http_request_error",
                method=request.method,
                path=str(request.url.path),
                duration_ms=duration_ms,
                error=type(exc).__name__,
                detail=str(exc),
            )
            raise

        duration_ms = round((time.monotonic() - start) * 1000, 1)
        duration_s = time.monotonic() - start
        _log.info(
            "http_request",
            method=request.method,
            path=str(request.url.path),
            status_code=response.status_code,
            duration_ms=duration_ms,
        )

        # Record Prometheus metrics (no-op if prometheus_client not available)
        if _METRICS_ENABLED:
            endpoint = _normalize_path(str(request.url.path))
            HTTP_REQUESTS.labels(
                method=request.method,
                endpoint=endpoint,
                status_code=str(response.status_code),
            ).inc()
            HTTP_DURATION.labels(method=request.method, endpoint=endpoint).observe(duration_s)

        response.headers["X-Request-ID"] = request_id
        return response


# ── API Key Rate Limiting ─────────────────────────────────────────────────────


class ApiKeyRateLimitMiddleware(BaseHTTPMiddleware):
    """
    P41 — Sliding window rate limiting for X-API-Key authenticated requests.

    Enforces two windows simultaneously (both must pass):
      • per-minute  — burst control   (X-RateLimit-Limit-Minute)
      • per-hour    — throughput cap  (X-RateLimit-Limit-Hour)

    The rate-limit key is the 8-char key_prefix extracted from the standard
    ASC key format `asc_{prefix}_{secret}`.  The raw key and HMAC hash are
    never read by this middleware.

    JWT-authenticated requests (no X-API-Key header) pass through unaffected.
    Requests with a malformed key format are forwarded to the auth dep which
    will reject them with 401 — no rate-limit slot is consumed.

    Fail-open: if the backend (Redis or memory) raises an unexpected error,
    the request is allowed through and the error is logged to asc.rate_limit.

    Response headers (on every API-key request, allowed or blocked):
      X-RateLimit-Limit-Minute      per-minute limit
      X-RateLimit-Remaining-Minute  remaining requests this minute
      X-RateLimit-Limit-Hour        per-hour limit
      X-RateLimit-Remaining-Hour    remaining requests this hour
      X-RateLimit-Reset             Unix timestamp of next minute-window reset

    On 429:
      Retry-After  seconds until the client may retry
    """

    def __init__(self, app, *, limit_per_minute: int, limit_per_hour: int) -> None:
        super().__init__(app)
        self._lpm = limit_per_minute
        self._lph = limit_per_hour

    async def dispatch(self, request: Request, call_next) -> Response:
        raw_key = request.headers.get("X-API-Key")
        if not raw_key:
            # JWT path — not subject to API-key rate limiting
            return await call_next(request)

        # Extract 8-char prefix — safe to use as rate-limit key (never the secret)
        parts = raw_key.split("_", 2)
        if len(parts) != 3 or parts[0] != "asc" or len(parts[1]) != 8:
            # Malformed key — let the auth dep handle it, skip rate-limiting
            return await call_next(request)

        prefix = parts[1]

        # Check both windows (each call counts this request)
        minute_result = await api_key_limiter.check(prefix, self._lpm, 60)
        hour_result = await api_key_limiter.check(prefix, self._lph, 3600)

        blocked = not minute_result.allowed or not hour_result.allowed
        retry_after = max(minute_result.retry_after, hour_result.retry_after)
        reset_at = minute_result.reset_at  # minute window resets sooner

        if blocked:
            # Ledger Premos — every rate limit breach is audit-logged
            log_security_action(
                "api_key_rate_limited",
                detail=(
                    f"prefix=asc_{prefix}… "
                    f"minute={minute_result.remaining}/{self._lpm} "
                    f"hour={hour_result.remaining}/{self._lph}"
                ),
                status="blocked",
            )
            return JSONResponse(
                status_code=429,
                content={
                    "detail": f"Rate limit exceeded. Retry after {retry_after} seconds.",
                    "retry_after": retry_after,
                },
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit-Minute": str(self._lpm),
                    "X-RateLimit-Remaining-Minute": str(minute_result.remaining),
                    "X-RateLimit-Limit-Hour": str(self._lph),
                    "X-RateLimit-Remaining-Hour": str(hour_result.remaining),
                    "X-RateLimit-Reset": str(reset_at),
                },
            )

        response = await call_next(request)
        # Attach rate limit telemetry to every allowed response
        response.headers["X-RateLimit-Limit-Minute"] = str(self._lpm)
        response.headers["X-RateLimit-Remaining-Minute"] = str(minute_result.remaining)
        response.headers["X-RateLimit-Limit-Hour"] = str(self._lph)
        response.headers["X-RateLimit-Remaining-Hour"] = str(hour_result.remaining)
        response.headers["X-RateLimit-Reset"] = str(reset_at)
        return response
