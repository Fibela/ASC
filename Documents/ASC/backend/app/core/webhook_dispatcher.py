"""
P42 — Webhook Dispatcher (Toque Premos).

Responsibilities
----------------
1. sign_payload(secret, body)  — HMAC-SHA256 signing identical to the GitHub/Stripe model.
2. deliver_to_url(...)         — Single async HTTP delivery with timeout and result capture.
3. emit_webhook_event(...)     — Query active webhooks for an event, fire delivery tasks.

Signing protocol
----------------
Outgoing requests carry:
    X-ASC-Signature: sha256=<64-hex-chars>
    X-ASC-Event:     <event_type>
    X-ASC-Delivery:  <uuid>  (unique per attempt)

Recipients verify:
    import hmac, hashlib
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert hmac.compare_digest(expected, request.headers["X-ASC-Signature"])

Delivery policy
---------------
• 10-second total timeout per attempt (connect 5 s, read 5 s).
• A 2xx status code is considered success; anything else is a failure.
• Failures increment webhook.failure_count, successes reset it to 0.
• Fire-and-forget via asyncio.create_task — delivery never blocks the caller.
• On delivery error (network failure, timeout) the exception is caught and logged;
  the webhook is NOT deactivated automatically at P42 (policy for a future sprint).

Toque Premos guarantees
-----------------------
• Secret never logged, echoed, or included in error payloads.
• Delivery ID (UUID) in X-ASC-Delivery makes each attempt uniquely auditable.
• All delivery outcomes (success + failure) are logged to asc.webhook.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac as _hmac
import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
import structlog

_log = structlog.get_logger("asc.webhook")

# Max concurrent in-flight delivery tasks per emit_webhook_event call
_MAX_CONCURRENT_DELIVERIES = 20
_DELIVERY_TIMEOUT = httpx.Timeout(connect=5.0, read=5.0, write=5.0, pool=5.0)


# ── Signing ───────────────────────────────────────────────────────────────────

def sign_payload(secret: str, body: bytes) -> str:
    """
    Return HMAC-SHA256 hex digest of body keyed with secret.
    Produces the value placed in the `X-ASC-Signature: sha256=<digest>` header.
    """
    mac = _hmac.new(secret.encode(), body, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


def verify_signature(secret: str, body: bytes, signature_header: str) -> bool:
    """
    Constant-time verification of an incoming X-ASC-Signature header.
    Exposed for use in tests and the test-delivery endpoint.
    """
    expected = sign_payload(secret, body)
    return _hmac.compare_digest(expected, signature_header)


# ── Single delivery ───────────────────────────────────────────────────────────

async def deliver_to_url(
    url: str,
    secret: str,
    event_type: str,
    payload: dict[str, Any],
) -> tuple[bool, int | None, float, str | None]:
    """
    Sign and POST `payload` to `url`.

    Returns (success, status_code, latency_ms, error_message).
    Never raises — all exceptions are caught and returned as (False, None, ..., str(exc)).
    """
    delivery_id = str(uuid.uuid4())
    body = json.dumps(payload, default=str).encode()
    signature = sign_payload(secret, body)
    headers = {
        "Content-Type": "application/json",
        "X-ASC-Event": event_type,
        "X-ASC-Signature": signature,
        "X-ASC-Delivery": delivery_id,
        "User-Agent": "ASC-PremosCorp-Webhook/1.0",
    }

    t0 = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=_DELIVERY_TIMEOUT) as client:
            response = await client.post(url, content=body, headers=headers)
        latency_ms = round((time.monotonic() - t0) * 1000, 1)
        success = 200 <= response.status_code < 300
        _log.info(
            "webhook_delivery",
            delivery_id=delivery_id,
            webhook_event=event_type,
            url=url,
            status_code=response.status_code,
            latency_ms=latency_ms,
            success=success,
        )
        return success, response.status_code, latency_ms, None
    except Exception as exc:
        latency_ms = round((time.monotonic() - t0) * 1000, 1)
        error_msg = f"{type(exc).__name__}: {exc}"
        _log.warning(
            "webhook_delivery_error",
            delivery_id=delivery_id,
            webhook_event=event_type,
            url=url,
            latency_ms=latency_ms,
            error=error_msg,
        )
        return False, None, latency_ms, error_msg


# ── Background delivery task ──────────────────────────────────────────────────

async def _deliver_webhook_background(webhook_id: str, webhook_url: str, webhook_secret: str,
                                       event_type: str, payload: dict[str, Any],
                                       db_factory) -> None:
    """
    Background task: deliver then update webhook stats in DB.
    db_factory is a callable that returns an AsyncSession (used to avoid
    holding a session across the HTTP call).
    """
    success, status_code, latency_ms, error = await deliver_to_url(
        webhook_url, webhook_secret, event_type, payload
    )
    try:
        from sqlalchemy import select
        from asc_api.models.webhook import Webhook

        async with db_factory() as db:
            result = await db.execute(select(Webhook).where(Webhook.id == webhook_id))
            wh = result.scalar_one_or_none()
            if wh:
                wh.last_triggered_at = datetime.now(timezone.utc)
                if success:
                    wh.failure_count = 0
                else:
                    wh.failure_count += 1
                await db.commit()
    except Exception as exc:
        _log.warning("webhook_db_update_error", webhook_id=webhook_id, error=str(exc))


# ── Emit event (public API) ───────────────────────────────────────────────────

async def emit_webhook_event(
    event_type: str,
    data: dict[str, Any],
    db,
    *,
    db_factory=None,
) -> int:
    """
    Query active webhooks subscribed to `event_type` and fire deliveries.

    Deliveries are dispatched as asyncio tasks (fire-and-forget).
    Returns the number of webhooks targeted.

    `db` is the current request's AsyncSession (read-only — fetch webhooks).
    `db_factory` is an optional async context manager factory for background writes.
    If db_factory is None, delivery stats are not persisted (for tests / fire-and-forget).
    """
    from sqlalchemy import select
    from asc_api.models.webhook import Webhook

    payload = {
        "event": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": data,
    }

    try:
        result = await db.execute(
            select(Webhook).where(
                Webhook.is_active == True,
            )
        )
        all_hooks = result.scalars().all()
    except Exception as exc:
        _log.warning("webhook_emit_db_error", event=event_type, error=str(exc))
        return 0

    # Filter to those subscribed to this event_type
    targets = [wh for wh in all_hooks if event_type in (wh.events or [])]

    for wh in targets[:_MAX_CONCURRENT_DELIVERIES]:
        if db_factory is not None:
            asyncio.create_task(
                _deliver_webhook_background(wh.id, wh.url, wh.secret, event_type, payload, db_factory)
            )
        else:
            # Fire-and-forget without DB update (test / no-factory path)
            asyncio.create_task(
                deliver_to_url(wh.url, wh.secret, event_type, payload)
            )

    if targets:
        _log.info("webhook_event_emitted", webhook_event=event_type, count=len(targets))

    return len(targets)
