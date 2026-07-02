"""
PANL Real-time Notification Endpoint — SSE Stream

Analysts connect once and receive push events as actions move through the
approval state machine without polling.

Usage (browser / curl):
    curl -N -H "Authorization: Bearer <jwt>" \
         http://localhost:8000/api/v1/notifications/stream

Event types received:
    pending_approval_created  — new action needs approval
    action_partial_approved   — 1/2 signatures received (CRITICAL multi-sig)
    action_approved           — fully approved, executing
    action_rejected           — analyst rejected
    action_escalated          — timeout expired
    action_completed          — executed successfully
    action_failed             — execution failed
    rollback_requested        — forensic rollback initiated

Connection lifecycle:
    - Client connects → subscribed to notification_bus.
    - Each event is delivered as an SSE 'data:' frame.
    - On disconnect (GeneratorExit / cancelled) → unsubscribed automatically.
    - A heartbeat comment (": heartbeat\\n\\n") is sent every 30 s to keep the
      connection alive through load balancers and browser timeouts.
"""
from __future__ import annotations

import asyncio
from typing import AsyncGenerator

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse

from asc_api.api.deps import get_analyst_or_admin
from asc_api.core.notifications import notification_bus
from asc_api.models.user import User

router = APIRouter(prefix="/notifications", tags=["Notifications"])

_HEARTBEAT_INTERVAL: int = 30  # seconds


async def _event_stream(
    request: Request,
    current_user: User,
) -> AsyncGenerator[str, None]:
    """Async generator that yields SSE frames until client disconnects."""
    queue = await notification_bus.subscribe()
    try:
        while True:
            # Wait for the next notification or heartbeat timeout
            try:
                notification = await asyncio.wait_for(
                    queue.get(), timeout=_HEARTBEAT_INTERVAL
                )
                yield notification.to_sse()
            except asyncio.TimeoutError:
                # Heartbeat keeps the connection alive through proxies
                yield ": heartbeat\n\n"

            # Detect client disconnect (ASGI disconnect signal)
            if await request.is_disconnected():
                break
    except (asyncio.CancelledError, GeneratorExit):
        pass
    finally:
        await notification_bus.unsubscribe(queue)


@router.get(
    "/stream",
    summary="PANL real-time event stream (SSE)",
    response_class=StreamingResponse,
)
async def notification_stream(
    request: Request,
    current_user: User = Depends(get_analyst_or_admin),
):
    """
    Server-Sent Events stream for PANL analyst notifications.

    Connect once; receive push events for every approval-queue state change.
    Authentication required (JWT bearer token via Authorization header or cookie).
    """
    return StreamingResponse(
        _event_stream(request, current_user),
        media_type="text/event-stream",
        headers={
            "Cache-Control":     "no-cache",
            "X-Accel-Buffering": "no",   # disable nginx buffering
        },
    )


@router.get("/status", summary="Notification bus subscriber count (health check)")
async def notification_status(
    current_user: User = Depends(get_analyst_or_admin),
):
    """Returns the number of currently connected SSE subscribers."""
    return {
        "subscribers": notification_bus.subscriber_count,
        "heartbeat_interval_s": _HEARTBEAT_INTERVAL,
    }
