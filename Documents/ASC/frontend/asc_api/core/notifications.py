"""
PANL Hybrid Notification Bus — P16 + P16.3 deuda técnica

Provides real-time SSE delivery with optional Redis pub/sub for multi-worker
deployments.

Architecture
------------
Local mode  (REDIS_URL empty or Redis unreachable):
  publish() → asyncio.Queue fan-out within the same process.
  Works for development and single-uvicorn-worker deployments.

Redis mode  (REDIS_URL configured and Redis reachable):
  publish() → Redis PUBLISH to NOTIFICATION_CHANNEL
            → Redis SUBSCRIBE listener coroutine receives the message
            → fan-out to local asyncio.Queue subscribers on THIS worker
  Each FastAPI worker independently subscribes to Redis and maintains
  its own local queues.  Cross-worker SSE delivery works transparently.

The interface (subscribe/unsubscribe/publish) is identical in both modes —
callers (approval.py, SSE endpoint) never need to know which mode is active.

Startup:
  await notification_bus.connect(settings.REDIS_URL)

Shutdown:
  await notification_bus.disconnect()

Event types
-----------
  pending_approval_created  → new action needs human sign-off
  action_approved           → action fully approved (multi-sig complete)
  action_partial_approved   → first of N required approvals received
  action_rejected           → analyst rejected the action
  action_escalated          → timeout expired without decision
  action_completed          → action executed successfully
  action_failed             → execution failed after approval
  rollback_requested        → forensic rollback initiated
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog

log = structlog.get_logger("asc.notifications")

# Shared Redis channel name — imported by escalation.py for direct Redis publish
NOTIFICATION_CHANNEL = "asc:panl:v1"


@dataclass
class Notification:
    event_type: str
    payload: dict[str, Any]
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_sse(self) -> str:
        """Serialise as SSE wire format (RFC 6202)."""
        data = json.dumps(
            {
                "event": self.event_type,
                "data": self.payload,
                "ts": self.timestamp,
            }
        )
        return f"event: {self.event_type}\ndata: {data}\n\n"


class HybridNotificationBus:
    """
    Async fan-out notification bus with optional Redis pub/sub backend.

    Mode is determined at startup by calling connect().  Falls back to
    local asyncio.Queue if Redis is unavailable or not configured.
    """

    def __init__(self) -> None:
        self._subscribers: list[asyncio.Queue[Notification]] = []
        self._redis_pub: Any = None  # redis.asyncio.Redis | None
        self._listener_task: asyncio.Task | None = None
        self._mode: str = "local"

    async def connect(self, redis_url: str | None = None) -> str:
        """
        Initialise the bus.  Call once from FastAPI lifespan.
        Returns "redis" if Redis is reachable, "local" otherwise.
        """
        if not redis_url:
            log.info("notification_bus_local_mode")
            return "local"
        try:
            import redis.asyncio as aioredis  # type: ignore[import]

            # Publisher connection
            pub = aioredis.from_url(redis_url, decode_responses=True)
            await pub.ping()
            self._redis_pub = pub

            # Subscriber connection (Redis requires a separate connection for pubsub)
            sub = aioredis.from_url(redis_url, decode_responses=True)
            ps = sub.pubsub()
            await ps.subscribe(NOTIFICATION_CHANNEL)

            self._listener_task = asyncio.ensure_future(self._redis_listener(ps))
            self._mode = "redis"
            log.info("notification_bus_redis_mode", channel=NOTIFICATION_CHANNEL)
            return "redis"

        except Exception as exc:
            log.warning(
                "notification_bus_redis_unavailable",
                error=str(exc),
                fallback="local",
            )
            self._redis_pub = None
            self._mode = "local"
            return "local"

    async def disconnect(self) -> None:
        """Clean up Redis connections. Call from FastAPI lifespan shutdown."""
        if self._listener_task:
            self._listener_task.cancel()
            try:
                await self._listener_task
            except asyncio.CancelledError:
                pass
        if self._redis_pub:
            try:
                await self._redis_pub.aclose()
            except Exception as exc:  # nosec B110 — best-effort cleanup on shutdown
                log.debug("redis_pub_close_error", error=str(exc))

    async def _redis_listener(self, pubsub: Any) -> None:
        """
        Receive messages from Redis and fan out to local subscriber queues.
        Runs as a background asyncio task for the lifetime of the process.
        """
        try:
            async for msg in pubsub.listen():
                if msg and msg.get("type") == "message":
                    try:
                        raw = json.loads(msg["data"])
                        n = Notification(
                            event_type=raw["event_type"],
                            payload=raw["payload"],
                            timestamp=raw.get("timestamp", datetime.now(UTC).isoformat()),
                        )
                        await self._fan_out(n)
                    except Exception as exc:
                        log.debug("redis_listener_parse_error", error=str(exc))
        except asyncio.CancelledError:
            await pubsub.unsubscribe(NOTIFICATION_CHANNEL)
        except Exception as exc:
            log.error("redis_listener_crashed", error=str(exc))

    async def _fan_out(self, n: Notification) -> None:
        """Deliver a notification to all local subscriber queues."""
        evicted: list[asyncio.Queue[Notification]] = []
        for q in list(self._subscribers):
            try:
                q.put_nowait(n)
            except asyncio.QueueFull:
                evicted.append(q)
        for q in evicted:
            try:
                self._subscribers.remove(q)
            except ValueError:
                pass

    async def subscribe(self) -> asyncio.Queue[Notification]:
        """Return a new queue wired to receive all future notifications."""
        q: asyncio.Queue[Notification] = asyncio.Queue(maxsize=100)
        self._subscribers.append(q)
        return q

    async def unsubscribe(self, q: asyncio.Queue[Notification]) -> None:
        """Remove a client queue (called on SSE disconnect)."""
        try:
            self._subscribers.remove(q)
        except ValueError:
            pass

    async def publish(self, event_type: str, payload: dict[str, Any]) -> None:
        """
        Broadcast a notification.

        Redis mode: PUBLISH to Redis channel → listener fan-outs to local queues
                    on every subscribed worker process.
        Local mode: direct fan-out to local queues in this process only.
        """
        n = Notification(event_type=event_type, payload=payload)

        if self._redis_pub and self._mode == "redis":
            data = json.dumps(
                {
                    "event_type": n.event_type,
                    "payload": n.payload,
                    "timestamp": n.timestamp,
                }
            )
            try:
                await self._redis_pub.publish(NOTIFICATION_CHANNEL, data)
                return
            except Exception as exc:
                log.warning("redis_publish_failed_falling_back", error=str(exc))
                # Fall through to local fan-out so analysts still get the event

        await self._fan_out(n)

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)

    @property
    def mode(self) -> str:
        """Current operating mode: 'redis' or 'local'."""
        return self._mode


# Process-level singleton — imported by approval.py and the SSE endpoint.
notification_bus = HybridNotificationBus()
