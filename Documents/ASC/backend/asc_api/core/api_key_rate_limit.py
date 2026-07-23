"""
P41 — Rate Limiting per API Key (Toque Premos).

Sliding window log algorithm using Redis ZSET (per-process deque fallback).

Algorithm
---------
For each check(prefix, limit, window_seconds):
  1. Remove ZSET members older than now - window_seconds.
  2. Add the current request (unique member, score = now).
  3. Read the ZSET cardinality — that is the count in the sliding window.
  4. If count > limit → blocked (429), else → allowed.

Two windows are always enforced: per-minute (burst) and per-hour (throughput).
The most restrictive result governs. Both windows are checked before the request
is allowed through, so a single check() pair in the middleware decides the outcome.

Redis key schema:  rl:apikey:<prefix>:<window_seconds>
Memory key schema: <prefix>:<window_seconds>

Fail-open policy
----------------
If Redis is unavailable during check() (connection error, timeout, etc.) we log
a warning and return allowed=True so a Redis outage never blocks legitimate traffic.
The in-memory fallback is always available as a safety net when connect() fails.

Toque Premos guarantees
-----------------------
• The key_prefix (8 safe chars) is used as the rate-limit key — the raw key and
  hash are never touched or logged here.
• Breaches are reported to the caller for Ledger Premos emission.
• Fail-open degradation is always logged to asc.rate_limit so operators can see it.
"""

from __future__ import annotations

import threading
import time as _time
import uuid
from collections import deque
from dataclasses import dataclass

import structlog

_log = structlog.get_logger("asc.rate_limit")


@dataclass
class RateLimitResult:
    """Outcome of a single sliding-window check."""

    allowed: bool
    limit: int
    remaining: int  # requests still allowed in this window
    reset_at: int  # Unix timestamp when the oldest entry in the window expires
    retry_after: int = 0  # seconds to wait (only meaningful when allowed=False)


class ApiKeyRateLimiter:
    """
    Sliding window rate limiter keyed by API key prefix.

    Supports two backends:
      • Redis  — multi-worker safe, survives process restarts, recommended for prod.
      • Memory — per-process deque, no external dependency, suitable for testing
                 and single-worker deployments.

    The backend is selected at startup via connect(redis_url).  If the connection
    fails or redis_url is empty the limiter silently falls back to memory mode.
    """

    def __init__(self) -> None:
        self._redis = None
        self._mode: str = "memory"
        self._lock = threading.Lock()
        # memory store: "{prefix}:{window_s}" → deque[float] of timestamps
        self._store: dict[str, deque] = {}

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def connect(self, redis_url: str) -> str:
        """
        Attempt to connect to Redis. Returns the active mode string.

        Called once during application startup (lifespan).  Safe to call
        multiple times — repeated calls replace the previous connection.
        """
        if not redis_url:
            _log.info("api_key_rate_limiter_mode", mode="memory", reason="no redis_url")
            return "memory"
        try:
            import redis.asyncio as aioredis

            client = aioredis.from_url(
                redis_url,
                decode_responses=True,
                socket_connect_timeout=2,
                socket_timeout=2,
            )
            await client.ping()
            self._redis = client
            self._mode = "redis"
            _log.info("api_key_rate_limiter_mode", mode="redis")
        except Exception as exc:  # pragma: no cover
            _log.warning(
                "api_key_rate_limiter_fallback",
                reason=str(exc),
                mode="memory",
            )
            self._mode = "memory"
        return self._mode

    # ── Core check ────────────────────────────────────────────────────────────

    async def check(self, prefix: str, limit: int, window_seconds: int) -> RateLimitResult:
        """
        Sliding window check-and-increment for the given prefix.

        The current request is always counted (even if it will be blocked)
        so attackers cannot probe the exact limit boundary without consuming slots.
        """
        now = _time.time()
        window_start = now - window_seconds

        if self._mode == "redis" and self._redis is not None:
            return await self._check_redis(prefix, limit, window_seconds, now, window_start)
        return self._check_memory(prefix, limit, window_seconds, now, window_start)

    async def _check_redis(
        self,
        prefix: str,
        limit: int,
        window_seconds: int,
        now: float,
        window_start: float,
    ) -> RateLimitResult:
        key = f"rl:apikey:{prefix}:{window_seconds}"
        # Unique member guarantees no ZADD overwrites when two requests arrive
        # at the exact same microsecond.
        member = f"{now:.6f}:{uuid.uuid4().hex[:8]}"
        try:
            pipe = self._redis.pipeline()
            pipe.zremrangebyscore(key, 0, window_start)  # evict stale
            pipe.zadd(key, {member: now})  # add this request
            pipe.zcard(key)  # count
            pipe.zrange(key, 0, 0, withscores=True)  # oldest entry
            pipe.expire(key, window_seconds * 2)  # keep key alive
            results = await pipe.execute()

            count: int = results[2]
            oldest_entries = results[3]
            oldest_ts: float = oldest_entries[0][1] if oldest_entries else now
            reset_at = int(oldest_ts + window_seconds)
            remaining = max(0, limit - count)
            allowed = count <= limit
            return RateLimitResult(
                allowed=allowed,
                limit=limit,
                remaining=remaining,
                reset_at=reset_at,
                retry_after=max(0, reset_at - int(now)) if not allowed else 0,
            )
        except Exception as exc:
            _log.warning("rate_limit_redis_check_error", prefix=prefix, error=str(exc))
            # Fail open — Redis degradation must never block legitimate traffic
            return RateLimitResult(
                allowed=True,
                limit=limit,
                remaining=limit,
                reset_at=int(now) + window_seconds,
            )

    def _check_memory(
        self,
        prefix: str,
        limit: int,
        window_seconds: int,
        now: float,
        window_start: float,
    ) -> RateLimitResult:
        key = f"{prefix}:{window_seconds}"
        with self._lock:
            if key not in self._store:
                self._store[key] = deque()
            dq = self._store[key]
            # Evict entries outside the sliding window
            while dq and dq[0] < window_start:
                dq.popleft()
            dq.append(now)
            count = len(dq)
            oldest_ts = dq[0]

        reset_at = int(oldest_ts + window_seconds)
        remaining = max(0, limit - count)
        allowed = count <= limit
        return RateLimitResult(
            allowed=allowed,
            limit=limit,
            remaining=remaining,
            reset_at=reset_at,
            retry_after=max(0, reset_at - int(now)) if not allowed else 0,
        )

    # ── Status query (read-only) ───────────────────────────────────────────────

    async def get_status(self, prefix: str, window_seconds: int) -> int:
        """
        Return current request count within the window (does NOT increment).
        Used by the rate-limit-status admin endpoint.
        """
        now = _time.time()
        window_start = now - window_seconds

        if self._mode == "redis" and self._redis is not None:
            try:
                key = f"rl:apikey:{prefix}:{window_seconds}"
                count = await self._redis.zcount(key, window_start, "+inf")
                return int(count)
            except Exception as exc:
                _log.warning("rate_limit_redis_status_error", prefix=prefix, error=str(exc))
                return 0

        key = f"{prefix}:{window_seconds}"
        with self._lock:
            dq = self._store.get(key, deque())
            return sum(1 for ts in dq if ts >= window_start)

    # ── Admin reset ───────────────────────────────────────────────────────────

    def reset_for_prefix(self, prefix: str) -> None:
        """Clear in-memory rate limit state for a prefix. Thread-safe."""
        with self._lock:
            keys_to_delete = [k for k in self._store if k.startswith(f"{prefix}:")]
            for k in keys_to_delete:
                del self._store[k]

    async def reset_for_prefix_all(self, prefix: str) -> None:
        """
        Clear all rate limit state (Redis + memory) for a prefix.
        Used by the admin reset endpoint.
        """
        if self._mode == "redis" and self._redis is not None:
            try:
                pattern = f"rl:apikey:{prefix}:*"
                keys = await self._redis.keys(pattern)
                if keys:
                    await self._redis.delete(*keys)
            except Exception as exc:
                _log.warning("rate_limit_redis_reset_error", prefix=prefix, error=str(exc))
        # Always clear memory store too
        self.reset_for_prefix(prefix)

    # ── Introspection ─────────────────────────────────────────────────────────

    @property
    def mode(self) -> str:
        """Active backend: 'redis' or 'memory'."""
        return self._mode


# Process singleton — imported by middleware.py and api_keys.py
api_key_limiter = ApiKeyRateLimiter()
