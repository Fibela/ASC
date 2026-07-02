"""
JWT Blacklist — token revocation for P16.3 IAM.

Architecture
------------
L1  in-process set — O(1) lookup, zero I/O, lost on process restart.
L2  PostgreSQL revoked_tokens table — durable, shared across workers.

On every auth request:
  1. check L1 (fast path — no I/O).
  2. on miss, check L2 (one DB query, ~1 ms).
  3. if found in L2, warm L1 so subsequent requests skip the DB.

Multi-worker note
-----------------
In a gunicorn multi-worker setup each process maintains its own L1.
A revocation written in worker A will miss worker B's L1 on the first
request, but fall through to L2 and warm B's cache immediately after.
The exposure window is bounded by one token-check latency — acceptable
for a SOC platform.  For stricter requirements, replace L1 with Redis.

Cleanup
-------
Call `purge_expired(db)` at startup or via a Celery periodic task to
prevent unbounded table growth.  Purged JTIs are also removed from L1.
"""
from __future__ import annotations

import threading
from datetime import datetime, timezone

from sqlalchemy import select, delete
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.models.revoked_token import RevokedToken


class JWTBlacklist:
    def __init__(self) -> None:
        self._local: set[str] = set()
        self._lock = threading.Lock()

    async def revoke(
        self,
        jti: str,
        expires_at: datetime,
        db: AsyncSession,
        *,
        revoked_by: str | None = None,
        reason: str | None = None,
    ) -> None:
        """
        Blacklist a JTI immediately in L1 and persist to L2.

        Race-condition guard: if two concurrent requests (logout + token_rotation,
        or double-click on logout button) attempt to revoke the same JTI simultaneously,
        the second INSERT hits the UNIQUE constraint.  We catch IntegrityError, roll back
        the failed transaction, and treat it as a no-op — the JTI is already blacklisted
        in both L1 and L2, so security is not compromised.
        """
        with self._lock:
            self._local.add(jti)
        try:
            entry = RevokedToken(
                jti=jti,
                expires_at=expires_at,
                revoked_by=revoked_by,
                reason=reason,
            )
            db.add(entry)
            await db.commit()
        except IntegrityError:
            await db.rollback()
            # Already in L2 — L1 already updated above, so state is consistent.

    async def is_revoked(self, jti: str, db: AsyncSession) -> bool:
        """Return True if the JTI is on the blacklist (L1 first, then L2)."""
        with self._lock:
            if jti in self._local:
                return True
        result = await db.execute(
            select(RevokedToken).where(RevokedToken.jti == jti)
        )
        if result.scalar_one_or_none():
            with self._lock:
                self._local.add(jti)
            return True
        return False

    async def purge_expired(self, db: AsyncSession) -> int:
        """
        Delete all revoked_tokens whose expires_at is in the past.
        Also evicts those JTIs from L1.
        Returns the number of entries purged.
        """
        now = datetime.now(timezone.utc)
        result = await db.execute(
            delete(RevokedToken)
            .where(RevokedToken.expires_at < now)
            .returning(RevokedToken.jti)
        )
        await db.commit()
        purged = [row[0] for row in result.fetchall()]
        if purged:
            with self._lock:
                self._local -= set(purged)
        return len(purged)

    def reset_local(self) -> None:
        """Clear the L1 in-process cache. For testing only."""
        with self._lock:
            self._local.clear()

    @property
    def local_size(self) -> int:
        with self._lock:
            return len(self._local)


# Process singleton — imported everywhere that needs blacklist access
jwt_blacklist = JWTBlacklist()
