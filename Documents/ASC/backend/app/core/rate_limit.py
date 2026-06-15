"""
P17 Rate Limiting — SlowAPI singleton.

Usage in endpoints:
    from app.core.rate_limit import limiter

    @router.post("/login")
    @limiter.limit(settings.RATE_LIMIT_LOGIN)
    async def login(request: Request, ...):
        ...

SlowAPI requires:
  1. app.state.limiter = limiter           (in main.py)
  2. RateLimitExceeded exception handler   (in main.py)
  3. request: Request as the FIRST parameter in any decorated endpoint

Storage: in-memory (per-process).  For multi-worker production deployments,
set SLOWAPI_STORAGE_URI in .env to a Redis URI so limits are shared across
workers:
    SLOWAPI_STORAGE_URI=redis://:password@redis:6379/1
"""
from __future__ import annotations

from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.config import get_settings

_settings = get_settings()

limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=_settings.SLOWAPI_STORAGE_URI or None,
)
