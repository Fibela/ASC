from __future__ import annotations

from datetime import datetime

from ..models import APIKey, APIKeyCreated, RateLimitStatus
from .base import BaseResource

_BASE = "/api/v1/api-keys"


class APIKeysResource(BaseResource):

    async def list(self) -> list[APIKey]:
        data = await self._c._request("GET", f"{_BASE}/")
        return [APIKey(**item) for item in (data if isinstance(data, list) else [])]

    async def get(self, key_id: str) -> APIKey:
        data = await self._c._request("GET", f"{_BASE}/{key_id}")
        return APIKey(**data)

    async def create(
        self,
        name: str,
        scopes: list[str] | None = None,
        expires_at: datetime | None = None,
    ) -> APIKeyCreated:
        body: dict = {"name": name, "scopes": scopes or ["read"]}
        if expires_at is not None:
            body["expires_at"] = expires_at.isoformat()
        data = await self._c._request("POST", f"{_BASE}/", json=body)
        return APIKeyCreated(**data)

    async def revoke(self, key_id: str) -> None:
        await self._c._request("DELETE", f"{_BASE}/{key_id}")

    async def rotate(self, key_id: str) -> APIKeyCreated:
        data = await self._c._request("POST", f"{_BASE}/{key_id}/rotate")
        return APIKeyCreated(**data)

    async def rate_limit_status(self, key_id: str) -> RateLimitStatus:
        data = await self._c._request("GET", f"{_BASE}/{key_id}/rate-limit-status")
        return RateLimitStatus(**data)
