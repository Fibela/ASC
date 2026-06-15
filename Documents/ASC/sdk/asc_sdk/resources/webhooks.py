from __future__ import annotations

from ..models import Webhook, WebhookCreated, WebhookTestResult
from .base import BaseResource

_BASE = "/api/v1/webhooks"


class WebhooksResource(BaseResource):

    async def list(self) -> list[Webhook]:
        data = await self._c._request("GET", f"{_BASE}/")
        return [Webhook(**item) for item in (data if isinstance(data, list) else [])]

    async def get(self, webhook_id: str) -> Webhook:
        data = await self._c._request("GET", f"{_BASE}/{webhook_id}")
        return Webhook(**data)

    async def create(
        self,
        url: str,
        events: list[str],
        description: str | None = None,
    ) -> WebhookCreated:
        body: dict = {"url": url, "events": events}
        if description is not None:
            body["description"] = description
        data = await self._c._request("POST", f"{_BASE}/", json=body)
        return WebhookCreated(**data)

    async def update(
        self,
        webhook_id: str,
        *,
        url: str | None = None,
        events: list[str] | None = None,
        is_active: bool | None = None,
        description: str | None = None,
    ) -> Webhook:
        body: dict = {}
        if url is not None:
            body["url"] = url
        if events is not None:
            body["events"] = events
        if is_active is not None:
            body["is_active"] = is_active
        if description is not None:
            body["description"] = description
        data = await self._c._request("PATCH", f"{_BASE}/{webhook_id}", json=body)
        return Webhook(**data)

    async def delete(self, webhook_id: str) -> None:
        await self._c._request("DELETE", f"{_BASE}/{webhook_id}")

    async def test(self, webhook_id: str) -> WebhookTestResult:
        data = await self._c._request("POST", f"{_BASE}/{webhook_id}/test")
        return WebhookTestResult(**data)
