from __future__ import annotations

from ..models import Event
from .base import BaseResource

_BASE = "/api/v1/events"


class EventsResource(BaseResource):

    async def list(self) -> list[Event]:
        data = await self._c._request("GET", f"{_BASE}/")
        if isinstance(data, list):
            return [Event(**item) for item in data]
        return [Event(**item) for item in data.get("items", data.get("events", []))]

    async def get(self, event_id: str) -> Event:
        data = await self._c._request("GET", f"{_BASE}/{event_id}")
        return Event(**data)
