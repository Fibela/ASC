from __future__ import annotations

from ..models import Alert
from .base import BaseResource

_BASE = "/api/v1/alerts"


class AlertsResource(BaseResource):

    async def list(self, status: str | None = None) -> list[Alert]:
        params: dict = {}
        if status is not None:
            params["status"] = status
        data = await self._c._request("GET", f"{_BASE}/", params=params)
        if isinstance(data, list):
            return [Alert(**item) for item in data]
        return [Alert(**item) for item in data.get("items", data.get("alerts", []))]

    async def get(self, alert_id: str) -> Alert:
        data = await self._c._request("GET", f"{_BASE}/{alert_id}")
        return Alert(**data)
