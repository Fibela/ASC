from __future__ import annotations

from ..models import Incident
from .base import BaseResource

_BASE = "/api/v1/incidents"


class IncidentsResource(BaseResource):

    async def list(self) -> list[Incident]:
        data = await self._c._request("GET", f"{_BASE}/")
        if isinstance(data, list):
            return [Incident(**item) for item in data]
        return [Incident(**item) for item in data.get("items", [])]

    async def get(self, incident_id: str) -> Incident:
        data = await self._c._request("GET", f"{_BASE}/{incident_id}")
        return Incident(**data)

    async def create(
        self,
        title: str,
        severity: str,
        description: str | None = None,
        assigned_to: str | None = None,
    ) -> Incident:
        body: dict = {"title": title, "severity": severity}
        if description is not None:
            body["description"] = description
        if assigned_to is not None:
            body["assigned_to"] = assigned_to
        data = await self._c._request("POST", f"{_BASE}/", json=body)
        return Incident(**data)

    async def update_status(self, incident_id: str, status: str) -> Incident:
        data = await self._c._request(
            "PATCH", f"{_BASE}/{incident_id}", json={"status": status}
        )
        return Incident(**data)
