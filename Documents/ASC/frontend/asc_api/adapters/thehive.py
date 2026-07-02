"""
TheHive Adapter — TheHive 5.x SOAR integration.

Responsibilities:
  - Create TheHive cases from ASC alerts (auto-escalation workflow).
  - Add IoCs as observables to TheHive cases.
  - Query and update existing TheHive cases.
  - Bidirectional status sync (TheHive → ASC).

Authentication: API key via Authorization header.
API: TheHive 5.x REST API v1 (/api/v1/).

ASC severity → TheHive severity:
  low      → 1 (Low)
  medium   → 2 (Medium)
  high     → 3 (High)
  critical → 4 (Critical)

ASC IoC type → TheHive dataType:
  ip           → ip
  domain       → domain
  url          → url
  hash_md5     → hash
  hash_sha1    → hash
  hash_sha256  → hash
  mutex        → other
  registry_key → registry
"""
from __future__ import annotations

import httpx
from datetime import datetime, timezone
from typing import Any

from asc_api.adapters import BaseAdapter, HTTP_TIMEOUT, USER_AGENT
from asc_api.core.config import get_settings


# ─── Severity mapping ─────────────────────────────────────────────────────────

_SEVERITY_MAP: dict[str, int] = {
    "low":      1,
    "medium":   2,
    "high":     3,
    "critical": 4,
}

_IOC_TYPE_MAP: dict[str, str] = {
    "ip":           "ip",
    "domain":       "domain",
    "url":          "url",
    "hash_md5":     "hash",
    "hash_sha1":    "hash",
    "hash_sha256":  "hash",
    "mutex":        "other",
    "registry_key": "registry",
}


class TheHiveAdapter(BaseAdapter):
    ADAPTER_NAME = "thehive"

    def __init__(self) -> None:
        s = get_settings()
        self._url    = s.THEHIVE_URL.rstrip("/")
        self._apikey = s.THEHIVE_API_KEY
        self._org    = s.THEHIVE_ORGANISATION

    # ─── Configuration ────────────────────────────────────────────────────────

    def is_configured(self) -> bool:
        return bool(self._url and self._apikey)

    def _auth_headers(self) -> dict:
        return {
            "User-Agent":    USER_AGENT,
            "Accept":        "application/json",
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {self._apikey}",
        }

    # ─── Document builders (pure — testable without HTTP) ────────────────────

    def alert_to_case(self, alert: dict) -> dict:
        """
        Transform an ASC alert dict into a TheHive 5.x case creation body.
        """
        severity = _SEVERITY_MAP.get(alert.get("severity", "medium"), 2)
        ttps     = alert.get("ttps", [])
        hosts    = alert.get("affected_hosts", [])

        tags = ["asc", "automated"]
        if ttps:
            tags.extend(ttps)

        description_parts = [
            f"**ASC Alert ID:** `{alert.get('id', 'N/A')}`",
            f"**Risk Score:** {alert.get('risk_score', 0.0):.2f}",
            "",
            alert.get("description", "No description provided."),
        ]
        if hosts:
            description_parts += ["", "**Affected Hosts:**", *[f"- `{h}`" for h in hosts]]
        if ttps:
            description_parts += ["", "**MITRE ATT&CK TTPs:**", *[f"- {t}" for t in ttps]]

        return {
            "title":       f"[ASC] {alert.get('title', 'Untitled Alert')}",
            "description": "\n".join(description_parts),
            "severity":    severity,
            "status":      "New",
            "flag":        severity >= 3,          # flag high/critical for immediate attention
            "tlp":         2,                      # TLP:AMBER
            "pap":         2,                      # PAP:AMBER
            "tags":        tags,
            "customFields": {
                "asc-alert-id":   {"string": alert.get("id", "")},
                "asc-risk-score": {"float":  float(alert.get("risk_score", 0.0))},
                "asc-severity":   {"string": alert.get("severity", "medium")},
            },
        }

    def ioc_to_observable(self, ioc: dict) -> dict:
        """
        Transform an ASC IoC dict into a TheHive observable creation body.
        """
        ioc_type  = ioc.get("ioc_type", "other")
        data_type = _IOC_TYPE_MAP.get(ioc_type, "other")

        tags = ["asc", "ioc"]
        if ioc.get("threat_type"):
            tags.append(ioc["threat_type"])

        return {
            "dataType":    data_type,
            "data":        ioc.get("value", ""),
            "message":     ioc.get("description") or f"IoC from ASC: {ioc_type}",
            "tlp":         2,
            "ioc":         True,
            "sighted":     bool(ioc.get("hit_count", 0)),
            "tags":        tags,
        }

    # ─── HTTP operations ──────────────────────────────────────────────────────

    async def test_connection(self) -> dict:
        if not self.is_configured():
            return self._not_configured()
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, verify=True) as client:
                resp = await client.get(
                    f"{self._url}/api/v1/user/current",
                    headers=self._auth_headers(),
                )
            if resp.status_code == 200:
                data = resp.json()
                return self._ok(
                    adapter=self.ADAPTER_NAME,
                    user=data.get("login", "unknown"),
                    roles=data.get("roles", []),
                    organisation=self._org,
                )
            return self._err(
                f"HTTP {resp.status_code}: {resp.text[:200]}",
                adapter=self.ADAPTER_NAME,
            )
        except Exception as exc:
            return self._err(str(exc), adapter=self.ADAPTER_NAME)

    async def create_case(self, alert: dict) -> dict:
        """Create a TheHive case from an ASC alert dict."""
        if not self.is_configured():
            return self._not_configured()
        body = self.alert_to_case(alert)
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, verify=True) as client:
                resp = await client.post(
                    f"{self._url}/api/v1/case",
                    json=body,
                    headers=self._auth_headers(),
                )
            if resp.status_code in (200, 201):
                data = resp.json()
                return self._ok(
                    adapter=self.ADAPTER_NAME,
                    case_id=data.get("_id", ""),
                    case_number=data.get("number", 0),
                    title=data.get("title", ""),
                )
            return self._err(
                f"HTTP {resp.status_code}: {resp.text[:200]}",
                adapter=self.ADAPTER_NAME,
            )
        except Exception as exc:
            return self._err(str(exc), adapter=self.ADAPTER_NAME)

    async def create_observable(self, case_id: str, ioc: dict) -> dict:
        """Add an IoC as an observable to an existing TheHive case."""
        if not self.is_configured():
            return self._not_configured()
        body = self.ioc_to_observable(ioc)
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, verify=True) as client:
                resp = await client.post(
                    f"{self._url}/api/v1/case/{case_id}/observable",
                    json=body,
                    headers=self._auth_headers(),
                )
            if resp.status_code in (200, 201):
                data = resp.json()
                obs_id = data[0].get("_id", "") if isinstance(data, list) else data.get("_id", "")
                return self._ok(
                    adapter=self.ADAPTER_NAME,
                    observable_id=obs_id,
                    data_type=body["dataType"],
                    value=body["data"],
                )
            return self._err(
                f"HTTP {resp.status_code}: {resp.text[:200]}",
                adapter=self.ADAPTER_NAME,
            )
        except Exception as exc:
            return self._err(str(exc), adapter=self.ADAPTER_NAME)

    async def get_case(self, case_id: str) -> dict:
        """Retrieve a TheHive case by ID."""
        if not self.is_configured():
            return self._not_configured()
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, verify=True) as client:
                resp = await client.get(
                    f"{self._url}/api/v1/case/{case_id}",
                    headers=self._auth_headers(),
                )
            if resp.status_code == 200:
                data = resp.json()
                return self._ok(
                    adapter=self.ADAPTER_NAME,
                    case_id=data.get("_id", case_id),
                    title=data.get("title", ""),
                    status=data.get("status", "unknown"),
                    severity=data.get("severity", 0),
                    assignee=data.get("assignee"),
                )
            if resp.status_code == 404:
                return self._err(f"Case {case_id} not found in TheHive", adapter=self.ADAPTER_NAME)
            return self._err(
                f"HTTP {resp.status_code}: {resp.text[:200]}",
                adapter=self.ADAPTER_NAME,
            )
        except Exception as exc:
            return self._err(str(exc), adapter=self.ADAPTER_NAME)

    async def update_case_status(self, case_id: str, status: str) -> dict:
        """Update a TheHive case status (e.g. 'InProgress', 'Resolved', 'Closed')."""
        if not self.is_configured():
            return self._not_configured()
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, verify=True) as client:
                resp = await client.patch(
                    f"{self._url}/api/v1/case/{case_id}",
                    json={"status": status},
                    headers=self._auth_headers(),
                )
            if resp.status_code in (200, 204):
                return self._ok(adapter=self.ADAPTER_NAME, case_id=case_id, new_status=status)
            return self._err(
                f"HTTP {resp.status_code}: {resp.text[:200]}",
                adapter=self.ADAPTER_NAME,
            )
        except Exception as exc:
            return self._err(str(exc), adapter=self.ADAPTER_NAME)
