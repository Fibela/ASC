"""
Wazuh Adapter — Wazuh Manager REST API integration (EDR / HIDS).

Responsibilities:
  - Authenticate with Wazuh Manager (JWT flow: Basic → token → Bearer).
  - Pull recent Wazuh alerts for ingestion into ASC as events.
  - Query active agent inventory.
  - Map Wazuh rule levels (1-15) to ASC severity strings.

Auth flow:
  POST /security/user/authenticate  (Basic auth) → {"data": {"token": "..."}}
  Subsequent requests: Authorization: Bearer <token>

Token caching:
  Wazuh tokens expire at 900s by default.  The adapter caches tokens at the
  class level (shared across all WazuhAdapter instances, which are created
  per-request in FastAPI) with a conservative TTL of 800s to avoid using a
  token that is about to expire.  Call WazuhAdapter.clear_cache() in tests
  to reset between runs.

Wazuh levels → ASC severity:
  1-7   → low
  8-11  → medium
  12-14 → high
  15    → critical
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta

import httpx

from asc_api.adapters import HTTP_TIMEOUT, USER_AGENT, BaseAdapter
from asc_api.core.config import get_settings

# ─── Severity mapping ─────────────────────────────────────────────────────────


def wazuh_level_to_severity(level: int) -> str:
    if level >= 15:
        return "critical"
    if level >= 12:
        return "high"
    if level >= 8:
        return "medium"
    return "low"


class WazuhAdapter(BaseAdapter):
    ADAPTER_NAME = "wazuh"

    # Class-level token cache: {cache_key: (token, expires_at)}
    # Shared across all instances so the cache survives across per-request instantiation.
    # TTL = 800s (Wazuh default expiry is 900s — 100s safety margin).
    _token_cache: dict[str, tuple[str, datetime]] = {}
    _TOKEN_TTL = 800

    def __init__(self) -> None:
        s = get_settings()
        self._url = s.WAZUH_URL.rstrip("/")
        self._username = s.WAZUH_USERNAME
        self._password = s.WAZUH_PASSWORD
        self._verify_ssl = s.WAZUH_VERIFY_SSL

    # ─── Cache helpers ────────────────────────────────────────────────────────

    def _cache_key(self) -> str:
        return f"{self._url}:{self._username}"

    @classmethod
    def clear_cache(cls) -> None:
        """Flush the token cache. Use in tests to ensure a clean state."""
        cls._token_cache.clear()

    def _invalidate_token(self) -> None:
        """Force a token refresh on next call (use after receiving 401)."""
        self._token_cache.pop(self._cache_key(), None)

    # ─── Configuration ────────────────────────────────────────────────────────

    def is_configured(self) -> bool:
        return bool(self._url and self._username and self._password)

    def _basic_auth_header(self) -> str:
        creds = f"{self._username}:{self._password}"
        return "Basic " + base64.b64encode(creds.encode()).decode()

    # ─── Authentication ───────────────────────────────────────────────────────

    async def _get_token(self, client: httpx.AsyncClient) -> str:
        """Obtain a fresh Wazuh JWT token via Basic auth. Raises on failure."""
        resp = await client.post(
            f"{self._url}/security/user/authenticate",
            headers={
                "User-Agent": USER_AGENT,
                "Authorization": self._basic_auth_header(),
                "Content-Type": "application/json",
            },
        )
        resp.raise_for_status()
        return resp.json()["data"]["token"]

    async def _get_cached_token(self, client: httpx.AsyncClient) -> str:
        """
        Return a cached token if still valid, otherwise fetch a new one and cache it.
        Reduces Wazuh Manager load and eliminates per-request Basic-auth round trips.
        """
        key = self._cache_key()
        now = datetime.now(UTC)

        cached = self._token_cache.get(key)
        if cached is not None:
            token, expires_at = cached
            if now < expires_at:
                return token

        token = await self._get_token(client)
        self._token_cache[key] = (token, now + timedelta(seconds=self._TOKEN_TTL))
        return token

    def _bearer_headers(self, token: str) -> dict:
        return {
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
        }

    # ─── Document transformer (pure — testable without HTTP) ─────────────────

    def wazuh_alert_to_asc_event(self, hit: dict) -> dict:
        """
        Transform a Wazuh alert (_source from Wazuh API) into an ASC event dict
        suitable for ingestion via the events pipeline.
        """
        rule = hit.get("rule", {})
        agent = hit.get("agent", {})
        level = int(rule.get("level", 0))
        ts_raw = hit.get("timestamp", datetime.now(UTC).isoformat())

        return {
            "source": "wazuh",
            "category": "hids",
            "action": rule.get("description", "wazuh_alert"),
            "host": agent.get("name", agent.get("id", "unknown")),
            "severity": wazuh_level_to_severity(level),
            "raw_log": str(hit.get("full_log", hit.get("data", ""))),
            "data": {
                "wazuh_rule_id": rule.get("id", ""),
                "wazuh_rule_level": level,
                "wazuh_rule_desc": rule.get("description", ""),
                "wazuh_agent_id": agent.get("id", ""),
                "wazuh_agent_name": agent.get("name", ""),
                "wazuh_groups": rule.get("groups", []),
                "original_id": hit.get("id", ""),
                "timestamp": ts_raw,
            },
        }

    # ─── HTTP operations ──────────────────────────────────────────────────────

    async def test_connection(self) -> dict:
        if not self.is_configured():
            return self._not_configured()
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, verify=self._verify_ssl) as client:
                token = await self._get_cached_token(client)
                resp = await client.get(
                    f"{self._url}/manager/info",
                    headers=self._bearer_headers(token),
                )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                return self._ok(
                    adapter=self.ADAPTER_NAME,
                    wazuh_version=data.get("version", "unknown"),
                    type=data.get("type", "unknown"),
                )
            if resp.status_code == 401:
                self._invalidate_token()
            return self._err(
                f"HTTP {resp.status_code}: {resp.text[:200]}",
                adapter=self.ADAPTER_NAME,
            )
        except Exception as exc:
            return self._err(str(exc), adapter=self.ADAPTER_NAME)

    async def get_alerts(
        self,
        since: datetime | None = None,
        limit: int = 100,
    ) -> dict:
        """
        Fetch recent Wazuh alerts.
        `since` defaults to 1 hour ago if not provided.
        Returns {"success": True, "alerts": [...], "total": N}.
        """
        if not self.is_configured():
            return self._not_configured()

        if since is None:
            since = datetime.now(UTC) - timedelta(hours=1)

        since_str = since.strftime("%Y-%m-%dT%H:%M:%S")

        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, verify=self._verify_ssl) as client:
                token = await self._get_cached_token(client)
                resp = await client.get(
                    f"{self._url}/alerts",
                    params={"limit": limit, "q": f"timestamp>{since_str}"},
                    headers=self._bearer_headers(token),
                )
            if resp.status_code == 200:
                body = resp.json()
                alerts = body.get("data", {}).get("affected_items", [])
                total = body.get("data", {}).get("total_affected_items", len(alerts))
                return self._ok(
                    adapter=self.ADAPTER_NAME,
                    total=total,
                    alerts=alerts,
                    asc_events=[self.wazuh_alert_to_asc_event(a) for a in alerts],
                )
            if resp.status_code == 401:
                self._invalidate_token()
            return self._err(
                f"HTTP {resp.status_code}: {resp.text[:200]}",
                adapter=self.ADAPTER_NAME,
            )
        except Exception as exc:
            return self._err(str(exc), adapter=self.ADAPTER_NAME)

    async def search_raw(
        self,
        query_text: str,
        *,
        limit: int = 100,
    ) -> dict:
        """
        Execute a free-form search against Wazuh's alert endpoint using the `q` filter.
        READ-ONLY — uses GET /alerts, never mutates data.
        `query_text` is passed as Wazuh API query syntax (field=value pairs, AND/OR allowed).
        """
        if not self.is_configured():
            return self._not_configured()

        limit = min(limit, 1000)
        try:
            import time

            t0 = time.monotonic()
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, verify=self._verify_ssl) as client:
                token = await self._get_cached_token(client)
                resp = await client.get(
                    f"{self._url}/alerts",
                    params={"limit": limit, "sort": "-timestamp", "q": query_text},
                    headers=self._bearer_headers(token),
                )
            elapsed_ms = int((time.monotonic() - t0) * 1000)

            if resp.status_code == 200:
                body = resp.json()
                items = body.get("data", {}).get("affected_items", [])
                total = body.get("data", {}).get("total_affected_items", len(items))
                return self._ok(
                    adapter=self.ADAPTER_NAME,
                    total=total,
                    result_count=len(items),
                    execution_ms=elapsed_ms,
                    truncated=total > limit,
                    results=items,
                )
            if resp.status_code == 401:
                self._invalidate_token()
            return self._err(
                f"HTTP {resp.status_code}: {resp.text[:200]}",
                adapter=self.ADAPTER_NAME,
            )
        except Exception as exc:
            return self._err(str(exc), adapter=self.ADAPTER_NAME)

    async def get_agents(self, status: str = "active") -> dict:
        """List Wazuh agents filtered by status."""
        if not self.is_configured():
            return self._not_configured()
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, verify=self._verify_ssl) as client:
                token = await self._get_cached_token(client)
                resp = await client.get(
                    f"{self._url}/agents",
                    params={"status": status, "limit": 500},
                    headers=self._bearer_headers(token),
                )
            if resp.status_code == 200:
                body = resp.json()
                agents = body.get("data", {}).get("affected_items", [])
                return self._ok(
                    adapter=self.ADAPTER_NAME,
                    total=len(agents),
                    agents=agents,
                )
            if resp.status_code == 401:
                self._invalidate_token()
            return self._err(
                f"HTTP {resp.status_code}: {resp.text[:200]}",
                adapter=self.ADAPTER_NAME,
            )
        except Exception as exc:
            return self._err(str(exc), adapter=self.ADAPTER_NAME)
