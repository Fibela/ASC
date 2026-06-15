"""
ELK Adapter — Elasticsearch / ELK Stack integration.

Responsibilities:
  - Push ASC alerts and events into Elasticsearch indices.
  - Pull recent events from Elasticsearch for ASC ingestion.
  - Cluster health check.

Authentication: API Key (base64 id:key) via Authorization header.
Document format: ECS-compatible (Elastic Common Schema).
"""
from __future__ import annotations

import httpx
from datetime import datetime, timezone
from typing import Any

from app.adapters import BaseAdapter, HTTP_TIMEOUT, USER_AGENT
from app.core.config import get_settings


# ─── ASC → ECS severity mapping ──────────────────────────────────────────────

_SEVERITY_TO_ECS: dict[str, int] = {
    "low":      25,
    "medium":   50,
    "high":     75,
    "critical": 99,
}


class ELKAdapter(BaseAdapter):
    ADAPTER_NAME = "elk"

    def __init__(self) -> None:
        s = get_settings()
        self._url              = s.ELASTICSEARCH_URL.rstrip("/")
        self._api_key          = s.ELASTICSEARCH_API_KEY
        self._index_alerts     = s.ELASTICSEARCH_INDEX_ALERTS
        self._index_events     = s.ELASTICSEARCH_INDEX_EVENTS

    # ─── Configuration ────────────────────────────────────────────────────────

    def is_configured(self) -> bool:
        return bool(self._url and self._api_key)

    def _auth_headers(self) -> dict:
        return {
            "User-Agent":    USER_AGENT,
            "Accept":        "application/json",
            "Content-Type":  "application/json",
            "Authorization": f"ApiKey {self._api_key}",
        }

    # ─── Document builders (pure — testable without HTTP) ────────────────────

    def alert_to_document(self, alert: dict) -> dict:
        """Transform an ASC alert dict into an ECS-compatible Elasticsearch document."""
        return {
            "@timestamp":           alert.get("detected_at") or datetime.now(timezone.utc).isoformat(),
            "event.kind":           "alert",
            "event.category":       ["intrusion_detection"],
            "event.severity":       _SEVERITY_TO_ECS.get(alert.get("severity", "low"), 25),
            "event.risk_score":     alert.get("risk_score", 0.0),
            "asc.alert.id":         alert.get("id", ""),
            "asc.alert.title":      alert.get("title", ""),
            "asc.alert.severity":   alert.get("severity", "low"),
            "asc.alert.status":     alert.get("status", "open"),
            "asc.alert.ttps":       alert.get("ttps", []),
            "host.hostname":        (alert.get("affected_hosts") or [""])[0],
            "source":               "asc-premoscorp",
        }

    def event_to_document(self, event: dict) -> dict:
        """Transform an ASC event dict into an ECS-compatible Elasticsearch document."""
        return {
            "@timestamp":       event.get("timestamp") or datetime.now(timezone.utc).isoformat(),
            "event.kind":       "event",
            "event.category":   [event.get("category", "unknown")],
            "event.action":     event.get("action", ""),
            "event.severity":   _SEVERITY_TO_ECS.get(event.get("severity", "low"), 25),
            "host.hostname":    event.get("host", ""),
            "asc.event.id":     event.get("id", ""),
            "asc.event.source": event.get("source", ""),
            "source":           "asc-premoscorp",
        }

    def _search_query(self, since: datetime, size: int) -> dict:
        """Build an Elasticsearch date-range query for recent events."""
        return {
            "size": size,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": since.isoformat(),
                        "lte": "now",
                    }
                }
            },
            "_source": True,
        }

    # ─── HTTP operations ──────────────────────────────────────────────────────

    async def test_connection(self) -> dict:
        if not self.is_configured():
            return self._not_configured()
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, verify=True) as client:
                resp = await client.get(
                    f"{self._url}/_cluster/health",
                    headers=self._auth_headers(),
                )
            if resp.status_code == 200:
                data = resp.json()
                return self._ok(
                    adapter=self.ADAPTER_NAME,
                    status=data.get("status", "unknown"),
                    cluster_name=data.get("cluster_name", ""),
                    node_count=data.get("number_of_nodes", 0),
                )
            return self._err(
                f"HTTP {resp.status_code}: {resp.text[:200]}",
                adapter=self.ADAPTER_NAME,
            )
        except Exception as exc:
            return self._err(str(exc), adapter=self.ADAPTER_NAME)

    async def push_alert(self, alert: dict) -> dict:
        """Index an ASC alert into Elasticsearch."""
        if not self.is_configured():
            return self._not_configured()
        doc_id = alert.get("id", "unknown")
        doc    = self.alert_to_document(alert)
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, verify=True) as client:
                resp = await client.put(
                    f"{self._url}/{self._index_alerts}/_doc/{doc_id}",
                    json=doc,
                    headers=self._auth_headers(),
                )
            if resp.status_code in (200, 201):
                body = resp.json()
                return self._ok(
                    adapter=self.ADAPTER_NAME,
                    index=self._index_alerts,
                    doc_id=doc_id,
                    result=body.get("result", ""),
                )
            return self._err(
                f"HTTP {resp.status_code}: {resp.text[:200]}",
                adapter=self.ADAPTER_NAME,
                doc_id=doc_id,
            )
        except Exception as exc:
            return self._err(str(exc), adapter=self.ADAPTER_NAME, doc_id=doc_id)

    async def push_event(self, event: dict) -> dict:
        """Index an ASC event into Elasticsearch."""
        if not self.is_configured():
            return self._not_configured()
        doc_id = event.get("id", "unknown")
        doc    = self.event_to_document(event)
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, verify=True) as client:
                resp = await client.put(
                    f"{self._url}/{self._index_events}/_doc/{doc_id}",
                    json=doc,
                    headers=self._auth_headers(),
                )
            if resp.status_code in (200, 201):
                body = resp.json()
                return self._ok(
                    adapter=self.ADAPTER_NAME,
                    index=self._index_events,
                    doc_id=doc_id,
                    result=body.get("result", ""),
                )
            return self._err(
                f"HTTP {resp.status_code}: {resp.text[:200]}",
                adapter=self.ADAPTER_NAME,
                doc_id=doc_id,
            )
        except Exception as exc:
            return self._err(str(exc), adapter=self.ADAPTER_NAME, doc_id=doc_id)

    async def search_raw(
        self,
        query_text: str,
        *,
        index: str | None = None,
        limit: int = 100,
    ) -> dict:
        """
        Execute a free-form Lucene/KQL query string against a given index.
        READ-ONLY — uses GET /_search, never mutates data.
        Returns at most `limit` hits (max 1000 enforced server-side).
        """
        if not self.is_configured():
            return self._not_configured()

        target_index = index or self._index_events
        limit = min(limit, 1000)
        body = {
            "size": limit,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "query_string": {
                    "query": query_text,
                    "default_operator": "AND",
                }
            },
        }
        try:
            import time
            t0 = time.monotonic()
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, verify=True) as client:
                resp = await client.post(
                    f"{self._url}/{target_index}/_search",
                    json=body,
                    headers=self._auth_headers(),
                )
            elapsed_ms = int((time.monotonic() - t0) * 1000)
            if resp.status_code == 200:
                body_resp = resp.json()
                hits = body_resp.get("hits", {}).get("hits", [])
                total = body_resp.get("hits", {}).get("total", {}).get("value", 0)
                return self._ok(
                    adapter=self.ADAPTER_NAME,
                    total=total,
                    result_count=len(hits),
                    execution_ms=elapsed_ms,
                    truncated=total > limit,
                    results=[h.get("_source", h) for h in hits],
                )
            return self._err(
                f"HTTP {resp.status_code}: {resp.text[:200]}",
                adapter=self.ADAPTER_NAME,
            )
        except Exception as exc:
            return self._err(str(exc), adapter=self.ADAPTER_NAME)

    async def search_events(
        self,
        since: datetime,
        size: int = 100,
    ) -> dict:
        """Pull recent events from Elasticsearch for ASC ingestion."""
        if not self.is_configured():
            return self._not_configured()
        query = self._search_query(since, size)
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, verify=True) as client:
                resp = await client.post(
                    f"{self._url}/{self._index_events}/_search",
                    json=query,
                    headers=self._auth_headers(),
                )
            if resp.status_code == 200:
                body  = resp.json()
                hits  = body.get("hits", {}).get("hits", [])
                total = body.get("hits", {}).get("total", {}).get("value", 0)
                return self._ok(
                    adapter=self.ADAPTER_NAME,
                    total=total,
                    events=[h["_source"] for h in hits],
                )
            return self._err(
                f"HTTP {resp.status_code}: {resp.text[:200]}",
                adapter=self.ADAPTER_NAME,
            )
        except Exception as exc:
            return self._err(str(exc), adapter=self.ADAPTER_NAME)
