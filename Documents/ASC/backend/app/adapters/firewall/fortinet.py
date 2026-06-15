"""
Fortinet FortiGate Adapter — REST API v2 integration.

Supports FortiOS 6.4 and above (standalone FortiGate or managed via FortiManager).
Uses the FortiGate REST API v2 with Bearer token authentication.

Authentication:
  API token passed as `Authorization: Bearer {token}` header.
  Token generated in: System → Administrators → Create API User.

Operations:
  block_ip      → Creates Address Object (ipmask) + adds to address group
  unblock_ip    → Removes from address group + deletes Address Object
  block_domain  → Creates Address Object (fqdn) + adds to address group
  unblock_domain→ Removes from address group + deletes FQDN Address Object
  test_connection → GET /api/v2/monitor/sys/status

Object naming convention (FortiGate max 79 chars):
  IPs:     ASC-BLK-IP-{ip_sanitized}   e.g. ASC-BLK-IP-203-0-113-5
  Domains: ASC-BLK-DOM-{dom_sanitized} e.g. ASC-BLK-DOM-evil-example-com

Key difference from PAN-OS:
  FortiGate changes apply immediately — no explicit commit step required.
  Address group updates require a full PUT (read-modify-write pattern):
    1. GET current group members
    2. Append new member
    3. PUT full updated group object

Retry:
  Network-level errors (httpx.TransportError) retried up to 3 times
  with exponential back-off (2s → 4s → 8s).
"""
from __future__ import annotations

import re
from typing import Any

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from app.adapters import HTTP_TIMEOUT, USER_AGENT
from app.adapters.firewall.base import BaseFirewallAdapter
from app.core.config import get_settings
from app.core.logging import get_logger

log = get_logger(__name__)

FW_TIMEOUT = max(HTTP_TIMEOUT, 15.0)

# ── Object name helpers ───────────────────────────────────────────────────────

def _sanitize_ip_name(ip: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9]", "-", ip)
    return f"ASC-BLK-IP-{safe}"[:79]


def _sanitize_domain_name(domain: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9]", "-", domain)
    return f"ASC-BLK-DOM-{safe}"[:79]


# ── Adapter ───────────────────────────────────────────────────────────────────

class FortinetAdapter(BaseFirewallAdapter):
    """
    Fortinet FortiGate adapter.
    All configuration read from app settings at instantiation time.
    """

    ADAPTER_NAME = "fortinet"

    def __init__(self) -> None:
        s = get_settings()
        self._host      = s.FORTINET_HOST.rstrip("/")
        self._token     = s.FORTINET_API_TOKEN
        self._vdom      = s.FORTINET_VDOM
        self._ip_group  = s.FORTINET_BLOCKED_IP_GROUP
        self._dom_group = s.FORTINET_BLOCKED_DOMAIN_GROUP
        self._base_url  = f"https://{self._host}/api/v2" if self._host else ""

    # ── Configuration ─────────────────────────────────────────────────────────

    def is_configured(self) -> bool:
        return bool(self._host and self._token)

    def _headers(self) -> dict[str, str]:
        return {
            "User-Agent":    USER_AGENT,
            "Accept":        "application/json",
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {self._token}",
        }

    def _vdom_param(self) -> dict[str, str]:
        return {"vdom": self._vdom}

    # ── Low-level REST helpers ────────────────────────────────────────────────

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=8),
        retry=retry_if_exception_type(httpx.TransportError),
        reraise=True,
    )
    async def _get(
        self,
        client: httpx.AsyncClient,
        path: str,
        params: dict[str, Any] | None = None,
    ) -> dict:
        all_params = {**self._vdom_param(), **(params or {})}
        resp = await client.get(
            f"{self._base_url}{path}",
            headers=self._headers(),
            params=all_params,
        )
        resp.raise_for_status()
        return resp.json()

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=8),
        retry=retry_if_exception_type(httpx.TransportError),
        reraise=True,
    )
    async def _post(
        self,
        client: httpx.AsyncClient,
        path: str,
        body: dict,
    ) -> dict:
        resp = await client.post(
            f"{self._base_url}{path}",
            headers=self._headers(),
            params=self._vdom_param(),
            json=body,
        )
        resp.raise_for_status()
        return resp.json()

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=8),
        retry=retry_if_exception_type(httpx.TransportError),
        reraise=True,
    )
    async def _put(
        self,
        client: httpx.AsyncClient,
        path: str,
        body: dict,
    ) -> dict:
        resp = await client.put(
            f"{self._base_url}{path}",
            headers=self._headers(),
            params=self._vdom_param(),
            json=body,
        )
        resp.raise_for_status()
        return resp.json()

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=8),
        retry=retry_if_exception_type(httpx.TransportError),
        reraise=True,
    )
    async def _delete(
        self,
        client: httpx.AsyncClient,
        path: str,
    ) -> None:
        resp = await client.delete(
            f"{self._base_url}{path}",
            headers=self._headers(),
            params=self._vdom_param(),
        )
        # 404 is acceptable on delete (object may not exist)
        if resp.status_code not in (200, 204, 404):
            resp.raise_for_status()

    # ── Address group read-modify-write ───────────────────────────────────────

    async def _get_group_members(
        self,
        client: httpx.AsyncClient,
        group_name: str,
    ) -> list[dict]:
        """Return current member list for a firewall address group."""
        try:
            data = await self._get(client, f"/cmdb/firewall/addrgrp/{group_name}")
            results = data.get("results", [])
            if results:
                return results[0].get("member", [])
            return []
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                return []
            raise

    async def _append_member_to_group(
        self,
        client: httpx.AsyncClient,
        group_name: str,
        obj_name: str,
        comment: str = "",
    ) -> dict:
        """
        Read-modify-write: append obj_name to address group.
        Creates the group if it doesn't exist.
        """
        existing = await self._get_group_members(client, group_name)
        member_names = {m["name"] for m in existing}

        if obj_name in member_names:
            return {"already_present": True}

        new_members = [*existing, {"name": obj_name}]
        body = {
            "name":    group_name,
            "member":  new_members,
            "comment": comment[:255] if comment else "",
        }

        try:
            return await self._put(client, f"/cmdb/firewall/addrgrp/{group_name}", body)
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                # Group doesn't exist — create it
                return await self._post(client, "/cmdb/firewall/addrgrp", body)
            raise

    async def _remove_member_from_group(
        self,
        client: httpx.AsyncClient,
        group_name: str,
        obj_name: str,
    ) -> dict:
        """Read-modify-write: remove obj_name from address group."""
        existing = await self._get_group_members(client, group_name)
        new_members = [m for m in existing if m["name"] != obj_name]

        if len(new_members) == len(existing):
            return {"not_present": True}

        body = {"name": group_name, "member": new_members}
        return await self._put(client, f"/cmdb/firewall/addrgrp/{group_name}", body)

    # ── Connection test ───────────────────────────────────────────────────────

    async def test_connection(self) -> dict:
        if not self.is_configured():
            return self._not_configured()
        try:
            async with httpx.AsyncClient(
                timeout=FW_TIMEOUT, verify=True
            ) as client:
                data = await self._get(client, "/monitor/sys/status")
            results = data.get("results", {})
            return self._ok(
                adapter=self.ADAPTER_NAME,
                host=self._host,
                serial=results.get("Serial-Number", "unknown"),
                version=results.get("Version", "unknown"),
                hostname=results.get("Hostname", "unknown"),
            )
        except Exception as exc:
            return self._err(str(exc), adapter=self.ADAPTER_NAME)

    # ── IP blocking ───────────────────────────────────────────────────────────

    async def block_ip(
        self,
        ip: str,
        direction: str = "both",
        reason: str = "",
    ) -> dict:
        if not self.is_configured():
            return self._not_configured()

        obj_name = _sanitize_ip_name(ip)
        log.info("fortinet_block_ip", ip=ip, object_name=obj_name, reason=reason)

        try:
            async with httpx.AsyncClient(
                timeout=FW_TIMEOUT, verify=True
            ) as client:
                # 1. Create Address Object (ipmask type)
                try:
                    await self._post(client, "/cmdb/firewall/address", {
                        "name":    obj_name,
                        "type":    "ipmask",
                        "subnet":  f"{ip}/32",
                        "comment": f"ASC blocked: {reason[:255]}",
                    })
                except httpx.HTTPStatusError as exc:
                    # 424 / 500 with "Object already exists" is acceptable
                    body = exc.response.text
                    if exc.response.status_code not in (200, 201) and "already exist" not in body.lower():
                        return self._err(
                            f"create_address_failed: HTTP {exc.response.status_code}",
                            adapter=self.ADAPTER_NAME, ip=ip,
                        )

                # 2. Add to blocked IP group (read-modify-write)
                await self._append_member_to_group(
                    client, self._ip_group, obj_name, reason
                )

            return self._ok(
                adapter=self.ADAPTER_NAME,
                ip=ip,
                object_name=obj_name,
                group=self._ip_group,
            )
        except Exception as exc:
            log.error("fortinet_block_ip_error", ip=ip, error=str(exc))
            return self._err(str(exc), adapter=self.ADAPTER_NAME, ip=ip)

    async def unblock_ip(self, ip: str) -> dict:
        if not self.is_configured():
            return self._not_configured()

        obj_name = _sanitize_ip_name(ip)
        log.info("fortinet_unblock_ip", ip=ip, object_name=obj_name)

        try:
            async with httpx.AsyncClient(
                timeout=FW_TIMEOUT, verify=True
            ) as client:
                # 1. Remove from group
                await self._remove_member_from_group(client, self._ip_group, obj_name)
                # 2. Delete address object (best-effort)
                await self._delete(client, f"/cmdb/firewall/address/{obj_name}")

            return self._ok(adapter=self.ADAPTER_NAME, ip=ip, object_name=obj_name)
        except Exception as exc:
            log.error("fortinet_unblock_ip_error", ip=ip, error=str(exc))
            return self._err(str(exc), adapter=self.ADAPTER_NAME, ip=ip)

    # ── Domain blocking ───────────────────────────────────────────────────────

    async def block_domain(self, domain: str, reason: str = "") -> dict:
        if not self.is_configured():
            return self._not_configured()

        obj_name = _sanitize_domain_name(domain)
        log.info("fortinet_block_domain", domain=domain, object_name=obj_name, reason=reason)

        try:
            async with httpx.AsyncClient(
                timeout=FW_TIMEOUT, verify=True
            ) as client:
                # 1. Create FQDN Address Object
                try:
                    await self._post(client, "/cmdb/firewall/address", {
                        "name":    obj_name,
                        "type":    "fqdn",
                        "fqdn":    domain,
                        "comment": f"ASC blocked: {reason[:255]}",
                    })
                except httpx.HTTPStatusError as exc:
                    body = exc.response.text
                    if exc.response.status_code not in (200, 201) and "already exist" not in body.lower():
                        return self._err(
                            f"create_fqdn_failed: HTTP {exc.response.status_code}",
                            adapter=self.ADAPTER_NAME, domain=domain,
                        )

                # 2. Add to domain group
                await self._append_member_to_group(
                    client, self._dom_group, obj_name, reason
                )

            return self._ok(
                adapter=self.ADAPTER_NAME,
                domain=domain,
                object_name=obj_name,
                group=self._dom_group,
            )
        except Exception as exc:
            log.error("fortinet_block_domain_error", domain=domain, error=str(exc))
            return self._err(str(exc), adapter=self.ADAPTER_NAME, domain=domain)

    async def unblock_domain(self, domain: str) -> dict:
        if not self.is_configured():
            return self._not_configured()

        obj_name = _sanitize_domain_name(domain)
        log.info("fortinet_unblock_domain", domain=domain, object_name=obj_name)

        try:
            async with httpx.AsyncClient(
                timeout=FW_TIMEOUT, verify=True
            ) as client:
                await self._remove_member_from_group(client, self._dom_group, obj_name)
                await self._delete(client, f"/cmdb/firewall/address/{obj_name}")

            return self._ok(adapter=self.ADAPTER_NAME, domain=domain, object_name=obj_name)
        except Exception as exc:
            log.error("fortinet_unblock_domain_error", domain=domain, error=str(exc))
            return self._err(str(exc), adapter=self.ADAPTER_NAME, domain=domain)
