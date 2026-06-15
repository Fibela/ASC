"""
Palo Alto Networks PAN-OS Adapter — XML API integration.

Supports PAN-OS 8.0 and above (Panorama or standalone firewall).
Uses the PAN-OS XML API (universal across all supported versions).

Authentication:
  API key passed as `key` query parameter on every request.
  Key is generated once and cached for the lifetime of the adapter instance.

Operations:
  block_ip      → Creates an Address Object + adds to ASC-Blocked-IPs group + commit
  unblock_ip    → Removes from group + deletes Address Object + commit
  block_domain  → Adds to ASC-Blocked-Domains Custom URL Category + commit
  unblock_domain→ Removes from Custom URL Category + commit
  test_connection → `show system info` operational command

Object naming convention (PAN-OS 63-char limit, alphanumeric + dash/underscore/dot/space):
  IPs:     ASC-BLK-IP-{ip_sanitized}   e.g. ASC-BLK-IP-203-0-113-5
  Domains: ASC-BLK-DOM-{dom_sanitized} e.g. ASC-BLK-DOM-evil-example-com

Commit strategy:
  Each mutating operation ends with a vsys-scoped partial commit.
  The adapter waits up to COMMIT_TIMEOUT_SECONDS for the commit job to complete.
  A failed commit is reported as {"success": False, "error": "commit_failed: ..."}.

Retry:
  Network-level errors (httpx.TransportError) are retried up to 3 times
  with exponential back-off (2s → 4s → 8s). HTTP 4xx/5xx are not retried.
"""
from __future__ import annotations

import re
import defusedxml.ElementTree as ET
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

# PAN-OS commit job completion polling
COMMIT_TIMEOUT_SECONDS: float = 30.0
COMMIT_POLL_SECONDS: float = 2.0

# Firewall-specific timeout — commits are slower than reads
FW_TIMEOUT = max(HTTP_TIMEOUT, 15.0)


# ── Object name helpers ───────────────────────────────────────────────────────

def _sanitize_ip_name(ip: str) -> str:
    """Convert an IP address to a safe PAN-OS object name (max 63 chars)."""
    safe = re.sub(r"[^a-zA-Z0-9]", "-", ip)
    return f"ASC-BLK-IP-{safe}"[:63]


def _sanitize_domain_name(domain: str) -> str:
    """Convert a domain to a safe PAN-OS object name (max 63 chars)."""
    safe = re.sub(r"[^a-zA-Z0-9]", "-", domain)
    return f"ASC-BLK-DOM-{safe}"[:63]


# ── XML response parsing ──────────────────────────────────────────────────────

def _parse_status(xml_text: str) -> tuple[bool, str]:
    """
    Parse a PAN-OS XML API response.
    Returns (success: bool, message: str).
    """
    try:
        root = ET.fromstring(xml_text)
        status = root.get("status", "error")
        if status == "success":
            result = root.find("result")
            msg = (result.text or "ok") if result is not None else "ok"
            return True, msg.strip()
        # Error path: <msg> or <line> under <msg>
        msg_el = root.find(".//msg")
        if msg_el is not None:
            lines = msg_el.findall("line")
            if lines:
                return False, " | ".join(el.text or "" for el in lines).strip()
            return False, (msg_el.text or "unknown error").strip()
        return False, "unknown error"
    except ET.ParseError as exc:
        return False, f"xml_parse_error: {exc}"


def _extract_job_id(xml_text: str) -> str | None:
    """Extract commit job ID from a PAN-OS commit response."""
    try:
        root = ET.fromstring(xml_text)
        job = root.find(".//job")
        return job.text.strip() if job is not None and job.text else None
    except ET.ParseError:
        return None


def _extract_group_members(xml_text: str) -> list[str]:
    """Extract current member names from an address-group XML response."""
    try:
        root = ET.fromstring(xml_text)
        return [m.text.strip() for m in root.findall(".//member") if m.text]
    except ET.ParseError:
        return []


def _extract_url_list(xml_text: str) -> list[str]:
    """Extract current URL entries from a custom-url-category XML response."""
    try:
        root = ET.fromstring(xml_text)
        return [m.text.strip() for m in root.findall(".//member") if m.text]
    except ET.ParseError:
        return []


# ── Adapter ───────────────────────────────────────────────────────────────────

class PaloAltoAdapter(BaseFirewallAdapter):
    """
    Palo Alto Networks PAN-OS adapter.
    All configuration read from app settings at instantiation time.
    """

    ADAPTER_NAME = "paloalto"

    def __init__(self) -> None:
        s = get_settings()
        self._host       = s.PALOALTO_HOST.rstrip("/")
        self._api_key    = s.PALOALTO_API_KEY
        self._vsys       = s.PALOALTO_VSYS
        self._ip_group   = s.PALOALTO_BLOCKED_IP_GROUP
        self._url_cat    = s.PALOALTO_BLOCKED_URL_CATEGORY
        self._base_url   = f"https://{self._host}/api/" if self._host else ""

    # ── Configuration ─────────────────────────────────────────────────────────

    def is_configured(self) -> bool:
        return bool(self._host and self._api_key)

    def _base_params(self) -> dict[str, str]:
        return {"key": self._api_key}

    # ── XPath helpers ─────────────────────────────────────────────────────────

    def _vsys_xpath(self, suffix: str = "") -> str:
        base = (
            f"/config/devices/entry[@name='localhost.localdomain']"
            f"/vsys/entry[@name='{self._vsys}']"
        )
        return base + suffix

    def _address_xpath(self, name: str) -> str:
        return self._vsys_xpath(f"/address/entry[@name='{name}']")

    def _address_group_xpath(self, group: str) -> str:
        return self._vsys_xpath(f"/address-group/entry[@name='{group}']")

    def _url_category_xpath(self, category: str) -> str:
        return self._vsys_xpath(f"/profiles/custom-url-category/entry[@name='{category}']")

    # ── Low-level XML API call ─────────────────────────────────────────────────

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=8),
        retry=retry_if_exception_type(httpx.TransportError),
        reraise=True,
    )
    async def _xml_api(
        self,
        client: httpx.AsyncClient,
        extra_params: dict[str, Any],
    ) -> str:
        """Execute a PAN-OS XML API call. Returns raw response text."""
        params = {**self._base_params(), **extra_params}
        resp = await client.get(self._base_url, params=params)
        resp.raise_for_status()
        return resp.text

    async def _commit(self, client: httpx.AsyncClient) -> tuple[bool, str]:
        """
        Commit candidate config scoped to the configured vsys.
        Polls until the commit job completes or COMMIT_TIMEOUT_SECONDS elapses.
        Returns (success, message).
        """
        import asyncio

        cmd = f"<commit><partial><vsys><entry name='{self._vsys}'/></vsys></partial></commit>"
        try:
            raw = await self._xml_api(client, {"type": "commit", "cmd": cmd})
        except Exception as exc:
            return False, f"commit_request_failed: {exc}"

        ok, msg = _parse_status(raw)
        if not ok:
            return False, f"commit_rejected: {msg}"

        job_id = _extract_job_id(raw)
        if not job_id:
            return True, "committed (no job id)"

        # Poll for job completion
        elapsed = 0.0
        while elapsed < COMMIT_TIMEOUT_SECONDS:
            await asyncio.sleep(COMMIT_POLL_SECONDS)
            elapsed += COMMIT_POLL_SECONDS
            try:
                poll_raw = await self._xml_api(
                    client,
                    {"type": "op", "cmd": f"<show><jobs><id>{job_id}</id></jobs></show>"},
                )
            except Exception:  # nosec B112 — poll loop: transient XML API errors are retried
                continue
            try:
                root = ET.fromstring(poll_raw)
                status_el = root.find(".//status")
                result_el = root.find(".//result")
                if status_el is not None and status_el.text == "FIN":
                    result_text = result_el.text if result_el is not None else ""
                    success = result_text.upper() == "OK" if result_text else True
                    return success, f"job_{job_id}_{result_text or 'completed'}"
            except ET.ParseError:
                continue

        return False, f"commit_timeout: job {job_id} did not complete in {COMMIT_TIMEOUT_SECONDS}s"

    # ── Connection test ───────────────────────────────────────────────────────

    async def test_connection(self) -> dict:
        if not self.is_configured():
            return self._not_configured()
        try:
            async with httpx.AsyncClient(
                timeout=FW_TIMEOUT, verify=True
            ) as client:
                raw = await self._xml_api(
                    client,
                    {"type": "op", "cmd": "<show><system><info/></system></show>"},
                )
            ok, _ = _parse_status(raw)
            if ok:
                try:
                    root = ET.fromstring(raw)
                    sw_ver = root.findtext(".//sw-version", "unknown")
                    model  = root.findtext(".//model", "unknown")
                except ET.ParseError:
                    sw_ver = model = "unknown"
                return self._ok(
                    adapter=self.ADAPTER_NAME,
                    host=self._host,
                    model=model,
                    sw_version=sw_ver,
                )
            return self._err(f"pan_os_error: {_parse_status(raw)[1]}", adapter=self.ADAPTER_NAME)
        except Exception as exc:
            return self._err(str(exc), adapter=self.ADAPTER_NAME)

    # ── IP blocking ──────────────────────────────────────────────────────────

    async def block_ip(
        self,
        ip: str,
        direction: str = "both",
        reason: str = "",
    ) -> dict:
        if not self.is_configured():
            return self._not_configured()

        obj_name = _sanitize_ip_name(ip)
        log.info("paloalto_block_ip", ip=ip, object_name=obj_name, reason=reason)

        try:
            async with httpx.AsyncClient(
                timeout=FW_TIMEOUT, verify=True
            ) as client:
                # 1. Create Address Object
                addr_element = f"<ip-netmask>{ip}/32</ip-netmask><description>ASC blocked: {reason[:64]}</description>"
                raw = await self._xml_api(client, {
                    "type":    "config",
                    "action":  "set",
                    "xpath":   self._address_xpath(obj_name),
                    "element": addr_element,
                })
                ok, msg = _parse_status(raw)
                if not ok:
                    return self._err(f"create_address_failed: {msg}", adapter=self.ADAPTER_NAME, ip=ip)

                # 2. Read current group members
                raw_group = await self._xml_api(client, {
                    "type":   "config",
                    "action": "get",
                    "xpath":  self._address_group_xpath(self._ip_group),
                })
                existing = _extract_group_members(raw_group)

                # 3. Add member if not already present
                if obj_name not in existing:
                    raw = await self._xml_api(client, {
                        "type":    "config",
                        "action":  "set",
                        "xpath":   self._address_group_xpath(self._ip_group) + "/static",
                        "element": f"<member>{obj_name}</member>",
                    })
                    ok, msg = _parse_status(raw)
                    if not ok:
                        return self._err(f"add_to_group_failed: {msg}", adapter=self.ADAPTER_NAME, ip=ip)

                # 4. Commit
                commit_ok, commit_msg = await self._commit(client)
                if not commit_ok:
                    return self._err(f"commit_failed: {commit_msg}", adapter=self.ADAPTER_NAME, ip=ip)

            return self._ok(
                adapter=self.ADAPTER_NAME,
                ip=ip,
                object_name=obj_name,
                group=self._ip_group,
                commit=commit_msg,
            )
        except Exception as exc:
            log.error("paloalto_block_ip_error", ip=ip, error=str(exc))
            return self._err(str(exc), adapter=self.ADAPTER_NAME, ip=ip)

    async def unblock_ip(self, ip: str) -> dict:
        if not self.is_configured():
            return self._not_configured()

        obj_name = _sanitize_ip_name(ip)
        log.info("paloalto_unblock_ip", ip=ip, object_name=obj_name)

        try:
            async with httpx.AsyncClient(
                timeout=FW_TIMEOUT, verify=True
            ) as client:
                # 1. Remove from group
                await self._xml_api(client, {
                    "type":   "config",
                    "action": "delete",
                    "xpath":  self._address_group_xpath(self._ip_group) + f"/static/member[text()='{obj_name}']",
                })

                # 2. Delete address object (best-effort — might not exist)
                await self._xml_api(client, {
                    "type":   "config",
                    "action": "delete",
                    "xpath":  self._address_xpath(obj_name),
                })

                # 3. Commit
                commit_ok, commit_msg = await self._commit(client)
                if not commit_ok:
                    return self._err(f"commit_failed: {commit_msg}", adapter=self.ADAPTER_NAME, ip=ip)

            return self._ok(
                adapter=self.ADAPTER_NAME,
                ip=ip,
                object_name=obj_name,
                commit=commit_msg,
            )
        except Exception as exc:
            log.error("paloalto_unblock_ip_error", ip=ip, error=str(exc))
            return self._err(str(exc), adapter=self.ADAPTER_NAME, ip=ip)

    # ── Domain blocking ───────────────────────────────────────────────────────

    async def block_domain(self, domain: str, reason: str = "") -> dict:
        if not self.is_configured():
            return self._not_configured()

        log.info("paloalto_block_domain", domain=domain, reason=reason)

        try:
            async with httpx.AsyncClient(
                timeout=FW_TIMEOUT, verify=True
            ) as client:
                # 1. Get current URL category entries
                raw_cat = await self._xml_api(client, {
                    "type":   "config",
                    "action": "get",
                    "xpath":  self._url_category_xpath(self._url_cat),
                })
                existing = _extract_url_list(raw_cat)

                # 2. Add domain if not already present
                if domain not in existing:
                    raw = await self._xml_api(client, {
                        "type":    "config",
                        "action":  "set",
                        "xpath":   self._url_category_xpath(self._url_cat) + "/list",
                        "element": f"<member>{domain}</member>",
                    })
                    ok, msg = _parse_status(raw)
                    if not ok:
                        return self._err(f"add_to_category_failed: {msg}", adapter=self.ADAPTER_NAME, domain=domain)

                # 3. Commit
                commit_ok, commit_msg = await self._commit(client)
                if not commit_ok:
                    return self._err(f"commit_failed: {commit_msg}", adapter=self.ADAPTER_NAME, domain=domain)

            return self._ok(
                adapter=self.ADAPTER_NAME,
                domain=domain,
                category=self._url_cat,
                commit=commit_msg,
            )
        except Exception as exc:
            log.error("paloalto_block_domain_error", domain=domain, error=str(exc))
            return self._err(str(exc), adapter=self.ADAPTER_NAME, domain=domain)

    async def unblock_domain(self, domain: str) -> dict:
        if not self.is_configured():
            return self._not_configured()

        log.info("paloalto_unblock_domain", domain=domain)

        try:
            async with httpx.AsyncClient(
                timeout=FW_TIMEOUT, verify=True
            ) as client:
                # Remove domain from URL category
                await self._xml_api(client, {
                    "type":   "config",
                    "action": "delete",
                    "xpath":  self._url_category_xpath(self._url_cat) + f"/list/member[text()='{domain}']",
                })

                commit_ok, commit_msg = await self._commit(client)
                if not commit_ok:
                    return self._err(f"commit_failed: {commit_msg}", adapter=self.ADAPTER_NAME, domain=domain)

            return self._ok(
                adapter=self.ADAPTER_NAME,
                domain=domain,
                commit=commit_msg,
            )
        except Exception as exc:
            log.error("paloalto_unblock_domain_error", domain=domain, error=str(exc))
            return self._err(str(exc), adapter=self.ADAPTER_NAME, domain=domain)
