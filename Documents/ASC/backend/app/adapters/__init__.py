"""
ASC Adapter Layer — SIEM/EDR/SOAR integrations.

Design contract:
  - Every public method returns a dict with at least {"success": bool}.
  - Adapters NEVER raise — all exceptions are caught and returned as
    {"success": False, "error": "<message>"}.
  - External HTTP calls always carry a 10-second timeout.
  - ASC keeps working if any or all adapters are unreachable.

Available adapters:
  ELKAdapter      — Elasticsearch / ELK Stack (SIEM)
  WazuhAdapter    — Wazuh Manager API (EDR/HIDS)
  TheHiveAdapter  — TheHive 5.x (SOAR)
"""
from __future__ import annotations

import abc
from typing import Any


# ─── Shared HTTP settings ─────────────────────────────────────────────────────

HTTP_TIMEOUT = 10.0          # seconds per external request
USER_AGENT   = "ASC-PremosCorp/1.0"


# ─── Abstract base class ──────────────────────────────────────────────────────

class BaseAdapter(abc.ABC):
    """
    Base class for all ASC external adapters.

    Subclasses must implement:
      - is_configured() → bool
      - test_connection() → dict
      - ADAPTER_NAME: str
    """

    ADAPTER_NAME: str = "base"

    @abc.abstractmethod
    def is_configured(self) -> bool:
        """Return True if all required configuration values are present."""

    @abc.abstractmethod
    async def test_connection(self) -> dict:
        """Probe the external system and return a health dict."""

    def _not_configured(self) -> dict:
        return {
            "success": False,
            "error":   f"{self.ADAPTER_NAME} adapter is not configured. "
                       f"Set the required environment variables.",
            "adapter": self.ADAPTER_NAME,
        }

    @staticmethod
    def _ok(**kwargs: Any) -> dict:
        return {"success": True, **kwargs}

    @staticmethod
    def _err(message: str, **kwargs: Any) -> dict:
        return {"success": False, "error": str(message), **kwargs}

    @staticmethod
    def _common_headers() -> dict:
        return {"User-Agent": USER_AGENT, "Accept": "application/json"}


# ─── Registry ────────────────────────────────────────────────────────────────

from app.adapters.elk     import ELKAdapter      # noqa: E402
from app.adapters.wazuh   import WazuhAdapter    # noqa: E402
from app.adapters.thehive import TheHiveAdapter  # noqa: E402

# F1 — Firewall and Identity adapters
from app.adapters.firewall.paloalto import PaloAltoAdapter   # noqa: E402
from app.adapters.firewall.fortinet import FortinetAdapter   # noqa: E402
from app.adapters.identity.active_directory import ActiveDirectoryAdapter  # noqa: E402

ADAPTERS: dict[str, type[BaseAdapter]] = {
    # SIEM / SOAR
    "elk":              ELKAdapter,
    "wazuh":            WazuhAdapter,
    "thehive":          TheHiveAdapter,
    # Firewall (F1)
    "paloalto":         PaloAltoAdapter,
    "fortinet":         FortinetAdapter,
    # Identity (F1)
    "active_directory": ActiveDirectoryAdapter,
}


def get_firewall_adapter() -> "BaseAdapter | None":
    """
    Return the first configured firewall adapter (PAN-OS preferred, Fortinet fallback).
    Returns None if neither is configured — callers must handle the None case.
    """
    pa = PaloAltoAdapter()
    if pa.is_configured():
        return pa
    ft = FortinetAdapter()
    if ft.is_configured():
        return ft
    return None


def get_identity_adapter() -> "BaseAdapter | None":
    """Return the Active Directory adapter if configured, else None."""
    ad = ActiveDirectoryAdapter()
    return ad if ad.is_configured() else None


__all__ = [
    "BaseAdapter",
    "ELKAdapter", "WazuhAdapter", "TheHiveAdapter",
    "PaloAltoAdapter", "FortinetAdapter",
    "ActiveDirectoryAdapter",
    "ADAPTERS",
    "get_firewall_adapter",
    "get_identity_adapter",
]
