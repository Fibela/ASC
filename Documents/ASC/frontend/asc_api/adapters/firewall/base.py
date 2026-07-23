"""
Base interface for all firewall adapters.

Firewall adapters handle network-level blocking — blocking an IP or domain
at the perimeter firewall, independent of whether any SPECTER agent is present
on the target. This is the first line of defense for broadcast neutralization
actions (block_ip, block_domain, unblock_ip, unblock_domain).

All implementing classes MUST follow the no-raise contract: catch all exceptions
and return {"success": False, "error": "..."}.
"""

from abc import abstractmethod

from asc_api.adapters import BaseAdapter


class BaseFirewallAdapter(BaseAdapter):
    """Abstract base for network firewall adapters (PAN-OS, FortiGate, etc.)."""

    @abstractmethod
    async def block_ip(
        self,
        ip: str,
        direction: str = "both",
        reason: str = "",
    ) -> dict:
        """
        Block an IP address at the network perimeter.

        Args:
            ip:        IPv4 or IPv6 address (e.g. "203.0.113.5").
            direction: "inbound", "outbound", or "both" (default).
            reason:    Human-readable justification written to audit trail.

        Returns:
            {"success": True, "object_name": "...", "adapter": "..."}
            {"success": False, "error": "..."}
        """

    @abstractmethod
    async def unblock_ip(self, ip: str) -> dict:
        """
        Remove a previously blocked IP from the firewall.

        Returns:
            {"success": True, "adapter": "..."}
            {"success": False, "error": "..."}
        """

    @abstractmethod
    async def block_domain(self, domain: str, reason: str = "") -> dict:
        """
        Block a domain/FQDN at the network perimeter (DNS sinkhole / URL filter).

        Args:
            domain: Fully-qualified domain name (e.g. "evil.example.com").
            reason: Human-readable justification.

        Returns:
            {"success": True, "object_name": "...", "adapter": "..."}
            {"success": False, "error": "..."}
        """

    @abstractmethod
    async def unblock_domain(self, domain: str) -> dict:
        """
        Remove a previously blocked domain from the firewall.

        Returns:
            {"success": True, "adapter": "..."}
            {"success": False, "error": "..."}
        """
