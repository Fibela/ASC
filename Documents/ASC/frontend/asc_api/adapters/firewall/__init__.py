"""
Firewall adapter layer — Palo Alto PAN-OS and Fortinet FortiGate integrations.

All adapters implement BaseFirewallAdapter and follow the same contract:
  - Every method returns a dict with at least {"success": bool}.
  - Methods NEVER raise — all exceptions are caught and returned as errors.
  - `is_configured()` returning False causes methods to return _not_configured().
  - External HTTP calls use a 15-second timeout (longer than SIEM — commits can be slow).

Available adapters:
  PaloAltoAdapter  — PAN-OS XML API (works on PAN-OS 8.0+)
  FortinetAdapter  — FortiGate REST API v2 (FortiOS 6.4+)
"""
from asc_api.adapters.firewall.base import BaseFirewallAdapter
from asc_api.adapters.firewall.paloalto import PaloAltoAdapter
from asc_api.adapters.firewall.fortinet import FortinetAdapter

__all__ = ["BaseFirewallAdapter", "PaloAltoAdapter", "FortinetAdapter"]
