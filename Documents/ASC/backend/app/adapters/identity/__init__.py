"""
Identity adapter layer — Active Directory / LDAP integration.

All adapters implement BaseIdentityAdapter and follow the same contract:
  - Every method returns a dict with at least {"success": bool}.
  - Methods NEVER raise — all exceptions are caught and returned as errors.
  - ldap3 is synchronous; all operations are wrapped in asyncio.to_thread().

Available adapters:
  ActiveDirectoryAdapter — Microsoft Active Directory via LDAP3 (LDAPS required in prod)
"""
from app.adapters.identity.active_directory import ActiveDirectoryAdapter

__all__ = ["ActiveDirectoryAdapter"]
