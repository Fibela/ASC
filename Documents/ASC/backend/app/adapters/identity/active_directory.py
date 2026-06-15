"""
Active Directory / LDAP Adapter — ldap3 integration.

Connects to Microsoft Active Directory via LDAPS (TLS, port 636) or plain LDAP
(port 389, development only). LDAPS is enforced when AD_USE_SSL=True (default).

Authentication:
  Service account bind with DN + password. The account must have:
  - Delegated "Write userAccountControl" on target OUs (to disable/enable accounts).
  - Delegated "Reset Password" on target OUs (to force password reset).
  - Delegated "Write pwdLastSet" on target OUs (for force-reset via pwdLastSet=0).
  - Delegated "Move objects" to the quarantine OU (move_to_quarantine_ou).
  Never use Domain Admin — minimum privilege principle.

User lookup:
  Users are located by sAMAccountName (Windows login name) under AD_BASE_DN.
  The search is scoped to SUBTREE so nested OUs are included.

Operations:
  disable_account        → Set userAccountControl |= UF_ACCOUNTDISABLE (0x0002)
  enable_account         → Clear userAccountControl &= ~UF_ACCOUNTDISABLE
  force_password_reset   → Set pwdLastSet = 0 (forces change at next login)
  move_to_quarantine_ou  → LDAP modifyDN to AD_QUARANTINE_OU
  health_check           → Simple bind + base search
  test_connection        → Same as health_check

Thread safety:
  ldap3 Connections are NOT thread-safe. Each operation opens its own
  Connection inside asyncio.to_thread() so there is no shared state.

Security notes:
  - AD_BIND_PASSWORD must come from environment / HashiCorp Vault, never hardcoded.
  - TLS certificate validation is enforced (ssl.CERT_REQUIRED) in production.
  - AD_VERIFY_CERT=False is available for development with self-signed certs.
"""
from __future__ import annotations

import asyncio
import ssl
from typing import Any

from app.adapters import BaseAdapter
from app.core.config import get_settings
from app.core.logging import get_logger

log = get_logger(__name__)

# userAccountControl flags
_UF_ACCOUNTDISABLE: int = 0x0002


def _import_ldap3():
    """Lazy import so the module loads even if ldap3 is not installed."""
    try:
        import ldap3
        return ldap3
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "ldap3 is required for Active Directory integration. "
            "Run: pip install ldap3"
        ) from exc


class ActiveDirectoryAdapter(BaseAdapter):
    """
    Microsoft Active Directory adapter via ldap3.
    All long-running operations run in asyncio.to_thread() to avoid blocking
    the FastAPI event loop.
    """

    ADAPTER_NAME = "active_directory"

    def __init__(self) -> None:
        s = get_settings()
        self._server_url  = s.AD_SERVER_URL        # ldaps://dc.corp.local:636
        self._bind_dn     = s.AD_BIND_DN           # CN=svc-asc,OU=Service Accounts,DC=corp,DC=local
        self._bind_pw     = s.AD_BIND_PASSWORD     # from Vault / env
        self._base_dn     = s.AD_BASE_DN           # DC=corp,DC=local
        self._quarantine  = s.AD_QUARANTINE_OU     # OU=Quarantine,DC=corp,DC=local
        self._use_ssl     = s.AD_USE_SSL
        self._verify_cert = s.AD_VERIFY_CERT

    # ── Configuration ─────────────────────────────────────────────────────────

    def is_configured(self) -> bool:
        return bool(self._server_url and self._bind_dn and self._bind_pw and self._base_dn)

    def _build_server(self, ldap3: Any):
        """Build ldap3 Server object with optional TLS."""
        if self._use_ssl:
            tls_cfg = ldap3.Tls(
                validate=ssl.CERT_REQUIRED if self._verify_cert else ssl.CERT_NONE,
                version=ssl.PROTOCOL_TLS_CLIENT if self._verify_cert else ssl.PROTOCOL_TLS,
            )
            return ldap3.Server(
                self._server_url,
                use_ssl=True,
                tls=tls_cfg,
                get_info=ldap3.ALL,
                connect_timeout=10,
            )
        return ldap3.Server(
            self._server_url,
            get_info=ldap3.ALL,
            connect_timeout=10,
        )

    def _connect(self, ldap3: Any):
        """Open an authenticated LDAP connection. Caller is responsible for closing."""
        server = self._build_server(ldap3)
        conn = ldap3.Connection(
            server,
            user=self._bind_dn,
            password=self._bind_pw,
            auto_bind=ldap3.AUTO_BIND_TLS_BEFORE_BIND if not self._use_ssl else True,
            raise_exceptions=True,
        )
        return conn

    # ── User lookup ───────────────────────────────────────────────────────────

    def _find_user_dn_sync(self, conn: Any, ldap3: Any, username: str) -> str | None:
        """
        Search for a user by sAMAccountName and return their full DN.
        Returns None if not found.
        """
        conn.search(
            search_base=self._base_dn,
            search_filter=f"(&(objectClass=user)(sAMAccountName={username}))",
            search_scope=ldap3.SUBTREE,
            attributes=["distinguishedName", "userAccountControl", "pwdLastSet"],
        )
        if not conn.entries:
            return None
        return str(conn.entries[0].distinguishedName)

    def _get_uac_sync(self, conn: Any, ldap3: Any, user_dn: str) -> int | None:
        """Fetch the current userAccountControl value for a user DN."""
        conn.search(
            search_base=user_dn,
            search_filter="(objectClass=user)",
            search_scope=ldap3.BASE,
            attributes=["userAccountControl"],
        )
        if not conn.entries:
            return None
        raw = conn.entries[0].userAccountControl.value
        return int(raw)

    # ── Synchronous operations (run inside to_thread) ─────────────────────────

    def _disable_account_sync(self, username: str, domain: str, reason: str) -> dict:
        ldap3 = _import_ldap3()
        try:
            with self._connect(ldap3) as conn:
                user_dn = self._find_user_dn_sync(conn, ldap3, username)
                if not user_dn:
                    return self._err(
                        f"user_not_found: {username}@{domain}",
                        adapter=self.ADAPTER_NAME,
                        username=username,
                    )
                uac = self._get_uac_sync(conn, ldap3, user_dn)
                if uac is None:
                    return self._err(
                        f"uac_read_failed: {username}",
                        adapter=self.ADAPTER_NAME,
                        username=username,
                    )
                new_uac = uac | _UF_ACCOUNTDISABLE
                conn.modify(
                    user_dn,
                    {"userAccountControl": [(ldap3.MODIFY_REPLACE, [new_uac])]},
                )
                if conn.result["result"] != 0:
                    return self._err(
                        f"modify_failed: {conn.result['description']}",
                        adapter=self.ADAPTER_NAME,
                        username=username,
                    )
                log.info("ad_disable_account", username=username, domain=domain, user_dn=user_dn, new_uac=new_uac)
                return self._ok(
                    adapter=self.ADAPTER_NAME,
                    username=username,
                    domain=domain,
                    user_dn=user_dn,
                    uac_before=uac,
                    uac_after=new_uac,
                    reason=reason,
                )
        except Exception as exc:
            log.error("ad_disable_account_error", username=username, error=str(exc))
            return self._err(str(exc), adapter=self.ADAPTER_NAME, username=username)

    def _enable_account_sync(self, username: str, domain: str) -> dict:
        ldap3 = _import_ldap3()
        try:
            with self._connect(ldap3) as conn:
                user_dn = self._find_user_dn_sync(conn, ldap3, username)
                if not user_dn:
                    return self._err(
                        f"user_not_found: {username}@{domain}",
                        adapter=self.ADAPTER_NAME,
                        username=username,
                    )
                uac = self._get_uac_sync(conn, ldap3, user_dn)
                if uac is None:
                    return self._err(
                        f"uac_read_failed: {username}",
                        adapter=self.ADAPTER_NAME,
                        username=username,
                    )
                new_uac = uac & ~_UF_ACCOUNTDISABLE
                conn.modify(
                    user_dn,
                    {"userAccountControl": [(ldap3.MODIFY_REPLACE, [new_uac])]},
                )
                if conn.result["result"] != 0:
                    return self._err(
                        f"modify_failed: {conn.result['description']}",
                        adapter=self.ADAPTER_NAME,
                        username=username,
                    )
                log.info("ad_enable_account", username=username, domain=domain, user_dn=user_dn, new_uac=new_uac)
                return self._ok(
                    adapter=self.ADAPTER_NAME,
                    username=username,
                    domain=domain,
                    user_dn=user_dn,
                    uac_before=uac,
                    uac_after=new_uac,
                )
        except Exception as exc:
            log.error("ad_enable_account_error", username=username, error=str(exc))
            return self._err(str(exc), adapter=self.ADAPTER_NAME, username=username)

    def _force_password_reset_sync(self, username: str, domain: str) -> dict:
        """
        Set pwdLastSet = 0 so AD forces password change at next login.
        The user's current password remains valid for the current session.
        """
        ldap3 = _import_ldap3()
        try:
            with self._connect(ldap3) as conn:
                user_dn = self._find_user_dn_sync(conn, ldap3, username)
                if not user_dn:
                    return self._err(
                        f"user_not_found: {username}@{domain}",
                        adapter=self.ADAPTER_NAME,
                        username=username,
                    )
                # pwdLastSet = 0 → must change at next login
                # pwdLastSet = -1 → password never expires (reset from forced-change)
                conn.modify(
                    user_dn,
                    {"pwdLastSet": [(ldap3.MODIFY_REPLACE, [0])]},
                )
                if conn.result["result"] != 0:
                    return self._err(
                        f"modify_failed: {conn.result['description']}",
                        adapter=self.ADAPTER_NAME,
                        username=username,
                    )
                log.info("ad_force_password_reset", username=username, domain=domain, user_dn=user_dn)
                return self._ok(
                    adapter=self.ADAPTER_NAME,
                    username=username,
                    domain=domain,
                    user_dn=user_dn,
                    pwd_last_set=0,
                )
        except Exception as exc:
            log.error("ad_force_password_reset_error", username=username, error=str(exc))
            return self._err(str(exc), adapter=self.ADAPTER_NAME, username=username)

    def _move_to_quarantine_sync(self, username: str, domain: str) -> dict:
        """
        Move user to the quarantine OU via LDAP modifyDN.
        Requires AD_QUARANTINE_OU to be configured and the service account
        to have 'Move objects' rights on both the source and target OUs.
        """
        ldap3 = _import_ldap3()
        if not self._quarantine:
            return self._err(
                "AD_QUARANTINE_OU not configured",
                adapter=self.ADAPTER_NAME,
                username=username,
            )
        try:
            with self._connect(ldap3) as conn:
                user_dn = self._find_user_dn_sync(conn, ldap3, username)
                if not user_dn:
                    return self._err(
                        f"user_not_found: {username}@{domain}",
                        adapter=self.ADAPTER_NAME,
                        username=username,
                    )
                # Extract RDN (CN=...) from current DN
                rdn = user_dn.split(",")[0]
                conn.modify_dn(
                    dn=user_dn,
                    relative_dn=rdn,
                    new_superior=self._quarantine,
                )
                if conn.result["result"] != 0:
                    return self._err(
                        f"move_failed: {conn.result['description']}",
                        adapter=self.ADAPTER_NAME,
                        username=username,
                    )
                new_dn = f"{rdn},{self._quarantine}"
                log.info("ad_move_to_quarantine", username=username, old_dn=user_dn, new_dn=new_dn)
                return self._ok(
                    adapter=self.ADAPTER_NAME,
                    username=username,
                    domain=domain,
                    old_dn=user_dn,
                    new_dn=new_dn,
                    quarantine_ou=self._quarantine,
                )
        except Exception as exc:
            log.error("ad_move_quarantine_error", username=username, error=str(exc))
            return self._err(str(exc), adapter=self.ADAPTER_NAME, username=username)

    def _search_user_sync(self, username: str) -> dict:
        """
        Search for a user by sAMAccountName and return their directory attributes.

        Returns a dict with: username, display_name, email, dn, enabled,
        groups, last_logon_str (if available), department, title.
        """
        ldap3 = _import_ldap3()
        try:
            with self._connect(ldap3) as conn:
                conn.search(
                    search_base=self._base_dn,
                    search_filter=f"(&(objectClass=user)(sAMAccountName={username}))",
                    search_scope=ldap3.SUBTREE,
                    attributes=[
                        "distinguishedName",
                        "displayName",
                        "mail",
                        "userAccountControl",
                        "memberOf",
                        "department",
                        "title",
                        "lastLogon",
                        "pwdLastSet",
                    ],
                )
                if not conn.entries:
                    return self._err(
                        f"user_not_found: {username}",
                        adapter=self.ADAPTER_NAME,
                        username=username,
                    )
                entry = conn.entries[0]

                def _str(attr) -> str | None:
                    try:
                        v = attr.value
                        return str(v) if v else None
                    except Exception:
                        return None

                uac = int(entry.userAccountControl.value or 0)
                groups = []
                try:
                    raw_groups = entry.memberOf.values
                    groups = [str(g).split(",")[0].replace("CN=", "") for g in raw_groups]
                except Exception:  # nosec B110 — memberOf is optional; empty list is safe default
                    pass

                return self._ok(
                    adapter=self.ADAPTER_NAME,
                    username=username,
                    dn=_str(entry.distinguishedName),
                    display_name=_str(entry.displayName),
                    email=_str(entry.mail),
                    enabled=not bool(uac & _UF_ACCOUNTDISABLE),
                    uac=uac,
                    department=_str(entry.department),
                    title=_str(entry.title),
                    groups=groups,
                    group_count=len(groups),
                )
        except Exception as exc:
            log.error("ad_search_user_error", username=username, error=str(exc))
            return self._err(str(exc), adapter=self.ADAPTER_NAME, username=username)

    def _list_group_members_sync(self, group_name: str) -> dict:
        """
        List members of an AD group by CN.

        Searches for the group DN first, then queries member DNs and resolves
        each to {username, display_name, email, enabled}.
        """
        ldap3 = _import_ldap3()
        try:
            with self._connect(ldap3) as conn:
                # Find group DN
                conn.search(
                    search_base=self._base_dn,
                    search_filter=f"(&(objectClass=group)(cn={group_name}))",
                    search_scope=ldap3.SUBTREE,
                    attributes=["member", "distinguishedName"],
                )
                if not conn.entries:
                    return self._err(
                        f"group_not_found: {group_name}",
                        adapter=self.ADAPTER_NAME,
                        group=group_name,
                    )
                group_entry = conn.entries[0]
                try:
                    member_dns = list(group_entry.member.values)
                except Exception:
                    member_dns = []

                members: list[dict] = []
                for member_dn in member_dns[:200]:  # cap at 200 to avoid huge responses
                    try:
                        conn.search(
                            search_base=str(member_dn),
                            search_filter="(objectClass=user)",
                            search_scope=ldap3.BASE,
                            attributes=["sAMAccountName", "displayName", "mail", "userAccountControl"],
                        )
                        if conn.entries:
                            e = conn.entries[0]
                            uac = int(e.userAccountControl.value or 0)
                            members.append({
                                "username": str(e.sAMAccountName.value or ""),
                                "display_name": str(e.displayName.value or ""),
                                "email": str(e.mail.value or "") if e.mail.value else None,
                                "enabled": not bool(uac & _UF_ACCOUNTDISABLE),
                                "dn": str(member_dn),
                            })
                    except Exception:  # nosec B110 — member attributes may be inaccessible; skip silently
                        pass

                log.info("ad_list_group_members", group=group_name, count=len(members))
                return self._ok(
                    adapter=self.ADAPTER_NAME,
                    group=group_name,
                    group_dn=str(group_entry.distinguishedName),
                    member_count=len(members),
                    members=members,
                )
        except Exception as exc:
            log.error("ad_list_group_members_error", group=group_name, error=str(exc))
            return self._err(str(exc), adapter=self.ADAPTER_NAME, group=group_name)

    def _health_check_sync(self) -> dict:
        ldap3 = _import_ldap3()
        try:
            with self._connect(ldap3) as conn:
                conn.search(
                    search_base=self._base_dn,
                    search_filter="(objectClass=domain)",
                    search_scope=ldap3.BASE,
                    attributes=["distinguishedName"],
                )
                if conn.entries:
                    return self._ok(
                        adapter=self.ADAPTER_NAME,
                        server=self._server_url,
                        base_dn=self._base_dn,
                        ssl=self._use_ssl,
                    )
                return self._err(
                    "base_dn_not_found",
                    adapter=self.ADAPTER_NAME,
                )
        except Exception as exc:
            return self._err(str(exc), adapter=self.ADAPTER_NAME)

    # ── Async public API ──────────────────────────────────────────────────────

    async def disable_account(self, username: str, domain: str, reason: str = "") -> dict:
        if not self.is_configured():
            return self._not_configured()
        return await asyncio.to_thread(self._disable_account_sync, username, domain, reason)

    async def enable_account(self, username: str, domain: str) -> dict:
        if not self.is_configured():
            return self._not_configured()
        return await asyncio.to_thread(self._enable_account_sync, username, domain)

    async def force_password_reset(self, username: str, domain: str) -> dict:
        if not self.is_configured():
            return self._not_configured()
        return await asyncio.to_thread(self._force_password_reset_sync, username, domain)

    async def move_to_quarantine_ou(self, username: str, domain: str) -> dict:
        if not self.is_configured():
            return self._not_configured()
        return await asyncio.to_thread(self._move_to_quarantine_sync, username, domain)

    async def test_connection(self) -> dict:
        if not self.is_configured():
            return self._not_configured()
        return await asyncio.to_thread(self._health_check_sync)

    async def search_user(self, username: str) -> dict:
        if not self.is_configured():
            return self._not_configured()
        return await asyncio.to_thread(self._search_user_sync, username)

    async def list_group_members(self, group_name: str) -> dict:
        if not self.is_configured():
            return self._not_configured()
        return await asyncio.to_thread(self._list_group_members_sync, group_name)
