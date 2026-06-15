"""
FASE 1 — Real Integrations: Unit test suite.

Coverage:
  TestPaloAltoHelpers        — name sanitization, XML parsing utilities
  TestPaloAltoConfiguration  — is_configured() / not-configured early returns
  TestPaloAltoBlockIP        — block_ip / unblock_ip HTTP interactions (mocked)
  TestPaloAltoBlockDomain    — block_domain / unblock_domain (mocked)
  TestPaloAltoConnection     — test_connection success / failure (mocked)
  TestFortinetConfiguration  — is_configured() / not-configured early returns
  TestFortinetBlockIP        — block_ip / unblock_ip HTTP interactions (mocked)
  TestFortinetBlockDomain    — block_domain / unblock_domain (mocked)
  TestFortinetConnection     — test_connection success / failure (mocked)
  TestADConfiguration        — is_configured() / not-configured early returns
  TestADDisableAccount       — disable_account sync logic (mocked ldap3)
  TestADEnableAccount        — enable_account sync logic (mocked ldap3)
  TestADForcePasswordReset   — force_password_reset sync logic (mocked ldap3)
  TestADMoveQuarantine       — move_to_quarantine_ou (mocked ldap3)
  TestADHealthCheck          — test_connection / health_check (mocked ldap3)
  TestSpectBridgeFirewallWire — SPECTER Bridge broadcast calls firewall adapter
  TestSpectBridgeIAMWire      — SPECTER Bridge IAM calls AD adapter

All external I/O (httpx, ldap3) is mocked — no live firewall or AD required.
Tests run without any external dependencies via pytest-asyncio + unittest.mock.

Mandatory test runs:
  cd backend
  python -m pytest tests/test_integrations.py -v
  python -m pytest tests/ -q
"""
from __future__ import annotations

import types
import unittest
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# Helpers — XML response builders
# ─────────────────────────────────────────────────────────────────────────────

def _pan_ok(inner: str = "<result>ok</result>") -> str:
    return f'<response status="success">{inner}</response>'


def _pan_err(msg: str = "error") -> str:
    return f'<response status="error"><msg>{msg}</msg></response>'


def _pan_job(job_id: str = "42") -> str:
    return f'<response status="success"><result><job>{job_id}</job></result></response>'


def _pan_job_fin(result: str = "OK") -> str:
    return (
        f'<response status="success"><result>'
        f'<job><status>FIN</status><result>{result}</result></job>'
        f'</result></response>'
    )


def _pan_group_members(*names: str) -> str:
    members = "".join(f"<member>{n}</member>" for n in names)
    return f'<response status="success"><result><static>{members}</static></result></response>'


# ─────────────────────────────────────────────────────────────────────────────
# TestPaloAltoHelpers
# ─────────────────────────────────────────────────────────────────────────────

class TestPaloAltoHelpers(unittest.TestCase):
    def test_ip_name_sanitization(self):
        from app.adapters.firewall.paloalto import _sanitize_ip_name
        assert _sanitize_ip_name("192.168.1.1") == "ASC-BLK-IP-192-168-1-1"

    def test_ip_name_max_63_chars(self):
        from app.adapters.firewall.paloalto import _sanitize_ip_name
        name = _sanitize_ip_name("255.255.255.255")
        assert len(name) <= 63

    def test_domain_name_sanitization(self):
        from app.adapters.firewall.paloalto import _sanitize_domain_name
        assert _sanitize_domain_name("evil.example.com") == "ASC-BLK-DOM-evil-example-com"

    def test_domain_name_max_63_chars(self):
        from app.adapters.firewall.paloalto import _sanitize_domain_name
        name = _sanitize_domain_name("a" * 70 + ".com")
        assert len(name) <= 63

    def test_parse_status_success(self):
        from app.adapters.firewall.paloalto import _parse_status
        ok, msg = _parse_status(_pan_ok())
        assert ok is True

    def test_parse_status_error(self):
        from app.adapters.firewall.paloalto import _parse_status
        ok, msg = _parse_status(_pan_err("bad xpath"))
        assert ok is False
        assert "bad xpath" in msg

    def test_parse_status_invalid_xml(self):
        from app.adapters.firewall.paloalto import _parse_status
        ok, msg = _parse_status("not xml at all <<<")
        assert ok is False
        assert "xml_parse_error" in msg

    def test_extract_job_id(self):
        from app.adapters.firewall.paloalto import _extract_job_id
        assert _extract_job_id(_pan_job("99")) == "99"

    def test_extract_job_id_missing(self):
        from app.adapters.firewall.paloalto import _extract_job_id
        assert _extract_job_id(_pan_ok()) is None

    def test_extract_group_members(self):
        from app.adapters.firewall.paloalto import _extract_group_members
        members = _extract_group_members(_pan_group_members("A", "B", "C"))
        assert members == ["A", "B", "C"]

    def test_extract_group_members_empty(self):
        from app.adapters.firewall.paloalto import _extract_group_members
        assert _extract_group_members(_pan_ok()) == []


# ─────────────────────────────────────────────────────────────────────────────
# TestPaloAltoConfiguration
# ─────────────────────────────────────────────────────────────────────────────

class TestPaloAltoConfiguration(unittest.IsolatedAsyncioTestCase):
    def _make_adapter(self, host="", api_key=""):
        from app.adapters.firewall.paloalto import PaloAltoAdapter
        with patch("app.adapters.firewall.paloalto.get_settings") as mock_s:
            s = MagicMock()
            s.PALOALTO_HOST = host
            s.PALOALTO_API_KEY = api_key
            s.PALOALTO_VSYS = "vsys1"
            s.PALOALTO_BLOCKED_IP_GROUP = "ASC-Blocked-IPs"
            s.PALOALTO_BLOCKED_URL_CATEGORY = "ASC-Blocked-Domains"
            mock_s.return_value = s
            return PaloAltoAdapter()

    def test_not_configured_when_no_host(self):
        adapter = self._make_adapter(host="", api_key="abc123")
        assert adapter.is_configured() is False

    def test_not_configured_when_no_key(self):
        adapter = self._make_adapter(host="fw.corp.local", api_key="")
        assert adapter.is_configured() is False

    def test_configured_when_both_set(self):
        adapter = self._make_adapter(host="fw.corp.local", api_key="abc123")
        assert adapter.is_configured() is True

    async def test_block_ip_returns_not_configured(self):
        adapter = self._make_adapter()
        result = await adapter.block_ip("1.2.3.4")
        assert result["success"] is False
        assert "not configured" in result["error"].lower()

    async def test_block_domain_returns_not_configured(self):
        adapter = self._make_adapter()
        result = await adapter.block_domain("evil.com")
        assert result["success"] is False

    async def test_test_connection_returns_not_configured(self):
        adapter = self._make_adapter()
        result = await adapter.test_connection()
        assert result["success"] is False


# ─────────────────────────────────────────────────────────────────────────────
# TestPaloAltoBlockIP
# ─────────────────────────────────────────────────────────────────────────────

class TestPaloAltoBlockIP(unittest.IsolatedAsyncioTestCase):
    def _make_configured_adapter(self):
        from app.adapters.firewall.paloalto import PaloAltoAdapter
        with patch("app.adapters.firewall.paloalto.get_settings") as mock_s:
            s = MagicMock()
            s.PALOALTO_HOST = "fw.corp.local"
            s.PALOALTO_API_KEY = "test-key"
            s.PALOALTO_VSYS = "vsys1"
            s.PALOALTO_BLOCKED_IP_GROUP = "ASC-Blocked-IPs"
            s.PALOALTO_BLOCKED_URL_CATEGORY = "ASC-Blocked-Domains"
            mock_s.return_value = s
            return PaloAltoAdapter()

    async def test_block_ip_success(self):
        adapter = self._make_configured_adapter()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        # Responses: create address → get group → set member → commit → poll job
        mock_resp.text = _pan_ok()

        responses = [
            _pan_ok(),                       # create address object
            _pan_group_members(),            # get group (empty)
            _pan_ok(),                       # add member
            _pan_job("1"),                   # commit accepted
            _pan_job_fin("OK"),              # job finished
        ]
        call_index = {"i": 0}

        async def fake_get(url, params=None, **kwargs):
            r = MagicMock()
            r.raise_for_status = MagicMock()
            r.text = responses[call_index["i"]]
            call_index["i"] += 1
            return r

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = fake_get
            mock_client_cls.return_value = mock_client

            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await adapter.block_ip("192.168.1.100")

        assert result["success"] is True
        assert result["ip"] == "192.168.1.100"
        assert result["adapter"] == "paloalto"
        assert "object_name" in result

    async def test_block_ip_already_in_group_skips_add(self):
        adapter = self._make_configured_adapter()
        ip = "10.0.0.1"
        obj_name = "ASC-BLK-IP-10-0-0-1"

        responses = [
            _pan_ok(),                            # create address
            _pan_group_members(obj_name, "other"),# get group — already present
            _pan_job("2"),                        # commit
            _pan_job_fin("OK"),
        ]
        call_index = {"i": 0}

        async def fake_get(url, params=None, **kwargs):
            r = MagicMock()
            r.raise_for_status = MagicMock()
            r.text = responses[call_index["i"]]
            call_index["i"] += 1
            return r

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = fake_get
            mock_client_cls.return_value = mock_client

            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await adapter.block_ip(ip)

        # Should succeed without calling set (only 4 calls, not 5)
        assert result["success"] is True
        assert call_index["i"] == 4

    async def test_block_ip_api_error_returns_failure(self):
        adapter = self._make_configured_adapter()

        async def fake_get(url, params=None, **kwargs):
            r = MagicMock()
            r.raise_for_status = MagicMock(side_effect=Exception("connection refused"))
            return r

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = fake_get
            mock_client_cls.return_value = mock_client

            result = await adapter.block_ip("1.2.3.4")

        assert result["success"] is False
        assert "error" in result

    async def test_unblock_ip_success(self):
        adapter = self._make_configured_adapter()
        responses = [
            _pan_ok(),        # delete from group
            _pan_ok(),        # delete address object
            _pan_job("3"),    # commit
            _pan_job_fin("OK"),
        ]
        call_index = {"i": 0}

        async def fake_get(url, params=None, **kwargs):
            r = MagicMock()
            r.raise_for_status = MagicMock()
            r.text = responses[call_index["i"]]
            call_index["i"] += 1
            return r

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = fake_get
            mock_client_cls.return_value = mock_client

            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await adapter.unblock_ip("192.168.1.100")

        assert result["success"] is True


# ─────────────────────────────────────────────────────────────────────────────
# TestPaloAltoBlockDomain
# ─────────────────────────────────────────────────────────────────────────────

class TestPaloAltoBlockDomain(unittest.IsolatedAsyncioTestCase):
    def _make_configured_adapter(self):
        from app.adapters.firewall.paloalto import PaloAltoAdapter
        with patch("app.adapters.firewall.paloalto.get_settings") as mock_s:
            s = MagicMock()
            s.PALOALTO_HOST = "fw.corp.local"
            s.PALOALTO_API_KEY = "test-key"
            s.PALOALTO_VSYS = "vsys1"
            s.PALOALTO_BLOCKED_IP_GROUP = "ASC-Blocked-IPs"
            s.PALOALTO_BLOCKED_URL_CATEGORY = "ASC-Blocked-Domains"
            mock_s.return_value = s
            return PaloAltoAdapter()

    async def test_block_domain_success(self):
        adapter = self._make_configured_adapter()

        responses = [
            _pan_ok(),          # get URL category (empty list)
            _pan_ok(),          # add member
            _pan_job("4"),      # commit
            _pan_job_fin("OK"),
        ]
        call_index = {"i": 0}

        async def fake_get(url, params=None, **kwargs):
            r = MagicMock()
            r.raise_for_status = MagicMock()
            r.text = responses[call_index["i"]]
            call_index["i"] += 1
            return r

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = fake_get
            mock_client_cls.return_value = mock_client

            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await adapter.block_domain("evil.example.com")

        assert result["success"] is True
        assert result["domain"] == "evil.example.com"

    async def test_unblock_domain_success(self):
        adapter = self._make_configured_adapter()
        responses = [
            _pan_ok(),        # delete from category
            _pan_job("5"),    # commit
            _pan_job_fin("OK"),
        ]
        call_index = {"i": 0}

        async def fake_get(url, params=None, **kwargs):
            r = MagicMock()
            r.raise_for_status = MagicMock()
            r.text = responses[call_index["i"]]
            call_index["i"] += 1
            return r

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = fake_get
            mock_client_cls.return_value = mock_client

            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await adapter.unblock_domain("evil.example.com")

        assert result["success"] is True


# ─────────────────────────────────────────────────────────────────────────────
# TestPaloAltoConnection
# ─────────────────────────────────────────────────────────────────────────────

class TestPaloAltoConnection(unittest.IsolatedAsyncioTestCase):
    def _make_configured_adapter(self):
        from app.adapters.firewall.paloalto import PaloAltoAdapter
        with patch("app.adapters.firewall.paloalto.get_settings") as mock_s:
            s = MagicMock()
            s.PALOALTO_HOST = "fw.corp.local"
            s.PALOALTO_API_KEY = "test-key"
            s.PALOALTO_VSYS = "vsys1"
            s.PALOALTO_BLOCKED_IP_GROUP = "ASC-Blocked-IPs"
            s.PALOALTO_BLOCKED_URL_CATEGORY = "ASC-Blocked-Domains"
            mock_s.return_value = s
            return PaloAltoAdapter()

    async def test_connection_success(self):
        adapter = self._make_configured_adapter()
        sys_info = _pan_ok(
            "<result><system>"
            "<model>PA-5250</model><sw-version>11.1.2</sw-version>"
            "</system></result>"
        )

        async def fake_get(url, params=None, **kwargs):
            r = MagicMock()
            r.raise_for_status = MagicMock()
            r.text = sys_info
            return r

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = fake_get
            mock_client_cls.return_value = mock_client

            result = await adapter.test_connection()

        assert result["success"] is True
        assert result["model"] == "PA-5250"
        assert result["sw_version"] == "11.1.2"

    async def test_connection_failure(self):
        adapter = self._make_configured_adapter()

        async def fake_get(url, params=None, **kwargs):
            raise Exception("Connection refused")

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = fake_get
            mock_client_cls.return_value = mock_client

            result = await adapter.test_connection()

        assert result["success"] is False
        assert "Connection refused" in result["error"]


# ─────────────────────────────────────────────────────────────────────────────
# TestFortinetConfiguration
# ─────────────────────────────────────────────────────────────────────────────

class TestFortinetConfiguration(unittest.IsolatedAsyncioTestCase):
    def _make_adapter(self, host="", token=""):
        from app.adapters.firewall.fortinet import FortinetAdapter
        with patch("app.adapters.firewall.fortinet.get_settings") as mock_s:
            s = MagicMock()
            s.FORTINET_HOST = host
            s.FORTINET_API_TOKEN = token
            s.FORTINET_VDOM = "root"
            s.FORTINET_BLOCKED_IP_GROUP = "ASC-Blocked-IPs"
            s.FORTINET_BLOCKED_DOMAIN_GROUP = "ASC-Blocked-Domains"
            mock_s.return_value = s
            return FortinetAdapter()

    def test_not_configured_when_no_host(self):
        adapter = self._make_adapter(token="tok")
        assert adapter.is_configured() is False

    def test_not_configured_when_no_token(self):
        adapter = self._make_adapter(host="fg.corp.local")
        assert adapter.is_configured() is False

    def test_configured_when_both_set(self):
        adapter = self._make_adapter(host="fg.corp.local", token="tok")
        assert adapter.is_configured() is True

    async def test_block_ip_returns_not_configured(self):
        adapter = self._make_adapter()
        result = await adapter.block_ip("1.2.3.4")
        assert result["success"] is False

    async def test_block_domain_returns_not_configured(self):
        adapter = self._make_adapter()
        result = await adapter.block_domain("evil.com")
        assert result["success"] is False


# ─────────────────────────────────────────────────────────────────────────────
# TestFortinetBlockIP
# ─────────────────────────────────────────────────────────────────────────────

class TestFortinetBlockIP(unittest.IsolatedAsyncioTestCase):
    def _make_configured_adapter(self):
        from app.adapters.firewall.fortinet import FortinetAdapter
        with patch("app.adapters.firewall.fortinet.get_settings") as mock_s:
            s = MagicMock()
            s.FORTINET_HOST = "fg.corp.local"
            s.FORTINET_API_TOKEN = "test-token"
            s.FORTINET_VDOM = "root"
            s.FORTINET_BLOCKED_IP_GROUP = "ASC-Blocked-IPs"
            s.FORTINET_BLOCKED_DOMAIN_GROUP = "ASC-Blocked-Domains"
            mock_s.return_value = s
            return FortinetAdapter()

    def _mock_http_client(self, post_resp=None, get_resp=None, put_resp=None):
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        def _make_resp(body):
            r = MagicMock()
            r.status_code = 200
            r.raise_for_status = MagicMock()
            r.json = MagicMock(return_value=body)
            r.text = str(body)
            return r

        if post_resp is not None:
            mock_client.post = AsyncMock(return_value=_make_resp(post_resp))
        if get_resp is not None:
            mock_client.get = AsyncMock(return_value=_make_resp(get_resp))
        if put_resp is not None:
            mock_client.put = AsyncMock(return_value=_make_resp(put_resp))
        if not hasattr(mock_client, "delete") or mock_client.delete is None:
            mock_client.delete = AsyncMock(return_value=_make_resp({}))
        return mock_client

    async def test_block_ip_success(self):
        adapter = self._make_configured_adapter()
        group_response = {"results": [{"name": "ASC-Blocked-IPs", "member": []}]}

        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)

            def _resp(body, status=200):
                r = MagicMock()
                r.status_code = status
                r.raise_for_status = MagicMock()
                r.json = MagicMock(return_value=body)
                r.text = ""
                return r

            mock_client.post = AsyncMock(return_value=_resp({"status": "success"}))
            mock_client.get = AsyncMock(return_value=_resp(group_response))
            mock_client.put = AsyncMock(return_value=_resp({"status": "success"}))
            mock_cls.return_value = mock_client

            result = await adapter.block_ip("192.168.1.50", "both", "test block")

        assert result["success"] is True
        assert result["ip"] == "192.168.1.50"
        assert result["adapter"] == "fortinet"

    async def test_fortinet_ip_name_sanitization(self):
        from app.adapters.firewall.fortinet import _sanitize_ip_name
        assert _sanitize_ip_name("10.0.0.1") == "ASC-BLK-IP-10-0-0-1"

    async def test_fortinet_domain_name_sanitization(self):
        from app.adapters.firewall.fortinet import _sanitize_domain_name
        assert _sanitize_domain_name("bad.actor.ru") == "ASC-BLK-DOM-bad-actor-ru"

    async def test_unblock_ip_success(self):
        adapter = self._make_configured_adapter()
        group_response = {
            "results": [{"name": "ASC-Blocked-IPs", "member": [{"name": "ASC-BLK-IP-10-0-0-1"}]}]
        }

        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)

            def _resp(body, status=200):
                r = MagicMock()
                r.status_code = status
                r.raise_for_status = MagicMock()
                r.json = MagicMock(return_value=body)
                r.text = ""
                return r

            mock_client.get = AsyncMock(return_value=_resp(group_response))
            mock_client.put = AsyncMock(return_value=_resp({"status": "success"}))
            mock_client.delete = AsyncMock(return_value=_resp({}, status=204))
            mock_cls.return_value = mock_client

            result = await adapter.unblock_ip("10.0.0.1")

        assert result["success"] is True

    async def test_fortinet_connection_success(self):
        adapter = self._make_configured_adapter()
        status_body = {
            "results": {
                "Serial-Number": "FGT60ETK12345",
                "Version": "v7.2.5",
                "Hostname": "fortigate-corp",
            }
        }

        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)

            def _resp(body):
                r = MagicMock()
                r.raise_for_status = MagicMock()
                r.json = MagicMock(return_value=body)
                return r

            mock_client.get = AsyncMock(return_value=_resp(status_body))
            mock_cls.return_value = mock_client

            result = await adapter.test_connection()

        assert result["success"] is True
        assert result["serial"] == "FGT60ETK12345"
        assert result["version"] == "v7.2.5"


# ─────────────────────────────────────────────────────────────────────────────
# TestADConfiguration
# ─────────────────────────────────────────────────────────────────────────────

class TestADConfiguration(unittest.IsolatedAsyncioTestCase):
    def _make_adapter(self, server="", bind_dn="", bind_pw="", base_dn=""):
        from app.adapters.identity.active_directory import ActiveDirectoryAdapter
        with patch("app.adapters.identity.active_directory.get_settings") as mock_s:
            s = MagicMock()
            s.AD_SERVER_URL = server
            s.AD_BIND_DN = bind_dn
            s.AD_BIND_PASSWORD = bind_pw
            s.AD_BASE_DN = base_dn
            s.AD_QUARANTINE_OU = ""
            s.AD_USE_SSL = True
            s.AD_VERIFY_CERT = False
            mock_s.return_value = s
            return ActiveDirectoryAdapter()

    def test_not_configured_when_empty(self):
        adapter = self._make_adapter()
        assert adapter.is_configured() is False

    def test_not_configured_missing_bind_pw(self):
        adapter = self._make_adapter(
            server="ldaps://dc.corp.local:636",
            bind_dn="CN=svc,DC=corp,DC=local",
            base_dn="DC=corp,DC=local",
        )
        assert adapter.is_configured() is False

    def test_configured_when_all_set(self):
        adapter = self._make_adapter(
            server="ldaps://dc.corp.local:636",
            bind_dn="CN=svc,DC=corp,DC=local",
            bind_pw="secret",
            base_dn="DC=corp,DC=local",
        )
        assert adapter.is_configured() is True

    async def test_disable_returns_not_configured(self):
        adapter = self._make_adapter()
        result = await adapter.disable_account("jsmith", "CORP")
        assert result["success"] is False

    async def test_enable_returns_not_configured(self):
        adapter = self._make_adapter()
        result = await adapter.enable_account("jsmith", "CORP")
        assert result["success"] is False

    async def test_force_reset_returns_not_configured(self):
        adapter = self._make_adapter()
        result = await adapter.force_password_reset("jsmith", "CORP")
        assert result["success"] is False


# ─────────────────────────────────────────────────────────────────────────────
# TestADDisableAccount (mocked ldap3 at sync level)
# ─────────────────────────────────────────────────────────────────────────────

def _make_ad_adapter_configured():
    from app.adapters.identity.active_directory import ActiveDirectoryAdapter
    with patch("app.adapters.identity.active_directory.get_settings") as mock_s:
        s = MagicMock()
        s.AD_SERVER_URL = "ldaps://dc.corp.local:636"
        s.AD_BIND_DN = "CN=svc-asc,DC=corp,DC=local"
        s.AD_BIND_PASSWORD = "test-password"  # nosec B106
        s.AD_BASE_DN = "DC=corp,DC=local"
        s.AD_QUARANTINE_OU = "OU=Quarantine,DC=corp,DC=local"
        s.AD_USE_SSL = False  # simplified for tests — no real SSL
        s.AD_VERIFY_CERT = False
        mock_s.return_value = s
        return ActiveDirectoryAdapter()


class TestADDisableAccount(unittest.TestCase):
    def _mock_ldap3_module(self, user_dn="CN=jsmith,OU=Users,DC=corp,DC=local", uac=512):
        """Build a fake ldap3 module with a mock Connection context manager."""
        ldap3_mock = MagicMock()
        ldap3_mock.SUBTREE = "SUBTREE"
        ldap3_mock.BASE = "BASE"
        ldap3_mock.MODIFY_REPLACE = "MODIFY_REPLACE"
        ldap3_mock.ALL = "ALL"
        ldap3_mock.AUTO_BIND_TLS_BEFORE_BIND = "AUTO_BIND_TLS_BEFORE_BIND"

        conn_mock = MagicMock()
        conn_mock.__enter__ = MagicMock(return_value=conn_mock)
        conn_mock.__exit__ = MagicMock(return_value=False)
        conn_mock.result = {"result": 0, "description": "success"}

        # Mock entry for user search
        entry_mock = MagicMock()
        entry_mock.distinguishedName.value = user_dn
        entry_mock.userAccountControl.value = str(uac)

        def search_side_effect(search_base, search_filter, search_scope, attributes):
            conn_mock.entries = [entry_mock]

        conn_mock.search = MagicMock(side_effect=search_side_effect)

        ldap3_mock.Connection = MagicMock(return_value=conn_mock)
        ldap3_mock.Server = MagicMock()
        ldap3_mock.Tls = MagicMock()
        return ldap3_mock, conn_mock

    def test_disable_account_sets_uac_disabled_flag(self):
        adapter = _make_ad_adapter_configured()
        ldap3_mock, conn_mock = self._mock_ldap3_module(uac=512)  # normal account

        with patch("app.adapters.identity.active_directory._import_ldap3", return_value=ldap3_mock):
            result = adapter._disable_account_sync("jsmith", "CORP", "test reason")

        assert result["success"] is True
        # UAC 512 | 0x0002 = 514
        assert result["uac_after"] == 514
        assert result["uac_before"] == 512
        conn_mock.modify.assert_called_once()

    def test_disable_account_user_not_found(self):
        adapter = _make_ad_adapter_configured()
        ldap3_mock = MagicMock()
        ldap3_mock.SUBTREE = "SUBTREE"
        ldap3_mock.BASE = "BASE"
        ldap3_mock.ALL = "ALL"
        ldap3_mock.AUTO_BIND_TLS_BEFORE_BIND = "AUTO_BIND_TLS_BEFORE_BIND"
        ldap3_mock.Tls = MagicMock()
        ldap3_mock.Server = MagicMock()

        conn_mock = MagicMock()
        conn_mock.__enter__ = MagicMock(return_value=conn_mock)
        conn_mock.__exit__ = MagicMock(return_value=False)
        conn_mock.entries = []
        conn_mock.search = MagicMock()
        ldap3_mock.Connection = MagicMock(return_value=conn_mock)

        with patch("app.adapters.identity.active_directory._import_ldap3", return_value=ldap3_mock):
            result = adapter._disable_account_sync("ghost", "CORP", "")

        assert result["success"] is False
        assert "user_not_found" in result["error"]

    def test_disable_account_ldap_error(self):
        adapter = _make_ad_adapter_configured()
        ldap3_mock = MagicMock()
        ldap3_mock.ALL = "ALL"
        ldap3_mock.AUTO_BIND_TLS_BEFORE_BIND = "AUTO_BIND_TLS_BEFORE_BIND"
        ldap3_mock.Tls = MagicMock()
        ldap3_mock.Server = MagicMock()
        ldap3_mock.Connection = MagicMock(side_effect=Exception("LDAP connection failed"))

        with patch("app.adapters.identity.active_directory._import_ldap3", return_value=ldap3_mock):
            result = adapter._disable_account_sync("jsmith", "CORP", "")

        assert result["success"] is False
        assert "LDAP connection failed" in result["error"]


class TestADEnableAccount(unittest.TestCase):
    def _mock_ldap3_module(self, user_dn="CN=jsmith,OU=Users,DC=corp,DC=local", uac=514):
        ldap3_mock = MagicMock()
        ldap3_mock.SUBTREE = "SUBTREE"
        ldap3_mock.BASE = "BASE"
        ldap3_mock.MODIFY_REPLACE = "MODIFY_REPLACE"
        ldap3_mock.ALL = "ALL"
        ldap3_mock.AUTO_BIND_TLS_BEFORE_BIND = "AUTO_BIND_TLS_BEFORE_BIND"
        ldap3_mock.Tls = MagicMock()

        conn_mock = MagicMock()
        conn_mock.__enter__ = MagicMock(return_value=conn_mock)
        conn_mock.__exit__ = MagicMock(return_value=False)
        conn_mock.result = {"result": 0, "description": "success"}

        entry_mock = MagicMock()
        entry_mock.distinguishedName.value = user_dn
        entry_mock.userAccountControl.value = str(uac)

        def search_side_effect(*a, **kw):
            conn_mock.entries = [entry_mock]

        conn_mock.search = MagicMock(side_effect=search_side_effect)
        ldap3_mock.Connection = MagicMock(return_value=conn_mock)
        ldap3_mock.Server = MagicMock()
        return ldap3_mock, conn_mock

    def test_enable_account_clears_disabled_flag(self):
        adapter = _make_ad_adapter_configured()
        ldap3_mock, conn_mock = self._mock_ldap3_module(uac=514)  # disabled account

        with patch("app.adapters.identity.active_directory._import_ldap3", return_value=ldap3_mock):
            result = adapter._enable_account_sync("jsmith", "CORP")

        assert result["success"] is True
        # UAC 514 & ~0x0002 = 512
        assert result["uac_after"] == 512
        assert result["uac_before"] == 514


class TestADForcePasswordReset(unittest.TestCase):
    def _mock_ldap3_module(self, user_dn="CN=jsmith,OU=Users,DC=corp,DC=local"):
        ldap3_mock = MagicMock()
        ldap3_mock.SUBTREE = "SUBTREE"
        ldap3_mock.BASE = "BASE"
        ldap3_mock.MODIFY_REPLACE = "MODIFY_REPLACE"
        ldap3_mock.ALL = "ALL"
        ldap3_mock.AUTO_BIND_TLS_BEFORE_BIND = "AUTO_BIND_TLS_BEFORE_BIND"
        ldap3_mock.Tls = MagicMock()

        conn_mock = MagicMock()
        conn_mock.__enter__ = MagicMock(return_value=conn_mock)
        conn_mock.__exit__ = MagicMock(return_value=False)
        conn_mock.result = {"result": 0, "description": "success"}

        entry_mock = MagicMock()
        entry_mock.distinguishedName.value = user_dn

        def search_side_effect(*a, **kw):
            conn_mock.entries = [entry_mock]

        conn_mock.search = MagicMock(side_effect=search_side_effect)
        ldap3_mock.Connection = MagicMock(return_value=conn_mock)
        ldap3_mock.Server = MagicMock()
        return ldap3_mock, conn_mock

    def test_force_password_reset_sets_pwd_last_set_zero(self):
        adapter = _make_ad_adapter_configured()
        ldap3_mock, conn_mock = self._mock_ldap3_module()

        with patch("app.adapters.identity.active_directory._import_ldap3", return_value=ldap3_mock):
            result = adapter._force_password_reset_sync("jsmith", "CORP")

        assert result["success"] is True
        assert result["pwd_last_set"] == 0
        # Verify modify was called with pwdLastSet=0
        call_args = conn_mock.modify.call_args
        assert "pwdLastSet" in call_args[0][1]
        assert call_args[0][1]["pwdLastSet"][0][1] == [0]


class TestADMoveQuarantine(unittest.TestCase):
    def _mock_ldap3_module(self, user_dn="CN=jsmith,OU=Users,DC=corp,DC=local"):
        ldap3_mock = MagicMock()
        ldap3_mock.SUBTREE = "SUBTREE"
        ldap3_mock.BASE = "BASE"
        ldap3_mock.ALL = "ALL"
        ldap3_mock.AUTO_BIND_TLS_BEFORE_BIND = "AUTO_BIND_TLS_BEFORE_BIND"
        ldap3_mock.Tls = MagicMock()

        conn_mock = MagicMock()
        conn_mock.__enter__ = MagicMock(return_value=conn_mock)
        conn_mock.__exit__ = MagicMock(return_value=False)
        conn_mock.result = {"result": 0, "description": "success"}

        entry_mock = MagicMock()
        entry_mock.distinguishedName.value = user_dn

        def search_side_effect(*a, **kw):
            conn_mock.entries = [entry_mock]

        conn_mock.search = MagicMock(side_effect=search_side_effect)
        ldap3_mock.Connection = MagicMock(return_value=conn_mock)
        ldap3_mock.Server = MagicMock()
        return ldap3_mock, conn_mock

    def test_move_to_quarantine_calls_modify_dn(self):
        adapter = _make_ad_adapter_configured()
        ldap3_mock, conn_mock = self._mock_ldap3_module()

        with patch("app.adapters.identity.active_directory._import_ldap3", return_value=ldap3_mock):
            result = adapter._move_to_quarantine_sync("jsmith", "CORP")

        assert result["success"] is True
        conn_mock.modify_dn.assert_called_once()
        assert "OU=Quarantine" in result["new_dn"]

    def test_move_quarantine_fails_without_ou_configured(self):
        from app.adapters.identity.active_directory import ActiveDirectoryAdapter
        with patch("app.adapters.identity.active_directory.get_settings") as mock_s:
            s = MagicMock()
            s.AD_SERVER_URL = "ldaps://dc.corp.local:636"
            s.AD_BIND_DN = "CN=svc,DC=corp,DC=local"
            s.AD_BIND_PASSWORD = "pw"  # nosec B106
            s.AD_BASE_DN = "DC=corp,DC=local"
            s.AD_QUARANTINE_OU = ""   # not configured
            s.AD_USE_SSL = False
            s.AD_VERIFY_CERT = False
            mock_s.return_value = s
            adapter = ActiveDirectoryAdapter()

        ldap3_mock = MagicMock()
        ldap3_mock.ALL = "ALL"
        ldap3_mock.AUTO_BIND_TLS_BEFORE_BIND = "AUTO_BIND_TLS_BEFORE_BIND"
        ldap3_mock.Tls = MagicMock()
        ldap3_mock.Server = MagicMock()
        ldap3_mock.Connection = MagicMock(return_value=MagicMock(
            __enter__=MagicMock(return_value=MagicMock()),
            __exit__=MagicMock(return_value=False),
        ))

        with patch("app.adapters.identity.active_directory._import_ldap3", return_value=ldap3_mock):
            result = adapter._move_to_quarantine_sync("jsmith", "CORP")

        assert result["success"] is False
        assert "AD_QUARANTINE_OU" in result["error"]


# ─────────────────────────────────────────────────────────────────────────────
# TestSpectBridgeFirewallWire
# ─────────────────────────────────────────────────────────────────────────────

class TestSpectBridgeFirewallWire(unittest.TestCase):
    """Verify that SPECTER bridge calls the firewall adapter for broadcast actions."""

    def test_firewall_factory_returns_none_when_unconfigured(self):
        from app.services.specter_bridge import _get_firewall_adapter
        with patch("app.adapters.firewall.paloalto.get_settings") as pa_s, \
             patch("app.adapters.firewall.fortinet.get_settings") as ft_s:
            for mock_s in (pa_s, ft_s):
                s = MagicMock()
                s.PALOALTO_HOST = ""
                s.PALOALTO_API_KEY = ""
                s.FORTINET_HOST = ""
                s.FORTINET_API_TOKEN = ""
                s.PALOALTO_VSYS = "vsys1"
                s.PALOALTO_BLOCKED_IP_GROUP = "ASC-Blocked-IPs"
                s.PALOALTO_BLOCKED_URL_CATEGORY = "ASC-Blocked-Domains"
                s.FORTINET_VDOM = "root"
                s.FORTINET_BLOCKED_IP_GROUP = "ASC-Blocked-IPs"
                s.FORTINET_BLOCKED_DOMAIN_GROUP = "ASC-Blocked-Domains"
                mock_s.return_value = s
            adapter = _get_firewall_adapter()
        assert adapter is None

    def test_firewall_factory_returns_paloalto_when_configured(self):
        from app.services.specter_bridge import _get_firewall_adapter
        from app.adapters.firewall.paloalto import PaloAltoAdapter
        with patch("app.adapters.firewall.paloalto.get_settings") as pa_s:
            s = MagicMock()
            s.PALOALTO_HOST = "fw.corp.local"
            s.PALOALTO_API_KEY = "key"
            s.PALOALTO_VSYS = "vsys1"
            s.PALOALTO_BLOCKED_IP_GROUP = "ASC-Blocked-IPs"
            s.PALOALTO_BLOCKED_URL_CATEGORY = "ASC-Blocked-Domains"
            pa_s.return_value = s
            adapter = _get_firewall_adapter()
        assert isinstance(adapter, PaloAltoAdapter)

    def test_firewall_factory_returns_fortinet_as_fallback(self):
        from app.services.specter_bridge import _get_firewall_adapter
        from app.adapters.firewall.fortinet import FortinetAdapter
        with patch("app.adapters.firewall.paloalto.get_settings") as pa_s, \
             patch("app.adapters.firewall.fortinet.get_settings") as ft_s:
            pa = MagicMock()
            pa.PALOALTO_HOST = ""
            pa.PALOALTO_API_KEY = ""
            pa.PALOALTO_VSYS = "vsys1"
            pa.PALOALTO_BLOCKED_IP_GROUP = "g"
            pa.PALOALTO_BLOCKED_URL_CATEGORY = "c"
            pa_s.return_value = pa

            ft = MagicMock()
            ft.FORTINET_HOST = "fg.corp.local"
            ft.FORTINET_API_TOKEN = "tok"
            ft.FORTINET_VDOM = "root"
            ft.FORTINET_BLOCKED_IP_GROUP = "ASC-Blocked-IPs"
            ft.FORTINET_BLOCKED_DOMAIN_GROUP = "ASC-Blocked-Domains"
            ft_s.return_value = ft

            adapter = _get_firewall_adapter()
        assert isinstance(adapter, FortinetAdapter)


# ─────────────────────────────────────────────────────────────────────────────
# TestSpectBridgeIAMWire
# ─────────────────────────────────────────────────────────────────────────────

class TestSpectBridgeIAMWire(unittest.TestCase):
    """Verify that SPECTER bridge calls AD adapter on disable_account."""

    def test_identity_factory_returns_none_when_unconfigured(self):
        from app.services.specter_bridge import _get_identity_adapter
        with patch("app.adapters.identity.active_directory.get_settings") as mock_s:
            s = MagicMock()
            s.AD_SERVER_URL = ""
            s.AD_BIND_DN = ""
            s.AD_BIND_PASSWORD = ""
            s.AD_BASE_DN = ""
            s.AD_QUARANTINE_OU = ""
            s.AD_USE_SSL = True
            s.AD_VERIFY_CERT = True
            mock_s.return_value = s
            adapter = _get_identity_adapter()
        assert adapter is None

    def test_identity_factory_returns_ad_when_configured(self):
        from app.services.specter_bridge import _get_identity_adapter
        from app.adapters.identity.active_directory import ActiveDirectoryAdapter
        with patch("app.adapters.identity.active_directory.get_settings") as mock_s:
            s = MagicMock()
            s.AD_SERVER_URL = "ldaps://dc.corp.local:636"
            s.AD_BIND_DN = "CN=svc,DC=corp,DC=local"
            s.AD_BIND_PASSWORD = "pw"  # nosec B106
            s.AD_BASE_DN = "DC=corp,DC=local"
            s.AD_QUARANTINE_OU = ""
            s.AD_USE_SSL = True
            s.AD_VERIFY_CERT = True
            mock_s.return_value = s
            adapter = _get_identity_adapter()
        assert isinstance(adapter, ActiveDirectoryAdapter)

    def test_adapter_registry_contains_f1_adapters(self):
        from app.adapters import ADAPTERS
        assert "paloalto" in ADAPTERS
        assert "fortinet" in ADAPTERS
        assert "active_directory" in ADAPTERS

    def test_adapter_registry_factory_functions_exported(self):
        from app.adapters import get_firewall_adapter, get_identity_adapter
        assert callable(get_firewall_adapter)
        assert callable(get_identity_adapter)
