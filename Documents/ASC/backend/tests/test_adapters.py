"""
Unit + integration tests — Priority 6: SIEM/EDR/SOAR Adapters

Strategy:
  - Pure-function tests (document transformers, severity maps, is_configured)
    run without any mocking — they need no HTTP.
  - HTTP operation tests mock httpx.AsyncClient via unittest.mock.patch
    so no real network calls are ever made.
  - API integration tests mock adapter methods directly (patch the class)
    and verify endpoint logic: auth enforcement, 404 handling, 503 on
    unconfigured adapters.

Test classes:
  TestBaseAdapter           — is_configured + _ok/_err/_not_configured helpers
  TestELKDocumentBuilders   — alert_to_document, event_to_document, _search_query (pure)
  TestELKSeverityMapping    — _SEVERITY_TO_ECS completeness and values
  TestELKHTTP               — push_alert, push_event, search_events, test_connection (mocked)
  TestELKNotConfigured      — every HTTP method returns _not_configured() when url/key missing
  TestWazuhSeverityMapping  — wazuh_level_to_severity boundary conditions
  TestWazuhDocumentBuilder  — wazuh_alert_to_asc_event shape and field mapping (pure)
  TestWazuhHTTP             — get_alerts, get_agents, test_connection (mocked)
  TestWazuhNotConfigured    — every HTTP method short-circuits when not configured
  TestTheHiveSeverityMap    — ASC severity → TheHive int mapping
  TestTheHiveDocumentBuilders — alert_to_case, ioc_to_observable shape (pure)
  TestTheHiveHTTP           — create_case, create_observable, get_case, update, test_connection
  TestTheHiveNotConfigured  — all methods short-circuit when not configured
  TestAdaptersCatalogAPI    — GET /adapters/ shape and auth
  TestAdaptersStatusAPI     — GET /adapters/{name}/status — 404 unknown, 503 unconfigured
  TestELKEndpointsAPI       — push alert/event, pull events — auth, 404, 503
  TestWazuhEndpointsAPI     — pull alerts, agents — auth, 503
  TestTheHiveEndpointsAPI   — create case, observable, get case — auth, 404, 503
"""
import uuid
import pytest
import pytest_asyncio
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, AsyncMock, MagicMock
from httpx import AsyncClient, Response

from asc_api.models.user  import User
from asc_api.models.alert import Alert
from asc_api.models.event import Event
from asc_api.models.ioc   import IoC
from asc_api.adapters.elk     import ELKAdapter, _SEVERITY_TO_ECS
from asc_api.adapters.wazuh   import WazuhAdapter, wazuh_level_to_severity
from asc_api.adapters.thehive import TheHiveAdapter, _SEVERITY_MAP, _IOC_TYPE_MAP


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def configured_elk(monkeypatch):
    monkeypatch.setenv("ELASTICSEARCH_URL",     "https://elastic.test:9200")
    monkeypatch.setenv("ELASTICSEARCH_API_KEY", "dGVzdDp0ZXN0")
    from asc_api.core.config import get_settings
    get_settings.cache_clear()
    adapter = ELKAdapter()
    yield adapter
    get_settings.cache_clear()


@pytest.fixture
def configured_wazuh(monkeypatch):
    monkeypatch.setenv("WAZUH_URL",      "https://wazuh.test:55000")
    monkeypatch.setenv("WAZUH_USERNAME", "wazuh-user")
    monkeypatch.setenv("WAZUH_PASSWORD", "wazuh-pass")
    from asc_api.core.config import get_settings
    get_settings.cache_clear()
    WazuhAdapter.clear_cache()   # ensure no stale cached token bleeds between tests
    adapter = WazuhAdapter()
    yield adapter
    WazuhAdapter.clear_cache()
    get_settings.cache_clear()


@pytest.fixture
def configured_thehive(monkeypatch):
    monkeypatch.setenv("THEHIVE_URL",     "https://thehive.test:9000")
    monkeypatch.setenv("THEHIVE_API_KEY", "thehive-secret-key")
    from asc_api.core.config import get_settings
    get_settings.cache_clear()
    adapter = TheHiveAdapter()
    yield adapter
    get_settings.cache_clear()


@pytest.fixture
def sample_alert_dict():
    return {
        "id":             str(uuid.uuid4()),
        "title":          "Lateral Movement via SMB",
        "description":    "SMB connections to multiple hosts detected",
        "severity":       "critical",
        "status":         "open",
        "risk_score":     0.90,
        "ttps":           ["T1021.002"],
        "affected_hosts": ["PREMOS-WS-01", "PREMOS-WS-02"],
        "detected_at":    "2026-06-05T12:00:00+00:00",
    }


@pytest.fixture
def sample_event_dict():
    return {
        "id":        str(uuid.uuid4()),
        "timestamp": "2026-06-05T12:00:00+00:00",
        "source":    "winlog",
        "category":  "network",
        "action":    "smb_connect",
        "host":      "PREMOS-WS-01",
        "severity":  "high",
        "risk_score": 0.75,
    }


@pytest.fixture
def sample_ioc_dict():
    return {
        "id":          str(uuid.uuid4()),
        "ioc_type":    "ip",
        "value":       "192.168.1.99",
        "description": "C2 IP observed in lateral movement",
        "threat_type": "apt",
        "confidence":  0.95,
        "hit_count":   3,
    }


@pytest.fixture
def sample_wazuh_alert():
    return {
        "id":        "wazuh-alert-001",
        "timestamp": "2026-06-05T12:00:00",
        "rule": {
            "id":          "5710",
            "description": "Windows Eventlog cleared",
            "level":       12,
            "groups":      ["windows", "system_monitor"],
        },
        "agent": {"id": "001", "name": "PREMOS-WS-01"},
        "full_log": "Windows EventLog channel System was cleared.",
        "data":     {"win.system.channel": "System"},
    }


def _mock_httpx_response(status: int, body: dict) -> Response:
    """Build a fake httpx.Response with a dummy Request so raise_for_status() works."""
    import json
    from httpx import Request
    req = Request("GET", "https://mock.test")
    return Response(
        status_code=status,
        content=json.dumps(body).encode(),
        headers={"content-type": "application/json"},
        request=req,
    )


# ─── BaseAdapter ──────────────────────────────────────────────────────────────

class TestBaseAdapter:
    def test_elk_not_configured_when_url_empty(self):
        adapter = ELKAdapter()
        assert not adapter.is_configured()

    def test_elk_configured_with_both_fields(self, configured_elk):
        assert configured_elk.is_configured()

    def test_not_configured_returns_failure_dict(self, configured_elk):
        # Manually break config to test _not_configured
        configured_elk._url = ""
        result = configured_elk._not_configured()
        assert result["success"] is False
        assert "not configured" in result["error"].lower()
        assert "adapter" in result

    def test_ok_helper_merges_kwargs(self, configured_elk):
        result = configured_elk._ok(foo="bar", count=3)
        assert result["success"] is True
        assert result["foo"] == "bar"
        assert result["count"] == 3

    def test_err_helper(self, configured_elk):
        result = configured_elk._err("Connection refused", adapter="elk")
        assert result["success"] is False
        assert result["error"] == "Connection refused"
        assert result["adapter"] == "elk"

    def test_common_headers_present(self, configured_elk):
        h = configured_elk._common_headers()
        assert "User-Agent" in h
        assert "Accept" in h


# ─── ELK — document builders (pure) ──────────────────────────────────────────

class TestELKDocumentBuilders:
    def test_alert_to_document_required_ecs_fields(self, configured_elk, sample_alert_dict):
        doc = configured_elk.alert_to_document(sample_alert_dict)
        assert "@timestamp" in doc
        assert "event.kind" in doc
        assert "event.severity" in doc
        assert doc["event.kind"] == "alert"
        assert doc["asc.alert.id"] == sample_alert_dict["id"]
        assert doc["asc.alert.severity"] == "critical"
        assert doc["source"] == "asc-premoscorp"

    def test_alert_severity_maps_to_ecs_int(self, configured_elk, sample_alert_dict):
        for sev, expected in [("low", 25), ("medium", 50), ("high", 75), ("critical", 99)]:
            sample_alert_dict["severity"] = sev
            doc = configured_elk.alert_to_document(sample_alert_dict)
            assert doc["event.severity"] == expected

    def test_alert_unknown_severity_defaults_to_low(self, configured_elk, sample_alert_dict):
        sample_alert_dict["severity"] = "unknown"
        doc = configured_elk.alert_to_document(sample_alert_dict)
        assert doc["event.severity"] == 25   # low default

    def test_alert_ttps_preserved(self, configured_elk, sample_alert_dict):
        doc = configured_elk.alert_to_document(sample_alert_dict)
        assert doc["asc.alert.ttps"] == ["T1021.002"]

    def test_alert_first_host_extracted(self, configured_elk, sample_alert_dict):
        doc = configured_elk.alert_to_document(sample_alert_dict)
        assert doc["host.hostname"] == "PREMOS-WS-01"

    def test_alert_no_hosts_empty_hostname(self, configured_elk, sample_alert_dict):
        sample_alert_dict["affected_hosts"] = []
        doc = configured_elk.alert_to_document(sample_alert_dict)
        assert doc["host.hostname"] == ""

    def test_event_to_document_shape(self, configured_elk, sample_event_dict):
        doc = configured_elk.event_to_document(sample_event_dict)
        assert doc["event.kind"] == "event"
        assert doc["host.hostname"] == "PREMOS-WS-01"
        assert doc["asc.event.id"] == sample_event_dict["id"]
        assert doc["event.action"] == "smb_connect"
        assert doc["source"] == "asc-premoscorp"

    def test_event_unknown_severity_defaults(self, configured_elk, sample_event_dict):
        sample_event_dict["severity"] = "extreme"
        doc = configured_elk.event_to_document(sample_event_dict)
        assert doc["event.severity"] == 25

    def test_search_query_structure(self, configured_elk):
        since = datetime(2026, 6, 5, 0, 0, 0, tzinfo=timezone.utc)
        q     = configured_elk._search_query(since, size=50)
        assert q["size"] == 50
        assert "range" in q["query"]
        assert "@timestamp" in q["query"]["range"]
        assert q["query"]["range"]["@timestamp"]["gte"] == since.isoformat()
        assert q["sort"][0] == {"@timestamp": {"order": "desc"}}


class TestELKSeverityMapping:
    def test_all_severities_defined(self):
        for sev in ("low", "medium", "high", "critical"):
            assert sev in _SEVERITY_TO_ECS

    def test_critical_is_highest(self):
        assert _SEVERITY_TO_ECS["critical"] > _SEVERITY_TO_ECS["high"]
        assert _SEVERITY_TO_ECS["high"] > _SEVERITY_TO_ECS["medium"]
        assert _SEVERITY_TO_ECS["medium"] > _SEVERITY_TO_ECS["low"]

    def test_critical_is_99(self):
        assert _SEVERITY_TO_ECS["critical"] == 99

    def test_low_is_25(self):
        assert _SEVERITY_TO_ECS["low"] == 25


# ─── ELK — HTTP operations (mocked) ──────────────────────────────────────────

class TestELKHTTP:
    @pytest.mark.asyncio
    async def test_test_connection_success(self, configured_elk):
        body = {"status": "green", "cluster_name": "premoscorp", "number_of_nodes": 3}
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = _mock_httpx_response(200, body)
            result = await configured_elk.test_connection()
        assert result["success"] is True
        assert result["status"] == "green"
        assert result["cluster_name"] == "premoscorp"
        assert result["node_count"] == 3

    @pytest.mark.asyncio
    async def test_test_connection_auth_failure(self, configured_elk):
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = _mock_httpx_response(401, {"error": "Unauthorized"})
            result = await configured_elk.test_connection()
        assert result["success"] is False
        assert "401" in result["error"]

    @pytest.mark.asyncio
    async def test_test_connection_network_error(self, configured_elk):
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = Exception("Connection refused")
            result = await configured_elk.test_connection()
        assert result["success"] is False
        assert "Connection refused" in result["error"]

    @pytest.mark.asyncio
    async def test_push_alert_success(self, configured_elk, sample_alert_dict):
        body = {"result": "created", "_id": sample_alert_dict["id"]}
        with patch("httpx.AsyncClient.put", new_callable=AsyncMock) as mock_put:
            mock_put.return_value = _mock_httpx_response(201, body)
            result = await configured_elk.push_alert(sample_alert_dict)
        assert result["success"] is True
        assert result["result"] == "created"
        assert result["doc_id"] == sample_alert_dict["id"]
        assert result["index"] == "asc-alerts"

    @pytest.mark.asyncio
    async def test_push_alert_returns_existing_on_200(self, configured_elk, sample_alert_dict):
        body = {"result": "updated", "_id": sample_alert_dict["id"]}
        with patch("httpx.AsyncClient.put", new_callable=AsyncMock) as mock_put:
            mock_put.return_value = _mock_httpx_response(200, body)
            result = await configured_elk.push_alert(sample_alert_dict)
        assert result["success"] is True
        assert result["result"] == "updated"

    @pytest.mark.asyncio
    async def test_push_alert_failure_on_403(self, configured_elk, sample_alert_dict):
        with patch("httpx.AsyncClient.put", new_callable=AsyncMock) as mock_put:
            mock_put.return_value = _mock_httpx_response(403, {"error": "Forbidden"})
            result = await configured_elk.push_alert(sample_alert_dict)
        assert result["success"] is False
        assert "403" in result["error"]

    @pytest.mark.asyncio
    async def test_push_alert_network_error_returns_err(self, configured_elk, sample_alert_dict):
        with patch("httpx.AsyncClient.put", new_callable=AsyncMock) as mock_put:
            mock_put.side_effect = Exception("Timeout")
            result = await configured_elk.push_alert(sample_alert_dict)
        assert result["success"] is False
        assert "Timeout" in result["error"]

    @pytest.mark.asyncio
    async def test_push_event_success(self, configured_elk, sample_event_dict):
        body = {"result": "created", "_id": sample_event_dict["id"]}
        with patch("httpx.AsyncClient.put", new_callable=AsyncMock) as mock_put:
            mock_put.return_value = _mock_httpx_response(201, body)
            result = await configured_elk.push_event(sample_event_dict)
        assert result["success"] is True
        assert result["index"] == "asc-events"
        assert result["doc_id"] == sample_event_dict["id"]

    @pytest.mark.asyncio
    async def test_search_events_success(self, configured_elk):
        body = {
            "hits": {
                "total": {"value": 2},
                "hits": [
                    {"_source": {"host.hostname": "H1"}},
                    {"_source": {"host.hostname": "H2"}},
                ],
            }
        }
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = _mock_httpx_response(200, body)
            result = await configured_elk.search_events(
                since=datetime.now(timezone.utc) - timedelta(hours=1)
            )
        assert result["success"] is True
        assert result["total"] == 2
        assert len(result["events"]) == 2

    @pytest.mark.asyncio
    async def test_search_events_failure(self, configured_elk):
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = _mock_httpx_response(503, {"error": "unavailable"})
            result = await configured_elk.search_events(datetime.now(timezone.utc))
        assert result["success"] is False
        assert "503" in result["error"]


# ─── ELK — not configured short-circuit ──────────────────────────────────────

class TestELKNotConfigured:
    def setup_method(self):
        self.adapter = ELKAdapter()   # url/key are empty strings → not configured

    @pytest.mark.asyncio
    async def test_test_connection_not_configured(self):
        result = await self.adapter.test_connection()
        assert result["success"] is False
        assert "not configured" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_push_alert_not_configured(self, sample_alert_dict):
        result = await self.adapter.push_alert(sample_alert_dict)
        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_push_event_not_configured(self, sample_event_dict):
        result = await self.adapter.push_event(sample_event_dict)
        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_search_events_not_configured(self):
        result = await self.adapter.search_events(datetime.now(timezone.utc))
        assert result["success"] is False


# ─── Wazuh — severity mapping ─────────────────────────────────────────────────

class TestWazuhSeverityMapping:
    def test_level_1_is_low(self):    assert wazuh_level_to_severity(1)  == "low"
    def test_level_7_is_low(self):    assert wazuh_level_to_severity(7)  == "low"
    def test_level_8_is_medium(self): assert wazuh_level_to_severity(8)  == "medium"
    def test_level_11_is_medium(self):assert wazuh_level_to_severity(11) == "medium"
    def test_level_12_is_high(self):  assert wazuh_level_to_severity(12) == "high"
    def test_level_14_is_high(self):  assert wazuh_level_to_severity(14) == "high"
    def test_level_15_is_critical(self): assert wazuh_level_to_severity(15) == "critical"
    def test_level_0_is_low(self):    assert wazuh_level_to_severity(0)  == "low"
    def test_level_20_is_critical(self): assert wazuh_level_to_severity(20) == "critical"


# ─── Wazuh — document builder (pure) ─────────────────────────────────────────

class TestWazuhDocumentBuilder:
    def test_asc_event_shape(self, configured_wazuh, sample_wazuh_alert):
        evt = configured_wazuh.wazuh_alert_to_asc_event(sample_wazuh_alert)
        assert evt["source"] == "wazuh"
        assert evt["category"] == "hids"
        assert evt["host"] == "PREMOS-WS-01"
        assert evt["severity"] == "high"    # level 12 → high
        assert evt["action"] == "Windows Eventlog cleared"

    def test_data_block_has_wazuh_fields(self, configured_wazuh, sample_wazuh_alert):
        evt = configured_wazuh.wazuh_alert_to_asc_event(sample_wazuh_alert)
        assert evt["data"]["wazuh_rule_id"] == "5710"
        assert evt["data"]["wazuh_rule_level"] == 12
        assert evt["data"]["wazuh_agent_id"] == "001"
        assert evt["data"]["wazuh_agent_name"] == "PREMOS-WS-01"
        assert evt["data"]["original_id"] == "wazuh-alert-001"

    def test_missing_agent_falls_back_to_unknown(self, configured_wazuh):
        alert = {"rule": {"level": 5, "description": "test"}, "agent": {}}
        evt   = configured_wazuh.wazuh_alert_to_asc_event(alert)
        assert evt["host"] == "unknown"

    def test_level_0_maps_to_low(self, configured_wazuh):
        alert = {"rule": {"level": 0, "description": "low alert"}, "agent": {"name": "H1"}}
        evt   = configured_wazuh.wazuh_alert_to_asc_event(alert)
        assert evt["severity"] == "low"

    def test_level_15_maps_to_critical(self, configured_wazuh):
        alert = {"rule": {"level": 15, "description": "critical"}, "agent": {"name": "H1"}}
        evt   = configured_wazuh.wazuh_alert_to_asc_event(alert)
        assert evt["severity"] == "critical"

    def test_groups_preserved(self, configured_wazuh, sample_wazuh_alert):
        evt = configured_wazuh.wazuh_alert_to_asc_event(sample_wazuh_alert)
        assert "windows" in evt["data"]["wazuh_groups"]


# ─── Wazuh — HTTP operations (mocked) ────────────────────────────────────────

class TestWazuhHTTP:
    @pytest.mark.asyncio
    async def test_test_connection_success(self, configured_wazuh):
        token_resp = {"data": {"token": "jwt-token-abc"}}
        info_resp  = {"data": {"version": "4.9.0", "type": "manager"}}

        async def fake_post(*args, **kwargs):
            return _mock_httpx_response(200, token_resp)

        async def fake_get(*args, **kwargs):
            return _mock_httpx_response(200, info_resp)

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, side_effect=fake_post):
            with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=fake_get):
                result = await configured_wazuh.test_connection()

        assert result["success"] is True
        assert result["wazuh_version"] == "4.9.0"

    @pytest.mark.asyncio
    async def test_test_connection_auth_failure(self, configured_wazuh):
        async def fake_post(*args, **kwargs):
            resp = _mock_httpx_response(401, {"error": "Unauthorized"})
            resp.raise_for_status = MagicMock(side_effect=Exception("401 Unauthorized"))
            return resp

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, side_effect=fake_post):
            result = await configured_wazuh.test_connection()

        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_get_alerts_success(self, configured_wazuh, sample_wazuh_alert):
        token_resp  = {"data": {"token": "jwt-token"}}
        alerts_body = {
            "data": {
                "affected_items":       [sample_wazuh_alert],
                "total_affected_items": 1,
            }
        }

        async def fake_post(*args, **kwargs):
            return _mock_httpx_response(200, token_resp)

        async def fake_get(*args, **kwargs):
            return _mock_httpx_response(200, alerts_body)

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, side_effect=fake_post):
            with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=fake_get):
                result = await configured_wazuh.get_alerts()

        assert result["success"] is True
        assert result["total"] == 1
        assert len(result["alerts"]) == 1
        assert len(result["asc_events"]) == 1
        assert result["asc_events"][0]["source"] == "wazuh"

    @pytest.mark.asyncio
    async def test_get_alerts_network_error(self, configured_wazuh):
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, side_effect=Exception("Timeout")):
            result = await configured_wazuh.get_alerts()
        assert result["success"] is False
        assert "Timeout" in result["error"]

    @pytest.mark.asyncio
    async def test_get_agents_success(self, configured_wazuh):
        token_resp  = {"data": {"token": "jwt-token"}}
        agents_body = {
            "data": {
                "affected_items": [
                    {"id": "001", "name": "PREMOS-WS-01", "status": "active"},
                    {"id": "002", "name": "PREMOS-SRV-01", "status": "active"},
                ]
            }
        }

        async def fake_post(*args, **kwargs):
            return _mock_httpx_response(200, token_resp)

        async def fake_get(*args, **kwargs):
            return _mock_httpx_response(200, agents_body)

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, side_effect=fake_post):
            with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=fake_get):
                result = await configured_wazuh.get_agents()

        assert result["success"] is True
        assert result["total"] == 2
        assert result["agents"][0]["name"] == "PREMOS-WS-01"


# ─── Wazuh — not configured short-circuit ────────────────────────────────────

class TestWazuhNotConfigured:
    def setup_method(self):
        self.adapter = WazuhAdapter()

    @pytest.mark.asyncio
    async def test_test_connection_not_configured(self):
        assert not self.adapter.is_configured()
        result = await self.adapter.test_connection()
        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_get_alerts_not_configured(self):
        result = await self.adapter.get_alerts()
        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_get_agents_not_configured(self):
        result = await self.adapter.get_agents()
        assert result["success"] is False


# ─── TheHive — severity and type maps ────────────────────────────────────────

class TestTheHiveSeverityMap:
    def test_low_is_1(self):      assert _SEVERITY_MAP["low"]      == 1
    def test_medium_is_2(self):   assert _SEVERITY_MAP["medium"]   == 2
    def test_high_is_3(self):     assert _SEVERITY_MAP["high"]     == 3
    def test_critical_is_4(self): assert _SEVERITY_MAP["critical"] == 4

    def test_ioc_ip_maps_to_ip(self):       assert _IOC_TYPE_MAP["ip"]          == "ip"
    def test_ioc_domain(self):              assert _IOC_TYPE_MAP["domain"]       == "domain"
    def test_ioc_url(self):                 assert _IOC_TYPE_MAP["url"]          == "url"
    def test_ioc_hash_md5_maps_to_hash(self):   assert _IOC_TYPE_MAP["hash_md5"]  == "hash"
    def test_ioc_hash_sha256_maps_to_hash(self): assert _IOC_TYPE_MAP["hash_sha256"] == "hash"
    def test_ioc_mutex_maps_to_other(self): assert _IOC_TYPE_MAP["mutex"]       == "other"
    def test_ioc_registry_key(self):        assert _IOC_TYPE_MAP["registry_key"] == "registry"


# ─── TheHive — document builders (pure) ──────────────────────────────────────

class TestTheHiveDocumentBuilders:
    def test_alert_to_case_title_prefixed(self, configured_thehive, sample_alert_dict):
        case = configured_thehive.alert_to_case(sample_alert_dict)
        assert case["title"].startswith("[ASC]")
        assert "Lateral Movement" in case["title"]

    def test_alert_to_case_severity_mapped(self, configured_thehive, sample_alert_dict):
        case = configured_thehive.alert_to_case(sample_alert_dict)
        assert case["severity"] == 4   # critical → 4

    def test_alert_to_case_medium_severity(self, configured_thehive, sample_alert_dict):
        sample_alert_dict["severity"] = "medium"
        case = configured_thehive.alert_to_case(sample_alert_dict)
        assert case["severity"] == 2

    def test_alert_to_case_flag_on_critical(self, configured_thehive, sample_alert_dict):
        case = configured_thehive.alert_to_case(sample_alert_dict)
        assert case["flag"] is True

    def test_alert_to_case_no_flag_on_low(self, configured_thehive, sample_alert_dict):
        sample_alert_dict["severity"] = "low"
        case = configured_thehive.alert_to_case(sample_alert_dict)
        assert case["flag"] is False

    def test_alert_to_case_tags_include_asc_and_ttps(self, configured_thehive, sample_alert_dict):
        case = configured_thehive.alert_to_case(sample_alert_dict)
        assert "asc" in case["tags"]
        assert "T1021.002" in case["tags"]

    def test_alert_to_case_custom_fields_present(self, configured_thehive, sample_alert_dict):
        case = configured_thehive.alert_to_case(sample_alert_dict)
        assert "asc-alert-id" in case["customFields"]
        assert "asc-risk-score" in case["customFields"]
        assert case["customFields"]["asc-risk-score"]["float"] == 0.90

    def test_alert_to_case_description_contains_hosts(self, configured_thehive, sample_alert_dict):
        case = configured_thehive.alert_to_case(sample_alert_dict)
        assert "PREMOS-WS-01" in case["description"]

    def test_ioc_to_observable_ip_type(self, configured_thehive, sample_ioc_dict):
        obs = configured_thehive.ioc_to_observable(sample_ioc_dict)
        assert obs["dataType"] == "ip"
        assert obs["data"] == "192.168.1.99"
        assert obs["ioc"] is True

    def test_ioc_to_observable_sighted_when_hit_count_gt_0(self, configured_thehive, sample_ioc_dict):
        obs = configured_thehive.ioc_to_observable(sample_ioc_dict)
        assert obs["sighted"] is True

    def test_ioc_to_observable_not_sighted_when_no_hits(self, configured_thehive, sample_ioc_dict):
        sample_ioc_dict["hit_count"] = 0
        obs = configured_thehive.ioc_to_observable(sample_ioc_dict)
        assert obs["sighted"] is False

    def test_ioc_to_observable_tags_include_type(self, configured_thehive, sample_ioc_dict):
        obs = configured_thehive.ioc_to_observable(sample_ioc_dict)
        assert "asc" in obs["tags"]
        assert "ioc" in obs["tags"]

    def test_ioc_to_observable_hash_type(self, configured_thehive, sample_ioc_dict):
        sample_ioc_dict["ioc_type"] = "hash_sha256"
        sample_ioc_dict["value"]    = "abc123" * 10
        obs = configured_thehive.ioc_to_observable(sample_ioc_dict)
        assert obs["dataType"] == "hash"


# ─── TheHive — HTTP operations (mocked) ──────────────────────────────────────

class TestTheHiveHTTP:
    @pytest.mark.asyncio
    async def test_test_connection_success(self, configured_thehive):
        body = {"login": "asc-bot", "roles": ["analyst"]}
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = _mock_httpx_response(200, body)
            result = await configured_thehive.test_connection()
        assert result["success"] is True
        assert result["user"] == "asc-bot"

    @pytest.mark.asyncio
    async def test_test_connection_auth_failure(self, configured_thehive):
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = _mock_httpx_response(401, {"message": "Unauthorized"})
            result = await configured_thehive.test_connection()
        assert result["success"] is False
        assert "401" in result["error"]

    @pytest.mark.asyncio
    async def test_create_case_success(self, configured_thehive, sample_alert_dict):
        body = {"_id": "case-abc123", "number": 42, "title": "[ASC] Lateral Movement via SMB"}
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = _mock_httpx_response(201, body)
            result = await configured_thehive.create_case(sample_alert_dict)
        assert result["success"] is True
        assert result["case_id"] == "case-abc123"
        assert result["case_number"] == 42

    @pytest.mark.asyncio
    async def test_create_case_auth_failure(self, configured_thehive, sample_alert_dict):
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = _mock_httpx_response(403, {"message": "Forbidden"})
            result = await configured_thehive.create_case(sample_alert_dict)
        assert result["success"] is False
        assert "403" in result["error"]

    @pytest.mark.asyncio
    async def test_create_case_network_error(self, configured_thehive, sample_alert_dict):
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.side_effect = Exception("SSL error")
            result = await configured_thehive.create_case(sample_alert_dict)
        assert result["success"] is False
        assert "SSL error" in result["error"]

    @pytest.mark.asyncio
    async def test_create_observable_success(self, configured_thehive, sample_ioc_dict):
        body = [{"_id": "obs-xyz", "dataType": "ip", "data": "192.168.1.99"}]
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = _mock_httpx_response(201, body)
            result = await configured_thehive.create_observable("case-abc123", sample_ioc_dict)
        assert result["success"] is True
        assert result["observable_id"] == "obs-xyz"
        assert result["data_type"] == "ip"

    @pytest.mark.asyncio
    async def test_get_case_success(self, configured_thehive):
        body = {"_id": "case-abc", "title": "[ASC] Test", "status": "InProgress", "severity": 3, "assignee": "analyst1"}
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = _mock_httpx_response(200, body)
            result = await configured_thehive.get_case("case-abc")
        assert result["success"] is True
        assert result["status"] == "InProgress"
        assert result["assignee"] == "analyst1"

    @pytest.mark.asyncio
    async def test_get_case_not_found(self, configured_thehive):
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = _mock_httpx_response(404, {"message": "Not found"})
            result = await configured_thehive.get_case("nonexistent")
        assert result["success"] is False
        assert "not found" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_update_case_status_success(self, configured_thehive):
        with patch("httpx.AsyncClient.patch", new_callable=AsyncMock) as mock_patch:
            mock_patch.return_value = _mock_httpx_response(200, {})
            result = await configured_thehive.update_case_status("case-abc", "Resolved")
        assert result["success"] is True
        assert result["new_status"] == "Resolved"

    @pytest.mark.asyncio
    async def test_update_case_status_204_also_ok(self, configured_thehive):
        with patch("httpx.AsyncClient.patch", new_callable=AsyncMock) as mock_patch:
            mock_patch.return_value = _mock_httpx_response(204, {})
            result = await configured_thehive.update_case_status("case-abc", "Closed")
        assert result["success"] is True


# ─── TheHive — not configured short-circuit ──────────────────────────────────

class TestTheHiveNotConfigured:
    def setup_method(self):
        self.adapter = TheHiveAdapter()

    @pytest.mark.asyncio
    async def test_test_connection_not_configured(self):
        result = await self.adapter.test_connection()
        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_create_case_not_configured(self, sample_alert_dict):
        result = await self.adapter.create_case(sample_alert_dict)
        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_create_observable_not_configured(self, sample_ioc_dict):
        result = await self.adapter.create_observable("case-x", sample_ioc_dict)
        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_get_case_not_configured(self):
        result = await self.adapter.get_case("case-x")
        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_update_case_not_configured(self):
        result = await self.adapter.update_case_status("case-x", "Resolved")
        assert result["success"] is False


# ─── API — adapters catalog ───────────────────────────────────────────────────

@pytest.mark.asyncio
class TestAdaptersCatalogAPI:
    async def test_list_requires_auth(self, client: AsyncClient):
        resp = await client.get("/api/v1/adapters/")
        assert resp.status_code in (401, 403)

    async def test_list_returns_200_with_auth(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        resp = await client.get("/api/v1/adapters/", headers=admin_headers)
        assert resp.status_code == 200

    async def test_list_shape_has_six_adapters(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        resp = await client.get("/api/v1/adapters/", headers=admin_headers)
        data = resp.json()
        assert "adapters" in data
        assert len(data["adapters"]) == 6

    async def test_list_adapter_names(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        resp  = await client.get("/api/v1/adapters/", headers=admin_headers)
        names = {a["name"] for a in resp.json()["adapters"]}
        assert names == {"elk", "wazuh", "thehive", "paloalto", "fortinet", "active_directory"}

    async def test_list_adapters_not_configured_by_default(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        resp = await client.get("/api/v1/adapters/", headers=admin_headers)
        for a in resp.json()["adapters"]:
            assert a["configured"] is False   # no env vars set in test env

    async def test_list_adapter_has_type_field(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        resp = await client.get("/api/v1/adapters/", headers=admin_headers)
        types = {a["type"] for a in resp.json()["adapters"]}
        assert "SIEM" in types
        assert "EDR/HIDS" in types
        assert "SOAR" in types
        assert "Firewall" in types
        assert "IAM" in types


# ─── API — adapter status endpoint ───────────────────────────────────────────

@pytest.mark.asyncio
class TestAdaptersStatusAPI:
    async def test_status_unknown_adapter_404(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        resp = await client.get("/api/v1/adapters/nonexistent/status", headers=admin_headers)
        assert resp.status_code == 404

    async def test_status_unconfigured_elk_503(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        resp = await client.get("/api/v1/adapters/elk/status", headers=admin_headers)
        assert resp.status_code == 503

    async def test_status_unconfigured_wazuh_503(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        resp = await client.get("/api/v1/adapters/wazuh/status", headers=admin_headers)
        assert resp.status_code == 503

    async def test_status_unconfigured_thehive_503(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        resp = await client.get("/api/v1/adapters/thehive/status", headers=admin_headers)
        assert resp.status_code == 503

    async def test_status_requires_auth(self, client: AsyncClient):
        resp = await client.get("/api/v1/adapters/elk/status")
        assert resp.status_code in (401, 403)


# ─── API — ELK endpoints ──────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestELKEndpointsAPI:
    async def test_push_alert_requires_auth(self, client: AsyncClient):
        resp = await client.post(f"/api/v1/adapters/elk/push/alert/{uuid.uuid4()}")
        assert resp.status_code in (401, 403)

    async def test_push_alert_not_found_404(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        resp = await client.post(
            f"/api/v1/adapters/elk/push/alert/{uuid.uuid4()}",
            headers=admin_headers,
        )
        assert resp.status_code == 404

    async def test_push_alert_unconfigured_503(self, client: AsyncClient, admin_user: User, admin_headers: dict, db):
        alert = Alert(
            id=str(uuid.uuid4()), title="T", description="D",
            severity="high", risk_score=0.8,
        )
        db.add(alert); await db.commit()
        resp = await client.post(
            f"/api/v1/adapters/elk/push/alert/{alert.id}",
            headers=admin_headers,
        )
        assert resp.status_code == 503

    async def test_push_event_not_found_404(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        resp = await client.post(
            f"/api/v1/adapters/elk/push/event/{uuid.uuid4()}",
            headers=admin_headers,
        )
        assert resp.status_code == 404

    async def test_pull_events_unconfigured_503(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        resp = await client.post(
            "/api/v1/adapters/elk/pull/events",
            json={"since_hours": 1, "size": 10},
            headers=admin_headers,
        )
        assert resp.status_code == 503


# ─── API — Wazuh endpoints ────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestWazuhEndpointsAPI:
    async def test_pull_alerts_requires_auth(self, client: AsyncClient):
        resp = await client.post("/api/v1/adapters/wazuh/pull/alerts", json={})
        assert resp.status_code in (401, 403)

    async def test_pull_alerts_unconfigured_503(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        resp = await client.post(
            "/api/v1/adapters/wazuh/pull/alerts",
            json={"since_hours": 1, "limit": 10},
            headers=admin_headers,
        )
        assert resp.status_code == 503

    async def test_agents_requires_auth(self, client: AsyncClient):
        resp = await client.get("/api/v1/adapters/wazuh/agents")
        assert resp.status_code in (401, 403)

    async def test_agents_unconfigured_503(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        resp = await client.get("/api/v1/adapters/wazuh/agents", headers=admin_headers)
        assert resp.status_code == 503


# ─── API — TheHive endpoints ──────────────────────────────────────────────────

@pytest.mark.asyncio
class TestTheHiveEndpointsAPI:
    async def test_create_case_requires_auth(self, client: AsyncClient):
        resp = await client.post("/api/v1/adapters/thehive/cases", json={"alert_id": str(uuid.uuid4())})
        assert resp.status_code in (401, 403)

    async def test_create_case_alert_not_found_404(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        resp = await client.post(
            "/api/v1/adapters/thehive/cases",
            json={"alert_id": str(uuid.uuid4())},
            headers=admin_headers,
        )
        assert resp.status_code == 404

    async def test_create_case_unconfigured_503(self, client: AsyncClient, admin_user: User, admin_headers: dict, db):
        alert = Alert(
            id=str(uuid.uuid4()), title="T", description="D",
            severity="critical", risk_score=0.95,
        )
        db.add(alert); await db.commit()
        resp = await client.post(
            "/api/v1/adapters/thehive/cases",
            json={"alert_id": alert.id},
            headers=admin_headers,
        )
        assert resp.status_code == 503

    async def test_add_observable_ioc_not_found_404(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        resp = await client.post(
            f"/api/v1/adapters/thehive/cases/case-xyz/observables?ioc_id={uuid.uuid4()}",
            headers=admin_headers,
        )
        assert resp.status_code == 404

    async def test_get_case_unconfigured_503(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        resp = await client.get("/api/v1/adapters/thehive/cases/case-xyz", headers=admin_headers)
        assert resp.status_code == 503

    async def test_get_case_requires_auth(self, client: AsyncClient):
        resp = await client.get("/api/v1/adapters/thehive/cases/case-xyz")
        assert resp.status_code in (401, 403)


# ─── API — F1/F2 status endpoints (paloalto, fortinet, active_directory) ─────

@pytest.mark.asyncio
class TestF1StatusEndpoints:
    """GET /adapters/{name}/status for the three F1 adapters — all return 503 when
    unconfigured (no env vars set in test environment)."""

    async def test_paloalto_status_unconfigured_503(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        resp = await client.get("/api/v1/adapters/paloalto/status", headers=admin_headers)
        assert resp.status_code == 503

    async def test_fortinet_status_unconfigured_503(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        resp = await client.get("/api/v1/adapters/fortinet/status", headers=admin_headers)
        assert resp.status_code == 503

    async def test_active_directory_status_unconfigured_503(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        resp = await client.get("/api/v1/adapters/active_directory/status", headers=admin_headers)
        assert resp.status_code == 503

    async def test_paloalto_status_requires_auth(self, client: AsyncClient):
        resp = await client.get("/api/v1/adapters/paloalto/status")
        assert resp.status_code in (401, 403)

    async def test_fortinet_status_requires_auth(self, client: AsyncClient):
        resp = await client.get("/api/v1/adapters/fortinet/status")
        assert resp.status_code in (401, 403)

    async def test_active_directory_status_requires_auth(self, client: AsyncClient):
        resp = await client.get("/api/v1/adapters/active_directory/status")
        assert resp.status_code in (401, 403)


# ─── API — Firewall endpoints (F2) ────────────────────────────────────────────

@pytest.mark.asyncio
class TestFirewallEndpointsAPI:
    """
    POST /adapters/firewall/{block,unblock}/{ip,domain}

    No firewall env vars are set in test env, so all calls return 503.
    We also verify:
      - Auth enforcement (no token → 401/403)
      - 200 + success=True when adapter is mocked to return success
    """

    async def test_block_ip_requires_auth(self, client: AsyncClient):
        resp = await client.post("/api/v1/adapters/firewall/block/ip", json={"ip": "1.2.3.4"})
        assert resp.status_code in (401, 403)

    async def test_block_ip_unconfigured_503(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        resp = await client.post(
            "/api/v1/adapters/firewall/block/ip",
            json={"ip": "192.0.2.1", "reason": "C2 IP"},
            headers=admin_headers,
        )
        assert resp.status_code == 503

    async def test_unblock_ip_unconfigured_503(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        resp = await client.post(
            "/api/v1/adapters/firewall/unblock/ip",
            json={"ip": "192.0.2.1"},
            headers=admin_headers,
        )
        assert resp.status_code == 503

    async def test_block_domain_unconfigured_503(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        resp = await client.post(
            "/api/v1/adapters/firewall/block/domain",
            json={"domain": "evil.example.com"},
            headers=admin_headers,
        )
        assert resp.status_code == 503

    async def test_unblock_domain_unconfigured_503(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        resp = await client.post(
            "/api/v1/adapters/firewall/unblock/domain",
            json={"domain": "evil.example.com"},
            headers=admin_headers,
        )
        assert resp.status_code == 503

    async def test_block_ip_success_with_mock(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        mock_adapter = AsyncMock()
        mock_adapter.block_ip = AsyncMock(return_value={"success": True, "committed": True, "ip": "192.0.2.5"})
        with patch("app.api.v1.endpoints.adapters.get_firewall_adapter", return_value=mock_adapter):
            resp = await client.post(
                "/api/v1/adapters/firewall/block/ip",
                json={"ip": "192.0.2.5", "reason": "test block"},
                headers=admin_headers,
            )
        assert resp.status_code == 200
        assert resp.json()["success"] is True
        mock_adapter.block_ip.assert_awaited_once_with("192.0.2.5", reason="test block")

    async def test_unblock_ip_success_with_mock(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        mock_adapter = AsyncMock()
        mock_adapter.unblock_ip = AsyncMock(return_value={"success": True, "ip": "192.0.2.5"})
        with patch("app.api.v1.endpoints.adapters.get_firewall_adapter", return_value=mock_adapter):
            resp = await client.post(
                "/api/v1/adapters/firewall/unblock/ip",
                json={"ip": "192.0.2.5"},
                headers=admin_headers,
            )
        assert resp.status_code == 200
        assert resp.json()["success"] is True
        mock_adapter.unblock_ip.assert_awaited_once_with("192.0.2.5")

    async def test_block_domain_success_with_mock(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        mock_adapter = AsyncMock()
        mock_adapter.block_domain = AsyncMock(return_value={"success": True, "domain": "evil.example.com"})
        with patch("app.api.v1.endpoints.adapters.get_firewall_adapter", return_value=mock_adapter):
            resp = await client.post(
                "/api/v1/adapters/firewall/block/domain",
                json={"domain": "evil.example.com", "reason": "phishing C2"},
                headers=admin_headers,
            )
        assert resp.status_code == 200
        assert resp.json()["success"] is True
        mock_adapter.block_domain.assert_awaited_once_with("evil.example.com", reason="phishing C2")

    async def test_unblock_domain_success_with_mock(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        mock_adapter = AsyncMock()
        mock_adapter.unblock_domain = AsyncMock(return_value={"success": True, "domain": "evil.example.com"})
        with patch("app.api.v1.endpoints.adapters.get_firewall_adapter", return_value=mock_adapter):
            resp = await client.post(
                "/api/v1/adapters/firewall/unblock/domain",
                json={"domain": "evil.example.com"},
                headers=admin_headers,
            )
        assert resp.status_code == 200
        assert resp.json()["success"] is True
        mock_adapter.unblock_domain.assert_awaited_once_with("evil.example.com")

    async def test_adapter_failure_returns_502(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        mock_adapter = AsyncMock()
        mock_adapter.block_ip = AsyncMock(return_value={"success": False, "error": "commit_failed: job 42"})
        with patch("app.api.v1.endpoints.adapters.get_firewall_adapter", return_value=mock_adapter):
            resp = await client.post(
                "/api/v1/adapters/firewall/block/ip",
                json={"ip": "10.0.0.1"},
                headers=admin_headers,
            )
        assert resp.status_code == 502


# ─── API — Identity endpoints (F2) ────────────────────────────────────────────

@pytest.mark.asyncio
class TestIdentityEndpointsAPI:
    """
    POST /adapters/identity/{disable,enable,force-reset,quarantine}

    No AD env vars set → 503 when no adapter mock provided.
    Also tests 200 with mocked adapter and proper arg forwarding.
    """

    async def test_disable_requires_auth(self, client: AsyncClient):
        resp = await client.post("/api/v1/adapters/identity/disable", json={"username": "jdoe", "domain": "corp.local"})
        assert resp.status_code in (401, 403)

    async def test_disable_unconfigured_503(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        resp = await client.post(
            "/api/v1/adapters/identity/disable",
            json={"username": "jdoe", "domain": "corp.local"},
            headers=admin_headers,
        )
        assert resp.status_code == 503

    async def test_enable_unconfigured_503(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        resp = await client.post(
            "/api/v1/adapters/identity/enable",
            json={"username": "jdoe", "domain": "corp.local"},
            headers=admin_headers,
        )
        assert resp.status_code == 503

    async def test_force_reset_unconfigured_503(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        resp = await client.post(
            "/api/v1/adapters/identity/force-reset",
            json={"username": "jdoe", "domain": "corp.local"},
            headers=admin_headers,
        )
        assert resp.status_code == 503

    async def test_quarantine_unconfigured_503(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        resp = await client.post(
            "/api/v1/adapters/identity/quarantine",
            json={"username": "jdoe", "domain": "corp.local"},
            headers=admin_headers,
        )
        assert resp.status_code == 503

    async def test_disable_success_with_mock(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        mock_adapter = AsyncMock()
        mock_adapter.disable_account = AsyncMock(return_value={"success": True, "username": "jdoe"})
        with patch("app.api.v1.endpoints.adapters.get_identity_adapter", return_value=mock_adapter):
            resp = await client.post(
                "/api/v1/adapters/identity/disable",
                json={"username": "jdoe", "domain": "corp.local", "reason": "compromised"},
                headers=admin_headers,
            )
        assert resp.status_code == 200
        assert resp.json()["success"] is True
        mock_adapter.disable_account.assert_awaited_once_with("jdoe", "corp.local", reason="compromised")

    async def test_enable_success_with_mock(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        mock_adapter = AsyncMock()
        mock_adapter.enable_account = AsyncMock(return_value={"success": True, "username": "jdoe"})
        with patch("app.api.v1.endpoints.adapters.get_identity_adapter", return_value=mock_adapter):
            resp = await client.post(
                "/api/v1/adapters/identity/enable",
                json={"username": "jdoe", "domain": "corp.local"},
                headers=admin_headers,
            )
        assert resp.status_code == 200
        assert resp.json()["success"] is True
        mock_adapter.enable_account.assert_awaited_once_with("jdoe", "corp.local")

    async def test_force_reset_success_with_mock(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        mock_adapter = AsyncMock()
        mock_adapter.force_password_reset = AsyncMock(return_value={"success": True, "username": "jdoe"})
        with patch("app.api.v1.endpoints.adapters.get_identity_adapter", return_value=mock_adapter):
            resp = await client.post(
                "/api/v1/adapters/identity/force-reset",
                json={"username": "jdoe", "domain": "corp.local"},
                headers=admin_headers,
            )
        assert resp.status_code == 200
        assert resp.json()["success"] is True
        mock_adapter.force_password_reset.assert_awaited_once_with("jdoe", "corp.local")

    async def test_quarantine_success_with_mock(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        mock_adapter = AsyncMock()
        mock_adapter.move_to_quarantine_ou = AsyncMock(return_value={"success": True, "username": "jdoe", "new_dn": "OU=Quarantine,DC=corp,DC=local"})
        with patch("app.api.v1.endpoints.adapters.get_identity_adapter", return_value=mock_adapter):
            resp = await client.post(
                "/api/v1/adapters/identity/quarantine",
                json={"username": "jdoe", "domain": "corp.local", "reason": "threat actor"},
                headers=admin_headers,
            )
        assert resp.status_code == 200
        assert resp.json()["success"] is True
        mock_adapter.move_to_quarantine_ou.assert_awaited_once_with("jdoe", "corp.local")

    async def test_identity_failure_returns_502(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        mock_adapter = AsyncMock()
        mock_adapter.disable_account = AsyncMock(return_value={"success": False, "error": "user not found in AD"})
        with patch("app.api.v1.endpoints.adapters.get_identity_adapter", return_value=mock_adapter):
            resp = await client.post(
                "/api/v1/adapters/identity/disable",
                json={"username": "ghost", "domain": "corp.local"},
                headers=admin_headers,
            )
        assert resp.status_code == 502

    async def test_quarantine_requires_auth(self, client: AsyncClient):
        resp = await client.post("/api/v1/adapters/identity/quarantine", json={"username": "j", "domain": "x"})
        assert resp.status_code in (401, 403)
