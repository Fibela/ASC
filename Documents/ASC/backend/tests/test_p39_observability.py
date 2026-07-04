"""
P39 Observability + Frontend Hardening â€” Test Suite

Coverage areas:
  1. MetricsRegistry  â€” _normalize_path, gauge set/read, registry isolation
  2. ObservabilityEndpoints â€” /metrics Prometheus text + /summary JSON
     Auth: no-auth 401, scrape-token, analyst JWT, viewer forbidden
  3. HealthSystemMetrics â€” /health/system process section (pid, cpu, memory)
  4. DeploymentArtifacts â€” .env.example + render.yaml include METRICS_SCRAPE_TOKEN
  5. MiddlewareMetrics  â€” HTTP_REQUESTS / HTTP_DURATION helper tests
  6. SSENotifications   â€” /api/v1/notifications/stream auth protection
  7. FormatUptime       â€” unit-level helper coverage
  8. Regression         â€” existing endpoints unaffected by P39
"""
from __future__ import annotations

import re
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient, ASGITransport

from asc_api.core.config import get_settings
from asc_api.core.security import create_access_token
from asc_api.db.session import get_db
from asc_api.main import app

settings = get_settings()
_REPO_ROOT = Path(__file__).parent.parent.parent


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 1. Metrics Registry â€” pure unit tests (no DB, no HTTP)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 0. Observability internal helpers â€” direct unit tests for coverage
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestObservabilityHelpers:
    """Direct unit tests for _check_scrape_token and _refresh_gauges (lines 65, 74-89)."""

    def test_check_scrape_token_empty_config_returns_false(self):
        from asc_api.api.v1.endpoints.observability import _check_scrape_token
        req = MagicMock()
        req.headers.get.return_value = "Bearer anytoken"
        with patch.object(settings, "METRICS_SCRAPE_TOKEN", ""):
            assert _check_scrape_token(req) is False

    def test_check_scrape_token_no_bearer_prefix_returns_false(self):
        """Line 65: non-Bearer auth when token IS configured â†’ False."""
        from asc_api.api.v1.endpoints.observability import _check_scrape_token
        req = MagicMock()
        req.headers.get.return_value = "Basic dXNlcjpwYXNz"
        with patch("asc_api.api.v1.endpoints.observability.settings") as ms:
            ms.METRICS_SCRAPE_TOKEN = "configured-token"
            result = _check_scrape_token(req)
        assert result is False

    def test_check_scrape_token_correct_returns_true(self):
        from asc_api.api.v1.endpoints.observability import _check_scrape_token
        req = MagicMock()
        req.headers.get.return_value = "Bearer correct-token"
        with patch("asc_api.api.v1.endpoints.observability.settings") as ms:
            ms.METRICS_SCRAPE_TOKEN = "correct-token"
            result = _check_scrape_token(req)
        assert result is True

    def test_check_scrape_token_wrong_value_returns_false(self):
        from asc_api.api.v1.endpoints.observability import _check_scrape_token
        req = MagicMock()
        req.headers.get.return_value = "Bearer wrong-token"
        with patch("asc_api.api.v1.endpoints.observability.settings") as ms:
            ms.METRICS_SCRAPE_TOKEN = "correct-token"
            result = _check_scrape_token(req)
        assert result is False

    @pytest.mark.asyncio
    async def test_refresh_gauges_sets_alert_count(self):
        """Lines 74-89: _refresh_gauges calls DB and sets Prometheus gauges."""
        from asc_api.api.v1.endpoints.observability import _refresh_gauges
        from asc_api.core.metrics_registry import ALERTS_GAUGE, EVENTS_GAUGE, AGENTS_GAUGE

        mock_db = AsyncMock()
        scalar_result = MagicMock()
        scalar_result.scalar.return_value = 7
        mock_db.execute = AsyncMock(return_value=scalar_result)

        with patch("asc_api.api.v1.endpoints.observability._proc", _make_proc_mock(cpu=5.0)):
            await _refresh_gauges(mock_db)

        assert ALERTS_GAUGE._value.get() == 7

    @pytest.mark.asyncio
    async def test_refresh_gauges_exception_does_not_propagate(self):
        """Line 89: exception in gauge refresh is swallowed (log warning only)."""
        from asc_api.api.v1.endpoints.observability import _refresh_gauges
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(side_effect=RuntimeError("DB unavailable"))
        await _refresh_gauges(mock_db)  # must not raise

    @pytest.mark.asyncio
    async def test_prometheus_metrics_with_scrape_token_via_settings_patch(self, client, analyst_user):
        """Lines 133-135: _refresh_gauges + generate_latest called via scrape token path."""
        from asc_api.api.v1.endpoints import observability as obs_mod
        with patch.object(obs_mod, "settings") as ms, \
             patch.object(obs_mod, "_proc", _make_proc_mock()):
            ms.METRICS_SCRAPE_TOKEN = "direct-patch-token"
            r = await client.get(
                "/api/v1/observability/metrics",
                headers={"Authorization": "Bearer direct-patch-token"},
            )
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_summary_body_lines_covered(self, client, analyst_user):
        """Lines 152-162: summary body (mem, cpu, db_ok, return JSON)."""
        from asc_api.api.v1.endpoints import observability as obs_mod
        token = create_access_token(analyst_user.id)
        with patch.object(obs_mod, "_proc", _make_proc_mock(pid=8888, cpu=3.5)):
            r = await client.get(
                "/api/v1/observability/summary",
                headers={"Authorization": f"Bearer {token}"},
            )
        assert r.status_code == 200
        assert r.json()["process"]["pid"] == 8888


class TestMetricsRegistry:
    """Unit tests for app.core.metrics_registry â€” importable without DB."""

    def test_registry_is_isolated_from_global(self):
        from prometheus_client import REGISTRY as GLOBAL
        from asc_api.core.metrics_registry import REGISTRY
        assert REGISTRY is not GLOBAL

    def test_required_counters_exist(self):
        from asc_api.core.metrics_registry import HTTP_REQUESTS, HTTP_DURATION
        assert HTTP_REQUESTS is not None
        assert HTTP_DURATION is not None

    def test_required_gauges_exist(self):
        from asc_api.core.metrics_registry import (
            ALERTS_GAUGE, EVENTS_GAUGE, AGENTS_GAUGE,
            PROCESS_CPU_GAUGE, PROCESS_MEMORY_BYTES,
        )
        for g in (ALERTS_GAUGE, EVENTS_GAUGE, AGENTS_GAUGE, PROCESS_CPU_GAUGE, PROCESS_MEMORY_BYTES):
            assert g is not None

    def test_gauge_set_and_read(self):
        from asc_api.core.metrics_registry import ALERTS_GAUGE
        ALERTS_GAUGE.set(99)
        assert ALERTS_GAUGE._value.get() == 99
        ALERTS_GAUGE.set(0)

    def test_counter_increment(self):
        from asc_api.core.metrics_registry import HTTP_REQUESTS
        label = dict(method="GET", endpoint="/p39_test", status_code="200")
        before = HTTP_REQUESTS.labels(**label)._value.get()
        HTTP_REQUESTS.labels(**label).inc()
        after = HTTP_REQUESTS.labels(**label)._value.get()
        assert after == before + 1

    def test_histogram_observe_no_error(self):
        from asc_api.core.metrics_registry import HTTP_DURATION
        HTTP_DURATION.labels(method="POST", endpoint="/p39_hist").observe(0.05)

    def test_generate_latest_returns_bytes(self):
        from asc_api.core.metrics_registry import REGISTRY, generate_latest
        output = generate_latest(REGISTRY)
        assert isinstance(output, bytes) and len(output) > 0

    def test_generate_latest_contains_asc_metrics(self):
        from asc_api.core.metrics_registry import REGISTRY, generate_latest, HTTP_REQUESTS
        HTTP_REQUESTS.labels(method="GET", endpoint="/health", status_code="200").inc()
        output = generate_latest(REGISTRY).decode()
        assert "asc_http_requests_total" in output

    def test_content_type_latest_is_text_plain(self):
        from asc_api.core.metrics_registry import CONTENT_TYPE_LATEST
        assert isinstance(CONTENT_TYPE_LATEST, str)
        assert "text/plain" in CONTENT_TYPE_LATEST


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 2. _normalize_path â€” cardinality collapse unit tests
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestNormalizePath:

    @pytest.fixture(autouse=True)
    def _fn(self):
        from asc_api.core.metrics_registry import _normalize_path
        self.fn = _normalize_path

    def test_api_v1_prefix_stripped(self):
        assert self.fn("/api/v1/agents") == "/agents"

    def test_uuid_segment_collapsed(self):
        assert self.fn("/api/v1/agents/abc-def-123") == "/agents"

    def test_nested_segments_collapsed(self):
        assert self.fn("/api/v1/incidents/uuid-here/timeline") == "/incidents"

    def test_health_passes_through(self):
        assert self.fn("/health") == "/health"

    def test_root_slash(self):
        assert self.fn("/") == "/"

    def test_empty_string(self):
        assert self.fn("") == "/"

    def test_non_api_path_preserved(self):
        assert self.fn("/docs") == "/docs"

    def test_api_v2_prefix_stripped(self):
        assert self.fn("/api/v2/alerts") == "/alerts"

    def test_only_first_segment_kept(self):
        # /api/v1/soar/triggers/5 â†’ /soar
        assert self.fn("/api/v1/soar/triggers/5") == "/soar"

    def test_two_uuids_same_label(self):
        p1 = self.fn("/api/v1/agents/aaaa-1111")
        p2 = self.fn("/api/v1/agents/bbbb-2222")
        assert p1 == p2 == "/agents"


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 3. Observability HTTP endpoints  (async, uses conftest `client` pattern)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def _make_proc_mock(pid=1234, cpu=0.0, rss=128*1024*1024, vms=256*1024*1024):
    mp = MagicMock()
    mp.pid = pid
    mp.cpu_percent.return_value = cpu
    mem = MagicMock()
    mem.rss = rss
    mem.vms = vms
    mp.memory_info.return_value = mem
    return mp


@pytest.mark.asyncio
class TestObservabilityMetricsEndpoint:
    """Tests for GET /api/v1/observability/metrics."""

    URL = "/api/v1/observability/metrics"

    async def test_no_auth_returns_401(self, client):
        r = await client.get(self.URL)
        assert r.status_code == 401

    async def test_wrong_bearer_token_returns_401(self, client):
        r = await client.get(self.URL, headers={"Authorization": "Bearer totally.wrong.token"})
        assert r.status_code == 401

    async def test_valid_scrape_token_returns_200(self, client):
        token = "my-scrape-token-xyz"
        with patch.object(settings, "METRICS_SCRAPE_TOKEN", token), \
             patch("asc_api.api.v1.endpoints.observability._proc", _make_proc_mock()):
            r = await client.get(self.URL, headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200

    async def test_scrape_token_content_type_prometheus(self, client):
        token = "ct-scrape-token"
        with patch.object(settings, "METRICS_SCRAPE_TOKEN", token), \
             patch("asc_api.api.v1.endpoints.observability._proc", _make_proc_mock()):
            r = await client.get(self.URL, headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert "text/plain" in r.headers.get("content-type", "")

    async def test_scrape_token_body_has_help_lines(self, client):
        token = "help-scrape-token"
        with patch.object(settings, "METRICS_SCRAPE_TOKEN", token), \
             patch("asc_api.api.v1.endpoints.observability._proc", _make_proc_mock()):
            r = await client.get(self.URL, headers={"Authorization": f"Bearer {token}"})
        assert "# HELP" in r.text

    async def test_scrape_token_body_contains_asc_counter(self, client):
        token = "counter-scrape-token"
        with patch.object(settings, "METRICS_SCRAPE_TOKEN", token), \
             patch("asc_api.api.v1.endpoints.observability._proc", _make_proc_mock()):
            r = await client.get(self.URL, headers={"Authorization": f"Bearer {token}"})
        assert "asc_http_requests_total" in r.text

    async def test_scrape_token_body_contains_gauges(self, client):
        token = "gauges-scrape-token"
        with patch.object(settings, "METRICS_SCRAPE_TOKEN", token), \
             patch("asc_api.api.v1.endpoints.observability._proc", _make_proc_mock()):
            r = await client.get(self.URL, headers={"Authorization": f"Bearer {token}"})
        assert "asc_alerts_total" in r.text
        assert "asc_agents_active" in r.text

    async def test_wrong_scrape_token_returns_401(self, client):
        with patch.object(settings, "METRICS_SCRAPE_TOKEN", "correct-token"):
            r = await client.get(self.URL, headers={"Authorization": "Bearer wrong-token"})
        assert r.status_code == 401

    async def test_analyst_jwt_returns_200(self, client, analyst_user):
        token = create_access_token(analyst_user.id)
        with patch("asc_api.api.v1.endpoints.observability._proc", _make_proc_mock()):
            r = await client.get(self.URL, headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200

    async def test_viewer_jwt_forbidden(self, client, viewer_user):
        token = create_access_token(viewer_user.id)
        r = await client.get(self.URL, headers={"Authorization": f"Bearer {token}"})
        assert r.status_code in (401, 403)


@pytest.mark.asyncio
class TestObservabilitySummaryEndpoint:
    """Tests for GET /api/v1/observability/summary."""

    URL = "/api/v1/observability/summary"

    async def test_no_auth_returns_401(self, client):
        r = await client.get(self.URL)
        assert r.status_code == 401

    async def test_viewer_returns_403(self, client, viewer_user):
        token = create_access_token(viewer_user.id)
        r = await client.get(self.URL, headers={"Authorization": f"Bearer {token}"})
        assert r.status_code in (401, 403)

    async def test_analyst_returns_200(self, client, analyst_user):
        token = create_access_token(analyst_user.id)
        with patch("asc_api.api.v1.endpoints.observability._proc", _make_proc_mock()):
            r = await client.get(self.URL, headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200

    async def test_admin_returns_200(self, client, admin_user):
        token = create_access_token(admin_user.id)
        with patch("asc_api.api.v1.endpoints.observability._proc", _make_proc_mock()):
            r = await client.get(self.URL, headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200

    async def test_summary_has_required_sections(self, client, analyst_user):
        token = create_access_token(analyst_user.id)
        with patch("asc_api.api.v1.endpoints.observability._proc", _make_proc_mock()):
            r = await client.get(self.URL, headers={"Authorization": f"Bearer {token}"})
        body = r.json()
        for key in ("ts", "process", "database", "agents", "prometheus"):
            assert key in body, f"Missing key in summary: {key}"

    async def test_summary_process_has_fields(self, client, analyst_user):
        token = create_access_token(analyst_user.id)
        with patch("asc_api.api.v1.endpoints.observability._proc", _make_proc_mock(pid=9999, cpu=7.5)):
            r = await client.get(self.URL, headers={"Authorization": f"Bearer {token}"})
        proc = r.json()["process"]
        assert "cpu_percent" in proc
        assert "memory_rss_mb" in proc
        assert "memory_vms_mb" in proc
        assert proc["pid"] == 9999

    async def test_summary_prometheus_has_endpoint_path(self, client, analyst_user):
        token = create_access_token(analyst_user.id)
        with patch("asc_api.api.v1.endpoints.observability._proc", _make_proc_mock()):
            r = await client.get(self.URL, headers={"Authorization": f"Bearer {token}"})
        prom = r.json()["prometheus"]
        assert prom["metrics_endpoint"] == "/api/v1/observability/metrics"
        assert "scrape_token_configured" in prom

    async def test_summary_agents_section(self, client, analyst_user):
        token = create_access_token(analyst_user.id)
        with patch("asc_api.api.v1.endpoints.observability._proc", _make_proc_mock()):
            r = await client.get(self.URL, headers={"Authorization": f"Bearer {token}"})
        assert "active_last_5min" in r.json()["agents"]

    async def test_summary_ts_is_iso8601(self, client, analyst_user):
        token = create_access_token(analyst_user.id)
        with patch("asc_api.api.v1.endpoints.observability._proc", _make_proc_mock()):
            r = await client.get(self.URL, headers={"Authorization": f"Bearer {token}"})
        from datetime import datetime
        ts = r.json()["ts"]
        datetime.fromisoformat(ts.replace("Z", "+00:00"))

    async def test_summary_database_section(self, client, analyst_user):
        token = create_access_token(analyst_user.id)
        with patch("asc_api.api.v1.endpoints.observability._proc", _make_proc_mock()):
            r = await client.get(self.URL, headers={"Authorization": f"Bearer {token}"})
        db_section = r.json()["database"]
        assert "ok" in db_section
        assert "alerts_total" in db_section
        assert "events_total" in db_section


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 4. /health/system â€” process CPU/mem section
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@pytest.mark.asyncio
class TestHealthSystemMetrics:
    """Tests for GET /api/v1/health/system â€” process section added in P39."""

    URL = "/api/v1/health/system"

    async def test_no_auth_returns_401(self, client):
        r = await client.get(self.URL)
        assert r.status_code == 401

    async def test_analyst_returns_200(self, client, analyst_user):
        token = create_access_token(analyst_user.id)
        with patch("asc_api.api.v1.endpoints.health._proc", _make_proc_mock()):
            r = await client.get(self.URL, headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200

    async def test_system_info_has_process_section(self, client, analyst_user):
        token = create_access_token(analyst_user.id)
        with patch("asc_api.api.v1.endpoints.health._proc", _make_proc_mock()):
            r = await client.get(self.URL, headers={"Authorization": f"Bearer {token}"})
        assert "process" in r.json()

    async def test_process_section_has_pid(self, client, analyst_user):
        token = create_access_token(analyst_user.id)
        with patch("asc_api.api.v1.endpoints.health._proc", _make_proc_mock(pid=4242)):
            r = await client.get(self.URL, headers={"Authorization": f"Bearer {token}"})
        assert r.json()["process"]["pid"] == 4242

    async def test_process_section_has_memory_fields(self, client, analyst_user):
        token = create_access_token(analyst_user.id)
        with patch("asc_api.api.v1.endpoints.health._proc", _make_proc_mock(rss=128*1024*1024)):
            r = await client.get(self.URL, headers={"Authorization": f"Bearer {token}"})
        proc = r.json()["process"]
        assert "memory_rss_mb" in proc
        assert "memory_vms_mb" in proc
        assert proc["memory_rss_mb"] == pytest.approx(128.0, abs=0.5)

    async def test_system_info_has_uptime_seconds(self, client, analyst_user):
        token = create_access_token(analyst_user.id)
        with patch("asc_api.api.v1.endpoints.health._proc", _make_proc_mock()):
            r = await client.get(self.URL, headers={"Authorization": f"Bearer {token}"})
        body = r.json()
        assert "uptime_seconds" in body
        assert body["uptime_seconds"] >= 0

    async def test_system_info_has_uptime_human(self, client, analyst_user):
        token = create_access_token(analyst_user.id)
        with patch("asc_api.api.v1.endpoints.health._proc", _make_proc_mock()):
            r = await client.get(self.URL, headers={"Authorization": f"Bearer {token}"})
        assert "uptime_human" in r.json()


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 5. format_uptime helper â€” unit-level coverage
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestFormatUptime:

    @pytest.fixture(autouse=True)
    def _fn(self):
        from asc_api.api.v1.endpoints.health import format_uptime
        self.fmt = format_uptime

    def test_zero_seconds(self):
        assert self.fmt(0) == "0s"

    def test_seconds_only(self):
        assert self.fmt(45) == "45s"

    def test_minutes_and_seconds(self):
        assert self.fmt(125) == "2m 5s"

    def test_exactly_one_minute(self):
        assert self.fmt(60) == "1m 0s"

    def test_hours(self):
        result = self.fmt(3700)
        assert "h" in result
        assert "m" in result

    def test_days(self):
        result = self.fmt(90000)
        assert "d" in result

    def test_one_day_exact(self):
        assert self.fmt(86400) == "1d 0s"


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 6. Deployment artifacts â€” METRICS_SCRAPE_TOKEN presence
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestDeploymentArtifactsP39:

    def test_env_example_has_metrics_scrape_token(self):
        env_file = _REPO_ROOT / ".env.example"
        assert env_file.exists()
        assert "METRICS_SCRAPE_TOKEN" in env_file.read_text(encoding="utf-8")

    def test_render_yaml_has_metrics_scrape_token(self):
        render_file = _REPO_ROOT / "render.yaml"
        assert render_file.exists()
        assert "METRICS_SCRAPE_TOKEN" in render_file.read_text(encoding="utf-8")

    def test_settings_has_metrics_scrape_token_attr(self):
        assert hasattr(settings, "METRICS_SCRAPE_TOKEN")

    def test_observability_router_registered_in_main_router(self):
        content = (_REPO_ROOT / "backend" / "app" / "api" / "v1" / "router.py").read_text()
        assert "observability" in content

    def test_observability_endpoint_prefix(self):
        from asc_api.api.v1.endpoints import observability
        assert observability.router.prefix == "/observability"


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 7. SSE Notifications endpoint â€” auth protection
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@pytest.mark.asyncio
class TestSSENotificationsEndpoint:
    """Tests for GET /api/v1/notifications/stream â€” SSE auth gates.

    The endpoint uses get_analyst_or_admin, so viewers are rejected (403).
    """

    URL = "/api/v1/notifications/stream"

    async def test_no_auth_returns_401(self, client):
        r = await client.get(self.URL)
        assert r.status_code == 401

    async def test_garbage_token_returns_401(self, client):
        r = await client.get(self.URL, headers={"Authorization": "Bearer garbage.not.valid"})
        assert r.status_code == 401

    async def test_viewer_is_forbidden(self, client, viewer_user):
        """SSE endpoint requires analyst+ â€” viewers get 403."""
        token = create_access_token(viewer_user.id)
        r = await client.get(self.URL, headers={"Authorization": f"Bearer {token}"})
        assert r.status_code in (401, 403)

    async def test_analyst_gets_event_stream(self, client, analyst_user):
        """Analyst gets 200 with text/event-stream â€” generator mocked to terminate immediately."""
        from fastapi import Request
        from asc_api.models.user import User

        async def _fast_generator(request: Request, user: User):
            # Yield one ping event then stop so the test doesn't block for 30s heartbeat
            yield ": ping\n\n"

        with patch("asc_api.api.v1.endpoints.notifications._event_stream", _fast_generator):
            token = create_access_token(analyst_user.id)
            async with client.stream("GET", self.URL,
                                     headers={"Authorization": f"Bearer {token}"}) as r:
                assert r.status_code == 200
                ct = r.headers.get("content-type", "")
                assert "text/event-stream" in ct


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 8. Regression â€” existing endpoints unaffected
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@pytest.mark.asyncio
class TestRegressionP39:

    async def test_liveness_still_200(self, client):
        r = await client.get("/api/v1/health/liveness")
        assert r.status_code == 200
        assert r.json()["status"] == "alive"

    async def test_root_health_still_200(self, client):
        r = await client.get("/health")
        assert r.status_code == 200

    async def test_auth_login_still_reachable(self, client):
        r = await client.post("/api/v1/auth/login", json={"username": "x@x.com", "password": "y"})
        assert r.status_code in (401, 422, 400)

    async def test_events_endpoint_requires_auth(self, client):
        r = await client.get("/api/v1/events")
        assert r.status_code == 401

    async def test_alerts_endpoint_requires_auth(self, client):
        r = await client.get("/api/v1/alerts")
        assert r.status_code == 401


# Sync helpers â€” kept outside TestRegressionP39 so the class @pytest.mark.asyncio
# decorator does not emit PytestWarning on non-async functions.
def test_normalize_path_no_cardinality_explosion():
    from asc_api.core.metrics_registry import _normalize_path
    endpoints = {_normalize_path(f"/api/v1/agents/{i}") for i in range(100)}
    assert len(endpoints) == 1, "UUID path fragments should all collapse to /agents"


def test_metrics_registry_import_is_stable():
    """Importing metrics_registry multiple times must not raise ValueError."""
    from asc_api.core.metrics_registry import REGISTRY, HTTP_REQUESTS
    assert REGISTRY is not None
    assert HTTP_REQUESTS is not None
