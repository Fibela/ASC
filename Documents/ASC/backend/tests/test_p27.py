"""
P27-B â€” Correlation Engine â€” Test Suite

Coverage:
  TestCorrelationModels          (8)  â€” ORM instantiation, forensic_hash, constants
  TestMaxSeverity                (6)  â€” severity ranking helper
  TestGatherHostSignals          (6)  â€” host pivot query with events/alerts/findings/panl
  TestGatherIdentitySignals      (4)  â€” identity pivot with IdentityActions + findings
  TestGatherIPSignals            (4)  â€” ip pivot with events/TI/panl
  TestGatherDomainSignals        (4)  â€” domain pivot with TI/panl/findings
  TestGatherTTPSignals           (4)  â€” ttp pivot with events/alerts
  TestUpsertCluster              (8)  â€” create new, update existing, dedup signals, campaign detection
  TestRunCorrelationSweep        (6)  â€” full sweep: rule iter, threshold filter, stat return
  TestQueryAPI                   (8)  â€” list_rules, create_rule, update_rule, delete_rule, list_clusters
  TestClusterStatusUpdate        (4)  â€” resolved/dismissed transitions
  TestClusterGraph               (6)  â€” graph node/edge structure, cluster-not-found
  TestCorrelationSummary         (4)  â€” KPI counts
  TestCorrelationEndpoints       (10) â€” REST status codes, auth, validation
  TestCeleryTask                 (4)  â€” run_sweep skips when Celery unavailable
  TestCeleryAppRegistration      (4)  â€” celery include + beat schedule entry

Total: 90 tests
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# â”€â”€ Shared mock helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _scalars_result(items):
    r = MagicMock()
    r.scalars = MagicMock(return_value=MagicMock(all=MagicMock(return_value=items)))
    return r


def _scalar_one(item):
    r = MagicMock()
    r.scalar_one_or_none = MagicMock(return_value=item)
    return r


def _scalar(value):
    r = MagicMock()
    r.scalar = MagicMock(return_value=value)
    return r


def _all_result(rows):
    r = MagicMock()
    r.all = MagicMock(return_value=rows)
    return r


def _make_rule(**kwargs):
    from asc_api.models.correlation import CorrelationRule
    rule = CorrelationRule()
    rule.id = kwargs.get("id", str(uuid.uuid4()))
    rule.name = kwargs.get("name", "Test Rule")
    rule.description = kwargs.get("description", None)
    rule.pivot_type = kwargs.get("pivot_type", "host_pivot")
    rule.min_signals = kwargs.get("min_signals", 2)
    rule.time_window_minutes = kwargs.get("time_window_minutes", 60)
    rule.severity_threshold = kwargs.get("severity_threshold", "low")
    rule.enabled = kwargs.get("enabled", True)
    rule.created_at = datetime.now(timezone.utc)
    rule.updated_at = datetime.now(timezone.utc)
    return rule


def _make_cluster(**kwargs):
    from asc_api.models.correlation import CorrelationCluster
    c = CorrelationCluster()
    c.id = kwargs.get("id", str(uuid.uuid4()))
    c.rule_id = kwargs.get("rule_id", str(uuid.uuid4()))
    c.cluster_key = kwargs.get("cluster_key", "ws-001")
    c.cluster_type = kwargs.get("cluster_type", "host_pivot")
    c.signal_count = kwargs.get("signal_count", 3)
    c.severity = kwargs.get("severity", "high")
    c.confidence_score = kwargs.get("confidence_score", 0.5)
    c.first_seen = kwargs.get("first_seen", datetime.now(timezone.utc))
    c.last_seen = kwargs.get("last_seen", datetime.now(timezone.utc))
    c.status = kwargs.get("status", "active")
    c.is_campaign = kwargs.get("is_campaign", False)
    c.campaign_name = kwargs.get("campaign_name", None)
    c.distinct_signal_domains = kwargs.get("distinct_signal_domains", 2)
    c.analyst_notes = kwargs.get("analyst_notes", None)
    c.assigned_to = kwargs.get("assigned_to", None)
    c.forensic_hash = kwargs.get("forensic_hash", None)
    c.meta = kwargs.get("meta", {})
    c.created_at = datetime.now(timezone.utc)
    c.updated_at = datetime.now(timezone.utc)
    return c


def _make_signal(**kwargs):
    from asc_api.models.correlation import CorrelationSignal
    s = CorrelationSignal()
    s.id = str(uuid.uuid4())
    s.cluster_id = kwargs.get("cluster_id", str(uuid.uuid4()))
    s.signal_type = kwargs.get("signal_type", "event")
    s.signal_id = kwargs.get("signal_id", str(uuid.uuid4()))
    s.pivot_value = kwargs.get("pivot_value", "ws-001")
    s.severity = kwargs.get("severity", "medium")
    s.timestamp = kwargs.get("timestamp", datetime.now(timezone.utc))
    s.meta = kwargs.get("meta", {})
    s.created_at = datetime.now(timezone.utc)
    return s


# â”€â”€ TestCorrelationModels â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestCorrelationModels:
    def test_pivot_types_constant(self):
        from asc_api.models.correlation import PIVOT_TYPES
        assert "host_pivot" in PIVOT_TYPES
        assert "identity_pivot" in PIVOT_TYPES
        assert "ip_pivot" in PIVOT_TYPES
        assert "domain_pivot" in PIVOT_TYPES
        assert "ttp_pivot" in PIVOT_TYPES

    def test_signal_types_constant(self):
        from asc_api.models.correlation import SIGNAL_TYPES
        assert "event" in SIGNAL_TYPES
        assert "alert" in SIGNAL_TYPES
        assert "finding" in SIGNAL_TYPES
        assert "identity_action" in SIGNAL_TYPES
        assert "panl_action" in SIGNAL_TYPES
        assert "ti_indicator" in SIGNAL_TYPES
        assert "agent_command" in SIGNAL_TYPES

    def test_cluster_statuses_constant(self):
        from asc_api.models.correlation import CLUSTER_STATUSES
        assert CLUSTER_STATUSES == {"active", "resolved", "dismissed"}

    def test_correlation_rule_instantiation(self):
        rule = _make_rule(name="R001", pivot_type="host_pivot", min_signals=3)
        assert rule.name == "R001"
        assert rule.pivot_type == "host_pivot"
        assert rule.min_signals == 3
        assert rule.enabled is True

    def test_correlation_cluster_instantiation(self):
        cluster = _make_cluster(cluster_key="10.0.0.5", cluster_type="ip_pivot", severity="critical")
        assert cluster.cluster_key == "10.0.0.5"
        assert cluster.severity == "critical"
        assert cluster.is_campaign is False

    def test_cluster_forensic_hash(self):
        import hashlib
        cluster = _make_cluster(
            id="aaa", rule_id="bbb", cluster_key="ws-001", cluster_type="host_pivot",
            signal_count=5, severity="high", is_campaign=True,
            first_seen=datetime(2026, 1, 1, tzinfo=timezone.utc),
            last_seen=datetime(2026, 1, 2, tzinfo=timezone.utc),
        )
        h = cluster.compute_forensic_hash()
        assert len(h) == 128  # SHA3-512 hex = 128 chars
        canonical = {
            "id": "aaa", "rule_id": "bbb", "cluster_key": "ws-001",
            "cluster_type": "host_pivot", "signal_count": 5, "severity": "high",
            "is_campaign": True,
            "first_seen": "2026-01-01T00:00:00+00:00",
            "last_seen": "2026-01-02T00:00:00+00:00",
        }
        expected = hashlib.sha3_512(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        assert h == expected

    def test_correlation_signal_instantiation(self):
        sig = _make_signal(signal_type="alert", pivot_value="jdoe@corp.local")
        assert sig.signal_type == "alert"
        assert sig.pivot_value == "jdoe@corp.local"

    def test_cluster_is_campaign_flag(self):
        cluster = _make_cluster(is_campaign=True, campaign_name="Campaign-ws001-abc12345")
        assert cluster.is_campaign is True
        assert "Campaign" in cluster.campaign_name


# â”€â”€ TestMaxSeverity â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestMaxSeverity:
    def _call(self, *args):
        from asc_api.services.correlation_service import _max_severity
        return _max_severity(list(args))

    def test_critical_wins(self):
        assert self._call("low", "medium", "critical", "high") == "critical"

    def test_high_over_medium(self):
        assert self._call("medium", "high", "low") == "high"

    def test_single_low(self):
        assert self._call("low") == "low"

    def test_empty_defaults_low(self):
        assert self._call() == "low"

    def test_all_same(self):
        assert self._call("medium", "medium", "medium") == "medium"

    def test_info_lowest(self):
        assert self._call("info", "low") == "low"


# â”€â”€ TestGatherHostSignals â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestGatherHostSignals:
    @pytest.mark.asyncio
    async def test_returns_event_signals(self):
        from asc_api.services.correlation_service import _gather_host_signals
        now = datetime.now(timezone.utc)
        # Mock event row
        event_row = MagicMock(); event_row.id = "e1"; event_row.host = "ws-001"
        event_row.severity = "high"; event_row.timestamp = now
        alert_row = MagicMock(); alert_row.id = "a1"; alert_row.affected_hosts = ["ws-001"]
        alert_row.severity = "medium"; alert_row.detected_at = now
        finding_row = MagicMock(); finding_row.id = "f1"; finding_row.affected_host = "ws-001"
        finding_row.severity = "low"; finding_row.created_at = now
        panl_row = MagicMock(); panl_row.id = "p1"; panl_row.target = "ws-001"
        panl_row.severity = "high"; panl_row.executed_at = now

        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[
            _all_result([event_row]),
            _all_result([alert_row]),
            _all_result([finding_row]),
            _all_result([panl_row]),
        ])
        signals = await _gather_host_signals(db, now - timedelta(hours=1))
        assert any(s["signal_type"] == "event" and s["pivot_value"] == "ws-001" for s in signals)

    @pytest.mark.asyncio
    async def test_alert_json_list_hosts_exploded(self):
        from asc_api.services.correlation_service import _gather_host_signals
        now = datetime.now(timezone.utc)
        alert_row = MagicMock(); alert_row.id = "a1"
        alert_row.affected_hosts = ["ws-001", "ws-002", "ws-003"]
        alert_row.severity = "critical"; alert_row.detected_at = now
        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[
            _all_result([]),          # events
            _all_result([alert_row]), # alerts
            _all_result([]),          # findings
            _all_result([]),          # panl
        ])
        signals = await _gather_host_signals(db, now - timedelta(hours=1))
        alert_signals = [s for s in signals if s["signal_type"] == "alert"]
        assert len(alert_signals) == 3
        pivot_vals = {s["pivot_value"] for s in alert_signals}
        assert "ws-001" in pivot_vals and "ws-002" in pivot_vals and "ws-003" in pivot_vals

    @pytest.mark.asyncio
    async def test_host_normalized_lowercase(self):
        from asc_api.services.correlation_service import _gather_host_signals
        now = datetime.now(timezone.utc)
        event_row = MagicMock(); event_row.id = "e1"; event_row.host = "WS-ALPHA"
        event_row.severity = "medium"; event_row.timestamp = now
        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[
            _all_result([event_row]),
            _all_result([]),
            _all_result([]),
            _all_result([]),
        ])
        signals = await _gather_host_signals(db, now - timedelta(hours=1))
        assert all(s["pivot_value"] == s["pivot_value"].lower() for s in signals)

    @pytest.mark.asyncio
    async def test_panl_isolate_endpoint_included(self):
        from asc_api.services.correlation_service import _gather_host_signals
        now = datetime.now(timezone.utc)
        panl_row = MagicMock(); panl_row.id = "p1"; panl_row.target = "endpoint-x"
        panl_row.severity = "high"; panl_row.executed_at = now
        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[
            _all_result([]),
            _all_result([]),
            _all_result([]),
            _all_result([panl_row]),
        ])
        signals = await _gather_host_signals(db, now - timedelta(hours=1))
        assert any(s["signal_type"] == "panl_action" for s in signals)

    @pytest.mark.asyncio
    async def test_empty_db_returns_empty_list(self):
        from asc_api.services.correlation_service import _gather_host_signals
        now = datetime.now(timezone.utc)
        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[
            _all_result([]), _all_result([]), _all_result([]), _all_result([])
        ])
        signals = await _gather_host_signals(db, now - timedelta(hours=1))
        assert signals == []

    @pytest.mark.asyncio
    async def test_alert_hosts_json_string_parsed(self):
        from asc_api.services.correlation_service import _gather_host_signals
        now = datetime.now(timezone.utc)
        alert_row = MagicMock(); alert_row.id = "a1"
        alert_row.affected_hosts = json.dumps(["ws-99"])  # stored as JSON string
        alert_row.severity = "high"; alert_row.detected_at = now
        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[
            _all_result([]),
            _all_result([alert_row]),
            _all_result([]),
            _all_result([]),
        ])
        signals = await _gather_host_signals(db, now - timedelta(hours=1))
        assert any(s["pivot_value"] == "ws-99" for s in signals)


# â”€â”€ TestGatherIdentitySignals â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestGatherIdentitySignals:
    @pytest.mark.asyncio
    async def test_identity_action_pivot_includes_domain(self):
        from asc_api.services.correlation_service import _gather_identity_signals
        now = datetime.now(timezone.utc)
        row = MagicMock(); row.id = "ia1"; row.username = "jdoe"
        row.domain = "corp.local"; row.action_type = "disable_account"; row.executed_at = now
        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[_all_result([row]), _all_result([])])
        signals = await _gather_identity_signals(db, now - timedelta(hours=2))
        assert any(s["pivot_value"] == "jdoe@corp.local" for s in signals)

    @pytest.mark.asyncio
    async def test_finding_affected_user_included(self):
        from asc_api.services.correlation_service import _gather_identity_signals
        now = datetime.now(timezone.utc)
        row = MagicMock(); row.id = "f1"; row.affected_user = "alice"
        row.severity = "medium"; row.created_at = now
        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[_all_result([]), _all_result([row])])
        signals = await _gather_identity_signals(db, now - timedelta(hours=2))
        assert any(s["pivot_value"] == "alice" for s in signals)

    @pytest.mark.asyncio
    async def test_identity_pivot_lowercase(self):
        from asc_api.services.correlation_service import _gather_identity_signals
        now = datetime.now(timezone.utc)
        row = MagicMock(); row.id = "ia1"; row.username = "ADMIN"
        row.domain = "CORP.LOCAL"; row.action_type = "quarantine_account"; row.executed_at = now
        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[_all_result([row]), _all_result([])])
        signals = await _gather_identity_signals(db, now - timedelta(hours=2))
        assert all(s["pivot_value"] == s["pivot_value"].lower() for s in signals)

    @pytest.mark.asyncio
    async def test_empty_returns_empty(self):
        from asc_api.services.correlation_service import _gather_identity_signals
        now = datetime.now(timezone.utc)
        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[_all_result([]), _all_result([])])
        signals = await _gather_identity_signals(db, now - timedelta(hours=2))
        assert signals == []


# â”€â”€ TestGatherIPSignals â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestGatherIPSignals:
    @pytest.mark.asyncio
    async def test_event_normalized_src_ip(self):
        from asc_api.services.correlation_service import _gather_ip_signals
        now = datetime.now(timezone.utc)
        row = MagicMock(); row.id = "e1"; row.normalized = {"src_ip": "1.2.3.4"}
        row.severity = "high"; row.timestamp = now
        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[_all_result([row]), _all_result([]), _all_result([])])
        signals = await _gather_ip_signals(db, now - timedelta(hours=1))
        assert any(s["pivot_value"] == "1.2.3.4" for s in signals)

    @pytest.mark.asyncio
    async def test_ti_indicator_ip_type(self):
        from asc_api.services.correlation_service import _gather_ip_signals
        now = datetime.now(timezone.utc)
        row = MagicMock(); row.id = "ti1"; row.value = "5.6.7.8"
        row.severity = "critical"; row.last_seen = now
        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[_all_result([]), _all_result([row]), _all_result([])])
        signals = await _gather_ip_signals(db, now - timedelta(hours=1))
        assert any(s["signal_type"] == "ti_indicator" and s["pivot_value"] == "5.6.7.8" for s in signals)

    @pytest.mark.asyncio
    async def test_panl_block_ip_included(self):
        from asc_api.services.correlation_service import _gather_ip_signals
        now = datetime.now(timezone.utc)
        row = MagicMock(); row.id = "p1"; row.target = "9.10.11.12"
        row.severity = "high"; row.executed_at = now
        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[_all_result([]), _all_result([]), _all_result([row])])
        signals = await _gather_ip_signals(db, now - timedelta(hours=1))
        assert any(s["signal_type"] == "panl_action" for s in signals)

    @pytest.mark.asyncio
    async def test_event_normalized_json_string(self):
        from asc_api.services.correlation_service import _gather_ip_signals
        now = datetime.now(timezone.utc)
        row = MagicMock(); row.id = "e1"
        row.normalized = json.dumps({"dst_ip": "200.200.200.200"})
        row.severity = "medium"; row.timestamp = now
        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[_all_result([row]), _all_result([]), _all_result([])])
        signals = await _gather_ip_signals(db, now - timedelta(hours=1))
        assert any(s["pivot_value"] == "200.200.200.200" for s in signals)


# â”€â”€ TestGatherDomainSignals â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestGatherDomainSignals:
    @pytest.mark.asyncio
    async def test_ti_domain_indicator(self):
        from asc_api.services.correlation_service import _gather_domain_signals
        now = datetime.now(timezone.utc)
        row = MagicMock(); row.id = "ti1"; row.value = "evil.ru"
        row.indicator_type = "domain"; row.severity = "high"; row.last_seen = now
        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[_all_result([row]), _all_result([]), _all_result([])])
        signals = await _gather_domain_signals(db, now - timedelta(hours=1))
        assert any(s["pivot_value"] == "evil.ru" for s in signals)

    @pytest.mark.asyncio
    async def test_panl_block_domain(self):
        from asc_api.services.correlation_service import _gather_domain_signals
        now = datetime.now(timezone.utc)
        row = MagicMock(); row.id = "p1"; row.target = "badsite.com"
        row.severity = "medium"; row.executed_at = now
        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[_all_result([]), _all_result([row]), _all_result([])])
        signals = await _gather_domain_signals(db, now - timedelta(hours=1))
        assert any(s["signal_type"] == "panl_action" and s["pivot_value"] == "badsite.com" for s in signals)

    @pytest.mark.asyncio
    async def test_finding_indicator_type_domain(self):
        from asc_api.services.correlation_service import _gather_domain_signals
        now = datetime.now(timezone.utc)
        row = MagicMock(); row.id = "f1"; row.indicator_value = "phishing.net"
        row.severity = "high"; row.created_at = now
        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[_all_result([]), _all_result([]), _all_result([row])])
        signals = await _gather_domain_signals(db, now - timedelta(hours=1))
        assert any(s["pivot_value"] == "phishing.net" for s in signals)

    @pytest.mark.asyncio
    async def test_domain_values_lowercased(self):
        from asc_api.services.correlation_service import _gather_domain_signals
        now = datetime.now(timezone.utc)
        row = MagicMock(); row.id = "ti1"; row.value = "EVIL.COM"
        row.indicator_type = "domain"; row.severity = "medium"; row.last_seen = now
        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[_all_result([row]), _all_result([]), _all_result([])])
        signals = await _gather_domain_signals(db, now - timedelta(hours=1))
        assert any(s["pivot_value"] == "evil.com" for s in signals)


# â”€â”€ TestGatherTTPSignals â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestGatherTTPSignals:
    @pytest.mark.asyncio
    async def test_event_tags_ttp(self):
        from asc_api.services.correlation_service import _gather_ttp_signals
        now = datetime.now(timezone.utc)
        row = MagicMock(); row.id = "e1"; row.tags = ["T1055", "T1059"]
        row.severity = "high"; row.timestamp = now
        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[_all_result([row]), _all_result([])])
        signals = await _gather_ttp_signals(db, now - timedelta(hours=1))
        pivot_vals = {s["pivot_value"] for s in signals}
        assert "T1055" in pivot_vals and "T1059" in pivot_vals

    @pytest.mark.asyncio
    async def test_alert_ttps(self):
        from asc_api.services.correlation_service import _gather_ttp_signals
        now = datetime.now(timezone.utc)
        row = MagicMock(); row.id = "a1"; row.ttps = ["T1078"]
        row.severity = "critical"; row.detected_at = now
        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[_all_result([]), _all_result([row])])
        signals = await _gather_ttp_signals(db, now - timedelta(hours=1))
        assert any(s["pivot_value"] == "T1078" and s["signal_type"] == "alert" for s in signals)

    @pytest.mark.asyncio
    async def test_non_mitre_tags_skipped(self):
        from asc_api.services.correlation_service import _gather_ttp_signals
        now = datetime.now(timezone.utc)
        row = MagicMock(); row.id = "e1"; row.tags = ["some-tag", "another"]
        row.severity = "low"; row.timestamp = now
        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[_all_result([row]), _all_result([])])
        signals = await _gather_ttp_signals(db, now - timedelta(hours=1))
        # "some-tag" doesn't start with Tâ†’digit combo but "another" â†’ just T-prefix filter
        # Our filter is tag.upper().startswith("T") â€” so "another" doesn't pass
        # "some-tag" also doesn't â†’ 0 signals
        assert all(s["pivot_value"].startswith("T") for s in signals)

    @pytest.mark.asyncio
    async def test_ttps_uppercased(self):
        from asc_api.services.correlation_service import _gather_ttp_signals
        now = datetime.now(timezone.utc)
        row = MagicMock(); row.id = "e1"; row.tags = ["t1055"]
        row.severity = "medium"; row.timestamp = now
        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[_all_result([row]), _all_result([])])
        signals = await _gather_ttp_signals(db, now - timedelta(hours=1))
        assert any(s["pivot_value"] == "T1055" for s in signals)


# â”€â”€ TestUpsertCluster â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestUpsertCluster:
    def _make_db(self, existing_cluster=None, existing_signals=None):
        db = AsyncMock()
        all_sigs_rows = existing_signals or []

        calls = []

        async def execute_side_effect(query, *args, **kwargs):
            calls.append(query)
            call_idx = len(calls) - 1
            if call_idx == 0:
                # SELECT cluster
                r = MagicMock()
                r.scalar_one_or_none = MagicMock(return_value=existing_cluster)
                return r
            elif call_idx == 1 and existing_cluster:
                # SELECT existing signal keys
                r = _all_result(all_sigs_rows)
                return r
            elif call_idx == 1 and not existing_cluster:
                # After flush â€” select existing signals (empty for new cluster)
                r = _all_result([])
                return r
            elif call_idx == 2:
                # Re-aggregate all signals
                r = _all_result(all_sigs_rows)
                return r
            return _all_result([])

        db.execute = AsyncMock(side_effect=execute_side_effect)
        db.flush = AsyncMock()
        db.add = MagicMock()
        return db

    @pytest.mark.asyncio
    async def test_creates_new_cluster_when_none_exists(self):
        from asc_api.services.correlation_service import _upsert_cluster
        rule = _make_rule(min_signals=2)
        db = AsyncMock()

        # Call 1: SELECT existing cluster â†’ None
        # Call 2: SELECT existing signals â†’ []
        # After flush â€” add signals
        # Call 3: Re-aggregate
        sig_row = MagicMock(); sig_row.severity = "high"; sig_row.signal_type = "event"
        sig_row.timestamp = datetime.now(timezone.utc)
        sig_row2 = MagicMock(); sig_row2.severity = "medium"; sig_row2.signal_type = "alert"
        sig_row2.timestamp = datetime.now(timezone.utc)

        call_count = [0]

        async def execute_se(q, *a, **kw):
            call_count[0] += 1
            if call_count[0] == 1:
                r = MagicMock(); r.scalar_one_or_none = MagicMock(return_value=None); return r
            elif call_count[0] == 2:
                return _all_result([])
            else:
                return _all_result([sig_row, sig_row2])

        db.execute = AsyncMock(side_effect=execute_se)
        db.flush = AsyncMock()
        db.add = MagicMock()

        signals = [
            {"signal_type": "event", "signal_id": "e1", "pivot_value": "ws-001",
             "severity": "high", "timestamp": datetime.now(timezone.utc), "meta": {}},
            {"signal_type": "alert", "signal_id": "a1", "pivot_value": "ws-001",
             "severity": "medium", "timestamp": datetime.now(timezone.utc), "meta": {}},
        ]
        cluster = await _upsert_cluster(db, rule, "ws-001", signals)
        assert cluster.cluster_key == "ws-001"
        assert cluster.signal_count == 2
        assert cluster.severity == "high"

    @pytest.mark.asyncio
    async def test_campaign_detected_at_3_domains(self):
        from asc_api.services.correlation_service import _upsert_cluster
        rule = _make_rule(min_signals=2)
        now = datetime.now(timezone.utc)

        sig_row_e = MagicMock(); sig_row_e.severity = "high"; sig_row_e.signal_type = "event"; sig_row_e.timestamp = now
        sig_row_a = MagicMock(); sig_row_a.severity = "high"; sig_row_a.signal_type = "alert"; sig_row_a.timestamp = now
        sig_row_i = MagicMock(); sig_row_i.severity = "critical"; sig_row_i.signal_type = "identity_action"; sig_row_i.timestamp = now

        call_count = [0]

        async def execute_se(q, *a, **kw):
            call_count[0] += 1
            if call_count[0] == 1:
                r = MagicMock(); r.scalar_one_or_none = MagicMock(return_value=None); return r
            elif call_count[0] == 2:
                return _all_result([])
            else:
                return _all_result([sig_row_e, sig_row_a, sig_row_i])

        db = AsyncMock()
        db.execute = AsyncMock(side_effect=execute_se)
        db.flush = AsyncMock()
        db.add = MagicMock()

        signals = [
            {"signal_type": "event", "signal_id": "e1", "pivot_value": "ws-001",
             "severity": "high", "timestamp": now, "meta": {}},
            {"signal_type": "alert", "signal_id": "a1", "pivot_value": "ws-001",
             "severity": "high", "timestamp": now, "meta": {}},
            {"signal_type": "identity_action", "signal_id": "ia1", "pivot_value": "ws-001",
             "severity": "critical", "timestamp": now, "meta": {}},
        ]
        cluster = await _upsert_cluster(db, rule, "ws-001", signals)
        assert cluster.is_campaign is True
        assert cluster.distinct_signal_domains == 3

    @pytest.mark.asyncio
    async def test_forensic_hash_set(self):
        from asc_api.services.correlation_service import _upsert_cluster
        rule = _make_rule()
        now = datetime.now(timezone.utc)
        sig_row = MagicMock(); sig_row.severity = "medium"
        sig_row.signal_type = "event"; sig_row.timestamp = now

        call_count = [0]

        async def execute_se(q, *a, **kw):
            call_count[0] += 1
            if call_count[0] == 1:
                r = MagicMock(); r.scalar_one_or_none = MagicMock(return_value=None); return r
            elif call_count[0] == 2:
                return _all_result([])
            else:
                return _all_result([sig_row, sig_row])

        db = AsyncMock()
        db.execute = AsyncMock(side_effect=execute_se)
        db.flush = AsyncMock()
        db.add = MagicMock()

        signals = [
            {"signal_type": "event", "signal_id": "e1", "pivot_value": "ws-001",
             "severity": "medium", "timestamp": now, "meta": {}},
            {"signal_type": "alert", "signal_id": "a1", "pivot_value": "ws-001",
             "severity": "medium", "timestamp": now, "meta": {}},
        ]
        cluster = await _upsert_cluster(db, rule, "ws-001", signals)
        assert cluster.forensic_hash is not None
        assert len(cluster.forensic_hash) == 128

    @pytest.mark.asyncio
    async def test_confidence_score_bounded_0_1(self):
        from asc_api.services.correlation_service import _upsert_cluster
        rule = _make_rule(min_signals=2)
        now = datetime.now(timezone.utc)

        many_sigs = [
            MagicMock(severity="high", signal_type="event", timestamp=now)
            for _ in range(100)
        ]

        call_count = [0]

        async def execute_se(q, *a, **kw):
            call_count[0] += 1
            if call_count[0] == 1:
                r = MagicMock(); r.scalar_one_or_none = MagicMock(return_value=None); return r
            elif call_count[0] == 2:
                return _all_result([])
            else:
                return _all_result(many_sigs)

        db = AsyncMock()
        db.execute = AsyncMock(side_effect=execute_se)
        db.flush = AsyncMock(); db.add = MagicMock()

        signals = [{"signal_type": "event", "signal_id": str(i), "pivot_value": "ws-001",
                    "severity": "high", "timestamp": now, "meta": {}} for i in range(10)]
        cluster = await _upsert_cluster(db, rule, "ws-001", signals)
        assert 0.0 <= cluster.confidence_score <= 1.0

    @pytest.mark.asyncio
    async def test_duplicate_signals_not_added(self):
        from asc_api.services.correlation_service import _upsert_cluster
        rule = _make_rule()
        now = datetime.now(timezone.utc)
        existing_cluster = _make_cluster(rule_id=rule.id, cluster_key="ws-001")

        # Existing signal in DB
        existing_sig = MagicMock()
        existing_sig.signal_type = "event"
        existing_sig.signal_id = "e1"

        agg_row = MagicMock(severity="medium", signal_type="event", timestamp=now)

        call_count = [0]

        async def execute_se(q, *a, **kw):
            call_count[0] += 1
            if call_count[0] == 1:
                r = MagicMock(); r.scalar_one_or_none = MagicMock(return_value=existing_cluster); return r
            elif call_count[0] == 2:
                return _all_result([existing_sig])
            else:
                return _all_result([agg_row])

        db = AsyncMock()
        db.execute = AsyncMock(side_effect=execute_se)
        db.flush = AsyncMock(); db.add = MagicMock()

        # Feed the same signal_id again â€” should NOT be added
        signals = [{"signal_type": "event", "signal_id": "e1", "pivot_value": "ws-001",
                    "severity": "medium", "timestamp": now, "meta": {}}]
        await _upsert_cluster(db, rule, "ws-001", signals)
        # db.add should NOT have been called for CorrelationSignal
        for call in db.add.call_args_list:
            from asc_api.models.correlation import CorrelationSignal
            assert not isinstance(call.args[0], CorrelationSignal)

    @pytest.mark.asyncio
    async def test_campaign_name_auto_generated(self):
        from asc_api.services.correlation_service import _upsert_cluster
        rule = _make_rule()
        now = datetime.now(timezone.utc)
        sig_rows = [
            MagicMock(severity="critical", signal_type="event", timestamp=now),
            MagicMock(severity="high", signal_type="alert", timestamp=now),
            MagicMock(severity="high", signal_type="identity_action", timestamp=now),
        ]

        call_count = [0]

        async def execute_se(q, *a, **kw):
            call_count[0] += 1
            if call_count[0] == 1:
                r = MagicMock(); r.scalar_one_or_none = MagicMock(return_value=None); return r
            elif call_count[0] == 2:
                return _all_result([])
            else:
                return _all_result(sig_rows)

        db = AsyncMock()
        db.execute = AsyncMock(side_effect=execute_se)
        db.flush = AsyncMock(); db.add = MagicMock()

        signals = [
            {"signal_type": st, "signal_id": f"id_{st}", "pivot_value": "ws-001",
             "severity": "high", "timestamp": now, "meta": {}}
            for st in ["event", "alert", "identity_action"]
        ]
        cluster = await _upsert_cluster(db, rule, "ws-001", signals)
        assert cluster.campaign_name is not None
        assert "Campaign" in cluster.campaign_name

    @pytest.mark.asyncio
    async def test_severity_max_from_signals(self):
        from asc_api.services.correlation_service import _upsert_cluster
        rule = _make_rule()
        now = datetime.now(timezone.utc)
        sig_rows = [
            MagicMock(severity="low", signal_type="event", timestamp=now),
            MagicMock(severity="critical", signal_type="alert", timestamp=now),
        ]

        call_count = [0]

        async def execute_se(q, *a, **kw):
            call_count[0] += 1
            if call_count[0] == 1:
                r = MagicMock(); r.scalar_one_or_none = MagicMock(return_value=None); return r
            elif call_count[0] == 2:
                return _all_result([])
            else:
                return _all_result(sig_rows)

        db = AsyncMock()
        db.execute = AsyncMock(side_effect=execute_se)
        db.flush = AsyncMock(); db.add = MagicMock()

        signals = [
            {"signal_type": "event", "signal_id": "e1", "pivot_value": "ws-001",
             "severity": "low", "timestamp": now, "meta": {}},
            {"signal_type": "alert", "signal_id": "a1", "pivot_value": "ws-001",
             "severity": "critical", "timestamp": now, "meta": {}},
        ]
        cluster = await _upsert_cluster(db, rule, "ws-001", signals)
        assert cluster.severity == "critical"


# â”€â”€ TestRunCorrelationSweep â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestRunCorrelationSweep:
    @pytest.mark.asyncio
    async def test_returns_stats_dict(self):
        from asc_api.services.correlation_service import run_correlation_sweep
        db = AsyncMock()
        # No enabled rules
        db.execute = AsyncMock(return_value=_scalars_result([]))
        db.commit = AsyncMock()
        with patch("asc_api.services.correlation_service.log_security_action", new_callable=AsyncMock):
            result = await run_correlation_sweep(db)
        assert "rules_evaluated" in result
        assert result["rules_evaluated"] == 0

    @pytest.mark.asyncio
    async def test_skips_unknown_pivot_type(self):
        from asc_api.services.correlation_service import run_correlation_sweep
        rule = _make_rule(pivot_type="unknown_pivot")
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalars_result([rule]))
        db.commit = AsyncMock()
        with patch("asc_api.services.correlation_service.log_security_action", new_callable=AsyncMock):
            result = await run_correlation_sweep(db)
        assert result["clusters_created"] == 0

    @pytest.mark.asyncio
    async def test_threshold_filters_low_severity_signals(self):
        from asc_api.services import correlation_service
        rule = _make_rule(pivot_type="host_pivot", severity_threshold="high", min_signals=2)
        # All low-severity signals should be filtered out
        low_signals = [
            {"signal_type": "event", "signal_id": f"e{i}", "pivot_value": "ws-001",
             "severity": "low", "timestamp": datetime.now(timezone.utc), "meta": {}}
            for i in range(5)
        ]
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalars_result([rule]))
        db.commit = AsyncMock()
        with patch("asc_api.services.correlation_service._gather_host_signals", new_callable=AsyncMock) as mock_gather, \
             patch("asc_api.services.correlation_service.log_security_action", new_callable=AsyncMock):
            mock_gather.return_value = low_signals
            result = await correlation_service.run_correlation_sweep(db)
        assert result["clusters_created"] == 0

    @pytest.mark.asyncio
    async def test_signals_below_min_skipped(self):
        from asc_api.services import correlation_service
        rule = _make_rule(pivot_type="host_pivot", min_signals=5, severity_threshold="low")
        # Only 2 signals â€” below min_signals=5
        signals = [
            {"signal_type": "event", "signal_id": f"e{i}", "pivot_value": "ws-001",
             "severity": "high", "timestamp": datetime.now(timezone.utc), "meta": {}}
            for i in range(2)
        ]
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalars_result([rule]))
        db.commit = AsyncMock()
        with patch("asc_api.services.correlation_service._gather_host_signals", new_callable=AsyncMock) as mock_gather, \
             patch("asc_api.services.correlation_service.log_security_action", new_callable=AsyncMock):
            mock_gather.return_value = signals
            result = await correlation_service.run_correlation_sweep(db)
        assert result["clusters_created"] == 0

    @pytest.mark.asyncio
    async def test_commits_after_sweep(self):
        from asc_api.services.correlation_service import run_correlation_sweep
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalars_result([]))
        db.commit = AsyncMock()
        with patch("asc_api.services.correlation_service.log_security_action", new_callable=AsyncMock):
            await run_correlation_sweep(db)
        db.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_deduplicates_signals_in_group(self):
        from asc_api.services import correlation_service
        rule = _make_rule(pivot_type="host_pivot", min_signals=2, severity_threshold="low")
        # Same signal_id duplicated â€” after dedup, only 1 unique â†’ below min_signals=2
        signals = [
            {"signal_type": "event", "signal_id": "e1", "pivot_value": "ws-001",
             "severity": "high", "timestamp": datetime.now(timezone.utc), "meta": {}},
            {"signal_type": "event", "signal_id": "e1", "pivot_value": "ws-001",
             "severity": "high", "timestamp": datetime.now(timezone.utc), "meta": {}},
        ]
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalars_result([rule]))
        db.commit = AsyncMock()
        with patch("asc_api.services.correlation_service._gather_host_signals", new_callable=AsyncMock) as mock_gather, \
             patch("asc_api.services.correlation_service.log_security_action", new_callable=AsyncMock):
            mock_gather.return_value = signals
            result = await correlation_service.run_correlation_sweep(db)
        assert result["clusters_created"] == 0  # only 1 unique after dedup


# â”€â”€ TestQueryAPI â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestQueryAPI:
    @pytest.mark.asyncio
    async def test_list_rules(self):
        from asc_api.services.correlation_service import list_rules
        rules = [_make_rule(name=f"Rule {i}") for i in range(3)]
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalars_result(rules))
        result = await list_rules(db)
        assert len(result) == 3

    @pytest.mark.asyncio
    async def test_get_rule_found(self):
        from asc_api.services.correlation_service import get_rule
        rule = _make_rule(id="rule-123")
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(rule))
        result = await get_rule(db, "rule-123")
        assert result.id == "rule-123"

    @pytest.mark.asyncio
    async def test_get_rule_not_found(self):
        from asc_api.services.correlation_service import get_rule
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(None))
        result = await get_rule(db, "nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_create_rule(self):
        from asc_api.services.correlation_service import create_rule
        db = AsyncMock()
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock()
        rule = await create_rule(db, name="New Rule", pivot_type="host_pivot", min_signals=3)
        assert rule.name == "New Rule"
        assert rule.pivot_type == "host_pivot"
        assert rule.min_signals == 3
        db.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_rule(self):
        from asc_api.services.correlation_service import update_rule
        rule = _make_rule(name="Old Name", enabled=True)
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(rule))
        db.commit = AsyncMock()
        db.refresh = AsyncMock()
        updated = await update_rule(db, rule.id, name="New Name", enabled=False)
        assert updated.name == "New Name"
        assert updated.enabled is False

    @pytest.mark.asyncio
    async def test_update_rule_not_found(self):
        from asc_api.services.correlation_service import update_rule
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(None))
        result = await update_rule(db, "ghost-id", name="X")
        assert result is None

    @pytest.mark.asyncio
    async def test_delete_rule_found(self):
        from asc_api.services.correlation_service import delete_rule
        rule = _make_rule()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(rule))
        db.delete = AsyncMock()
        db.commit = AsyncMock()
        ok = await delete_rule(db, rule.id)
        assert ok is True
        db.delete.assert_called_once_with(rule)

    @pytest.mark.asyncio
    async def test_delete_rule_not_found(self):
        from asc_api.services.correlation_service import delete_rule
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(None))
        ok = await delete_rule(db, "nope")
        assert ok is False


# â”€â”€ TestClusterStatusUpdate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestClusterStatusUpdate:
    @pytest.mark.asyncio
    async def test_resolve_cluster(self):
        from asc_api.services.correlation_service import update_cluster_status
        cluster = _make_cluster(status="active")
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(cluster))
        db.commit = AsyncMock(); db.refresh = AsyncMock()
        result = await update_cluster_status(db, cluster.id, status="resolved",
                                             analyst_notes="Confirmed false positive")
        assert result.status == "resolved"
        assert result.analyst_notes == "Confirmed false positive"

    @pytest.mark.asyncio
    async def test_dismiss_cluster(self):
        from asc_api.services.correlation_service import update_cluster_status
        cluster = _make_cluster(status="active")
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(cluster))
        db.commit = AsyncMock(); db.refresh = AsyncMock()
        result = await update_cluster_status(db, cluster.id, status="dismissed")
        assert result.status == "dismissed"

    @pytest.mark.asyncio
    async def test_assign_analyst(self):
        from asc_api.services.correlation_service import update_cluster_status
        cluster = _make_cluster()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(cluster))
        db.commit = AsyncMock(); db.refresh = AsyncMock()
        result = await update_cluster_status(db, cluster.id, status="active",
                                             assigned_to="analyst@corp.local")
        assert result.assigned_to == "analyst@corp.local"

    @pytest.mark.asyncio
    async def test_not_found_returns_none(self):
        from asc_api.services.correlation_service import update_cluster_status
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(None))
        result = await update_cluster_status(db, "ghost", status="resolved")
        assert result is None


# â”€â”€ TestClusterGraph â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestClusterGraph:
    @pytest.mark.asyncio
    async def test_not_found_returns_none(self):
        from asc_api.services.correlation_service import get_cluster_graph
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar_one(None))
        result = await get_cluster_graph(db, "ghost-id")
        assert result is None

    @pytest.mark.asyncio
    async def test_graph_has_required_keys(self):
        from asc_api.services.correlation_service import get_cluster_graph
        rule = _make_rule()
        cluster = _make_cluster(rule_id=rule.id, cluster_key="ws-001")
        sig = _make_signal(cluster_id=cluster.id, signal_type="event", signal_id="e1")

        call_count = [0]

        async def execute_se(q, *a, **kw):
            call_count[0] += 1
            if call_count[0] == 1:
                r = MagicMock(); r.scalar_one_or_none = MagicMock(return_value=cluster); return r
            elif call_count[0] == 2:
                return _scalars_result([sig])
            else:
                r = MagicMock(); r.scalar_one_or_none = MagicMock(return_value=rule); return r

        db = AsyncMock()
        db.execute = AsyncMock(side_effect=execute_se)
        graph = await get_cluster_graph(db, cluster.id)
        assert graph is not None
        assert "nodes" in graph
        assert "edges" in graph
        assert "pivot_type" in graph
        assert "pivot_value" in graph

    @pytest.mark.asyncio
    async def test_graph_has_cluster_center_node(self):
        from asc_api.services.correlation_service import get_cluster_graph
        rule = _make_rule()
        cluster = _make_cluster(rule_id=rule.id, cluster_key="jdoe@corp.local",
                                 cluster_type="identity_pivot")
        sig = _make_signal(cluster_id=cluster.id, signal_type="identity_action")

        call_count = [0]

        async def execute_se(q, *a, **kw):
            call_count[0] += 1
            if call_count[0] == 1:
                r = MagicMock(); r.scalar_one_or_none = MagicMock(return_value=cluster); return r
            elif call_count[0] == 2:
                return _scalars_result([sig])
            else:
                r = MagicMock(); r.scalar_one_or_none = MagicMock(return_value=rule); return r

        db = AsyncMock()
        db.execute = AsyncMock(side_effect=execute_se)
        graph = await get_cluster_graph(db, cluster.id)
        cluster_nodes = [n for n in graph["nodes"] if n["type"] == "cluster"]
        assert len(cluster_nodes) == 1
        assert cluster_nodes[0]["label"] == "jdoe@corp.local"

    @pytest.mark.asyncio
    async def test_graph_edges_reference_cluster_id(self):
        from asc_api.services.correlation_service import get_cluster_graph
        rule = _make_rule()
        cluster = _make_cluster(rule_id=rule.id)
        sig1 = _make_signal(cluster_id=cluster.id, signal_type="event", signal_id="e1")
        sig2 = _make_signal(cluster_id=cluster.id, signal_type="alert", signal_id="a1")

        call_count = [0]

        async def execute_se(q, *a, **kw):
            call_count[0] += 1
            if call_count[0] == 1:
                r = MagicMock(); r.scalar_one_or_none = MagicMock(return_value=cluster); return r
            elif call_count[0] == 2:
                return _scalars_result([sig1, sig2])
            else:
                r = MagicMock(); r.scalar_one_or_none = MagicMock(return_value=rule); return r

        db = AsyncMock()
        db.execute = AsyncMock(side_effect=execute_se)
        graph = await get_cluster_graph(db, cluster.id)
        assert all(e["source"] == cluster.id for e in graph["edges"])

    @pytest.mark.asyncio
    async def test_campaign_flag_propagated_to_graph(self):
        from asc_api.services.correlation_service import get_cluster_graph
        rule = _make_rule()
        cluster = _make_cluster(rule_id=rule.id, is_campaign=True,
                                 campaign_name="Campaign-ws001-abc123")
        sig = _make_signal(cluster_id=cluster.id)

        call_count = [0]

        async def execute_se(q, *a, **kw):
            call_count[0] += 1
            if call_count[0] == 1:
                r = MagicMock(); r.scalar_one_or_none = MagicMock(return_value=cluster); return r
            elif call_count[0] == 2:
                return _scalars_result([sig])
            else:
                r = MagicMock(); r.scalar_one_or_none = MagicMock(return_value=rule); return r

        db = AsyncMock()
        db.execute = AsyncMock(side_effect=execute_se)
        graph = await get_cluster_graph(db, cluster.id)
        assert graph["is_campaign"] is True
        assert "Campaign" in graph["campaign_name"]

    @pytest.mark.asyncio
    async def test_duplicate_signal_ids_produce_single_node(self):
        from asc_api.services.correlation_service import get_cluster_graph
        rule = _make_rule()
        cluster = _make_cluster(rule_id=rule.id)
        # Two signals with same signal_id â€” should produce 1 node
        sig1 = _make_signal(cluster_id=cluster.id, signal_type="event", signal_id="e1", pivot_value="ws-001")
        sig2 = _make_signal(cluster_id=cluster.id, signal_type="event", signal_id="e1", pivot_value="ws-001")

        call_count = [0]

        async def execute_se(q, *a, **kw):
            call_count[0] += 1
            if call_count[0] == 1:
                r = MagicMock(); r.scalar_one_or_none = MagicMock(return_value=cluster); return r
            elif call_count[0] == 2:
                return _scalars_result([sig1, sig2])
            else:
                r = MagicMock(); r.scalar_one_or_none = MagicMock(return_value=rule); return r

        db = AsyncMock()
        db.execute = AsyncMock(side_effect=execute_se)
        graph = await get_cluster_graph(db, cluster.id)
        non_cluster_nodes = [n for n in graph["nodes"] if n["type"] != "cluster"]
        assert len(non_cluster_nodes) == 1  # deduped


# â”€â”€ TestCorrelationSummary â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestCorrelationSummary:
    @pytest.mark.asyncio
    async def test_summary_returns_all_keys(self):
        from asc_api.services.correlation_service import get_correlation_summary
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar(5))
        result = await get_correlation_summary(db)
        assert "total_clusters" in result
        assert "active_clusters" in result
        assert "campaigns_detected" in result
        assert "critical_clusters" in result
        assert "total_signals" in result
        assert "active_rules" in result

    @pytest.mark.asyncio
    async def test_summary_counts_non_negative(self):
        from asc_api.services.correlation_service import get_correlation_summary
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar(0))
        result = await get_correlation_summary(db)
        assert all(v >= 0 for v in result.values())

    @pytest.mark.asyncio
    async def test_summary_zero_when_empty(self):
        from asc_api.services.correlation_service import get_correlation_summary
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalar(None))
        result = await get_correlation_summary(db)
        assert result["total_clusters"] == 0

    @pytest.mark.asyncio
    async def test_list_clusters_filterable(self):
        from asc_api.services.correlation_service import list_clusters
        clusters = [_make_cluster(status="active") for _ in range(5)]
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_scalars_result(clusters))
        result = await list_clusters(db, status="active", limit=10)
        assert len(result) == 5


# â”€â”€ TestCorrelationEndpoints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _make_endpoint_app():
    from fastapi import FastAPI
    from asc_api.api.v1.endpoints.correlation import router as cr
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.errors import RateLimitExceeded
    from slowapi.util import get_remote_address
    app = FastAPI()
    app.include_router(cr)
    limiter = Limiter(key_func=get_remote_address)
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    return app


def _mock_analyst():
    from asc_api.models.user import User
    u = MagicMock(spec=User)
    u.role = "admin"
    return u


class TestCorrelationEndpoints:
    @pytest.mark.asyncio
    async def test_get_summary_200(self):
        from httpx import AsyncClient, ASGITransport
        from asc_api.api.deps import get_analyst_or_admin
        from asc_api.db.session import get_db
        summary = {"total_clusters": 5, "active_clusters": 3, "campaigns_detected": 1,
                   "critical_clusters": 0, "total_signals": 20, "active_rules": 4}
        app = _make_endpoint_app()
        mock_user = _mock_analyst()
        mock_db = AsyncMock()
        app.dependency_overrides[get_analyst_or_admin] = lambda: mock_user
        app.dependency_overrides[get_db] = lambda: mock_db
        with patch("asc_api.api.v1.endpoints.correlation.correlation_service.get_correlation_summary",
                   new_callable=AsyncMock, return_value=summary):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                resp = await ac.get("/correlation/summary")
        assert resp.status_code == 200
        assert resp.json()["total_clusters"] == 5

    @pytest.mark.asyncio
    async def test_list_rules_200(self):
        from httpx import AsyncClient, ASGITransport
        from asc_api.api.deps import get_analyst_or_admin
        from asc_api.db.session import get_db
        rules = [_make_rule()]
        app = _make_endpoint_app()
        app.dependency_overrides[get_analyst_or_admin] = lambda: _mock_analyst()
        app.dependency_overrides[get_db] = lambda: AsyncMock()
        with patch("asc_api.api.v1.endpoints.correlation.correlation_service.list_rules",
                   new_callable=AsyncMock, return_value=rules):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                resp = await ac.get("/correlation/rules")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    @pytest.mark.asyncio
    async def test_get_rule_404_when_not_found(self):
        from httpx import AsyncClient, ASGITransport
        from asc_api.api.deps import get_analyst_or_admin
        from asc_api.db.session import get_db
        app = _make_endpoint_app()
        app.dependency_overrides[get_analyst_or_admin] = lambda: _mock_analyst()
        app.dependency_overrides[get_db] = lambda: AsyncMock()
        with patch("asc_api.api.v1.endpoints.correlation.correlation_service.get_rule",
                   new_callable=AsyncMock, return_value=None):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                resp = await ac.get("/correlation/rules/nonexistent")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_create_rule_invalid_pivot_type_422(self):
        from httpx import AsyncClient, ASGITransport
        from asc_api.api.deps import get_analyst_or_admin
        from asc_api.db.session import get_db
        app = _make_endpoint_app()
        app.dependency_overrides[get_analyst_or_admin] = lambda: _mock_analyst()
        app.dependency_overrides[get_db] = lambda: AsyncMock()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            resp = await ac.post("/correlation/rules", json={
                "name": "Bad Rule",
                "pivot_type": "invalid_pivot",
            })
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_list_clusters_200(self):
        from httpx import AsyncClient, ASGITransport
        from asc_api.api.deps import get_analyst_or_admin
        from asc_api.db.session import get_db
        clusters = [_make_cluster()]
        app = _make_endpoint_app()
        app.dependency_overrides[get_analyst_or_admin] = lambda: _mock_analyst()
        app.dependency_overrides[get_db] = lambda: AsyncMock()
        with patch("asc_api.api.v1.endpoints.correlation.correlation_service.list_clusters",
                   new_callable=AsyncMock, return_value=clusters):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                resp = await ac.get("/correlation/clusters")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_get_cluster_404(self):
        from httpx import AsyncClient, ASGITransport
        from asc_api.api.deps import get_analyst_or_admin
        from asc_api.db.session import get_db
        app = _make_endpoint_app()
        app.dependency_overrides[get_analyst_or_admin] = lambda: _mock_analyst()
        app.dependency_overrides[get_db] = lambda: AsyncMock()
        with patch("asc_api.api.v1.endpoints.correlation.correlation_service.get_cluster",
                   new_callable=AsyncMock, return_value=None):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                resp = await ac.get("/correlation/clusters/ghost")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_update_cluster_status_invalid_422(self):
        from httpx import AsyncClient, ASGITransport
        from asc_api.api.deps import get_analyst_or_admin
        from asc_api.db.session import get_db
        app = _make_endpoint_app()
        app.dependency_overrides[get_analyst_or_admin] = lambda: _mock_analyst()
        app.dependency_overrides[get_db] = lambda: AsyncMock()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            resp = await ac.patch("/correlation/clusters/some-id/status",
                                  json={"status": "invalid_status"})
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_get_cluster_graph_404(self):
        from httpx import AsyncClient, ASGITransport
        from asc_api.api.deps import get_analyst_or_admin
        from asc_api.db.session import get_db
        app = _make_endpoint_app()
        app.dependency_overrides[get_analyst_or_admin] = lambda: _mock_analyst()
        app.dependency_overrides[get_db] = lambda: AsyncMock()
        with patch("asc_api.api.v1.endpoints.correlation.correlation_service.get_cluster_graph",
                   new_callable=AsyncMock, return_value=None):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                resp = await ac.get("/correlation/clusters/ghost/graph")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_rule_admin_only_403(self):
        from httpx import AsyncClient, ASGITransport
        from fastapi import HTTPException
        from asc_api.api.deps import get_current_admin
        from asc_api.db.session import get_db
        app = _make_endpoint_app()
        app.dependency_overrides[get_current_admin] = lambda: (_ for _ in ()).throw(
            HTTPException(status_code=403, detail="Forbidden")
        )
        app.dependency_overrides[get_db] = lambda: AsyncMock()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            resp = await ac.delete("/correlation/rules/some-id")
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_create_rule_valid_201(self):
        from httpx import AsyncClient, ASGITransport
        from asc_api.api.deps import get_analyst_or_admin
        from asc_api.db.session import get_db
        new_rule = _make_rule(name="My Rule", pivot_type="ip_pivot")
        app = _make_endpoint_app()
        app.dependency_overrides[get_analyst_or_admin] = lambda: _mock_analyst()
        app.dependency_overrides[get_db] = lambda: AsyncMock()
        with patch("asc_api.api.v1.endpoints.correlation.correlation_service.create_rule",
                   new_callable=AsyncMock, return_value=new_rule):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                resp = await ac.post("/correlation/rules", json={
                    "name": "My Rule",
                    "pivot_type": "ip_pivot",
                })
        assert resp.status_code == 201


# â”€â”€ TestCeleryTask â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestCeleryTask:
    def test_task_registered_in_celery_app(self):
        try:
            from asc_api.tasks.celery_app import celery_app
        except Exception:
            pytest.skip("Celery not installed")
        assert "app.tasks.correlation_sweep" in celery_app.conf.include

    def test_beat_schedule_contains_correlation(self):
        try:
            from asc_api.tasks.celery_app import celery_app
        except Exception:
            pytest.skip("Celery not installed")
        assert "correlation-sweep" in celery_app.conf.beat_schedule

    def test_sweep_task_callable(self):
        try:
            from asc_api.tasks.correlation_sweep import run_sweep
        except ImportError:
            pytest.skip("Celery not installed")
        assert callable(run_sweep)

    def test_sweep_task_name(self):
        try:
            from asc_api.tasks.correlation_sweep import run_sweep
        except ImportError:
            pytest.skip("Celery not installed")
        assert run_sweep.name == "asc.correlation_sweep.run_sweep"


# â”€â”€ TestCeleryAppRegistration â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestCeleryAppRegistration:
    def test_correlation_in_include(self):
        try:
            from asc_api.tasks.celery_app import celery_app
        except Exception:
            pytest.skip("Celery not installed")
        assert "app.tasks.correlation_sweep" in celery_app.conf.include

    def test_correlation_beat_interval(self):
        try:
            from asc_api.tasks.celery_app import celery_app
        except Exception:
            pytest.skip("Celery not installed")
        entry = celery_app.conf.beat_schedule.get("correlation-sweep", {})
        assert entry.get("task") == "asc.correlation_sweep.run_sweep"
        assert entry.get("schedule", 0) > 0

    def test_all_tasks_in_include(self):
        try:
            from asc_api.tasks.celery_app import celery_app
        except Exception:
            pytest.skip("Celery not installed")
        expected = {
            "app.tasks.escalation",
            "app.tasks.pcdi_escalation",
            "app.tasks.scheduled_reports",
            "app.tasks.correlation_sweep",
        }
        assert expected.issubset(set(celery_app.conf.include))

    def test_router_includes_correlation(self):
        from asc_api.api.v1.router import api_router
        routes = {r.path for r in api_router.routes}
        # The correlation router is included â€” check for one of its paths
        assert any("/correlation" in p for p in routes)
