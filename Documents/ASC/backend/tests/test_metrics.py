"""
Unit + integration tests — Priority 4: MTTD/MTTR real calculation

Tests:
  TestStatBlock          — _stat_block() percentile and SLA logic
  TestMTTD               — calculate_mttd() boundary and skip logic
  TestMTTA               — calculate_mtta() boundary and skip logic
  TestMTTR               — calculate_mttr() boundary and skip logic
  TestMTTRRespond        — calculate_mttr_respond() boundary and skip logic
  TestBreakdownBySeverity — breakdown_by_severity() bucketing
  TestStatusFunnel       — status_funnel() lifecycle counts
  TestDailyTrend         — daily_mttr_trend() shape and correctness
  TestBuildSocSummary    — build_soc_summary() combines metrics
  TestMetricsSocAPI      — GET /metrics/soc (authenticated)
  TestMetricsPublicAPI   — GET /metrics/public (no auth)
  TestMetricsPerformanceAPI — GET /metrics/performance (authenticated)
  TestMetricsTimelineAPI — GET /metrics/timeline (authenticated)
  TestNegativeDeltaSkip  — guards against data-integrity issues
  TestSLACompliance      — SLA thresholds and edge cases
"""
import uuid
import pytest
import pytest_asyncio
from datetime import datetime, timezone, timedelta
from types import SimpleNamespace
from httpx import AsyncClient

from app.models.alert import Alert
from app.models.user import User
from app.services.metrics import (
    calculate_mttd, calculate_mtta, calculate_mttr, calculate_mttr_respond,
    breakdown_by_severity, status_funnel, daily_mttr_trend, build_soc_summary,
    MTTD_SLA_SECONDS, MTTA_SLA_SECONDS, MTTR_SLA_SECONDS,
    _stat_block, _avg, _percentile,
)

# ─── Helpers ──────────────────────────────────────────────────────────────────

NOW = datetime.now(timezone.utc).replace(hour=12, minute=0, second=0, microsecond=0)


def _alert(
    severity: str = "medium",
    status: str = "open",
    threat_start_offset_m: int | None = None,   # minutes before detected_at
    detected_offset_m: int = 0,                  # minutes before NOW
    ack_offset_m: int | None = None,             # minutes after detected_at
    resolved_offset_m: int | None = None,        # minutes after detected_at
    false_positive: bool = False,
) -> SimpleNamespace:
    """
    Build a lightweight Alert-like namespace for pure-function unit tests.
    Uses SimpleNamespace (not a SQLAlchemy ORM instance) to avoid ORM init overhead.
    The metrics service functions only access attribute values — no ORM methods needed.
    """
    detected_at = NOW - timedelta(minutes=detected_offset_m)
    threat_start = (
        detected_at - timedelta(minutes=threat_start_offset_m)
        if threat_start_offset_m is not None else None
    )
    acknowledged_at = (
        detected_at + timedelta(minutes=ack_offset_m)
        if ack_offset_m is not None else None
    )
    resolved_at = (
        detected_at + timedelta(minutes=resolved_offset_m)
        if resolved_offset_m is not None else None
    )
    return SimpleNamespace(
        id=str(uuid.uuid4()),
        severity=severity,
        status=status,
        threat_start_at=threat_start,
        detected_at=detected_at,
        acknowledged_at=acknowledged_at,
        resolved_at=resolved_at,
        false_positive=false_positive,
        risk_score=0.5,
    )


# ─── _avg and _percentile primitives ────────────────────────────────────────

class TestCoreHelpers:
    def test_avg_empty(self):
        assert _avg([]) is None

    def test_avg_single(self):
        assert _avg([60.0]) == 60.0

    def test_avg_multiple(self):
        assert _avg([60.0, 120.0]) == 90.0

    def test_percentile_p50_single(self):
        assert _percentile([100.0], 50) == 100.0

    def test_percentile_p50_two(self):
        # Nearest-rank: p50 of [10, 20] → index max(0, int(2*50/100)-1)=0 → 10
        assert _percentile([10.0, 20.0], 50) == 10.0

    def test_percentile_p90_ten_items(self):
        vals = [float(i) for i in range(1, 11)]  # 1..10
        # p90: idx = max(0, int(10*90/100)-1) = max(0,8) = 8 → val=9
        assert _percentile(vals, 90) == 9.0

    def test_percentile_p99_returns_last(self):
        vals = [1.0, 2.0, 3.0]
        # p99: idx = max(0, int(3*99/100)-1) = max(0,1) = 1 → val=2.0
        result = _percentile(vals, 99)
        assert result == 2.0


# ─── _stat_block ─────────────────────────────────────────────────────────────

class TestStatBlock:
    def test_empty_list_all_none(self):
        b = _stat_block([])
        assert b["count"] == 0
        assert b["avg_seconds"] is None
        assert b["avg_minutes"] is None
        assert b["p50_seconds"] is None
        assert b["p90_seconds"] is None
        assert b["p99_seconds"] is None

    def test_single_value(self):
        b = _stat_block([120.0])
        assert b["count"] == 1
        assert b["avg_seconds"] == 120.0
        assert b["avg_minutes"] == 2.0
        assert b["p50_seconds"] == 120.0

    def test_sla_all_compliant(self):
        b = _stat_block([60.0, 120.0], sla_seconds=300.0)
        assert b["sla_compliant_count"] == 2
        assert b["sla_compliant_pct"] == 100.0

    def test_sla_none_compliant(self):
        b = _stat_block([600.0, 900.0], sla_seconds=300.0)
        assert b["sla_compliant_count"] == 0
        assert b["sla_compliant_pct"] == 0.0

    def test_sla_partial_compliance(self):
        b = _stat_block([100.0, 200.0, 600.0], sla_seconds=300.0)
        assert b["sla_compliant_count"] == 2
        assert abs(b["sla_compliant_pct"] - 66.7) < 0.1

    def test_no_sla_key_when_threshold_none(self):
        b = _stat_block([100.0])
        assert "sla_compliant_pct" not in b
        assert "sla_threshold_seconds" not in b

    def test_avg_minutes_precision(self):
        b = _stat_block([90.0])   # 1.5 minutes
        assert b["avg_minutes"] == 1.5

    def test_multiple_values_avg(self):
        b = _stat_block([60.0, 180.0])   # avg = 120s = 2m
        assert b["avg_seconds"] == 120.0
        assert b["avg_minutes"] == 2.0


# ─── calculate_mttd ──────────────────────────────────────────────────────────

class TestMTTD:
    def test_empty_alerts(self):
        result = calculate_mttd([])
        assert result["count"] == 0
        assert result["avg_seconds"] is None

    def test_alert_without_threat_start_skipped(self):
        a = _alert(threat_start_offset_m=None)
        result = calculate_mttd([a])
        assert result["count"] == 0

    def test_single_alert_30min_mttd(self):
        a = _alert(threat_start_offset_m=30)  # threat 30m before detection
        result = calculate_mttd([a])
        assert result["count"] == 1
        assert result["avg_seconds"] == 1800.0
        assert result["avg_minutes"] == 30.0

    def test_two_alerts_average(self):
        a1 = _alert(threat_start_offset_m=60)   # 1h = 3600s
        a2 = _alert(threat_start_offset_m=30)   # 30m = 1800s
        result = calculate_mttd([a1, a2])
        assert result["count"] == 2
        assert result["avg_seconds"] == 2700.0   # avg(3600, 1800)

    def test_sla_threshold_present(self):
        a = _alert(threat_start_offset_m=30)
        result = calculate_mttd([a])
        assert result["sla_threshold_seconds"] == MTTD_SLA_SECONDS

    def test_within_sla_1h(self):
        a = _alert(threat_start_offset_m=30)   # 1800s < 3600s SLA
        result = calculate_mttd([a])
        assert result["sla_compliant_count"] == 1

    def test_exceeds_sla_1h(self):
        a = _alert(threat_start_offset_m=120)  # 7200s > 3600s SLA
        result = calculate_mttd([a])
        assert result["sla_compliant_count"] == 0

    def test_mixed_alerts_some_with_threat_start(self):
        a1 = _alert(threat_start_offset_m=45)
        a2 = _alert(threat_start_offset_m=None)   # no threat_start → skipped
        result = calculate_mttd([a1, a2])
        assert result["count"] == 1

    def test_percentiles_present(self):
        alerts = [_alert(threat_start_offset_m=i * 10) for i in range(1, 11)]
        result = calculate_mttd(alerts)
        assert result["p50_seconds"] is not None
        assert result["p90_seconds"] is not None
        assert result["p90_seconds"] >= result["p50_seconds"]


# ─── calculate_mtta ──────────────────────────────────────────────────────────

class TestMTTA:
    def test_empty_alerts(self):
        result = calculate_mtta([])
        assert result["count"] == 0

    def test_unacknowledged_alerts_skipped(self):
        a = _alert(ack_offset_m=None)
        result = calculate_mtta([a])
        assert result["count"] == 0

    def test_single_alert_10min_ack(self):
        a = _alert(ack_offset_m=10)
        result = calculate_mtta([a])
        assert result["count"] == 1
        assert result["avg_seconds"] == 600.0
        assert result["avg_minutes"] == 10.0

    def test_sla_15min_compliant(self):
        a = _alert(ack_offset_m=10)   # 600s < 900s SLA
        result = calculate_mtta([a])
        assert result["sla_compliant_count"] == 1

    def test_sla_15min_breach(self):
        a = _alert(ack_offset_m=20)   # 1200s > 900s SLA
        result = calculate_mtta([a])
        assert result["sla_compliant_count"] == 0

    def test_mixed_ack_unack(self):
        a1 = _alert(ack_offset_m=5)
        a2 = _alert(ack_offset_m=None)
        result = calculate_mtta([a1, a2])
        assert result["count"] == 1

    def test_sla_threshold_is_900(self):
        result = calculate_mtta([_alert(ack_offset_m=5)])
        assert result["sla_threshold_seconds"] == MTTA_SLA_SECONDS
        assert MTTA_SLA_SECONDS == 900.0


# ─── calculate_mttr ──────────────────────────────────────────────────────────

class TestMTTR:
    def test_empty_alerts(self):
        result = calculate_mttr([])
        assert result["count"] == 0
        assert result["avg_seconds"] is None

    def test_unresolved_alerts_skipped(self):
        a = _alert(resolved_offset_m=None)
        result = calculate_mttr([a])
        assert result["count"] == 0

    def test_single_resolved_alert_2h(self):
        a = _alert(resolved_offset_m=120)   # 120 min = 7200s
        result = calculate_mttr([a])
        assert result["count"] == 1
        assert result["avg_seconds"] == 7200.0
        assert result["avg_minutes"] == 120.0

    def test_sla_4h_compliant(self):
        a = _alert(resolved_offset_m=120)   # 7200s < 14400s SLA
        result = calculate_mttr([a])
        assert result["sla_compliant_count"] == 1

    def test_sla_4h_breach(self):
        a = _alert(resolved_offset_m=300)   # 18000s > 14400s SLA
        result = calculate_mttr([a])
        assert result["sla_compliant_count"] == 0

    def test_two_resolved_avg(self):
        a1 = _alert(resolved_offset_m=60)    # 3600s
        a2 = _alert(resolved_offset_m=120)   # 7200s
        result = calculate_mttr([a1, a2])
        assert result["avg_seconds"] == 5400.0

    def test_resolved_and_unresolved_mixed(self):
        a1 = _alert(resolved_offset_m=60)
        a2 = _alert(resolved_offset_m=None)
        result = calculate_mttr([a1, a2])
        assert result["count"] == 1

    def test_percentile_shape(self):
        alerts = [_alert(resolved_offset_m=i * 30) for i in range(1, 11)]
        result = calculate_mttr(alerts)
        assert result["p99_seconds"] >= result["p90_seconds"] >= result["p50_seconds"]


# ─── calculate_mttr_respond ──────────────────────────────────────────────────

class TestMTTRRespond:
    def test_empty(self):
        result = calculate_mttr_respond([])
        assert result["count"] == 0

    def test_no_ack_skipped(self):
        a = _alert(ack_offset_m=None, resolved_offset_m=60)
        result = calculate_mttr_respond([a])
        assert result["count"] == 0

    def test_no_resolved_skipped(self):
        a = _alert(ack_offset_m=10, resolved_offset_m=None)
        result = calculate_mttr_respond([a])
        assert result["count"] == 0

    def test_ack_15min_resolved_90min_means_75min_respond(self):
        # ack_offset = 15min after detected, resolved_offset = 90min after detected
        # respond = 90 - 15 = 75 min = 4500s
        a = _alert(ack_offset_m=15, resolved_offset_m=90)
        result = calculate_mttr_respond([a])
        assert result["count"] == 1
        assert result["avg_seconds"] == 4500.0

    def test_multiple_respond_times(self):
        a1 = _alert(ack_offset_m=10, resolved_offset_m=70)   # 60m = 3600s
        a2 = _alert(ack_offset_m=5, resolved_offset_m=125)   # 120m = 7200s
        result = calculate_mttr_respond([a1, a2])
        assert result["avg_seconds"] == 5400.0


# ─── Negative delta skip ──────────────────────────────────────────────────────

class TestNegativeDeltaSkip:
    """Data integrity: if timestamps are inverted, skip the alert rather than corrupt stats."""

    def _alert_with_inverted_ts(self) -> SimpleNamespace:
        now = datetime.now(timezone.utc)
        return SimpleNamespace(
            id=str(uuid.uuid4()),
            severity="high",
            status="resolved",
            risk_score=0.8,
            false_positive=False,
            # threat_start AFTER detected (data corruption)
            threat_start_at=now + timedelta(hours=1),
            detected_at=now,
            # acknowledged BEFORE detected
            acknowledged_at=now - timedelta(minutes=5),
            # resolved BEFORE detected
            resolved_at=now - timedelta(hours=1),
        )

    def test_inverted_mttd_skipped(self):
        a = self._alert_with_inverted_ts()
        assert calculate_mttd([a])["count"] == 0

    def test_inverted_mtta_skipped(self):
        a = self._alert_with_inverted_ts()
        assert calculate_mtta([a])["count"] == 0

    def test_inverted_mttr_skipped(self):
        a = self._alert_with_inverted_ts()
        assert calculate_mttr([a])["count"] == 0


# ─── Breakdown by severity ────────────────────────────────────────────────────

class TestBreakdownBySeverity:
    def test_all_severities_present(self):
        alerts = [_alert(severity=s) for s in ["critical", "high", "medium", "low"]]
        result = breakdown_by_severity(alerts, calculate_mttr)
        assert set(result.keys()) == {"critical", "high", "medium", "low"}

    def test_empty_bucket_has_zero_count(self):
        # Only critical alert
        result = breakdown_by_severity([_alert(severity="critical")], calculate_mttr)
        assert result["high"]["count"] == 0
        assert result["medium"]["count"] == 0
        assert result["low"]["count"] == 0

    def test_correct_bucketing(self):
        alerts = [
            _alert(severity="critical", resolved_offset_m=60),
            _alert(severity="critical", resolved_offset_m=120),
            _alert(severity="high", resolved_offset_m=30),
        ]
        result = breakdown_by_severity(alerts, calculate_mttr)
        assert result["critical"]["count"] == 2
        assert result["high"]["count"] == 1

    def test_unknown_severity_ignored(self):
        a = _alert()
        a.severity = "unknown_xyz"
        result = breakdown_by_severity([a], calculate_mttr)
        # Not in any bucket
        assert all(result[s]["count"] == 0 for s in ["critical", "high", "medium", "low"])


# ─── Status funnel ────────────────────────────────────────────────────────────

class TestStatusFunnel:
    def test_empty_all_zeros(self):
        result = status_funnel([])
        assert all(v == 0 for v in result.values())

    def test_known_statuses(self):
        alerts = [
            _alert(status="open"),
            _alert(status="open"),
            _alert(status="investigating"),
            _alert(status="resolved"),
            _alert(status="false_positive"),
        ]
        result = status_funnel(alerts)
        assert result["open"] == 2
        assert result["investigating"] == 1
        assert result["resolved"] == 1
        assert result["false_positive"] == 1

    def test_unknown_status_goes_to_open(self):
        a = _alert()
        a.status = "custom_status"
        result = status_funnel([a])
        assert result["open"] == 1

    def test_contained_status(self):
        a = _alert(status="contained")
        result = status_funnel([a])
        assert result["contained"] == 1


# ─── Daily trend ─────────────────────────────────────────────────────────────

class TestDailyTrend:
    def test_returns_n_days(self):
        result = daily_mttr_trend([], days=7)
        assert len(result) == 7

    def test_returns_3_days(self):
        result = daily_mttr_trend([], days=3)
        assert len(result) == 3

    def test_ascending_dates(self):
        result = daily_mttr_trend([], days=5)
        dates = [r["date"] for r in result]
        assert dates == sorted(dates)

    def test_date_format(self):
        result = daily_mttr_trend([], days=1)
        assert len(result[0]["date"]) == 10   # YYYY-MM-DD

    def test_empty_days_have_none_mttr(self):
        result = daily_mttr_trend([], days=3)
        assert all(r["mttr_avg_m"] is None for r in result)

    def test_alert_appears_on_correct_day(self):
        # Alert detected exactly today
        a = _alert(resolved_offset_m=60)   # resolved 60 min after detection
        result = daily_mttr_trend([a], days=1)
        # The single day bucket should have this alert
        assert result[0]["count"] == 1
        assert result[0]["mttr_avg_m"] == 60.0

    def test_shape_keys(self):
        result = daily_mttr_trend([], days=1)
        assert "date" in result[0]
        assert "count" in result[0]
        assert "mttr_avg_m" in result[0]
        assert "mttr_p90_m" in result[0]


# ─── build_soc_summary ───────────────────────────────────────────────────────

class TestBuildSocSummary:
    def test_empty_all_none(self):
        result = build_soc_summary([])
        assert result["mttd_seconds"] is None
        assert result["mtta_seconds"] is None
        assert result["mttr_seconds"] is None

    def test_minutes_derived_from_seconds(self):
        a = _alert(threat_start_offset_m=60, ack_offset_m=10, resolved_offset_m=120)
        result = build_soc_summary([a])
        assert result["mttd_minutes"] == 60.0
        assert result["mtta_minutes"] == 10.0
        assert result["mttr_minutes"] == 120.0

    def test_keys_present(self):
        result = build_soc_summary([])
        expected_keys = [
            "mttd_seconds", "mttd_minutes",
            "mtta_seconds", "mtta_minutes",
            "mttr_seconds", "mttr_minutes",
        ]
        for k in expected_keys:
            assert k in result


# ─── SLA threshold constants ─────────────────────────────────────────────────

class TestSLAConstants:
    def test_mttd_sla_is_1_hour(self):
        assert MTTD_SLA_SECONDS == 3600.0

    def test_mtta_sla_is_15_minutes(self):
        assert MTTA_SLA_SECONDS == 900.0

    def test_mttr_sla_is_4_hours(self):
        assert MTTR_SLA_SECONDS == 14400.0


# ─── API integration tests ────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestMetricsSocAPI:
    async def test_soc_requires_auth(self, client: AsyncClient):
        resp = await client.get("/api/v1/metrics/soc")
        assert resp.status_code in (401, 403)

    async def test_soc_returns_200_with_auth(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        resp = await client.get("/api/v1/metrics/soc", headers=admin_headers)
        assert resp.status_code == 200

    async def test_soc_response_shape(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        resp = await client.get("/api/v1/metrics/soc", headers=admin_headers)
        data = resp.json()
        required = [
            "period_hours", "total_events", "total_alerts",
            "false_positive_rate", "ioc_coverage",
            "mttd_seconds", "mttd_minutes",
            "mtta_seconds", "mtta_minutes",
            "mttr_seconds", "mttr_minutes",
            "risk_posture", "by_severity", "by_status",
        ]
        for key in required:
            assert key in data, f"Missing key: {key}"

    async def test_soc_empty_db_sensible_defaults(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        resp = await client.get("/api/v1/metrics/soc", headers=admin_headers)
        data = resp.json()
        assert data["total_alerts"] == 0
        assert data["mttd_seconds"] is None
        assert data["mttr_seconds"] is None
        assert data["risk_posture"] == "NORMAL"

    async def test_soc_by_severity_has_all_levels(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        resp = await client.get("/api/v1/metrics/soc", headers=admin_headers)
        sev = resp.json()["by_severity"]
        assert "critical" in sev
        assert "high" in sev
        assert "medium" in sev
        assert "low" in sev

    async def test_soc_by_status_has_expected_keys(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        resp = await client.get("/api/v1/metrics/soc", headers=admin_headers)
        funnel = resp.json()["by_status"]
        assert "open" in funnel
        assert "investigating" in funnel
        assert "resolved" in funnel

    async def test_soc_hours_param_accepted(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        resp = await client.get("/api/v1/metrics/soc?hours=48", headers=admin_headers)
        assert resp.status_code == 200
        assert resp.json()["period_hours"] == 48

    async def test_soc_with_resolved_alert_calculates_mttr(
        self, client: AsyncClient, admin_user: User, admin_headers: dict, db
    ):
        from sqlalchemy.ext.asyncio import AsyncSession
        now = datetime.now(timezone.utc)
        alert = Alert(
            id=str(uuid.uuid4()),
            title="Test Alert",
            description="Test",
            severity="high",
            risk_score=0.8,
            detected_at=now - timedelta(hours=2),
            resolved_at=now,
        )
        db.add(alert)
        await db.commit()

        resp = await client.get("/api/v1/metrics/soc", headers=admin_headers)
        data = resp.json()
        assert data["mttr_seconds"] is not None
        # 2 hours = 7200s
        assert abs(data["mttr_seconds"] - 7200) < 5


@pytest.mark.asyncio
class TestMetricsPublicAPI:
    async def test_public_no_auth_required(self, client: AsyncClient):
        resp = await client.get("/api/v1/metrics/public")
        assert resp.status_code == 200

    async def test_public_response_shape(self, client: AsyncClient):
        resp = await client.get("/api/v1/metrics/public")
        data = resp.json()
        assert "mttd_minutes" in data
        assert "mtta_minutes" in data
        assert "mttr_minutes" in data
        assert "false_positive_rate" in data
        assert "ioc_coverage" in data
        assert "risk_posture" in data
        assert "period_hours" in data
        assert data["period_hours"] == 24

    async def test_public_empty_db(self, client: AsyncClient):
        resp = await client.get("/api/v1/metrics/public")
        data = resp.json()
        assert data["mttd_minutes"] is None
        assert data["mttr_minutes"] is None
        assert data["false_positive_rate"] == 0.0

    async def test_public_posture_normal_empty(self, client: AsyncClient):
        resp = await client.get("/api/v1/metrics/public")
        assert resp.json()["risk_posture"] == "NORMAL"

    async def test_public_posture_critical_with_critical_alert(self, client: AsyncClient, db):
        alert = Alert(
            id=str(uuid.uuid4()),
            title="Critical",
            description="critical test",
            severity="critical",
            risk_score=0.95,
            detected_at=datetime.now(timezone.utc),
        )
        db.add(alert)
        await db.commit()
        resp = await client.get("/api/v1/metrics/public")
        assert resp.json()["risk_posture"] == "CRITICAL"


@pytest.mark.asyncio
class TestMetricsPerformanceAPI:
    async def test_performance_requires_auth(self, client: AsyncClient):
        resp = await client.get("/api/v1/metrics/performance")
        assert resp.status_code in (401, 403)

    async def test_performance_200_with_auth(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        resp = await client.get("/api/v1/metrics/performance", headers=admin_headers)
        assert resp.status_code == 200

    async def test_performance_response_shape(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        resp = await client.get("/api/v1/metrics/performance", headers=admin_headers)
        data = resp.json()
        assert "mttd" in data
        assert "mtta" in data
        assert "mttr" in data
        assert "mttr_respond" in data
        assert "by_severity" in data
        assert "status_funnel" in data
        assert "daily_trend" in data
        assert "total_alerts" in data

    async def test_mttd_block_has_percentiles(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        resp = await client.get("/api/v1/metrics/performance", headers=admin_headers)
        mttd = resp.json()["mttd"]
        assert "p50_seconds" in mttd
        assert "p90_seconds" in mttd
        assert "p99_seconds" in mttd
        assert "sla_threshold_seconds" in mttd

    async def test_by_severity_has_all_levels(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        resp = await client.get("/api/v1/metrics/performance", headers=admin_headers)
        sev = resp.json()["by_severity"]
        for metric in ["mttd", "mtta", "mttr"]:
            assert metric in sev
            for level in ["critical", "high", "medium", "low"]:
                assert level in sev[metric]

    async def test_daily_trend_default_7_days(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        resp = await client.get("/api/v1/metrics/performance", headers=admin_headers)
        assert len(resp.json()["daily_trend"]) == 7

    async def test_daily_trend_custom_days(self, client: AsyncClient, admin_user: User, admin_headers: dict):
        resp = await client.get("/api/v1/metrics/performance?trend_days=3", headers=admin_headers)
        assert len(resp.json()["daily_trend"]) == 3

    async def test_performance_with_full_lifecycle_alert(
        self, client: AsyncClient, admin_user: User, admin_headers: dict, db
    ):
        now = datetime.now(timezone.utc)
        alert = Alert(
            id=str(uuid.uuid4()),
            title="Full lifecycle",
            description="MTTD+MTTA+MTTR test",
            severity="critical",
            risk_score=0.95,
            threat_start_at=now - timedelta(hours=3),
            detected_at=now - timedelta(hours=2),
            acknowledged_at=now - timedelta(hours=1, minutes=50),
            resolved_at=now,
        )
        db.add(alert)
        await db.commit()

        resp = await client.get("/api/v1/metrics/performance", headers=admin_headers)
        data = resp.json()

        # MTTD = 1h = 3600s
        assert abs(data["mttd"]["avg_seconds"] - 3600) < 5
        # MTTA = 10min = 600s
        assert abs(data["mtta"]["avg_seconds"] - 600) < 5
        # MTTR = 2h = 7200s
        assert abs(data["mttr"]["avg_seconds"] - 7200) < 5
        # MTTR_respond = 1h50min = 6600s
        assert abs(data["mttr_respond"]["avg_seconds"] - 6600) < 5


@pytest.mark.asyncio
class TestMetricsTimelineAPI:
    async def test_timeline_requires_auth(self, client: AsyncClient):
        resp = await client.get("/api/v1/metrics/timeline")
        assert resp.status_code in (401, 403)

    async def test_timeline_empty_db_returns_empty_list(
        self, client: AsyncClient, admin_user: User, admin_headers: dict
    ):
        resp = await client.get("/api/v1/metrics/timeline", headers=admin_headers)
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_timeline_bucket_shape(
        self, client: AsyncClient, admin_user: User, admin_headers: dict, db
    ):
        alert = Alert(
            id=str(uuid.uuid4()),
            title="T",
            description="Test",
            severity="high",
            risk_score=0.7,
            detected_at=datetime.now(timezone.utc),
        )
        db.add(alert)
        await db.commit()

        resp = await client.get("/api/v1/metrics/timeline", headers=admin_headers)
        data = resp.json()
        assert len(data) >= 1
        assert "timestamp" in data[0]
        assert "total" in data[0]
        assert "critical" in data[0]
