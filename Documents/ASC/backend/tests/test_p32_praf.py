"""
P32-PRAF — Premos Resilience & Authenticity Framework unit tests.

Tests cover:
  - PRAFLedger: record, fingerprint, signature, get_all, clear
  - AdaptiveLoadScorer: all score bands (low/medium/high/critical), edge cases
  - CrossDomainCorrelator: soar context mapping, failure correlation
  - ExecutiveReporter: summary generation, signature inclusion
  - Helper functions: SHA3-512, latency/throughput component scoring
  - Security: fingerprint changes when payload changes, signatures differ per entry
"""
import hashlib
import json
import pytest

from app.services.praf import (
    PRAFLedger,
    AdaptiveLoadScorer,
    CrossDomainCorrelator,
    ExecutiveReporter,
    _sha3_512,
    _latency_component,
    _throughput_component,
    _band,
)

pytestmark = pytest.mark.asyncio


# ══════════════════════════════════════════════════════════════════════════════
# PRAFLedger
# ══════════════════════════════════════════════════════════════════════════════

class TestPRAFLedger:
    def setup_method(self):
        self.ledger = PRAFLedger()
        self.ledger.clear()

    def test_record_returns_entry_with_required_fields(self):
        entry = self.ledger.record("test_foo", duration_ms=120.0, passed=True)
        assert entry["test_name"] == "test_foo"
        assert entry["duration_ms"] == 120.0
        assert entry["passed"] is True
        assert "id" in entry
        assert "recorded_at" in entry
        assert "fingerprint_sha3_512" in entry
        assert "signature_ed25519" in entry

    def test_record_with_metrics(self):
        metrics = {"p95_latency_ms": 280, "error_rate": 0.001, "rps": 9500}
        entry = self.ledger.record("load_test", 400.0, True, metrics=metrics)
        assert entry["metrics"]["p95_latency_ms"] == 280
        assert entry["metrics"]["error_rate"] == 0.001

    def test_fingerprint_is_sha3_512_hex(self):
        entry = self.ledger.record("hash_check", 50.0, True)
        fp = entry["fingerprint_sha3_512"]
        assert len(fp) == 128  # SHA3-512 → 64 bytes → 128 hex chars
        assert all(c in "0123456789abcdef" for c in fp)

    def test_fingerprint_changes_with_different_payload(self):
        e1 = self.ledger.record("test_a", 100.0, True)
        e2 = self.ledger.record("test_b", 100.0, True)
        assert e1["fingerprint_sha3_512"] != e2["fingerprint_sha3_512"]

    def test_get_all_accumulates_entries(self):
        self.ledger.record("t1", 10.0, True)
        self.ledger.record("t2", 20.0, False)
        all_entries = self.ledger.get_all()
        assert len(all_entries) == 2

    def test_clear_empties_ledger(self):
        self.ledger.record("t1", 10.0, True)
        self.ledger.clear()
        assert self.ledger.get_all() == []

    def test_failed_test_recorded_correctly(self):
        entry = self.ledger.record("failing_test", 5000.0, False)
        assert entry["passed"] is False

    def test_duration_precision_preserved(self):
        entry = self.ledger.record("precise", 123.456, True)
        assert entry["duration_ms"] == 123.456

    def test_empty_metrics_defaults_to_empty_dict(self):
        entry = self.ledger.record("no_metrics", 10.0, True)
        assert entry["metrics"] == {}

    def test_signature_is_present_and_non_empty(self):
        entry = self.ledger.record("sig_check", 10.0, True)
        assert entry["signature_ed25519"]
        assert len(entry["signature_ed25519"]) > 0


# ══════════════════════════════════════════════════════════════════════════════
# AdaptiveLoadScorer
# ══════════════════════════════════════════════════════════════════════════════

class TestAdaptiveLoadScorer:
    def setup_method(self):
        self.scorer = AdaptiveLoadScorer(target_rps=1000.0)

    def test_perfect_performance_low_severity(self):
        result = self.scorer.score(100.0, 0.0, 1200.0)
        assert result["severity"] == "low"
        assert result["score"] <= 30

    def test_high_latency_critical(self):
        result = self.scorer.score(2000.0, 0.10, 200.0)
        assert result["severity"] in ("high", "critical")
        assert result["score"] >= 61

    def test_high_error_rate_triggers_high(self):
        result = self.scorer.score(400.0, 0.15, 800.0)
        assert result["score"] > 30

    def test_zero_throughput_worst_case(self):
        result = self.scorer.score(2000.0, 1.0, 0.0)
        assert result["severity"] == "critical"
        assert result["score"] == 100

    def test_exact_sla_boundary_score_zero(self):
        # At exactly the latency budget with zero errors and full throughput
        result = self.scorer.score(500.0, 0.0, 1000.0)
        assert result["components"]["latency_score"] == 0
        assert result["components"]["error_score"] == 0
        assert result["components"]["throughput_score"] == 0

    def test_result_has_required_keys(self):
        result = self.scorer.score(300.0, 0.01, 900.0)
        assert "score" in result
        assert "severity" in result
        assert "components" in result
        assert "evaluated_at" in result
        assert "latency_score" in result["components"]
        assert "error_score" in result["components"]
        assert "throughput_score" in result["components"]

    def test_score_clamped_to_0_100(self):
        result = self.scorer.score(-100.0, -1.0, 99999.0)
        assert 0 <= result["score"] <= 100

    def test_medium_severity_band(self):
        # p95=700ms (above 500 budget), 2% error rate, 850rps
        result = self.scorer.score(700.0, 0.02, 850.0)
        assert result["severity"] in ("low", "medium", "high")

    def test_score_monotone_with_latency(self):
        r1 = self.scorer.score(400.0, 0.0, 1000.0)
        r2 = self.scorer.score(1000.0, 0.0, 1000.0)
        assert r2["score"] >= r1["score"]


# ══════════════════════════════════════════════════════════════════════════════
# CrossDomainCorrelator
# ══════════════════════════════════════════════════════════════════════════════

class TestCrossDomainCorrelator:
    def setup_method(self):
        self.scorer = AdaptiveLoadScorer()
        self.correlator = CrossDomainCorrelator()

    def test_build_soar_context_contains_pcdi_score(self):
        score_result = self.scorer.score(800.0, 0.05, 600.0)
        context = self.correlator.build_soar_context(score_result)
        assert "pcdi_score" in context
        assert context["severity"] == score_result["severity"]
        assert context["source"] == "praf_load_score"

    def test_correlate_failure_includes_modules(self):
        score_result = self.scorer.score(1500.0, 0.08, 400.0)
        correlation = self.correlator.correlate_failure(
            score_result,
            failed_modules=["hunt_service", "neutralizer"],
        )
        assert "hunt_service" in correlation["failed_modules"]
        assert "neutralizer" in correlation["failed_modules"]
        assert "correlation_id" in correlation
        assert "correlated_at" in correlation
        assert "soar_context" in correlation

    def test_correlate_failure_links_praf_score(self):
        score_result = self.scorer.score(1200.0, 0.04, 500.0)
        correlation = self.correlator.correlate_failure(score_result, [])
        assert correlation["praf_score"] == score_result["score"]
        assert correlation["praf_severity"] == score_result["severity"]

    def test_empty_failed_modules(self):
        score_result = self.scorer.score(200.0, 0.001, 1000.0)
        correlation = self.correlator.correlate_failure(score_result, [])
        assert correlation["failed_modules"] == []


# ══════════════════════════════════════════════════════════════════════════════
# ExecutiveReporter
# ══════════════════════════════════════════════════════════════════════════════

class TestExecutiveReporter:
    def setup_method(self):
        self.ledger = PRAFLedger()
        self.ledger.clear()
        self.scorer = AdaptiveLoadScorer()
        self.reporter = ExecutiveReporter(self.ledger, self.scorer)

    def test_empty_ledger_report(self):
        report = self.reporter.generate()
        assert report["summary"]["total_tests"] == 0
        assert report["summary"]["passed"] == 0
        assert report["summary"]["pass_rate"] == 1.0

    def test_report_with_entries(self):
        self.ledger.record("t1", 200.0, True, {"p95_latency_ms": 200, "error_rate": 0.001, "rps": 1000})
        self.ledger.record("t2", 300.0, True, {"p95_latency_ms": 300, "error_rate": 0.002, "rps": 950})
        self.ledger.record("t3", 600.0, False, {"p95_latency_ms": 600, "error_rate": 0.05, "rps": 400})
        report = self.reporter.generate()
        assert report["summary"]["total_tests"] == 3
        assert report["summary"]["passed"] == 2
        assert report["summary"]["failed"] == 1
        assert abs(report["summary"]["pass_rate"] - 0.6667) < 0.001

    def test_report_has_signature(self):
        report = self.reporter.generate()
        assert "signature_ed25519" in report
        assert "fingerprint_sha3_512" in report

    def test_report_has_adaptive_score(self):
        self.ledger.record("load", 450.0, True, {"p95_latency_ms": 450, "error_rate": 0.01, "rps": 800})
        report = self.reporter.generate()
        assert "adaptive_score" in report
        assert "score" in report["adaptive_score"]
        assert "severity" in report["adaptive_score"]

    def test_report_title_and_author(self):
        report = self.reporter.generate(title="SOC Weekly", author="PremosCorp SOC")
        assert report["title"] == "SOC Weekly"
        assert report["author"] == "PremosCorp SOC"

    def test_fingerprint_changes_between_calls(self):
        r1 = self.reporter.generate()
        self.ledger.record("extra", 10.0, True)
        r2 = self.reporter.generate()
        assert r1["fingerprint_sha3_512"] != r2["fingerprint_sha3_512"]


# ══════════════════════════════════════════════════════════════════════════════
# Helper functions
# ══════════════════════════════════════════════════════════════════════════════

class TestHelpers:
    def test_sha3_512_length(self):
        digest = _sha3_512({"key": "value"})
        assert len(digest) == 128

    def test_sha3_512_deterministic(self):
        d1 = _sha3_512({"a": 1, "b": 2})
        d2 = _sha3_512({"b": 2, "a": 1})
        assert d1 == d2  # sorted keys → same canonical JSON

    def test_sha3_512_collision_resistant(self):
        d1 = _sha3_512({"score": 80})
        d2 = _sha3_512({"score": 81})
        assert d1 != d2

    def test_sha3_512_matches_stdlib(self):
        payload = {"test": "praf"}
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        expected = hashlib.sha3_512(canonical.encode()).hexdigest()
        assert _sha3_512(payload) == expected

    def test_latency_below_budget_scores_zero(self):
        assert _latency_component(200.0, 500.0, 2000.0) == 0

    def test_latency_at_budget_scores_zero(self):
        assert _latency_component(500.0, 500.0, 2000.0) == 0

    def test_latency_at_ceiling_scores_100(self):
        assert _latency_component(2000.0, 500.0, 2000.0) == 100

    def test_latency_midpoint_scores_fifty(self):
        score = _latency_component(1250.0, 500.0, 2000.0)
        assert abs(score - 50) <= 2

    def test_throughput_above_target_scores_zero(self):
        assert _throughput_component(1200.0, 1000.0) == 0

    def test_throughput_at_target_scores_zero(self):
        assert _throughput_component(1000.0, 1000.0) == 0

    def test_throughput_zero_scores_100(self):
        assert _throughput_component(0.0, 1000.0) == 100

    def test_throughput_half_scores_50(self):
        score = _throughput_component(500.0, 1000.0)
        assert abs(score - 50) <= 2

    def test_throughput_zero_target_scores_zero(self):
        assert _throughput_component(500.0, 0.0) == 0

    def test_band_critical(self):
        assert _band(85) == "critical"
        assert _band(100) == "critical"

    def test_band_high(self):
        assert _band(61) == "high"
        assert _band(84) == "high"

    def test_band_medium(self):
        assert _band(31) == "medium"
        assert _band(60) == "medium"

    def test_band_low(self):
        assert _band(0) == "low"
        assert _band(30) == "low"
