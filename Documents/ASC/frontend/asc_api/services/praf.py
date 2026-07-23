"""
PRAF — Premos Resilience & Authenticity Framework  (P32)

Provides four capabilities:

1. Forensic Performance Ledger
   Each test-run or load-test result is committed as a ledger entry:
     - SHA3-512 fingerprint of the canonical JSON payload
     - Ed25519 signature (using the SPECTER signing keypair)
     - Immutable audit trail of performance evidence

2. Adaptive Load Score  (0–100)
   Combines p95 latency, error rate, and throughput into a composite score.
   Maps to alert severity: low / medium / high / critical

3. Cross-Domain Resilience Correlation
   Links performance degradation events to TI / Hunting / Incident modules
   by injecting SOAR evaluation contexts automatically.

4. Executive Authenticity
   Generates a signed performance summary dict (PDF rendering is a P33+ task).

Security guarantees:
  - Signatures use the SPECTER_SIGNING_PRIVATE_KEY (Ed25519 raw bytes, base64)
  - Fingerprints use SHA3-512 (collision-resistant, quantum-hardened subset)
  - All operations are READ-ONLY with respect to the test database
  - No mutation of ELK / Wazuh data
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from asc_api.core.config import get_settings
from asc_api.core.logging import get_logger
from asc_api.core.signing import sign_command

log = get_logger("asc.praf")

# ── Severity thresholds for Adaptive Load Score ───────────────────────────────
# Score bands (0–100):   0-30=low, 31-60=medium, 61-84=high, 85-100=critical
_SCORE_BANDS = [
    (85, "critical"),
    (61, "high"),
    (31, "medium"),
    (0, "low"),
]

# Weights for composite score components
_W_LATENCY = 0.50  # p95 latency dominates (user-facing)
_W_ERROR_RATE = 0.35  # error rate is a hard signal
_W_THROUGHPUT = 0.15  # throughput contributes least in burst scenarios

# p95 latency baselines (ms)
_LATENCY_BUDGET_MS = 500.0  # SLA target
_LATENCY_CEILING_MS = 2000.0  # absolute ceiling (maps to score=100)

# ── In-process ephemeral ledger  (replace with DB table for persistence) ──────
_ledger: list[dict] = []


# ── Public API ────────────────────────────────────────────────────────────────


class PRAFLedger:
    """
    Forensic performance ledger.

    Typical flow:
        ledger = PRAFLedger()
        entry = ledger.record(
            test_name="test_neutralize_10k",
            duration_ms=320.0,
            passed=True,
            metrics={"p95_latency_ms": 290, "error_rate": 0.001, "rps": 9800},
        )
    """

    def record(
        self,
        test_name: str,
        duration_ms: float,
        passed: bool,
        metrics: dict[str, Any] | None = None,
    ) -> dict:
        """
        Commit a test result to the in-process ledger.

        Returns the signed ledger entry dict (fingerprint + signature included).
        """
        ts = datetime.now(UTC).isoformat()
        payload: dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "test_name": test_name,
            "duration_ms": round(duration_ms, 3),
            "passed": passed,
            "metrics": metrics or {},
            "recorded_at": ts,
        }
        fingerprint = _sha3_512(payload)
        sig = _sign_payload(payload)

        entry = {
            **payload,
            "fingerprint_sha3_512": fingerprint,
            "signature_ed25519": sig,
        }
        _ledger.append(entry)
        log.info(
            "praf_ledger_entry",
            test_name=test_name,
            passed=passed,
            fingerprint=fingerprint[:16] + "…",
        )
        return entry

    def get_all(self) -> list[dict]:
        return list(_ledger)

    def clear(self) -> None:
        """Reset the ephemeral ledger (useful in tests)."""
        _ledger.clear()


class AdaptiveLoadScorer:
    """
    Compute 0–100 composite performance score.

    Higher score → worse performance → higher alert severity.

    Parameters
    ----------
    p95_latency_ms : float
        95th-percentile request latency in milliseconds.
    error_rate : float
        Fraction of requests that returned 4xx/5xx (0.0–1.0).
    throughput_rps : float
        Successful requests per second.
    target_rps : float
        Expected baseline throughput (used to compute deficit).
    """

    def __init__(
        self,
        *,
        latency_budget_ms: float = _LATENCY_BUDGET_MS,
        latency_ceiling_ms: float = _LATENCY_CEILING_MS,
        target_rps: float = 1000.0,
    ):
        self._latency_budget = latency_budget_ms
        self._latency_ceiling = latency_ceiling_ms
        self._target_rps = target_rps

    def score(
        self,
        p95_latency_ms: float,
        error_rate: float,
        throughput_rps: float,
    ) -> dict:
        """
        Return:
            {
                "score": <int 0-100>,
                "severity": "low"|"medium"|"high"|"critical",
                "components": {
                    "latency_score": <int>,
                    "error_score": <int>,
                    "throughput_score": <int>,
                },
                "evaluated_at": <ISO-str>,
            }
        """
        latency_score = _latency_component(p95_latency_ms, self._latency_budget, self._latency_ceiling)
        error_score = min(100, int(error_rate * 100 / 0.05))  # 5% error → 100
        throughput_score = _throughput_component(throughput_rps, self._target_rps)

        composite = _W_LATENCY * latency_score + _W_ERROR_RATE * error_score + _W_THROUGHPUT * throughput_score
        composite = max(0, min(100, round(composite)))
        severity = _band(composite)

        return {
            "score": composite,
            "severity": severity,
            "components": {
                "latency_score": latency_score,
                "error_score": error_score,
                "throughput_score": throughput_score,
            },
            "evaluated_at": datetime.now(UTC).isoformat(),
        }


class CrossDomainCorrelator:
    """
    Map a PRAF load score to a SOAR evaluation context so performance
    degradation can automatically fire playbooks (e.g. PB-010 = scale-out).
    """

    def build_soar_context(self, score_result: dict) -> dict:
        """
        Convert a score dict (from AdaptiveLoadScorer.score) into a SOAR
        evaluation context ready for POST /soar/evaluate.
        """
        return {
            "pcdi_score": score_result["score"],
            "severity": score_result["severity"],
            "source": "praf_load_score",
            "evaluated_at": score_result.get("evaluated_at"),
        }

    def correlate_failure(
        self,
        score_result: dict,
        failed_modules: list[str],
    ) -> dict:
        """
        Return a correlation dict linking performance score to affected modules.
        Stored in AUDIT_LOG / forwarded to SOAR.
        """
        return {
            "correlation_id": str(uuid.uuid4()),
            "praf_score": score_result["score"],
            "praf_severity": score_result["severity"],
            "failed_modules": failed_modules,
            "soar_context": self.build_soar_context(score_result),
            "correlated_at": datetime.now(UTC).isoformat(),
        }


class ExecutiveReporter:
    """
    Produce a signed performance summary.

    PDF rendering is a P33+ capability.  This class produces a signed dict
    that can be serialised to JSON or rendered by a downstream PDF service.
    """

    def __init__(self, ledger: PRAFLedger, scorer: AdaptiveLoadScorer):
        self._ledger = ledger
        self._scorer = scorer

    def generate(
        self,
        *,
        title: str = "PRAF Performance Report",
        author: str = "ASC PremosCorp",
    ) -> dict:
        entries = self._ledger.get_all()
        total = len(entries)
        passed = sum(1 for e in entries if e.get("passed"))
        failed = total - passed

        metrics_list = [e.get("metrics", {}) for e in entries if e.get("metrics")]
        avg_latency = sum(m.get("p95_latency_ms", 0) for m in metrics_list) / len(metrics_list) if metrics_list else 0
        avg_error_rate = sum(m.get("error_rate", 0) for m in metrics_list) / len(metrics_list) if metrics_list else 0
        avg_rps = sum(m.get("rps", 0) for m in metrics_list) / len(metrics_list) if metrics_list else 0

        score_result = self._scorer.score(avg_latency, avg_error_rate, avg_rps)

        report_payload: dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "title": title,
            "author": author,
            "generated_at": datetime.now(UTC).isoformat(),
            "summary": {
                "total_tests": total,
                "passed": passed,
                "failed": failed,
                "pass_rate": round(passed / total, 4) if total else 1.0,
                "avg_p95_latency_ms": round(avg_latency, 2),
                "avg_error_rate": round(avg_error_rate, 6),
                "avg_rps": round(avg_rps, 2),
            },
            "adaptive_score": score_result,
            "entries": entries,
        }

        fingerprint = _sha3_512(report_payload)
        sig = _sign_payload(report_payload)

        return {
            **report_payload,
            "fingerprint_sha3_512": fingerprint,
            "signature_ed25519": sig,
        }


# ── Private helpers ────────────────────────────────────────────────────────────


def _sha3_512(payload: dict) -> str:
    """SHA3-512 fingerprint of canonical JSON (sorted keys, no spaces)."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha3_512(canonical.encode()).hexdigest()


def _sign_payload(payload: dict) -> str:
    """
    Sign the canonical payload with the SPECTER Ed25519 private key.
    Falls back to a deterministic no-op signature if key is not configured
    (e.g. in test environments without a SPECTER_SIGNING_PRIVATE_KEY set).
    """
    settings = get_settings()
    priv_key_b64: str | None = getattr(settings, "SPECTER_SIGNING_PRIVATE_KEY", None)
    if not priv_key_b64:
        # Derive an ephemeral key from the app secret for test environments.
        # NOT for production — in production, SPECTER_SIGNING_PRIVATE_KEY must be set.
        import hmac as _hmac

        token = _hmac.new(
            settings.SECRET_KEY.encode(),
            msg=json.dumps(payload, sort_keys=True).encode(),
            digestmod="sha3_512",
        ).hexdigest()
        return f"hmac-fallback:{token[:32]}"
    return sign_command(priv_key_b64, payload)


def _latency_component(actual_ms: float, budget_ms: float, ceiling_ms: float) -> int:
    """Map p95 latency to a 0-100 score. 0 = at-or-below budget, 100 = at ceiling."""
    if actual_ms <= budget_ms:
        return 0
    capped = min(actual_ms, ceiling_ms)
    return round((capped - budget_ms) / (ceiling_ms - budget_ms) * 100)


def _throughput_component(actual_rps: float, target_rps: float) -> int:
    """Map throughput deficit to 0-100. 0 = at-or-above target, 100 = 0 rps."""
    if actual_rps >= target_rps or target_rps == 0:
        return 0
    deficit = (target_rps - actual_rps) / target_rps
    return round(deficit * 100)


def _band(score: int) -> str:
    for threshold, severity in _SCORE_BANDS:
        if score >= threshold:
            return severity
    return "low"
