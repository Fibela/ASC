"""
SOC Metrics Calculation Service — MTTD, MTTA, MTTR, SLA Compliance

Definitions:
  MTTD         (Mean Time To Detect)      = detected_at     - threat_start_at
  MTTA         (Mean Time To Acknowledge) = acknowledged_at  - detected_at
  MTTR         (Mean Time To Respond)     = resolved_at      - detected_at
  MTTR_respond (Post-Ack Resolution Time) = resolved_at      - acknowledged_at

All functions accept sequences of Alert ORM objects and return plain dicts
(no DB access here — keep this layer pure and testable).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Callable, Sequence

from asc_api.models.alert import Alert

# ─── SLA thresholds (SOC standard defaults) ──────────────────────────────────

MTTD_SLA_SECONDS: float = 3_600.0  # 1 h
MTTA_SLA_SECONDS: float = 900.0  # 15 min
MTTR_SLA_SECONDS: float = 14_400.0  # 4 h


# ─── Low-level stat helpers ───────────────────────────────────────────────────


def _avg(values: list[float]) -> float | None:
    return sum(values) / len(values) if values else None


def _percentile(sorted_values: list[float], p: int) -> float:
    """Nearest-rank percentile from a pre-sorted list."""
    if not sorted_values:
        return 0.0
    idx = max(0, int(len(sorted_values) * p / 100) - 1)
    return sorted_values[idx]


def _stat_block(values: list[float], sla_seconds: float | None = None) -> dict:
    """
    Build a standardised statistics dict from a list of second-based durations.
    Includes count, avg, p50/p90/p99, and optional SLA compliance %.
    """
    s = sorted(values)
    avg = _avg(values)

    result: dict = {
        "count": len(values),
        "avg_seconds": round(avg, 1) if avg is not None else None,
        "avg_minutes": round(avg / 60, 2) if avg is not None else None,
        "p50_seconds": round(_percentile(s, 50), 1) if s else None,
        "p90_seconds": round(_percentile(s, 90), 1) if s else None,
        "p99_seconds": round(_percentile(s, 99), 1) if s else None,
    }

    if sla_seconds is not None:
        within = sum(1 for v in values if v <= sla_seconds)
        result["sla_threshold_seconds"] = sla_seconds
        result["sla_compliant_count"] = within
        result["sla_compliant_pct"] = round(within / len(values) * 100, 1) if values else None

    return result


# ─── Per-metric calculators ───────────────────────────────────────────────────


def calculate_mttd(alerts: Sequence[Alert]) -> dict:
    """
    MTTD = detected_at - threat_start_at.
    Only alerts with a non-None threat_start_at are included.
    Negative deltas (data integrity issue) are skipped.
    """
    deltas: list[float] = []
    for a in alerts:
        if a.threat_start_at and a.detected_at:
            delta = (a.detected_at - a.threat_start_at).total_seconds()
            if delta >= 0:
                deltas.append(delta)
    return _stat_block(deltas, MTTD_SLA_SECONDS)


def calculate_mtta(alerts: Sequence[Alert]) -> dict:
    """
    MTTA = acknowledged_at - detected_at.
    Only acknowledged alerts are included.
    """
    deltas: list[float] = []
    for a in alerts:
        if a.acknowledged_at and a.detected_at:
            delta = (a.acknowledged_at - a.detected_at).total_seconds()
            if delta >= 0:
                deltas.append(delta)
    return _stat_block(deltas, MTTA_SLA_SECONDS)


def calculate_mttr(alerts: Sequence[Alert]) -> dict:
    """
    MTTR = resolved_at - detected_at (total resolution time from detection).
    Only resolved alerts are included.
    """
    deltas: list[float] = []
    for a in alerts:
        if a.resolved_at and a.detected_at:
            delta = (a.resolved_at - a.detected_at).total_seconds()
            if delta >= 0:
                deltas.append(delta)
    return _stat_block(deltas, MTTR_SLA_SECONDS)


def calculate_mttr_respond(alerts: Sequence[Alert]) -> dict:
    """
    MTTR_respond = resolved_at - acknowledged_at.
    Pure response time after an analyst picks up the alert.
    Only alerts with both acknowledged_at and resolved_at are included.
    """
    deltas: list[float] = []
    for a in alerts:
        if a.acknowledged_at and a.resolved_at:
            delta = (a.resolved_at - a.acknowledged_at).total_seconds()
            if delta >= 0:
                deltas.append(delta)
    return _stat_block(deltas, MTTR_SLA_SECONDS)


# ─── Breakdown helpers ────────────────────────────────────────────────────────


def breakdown_by_severity(
    alerts: Sequence[Alert],
    metric_fn: Callable[[Sequence[Alert]], dict],
) -> dict[str, dict]:
    """Apply a metric function to each severity bucket."""
    buckets: dict[str, list[Alert]] = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
    }
    for a in alerts:
        if a.severity in buckets:
            buckets[a.severity].append(a)
    return {sev: metric_fn(alts) for sev, alts in buckets.items()}


def status_funnel(alerts: Sequence[Alert]) -> dict[str, int]:
    """Count alerts per status — shows the incident lifecycle pipeline."""
    funnel: dict[str, int] = {
        "open": 0,
        "investigating": 0,
        "contained": 0,
        "resolved": 0,
        "false_positive": 0,
    }
    for a in alerts:
        key = a.status if a.status in funnel else "open"
        funnel[key] += 1
    return funnel


def daily_mttr_trend(alerts: Sequence[Alert], days: int = 7) -> list[dict]:
    """
    MTTR broken down by calendar day for the past N days.
    Useful for trending charts in the frontend.
    """
    now = datetime.now(UTC)
    trend: list[dict] = []
    for i in range(days - 1, -1, -1):
        day_start = (now - timedelta(days=i)).replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1)
        day_alerts = [a for a in alerts if a.detected_at and day_start <= a.detected_at < day_end]
        mttr = calculate_mttr(day_alerts)
        trend.append(
            {
                "date": day_start.strftime("%Y-%m-%d"),
                "count": len(day_alerts),
                "mttr_avg_m": round(mttr["avg_seconds"] / 60, 1) if mttr["avg_seconds"] else None,
                "mttr_p90_m": round(mttr["p90_seconds"] / 60, 1) if mttr["p90_seconds"] else None,
            }
        )
    return trend


# ─── Combined window summary ─────────────────────────────────────────────────


def build_soc_summary(alerts: Sequence[Alert]) -> dict:
    """
    One-call helper used by /metrics/soc.
    Returns flat top-level numbers for KPI cards (backward-compatible).
    """
    mttd = calculate_mttd(alerts)
    mtta = calculate_mtta(alerts)
    mttr = calculate_mttr(alerts)

    return {
        "mttd_seconds": mttd["avg_seconds"],
        "mttd_minutes": mttd["avg_minutes"],
        "mtta_seconds": mtta["avg_seconds"],
        "mtta_minutes": mtta["avg_minutes"],
        "mttr_seconds": mttr["avg_seconds"],
        "mttr_minutes": mttr["avg_minutes"],
    }
