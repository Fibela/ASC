"""
ASC Prometheus Metrics Registry — P39

Single CollectorRegistry (not the default global one) to avoid
ValueError: Duplicated timeseries in test environments where the app
module is imported multiple times.

Metrics are recorded by:
  • RequestContextMiddleware  — HTTP counters + latency histograms
  • /api/v1/observability/metrics endpoint  — gauge snapshots from DB
"""

from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
    CONTENT_TYPE_LATEST,
)

# Re-export so callers don't need a second import
__all__ = [
    "REGISTRY",
    "HTTP_REQUESTS",
    "HTTP_DURATION",
    "ALERTS_GAUGE",
    "EVENTS_GAUGE",
    "AGENTS_GAUGE",
    "CONTENT_TYPE_LATEST",
    "generate_latest",
]

REGISTRY = CollectorRegistry(auto_describe=True)

# ── HTTP layer ────────────────────────────────────────────────────────────────

HTTP_REQUESTS = Counter(
    "asc_http_requests_total",
    "Total HTTP requests processed by the ASC backend",
    ["method", "endpoint", "status_code"],
    registry=REGISTRY,
)

HTTP_DURATION = Histogram(
    "asc_http_request_duration_seconds",
    "HTTP request latency in seconds",
    ["method", "endpoint"],
    # SLO-aligned buckets: 10ms, 25ms, 50ms, 100ms, 250ms, 500ms (p95 target), 1s, 2.5s, 5s
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
    registry=REGISTRY,
)

# ── Application-level gauges (refreshed on each scrape) ──────────────────────

ALERTS_GAUGE = Gauge(
    "asc_alerts_total",
    "Total number of alerts currently in the database",
    registry=REGISTRY,
)

EVENTS_GAUGE = Gauge(
    "asc_events_total",
    "Total number of events currently in the database",
    registry=REGISTRY,
)

AGENTS_GAUGE = Gauge(
    "asc_agents_active",
    "SPECTER agents with a heartbeat in the last 5 minutes",
    registry=REGISTRY,
)

PROCESS_CPU_GAUGE = Gauge(
    "asc_process_cpu_percent",
    "Process CPU usage percentage (rolling 1s average)",
    registry=REGISTRY,
)

PROCESS_MEMORY_BYTES = Gauge(
    "asc_process_memory_bytes",
    "Process RSS memory usage in bytes",
    registry=REGISTRY,
)


def _normalize_path(path: str) -> str:
    """
    Collapse parameterized path segments to avoid high-cardinality labels.
    /api/v1/agents/abc-uuid  →  /api/v1/agents
    /health                  →  /health

    Keeps the first 3 meaningful segments (after stripping /api/v1 prefix).
    """
    parts = [p for p in path.split("/") if p]
    # Strip 'api' and 'v1' prefix when present
    if len(parts) >= 2 and parts[0] == "api" and parts[1].startswith("v"):
        parts = parts[2:]
    # Keep only the first segment (endpoint family)
    endpoint = "/" + parts[0] if parts else "/"
    return endpoint
