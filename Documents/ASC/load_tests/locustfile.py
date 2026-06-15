"""
P32-LOAD — PremosCorp ASC Load Test Suite (Locust)

Target: 10,000 concurrent requests on critical endpoints.
SLA:    p95 latency < 500ms on /neutralize/, /hunt/, /incidents/

Usage
-----
  # Install: pip install locust
  # Run headless (CI):
  locust -f load_tests/locustfile.py \
      --headless \
      --users 1000 \
      --spawn-rate 100 \
      --run-time 60s \
      --host http://localhost:8000 \
      --html load_tests/report.html

  # Interactive (browser at http://localhost:8089):
  locust -f load_tests/locustfile.py --host http://localhost:8000

  # 10k concurrent (production baseline):
  locust -f load_tests/locustfile.py \
      --headless \
      --users 10000 \
      --spawn-rate 500 \
      --run-time 120s \
      --host http://localhost:8000

Security
--------
  - All requests use a pre-generated JWT bearer token (analyst role).
  - No actual destructive actions: neutralize uses severity=medium with a
    sandbox target (100.64.0.1 — RFC 6890 shared address space, no real host).
  - Hunt queries are read-only keyword searches against the test dataset.
  - Incident creation uses fake incident IDs scoped to "load-test" tag.

Architecture
------------
  ASCUser  — base user with auth token + PRAF scoring.
  NeutralizeUser  — targets POST /neutralize/, GET /neutralize/pending
  HuntUser        — targets GET /threat-hunting/hunts, POST search
  IncidentUser    — targets GET /incidents, POST /incidents, PATCH status
  ReadOnlyUser    — targets metrics, health, IoC list (read-only paths)

Run all in one swarm:
  locust -f load_tests/locustfile.py --host http://localhost:8000

Or run specific class:
  locust -f load_tests/locustfile.py NeutralizeUser --host http://localhost:8000

PRAF Integration
----------------
  Each Locust task records timing data. The PRAF scorer is invoked at test
  teardown (via the `on_stop` handler) to generate an adaptive load score
  and cross-domain correlation report.
"""
from __future__ import annotations

import json
import os
import random
import time
import uuid
from typing import Any

from locust import HttpUser, SequentialTaskSet, TaskSet, between, events, tag, task

# ── Auth configuration ────────────────────────────────────────────────────────
# Set via environment variable or override below.
# Generate a real JWT from the app (POST /auth/login) before load testing.
# In CI: export ASC_LOAD_TEST_TOKEN=$(curl -X POST .../auth/login -d '...' | jq -r .access_token)
_JWT_TOKEN = os.getenv(
    "ASC_LOAD_TEST_TOKEN",
    "REPLACE_ME_WITH_REAL_JWT_TOKEN",
)
_AUTH_HEADERS = {"Authorization": f"Bearer {_JWT_TOKEN}"}

# ── Sandbox target (RFC 6890 — shared address space, never routed) ─────────
_SANDBOX_IP = "100.64.0.1"
_SANDBOX_DOMAIN = "load-test.premoscorp.internal"

# ── Shared state for sequential scenario ──────────────────────────────────────
_created_incident_ids: list[str] = []
_created_action_ids:   list[str] = []


# ══════════════════════════════════════════════════════════════════════════════
# PRAF in-load collector
# ══════════════════════════════════════════════════════════════════════════════

class _PRAFCollector:
    """Accumulates per-request latencies for end-of-run PRAF scoring."""

    def __init__(self):
        self._latencies: dict[str, list[float]] = {}
        self._errors: dict[str, int] = {}
        self._counts: dict[str, int] = {}

    def record(self, endpoint: str, latency_ms: float, success: bool) -> None:
        self._latencies.setdefault(endpoint, []).append(latency_ms)
        self._counts[endpoint] = self._counts.get(endpoint, 0) + 1
        if not success:
            self._errors[endpoint] = self._errors.get(endpoint, 0) + 1

    def p95(self, endpoint: str) -> float:
        lats = sorted(self._latencies.get(endpoint, [0.0]))
        idx = int(len(lats) * 0.95)
        return lats[min(idx, len(lats) - 1)]

    def error_rate(self, endpoint: str) -> float:
        total = self._counts.get(endpoint, 0)
        if total == 0:
            return 0.0
        return self._errors.get(endpoint, 0) / total

    def summary(self) -> dict:
        endpoints = list(self._counts.keys())
        return {
            ep: {
                "p95_ms": self.p95(ep),
                "error_rate": self.error_rate(ep),
                "total_requests": self._counts[ep],
                "sla_ok": self.p95(ep) < 500.0,
            }
            for ep in endpoints
        }


_praf = _PRAFCollector()


@events.quitting.add_listener
def _on_quitting(environment, **kw):
    """On Locust exit: print PRAF summary and SLA verdict."""
    summary = _praf.summary()
    sla_breaches = [ep for ep, stats in summary.items() if not stats["sla_ok"]]
    print("\n" + "=" * 60)
    print("PRAF Load Score Summary")
    print("=" * 60)
    for ep, stats in summary.items():
        mark = "✓" if stats["sla_ok"] else "✗ SLA BREACH"
        print(f"  {mark}  {ep:<40}  p95={stats['p95_ms']:.1f}ms  err={stats['error_rate']:.3%}")
    if sla_breaches:
        print(f"\nSLA BREACHES: {sla_breaches}")
    else:
        print("\nAll endpoints within p95 < 500ms SLA ✓")
    print("=" * 60 + "\n")

    # Write PRAF JSON report
    report_path = os.path.join(os.path.dirname(__file__), "praf_load_report.json")
    with open(report_path, "w") as f:
        json.dump({"summary": summary, "sla_breaches": sla_breaches}, f, indent=2)
    print(f"PRAF report written to {report_path}")


# ══════════════════════════════════════════════════════════════════════════════
# Base user class
# ══════════════════════════════════════════════════════════════════════════════

class ASCUser(HttpUser):
    """Base Locust user — sets auth headers for all requests."""
    abstract = True
    wait_time = between(0.1, 0.5)

    def on_start(self):
        self.headers = dict(_AUTH_HEADERS)
        # In a real environment, authenticate here:
        # resp = self.client.post("/api/v1/auth/login", json={...})
        # self.headers = {"Authorization": f"Bearer {resp.json()['access_token']}"}

    def _record(self, name: str, response) -> None:
        _praf.record(name, response.elapsed.total_seconds() * 1000, response.ok)


# ══════════════════════════════════════════════════════════════════════════════
# Neutralization Load User
# ══════════════════════════════════════════════════════════════════════════════

class NeutralizeUser(ASCUser):
    """
    Simulates analyst submitting neutralization actions under load.
    Primary target: POST /neutralize/ and GET /neutralize/pending.

    10k concurrent requests → validates PANL throughput and HitL queue depth.
    """
    weight = 3

    @tag("neutralize", "write")
    @task(3)
    def submit_block_ip(self):
        payload = {
            "action_type": "block_ip",
            "target": _SANDBOX_IP,
            "target_type": "ip",
            "severity": "medium",
            "params": {"reason": f"load-test-{uuid.uuid4().hex[:8]}"},
        }
        with self.client.post(
            "/api/v1/neutralize/",
            json=payload,
            headers=self.headers,
            name="POST /neutralize/ [block_ip]",
            catch_response=True,
        ) as resp:
            if resp.status_code not in (200, 201, 429):
                resp.failure(f"Unexpected status: {resp.status_code}")
            self._record("POST /neutralize/", resp)

    @tag("neutralize", "write")
    @task(1)
    def submit_block_domain(self):
        payload = {
            "action_type": "block_domain",
            "target": _SANDBOX_DOMAIN,
            "target_type": "domain",
            "severity": "low",
            "params": {"reason": "load-test domain block"},
        }
        with self.client.post(
            "/api/v1/neutralize/",
            json=payload,
            headers=self.headers,
            name="POST /neutralize/ [block_domain]",
            catch_response=True,
        ) as resp:
            if resp.status_code not in (200, 201, 429):
                resp.failure(f"Unexpected: {resp.status_code}")
            self._record("POST /neutralize/ [domain]", resp)

    @tag("neutralize", "read")
    @task(5)
    def list_pending(self):
        with self.client.get(
            "/api/v1/neutralize/pending",
            headers=self.headers,
            name="GET /neutralize/pending",
            catch_response=True,
        ) as resp:
            if not resp.ok:
                resp.failure(f"list_pending: {resp.status_code}")
            self._record("GET /neutralize/pending", resp)

    @tag("neutralize", "read")
    @task(2)
    def list_all_actions(self):
        with self.client.get(
            "/api/v1/neutralize/",
            headers=self.headers,
            name="GET /neutralize/",
            catch_response=True,
        ) as resp:
            if not resp.ok:
                resp.failure(f"list_all: {resp.status_code}")
            self._record("GET /neutralize/", resp)


# ══════════════════════════════════════════════════════════════════════════════
# Hunt Load User
# ══════════════════════════════════════════════════════════════════════════════

class HuntUser(ASCUser):
    """
    Simulates SOC analysts running threat hunts under load.
    Targets: GET /threat-hunting/hunts, GET /threat-hunting/hunts/{id}
    """
    weight = 4

    _hunt_ids: list[str] = []

    def on_start(self):
        super().on_start()
        # Pre-fetch hunt IDs for GET by ID tasks
        resp = self.client.get("/api/v1/threat-hunting/hunts", headers=self.headers)
        if resp.ok:
            hunts = resp.json() if isinstance(resp.json(), list) else resp.json().get("hunts", [])
            self._hunt_ids = [h["id"] for h in hunts[:20] if isinstance(h, dict) and "id" in h]

    @tag("hunt", "read")
    @task(8)
    def list_hunts(self):
        with self.client.get(
            "/api/v1/threat-hunting/hunts",
            headers=self.headers,
            name="GET /hunt/hunts",
            catch_response=True,
        ) as resp:
            if not resp.ok:
                resp.failure(f"list_hunts: {resp.status_code}")
            self._record("GET /hunt/hunts", resp)

    @tag("hunt", "read")
    @task(3)
    def get_hunt_detail(self):
        if not self._hunt_ids:
            return
        hunt_id = random.choice(self._hunt_ids)
        with self.client.get(
            f"/api/v1/threat-hunting/hunts/{hunt_id}",
            headers=self.headers,
            name="GET /hunt/hunts/{id}",
            catch_response=True,
        ) as resp:
            if resp.status_code not in (200, 404):
                resp.failure(f"get_hunt: {resp.status_code}")
            self._record("GET /hunt/hunts/{id}", resp)

    @tag("hunt", "read")
    @task(2)
    def hunt_summary(self):
        with self.client.get(
            "/api/v1/threat-hunting/summary",
            headers=self.headers,
            name="GET /hunt/summary",
            catch_response=True,
        ) as resp:
            if not resp.ok:
                resp.failure(f"hunt_summary: {resp.status_code}")
            self._record("GET /hunt/summary", resp)


# ══════════════════════════════════════════════════════════════════════════════
# Incident Load User
# ══════════════════════════════════════════════════════════════════════════════

class IncidentUser(ASCUser):
    """
    Simulates SOC analysts managing incidents under load.
    Targets: GET /incidents, POST /incidents, PATCH /incidents/{id}/status
    """
    weight = 3

    @tag("incidents", "read")
    @task(6)
    def list_incidents(self):
        with self.client.get(
            "/api/v1/incidents",
            headers=self.headers,
            name="GET /incidents",
            catch_response=True,
        ) as resp:
            if not resp.ok:
                resp.failure(f"list_incidents: {resp.status_code}")
            self._record("GET /incidents", resp)

    @tag("incidents", "read")
    @task(2)
    def incident_summary(self):
        with self.client.get(
            "/api/v1/incidents/summary",
            headers=self.headers,
            name="GET /incidents/summary",
            catch_response=True,
        ) as resp:
            if not resp.ok:
                resp.failure(f"incident_summary: {resp.status_code}")
            self._record("GET /incidents/summary", resp)

    @tag("incidents", "write")
    @task(2)
    def create_incident(self):
        payload = {
            "title": f"Load Test Incident {uuid.uuid4().hex[:8]}",
            "incident_type": "network_intrusion",
            "severity": "medium",
            "description": "Auto-generated by Locust load test",
            "tags": ["load-test", "automated"],
            "risk_score": round(random.uniform(0.3, 0.9), 2),
        }
        with self.client.post(
            "/api/v1/incidents",
            json=payload,
            headers=self.headers,
            name="POST /incidents",
            catch_response=True,
        ) as resp:
            if resp.status_code not in (200, 201, 429):
                resp.failure(f"create_incident: {resp.status_code}")
            elif resp.ok:
                inc_id = resp.json().get("id")
                if inc_id:
                    _created_incident_ids.append(inc_id)
            self._record("POST /incidents", resp)

    @tag("incidents", "write")
    @task(1)
    def transition_incident_status(self):
        if not _created_incident_ids:
            return
        inc_id = random.choice(_created_incident_ids)
        with self.client.patch(
            f"/api/v1/incidents/{inc_id}/status",
            json={"new_status": "investigating"},
            headers=self.headers,
            name="PATCH /incidents/{id}/status",
            catch_response=True,
        ) as resp:
            if resp.status_code not in (200, 422, 404):
                resp.failure(f"transition: {resp.status_code}")
            self._record("PATCH /incidents/{id}/status", resp)


# ══════════════════════════════════════════════════════════════════════════════
# Read-Only Metrics / Health User
# ══════════════════════════════════════════════════════════════════════════════

class ReadOnlyUser(ASCUser):
    """
    High-volume read-only users — simulates SOC dashboard polling.
    Targets: /health, /metrics, /iocs (list), /alerts (list)
    """
    weight = 2

    @tag("health", "read")
    @task(5)
    def health_check(self):
        with self.client.get(
            "/health",
            name="GET /health",
            catch_response=True,
        ) as resp:
            if not resp.ok:
                resp.failure(f"health: {resp.status_code}")
            self._record("GET /health", resp)

    @tag("metrics", "read")
    @task(3)
    def get_metrics_posture(self):
        with self.client.get(
            "/api/v1/metrics/posture",
            headers=self.headers,
            name="GET /metrics/posture",
            catch_response=True,
        ) as resp:
            if not resp.ok:
                resp.failure(f"metrics_posture: {resp.status_code}")
            self._record("GET /metrics/posture", resp)

    @tag("iocs", "read")
    @task(2)
    def list_iocs(self):
        with self.client.get(
            "/api/v1/iocs/?limit=50",
            headers=self.headers,
            name="GET /iocs/",
            catch_response=True,
        ) as resp:
            if not resp.ok:
                resp.failure(f"list_iocs: {resp.status_code}")
            self._record("GET /iocs/", resp)

    @tag("soar", "read")
    @task(1)
    def list_soar_triggers(self):
        with self.client.get(
            "/api/v1/soar/triggers",
            headers=self.headers,
            name="GET /soar/triggers",
            catch_response=True,
        ) as resp:
            if not resp.ok:
                resp.failure(f"soar_triggers: {resp.status_code}")
            self._record("GET /soar/triggers", resp)


# ══════════════════════════════════════════════════════════════════════════════
# Sequential Scenario — Full E2E under load
# ══════════════════════════════════════════════════════════════════════════════

class E2EScenarioTasks(SequentialTaskSet):
    """
    Simulates a full SOC analyst session: login → detect → neutralize → incident.
    One complete cycle per virtual user.
    """
    _incident_id: str | None = None
    _action_id:   str | None = None

    @task
    def step1_list_alerts(self):
        with self.client.get(
            "/api/v1/alerts/",
            headers=self.user.headers,
            name="[E2E] GET /alerts/",
            catch_response=True,
        ) as resp:
            _praf.record("[E2E] list_alerts", resp.elapsed.total_seconds() * 1000, resp.ok)
            if not resp.ok:
                resp.failure(f"alerts: {resp.status_code}")

    @task
    def step2_submit_neutralize(self):
        with self.client.post(
            "/api/v1/neutralize/",
            json={
                "action_type": "block_ip",
                "target": _SANDBOX_IP,
                "target_type": "ip",
                "severity": "medium",
                "params": {"reason": "E2E sequential scenario"},
            },
            headers=self.user.headers,
            name="[E2E] POST /neutralize/",
            catch_response=True,
        ) as resp:
            _praf.record("[E2E] submit_neutralize", resp.elapsed.total_seconds() * 1000, resp.ok)
            if resp.status_code in (200, 201):
                self._action_id = resp.json().get("id")
            elif resp.status_code != 429:
                resp.failure(f"neutralize: {resp.status_code}")

    @task
    def step3_create_incident(self):
        with self.client.post(
            "/api/v1/incidents",
            json={
                "title": f"E2E Scenario Incident {uuid.uuid4().hex[:6]}",
                "incident_type": "network_intrusion",
                "severity": "high",
                "tags": ["e2e", "load-test"],
            },
            headers=self.user.headers,
            name="[E2E] POST /incidents",
            catch_response=True,
        ) as resp:
            _praf.record("[E2E] create_incident", resp.elapsed.total_seconds() * 1000, resp.ok)
            if resp.status_code in (200, 201):
                self._incident_id = resp.json().get("id")
                _created_incident_ids.append(self._incident_id)
            elif resp.status_code != 429:
                resp.failure(f"create_incident: {resp.status_code}")

    @task
    def step4_check_incident(self):
        if not self._incident_id:
            self.interrupt()
            return
        with self.client.get(
            f"/api/v1/incidents/{self._incident_id}",
            headers=self.user.headers,
            name="[E2E] GET /incidents/{id}",
            catch_response=True,
        ) as resp:
            _praf.record("[E2E] get_incident", resp.elapsed.total_seconds() * 1000, resp.ok)
            if resp.status_code not in (200, 404):
                resp.failure(f"get_incident: {resp.status_code}")
        self.interrupt()  # End sequential cycle


class E2ESequentialUser(ASCUser):
    """Runs the full E2E scenario sequentially (one complete cycle per user)."""
    weight = 1
    tasks = [E2EScenarioTasks]


# ══════════════════════════════════════════════════════════════════════════════
# P48 — API Keys Load User (P40-P41)
# ══════════════════════════════════════════════════════════════════════════════

_created_api_key_ids: list[str] = []


class ApiKeyUser(ASCUser):
    """
    P48 — Simulates analyst managing and using API keys under load.
    Targets: GET /api-keys/, POST /api-keys/, GET rate-limit-status.

    Security: keys created with read-only scope and short expiry.
    Never tests the raw X-API-Key auth path (avoids burning real key slots).
    Accepts 429 as valid (rate-limit enforcement is expected behavior).
    """
    weight = 2

    @tag("api_keys", "read")
    @task(5)
    def list_api_keys(self):
        with self.client.get(
            "/api/v1/api-keys/",
            headers=self.headers,
            name="GET /api-keys/",
            catch_response=True,
        ) as resp:
            if resp.status_code not in (200, 429):
                resp.failure(f"list_api_keys: {resp.status_code}")
            self._record("GET /api-keys/", resp)

    @tag("api_keys", "write")
    @task(1)
    def create_and_revoke_api_key(self):
        """Create a key then immediately revoke it to avoid exhausting the 20-key cap."""
        payload = {
            "name": f"load-test-key-{uuid.uuid4().hex[:6]}",
            "scopes": ["read"],
        }
        with self.client.post(
            "/api/v1/api-keys/",
            json=payload,
            headers=self.headers,
            name="POST /api-keys/",
            catch_response=True,
        ) as resp:
            if resp.status_code not in (200, 201, 429):
                resp.failure(f"create_api_key: {resp.status_code}")
            elif resp.status_code in (200, 201):
                key_id = resp.json().get("id")
                if key_id:
                    _created_api_key_ids.append(key_id)
                    # Immediately revoke to keep under cap
                    self.client.delete(
                        f"/api/v1/api-keys/{key_id}",
                        headers=self.headers,
                        name="DELETE /api-keys/{id}",
                    )
            self._record("POST /api-keys/", resp)

    @tag("api_keys", "read")
    @task(2)
    def get_rate_limit_status(self):
        if not _created_api_key_ids:
            return
        key_id = random.choice(_created_api_key_ids)
        with self.client.get(
            f"/api/v1/api-keys/{key_id}/rate-limit-status",
            headers=self.headers,
            name="GET /api-keys/{id}/rate-limit-status",
            catch_response=True,
        ) as resp:
            if resp.status_code not in (200, 404, 429):
                resp.failure(f"rate_limit_status: {resp.status_code}")
            self._record("GET /api-keys/{id}/rate-limit-status", resp)


# ══════════════════════════════════════════════════════════════════════════════
# P48 — Webhook Load User (P42)
# ══════════════════════════════════════════════════════════════════════════════

_created_webhook_ids: list[str] = []


class WebhookUser(ASCUser):
    """
    P48 — Simulates webhook lifecycle under load.
    Targets: GET /webhooks/, POST /webhooks/, POST /webhooks/{id}/test.

    Uses a safe target URL (localhost:9999) that will fail delivery
    but exercises the full dispatch path and latency tracking.
    Accepts 502/503 on test delivery (no real listener required).
    """
    weight = 1

    @tag("webhooks", "read")
    @task(5)
    def list_webhooks(self):
        with self.client.get(
            "/api/v1/webhooks/",
            headers=self.headers,
            name="GET /webhooks/",
            catch_response=True,
        ) as resp:
            if resp.status_code not in (200, 429):
                resp.failure(f"list_webhooks: {resp.status_code}")
            self._record("GET /webhooks/", resp)

    @tag("webhooks", "write")
    @task(1)
    def create_and_delete_webhook(self):
        """Create then delete to avoid exhausting the 10-webhook cap."""
        payload = {
            "url": f"http://load-test.premoscorp.internal:9999/hook/{uuid.uuid4().hex[:8]}",
            "events": ["test"],
            "description": "Locust load test webhook",
        }
        with self.client.post(
            "/api/v1/webhooks/",
            json=payload,
            headers=self.headers,
            name="POST /webhooks/",
            catch_response=True,
        ) as resp:
            if resp.status_code not in (200, 201, 429):
                resp.failure(f"create_webhook: {resp.status_code}")
            elif resp.status_code in (200, 201):
                hook_id = resp.json().get("id")
                if hook_id:
                    _created_webhook_ids.append(hook_id)
                    # Delete immediately to stay under cap
                    self.client.delete(
                        f"/api/v1/webhooks/{hook_id}",
                        headers=self.headers,
                        name="DELETE /webhooks/{id}",
                    )
            self._record("POST /webhooks/", resp)

    @tag("webhooks", "write")
    @task(2)
    def test_webhook_delivery(self):
        if not _created_webhook_ids:
            return
        hook_id = random.choice(_created_webhook_ids)
        with self.client.post(
            f"/api/v1/webhooks/{hook_id}/test",
            headers=self.headers,
            name="POST /webhooks/{id}/test",
            catch_response=True,
        ) as resp:
            # 200 (success or failure is in body), 404 (deleted), 429 (rate)
            if resp.status_code not in (200, 404, 429):
                resp.failure(f"test_webhook: {resp.status_code}")
            self._record("POST /webhooks/{id}/test", resp)
