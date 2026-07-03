"""
P14.5 — SPECTER Advanced Honeypot test suite.

Unit and integration tests covering all honeypot engine components:

  TestCanaryTokenStore        — Canary token lifecycle               (6)
  TestAttackerFingerprinting  — HTTP fingerprint extraction          (6)
  TestDecoyContentGenerator   — Realistic decoy content             (6)
  TestSignedEvidenceReport    — HMAC-signed report generation       (6)
  TestHoneypotEndpoints       — /probe, /dump, /export rich decoys  (6)
  TestCanaryCallback          — GET /c/{token} fingerprint + 404    (4)
  TestAdminHoneypotAPI        — Token + report admin endpoints      (5)

Total: 39 tests
"""

import uuid
import time

import pytest
import pytest_asyncio
from httpx import AsyncClient

from asc_api.core.honeypot import (
    CanaryTokenStore,
    AttackerFingerprint,
    fingerprint_request,
    build_probe_decoy,
    build_dump_decoy,
    build_export_decoy,
    generate_evidence_report,
    verify_report_signature,
    canary_store,
)


# ── Shared helpers ─────────────────────────────────────────────────────────────

_FAKE_HEADERS = {
    "user-agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "accept-language": "es-CO,es;q=0.9,en;q=0.8",
    "accept-encoding": "gzip, deflate, br",
    "referer":         "https://google.com",
    "x-forwarded-for": "198.51.100.42, 203.0.113.1",
    "connection":      "keep-alive",
}

SECRET = "specter-honeypot-test-secret"  # nosec B105


# ══════════════════════════════════════════════════════════════════════════════
#  TestCanaryTokenStore
# ══════════════════════════════════════════════════════════════════════════════

class TestCanaryTokenStore:
    def test_create_returns_token_with_id(self):
        store = CanaryTokenStore()
        token = store.create("/test/endpoint", "test-label")
        assert len(token.token_id) == 32  # UUID without dashes
        assert token.endpoint == "/test/endpoint"
        assert token.label == "test-label"

    def test_create_stores_token(self):
        store = CanaryTokenStore()
        token = store.create("/test", "t")
        retrieved = store.get(token.token_id)
        assert retrieved is not None
        assert retrieved.token_id == token.token_id

    def test_get_nonexistent_returns_none(self):
        store = CanaryTokenStore()
        assert store.get("nonexistent-id") is None

    def test_record_access_logs_ip_and_ua(self):
        store = CanaryTokenStore()
        token = store.create("/test", "t")
        result = store.record_access(token.token_id, "1.2.3.4", _FAKE_HEADERS)
        assert result is not None
        assert result.access_count == 1
        assert result.accesses[0].client_ip == "1.2.3.4"
        assert "Mozilla" in result.accesses[0].user_agent

    def test_multiple_accesses_recorded(self):
        store = CanaryTokenStore()
        token = store.create("/test", "t")
        for i in range(3):
            store.record_access(token.token_id, f"1.2.3.{i}", _FAKE_HEADERS)
        assert store.get(token.token_id).access_count == 3

    def test_record_access_unknown_token_returns_none(self):
        store = CanaryTokenStore()
        result = store.record_access("bad-token-id", "1.2.3.4", {})
        assert result is None


# ══════════════════════════════════════════════════════════════════════════════
#  TestAttackerFingerprinting
# ══════════════════════════════════════════════════════════════════════════════

class TestAttackerFingerprinting:
    def test_extracts_client_ip(self):
        fp = fingerprint_request("10.0.0.5", _FAKE_HEADERS)
        assert fp.client_ip == "10.0.0.5"

    def test_extracts_user_agent(self):
        fp = fingerprint_request("10.0.0.5", _FAKE_HEADERS)
        assert "Mozilla" in fp.user_agent

    def test_extracts_x_forwarded_for(self):
        fp = fingerprint_request("10.0.0.5", _FAKE_HEADERS)
        assert "198.51.100.42" in fp.x_forwarded_for

    def test_fingerprint_hash_is_consistent(self):
        fp1 = fingerprint_request("10.0.0.5", _FAKE_HEADERS)
        fp2 = fingerprint_request("10.0.0.5", _FAKE_HEADERS)
        assert fp1.fingerprint_hash == fp2.fingerprint_hash

    def test_different_ip_different_hash(self):
        fp1 = fingerprint_request("10.0.0.5", _FAKE_HEADERS)
        fp2 = fingerprint_request("10.0.0.6", _FAKE_HEADERS)
        assert fp1.fingerprint_hash != fp2.fingerprint_hash

    def test_strips_sensitive_headers(self):
        headers = {**_FAKE_HEADERS, "cookie": "session=secret", "authorization": "Bearer token"}
        fp = fingerprint_request("1.2.3.4", headers)
        assert "cookie" not in fp.all_headers
        assert "authorization" not in fp.all_headers


# ══════════════════════════════════════════════════════════════════════════════
#  TestDecoyContentGenerator
# ══════════════════════════════════════════════════════════════════════════════

class TestDecoyContentGenerator:
    _BASE = "http://test.premoscorp.local"

    def test_probe_decoy_has_canary_url(self):
        decoy, token = build_probe_decoy(self._BASE)
        assert "diagnostics_url" in decoy
        assert token.token_id in decoy["diagnostics_url"]

    def test_probe_decoy_looks_operational(self):
        decoy, _ = build_probe_decoy(self._BASE)
        assert decoy["status"] == "operational"
        assert "probe_ts" in decoy

    def test_dump_decoy_has_agent_list(self):
        decoy, _ = build_dump_decoy(self._BASE)
        assert "agents" in decoy
        assert len(decoy["agents"]) > 0
        assert "hostname" in decoy["agents"][0]

    def test_dump_decoy_has_canary_url(self):
        decoy, token = build_dump_decoy(self._BASE)
        assert token.token_id in decoy["report_url"]

    def test_export_decoy_has_fake_db_config(self):
        decoy, _ = build_export_decoy(self._BASE)
        assert "config" in decoy
        assert "database" in decoy["config"]
        assert "premoscorp.local" in decoy["config"]["database"]["host"]

    def test_export_decoy_has_canary_url(self):
        decoy, token = build_export_decoy(self._BASE)
        assert token.token_id in decoy["download_url"]


# ══════════════════════════════════════════════════════════════════════════════
#  TestSignedEvidenceReport
# ══════════════════════════════════════════════════════════════════════════════

class TestSignedEvidenceReport:
    def _make_fp(self) -> AttackerFingerprint:
        return fingerprint_request("198.51.100.42", _FAKE_HEADERS)

    def test_report_has_report_id(self):
        fp = self._make_fp()
        result = generate_evidence_report("test_event", fp, None, None, SECRET)
        assert "report_id" in result
        assert len(result["report_id"]) == 36  # UUID

    def test_report_contains_attacker_ip(self):
        fp = self._make_fp()
        result = generate_evidence_report("test_event", fp, None, None, SECRET)
        assert result["report"]["incident_summary"]["attacker_ip"] == "198.51.100.42"

    def test_report_has_legal_notice(self):
        fp = self._make_fp()
        result = generate_evidence_report("test_event", fp, None, None, SECRET)
        assert "legal_notice" in result["report"]
        assert "PremosCorp" in result["report"]["legal_notice"]

    def test_report_has_valid_signature(self):
        fp = self._make_fp()
        result = generate_evidence_report("test_event", fp, None, None, SECRET)
        assert verify_report_signature(result["report"], result["signature"], SECRET) is True

    def test_tampered_report_fails_verification(self):
        fp = self._make_fp()
        result = generate_evidence_report("test_event", fp, None, None, SECRET)
        result["report"]["incident_summary"]["attacker_ip"] = "0.0.0.0"
        assert verify_report_signature(result["report"], result["signature"], SECRET) is False

    def test_report_includes_canary_evidence_when_token_provided(self):
        store = CanaryTokenStore()
        token = store.create("/agents/probe", "probe-label")
        store.record_access(token.token_id, "1.2.3.4", _FAKE_HEADERS)
        fp = self._make_fp()
        result = generate_evidence_report("canary_access", fp, token, None, SECRET)
        assert result["report"]["canary_evidence"]["token_id"] == token.token_id
        assert result["report"]["canary_evidence"]["access_count"] == 1


# ══════════════════════════════════════════════════════════════════════════════
#  TestHoneypotEndpoints
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
class TestHoneypotEndpoints:
    async def test_probe_returns_200(self, client: AsyncClient):
        resp = await client.get("/api/v1/agents/probe")
        assert resp.status_code == 200

    async def test_probe_response_looks_operational(self, client: AsyncClient):
        resp = await client.get("/api/v1/agents/probe")
        data = resp.json()
        assert data.get("status") == "operational"
        assert "diagnostics_url" in data

    async def test_dump_returns_agent_list(self, client: AsyncClient):
        resp = await client.get("/api/v1/agents/dump")
        data = resp.json()
        assert resp.status_code == 200
        assert "agents" in data
        assert isinstance(data["agents"], list)

    async def test_export_returns_db_config(self, client: AsyncClient):
        resp = await client.get("/api/v1/agents/export")
        data = resp.json()
        assert resp.status_code == 200
        assert "config" in data
        assert "database" in data["config"]

    async def test_probe_creates_canary_token(self, client: AsyncClient):
        before = canary_store.active_count()
        await client.get("/api/v1/agents/probe")
        assert canary_store.active_count() > before

    async def test_export_canary_url_points_to_c_endpoint(self, client: AsyncClient):
        resp = await client.get("/api/v1/agents/export")
        data = resp.json()
        assert "/api/v1/c/" in data.get("download_url", "")


# ══════════════════════════════════════════════════════════════════════════════
#  TestCanaryCallback
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
class TestCanaryCallback:
    async def test_canary_callback_returns_404(self, client: AsyncClient):
        # Access a known canary token
        store = CanaryTokenStore()
        token = canary_store.create("/agents/probe", "test-cb")
        resp = await client.get(f"/api/v1/c/{token.token_id}")
        assert resp.status_code == 404

    async def test_canary_callback_unknown_token_still_404(self, client: AsyncClient):
        resp = await client.get(f"/api/v1/c/{uuid.uuid4().hex}")
        assert resp.status_code == 404

    async def test_canary_callback_records_access(self, client: AsyncClient):
        token = canary_store.create("/agents/dump", "callback-test")
        count_before = token.access_count
        await client.get(f"/api/v1/c/{token.token_id}")
        updated = canary_store.get(token.token_id)
        assert updated.access_count == count_before + 1

    async def test_canary_callback_is_not_in_schema(self, client: AsyncClient):
        # Verify it doesn't appear in OpenAPI docs
        resp = await client.get("/api/v1/openapi.json")
        if resp.status_code == 200:
            paths = resp.json().get("paths", {})
            assert "/api/v1/c/{token_id}" not in paths


# ══════════════════════════════════════════════════════════════════════════════
#  TestAdminHoneypotAPI
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
class TestAdminHoneypotAPI:
    async def test_list_tokens_requires_admin(self, client: AsyncClient, analyst_headers: dict):
        resp = await client.get("/api/v1/honeypot/tokens", headers=analyst_headers)
        assert resp.status_code in (401, 403)

    async def test_admin_can_list_tokens(self, client: AsyncClient, admin_headers: dict):
        resp = await client.get("/api/v1/honeypot/tokens", headers=admin_headers)
        assert resp.status_code == 200
        assert "tokens" in resp.json()
        assert "total" in resp.json()

    async def test_admin_can_list_reports(self, client: AsyncClient, admin_headers: dict):
        resp = await client.get("/api/v1/honeypot/reports", headers=admin_headers)
        assert resp.status_code == 200
        assert "reports" in resp.json()

    async def test_unknown_token_returns_404(self, client: AsyncClient, admin_headers: dict):
        resp = await client.get("/api/v1/honeypot/token/nonexistent-id", headers=admin_headers)
        assert resp.status_code == 404

    async def test_unknown_report_returns_404(self, client: AsyncClient, admin_headers: dict):
        resp = await client.get(f"/api/v1/honeypot/report/{uuid.uuid4()}", headers=admin_headers)
        assert resp.status_code == 404
