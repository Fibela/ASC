"""
P33 Coverage â€” targets that push total from 82.15% â†’ â‰¥85%

1. Neutralize routing-fix endpoints:
   - GET /neutralize/history      (was 404 before P33-ROUTE-FIX)
   - GET /neutralize/recommended/{severity}
   - GET /neutralize/{id}/commands

2. PFN (pfn.py) pure-function unit tests â€” no DB required

3. Analyzer (analyzer.py) pure-function unit tests â€” no DB required

4. Executive Reports CRUD endpoints (executive_reports.py)
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
import pytest_asyncio

# â”€â”€â”€ Rate-limit reset (for @limiter.limit endpoints) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@pytest.fixture(autouse=True)
def _reset_limiter():
    from asc_api.core.rate_limit import limiter
    try:
        limiter._storage.reset()
    except Exception:
        pass
    yield


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 1. NEUTRALIZE â€” ROUTING FIX ENDPOINTS
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestNeutralizeHistoryFixed:
    """GET /neutralize/history was shadowed by /{action_id} before P33-ROUTE-FIX.
    After the fix, literal paths are registered before the parameterized route."""

    async def test_history_returns_200_not_404(self, client, analyst_headers):
        resp = await client.get("/api/v1/neutralize/history", headers=analyst_headers)
        assert resp.status_code == 200, (
            f"Expected 200 â€” routing still broken? Got {resp.status_code}: {resp.text}"
        )

    async def test_history_response_shape(self, client, analyst_headers):
        resp = await client.get("/api/v1/neutralize/history", headers=analyst_headers)
        body = resp.json()
        assert "actions" in body
        assert "total" in body
        assert isinstance(body["actions"], list)
        assert body["total"] == len(body["actions"])

    async def test_history_empty_on_fresh_db(self, client, analyst_headers):
        resp = await client.get("/api/v1/neutralize/history", headers=analyst_headers)
        assert resp.json()["total"] == 0

    async def test_history_limit_param_accepted(self, client, analyst_headers):
        resp = await client.get(
            "/api/v1/neutralize/history?limit=5", headers=analyst_headers
        )
        assert resp.status_code == 200
        assert len(resp.json()["actions"]) <= 5

    async def test_history_requires_auth(self, client):
        resp = await client.get("/api/v1/neutralize/history")
        assert resp.status_code == 401

    async def test_history_viewer_blocked(self, client, viewer_headers):
        resp = await client.get("/api/v1/neutralize/history", headers=viewer_headers)
        assert resp.status_code == 403

    async def test_history_contains_past_actions(self, client, analyst_headers):
        # Create an action first
        create = await client.post(
            "/api/v1/neutralize",
            json={
                "action_type": "block_ip",
                "target": "192.0.2.1",
                "target_type": "ip",
                "severity": "medium",
            },
            headers=analyst_headers,
        )
        assert create.status_code == 200, create.text
        action_id = create.json()["id"]

        hist = await client.get("/api/v1/neutralize/history", headers=analyst_headers)
        ids = [a["id"] for a in hist.json()["actions"]]
        assert action_id in ids


class TestNeutralizeRecommendedFixed:
    """GET /neutralize/recommended/{severity} â€” verify routing intact after fix."""

    @pytest.mark.parametrize("sev", ["critical", "high", "medium", "low"])
    async def test_valid_severity_returns_200(self, client, analyst_headers, sev):
        resp = await client.get(
            f"/api/v1/neutralize/recommended/{sev}", headers=analyst_headers
        )
        assert resp.status_code == 200, f"severity={sev}: {resp.text}"

    @pytest.mark.parametrize("sev", ["critical", "high", "medium", "low"])
    async def test_valid_severity_response_shape(self, client, analyst_headers, sev):
        resp = await client.get(
            f"/api/v1/neutralize/recommended/{sev}", headers=analyst_headers
        )
        body = resp.json()
        assert body["severity"] == sev
        assert isinstance(body["recommended_actions"], list)
        assert len(body["recommended_actions"]) > 0

    async def test_invalid_severity_returns_400(self, client, analyst_headers):
        resp = await client.get(
            "/api/v1/neutralize/recommended/catastrophic", headers=analyst_headers
        )
        assert resp.status_code == 400

    async def test_recommended_requires_auth(self, client):
        resp = await client.get("/api/v1/neutralize/recommended/high")
        assert resp.status_code == 401


class TestNeutralizeCommands:
    """GET /neutralize/{action_id}/commands â€” largely untested before P33."""

    async def test_unknown_action_id_returns_404(self, client, analyst_headers):
        resp = await client.get(
            f"/api/v1/neutralize/{uuid.uuid4()}/commands",
            headers=analyst_headers,
        )
        assert resp.status_code == 404

    async def _create_action(self, client, headers) -> dict:
        resp = await client.post(
            "/api/v1/neutralize",
            json={
                "action_type": "block_ip",
                "target": "192.0.2.55",
                "target_type": "ip",
                "severity": "medium",
            },
            headers=headers,
        )
        assert resp.status_code == 200, resp.text
        return resp.json()

    async def test_existing_action_no_commands_returns_empty_list(
        self, client, analyst_headers
    ):
        action = await self._create_action(client, analyst_headers)
        resp = await client.get(
            f"/api/v1/neutralize/{action['id']}/commands",
            headers=analyst_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["action_id"] == action["id"]
        assert isinstance(body["commands"], list)
        # dispatch_mode should be 'simulation' when no real SPECTER agents present
        assert "dispatch_mode" in body

    async def test_commands_requires_auth(self, client):
        resp = await client.get(
            f"/api/v1/neutralize/{uuid.uuid4()}/commands"
        )
        assert resp.status_code == 401


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 2. PFN PURE FUNCTIONS â€” unit level (no DB, no HTTP)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestPFNBuildCanonical:
    def _make_action(self, **overrides) -> SimpleNamespace:
        now = datetime.now(timezone.utc)
        defaults = dict(
            id=str(uuid.uuid4()),
            action_type="block_ip",
            target="10.0.0.1",
            target_type="ip",
            severity="high",
            approved_at=now,
            executed_at=now,
            params={"direction": "both"},
        )
        defaults.update(overrides)
        return SimpleNamespace(**defaults)

    def test_canonical_has_required_fields(self):
        from asc_api.services.pfn import _build_canonical
        action = self._make_action()
        c = _build_canonical(action, "analyst@premoscorp.com")
        for key in ("action_id", "action_type", "target", "target_type",
                    "severity", "approved_by", "approved_at", "executed_at",
                    "params", "pfn_version"):
            assert key in c, f"missing: {key}"

    def test_canonical_approved_by_matches_input(self):
        from asc_api.services.pfn import _build_canonical
        action = self._make_action()
        c = _build_canonical(action, "soc@premoscorp.com")
        assert c["approved_by"] == "soc@premoscorp.com"

    def test_canonical_action_id_matches(self):
        from asc_api.services.pfn import _build_canonical
        action = self._make_action()
        c = _build_canonical(action, "x@y.com")
        assert c["action_id"] == action.id

    def test_canonical_none_approved_at_uses_now(self):
        from asc_api.services.pfn import _build_canonical
        action = self._make_action(approved_at=None, executed_at=None)
        c = _build_canonical(action, "x@y.com")
        # Should not raise and should have a timestamp string
        assert isinstance(c["approved_at"], str)
        assert isinstance(c["executed_at"], str)

    def test_canonical_is_deterministic(self):
        from asc_api.services.pfn import _build_canonical
        action = self._make_action()
        c1 = _build_canonical(action, "a@b.com")
        c2 = _build_canonical(action, "a@b.com")
        assert c1 == c2


class TestPFNComputeHash:
    def test_hash_length_is_128_chars(self):
        from asc_api.services.pfn import _compute_hash
        h = _compute_hash({"key": "value"})
        assert len(h) == 128

    def test_hash_is_hex(self):
        from asc_api.services.pfn import _compute_hash
        h = _compute_hash({"key": "value"})
        assert all(c in "0123456789abcdef" for c in h)

    def test_hash_is_deterministic(self):
        from asc_api.services.pfn import _compute_hash
        payload = {"a": 1, "z": 99, "m": "hello"}
        assert _compute_hash(payload) == _compute_hash(payload)

    def test_hash_uses_sorted_keys(self):
        from asc_api.services.pfn import _compute_hash
        # Order-independent: same content regardless of dict order
        assert _compute_hash({"a": 1, "b": 2}) == _compute_hash({"b": 2, "a": 1})

    def test_hash_matches_stdlib_sha3_512(self):
        from asc_api.services.pfn import _compute_hash
        payload = {"action_id": "abc", "severity": "high"}
        canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        expected = hashlib.sha3_512(canonical_json).hexdigest()
        assert _compute_hash(payload) == expected

    def test_different_payloads_produce_different_hashes(self):
        from asc_api.services.pfn import _compute_hash
        assert _compute_hash({"x": 1}) != _compute_hash({"x": 2})


class TestPFNSignVerify:
    def _keypair(self):
        from asc_api.core.signing import generate_analyst_keypair
        return generate_analyst_keypair()

    def test_sign_returns_base64_string(self):
        from asc_api.services.pfn import _sign_hash
        priv_b64, _ = self._keypair()
        sig = _sign_hash("abc123", priv_b64)
        assert isinstance(sig, str)
        assert len(sig) > 0

    def test_roundtrip_valid(self):
        from asc_api.services.pfn import _sign_hash, _verify_signature
        priv_b64, pub_b64 = self._keypair()
        hash_hex = "a" * 128
        sig = _sign_hash(hash_hex, priv_b64)
        assert _verify_signature(hash_hex, sig, pub_b64) is True

    def test_invalid_signature_returns_false(self):
        from asc_api.services.pfn import _verify_signature
        _, pub_b64 = self._keypair()
        import base64
        bad_sig = base64.b64encode(b"\x00" * 64).decode()
        assert _verify_signature("a" * 128, bad_sig, pub_b64) is False

    def test_wrong_key_returns_false(self):
        from asc_api.services.pfn import _sign_hash, _verify_signature
        priv1, _ = self._keypair()
        _, pub2 = self._keypair()
        sig = _sign_hash("deadbeef" * 16, priv1)
        assert _verify_signature("deadbeef" * 16, sig, pub2) is False

    def test_tampered_hash_returns_false(self):
        from asc_api.services.pfn import _sign_hash, _verify_signature
        priv_b64, pub_b64 = self._keypair()
        original_hash = "a" * 128
        sig = _sign_hash(original_hash, priv_b64)
        tampered_hash = "b" * 128
        assert _verify_signature(tampered_hash, sig, pub_b64) is False


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 3. ANALYZER PURE FUNCTIONS â€” unit level (no DB, no HTTP)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestAnalyzerComputeHashes:
    def test_returns_three_hash_types(self):
        from asc_api.services.analyzer import _compute_hashes
        result = _compute_hashes(b"hello world")
        assert set(result.keys()) == {"md5", "sha1", "sha256"}

    def test_hash_lengths(self):
        from asc_api.services.analyzer import _compute_hashes
        result = _compute_hashes(b"test")
        assert len(result["md5"]) == 32
        assert len(result["sha1"]) == 40
        assert len(result["sha256"]) == 64

    def test_empty_bytes_doesnt_raise(self):
        from asc_api.services.analyzer import _compute_hashes
        result = _compute_hashes(b"")
        assert all(isinstance(v, str) for v in result.values())

    def test_deterministic(self):
        from asc_api.services.analyzer import _compute_hashes
        data = b"premoscorp_test_payload"
        assert _compute_hashes(data) == _compute_hashes(data)


class TestAnalyzerScanSignatures:
    def test_clean_data_no_hits(self):
        from asc_api.services.analyzer import _scan_signatures
        hits = _scan_signatures(b"hello world nothing suspicious here")
        assert hits == []

    def test_mimikatz_detected(self):
        from asc_api.services.analyzer import _scan_signatures
        data = b"sekurlsa::logonpasswords dump collected"
        hits = _scan_signatures(data)
        names = [h["rule"] for h in hits]
        assert "Mimikatz_strings" in names

    def test_metasploit_detected(self):
        from asc_api.services.analyzer import _scan_signatures
        hits = _scan_signatures(b"meterpreter session established")
        assert any(h["rule"] == "Metasploit_payload" for h in hits)

    def test_ransomware_extension_detected(self):
        from asc_api.services.analyzer import _scan_signatures
        hits = _scan_signatures(b"files now have .encrypted extension")
        assert any(h["threat"] == "ransomware" for h in hits)

    def test_hit_has_required_fields(self):
        from asc_api.services.analyzer import _scan_signatures
        hits = _scan_signatures(b"meterpreter")
        assert len(hits) >= 1
        for h in hits:
            assert "rule" in h
            assert "severity" in h
            assert "threat" in h

    def test_case_insensitive_matching(self):
        from asc_api.services.analyzer import _scan_signatures
        hits_lower = _scan_signatures(b"sekurlsa::logonpasswords")
        hits_upper = _scan_signatures(b"SEKURLSA::LOGONPASSWORDS")
        assert len(hits_lower) == len(hits_upper)

    def test_multiple_signatures_in_one_payload(self):
        from asc_api.services.analyzer import _scan_signatures
        data = b"meterpreter sekurlsa::logonpasswords cmd.exe /c"
        hits = _scan_signatures(data)
        assert len(hits) >= 3


class TestAnalyzerDetectFileType:
    def test_pe_executable(self):
        from asc_api.services.analyzer import _detect_file_type
        label = _detect_file_type(b"MZ\x90\x00" + b"\x00" * 100, "malware.exe")
        assert "PE" in label

    def test_elf_executable(self):
        from asc_api.services.analyzer import _detect_file_type
        label = _detect_file_type(b"\x7fELF" + b"\x00" * 50, "binary.elf")
        assert "ELF" in label

    def test_pdf_document(self):
        from asc_api.services.analyzer import _detect_file_type
        label = _detect_file_type(b"%PDF-1.7\n%%EOF", "report.pdf")
        assert "PDF" in label

    def test_zip_document(self):
        from asc_api.services.analyzer import _detect_file_type
        label = _detect_file_type(b"PK\x03\x04" + b"\x00" * 20, "archive.zip")
        assert "ZIP" in label

    def test_unknown_file_type_includes_extension(self):
        from asc_api.services.analyzer import _detect_file_type
        label = _detect_file_type(b"\x00\x01\x02\x03", "mystery.xyz")
        assert "xyz" in label.lower() or "Unknown" in label


class TestAnalyzerExtractStrings:
    def test_extracts_ascii_strings(self):
        from asc_api.services.analyzer import _extract_strings
        data = b"\x00\x00hello world\x00\x00"
        strings = _extract_strings(data)
        assert any("hello world" in s for s in strings)

    def test_short_strings_excluded(self):
        from asc_api.services.analyzer import _extract_strings
        # Strings shorter than min_len=4 should not appear
        data = b"ab\x00\x00\x00\x00\x00\x00"
        strings = _extract_strings(data)
        assert not any(len(s) < 4 for s in strings)

    def test_returns_sorted_list(self):
        from asc_api.services.analyzer import _extract_strings
        data = b"zebra apple mango cherry"
        strings = _extract_strings(data)
        assert strings == sorted(strings)

    def test_empty_bytes_returns_empty_list(self):
        from asc_api.services.analyzer import _extract_strings
        assert _extract_strings(b"") == []

    def test_known_malware_string_extracted(self):
        from asc_api.services.analyzer import _extract_strings
        data = b"\x00\x00CreateRemoteThread\x00\x00meterpreter\x00"
        strings = _extract_strings(data)
        assert any("CreateRemoteThread" in s for s in strings)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 4. EXECUTIVE REPORTS ENDPOINTS
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestExecutiveReportsSummary:
    async def test_summary_requires_auth(self, client):
        resp = await client.get("/api/v1/reports/executive/summary")
        assert resp.status_code == 401

    async def test_summary_analyst_can_read(self, client, analyst_headers):
        resp = await client.get(
            "/api/v1/reports/executive/summary", headers=analyst_headers
        )
        assert resp.status_code == 200

    async def test_summary_viewer_blocked(self, client, viewer_headers):
        resp = await client.get(
            "/api/v1/reports/executive/summary", headers=viewer_headers
        )
        assert resp.status_code == 403


class TestExecutiveReportsList:
    async def test_list_requires_auth(self, client):
        resp = await client.get("/api/v1/reports/executive")
        assert resp.status_code == 401

    async def test_list_empty_on_fresh_db(self, client, analyst_headers):
        resp = await client.get("/api/v1/reports/executive", headers=analyst_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "items" in body
        assert "count" in body
        assert body["count"] == 0

    async def test_list_invalid_report_type_422(self, client, analyst_headers):
        resp = await client.get(
            "/api/v1/reports/executive?report_type=fake_type",
            headers=analyst_headers,
        )
        assert resp.status_code == 422

    async def test_list_pagination_params(self, client, analyst_headers):
        resp = await client.get(
            "/api/v1/reports/executive?limit=10&offset=0",
            headers=analyst_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["limit"] == 10
        assert body["offset"] == 0


class TestExecutiveReportsGenerate:
    @pytest.fixture(autouse=True)
    def _signing_key(self, monkeypatch):
        """
        Provide a real Ed25519 keypair so generate endpoint returns 201.
        get_settings() is @lru_cache â€” patch the cached object directly.
        """
        from asc_api.core.signing import generate_analyst_keypair
        import asc_api.services.reporting_service as rs
        priv_b64, pub_b64 = generate_analyst_keypair()
        monkeypatch.setattr(rs._s, "SPECTER_SIGNING_PRIVATE_KEY", priv_b64)
        monkeypatch.setattr(rs._s, "SPECTER_SIGNING_PUBLIC_KEY", pub_b64)

    def _body(self, **overrides) -> dict:
        base = {
            "report_type": "full_executive",
            "period": "custom",
            "period_start": "2026-06-01T00:00:00Z",
            "period_end": "2026-06-12T23:59:59Z",
            "title": "P33 Test Report",
        }
        base.update(overrides)
        return base

    async def test_generate_requires_admin(self, client, analyst_headers):
        resp = await client.post(
            "/api/v1/reports/executive/generate",
            json=self._body(),
            headers=analyst_headers,
        )
        assert resp.status_code == 403

    async def test_generate_admin_returns_201(self, client, admin_headers):
        resp = await client.post(
            "/api/v1/reports/executive/generate",
            json=self._body(),
            headers=admin_headers,
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert "id" in body
        assert "hash_sha3_512" in body
        assert len(body["hash_sha3_512"]) == 128

    async def test_generate_invalid_report_type_422(self, client, admin_headers):
        resp = await client.post(
            "/api/v1/reports/executive/generate",
            json=self._body(report_type="invalid_type"),
            headers=admin_headers,
        )
        assert resp.status_code == 422

    async def test_generate_invalid_period_422(self, client, admin_headers):
        resp = await client.post(
            "/api/v1/reports/executive/generate",
            json=self._body(period="biannual"),
            headers=admin_headers,
        )
        assert resp.status_code == 422

    async def test_generate_end_before_start_422(self, client, admin_headers):
        resp = await client.post(
            "/api/v1/reports/executive/generate",
            json=self._body(
                period_start="2026-06-12T00:00:00Z",
                period_end="2026-06-01T00:00:00Z",
            ),
            headers=admin_headers,
        )
        assert resp.status_code == 422


class TestExecutiveReportsGetVerifyDelete:
    @pytest.fixture(autouse=True)
    def _signing_key(self, monkeypatch):
        """
        Generate a test Ed25519 keypair and patch the cached settings object
        so the generate endpoint doesn't return 503.
        get_settings() uses @lru_cache, so monkeypatch.setenv has no effect â€”
        we must patch the already-instantiated settings object directly.
        """
        from asc_api.core.signing import generate_analyst_keypair
        import asc_api.services.reporting_service as rs
        priv_b64, pub_b64 = generate_analyst_keypair()
        monkeypatch.setattr(rs._s, "SPECTER_SIGNING_PRIVATE_KEY", priv_b64)
        monkeypatch.setattr(rs._s, "SPECTER_SIGNING_PUBLIC_KEY", pub_b64)

    async def _create_report(self, client, admin_headers) -> dict:
        resp = await client.post(
            "/api/v1/reports/executive/generate",
            json={
                "report_type": "full_executive",
                "period": "custom",
                "period_start": "2026-06-01T00:00:00Z",
                "period_end": "2026-06-12T23:59:59Z",
            },
            headers=admin_headers,
        )
        assert resp.status_code == 201, resp.text
        return resp.json()

    async def test_get_existing_report(self, client, analyst_headers, admin_headers):
        report = await self._create_report(client, admin_headers)
        resp = await client.get(
            f"/api/v1/reports/executive/{report['id']}",
            headers=analyst_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["id"] == report["id"]

    async def test_get_nonexistent_report_404(self, client, analyst_headers):
        resp = await client.get(
            f"/api/v1/reports/executive/{uuid.uuid4()}",
            headers=analyst_headers,
        )
        assert resp.status_code == 404

    async def test_get_includes_canonical_data(self, client, analyst_headers, admin_headers):
        report = await self._create_report(client, admin_headers)
        resp = await client.get(
            f"/api/v1/reports/executive/{report['id']}",
            headers=analyst_headers,
        )
        assert "canonical_data" in resp.json()

    async def test_verify_existing_report(self, client, analyst_headers, admin_headers):
        report = await self._create_report(client, admin_headers)
        resp = await client.post(
            f"/api/v1/reports/executive/{report['id']}/verify",
            headers=analyst_headers,
        )
        assert resp.status_code == 200

    async def test_verify_nonexistent_report_404(self, client, analyst_headers):
        resp = await client.post(
            f"/api/v1/reports/executive/{uuid.uuid4()}/verify",
            headers=analyst_headers,
        )
        assert resp.status_code == 404

    async def test_delete_requires_admin(self, client, analyst_headers, admin_headers):
        report = await self._create_report(client, admin_headers)
        resp = await client.delete(
            f"/api/v1/reports/executive/{report['id']}",
            headers=analyst_headers,
        )
        assert resp.status_code == 403

    async def test_delete_admin_returns_204(self, client, admin_headers):
        report = await self._create_report(client, admin_headers)
        resp = await client.delete(
            f"/api/v1/reports/executive/{report['id']}",
            headers=admin_headers,
        )
        assert resp.status_code == 204

    async def test_delete_then_get_returns_404(self, client, analyst_headers, admin_headers):
        report = await self._create_report(client, admin_headers)
        await client.delete(
            f"/api/v1/reports/executive/{report['id']}", headers=admin_headers
        )
        resp = await client.get(
            f"/api/v1/reports/executive/{report['id']}", headers=analyst_headers
        )
        assert resp.status_code == 404

    async def test_delete_nonexistent_404(self, client, admin_headers):
        resp = await client.delete(
            f"/api/v1/reports/executive/{uuid.uuid4()}",
            headers=admin_headers,
        )
        assert resp.status_code == 404
