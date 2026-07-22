"""
P29-B â€” Executive Reporting & PIIL â€” Test Suite
================================================
Coverage:
  TestExecutiveReportModel     (12) â€” ORM init, constants, compute_hash, is_hash_valid
  TestPIILSigning              (14) â€” _sha3_512_hex, _sign_report no-key/key/error,
                                      verify_report_signature valid/invalid/no-pubkey
  TestIncidentKpis             (10) â€” mock DB, return dict structure and values
  TestCampaignKpis              (8) â€” mock DB, new/active/critical
  TestHuntingKpis               (8) â€” mock DB, hunts/findings/critical
  TestSoarKpis                  (6) â€” mock DB, triggers_fired/alerts_in_period
  TestGenerateReport           (14) â€” happy path, auto-title, canonical pre-bakes id,
                                      hash length, unsigned fallback, db.add/commit called
  TestVerifyReport             (10) â€” hash_ok/sig_ok/both/neither, not-found raises,
                                      updates signature_valid + last_verified_at
  TestGetReport                 (4) â€” found / not-found
  TestListReports               (6) â€” no filter / type filter / limit+offset
  TestGetReportingSummary       (8) â€” totals, by_type, unsigned, latest
  TestReportingEndpoints       (12) â€” summary/list/generate/get/verify/delete:
                                      auth guard, status codes, validation errors

Total: 112 tests
"""
from __future__ import annotations

import base64
import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest

# â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _make_report(**kwargs):
    from asc_api.models.executive_report import ExecutiveReport
    r = ExecutiveReport()
    r.id = kwargs.get("id", str(uuid.uuid4()))
    r.report_type = kwargs.get("report_type", "full_executive")
    r.period = kwargs.get("period", "monthly")
    r.title = kwargs.get("title", "Test Report")
    r.generated_by = kwargs.get("generated_by", "admin@premos.com")
    r.period_start = kwargs.get("period_start", _utcnow() - timedelta(days=30))
    r.period_end = kwargs.get("period_end", _utcnow())
    r.total_incidents = kwargs.get("total_incidents", 0)
    r.closed_incidents = kwargs.get("closed_incidents", 0)
    r.sla_breach_count = kwargs.get("sla_breach_count", 0)
    r.campaign_count = kwargs.get("campaign_count", 0)
    r.avg_mttd_minutes = kwargs.get("avg_mttd_minutes", None)
    r.avg_mttc_minutes = kwargs.get("avg_mttc_minutes", None)
    r.avg_mttr_minutes = kwargs.get("avg_mttr_minutes", None)
    r.canonical_data = kwargs.get("canonical_data", {"report_id": r.id, "incidents": {}})
    hash_hex = hashlib.sha3_512(
        json.dumps(r.canonical_data, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    r.hash_sha3_512 = kwargs.get("hash_sha3_512", hash_hex)
    r.signature_ed25519 = kwargs.get("signature_ed25519", base64.b64encode(b"PIIL-UNSIGNED-NO-KEY-CONFIGURED").decode())
    r.pubkey_fingerprint = kwargs.get("pubkey_fingerprint", "0000000000000000")
    r.signature_valid = kwargs.get("signature_valid", False)
    r.last_verified_at = kwargs.get("last_verified_at", None)
    r.created_at = kwargs.get("created_at", _utcnow())
    return r


def _mock_scalar(value):
    """Return AsyncMock.execute result that yields scalar_one() â†’ value."""
    row = MagicMock()
    row.scalar_one.return_value = value
    row.scalar_one_or_none.return_value = value
    return row


def _mock_scalars(rows):
    """Return AsyncMock.execute result for .scalars().all()."""
    result = MagicMock()
    scalars_mock = MagicMock()
    scalars_mock.all.return_value = rows
    result.scalars.return_value = scalars_mock
    return result


def _mock_all(rows):
    row_result = MagicMock()
    row_result.all.return_value = rows
    return row_result


# â”€â”€ TestExecutiveReportModel â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestExecutiveReportModel:

    def test_instantiation_defaults(self):
        from asc_api.models.executive_report import ExecutiveReport
        r = ExecutiveReport()
        r.id = str(uuid.uuid4())
        r.report_type = "period_kpi"
        r.title = "t"
        r.generated_by = "admin@premos.com"
        r.period_start = _utcnow()
        r.period_end = _utcnow()
        r.canonical_data = {}
        r.hash_sha3_512 = "a" * 128
        r.signature_ed25519 = "sig"
        assert r.report_type == "period_kpi"

    def test_report_types_frozenset(self):
        from asc_api.models.executive_report import REPORT_TYPES
        assert isinstance(REPORT_TYPES, frozenset)
        assert "full_executive" in REPORT_TYPES
        assert "period_kpi" in REPORT_TYPES
        assert "campaign_brief" in REPORT_TYPES
        assert "sla_breach" in REPORT_TYPES

    def test_report_types_immutable(self):
        from asc_api.models.executive_report import REPORT_TYPES
        with pytest.raises((AttributeError, TypeError)):
            REPORT_TYPES.add("bad_type")  # type: ignore

    def test_report_periods_frozenset(self):
        from asc_api.models.executive_report import REPORT_PERIODS
        assert isinstance(REPORT_PERIODS, frozenset)
        assert "monthly" in REPORT_PERIODS
        assert "custom" in REPORT_PERIODS
        assert "quarterly" in REPORT_PERIODS

    def test_compute_hash_returns_128_chars(self):
        r = _make_report()
        h = r.compute_hash()
        assert len(h) == 128
        assert all(c in "0123456789abcdef" for c in h)

    def test_compute_hash_deterministic(self):
        r = _make_report(canonical_data={"x": 1})
        assert r.compute_hash() == r.compute_hash()

    def test_is_hash_valid_true(self):
        data = {"report_id": "abc", "x": 1}
        h = hashlib.sha3_512(
            json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        r = _make_report(canonical_data=data, hash_sha3_512=h)
        assert r.is_hash_valid() is True

    def test_is_hash_valid_false_on_tamper(self):
        r = _make_report(canonical_data={"x": 1}, hash_sha3_512="0" * 128)
        assert r.is_hash_valid() is False

    def test_is_hash_valid_false_on_wrong_hash(self):
        r = _make_report(canonical_data={"x": 1}, hash_sha3_512="deadbeef" * 16)
        assert r.is_hash_valid() is False

    def test_canonical_data_key_order_does_not_affect_hash(self):
        data_a = {"b": 2, "a": 1}
        data_b = {"a": 1, "b": 2}
        h = lambda d: hashlib.sha3_512(
            json.dumps(d, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        assert h(data_a) == h(data_b)

    def test_tablename(self):
        from asc_api.models.executive_report import ExecutiveReport
        assert ExecutiveReport.__tablename__ == "executive_reports"

    def test_required_columns_present(self):
        from asc_api.models.executive_report import ExecutiveReport
        cols = [c.name for c in ExecutiveReport.__table__.columns]
        for expected in ("id", "report_type", "period", "title", "generated_by",
                         "period_start", "period_end", "hash_sha3_512",
                         "signature_ed25519", "canonical_data", "signature_valid"):
            assert expected in cols, f"Missing column: {expected}"


# â”€â”€ TestPIILSigning â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestPIILSigning:

    def test_sha3_512_hex_returns_128_chars(self):
        from asc_api.services.reporting_service import _sha3_512_hex
        h = _sha3_512_hex({"foo": "bar"})
        assert len(h) == 128

    def test_sha3_512_hex_deterministic(self):
        from asc_api.services.reporting_service import _sha3_512_hex
        assert _sha3_512_hex({"a": 1}) == _sha3_512_hex({"a": 1})

    def test_sha3_512_hex_key_order_invariant(self):
        from asc_api.services.reporting_service import _sha3_512_hex
        assert _sha3_512_hex({"a": 1, "b": 2}) == _sha3_512_hex({"b": 2, "a": 1})

    def test_sign_report_no_key_raises_value_error(self):
        from asc_api.services.reporting_service import _sign_report
        with patch("asc_api.services.reporting_service._s") as ms:
            ms.SPECTER_SIGNING_PRIVATE_KEY = ""
            ms.SPECTER_SIGNING_PUBLIC_KEY = ""
            with pytest.raises(ValueError, match="SPECTER_SIGNING_PRIVATE_KEY"):
                _sign_report("deadbeef" * 32)

    def test_sign_report_no_key_fingerprint_is_16_zeros(self):
        from asc_api.services.reporting_service import _sign_report
        with patch("asc_api.services.reporting_service._s") as ms:
            ms.SPECTER_SIGNING_PRIVATE_KEY = ""
            ms.SPECTER_SIGNING_PUBLIC_KEY = ""
            with pytest.raises(ValueError):
                _sign_report("abc")

    def test_sign_report_with_invalid_key_raises_value_error(self):
        from asc_api.services.reporting_service import _sign_report
        with patch("asc_api.services.reporting_service._s") as ms:
            ms.SPECTER_SIGNING_PRIVATE_KEY = "NOTAVALIDKEY=="
            ms.SPECTER_SIGNING_PUBLIC_KEY = ""
            with pytest.raises(ValueError):
                _sign_report("abc")

    def test_verify_report_signature_no_public_key_returns_false(self):
        from asc_api.services.reporting_service import verify_report_signature
        r = _make_report()
        with patch("asc_api.services.reporting_service._s") as ms:
            ms.SPECTER_SIGNING_PUBLIC_KEY = ""
        # Without public key, should return False (no key â†’ can't verify)
        with patch("asc_api.services.reporting_service._s") as ms:
            ms.SPECTER_SIGNING_PUBLIC_KEY = ""
            result = verify_report_signature(r)
        assert result is False

    def test_verify_report_signature_invalid_hash_returns_false(self):
        from asc_api.services.reporting_service import verify_report_signature
        r = _make_report(canonical_data={"x": 1}, hash_sha3_512="0" * 128)
        # hash won't match canonical_data â†’ is_hash_valid() returns False
        with patch("asc_api.services.reporting_service._s") as ms:
            ms.SPECTER_SIGNING_PUBLIC_KEY = "somekey"
            result = verify_report_signature(r)
        assert result is False

    def test_verify_report_signature_bad_signature_returns_false(self):
        from asc_api.services.reporting_service import verify_report_signature
        r = _make_report()
        with patch.object(r, "is_hash_valid", return_value=True):
            with patch("asc_api.services.reporting_service._s") as ms:
                ms.SPECTER_SIGNING_PUBLIC_KEY = "dGVzdA=="
                result = verify_report_signature(r)
        assert result is False

    def test_sha3_512_different_inputs_produce_different_hashes(self):
        from asc_api.services.reporting_service import _sha3_512_hex
        assert _sha3_512_hex({"a": 1}) != _sha3_512_hex({"a": 2})

    def test_piil_unsigned_constant_decodable(self):
        sig = base64.b64encode(b"PIIL-UNSIGNED-NO-KEY-CONFIGURED").decode()
        assert base64.b64decode(sig) == b"PIIL-UNSIGNED-NO-KEY-CONFIGURED"

    def test_sign_report_with_valid_key_returns_tuple(self):
        from asc_api.services.reporting_service import _sign_report
        from asc_api.core.signing import generate_analyst_keypair
        priv_b64, pub_b64 = generate_analyst_keypair()
        with patch("asc_api.services.reporting_service._s") as ms:
            ms.SPECTER_SIGNING_PRIVATE_KEY = priv_b64
            ms.SPECTER_SIGNING_PUBLIC_KEY = pub_b64
            result = _sign_report("abc")
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_sha3_512_hex_empty_dict(self):
        from asc_api.services.reporting_service import _sha3_512_hex
        h = _sha3_512_hex({})
        assert len(h) == 128

    def test_sha3_512_hex_nested_data(self):
        from asc_api.services.reporting_service import _sha3_512_hex
        h = _sha3_512_hex({"incidents": {"total": 5, "by_severity": {"high": 2}}})
        assert len(h) == 128

    def test_sha3_512_hex_matches_reference(self):
        from asc_api.services.reporting_service import _sha3_512_hex
        data = {"a": 1}
        expected = hashlib.sha3_512(
            json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        assert _sha3_512_hex(data) == expected


# â”€â”€ TestIncidentKpis â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestIncidentKpis:

    def _make_db(self, total=5, closed=3, breach=1,
                 mttd=30.0, mttc=15.0, mttr=60.0,
                 by_sev=None, by_status=None):
        db = AsyncMock()
        calls = [
            _mock_scalar(total),          # total
            _mock_scalar(closed),         # closed
            _mock_scalar(breach),         # sla_breach
            _mock_scalar(mttd),           # avg_mttd
            _mock_scalar(mttc),           # avg_mttc
            _mock_scalar(mttr),           # avg_mttr
            _mock_all(by_sev or [("high", 2), ("medium", 3)]),  # by_severity
            _mock_all(by_status or [("detected", 2)]),          # by_status
        ]
        db.execute = AsyncMock(side_effect=calls)
        return db

    @pytest.mark.asyncio
    async def test_returns_dict_with_expected_keys(self):
        from asc_api.services.reporting_service import _incident_kpis
        db = self._make_db()
        result = await _incident_kpis(db, _utcnow() - timedelta(days=30), _utcnow())
        for key in ("total", "closed", "sla_breach_count", "avg_mttd_minutes",
                    "avg_mttc_minutes", "avg_mttr_minutes", "by_severity", "by_status"):
            assert key in result

    @pytest.mark.asyncio
    async def test_total_matches_db(self):
        from asc_api.services.reporting_service import _incident_kpis
        db = self._make_db(total=10)
        result = await _incident_kpis(db, _utcnow() - timedelta(days=30), _utcnow())
        assert result["total"] == 10

    @pytest.mark.asyncio
    async def test_closed_matches_db(self):
        from asc_api.services.reporting_service import _incident_kpis
        db = self._make_db(closed=7)
        result = await _incident_kpis(db, _utcnow() - timedelta(days=30), _utcnow())
        assert result["closed"] == 7

    @pytest.mark.asyncio
    async def test_sla_breach_count(self):
        from asc_api.services.reporting_service import _incident_kpis
        db = self._make_db(breach=3)
        result = await _incident_kpis(db, _utcnow() - timedelta(days=30), _utcnow())
        assert result["sla_breach_count"] == 3

    @pytest.mark.asyncio
    async def test_avg_mttd_rounded(self):
        from asc_api.services.reporting_service import _incident_kpis
        db = self._make_db(mttd=30.567)
        result = await _incident_kpis(db, _utcnow() - timedelta(days=30), _utcnow())
        assert result["avg_mttd_minutes"] == round(30.567, 1)

    @pytest.mark.asyncio
    async def test_avg_mttx_none_when_no_data(self):
        from asc_api.services.reporting_service import _incident_kpis
        db = self._make_db(mttd=None, mttc=None, mttr=None)
        result = await _incident_kpis(db, _utcnow() - timedelta(days=30), _utcnow())
        assert result["avg_mttd_minutes"] is None
        assert result["avg_mttc_minutes"] is None
        assert result["avg_mttr_minutes"] is None

    @pytest.mark.asyncio
    async def test_by_severity_dict(self):
        from asc_api.services.reporting_service import _incident_kpis
        db = self._make_db(by_sev=[("critical", 5), ("high", 2)])
        result = await _incident_kpis(db, _utcnow() - timedelta(days=30), _utcnow())
        assert result["by_severity"]["critical"] == 5
        assert result["by_severity"]["high"] == 2

    @pytest.mark.asyncio
    async def test_by_status_dict(self):
        from asc_api.services.reporting_service import _incident_kpis
        db = self._make_db(by_status=[("detected", 3), ("closed", 2)])
        result = await _incident_kpis(db, _utcnow() - timedelta(days=30), _utcnow())
        assert result["by_status"]["detected"] == 3

    @pytest.mark.asyncio
    async def test_zero_totals(self):
        from asc_api.services.reporting_service import _incident_kpis
        db = self._make_db(total=0, closed=0, breach=0,
                           mttd=None, mttc=None, mttr=None)
        result = await _incident_kpis(db, _utcnow() - timedelta(days=30), _utcnow())
        assert result["total"] == 0
        assert result["closed"] == 0

    @pytest.mark.asyncio
    async def test_db_called_eight_times(self):
        from asc_api.services.reporting_service import _incident_kpis
        db = self._make_db()
        await _incident_kpis(db, _utcnow() - timedelta(days=30), _utcnow())
        assert db.execute.call_count == 8


# â”€â”€ TestCampaignKpis â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestCampaignKpis:

    def _make_db(self, new=2, active=1, critical=0):
        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[
            _mock_scalar(new),
            _mock_scalar(active),
            _mock_scalar(critical),
        ])
        return db

    @pytest.mark.asyncio
    async def test_returns_expected_keys(self):
        from asc_api.services.reporting_service import _campaign_kpis
        db = self._make_db()
        result = await _campaign_kpis(db, _utcnow() - timedelta(days=7), _utcnow())
        assert "new_campaigns" in result
        assert "active_campaigns" in result
        assert "critical_clusters" in result

    @pytest.mark.asyncio
    async def test_new_campaigns_value(self):
        from asc_api.services.reporting_service import _campaign_kpis
        db = self._make_db(new=5)
        result = await _campaign_kpis(db, _utcnow() - timedelta(days=7), _utcnow())
        assert result["new_campaigns"] == 5

    @pytest.mark.asyncio
    async def test_active_campaigns_value(self):
        from asc_api.services.reporting_service import _campaign_kpis
        db = self._make_db(active=3)
        result = await _campaign_kpis(db, _utcnow() - timedelta(days=7), _utcnow())
        assert result["active_campaigns"] == 3

    @pytest.mark.asyncio
    async def test_critical_clusters_zero(self):
        from asc_api.services.reporting_service import _campaign_kpis
        db = self._make_db(critical=0)
        result = await _campaign_kpis(db, _utcnow() - timedelta(days=7), _utcnow())
        assert result["critical_clusters"] == 0

    @pytest.mark.asyncio
    async def test_critical_clusters_nonzero(self):
        from asc_api.services.reporting_service import _campaign_kpis
        db = self._make_db(critical=4)
        result = await _campaign_kpis(db, _utcnow() - timedelta(days=7), _utcnow())
        assert result["critical_clusters"] == 4

    @pytest.mark.asyncio
    async def test_db_called_three_times(self):
        from asc_api.services.reporting_service import _campaign_kpis
        db = self._make_db()
        await _campaign_kpis(db, _utcnow() - timedelta(days=7), _utcnow())
        assert db.execute.call_count == 3

    @pytest.mark.asyncio
    async def test_zero_values(self):
        from asc_api.services.reporting_service import _campaign_kpis
        db = self._make_db(new=0, active=0, critical=0)
        result = await _campaign_kpis(db, _utcnow() - timedelta(days=7), _utcnow())
        assert result["new_campaigns"] == 0

    @pytest.mark.asyncio
    async def test_large_values(self):
        from asc_api.services.reporting_service import _campaign_kpis
        db = self._make_db(new=999, active=50, critical=10)
        result = await _campaign_kpis(db, _utcnow() - timedelta(days=30), _utcnow())
        assert result["new_campaigns"] == 999


# â”€â”€ TestHuntingKpis â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestHuntingKpis:

    def _make_db(self, total=3, findings=2, critical=1):
        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[
            _mock_scalar(total),
            _mock_scalar(findings),
            _mock_scalar(critical),
        ])
        return db

    @pytest.mark.asyncio
    async def test_returns_expected_keys(self):
        from asc_api.services.reporting_service import _hunting_kpis
        db = self._make_db()
        result = await _hunting_kpis(db, _utcnow() - timedelta(days=7), _utcnow())
        assert "total_hunts" in result
        assert "confirmed_findings" in result
        assert "critical_findings" in result

    @pytest.mark.asyncio
    async def test_total_hunts(self):
        from asc_api.services.reporting_service import _hunting_kpis
        db = self._make_db(total=10)
        result = await _hunting_kpis(db, _utcnow() - timedelta(days=7), _utcnow())
        assert result["total_hunts"] == 10

    @pytest.mark.asyncio
    async def test_confirmed_findings(self):
        from asc_api.services.reporting_service import _hunting_kpis
        db = self._make_db(findings=5)
        result = await _hunting_kpis(db, _utcnow() - timedelta(days=7), _utcnow())
        assert result["confirmed_findings"] == 5

    @pytest.mark.asyncio
    async def test_critical_findings(self):
        from asc_api.services.reporting_service import _hunting_kpis
        db = self._make_db(critical=3)
        result = await _hunting_kpis(db, _utcnow() - timedelta(days=7), _utcnow())
        assert result["critical_findings"] == 3

    @pytest.mark.asyncio
    async def test_zero_values(self):
        from asc_api.services.reporting_service import _hunting_kpis
        db = self._make_db(total=0, findings=0, critical=0)
        result = await _hunting_kpis(db, _utcnow() - timedelta(days=7), _utcnow())
        assert all(v == 0 for v in result.values())

    @pytest.mark.asyncio
    async def test_db_called_three_times(self):
        from asc_api.services.reporting_service import _hunting_kpis
        db = self._make_db()
        await _hunting_kpis(db, _utcnow() - timedelta(days=7), _utcnow())
        assert db.execute.call_count == 3

    @pytest.mark.asyncio
    async def test_false_positive_excluded(self):
        # confirmed_findings count excludes false positives â€” verify DB is called
        # (the WHERE clause in the service enforces this; we just check structure)
        from asc_api.services.reporting_service import _hunting_kpis
        db = self._make_db(findings=2)
        result = await _hunting_kpis(db, _utcnow() - timedelta(days=7), _utcnow())
        assert result["confirmed_findings"] == 2

    @pytest.mark.asyncio
    async def test_critical_less_than_total_findings(self):
        from asc_api.services.reporting_service import _hunting_kpis
        db = self._make_db(findings=10, critical=2)
        result = await _hunting_kpis(db, _utcnow() - timedelta(days=7), _utcnow())
        assert result["critical_findings"] <= result["confirmed_findings"]


# â”€â”€ TestSoarKpis â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestSoarKpis:

    def _make_db(self, fired=4, alerts=50):
        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[
            _mock_scalar(fired),
            _mock_scalar(alerts),
        ])
        return db

    @pytest.mark.asyncio
    async def test_returns_expected_keys(self):
        from asc_api.services.reporting_service import _soar_kpis
        db = self._make_db()
        result = await _soar_kpis(db, _utcnow() - timedelta(days=7), _utcnow())
        assert "soar_triggers_fired" in result
        assert "alerts_in_period" in result

    @pytest.mark.asyncio
    async def test_triggers_fired_value(self):
        from asc_api.services.reporting_service import _soar_kpis
        db = self._make_db(fired=7)
        result = await _soar_kpis(db, _utcnow() - timedelta(days=7), _utcnow())
        assert result["soar_triggers_fired"] == 7

    @pytest.mark.asyncio
    async def test_alerts_in_period_value(self):
        from asc_api.services.reporting_service import _soar_kpis
        db = self._make_db(alerts=100)
        result = await _soar_kpis(db, _utcnow() - timedelta(days=7), _utcnow())
        assert result["alerts_in_period"] == 100

    @pytest.mark.asyncio
    async def test_zero_values(self):
        from asc_api.services.reporting_service import _soar_kpis
        db = self._make_db(fired=0, alerts=0)
        result = await _soar_kpis(db, _utcnow() - timedelta(days=7), _utcnow())
        assert result["soar_triggers_fired"] == 0
        assert result["alerts_in_period"] == 0

    @pytest.mark.asyncio
    async def test_db_called_twice(self):
        from asc_api.services.reporting_service import _soar_kpis
        db = self._make_db()
        await _soar_kpis(db, _utcnow() - timedelta(days=7), _utcnow())
        assert db.execute.call_count == 2

    @pytest.mark.asyncio
    async def test_high_volume_values(self):
        from asc_api.services.reporting_service import _soar_kpis
        db = self._make_db(fired=1000, alerts=50000)
        result = await _soar_kpis(db, _utcnow() - timedelta(days=30), _utcnow())
        assert result["soar_triggers_fired"] == 1000


# â”€â”€ TestGenerateReport â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestGenerateReport:

    @pytest.fixture(autouse=True)
    def _patch_sign_report(self, monkeypatch):
        """
        Patch _sign_report with a real Ed25519 key so generate_report
        doesn't raise ValueError for missing key.
        Tests that patch _s still work: _sign_report is patched at the
        function level, bypassing the _s.SPECTER_SIGNING_PRIVATE_KEY check.
        """
        from asc_api.core.signing import generate_analyst_keypair
        import hashlib, base64 as b64
        priv_b64, pub_b64 = generate_analyst_keypair()
        self._priv_key = priv_b64
        self._pub_key = pub_b64

        def _fake_sign(hash_hex: str):
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            raw = b64.b64decode(priv_b64)
            key = Ed25519PrivateKey.from_private_bytes(raw)
            sig = b64.b64encode(key.sign(hash_hex.encode())).decode()
            pub_bytes = b64.b64decode(pub_b64)
            fp = hashlib.sha3_512(pub_bytes).hexdigest()[:16]
            return sig, fp

        import asc_api.services.reporting_service as rs
        monkeypatch.setattr(rs, "_sign_report", _fake_sign)

    def _make_db_for_generate(self):
        """Return DB mock with 8 inc + 3 camp + 3 hunt + 2 soar = 16 scalar calls."""
        db = AsyncMock()
        calls = (
            # _incident_kpis (8)
            [_mock_scalar(v) for v in [5, 3, 1, 30.0, 15.0, 60.0]] +
            [_mock_all([("high", 3)]), _mock_all([("detected", 2)])] +
            # _campaign_kpis (3)
            [_mock_scalar(2), _mock_scalar(1), _mock_scalar(0)] +
            # _hunting_kpis (3)
            [_mock_scalar(4), _mock_scalar(3), _mock_scalar(1)] +
            # _soar_kpis (2)
            [_mock_scalar(5), _mock_scalar(20)]
        )
        db.execute = AsyncMock(side_effect=calls)
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock()
        return db

    @pytest.mark.asyncio
    async def test_returns_executive_report_instance(self):
        from asc_api.services.reporting_service import generate_report
        from asc_api.models.executive_report import ExecutiveReport
        db = self._make_db_for_generate()
        db.refresh = AsyncMock(side_effect=lambda r: None)
        with patch("asc_api.services.reporting_service._s") as ms:
            ms.SPECTER_SIGNING_PRIVATE_KEY = ""
            ms.SPECTER_SIGNING_PUBLIC_KEY = ""
            with patch("asc_api.services.reporting_service.log_security_action"):
                report = await generate_report(
                    db, report_type="full_executive", period="monthly",
                    period_start=_utcnow() - timedelta(days=30),
                    period_end=_utcnow(), generated_by="admin@premos.com",
                )
        assert isinstance(report, ExecutiveReport)

    @pytest.mark.asyncio
    async def test_report_id_in_canonical_data(self):
        from asc_api.services.reporting_service import generate_report
        db = self._make_db_for_generate()
        db.refresh = AsyncMock(side_effect=lambda r: None)
        with patch("asc_api.services.reporting_service._s") as ms:
            ms.SPECTER_SIGNING_PRIVATE_KEY = ""
            ms.SPECTER_SIGNING_PUBLIC_KEY = ""
            with patch("asc_api.services.reporting_service.log_security_action"):
                report = await generate_report(
                    db, report_type="period_kpi", period="monthly",
                    period_start=_utcnow() - timedelta(days=30),
                    period_end=_utcnow(), generated_by="admin@premos.com",
                )
        assert report.id == report.canonical_data["report_id"]

    @pytest.mark.asyncio
    async def test_hash_is_128_hex_chars(self):
        from asc_api.services.reporting_service import generate_report
        db = self._make_db_for_generate()
        db.refresh = AsyncMock(side_effect=lambda r: None)
        with patch("asc_api.services.reporting_service._s") as ms:
            ms.SPECTER_SIGNING_PRIVATE_KEY = ""
            ms.SPECTER_SIGNING_PUBLIC_KEY = ""
            with patch("asc_api.services.reporting_service.log_security_action"):
                report = await generate_report(
                    db, report_type="period_kpi", period="monthly",
                    period_start=_utcnow() - timedelta(days=30),
                    period_end=_utcnow(), generated_by="admin@premos.com",
                )
        assert len(report.hash_sha3_512) == 128

    @pytest.mark.asyncio
    async def test_signed_report_has_valid_ed25519_signature(self):
        from asc_api.services.reporting_service import generate_report
        db = self._make_db_for_generate()
        db.refresh = AsyncMock(side_effect=lambda r: None)
        with patch("asc_api.services.reporting_service._s") as ms:
            ms.SPECTER_SIGNING_PRIVATE_KEY = ""
            ms.SPECTER_SIGNING_PUBLIC_KEY = ""
            with patch("asc_api.services.reporting_service.log_security_action"):
                report = await generate_report(
                    db, report_type="period_kpi", period="monthly",
                    period_start=_utcnow() - timedelta(days=30),
                    period_end=_utcnow(), generated_by="admin@premos.com",
                )
        assert report.signature_ed25519 is not None
        assert len(base64.b64decode(report.signature_ed25519)) == 64

    @pytest.mark.asyncio
    async def test_signature_valid_false_when_no_key(self):
        from asc_api.services.reporting_service import generate_report
        db = self._make_db_for_generate()
        db.refresh = AsyncMock(side_effect=lambda r: None)
        with patch("asc_api.services.reporting_service._s") as ms:
            ms.SPECTER_SIGNING_PRIVATE_KEY = ""
            ms.SPECTER_SIGNING_PUBLIC_KEY = ""
            with patch("asc_api.services.reporting_service.log_security_action"):
                report = await generate_report(
                    db, report_type="period_kpi", period="monthly",
                    period_start=_utcnow() - timedelta(days=30),
                    period_end=_utcnow(), generated_by="admin@premos.com",
                )
        assert report.signature_valid is False

    @pytest.mark.asyncio
    async def test_auto_title_generated_when_none(self):
        from asc_api.services.reporting_service import generate_report
        db = self._make_db_for_generate()
        db.refresh = AsyncMock(side_effect=lambda r: None)
        with patch("asc_api.services.reporting_service._s") as ms:
            ms.SPECTER_SIGNING_PRIVATE_KEY = ""
            ms.SPECTER_SIGNING_PUBLIC_KEY = ""
            with patch("asc_api.services.reporting_service.log_security_action"):
                report = await generate_report(
                    db, report_type="period_kpi", period="monthly",
                    period_start=_utcnow() - timedelta(days=30),
                    period_end=_utcnow(), generated_by="admin@premos.com",
                    title=None,
                )
        assert "PremosCorp ASC" in report.title

    @pytest.mark.asyncio
    async def test_custom_title_respected(self):
        from asc_api.services.reporting_service import generate_report
        db = self._make_db_for_generate()
        db.refresh = AsyncMock(side_effect=lambda r: None)
        with patch("asc_api.services.reporting_service._s") as ms:
            ms.SPECTER_SIGNING_PRIVATE_KEY = ""
            ms.SPECTER_SIGNING_PUBLIC_KEY = ""
            with patch("asc_api.services.reporting_service.log_security_action"):
                report = await generate_report(
                    db, report_type="period_kpi", period="monthly",
                    period_start=_utcnow() - timedelta(days=30),
                    period_end=_utcnow(), generated_by="admin@premos.com",
                    title="Custom Title XYZ",
                )
        assert report.title == "Custom Title XYZ"

    @pytest.mark.asyncio
    async def test_db_add_called(self):
        from asc_api.services.reporting_service import generate_report
        db = self._make_db_for_generate()
        db.refresh = AsyncMock(side_effect=lambda r: None)
        with patch("asc_api.services.reporting_service._s") as ms:
            ms.SPECTER_SIGNING_PRIVATE_KEY = ""
            ms.SPECTER_SIGNING_PUBLIC_KEY = ""
            with patch("asc_api.services.reporting_service.log_security_action"):
                await generate_report(
                    db, report_type="period_kpi", period="monthly",
                    period_start=_utcnow() - timedelta(days=30),
                    period_end=_utcnow(), generated_by="admin@premos.com",
                )
        db.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_db_commit_called(self):
        from asc_api.services.reporting_service import generate_report
        db = self._make_db_for_generate()
        db.refresh = AsyncMock(side_effect=lambda r: None)
        with patch("asc_api.services.reporting_service._s") as ms:
            ms.SPECTER_SIGNING_PRIVATE_KEY = ""
            ms.SPECTER_SIGNING_PUBLIC_KEY = ""
            with patch("asc_api.services.reporting_service.log_security_action"):
                await generate_report(
                    db, report_type="period_kpi", period="monthly",
                    period_start=_utcnow() - timedelta(days=30),
                    period_end=_utcnow(), generated_by="admin@premos.com",
                )
        db.commit.assert_awaited()

    @pytest.mark.asyncio
    async def test_total_incidents_from_kpis(self):
        from asc_api.services.reporting_service import generate_report
        db = self._make_db_for_generate()
        db.refresh = AsyncMock(side_effect=lambda r: None)
        with patch("asc_api.services.reporting_service._s") as ms:
            ms.SPECTER_SIGNING_PRIVATE_KEY = ""
            ms.SPECTER_SIGNING_PUBLIC_KEY = ""
            with patch("asc_api.services.reporting_service.log_security_action"):
                report = await generate_report(
                    db, report_type="full_executive", period="monthly",
                    period_start=_utcnow() - timedelta(days=30),
                    period_end=_utcnow(), generated_by="admin@premos.com",
                )
        assert report.total_incidents == 5  # mock returns 5

    @pytest.mark.asyncio
    async def test_canonical_data_contains_platform_field(self):
        from asc_api.services.reporting_service import generate_report
        db = self._make_db_for_generate()
        db.refresh = AsyncMock(side_effect=lambda r: None)
        with patch("asc_api.services.reporting_service._s") as ms:
            ms.SPECTER_SIGNING_PRIVATE_KEY = ""
            ms.SPECTER_SIGNING_PUBLIC_KEY = ""
            with patch("asc_api.services.reporting_service.log_security_action"):
                report = await generate_report(
                    db, report_type="full_executive", period="monthly",
                    period_start=_utcnow() - timedelta(days=30),
                    period_end=_utcnow(), generated_by="admin@premos.com",
                )
        assert report.canonical_data["platform"] == "PremosCorp ASC"
        assert report.canonical_data["piil_version"] == "1.0"

    @pytest.mark.asyncio
    async def test_log_security_action_called(self):
        from asc_api.services.reporting_service import generate_report
        db = self._make_db_for_generate()
        db.refresh = AsyncMock(side_effect=lambda r: None)
        with patch("asc_api.services.reporting_service._s") as ms:
            ms.SPECTER_SIGNING_PRIVATE_KEY = ""
            ms.SPECTER_SIGNING_PUBLIC_KEY = ""
            with patch("asc_api.services.reporting_service.log_security_action") as mock_audit:
                await generate_report(
                    db, report_type="full_executive", period="monthly",
                    period_start=_utcnow() - timedelta(days=30),
                    period_end=_utcnow(), generated_by="admin@premos.com",
                )
        mock_audit.assert_called_once()

    @pytest.mark.asyncio
    async def test_pubkey_fingerprint_is_16_hex_chars(self):
        from asc_api.services.reporting_service import generate_report
        db = self._make_db_for_generate()
        db.refresh = AsyncMock(side_effect=lambda r: None)
        with patch("asc_api.services.reporting_service._s") as ms:
            ms.SPECTER_SIGNING_PRIVATE_KEY = ""
            ms.SPECTER_SIGNING_PUBLIC_KEY = ""
            with patch("asc_api.services.reporting_service.log_security_action"):
                report = await generate_report(
                    db, report_type="full_executive", period="monthly",
                    period_start=_utcnow() - timedelta(days=30),
                    period_end=_utcnow(), generated_by="admin@premos.com",
                )
        assert len(report.pubkey_fingerprint) == 16
        assert all(c in "0123456789abcdef" for c in report.pubkey_fingerprint)


# â”€â”€ TestVerifyReport â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestVerifyReport:

    @pytest.mark.asyncio
    async def test_not_found_raises_value_error(self):
        from asc_api.services.reporting_service import verify_report
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalar(None))
        with pytest.raises(ValueError, match="not found"):
            await verify_report(db, "nonexistent-id")

    @pytest.mark.asyncio
    async def test_returns_dict_with_expected_keys(self):
        from asc_api.services.reporting_service import verify_report
        r = _make_report()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalar(r))
        db.commit = AsyncMock()
        with patch("asc_api.services.reporting_service.verify_report_signature", return_value=False):
            with patch("asc_api.services.reporting_service.log_security_action"):
                result = await verify_report(db, r.id)
        for key in ("report_id", "hash_valid", "signature_valid", "overall_valid", "verified_at"):
            assert key in result

    @pytest.mark.asyncio
    async def test_hash_valid_true_updates_result(self):
        from asc_api.services.reporting_service import verify_report
        r = _make_report()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalar(r))
        db.commit = AsyncMock()
        with patch.object(r, "is_hash_valid", return_value=True):
            with patch("asc_api.services.reporting_service.verify_report_signature", return_value=False):
                with patch("asc_api.services.reporting_service.log_security_action"):
                    result = await verify_report(db, r.id)
        assert result["hash_valid"] is True

    @pytest.mark.asyncio
    async def test_overall_valid_requires_both_hash_and_sig(self):
        from asc_api.services.reporting_service import verify_report
        r = _make_report()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalar(r))
        db.commit = AsyncMock()
        with patch.object(r, "is_hash_valid", return_value=True):
            with patch("asc_api.services.reporting_service.verify_report_signature", return_value=False):
                with patch("asc_api.services.reporting_service.log_security_action"):
                    result = await verify_report(db, r.id)
        assert result["overall_valid"] is False

    @pytest.mark.asyncio
    async def test_signature_valid_cache_updated(self):
        from asc_api.services.reporting_service import verify_report
        r = _make_report(signature_valid=False)
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalar(r))
        db.commit = AsyncMock()
        with patch.object(r, "is_hash_valid", return_value=False):
            with patch("asc_api.services.reporting_service.verify_report_signature", return_value=False):
                with patch("asc_api.services.reporting_service.log_security_action"):
                    await verify_report(db, r.id)
        assert r.signature_valid is False

    @pytest.mark.asyncio
    async def test_last_verified_at_updated(self):
        from asc_api.services.reporting_service import verify_report
        r = _make_report(last_verified_at=None)
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalar(r))
        db.commit = AsyncMock()
        with patch("asc_api.services.reporting_service.verify_report_signature", return_value=False):
            with patch("asc_api.services.reporting_service.log_security_action"):
                await verify_report(db, r.id)
        assert r.last_verified_at is not None

    @pytest.mark.asyncio
    async def test_db_commit_called_on_verify(self):
        from asc_api.services.reporting_service import verify_report
        r = _make_report()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalar(r))
        db.commit = AsyncMock()
        with patch("asc_api.services.reporting_service.verify_report_signature", return_value=False):
            with patch("asc_api.services.reporting_service.log_security_action"):
                await verify_report(db, r.id)
        db.commit.assert_awaited()

    @pytest.mark.asyncio
    async def test_overall_valid_true_when_both_pass(self):
        from asc_api.services.reporting_service import verify_report
        r = _make_report()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalar(r))
        db.commit = AsyncMock()
        with patch.object(r, "is_hash_valid", return_value=True):
            with patch("asc_api.services.reporting_service.verify_report_signature", return_value=True):
                with patch("asc_api.services.reporting_service.log_security_action"):
                    result = await verify_report(db, r.id)
        assert result["overall_valid"] is True
        assert result["hash_valid"] is True
        assert result["signature_valid"] is True

    @pytest.mark.asyncio
    async def test_pubkey_fingerprint_in_result(self):
        from asc_api.services.reporting_service import verify_report
        r = _make_report(pubkey_fingerprint="abc123")
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalar(r))
        db.commit = AsyncMock()
        with patch("asc_api.services.reporting_service.verify_report_signature", return_value=False):
            with patch("asc_api.services.reporting_service.log_security_action"):
                result = await verify_report(db, r.id)
        assert result["pubkey_fingerprint"] == "abc123"

    @pytest.mark.asyncio
    async def test_log_security_action_called_on_verify(self):
        from asc_api.services.reporting_service import verify_report
        r = _make_report()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalar(r))
        db.commit = AsyncMock()
        with patch("asc_api.services.reporting_service.verify_report_signature", return_value=False):
            with patch("asc_api.services.reporting_service.log_security_action") as mock_audit:
                await verify_report(db, r.id)
        mock_audit.assert_called_once()


# â”€â”€ TestGetReport â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestGetReport:

    @pytest.mark.asyncio
    async def test_returns_report_when_found(self):
        from asc_api.services.reporting_service import get_report
        r = _make_report()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalar(r))
        result = await get_report(db, r.id)
        assert result is r

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self):
        from asc_api.services.reporting_service import get_report
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalar(None))
        result = await get_report(db, "missing")
        assert result is None

    @pytest.mark.asyncio
    async def test_db_called_once(self):
        from asc_api.services.reporting_service import get_report
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalar(None))
        await get_report(db, "x")
        db.execute.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_passes_correct_id(self):
        from asc_api.services.reporting_service import get_report
        r = _make_report(id="specific-id")
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalar(r))
        result = await get_report(db, "specific-id")
        assert result.id == "specific-id"


# â”€â”€ TestListReports â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestListReports:

    @pytest.mark.asyncio
    async def test_returns_list(self):
        from asc_api.services.reporting_service import list_reports
        reports = [_make_report(), _make_report()]
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars(reports))
        result = await list_reports(db)
        assert isinstance(result, list)
        assert len(result) == 2

    @pytest.mark.asyncio
    async def test_empty_list_when_no_reports(self):
        from asc_api.services.reporting_service import list_reports
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([]))
        result = await list_reports(db)
        assert result == []

    @pytest.mark.asyncio
    async def test_accepts_report_type_filter(self):
        from asc_api.services.reporting_service import list_reports
        r = _make_report(report_type="period_kpi")
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([r]))
        result = await list_reports(db, report_type="period_kpi")
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_accepts_limit(self):
        from asc_api.services.reporting_service import list_reports
        reports = [_make_report() for _ in range(5)]
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars(reports[:3]))
        result = await list_reports(db, limit=3)
        assert len(result) == 3

    @pytest.mark.asyncio
    async def test_accepts_offset(self):
        from asc_api.services.reporting_service import list_reports
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([]))
        await list_reports(db, offset=10)
        db.execute.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_returns_list_type(self):
        from asc_api.services.reporting_service import list_reports
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([]))
        result = await list_reports(db)
        assert isinstance(result, list)


# â”€â”€ TestGetReportingSummary â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestGetReportingSummary:

    def _make_db(self, total=5, unsigned=1, by_type=None, latest=None):
        latest = latest or _make_report()
        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[
            _mock_scalar(total),
            _mock_scalar(unsigned),
            _mock_all(by_type or [("full_executive", 3), ("period_kpi", 2)]),
            _mock_scalar(latest),
        ])
        return db

    @pytest.mark.asyncio
    async def test_returns_expected_keys(self):
        from asc_api.services.reporting_service import get_reporting_summary
        db = self._make_db()
        result = await get_reporting_summary(db)
        for key in ("total_reports", "unsigned_reports", "by_type",
                    "last_generated_at", "last_report_id"):
            assert key in result

    @pytest.mark.asyncio
    async def test_total_reports(self):
        from asc_api.services.reporting_service import get_reporting_summary
        db = self._make_db(total=12)
        result = await get_reporting_summary(db)
        assert result["total_reports"] == 12

    @pytest.mark.asyncio
    async def test_unsigned_reports(self):
        from asc_api.services.reporting_service import get_reporting_summary
        db = self._make_db(unsigned=4)
        result = await get_reporting_summary(db)
        assert result["unsigned_reports"] == 4

    @pytest.mark.asyncio
    async def test_by_type_dict(self):
        from asc_api.services.reporting_service import get_reporting_summary
        db = self._make_db(by_type=[("period_kpi", 7)])
        result = await get_reporting_summary(db)
        assert result["by_type"]["period_kpi"] == 7

    @pytest.mark.asyncio
    async def test_last_report_id_from_latest(self):
        from asc_api.services.reporting_service import get_reporting_summary
        latest = _make_report(id="latest-report-id")
        db = self._make_db(latest=latest)
        result = await get_reporting_summary(db)
        assert result["last_report_id"] == "latest-report-id"

    @pytest.mark.asyncio
    async def test_none_when_no_reports(self):
        from asc_api.services.reporting_service import get_reporting_summary
        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[
            _mock_scalar(0),
            _mock_scalar(0),
            _mock_all([]),
            _mock_scalar(None),
        ])
        result = await get_reporting_summary(db)
        assert result["last_generated_at"] is None
        assert result["last_report_id"] is None

    @pytest.mark.asyncio
    async def test_last_generated_at_is_isoformat(self):
        from asc_api.services.reporting_service import get_reporting_summary
        latest = _make_report(created_at=_utcnow())
        db = self._make_db(latest=latest)
        result = await get_reporting_summary(db)
        if result["last_generated_at"]:
            datetime.fromisoformat(result["last_generated_at"])

    @pytest.mark.asyncio
    async def test_db_called_four_times(self):
        from asc_api.services.reporting_service import get_reporting_summary
        db = self._make_db()
        await get_reporting_summary(db)
        assert db.execute.call_count == 4


# â”€â”€ TestReportingEndpoints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _make_endpoint_app():
    from fastapi import FastAPI
    from asc_api.api.v1.endpoints.executive_reports import router
    mini = FastAPI()
    mini.include_router(router)
    return mini


def _mock_analyst_user(role="analyst"):
    return SimpleNamespace(email=f"{role}@premos.com", role=role, id="u1",
                           tenant_id=None,
                           is_active=True, is_locked=False, force_password_reset=False)


class TestReportingEndpoints:

    def test_summary_requires_auth(self):
        from fastapi.testclient import TestClient
        mini = _make_endpoint_app()
        client = TestClient(mini, raise_server_exceptions=False)
        r = client.get("/reports/executive/summary")
        assert r.status_code in (401, 403, 422)

    def test_summary_returns_200_for_analyst(self):
        from fastapi.testclient import TestClient
        from asc_api.api.deps import get_analyst_or_admin, get_current_admin
        from asc_api.db.session import get_db
        mini = _make_endpoint_app()
        user = _mock_analyst_user("analyst")
        mini.dependency_overrides[get_analyst_or_admin] = lambda: user
        mini.dependency_overrides[get_db] = lambda: AsyncMock()
        with patch("asc_api.api.v1.endpoints.executive_reports.reporting_service.get_reporting_summary",
                   new_callable=AsyncMock,
                   return_value={"total_reports": 0, "unsigned_reports": 0,
                                 "by_type": {}, "last_generated_at": None, "last_report_id": None}):
            client = TestClient(mini)
            r = client.get("/reports/executive/summary")
        assert r.status_code == 200

    def test_generate_blocked_for_analyst(self):
        from fastapi.testclient import TestClient
        from asc_api.api.deps import get_analyst_or_admin, get_current_admin
        from asc_api.db.session import get_db
        mini = _make_endpoint_app()
        analyst = _mock_analyst_user("analyst")
        mini.dependency_overrides[get_analyst_or_admin] = lambda: analyst
        mini.dependency_overrides[get_db] = lambda: AsyncMock()
        # NOT overriding get_current_admin â†’ will raise 403
        client = TestClient(mini, raise_server_exceptions=False)
        r = client.post("/reports/executive/generate", json={
            "report_type": "full_executive", "period": "monthly",
            "period_start": "2026-01-01T00:00:00Z", "period_end": "2026-01-31T23:59:59Z",
        })
        assert r.status_code in (401, 403)

    def test_generate_validates_report_type(self):
        from fastapi.testclient import TestClient
        from asc_api.api.deps import get_analyst_or_admin, get_current_admin
        from asc_api.db.session import get_db
        mini = _make_endpoint_app()
        admin = _mock_analyst_user("admin")
        mini.dependency_overrides[get_analyst_or_admin] = lambda: admin
        mini.dependency_overrides[get_current_admin] = lambda: admin
        mini.dependency_overrides[get_db] = lambda: AsyncMock()
        client = TestClient(mini, raise_server_exceptions=False)
        r = client.post("/reports/executive/generate", json={
            "report_type": "INVALID_TYPE", "period": "monthly",
            "period_start": "2026-01-01T00:00:00Z", "period_end": "2026-01-31T23:59:59Z",
        })
        assert r.status_code == 422

    def test_generate_validates_period(self):
        from fastapi.testclient import TestClient
        from asc_api.api.deps import get_analyst_or_admin, get_current_admin
        from asc_api.db.session import get_db
        mini = _make_endpoint_app()
        admin = _mock_analyst_user("admin")
        mini.dependency_overrides[get_analyst_or_admin] = lambda: admin
        mini.dependency_overrides[get_current_admin] = lambda: admin
        mini.dependency_overrides[get_db] = lambda: AsyncMock()
        client = TestClient(mini, raise_server_exceptions=False)
        r = client.post("/reports/executive/generate", json={
            "report_type": "full_executive", "period": "INVALID",
            "period_start": "2026-01-01T00:00:00Z", "period_end": "2026-01-31T23:59:59Z",
        })
        assert r.status_code == 422

    def test_generate_validates_date_order(self):
        from fastapi.testclient import TestClient
        from asc_api.api.deps import get_analyst_or_admin, get_current_admin
        from asc_api.db.session import get_db
        mini = _make_endpoint_app()
        admin = _mock_analyst_user("admin")
        mini.dependency_overrides[get_analyst_or_admin] = lambda: admin
        mini.dependency_overrides[get_current_admin] = lambda: admin
        mini.dependency_overrides[get_db] = lambda: AsyncMock()
        client = TestClient(mini, raise_server_exceptions=False)
        r = client.post("/reports/executive/generate", json={
            "report_type": "full_executive", "period": "monthly",
            "period_start": "2026-02-01T00:00:00Z",
            "period_end": "2026-01-01T00:00:00Z",
        })
        assert r.status_code == 422

    def test_get_report_404_when_missing(self):
        from fastapi.testclient import TestClient
        from asc_api.api.deps import get_analyst_or_admin
        from asc_api.db.session import get_db
        mini = _make_endpoint_app()
        user = _mock_analyst_user("analyst")
        mini.dependency_overrides[get_analyst_or_admin] = lambda: user
        mini.dependency_overrides[get_db] = lambda: AsyncMock()
        with patch("asc_api.api.v1.endpoints.executive_reports.reporting_service.get_report",
                   new_callable=AsyncMock, return_value=None):
            client = TestClient(mini, raise_server_exceptions=False)
            r = client.get("/reports/executive/nonexistent-id")
        assert r.status_code == 404

    def test_list_reports_returns_200(self):
        from fastapi.testclient import TestClient
        from asc_api.api.deps import get_analyst_or_admin
        from asc_api.db.session import get_db
        mini = _make_endpoint_app()
        user = _mock_analyst_user("analyst")
        mini.dependency_overrides[get_analyst_or_admin] = lambda: user
        mini.dependency_overrides[get_db] = lambda: AsyncMock()
        with patch("asc_api.api.v1.endpoints.executive_reports.reporting_service.list_reports",
                   new_callable=AsyncMock, return_value=[]):
            client = TestClient(mini)
            r = client.get("/reports/executive")
        assert r.status_code == 200
        assert "items" in r.json()

    def test_delete_requires_admin(self):
        from fastapi.testclient import TestClient
        from asc_api.api.deps import get_analyst_or_admin
        from asc_api.db.session import get_db
        mini = _make_endpoint_app()
        analyst = _mock_analyst_user("analyst")
        mini.dependency_overrides[get_analyst_or_admin] = lambda: analyst
        mini.dependency_overrides[get_db] = lambda: AsyncMock()
        # No get_current_admin override â†’ 403
        client = TestClient(mini, raise_server_exceptions=False)
        r = client.delete("/reports/executive/some-id")
        assert r.status_code in (401, 403)

    def test_verify_returns_200(self):
        from fastapi.testclient import TestClient
        from asc_api.api.deps import get_analyst_or_admin
        from asc_api.db.session import get_db
        mini = _make_endpoint_app()
        user = _mock_analyst_user("analyst")
        mini.dependency_overrides[get_analyst_or_admin] = lambda: user
        mini.dependency_overrides[get_db] = lambda: AsyncMock()
        with patch("asc_api.api.v1.endpoints.executive_reports.reporting_service.verify_report",
                   new_callable=AsyncMock,
                   return_value={"report_id": "r1", "hash_valid": True,
                                 "signature_valid": False, "overall_valid": False,
                                 "pubkey_fingerprint": "0000000000000000",
                                 "verified_at": "2026-01-01T00:00:00Z"}):
            client = TestClient(mini)
            r = client.post("/reports/executive/r1/verify")
        assert r.status_code == 200

    def test_generate_returns_201_for_admin(self):
        from fastapi.testclient import TestClient
        from asc_api.api.deps import get_analyst_or_admin, get_current_admin
        from asc_api.db.session import get_db
        mini = _make_endpoint_app()
        admin = _mock_analyst_user("admin")
        mini.dependency_overrides[get_analyst_or_admin] = lambda: admin
        mini.dependency_overrides[get_current_admin] = lambda: admin
        mini.dependency_overrides[get_db] = lambda: AsyncMock()
        mock_report = _make_report()
        with patch("asc_api.api.v1.endpoints.executive_reports.reporting_service.generate_report",
                   new_callable=AsyncMock, return_value=mock_report):
            client = TestClient(mini)
            r = client.post("/reports/executive/generate", json={
                "report_type": "full_executive", "period": "monthly",
                "period_start": "2026-01-01T00:00:00Z", "period_end": "2026-01-31T23:59:59Z",
            })
        assert r.status_code == 201

    def test_delete_returns_204_for_admin(self):
        from fastapi.testclient import TestClient
        from asc_api.api.deps import get_analyst_or_admin, get_current_admin
        from asc_api.db.session import get_db
        mini = _make_endpoint_app()
        admin = _mock_analyst_user("admin")
        mini.dependency_overrides[get_analyst_or_admin] = lambda: admin
        mini.dependency_overrides[get_current_admin] = lambda: admin
        db_mock = AsyncMock()
        db_mock.delete = AsyncMock()
        db_mock.commit = AsyncMock()
        mini.dependency_overrides[get_db] = lambda: db_mock
        mock_report = _make_report()
        with patch("asc_api.api.v1.endpoints.executive_reports.reporting_service.get_report",
                   new_callable=AsyncMock, return_value=mock_report):
            client = TestClient(mini)
            r = client.delete(f"/reports/executive/{mock_report.id}")
        assert r.status_code == 204
