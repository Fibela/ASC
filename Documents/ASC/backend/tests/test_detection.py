"""
Detection tests — covers:
  - services/detection.py (pure unit, no DB)
  - GET /detection/rules endpoint (DB-backed via conftest fixtures)
"""
import uuid
from datetime import datetime, timezone, timedelta

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.services.detection import (
    check_suspicious_process,
    check_hook_detection,
    check_registry_persistence,
    check_deferred_traffic,
    evaluate_event,
    evaluate_bulk,
    DEFERRED_THRESHOLD_HOURS,
)


# ─── DET-001: Suspicious acord32.exe ──────────────────────────────────────────

class TestSuspiciousProcess:
    def test_acord32_with_two_params_is_critical(self):
        event = {"process": "acord32.exe", "args": "/s /o"}
        result = check_suspicious_process(event)
        assert result is not None
        assert result.rule_id == "DET-001"
        assert result.severity == "critical"
        assert result.semaphore == "red"
        assert result.risk_score == 0.88

    def test_acord32_with_one_param_is_high(self):
        event = {"process": "C:\\Program Files\\acord32.exe", "args": "/silent"}
        result = check_suspicious_process(event)
        assert result is not None
        assert result.severity == "high"
        assert result.risk_score == 0.70

    def test_acord32_clean_args_no_match(self):
        event = {"process": "acord32.exe", "args": "/help"}
        result = check_suspicious_process(event)
        assert result is None

    def test_acord32_no_args_no_match(self):
        event = {"process": "acord32.exe", "args": ""}
        result = check_suspicious_process(event)
        assert result is None

    def test_unrelated_process_no_match(self):
        event = {"process": "notepad.exe", "args": "/s /o"}
        result = check_suspicious_process(event)
        assert result is None

    def test_command_line_field_used_as_fallback(self):
        event = {"process": "acord32.exe", "command_line": "acord32.exe /noui /q"}
        result = check_suspicious_process(event)
        assert result is not None
        assert result.severity == "critical"

    def test_mitre_ttp_tag(self):
        event = {"process": "acord32.exe", "args": "/s"}
        result = check_suspicious_process(event)
        assert result.mitre_ttp == "T1036.005"

    def test_evidence_contains_process_and_params(self):
        event = {"process": "acord32.exe", "args": "/o", "host": "PREMOS-WS-01", "pid": 1234}
        result = check_suspicious_process(event)
        assert result.evidence["process"] == "acord32.exe"
        assert result.evidence["host"] == "PREMOS-WS-01"
        assert result.evidence["pid"] == 1234
        assert "/o" in result.evidence["suspicious_params"]

    def test_case_insensitive_process_name(self):
        event = {"process": "ACORD32.EXE", "args": "/S"}
        result = check_suspicious_process(event)
        assert result is not None


# ─── DET-002: Windows Hook APIs ───────────────────────────────────────────────

class TestHookDetection:
    def test_setwindowshookexw_is_critical(self):
        event = {"api_call": "SetWindowsHookExW", "pid": 9999}
        result = check_hook_detection(event)
        assert result is not None
        assert result.rule_id == "DET-002"
        assert result.severity == "critical"
        assert result.risk_score == 0.85

    def test_setwindowshookexA_is_critical(self):
        event = {"api_call": "SetWindowsHookExA"}
        result = check_hook_detection(event)
        assert result is not None
        assert result.severity == "critical"

    def test_findwindoww_is_medium(self):
        event = {"api_call": "FindWindowW"}
        result = check_hook_detection(event)
        assert result is not None
        assert result.severity == "medium"
        assert result.risk_score == 0.55

    def test_findwindowexw_is_medium(self):
        event = {"action": "FindWindowExW"}
        result = check_hook_detection(event)
        assert result is not None
        assert result.severity == "medium"

    def test_unrelated_api_no_match(self):
        event = {"api_call": "CreateFile"}
        result = check_hook_detection(event)
        assert result is None

    def test_empty_event_no_match(self):
        result = check_hook_detection({})
        assert result is None

    def test_mitre_ttp(self):
        result = check_hook_detection({"api_call": "SetWindowsHookExW"})
        assert result.mitre_ttp == "T1056.001"

    def test_semaphore_red_for_hook(self):
        result = check_hook_detection({"api_call": "SetWindowsHookExW"})
        assert result.semaphore == "red"

    def test_semaphore_yellow_for_findwindow(self):
        result = check_hook_detection({"api_call": "FindWindowA"})
        assert result.semaphore == "yellow"


# ─── DET-003: Registry Persistence ───────────────────────────────────────────

class TestRegistryPersistence:
    def _run_reg(self):
        return {
            "api_call":    "RegSetValueExW",
            "registry_key": r"software\microsoft\windows\currentversion\run\backdoor",
        }

    def test_regsetvalueex_on_run_key(self):
        result = check_registry_persistence(self._run_reg())
        assert result is not None
        assert result.rule_id == "DET-003"
        assert result.severity == "high"
        assert result.risk_score == 0.80

    def test_regcreatekey_on_runonce(self):
        event = {
            "api_call":    "RegCreateKeyW",
            "registry_key": r"software\microsoft\windows\currentversion\runonce\evil",
        }
        result = check_registry_persistence(event)
        assert result is not None
        assert "runonce" in result.evidence["registry_key"]

    def test_regdeletekey_on_run_key_detected(self):
        event = {
            "api_call":    "RegDeleteKeyW",
            "registry_key": r"software\microsoft\windows\currentversion\run\cleanup",
        }
        result = check_registry_persistence(event)
        assert result is not None
        assert result.evidence["operation"] == "delete"
        assert "limpiar huellas" in result.description

    def test_api_without_persistence_key_no_match(self):
        event = {
            "api_call":    "RegSetValueExW",
            "registry_key": r"software\myapp\settings",
        }
        result = check_registry_persistence(event)
        assert result is None

    def test_persistence_key_without_registry_api_no_match(self):
        event = {
            "api_call":    "CreateFile",
            "registry_key": r"software\microsoft\windows\currentversion\run\evil",
        }
        result = check_registry_persistence(event)
        assert result is None

    def test_winlogon_key_detected(self):
        event = {
            "api_call":    "RegSetValueExA",
            "registry_key": r"software\microsoft\windows nt\currentversion\winlogon\userinit",
        }
        result = check_registry_persistence(event)
        assert result is not None

    def test_mitre_ttp(self):
        result = check_registry_persistence(self._run_reg())
        assert result.mitre_ttp == "T1547.001"

    def test_semaphore_red(self):
        result = check_registry_persistence(self._run_reg())
        assert result.semaphore == "red"


# ─── DET-004: Deferred Traffic ────────────────────────────────────────────────

class TestDeferredTraffic:
    def _base_ts(self):
        return datetime(2025, 6, 1, 12, 0, 0, tzinfo=timezone.utc)

    def _conn_after(self, hours: float) -> dict:
        ts = self._base_ts() + timedelta(hours=hours)
        return {
            "timestamp":  ts.isoformat(),
            "dst_ip":     "185.220.101.45",
            "dst_port":   443,
            "protocol":   "tcp",
            "host":       "PREMOS-WS-10",
            "category":   "network",
        }

    def test_connection_after_25h_is_critical(self):
        result = check_deferred_traffic(self._conn_after(25), self._base_ts())
        assert result is not None
        assert result.severity == "critical"
        assert result.risk_score == 0.90
        assert result.semaphore == "red"

    def test_connection_after_3h_is_high(self):
        result = check_deferred_traffic(self._conn_after(3), self._base_ts())
        assert result is not None
        assert result.severity == "high"
        assert result.risk_score == 0.75

    def test_connection_exactly_at_threshold_no_match(self):
        # At exactly DEFERRED_THRESHOLD_HOURS it should NOT trigger (< threshold)
        result = check_deferred_traffic(
            self._conn_after(DEFERRED_THRESHOLD_HOURS),
            self._base_ts(),
        )
        assert result is None

    def test_connection_before_threshold_no_match(self):
        result = check_deferred_traffic(self._conn_after(0.5), self._base_ts())
        assert result is None

    def test_missing_timestamp_no_match(self):
        event = {"dst_ip": "1.2.3.4", "host": "WS"}
        result = check_deferred_traffic(event, self._base_ts())
        assert result is None

    def test_invalid_timestamp_no_match(self):
        event = {"timestamp": "not-a-date", "dst_ip": "1.2.3.4"}
        result = check_deferred_traffic(event, self._base_ts())
        assert result is None

    def test_mitre_ttp(self):
        result = check_deferred_traffic(self._conn_after(30), self._base_ts())
        assert result.mitre_ttp == "T1071.001"

    def test_evidence_contains_delay(self):
        result = check_deferred_traffic(self._conn_after(5), self._base_ts())
        assert result.evidence["delay_hours"] == pytest.approx(5.0, abs=0.1)
        assert result.evidence["dst_ip"] == "185.220.101.45"

    def test_z_suffix_timestamp_parsed(self):
        ts = self._base_ts() + timedelta(hours=4)
        event = {"timestamp": ts.strftime("%Y-%m-%dT%H:%M:%SZ"), "dst_ip": "10.0.0.1"}
        result = check_deferred_traffic(event, self._base_ts())
        assert result is not None


# ─── evaluate_event: master dispatcher ───────────────────────────────────────

class TestEvaluateEvent:
    def test_multiple_rules_can_fire_for_one_event(self):
        # DET-001 + DET-002 fire from a single event with process+api_call
        event = {
            "process":  "acord32.exe",
            "args":     "/s /o",
            "api_call": "SetWindowsHookExW",
        }
        results = evaluate_event(event)
        rule_ids = {r.rule_id for r in results}
        assert "DET-001" in rule_ids
        assert "DET-002" in rule_ids
        # DET-003 requires a registry API call (separate from hook API)
        # and a persistence key — covered in TestRegistryPersistence separately

    def test_registry_fires_independently(self):
        # DET-003 fires when both a registry API and a persistence key are present
        event = {
            "api_call":     "RegSetValueExW",
            "registry_key": r"software\microsoft\windows\currentversion\run\malware",
        }
        results = evaluate_event(event)
        rule_ids = {r.rule_id for r in results}
        assert "DET-003" in rule_ids

    def test_clean_event_returns_empty_list(self):
        results = evaluate_event({"process": "notepad.exe", "args": ""})
        assert results == []

    def test_deferred_traffic_requires_network_category_and_ts(self):
        now = datetime.now(timezone.utc)
        conn_ts = now + timedelta(hours=10)
        event = {
            "timestamp": conn_ts.isoformat(),
            "dst_ip":    "1.2.3.4",
            "category":  "network",
        }
        results = evaluate_event(event, original_analysis_ts=now - timedelta(hours=10))
        assert any(r.rule_id == "DET-004" for r in results)

    def test_deferred_traffic_ignored_without_original_ts(self):
        event = {"timestamp": datetime.now(timezone.utc).isoformat(), "category": "network"}
        results = evaluate_event(event, original_analysis_ts=None)
        assert not any(r.rule_id == "DET-004" for r in results)


# ─── evaluate_bulk: deduplication ────────────────────────────────────────────

class TestEvaluateBulk:
    def test_same_rule_same_host_deduplicated(self):
        events = [
            {"process": "acord32.exe", "args": "/s", "host": "HOST-A"},
            {"process": "acord32.exe", "args": "/o", "host": "HOST-A"},
        ]
        results = evaluate_bulk(events)
        det001 = [r for r in results if r.rule_id == "DET-001"]
        assert len(det001) == 1  # deduplicated

    def test_same_rule_different_hosts_not_deduplicated(self):
        events = [
            {"process": "acord32.exe", "args": "/s", "host": "HOST-A"},
            {"process": "acord32.exe", "args": "/o", "host": "HOST-B"},
        ]
        results = evaluate_bulk(events)
        det001 = [r for r in results if r.rule_id == "DET-001"]
        assert len(det001) == 2

    def test_empty_events_returns_empty(self):
        assert evaluate_bulk([]) == []

    def test_bulk_returns_all_matching_rules(self):
        events = [
            {"process": "acord32.exe", "args": "/s /o", "host": "H"},
            {"api_call": "SetWindowsHookExW", "host": "H"},
        ]
        results = evaluate_bulk(events)
        rule_ids = {r.rule_id for r in results}
        assert rule_ids == {"DET-001", "DET-002"}


# ─── GET /detection/rules — real DB endpoint tests ───────────────────────────

from asc_api.models.detection_rule import DetectionRule


def _make_rule(rule_id: str, **kwargs) -> DetectionRule:
    now = datetime.now(timezone.utc)
    defaults = {
        "DET-001": dict(name="Suspicious acord32.exe Execution", mitre_ttp="T1036.005", severity="critical/high"),
        "DET-002": dict(name="Windows Hook API Detected", mitre_ttp="T1056.001", severity="critical/medium"),
        "DET-003": dict(name="Registry Persistence Mechanism", mitre_ttp="T1547.001", severity="high"),
        "DET-004": dict(name="Deferred Network Traffic", mitre_ttp="T1071.001", severity="critical/high"),
    }
    d = defaults.get(rule_id, {}).copy()
    d.update(kwargs)
    return DetectionRule(
        id=str(uuid.uuid4()),
        rule_id=rule_id,
        name=d.get("name", f"Rule {rule_id}"),
        mitre_ttp=d.get("mitre_ttp", "T0000"),
        severity=d.get("severity", "medium"),
        description=d.get("description", f"Test description for {rule_id}"),
        tags=d.get("tags", []),
        risk_score_default=d.get("risk_score_default", 0.5),
        is_active=d.get("is_active", True),
        created_at=now,
        updated_at=now,
    )


@pytest_asyncio.fixture
async def seeded_rules(db: AsyncSession):
    """Seed canonical DET-001..004 into the test DB."""
    rules = [_make_rule(r) for r in ("DET-001", "DET-002", "DET-003", "DET-004")]
    for r in rules:
        db.add(r)
    await db.commit()
    return rules


class TestDetectionRulesEndpoint:
    @pytest.mark.asyncio
    async def test_unauthenticated_returns_401(self, client, seeded_rules):
        resp = await client.get("/api/v1/detection/rules")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_analyst_gets_200(self, client, seeded_rules, analyst_headers):
        resp = await client.get("/api/v1/detection/rules", headers=analyst_headers)
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_returns_four_active_rules(self, client, seeded_rules, analyst_headers):
        resp = await client.get("/api/v1/detection/rules", headers=analyst_headers)
        data = resp.json()
        assert "rules" in data
        assert len(data["rules"]) == 4

    @pytest.mark.asyncio
    async def test_rules_ordered_by_rule_id(self, client, seeded_rules, analyst_headers):
        resp = await client.get("/api/v1/detection/rules", headers=analyst_headers)
        ids = [r["rule_id"] for r in resp.json()["rules"]]
        assert ids == sorted(ids)

    @pytest.mark.asyncio
    async def test_rule_has_required_fields(self, client, seeded_rules, analyst_headers):
        resp = await client.get("/api/v1/detection/rules", headers=analyst_headers)
        rule = resp.json()["rules"][0]
        for field in ("rule_id", "name", "mitre_ttp", "severity", "description", "tags", "risk_score"):
            assert field in rule, f"Missing field: {field}"

    @pytest.mark.asyncio
    async def test_det001_mitre_ttp(self, client, seeded_rules, analyst_headers):
        resp = await client.get("/api/v1/detection/rules", headers=analyst_headers)
        det001 = next(r for r in resp.json()["rules"] if r["rule_id"] == "DET-001")
        assert det001["mitre_ttp"] == "T1036.005"

    @pytest.mark.asyncio
    async def test_inactive_rule_excluded(self, client, db: AsyncSession, analyst_headers):
        # Add active + inactive rules
        active = _make_rule("DET-001", is_active=True)
        inactive = _make_rule("DET-002", is_active=False)
        db.add(active)
        db.add(inactive)
        await db.commit()
        resp = await client.get("/api/v1/detection/rules", headers=analyst_headers)
        ids = [r["rule_id"] for r in resp.json()["rules"]]
        assert "DET-001" in ids
        assert "DET-002" not in ids

    @pytest.mark.asyncio
    async def test_empty_db_returns_empty_list(self, client, analyst_headers):
        resp = await client.get("/api/v1/detection/rules", headers=analyst_headers)
        assert resp.status_code == 200
        assert resp.json()["rules"] == []

    @pytest.mark.asyncio
    async def test_fingerprint_checks_present(self, client, seeded_rules, analyst_headers):
        resp = await client.get("/api/v1/detection/rules", headers=analyst_headers)
        data = resp.json()
        assert "fingerprint_checks" in data
        assert len(data["fingerprint_checks"]) > 0

    @pytest.mark.asyncio
    async def test_viewer_gets_200(self, client, seeded_rules, viewer_headers):
        resp = await client.get("/api/v1/detection/rules", headers=viewer_headers)
        assert resp.status_code == 200
