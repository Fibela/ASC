"""
test_correlator.py — Tech Debt TD4: Event Correlation Service
=============================================================

Tests every function in app/services/correlator.py plus verifies:
  - B29 fix: rule_data_exfiltration now fires correctly

Test classes:
  TestMatchIoCs               (9)  — IoC lookup against DB
  TestNormalizeEvent          (8)  — Field mapping and defaults
  TestEvaluateCorrelationRules (13) — All 5 rules + edge cases
  TestGetIoCCoverage          (5)  — Coverage ratio calculation
  TestCorrelationRulesSchema  (4)  — CORRELATION_RULES structure invariants
"""
from __future__ import annotations

import uuid
import pytest
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.models.ioc import IoC
from asc_api.models.alert import Alert
from asc_api.services.correlator import (
    match_iocs,
    normalize_event,
    evaluate_correlation_rules,
    get_ioc_coverage,
    CORRELATION_RULES,
)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _make_ioc(
    value: str = "1.2.3.4",
    ioc_type: str = "ip",
    active: bool = True,
    hit_count: int = 0,
) -> IoC:
    return IoC(
        id=str(uuid.uuid4()),
        value=value,
        ioc_type=ioc_type,
        threat_type="c2",
        confidence=0.85,
        severity="high",
        source="internal",
        active=active,
        hit_count=hit_count,
    )


async def _seed_ioc(db: AsyncSession, **kwargs) -> IoC:
    ioc = _make_ioc(**kwargs)
    db.add(ioc)
    await db.commit()
    await db.refresh(ioc)
    return ioc


# ══════════════════════════════════════════════════════════════════════════════
# 1. match_iocs
# ══════════════════════════════════════════════════════════════════════════════
class TestMatchIoCs:

    async def test_no_iocs_returns_empty(self, db: AsyncSession):
        result = await match_iocs("8.8.8.8", db)
        assert result == []

    async def test_active_ioc_matches(self, db: AsyncSession):
        await _seed_ioc(db, value="evil.com", ioc_type="domain")
        result = await match_iocs("evil.com", db)
        assert len(result) == 1
        assert result[0]["value"] == "evil.com"

    async def test_inactive_ioc_does_not_match(self, db: AsyncSession):
        await _seed_ioc(db, value="inactive.com", active=False)
        result = await match_iocs("inactive.com", db)
        assert result == []

    async def test_different_value_no_match(self, db: AsyncSession):
        await _seed_ioc(db, value="evil.com")
        result = await match_iocs("clean.com", db)
        assert result == []

    async def test_match_returns_required_fields(self, db: AsyncSession):
        await _seed_ioc(db, value="10.0.0.1", ioc_type="ip")
        result = await match_iocs("10.0.0.1", db)
        assert len(result) == 1
        for field in ("ioc_id", "value", "type", "threat", "confidence", "severity"):
            assert field in result[0], f"Missing field: {field}"

    async def test_hit_count_increments_on_match(self, db: AsyncSession):
        ioc = await _seed_ioc(db, value="beacon.io", hit_count=0)
        await match_iocs("beacon.io", db)
        await db.refresh(ioc)
        assert ioc.hit_count == 1

    async def test_multiple_hits_cumulate(self, db: AsyncSession):
        ioc = await _seed_ioc(db, value="c2.evil", hit_count=5)
        await match_iocs("c2.evil", db)
        await db.refresh(ioc)
        assert ioc.hit_count == 6

    async def test_last_seen_updated_on_match(self, db: AsyncSession):
        # SQLite returns naive datetimes even for DateTime(timezone=True) columns;
        # strip tz from the reference to allow comparison.
        before = datetime.now(timezone.utc).replace(tzinfo=None)
        ioc = await _seed_ioc(db, value="timestamp.test")
        await match_iocs("timestamp.test", db)
        await db.refresh(ioc)
        last_seen = ioc.last_seen.replace(tzinfo=None) if ioc.last_seen.tzinfo else ioc.last_seen
        assert last_seen >= before

    async def test_multiple_iocs_same_value_all_match(self, db: AsyncSession):
        await _seed_ioc(db, value="dup.com", ioc_type="domain")
        await _seed_ioc(db, value="dup.com", ioc_type="url")
        result = await match_iocs("dup.com", db)
        assert len(result) == 2


# ══════════════════════════════════════════════════════════════════════════════
# 2. normalize_event
# ══════════════════════════════════════════════════════════════════════════════
class TestNormalizeEvent:

    async def test_empty_dict_all_defaults(self):
        result = await normalize_event({})
        assert result["source"]   == "unknown"
        assert result["category"] == "unknown"
        assert result["host"]     == "unknown"
        assert result["user"]     == ""
        assert result["process"]  == ""
        assert result["tags"]     == []

    async def test_explicit_fields_preserved(self):
        raw = {
            "source": "wazuh", "category": "authentication",
            "action": "login_failed", "host": "WIN-01",
            "user": "bob", "src_ip": "10.0.0.5",
        }
        result = await normalize_event(raw)
        assert result["source"]   == "wazuh"
        assert result["category"] == "authentication"
        assert result["action"]   == "login_failed"
        assert result["host"]     == "WIN-01"
        assert result["user"]     == "bob"
        assert result["src_ip"]   == "10.0.0.5"

    async def test_hostname_alias_mapped_to_host(self):
        result = await normalize_event({"hostname": "SERVER-01"})
        assert result["host"] == "SERVER-01"

    async def test_username_alias_mapped_to_user(self):
        result = await normalize_event({"username": "alice"})
        assert result["user"] == "alice"

    async def test_process_name_alias(self):
        result = await normalize_event({"process_name": "lsass.exe"})
        assert result["process"] == "lsass.exe"

    async def test_dest_ip_alias_mapped(self):
        result = await normalize_event({"dest_ip": "8.8.8.8"})
        assert result["dst_ip"] == "8.8.8.8"

    async def test_tags_preserved(self):
        result = await normalize_event({"tags": ["lateral", "t1021"]})
        assert result["tags"] == ["lateral", "t1021"]

    async def test_timestamp_preserved(self):
        ts = "2026-06-07T00:00:00+00:00"
        result = await normalize_event({"timestamp": ts})
        assert result["timestamp"] == ts


# ══════════════════════════════════════════════════════════════════════════════
# 3. evaluate_correlation_rules
# ══════════════════════════════════════════════════════════════════════════════
class TestEvaluateCorrelationRules:

    async def test_no_events_no_alerts(self, db: AsyncSession):
        result = await evaluate_correlation_rules([], db)
        assert result == []

    # ── rule_brute_force ──────────────────────────────────────────────────────

    async def test_brute_force_fires_on_3_auth_failures(self, db: AsyncSession):
        events = [
            {"category": "authentication", "action": "login_failed", "host": "WIN-01"}
            for _ in range(3)
        ]
        result = await evaluate_correlation_rules(events, db)
        rule_ids = [r["rule_id"] for r in result]
        assert "rule_brute_force" in rule_ids

    async def test_brute_force_does_not_fire_on_2_failures(self, db: AsyncSession):
        events = [
            {"category": "authentication", "action": "login_failed", "host": "WIN-01"}
            for _ in range(2)
        ]
        result = await evaluate_correlation_rules(events, db)
        rule_ids = [r["rule_id"] for r in result]
        assert "rule_brute_force" not in rule_ids

    async def test_brute_force_requires_fail_in_action(self, db: AsyncSession):
        """Successful logins must not trigger brute force rule."""
        events = [
            {"category": "authentication", "action": "login_success", "host": "WIN-01"}
            for _ in range(5)
        ]
        result = await evaluate_correlation_rules(events, db)
        rule_ids = [r["rule_id"] for r in result]
        assert "rule_brute_force" not in rule_ids

    # ── rule_persistence_registry ─────────────────────────────────────────────

    async def test_registry_persistence_fires(self, db: AsyncSession):
        events = [{"category": "registry", "action": "registry_write", "host": "WIN-01"}]
        result = await evaluate_correlation_rules(events, db)
        rule_ids = [r["rule_id"] for r in result]
        assert "rule_persistence_registry" in rule_ids

    async def test_registry_read_does_not_fire(self, db: AsyncSession):
        events = [{"category": "registry", "action": "registry_read", "host": "WIN-01"}]
        result = await evaluate_correlation_rules(events, db)
        rule_ids = [r["rule_id"] for r in result]
        assert "rule_persistence_registry" not in rule_ids

    # ── rule_credential_dump ──────────────────────────────────────────────────

    async def test_lsass_access_fires_cred_dump(self, db: AsyncSession):
        events = [{"category": "process", "process": "lsass.exe", "action": "memory_read"}]
        result = await evaluate_correlation_rules(events, db)
        rule_ids = [r["rule_id"] for r in result]
        assert "rule_credential_dump" in rule_ids

    async def test_mimikatz_in_action_fires_cred_dump(self, db: AsyncSession):
        events = [{"category": "process", "action": "mimikatz_sekurlsa", "process": "cmd.exe"}]
        result = await evaluate_correlation_rules(events, db)
        rule_ids = [r["rule_id"] for r in result]
        assert "rule_credential_dump" in rule_ids

    # ── rule_lateral_movement ─────────────────────────────────────────────────

    async def test_smb_port_445_fires_lateral(self, db: AsyncSession):
        events = [
            {"category": "network", "dst_port": 445, "host": "WIN-01"},
            {"category": "network", "dst_port": 445, "host": "WIN-02"},
        ]
        result = await evaluate_correlation_rules(events, db)
        rule_ids = [r["rule_id"] for r in result]
        assert "rule_lateral_movement" in rule_ids

    async def test_single_smb_event_does_not_fire(self, db: AsyncSession):
        events = [{"category": "network", "dst_port": 445, "host": "WIN-01"}]
        result = await evaluate_correlation_rules(events, db)
        rule_ids = [r["rule_id"] for r in result]
        assert "rule_lateral_movement" not in rule_ids

    # ── rule_data_exfiltration (B29 fix) ─────────────────────────────────────

    async def test_exfil_action_fires_data_exfil_rule(self, db: AsyncSession):
        """B29: rule_data_exfiltration was never implemented — now verified working."""
        events = [{"category": "network", "action": "data_exfil_detected", "dst_ip": "1.2.3.4"}]
        result = await evaluate_correlation_rules(events, db)
        rule_ids = [r["rule_id"] for r in result]
        assert "rule_data_exfiltration" in rule_ids, \
            "B29 regression: rule_data_exfiltration must fire on network exfil events"

    async def test_non_exfil_network_event_does_not_fire(self, db: AsyncSession):
        events = [{"category": "network", "action": "dns_query", "dst_ip": "8.8.8.8"}]
        result = await evaluate_correlation_rules(events, db)
        rule_ids = [r["rule_id"] for r in result]
        assert "rule_data_exfiltration" not in rule_ids

    async def test_multiple_rules_fire_simultaneously(self, db: AsyncSession):
        events = [
            {"category": "authentication", "action": "login_failed"},
            {"category": "authentication", "action": "login_failed"},
            {"category": "authentication", "action": "login_failed"},
            {"category": "process", "process": "lsass.exe", "action": "mem_dump"},
        ]
        result = await evaluate_correlation_rules(events, db)
        rule_ids = [r["rule_id"] for r in result]
        assert "rule_brute_force"    in rule_ids
        assert "rule_credential_dump" in rule_ids


# ══════════════════════════════════════════════════════════════════════════════
# 4. get_ioc_coverage
# ══════════════════════════════════════════════════════════════════════════════
class TestGetIoCCoverage:

    async def test_empty_db_returns_zero(self, db: AsyncSession):
        result = await get_ioc_coverage(db)
        assert result == 0.0

    async def test_no_hits_returns_zero(self, db: AsyncSession):
        await _seed_ioc(db, hit_count=0)
        await _seed_ioc(db, value="2.2.2.2", hit_count=0)
        result = await get_ioc_coverage(db)
        assert result == 0.0

    async def test_partial_coverage(self, db: AsyncSession):
        await _seed_ioc(db, value="hit.com", hit_count=3)
        await _seed_ioc(db, value="miss.com", hit_count=0)
        result = await get_ioc_coverage(db)
        assert result == 0.5

    async def test_full_coverage(self, db: AsyncSession):
        await _seed_ioc(db, value="hit1.com", hit_count=1)
        await _seed_ioc(db, value="hit2.com", hit_count=10)
        result = await get_ioc_coverage(db)
        assert result == 1.0

    async def test_inactive_iocs_excluded(self, db: AsyncSession):
        await _seed_ioc(db, value="active.com", active=True, hit_count=1)
        await _seed_ioc(db, value="inactive.com", active=False, hit_count=999)
        result = await get_ioc_coverage(db)
        assert result == 1.0


# ══════════════════════════════════════════════════════════════════════════════
# 5. CORRELATION_RULES schema invariants
# ══════════════════════════════════════════════════════════════════════════════
class TestCorrelationRulesSchema:

    def test_five_rules_defined(self):
        assert len(CORRELATION_RULES) == 5

    def test_all_rules_have_required_fields(self):
        required = {"id", "name", "description", "category", "severity", "risk_score", "ttps"}
        for rule in CORRELATION_RULES:
            missing = required - set(rule.keys())
            assert not missing, f"Rule '{rule.get('id')}' missing fields: {missing}"

    def test_risk_scores_in_valid_range(self):
        for rule in CORRELATION_RULES:
            assert 0.0 <= rule["risk_score"] <= 1.0, \
                f"Rule '{rule['id']}' has out-of-range risk_score: {rule['risk_score']}"

    def test_data_exfiltration_rule_present(self):
        """B29: this rule existed in CORRELATION_RULES but was never evaluated."""
        ids = [r["id"] for r in CORRELATION_RULES]
        assert "rule_data_exfiltration" in ids
