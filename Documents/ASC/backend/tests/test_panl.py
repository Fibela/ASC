"""
PANL Engine Unit Tests
======================
Tests for all five PANL components:
  - AdaptiveSeverity (adapt_severity + UPGRADE_RULES)
  - BehavioralThrottle (sliding window, threshold, reset)
  - MultiSigPolicy (required_approvals_for)
  - FleetProximity (subnet_proximity scoring)
  - RequestRateLimiter (per-user sliding window)

All tests are pure-function / in-process — no DB, no network, no Celery.
Throttle/limiter singletons are reset before each test to ensure isolation.
"""
from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from app.core.panl import (
    UPGRADE_RULES,
    AdaptiveContext,
    BehavioralThrottle,
    RequestRateLimiter,
    adapt_severity,
    behavioral_throttle,
    check_behavioral_throttle,
    request_rate_limiter,
    required_approvals_for,
    subnet_proximity,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def reset_singletons():
    """Reset all PANL singletons before each test for full isolation."""
    behavioral_throttle.reset_all()
    request_rate_limiter.reset_all()
    yield
    behavioral_throttle.reset_all()
    request_rate_limiter.reset_all()


# ── 1. AdaptiveContext ────────────────────────────────────────────────────────

class TestAdaptiveContext:
    def test_default_all_false(self):
        ctx = AdaptiveContext()
        assert ctx.endpoint_is_critical_infrastructure is False
        assert ctx.active_threat_intel_match is False
        assert ctx.multiple_recent_alerts is False
        assert ctx.known_lateral_movement is False
        assert ctx.ransomware_indicator is False
        assert ctx.agent_labels == []

    def test_from_dict_populates_correctly(self):
        data = {
            "endpoint_is_critical_infrastructure": True,
            "ransomware_indicator": True,
            "agent_labels": ["domain_controller"],
        }
        ctx = AdaptiveContext.from_dict(data)
        assert ctx.endpoint_is_critical_infrastructure is True
        assert ctx.ransomware_indicator is True
        assert ctx.agent_labels == ["domain_controller"]
        assert ctx.known_lateral_movement is False

    def test_from_dict_handles_empty(self):
        ctx = AdaptiveContext.from_dict({})
        assert ctx.endpoint_is_critical_infrastructure is False

    def test_from_dict_falsy_values_become_false(self):
        ctx = AdaptiveContext.from_dict({"active_threat_intel_match": 0})
        assert ctx.active_threat_intel_match is False


# ── 2. AdaptiveSeverity ───────────────────────────────────────────────────────

class TestAdaptSeverity:
    def test_no_context_returns_same_severity(self):
        ctx = AdaptiveContext()
        assert adapt_severity("low", ctx) == "low"
        assert adapt_severity("medium", ctx) == "medium"
        assert adapt_severity("high", ctx) == "high"
        assert adapt_severity("critical", ctx) == "critical"

    def test_critical_infra_upgrades_medium_to_high(self):
        ctx = AdaptiveContext(endpoint_is_critical_infrastructure=True)
        assert adapt_severity("medium", ctx) == "high"

    def test_critical_infra_upgrades_low_to_medium(self):
        ctx = AdaptiveContext(endpoint_is_critical_infrastructure=True)
        assert adapt_severity("low", ctx) == "medium"

    def test_ransomware_upgrades_low_to_high(self):
        ctx = AdaptiveContext(ransomware_indicator=True)
        assert adapt_severity("low", ctx) == "high"

    def test_known_lateral_movement_upgrades_low_to_high(self):
        ctx = AdaptiveContext(known_lateral_movement=True)
        assert adapt_severity("low", ctx) == "high"

    def test_multiple_flags_stack_up_to_critical(self):
        ctx = AdaptiveContext(
            endpoint_is_critical_infrastructure=True,
            ransomware_indicator=True,
        )
        # low(0) + 1 (critical_infra) + 2 (ransomware) = 3 (critical)
        assert adapt_severity("low", ctx) == "critical"

    def test_severity_never_downgraded(self):
        ctx = AdaptiveContext()
        assert adapt_severity("critical", ctx) == "critical"
        assert adapt_severity("high", ctx) == "high"

    def test_caps_at_critical(self):
        ctx = AdaptiveContext(
            endpoint_is_critical_infrastructure=True,
            ransomware_indicator=True,
            known_lateral_movement=True,
            multiple_recent_alerts=True,
            active_threat_intel_match=True,
        )
        result = adapt_severity("low", ctx)
        assert result == "critical"  # capped at 3

    def test_agent_label_critical_infrastructure_promotes_flag(self):
        ctx = AdaptiveContext(agent_labels=["critical_infrastructure"])
        assert adapt_severity("medium", ctx) == "high"

    def test_agent_label_domain_controller_promotes_flag(self):
        ctx = AdaptiveContext(agent_labels=["domain_controller"])
        assert adapt_severity("medium", ctx) == "high"

    def test_upgrade_rules_all_present(self):
        rule_fields = {r[0] for r in UPGRADE_RULES}
        assert "endpoint_is_critical_infrastructure" in rule_fields
        assert "ransomware_indicator" in rule_fields
        assert "known_lateral_movement" in rule_fields

    def test_active_threat_intel_upgrades_medium_to_high(self):
        ctx = AdaptiveContext(active_threat_intel_match=True)
        assert adapt_severity("medium", ctx) == "high"

    def test_unknown_severity_treated_as_medium(self):
        ctx = AdaptiveContext()
        # "unknown" defaults to rank=1 (medium), no flags → stays medium
        result = adapt_severity("unknown_level", ctx)
        assert result == "medium"


# ── 3. BehavioralThrottle ─────────────────────────────────────────────────────

class TestBehavioralThrottle:
    def test_first_request_always_allowed(self):
        bt = BehavioralThrottle()
        assert bt.check("alice@premos.com", "block_ip") is True

    def test_below_threshold_allowed(self):
        bt = BehavioralThrottle()
        for _ in range(BehavioralThrottle.THRESHOLD - 1):
            assert bt.check("alice@premos.com", "block_ip") is True

    def test_at_threshold_blocked(self):
        bt = BehavioralThrottle()
        for _ in range(BehavioralThrottle.THRESHOLD):
            bt.check("alice@premos.com", "block_ip")
        assert bt.check("alice@premos.com", "block_ip") is False

    def test_different_users_independent(self):
        bt = BehavioralThrottle()
        for _ in range(BehavioralThrottle.THRESHOLD):
            bt.check("alice@premos.com", "block_ip")
        # alice throttled, but bob is not
        assert bt.check("bob@premos.com", "block_ip") is True

    def test_different_action_types_independent(self):
        bt = BehavioralThrottle()
        for _ in range(BehavioralThrottle.THRESHOLD):
            bt.check("alice@premos.com", "block_ip")
        # same user, different action_type → different bucket
        assert bt.check("alice@premos.com", "kill_process") is True

    def test_reset_clears_bucket(self):
        bt = BehavioralThrottle()
        for _ in range(BehavioralThrottle.THRESHOLD):
            bt.check("alice@premos.com", "block_ip")
        assert bt.check("alice@premos.com", "block_ip") is False  # throttled
        bt.reset("alice@premos.com", "block_ip")
        assert bt.check("alice@premos.com", "block_ip") is True   # reset, allowed

    def test_reset_all_clears_everything(self):
        bt = BehavioralThrottle()
        for _ in range(BehavioralThrottle.THRESHOLD):
            bt.check("alice@premos.com", "block_ip")
            bt.check("bob@premos.com", "quarantine_file")
        bt.reset_all()
        assert bt.check("alice@premos.com", "block_ip") is True
        assert bt.check("bob@premos.com", "quarantine_file") is True

    def test_count_reflects_window(self):
        bt = BehavioralThrottle()
        for _ in range(5):
            bt.check("carol@premos.com", "block_ip")
        assert bt.count("carol@premos.com", "block_ip") == 5

    def test_expired_timestamps_not_counted(self):
        bt = BehavioralThrottle()
        # Inject old timestamps directly
        key = "dave@premos.com:block_ip"
        old_time = time.time() - bt.WINDOW_SECONDS - 10
        with bt._lock:
            bt._buckets[key] = [old_time] * (bt.THRESHOLD + 5)
        # Old entries should be pruned → new request allowed
        assert bt.check("dave@premos.com", "block_ip") is True


class TestCheckBehavioralThrottle:
    def test_does_not_raise_below_threshold(self):
        for _ in range(BehavioralThrottle.THRESHOLD - 1):
            check_behavioral_throttle("analyst@premos.com", "block_ip")

    def test_raises_value_error_when_throttled(self):
        for _ in range(BehavioralThrottle.THRESHOLD):
            try:
                check_behavioral_throttle("spam@premos.com", "block_ip")
            except ValueError:
                pass  # might raise on the last one

        with pytest.raises(ValueError, match="throttle"):
            check_behavioral_throttle("spam@premos.com", "block_ip")

    def test_logs_security_event_when_throttled(self):
        for _ in range(BehavioralThrottle.THRESHOLD):
            behavioral_throttle.check("log_test@premos.com", "block_ip")

        logged = []
        with patch(
            "app.core.panl.log_security_action",
            side_effect=lambda *a, **kw: logged.append(kw),
        ):
            with pytest.raises(ValueError):
                check_behavioral_throttle("log_test@premos.com", "block_ip")

        assert len(logged) >= 1
        assert any("throttle" in str(entry).lower() for entry in logged)


# ── 4. MultiSig Policy ────────────────────────────────────────────────────────

class TestRequiredApprovalsFor:
    def test_critical_requires_two(self):
        assert required_approvals_for("critical", "block_ip") == 2

    def test_critical_requires_two_for_any_action(self):
        for action in ("block_ip", "kill_process", "quarantine_file", "isolate_endpoint"):
            assert required_approvals_for("critical", action) == 2

    def test_high_requires_one(self):
        assert required_approvals_for("high", "block_ip") == 1

    def test_medium_non_sensitive_requires_zero(self):
        assert required_approvals_for("medium", "block_ip") == 0

    def test_low_non_sensitive_requires_zero(self):
        assert required_approvals_for("low", "block_domain") == 0

    def test_isolate_endpoint_always_requires_one_or_more(self):
        assert required_approvals_for("low", "isolate_endpoint") >= 1
        assert required_approvals_for("medium", "isolate_endpoint") >= 1
        assert required_approvals_for("high", "isolate_endpoint") >= 1

    def test_disable_account_requires_at_least_one(self):
        assert required_approvals_for("low", "disable_account") >= 1


# ── 5. SubnetProximity ────────────────────────────────────────────────────────

class TestSubnetProximity:
    def test_same_ip_returns_zero(self):
        assert subnet_proximity("10.0.1.5", "10.0.1.5") == 0

    def test_same_24_returns_one(self):
        assert subnet_proximity("10.0.1.5", "10.0.1.200") == 1

    def test_same_16_returns_two(self):
        assert subnet_proximity("10.0.1.5", "10.0.200.1") == 2

    def test_same_8_returns_three(self):
        assert subnet_proximity("10.0.1.5", "10.200.1.1") == 3

    def test_different_class_returns_four(self):
        assert subnet_proximity("10.0.1.5", "192.168.1.1") == 4

    def test_none_agent_ip_returns_four(self):
        assert subnet_proximity(None, "10.0.1.5") == 4

    def test_none_target_ip_returns_four(self):
        assert subnet_proximity("10.0.1.5", None) == 4

    def test_both_none_returns_four(self):
        assert subnet_proximity(None, None) == 4

    def test_hostname_target_returns_four(self):
        assert subnet_proximity("10.0.1.5", "workstation-001") == 4

    def test_invalid_ip_returns_four(self):
        assert subnet_proximity("not.an.ip.addr", "10.0.1.5") == 4

    def test_ipv6_like_returns_four(self):
        assert subnet_proximity("::1", "10.0.1.5") == 4

    def test_proximity_ordering(self):
        target = "192.168.1.50"
        # closer agents should score lower
        same_host  = subnet_proximity("192.168.1.50", target)   # 0
        same_24    = subnet_proximity("192.168.1.100", target)   # 1
        same_16    = subnet_proximity("192.168.2.1", target)     # 2
        different  = subnet_proximity("10.0.0.1", target)        # 4
        assert same_host < same_24 < same_16 < different


# ── 6. RequestRateLimiter ─────────────────────────────────────────────────────

class TestRequestRateLimiter:
    def test_first_request_allowed(self):
        rl = RequestRateLimiter()
        assert rl.is_allowed("alice@premos.com") is True

    def test_below_max_allowed(self):
        rl = RequestRateLimiter()
        for _ in range(rl.MAX_REQUESTS - 1):
            assert rl.is_allowed("alice@premos.com") is True

    def test_at_max_blocked(self):
        rl = RequestRateLimiter()
        for _ in range(rl.MAX_REQUESTS):
            rl.is_allowed("alice@premos.com")
        assert rl.is_allowed("alice@premos.com") is False

    def test_different_users_independent(self):
        rl = RequestRateLimiter()
        for _ in range(rl.MAX_REQUESTS):
            rl.is_allowed("alice@premos.com")
        assert rl.is_allowed("bob@premos.com") is True

    def test_reset_clears_bucket(self):
        rl = RequestRateLimiter()
        for _ in range(rl.MAX_REQUESTS):
            rl.is_allowed("alice@premos.com")
        rl.reset("alice@premos.com")
        assert rl.is_allowed("alice@premos.com") is True

    def test_reset_all(self):
        rl = RequestRateLimiter()
        for _ in range(rl.MAX_REQUESTS):
            rl.is_allowed("alice@premos.com")
            rl.is_allowed("bob@premos.com")
        rl.reset_all()
        assert rl.is_allowed("alice@premos.com") is True
        assert rl.is_allowed("bob@premos.com") is True
