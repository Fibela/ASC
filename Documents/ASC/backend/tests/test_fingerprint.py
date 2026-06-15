"""
Unit tests — Environmental Fingerprinting Service (services/fingerprint.py)

Tests each individual check, confidence scoring, and the master
analyze_environmental_keying() function with synthetic byte payloads.
"""
import pytest

from app.services.fingerprint import (
    analyze_environmental_keying,
    _check_hostname_patterns,
    _check_domain_patterns,
    _check_registry_patterns,
    _check_ad_enumeration,
    _check_network_fingerprinting,
    _check_timing_evasion,
    _check_string_obfuscation,
    FingerprintResult,
)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _make_bytes(*strings: str) -> bytes:
    return b"\x00".join(s.encode() for s in strings) + b"\x00"


# ─── Hostname pattern checks ──────────────────────────────────────────────────

class TestHostnamePatterns:
    def test_premos_hostname_detected(self):
        data = b"connecting to host PREMOS-WS-042\x00"
        findings = _check_hostname_patterns(data)
        assert len(findings) > 0
        assert any(f["check"] == "hostname_pattern" for f in findings)

    def test_premoscorp_string_detected(self):
        data = b"workstation=PremosCorp-LAPTOP-001\x00"
        findings = _check_hostname_patterns(data)
        assert len(findings) > 0

    def test_case_insensitive_match(self):
        data = b"HOST: premos-srv-10\x00"
        findings = _check_hostname_patterns(data)
        assert len(findings) > 0

    def test_unrelated_hostname_no_match(self):
        data = b"DESKTOP-ABCD1234\x00WIN-QWERTY5678\x00"
        findings = _check_hostname_patterns(data)
        assert findings == []


# ─── Domain pattern checks ────────────────────────────────────────────────────

class TestDomainPatterns:
    def test_premoscorp_com_detected(self):
        data = b"endpoint=https://premoscorp.com/auth\x00"
        findings = _check_domain_patterns(data)
        assert len(findings) > 0

    def test_premos_local_detected(self):
        data = b"LDAP://DC=premos.local\x00"
        findings = _check_domain_patterns(data)
        assert len(findings) > 0

    def test_premoscorp_internal_detected(self):
        data = b"DC=premoscorp.internal\x00"
        findings = _check_domain_patterns(data)
        assert len(findings) > 0

    def test_unrelated_domain_no_match(self):
        data = b"google.com\x00microsoft.com\x00"
        findings = _check_domain_patterns(data)
        assert findings == []


# ─── Registry pattern checks ──────────────────────────────────────────────────

class TestRegistryPatterns:
    def test_software_premoscorp_key_detected(self):
        data = rb"SOFTWARE\PremosCorp\Config\x00"
        findings = _check_registry_patterns(data)
        assert len(findings) > 0

    def test_premos_string_in_reg_detected(self):
        data = b"checking registry for PREMOS entry\x00"
        findings = _check_registry_patterns(data)
        assert len(findings) > 0

    def test_unrelated_registry_key_no_match(self):
        data = rb"SOFTWARE\Microsoft\Windows\CurrentVersion\x00"
        findings = _check_registry_patterns(data)
        assert findings == []


# ─── Active Directory enumeration checks ─────────────────────────────────────

class TestADEnumeration:
    def test_single_ad_api_detected(self):
        data = b"NetGetJoinInformation\x00"
        findings = _check_ad_enumeration(data)
        assert any(f["check"] == "active_directory_enum" for f in findings)

    def test_dsgetdcname_detected(self):
        data = b"DsGetDcName\x00DsGetDcName\x00"
        findings = _check_ad_enumeration(data)
        assert any(f["check"] == "active_directory_enum" for f in findings)

    def test_env_check_alone_below_threshold_no_finding(self):
        # Only 1 env check — threshold is >=3 (without AD api)
        data = b"USERDOMAIN=PREMOS\x00"
        findings = _check_ad_enumeration(data)
        # Either no env_variable_check finding, or if AD also present
        assert not any(f["check"] == "environment_variable_check" for f in findings)

    def test_three_env_checks_trigger_finding(self):
        data = b"GetEnvironmentVariable\x00USERDOMAIN\x00COMPUTERNAME\x00LOGONSERVER\x00"
        findings = _check_ad_enumeration(data)
        assert any(f["check"] == "environment_variable_check" for f in findings)

    def test_empty_data_no_match(self):
        findings = _check_ad_enumeration(b"")
        assert findings == []


# ─── Network fingerprinting checks ───────────────────────────────────────────

class TestNetworkFingerprinting:
    def test_getadaptersinfo_detected(self):
        data = b"GetAdaptersInfo\x00"
        findings = _check_network_fingerprinting(data)
        assert len(findings) > 0
        assert findings[0]["check"] == "network_fingerprinting"

    def test_dnsquerya_detected(self):
        data = b"DnsQueryA\x00"
        findings = _check_network_fingerprinting(data)
        assert len(findings) > 0

    def test_unrelated_network_no_match(self):
        data = b"socket\x00connect\x00send\x00"
        findings = _check_network_fingerprinting(data)
        assert findings == []


# ─── Timing evasion checks ────────────────────────────────────────────────────

class TestTimingEvasion:
    def test_sleep_with_two_env_checks_triggers(self):
        data = b"Sleep\x00WaitForSingleObject\x00GetEnvironmentVariable\x00USERDOMAIN\x00"
        findings = _check_timing_evasion(data)
        assert len(findings) > 0
        assert findings[0]["check"] == "timing_evasion_with_env_check"

    def test_sleep_alone_no_trigger(self):
        data = b"Sleep\x00SleepEx\x00"
        findings = _check_timing_evasion(data)
        assert findings == []

    def test_env_checks_alone_without_sleep_no_trigger(self):
        data = b"GetEnvironmentVariable\x00USERDOMAIN\x00NetGetJoinInformation\x00"
        findings = _check_timing_evasion(data)
        assert findings == []


# ─── High entropy / string obfuscation checks ────────────────────────────────

class TestStringObfuscation:
    def test_random_bytes_high_entropy(self):
        import os
        # 16384 bytes → 64 chunks of 256 bytes → reliably ≥3 chunks with entropy >7.2
        data = os.urandom(16384)
        result = _check_string_obfuscation(data)
        assert result is not None
        assert result["check"] == "high_entropy_sections"

    def test_repeated_pattern_low_entropy_no_match(self):
        data = b"\xAA\xBB" * 2048   # very low entropy
        result = _check_string_obfuscation(data)
        assert result is None

    def test_plaintext_low_entropy_no_match(self):
        data = b"Hello World " * 500
        result = _check_string_obfuscation(data)
        assert result is None


# ─── Master: analyze_environmental_keying ─────────────────────────────────────

class TestAnalyzeEnvironmentalKeying:
    def test_direct_premoscorp_reference_triggers_detection(self):
        data = b"connecting to premoscorp.com\x00checking host PREMOS-WS-01\x00"
        result = analyze_environmental_keying("malware.exe", data)
        assert isinstance(result, FingerprintResult)
        assert result.environmental_keying_detected is True
        assert result.confidence >= 0.70
        assert "domain_check" in result.triggers or "hostname_pattern" in result.triggers

    def test_clean_generic_binary_no_detection(self):
        data = b"CreateFile\x00ReadFile\x00CloseHandle\x00kernel32.dll\x00"
        result = analyze_environmental_keying("clean.exe", data)
        assert result.environmental_keying_detected is False
        assert result.confidence < 0.30

    def test_result_to_dict_shape(self):
        data = b"premoscorp.com\x00PREMOS\x00"
        result = analyze_environmental_keying("test.dll", data)
        d = result.to_dict()
        assert "environmental_keying_detected" in d
        assert "confidence" in d
        assert "risk_score" in d
        assert "triggers" in d
        assert "details" in d
        assert "recommendation" in d

    def test_confidence_bounded_0_to_1(self):
        # Pile in every possible trigger
        data = _make_bytes(
            "premoscorp.com", "PREMOS-WS-01", "SOFTWARE\\PremosCorp",
            "NetGetJoinInformation", "DsGetDcName",
            "GetAdaptersInfo", "DnsQueryA",
            "GetEnvironmentVariable", "USERDOMAIN", "COMPUTERNAME", "LOGONSERVER",
            "Sleep", "WaitForSingleObject",
        )
        result = analyze_environmental_keying("omnibus.exe", data)
        assert 0.0 <= result.confidence <= 1.0
        assert 0.0 <= result.risk_score <= 1.0

    def test_recommendation_critical_for_direct_reference(self):
        data = b"premoscorp.com\x00"
        result = analyze_environmental_keying("trojan.exe", data)
        assert "ALERTA CRÍTICA" in result.recommendation

    def test_recommendation_clean_for_no_triggers(self):
        data = b"notepad.exe\x00kernel32.dll\x00"
        result = analyze_environmental_keying("notepad.exe", data)
        assert "Sin indicadores" in result.recommendation

    def test_empty_file_no_detection(self):
        result = analyze_environmental_keying("empty.bin", b"")
        assert result.environmental_keying_detected is False

    def test_ad_combined_with_env_checks_raises_confidence(self):
        data = _make_bytes(
            "NetGetJoinInformation",
            "GetEnvironmentVariable", "USERDOMAIN", "COMPUTERNAME",
        )
        result = analyze_environmental_keying("recon.exe", data)
        assert result.confidence >= 0.30
        assert result.environmental_keying_detected is True

    def test_triggers_list_is_consistent_with_details(self):
        data = b"premoscorp.com\x00NetGetJoinInformation\x00GetAdaptersInfo\x00"
        result = analyze_environmental_keying("recon2.exe", data)
        # Every trigger name should have at least one detail entry with matching check
        for trigger in result.triggers:
            has_detail = any(
                d.get("check", "").startswith(trigger.split("_")[0])
                for d in result.details
            )
            assert has_detail or trigger in ("timing_evasion", "high_entropy_sections"), \
                f"Trigger '{trigger}' has no corresponding detail"
