"""Unit tests — specter/identity.py (no I/O, keys in memory)."""

import base64
import json
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

# ── helpers mirrored inline ────────────────────────────────────────────────────

def _generate_keypair():
    key = Ed25519PrivateKey.generate()
    priv = base64.b64encode(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode()
    pub  = base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
    return priv, pub

def _sign(priv_b64: str, payload: dict) -> str:
    from specter.identity import sign_event
    return sign_event(priv_b64, payload)

def _verify(pub_b64: str, payload: dict, sig: str) -> bool:
    from specter.identity import verify_command
    return verify_command(pub_b64, payload, sig)


class TestKeypairGeneration:
    def test_private_key_is_32_bytes(self):
        priv, _ = _generate_keypair()
        assert len(base64.b64decode(priv)) == 32

    def test_public_key_is_32_bytes(self):
        _, pub = _generate_keypair()
        assert len(base64.b64decode(pub)) == 32

    def test_keys_are_different_each_call(self):
        p1, q1 = _generate_keypair()
        p2, q2 = _generate_keypair()
        assert p1 != p2
        assert q1 != q2


class TestSignAndVerify:
    def setup_method(self):
        self.priv, self.pub = _generate_keypair()

    def test_valid_signature_verifies(self):
        payload = {"event_type": "process_start", "pid": 1234, "ts": time.time()}
        sig = _sign(self.priv, payload)
        assert _verify(self.pub, payload, sig) is True

    def test_tampered_payload_fails(self):
        payload = {"event_type": "process_start", "pid": 1234, "ts": time.time()}
        sig = _sign(self.priv, payload)
        payload["pid"] = 9999  # tamper
        assert _verify(self.pub, payload, sig) is False

    def test_wrong_key_fails(self):
        _, other_pub = _generate_keypair()
        payload = {"event_type": "net_connect", "ts": time.time()}
        sig = _sign(self.priv, payload)
        assert _verify(other_pub, payload, sig) is False

    def test_empty_payload_signs_and_verifies(self):
        payload: dict = {}
        sig = _sign(self.priv, payload)
        assert _verify(self.pub, payload, sig) is True

    def test_signature_is_base64(self):
        payload = {"x": 1}
        sig = _sign(self.priv, payload)
        decoded = base64.b64decode(sig)
        assert len(decoded) == 64  # Ed25519 signature is always 64 bytes

    def test_deterministic_canonical_serialisation(self):
        # Same payload with different key ordering → same signature
        p1 = {"b": 2, "a": 1}
        p2 = {"a": 1, "b": 2}
        s1 = _sign(self.priv, p1)
        s2 = _sign(self.priv, p2)
        assert s1 == s2

    def test_invalid_signature_string_returns_false(self):
        payload = {"x": 1}
        assert _verify(self.pub, payload, "not-a-real-signature==") is False

    def test_invalid_public_key_returns_false(self):
        payload = {"x": 1}
        sig = _sign(self.priv, payload)
        assert _verify("aW52YWxpZA==", payload, sig) is False


class TestHostInfo:
    def test_hostname_non_empty(self):
        from specter.identity import get_host_info
        info = get_host_info()
        assert info["hostname"]

    def test_os_type_is_known(self):
        from specter.identity import get_host_info
        info = get_host_info()
        assert info["os_type"] in ("windows", "linux", "darwin")

    def test_arch_non_empty(self):
        from specter.identity import get_host_info
        info = get_host_info()
        assert info["arch"]

    def test_ip_address_format(self):
        from specter.identity import get_host_info
        import re
        info = get_host_info()
        # Basic IPv4 pattern
        assert re.match(r"\d+\.\d+\.\d+\.\d+", info["ip_address"])
