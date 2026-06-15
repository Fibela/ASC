"""Unit tests — specter/communicator.py (httpx mocked, no disk I/O)."""

import base64
import json
import time
import uuid
from unittest.mock import MagicMock, call, patch

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_keypair():
    key = Ed25519PrivateKey.generate()
    priv = base64.b64encode(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode()
    pub = base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
    return priv, pub, key


def _sign_dict(key: Ed25519PrivateKey, payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return base64.b64encode(key.sign(canonical)).decode()


def _build_comm(backend_pub_b64: str = ""):
    """Construct SprecterComm without touching disk."""
    agent_priv, agent_pub, _ = _make_keypair()
    with patch("specter.communicator.load_or_generate_keypair", return_value=(agent_priv, agent_pub)), \
         patch("specter.communicator.load_agent_id", return_value=str(uuid.uuid4())):
        from specter.communicator import SprecterComm
        comm = SprecterComm("http://testserver", verify_ssl=False)
    comm._backend_pub_key = backend_pub_b64
    return comm, agent_priv, agent_pub


def _mock_client(responses: list):
    """
    Build a context-manager-compatible mock httpx.Client.
    `responses` is a list of (method, return_value) tuples or just return_values for post/get.
    Simplification: returns a single mock whose .post and .get return items from responses.
    """
    mock = MagicMock()
    mock.__enter__ = lambda s: s
    mock.__exit__ = MagicMock(return_value=False)
    return mock


# ── Registration ──────────────────────────────────────────────────────────────

class TestRegister:
    def test_successful_register_saves_agent_id(self):
        comm, _, _ = _build_comm()
        new_id = str(uuid.uuid4())
        resp_json = {
            "agent_id": new_id,
            "poll_interval": 30,
            "threat_level": "normal",
            "backend_pub_key": "",
        }
        mock_r = MagicMock()
        mock_r.status_code = 200
        mock_r.json.return_value = resp_json
        mock_r.raise_for_status = MagicMock()

        with patch("httpx.Client") as mock_cls, \
             patch("specter.communicator.save_agent_id") as mock_save:
            mc = _mock_client([])
            mc.post.return_value = mock_r
            mock_cls.return_value = mc
            result = comm.register()

        assert result is True
        mock_save.assert_called_once_with(new_id)
        assert comm._agent_id == new_id

    def test_register_sends_public_key(self):
        comm, _, agent_pub = _build_comm()
        resp_json = {"agent_id": str(uuid.uuid4()), "poll_interval": 30,
                     "threat_level": "normal", "backend_pub_key": ""}
        mock_r = MagicMock()
        mock_r.status_code = 200
        mock_r.json.return_value = resp_json
        mock_r.raise_for_status = MagicMock()

        with patch("httpx.Client") as mock_cls, \
             patch("specter.communicator.save_agent_id"):
            mc = _mock_client([])
            mc.post.return_value = mock_r
            mock_cls.return_value = mc
            comm.register()
            _, kwargs = mc.post.call_args
            body = kwargs.get("json", {})

        assert body.get("public_key") == agent_pub

    def test_register_returns_false_on_exception(self):
        comm, _, _ = _build_comm()
        with patch("httpx.Client") as mock_cls:
            mc = _mock_client([])
            mc.post.side_effect = Exception("connection refused")
            mock_cls.return_value = mc
            result = comm.register()
        assert result is False

    def test_register_stores_poll_interval(self):
        comm, _, _ = _build_comm()
        resp_json = {"agent_id": str(uuid.uuid4()), "poll_interval": 5,
                     "threat_level": "elevated", "backend_pub_key": ""}
        mock_r = MagicMock()
        mock_r.status_code = 200
        mock_r.json.return_value = resp_json
        mock_r.raise_for_status = MagicMock()

        with patch("httpx.Client") as mock_cls, \
             patch("specter.communicator.save_agent_id"):
            mc = _mock_client([])
            mc.post.return_value = mock_r
            mock_cls.return_value = mc
            comm.register()

        assert comm._poll_interval == 5
        assert comm._threat_level == "elevated"


# ── Submit Events ─────────────────────────────────────────────────────────────

class TestSubmitEvents:
    def _event(self):
        return {"event_type": "process_start", "severity": "info",
                "data": {"pid": 1, "name": "test"}, "ts": time.time()}

    def test_events_posted_to_correct_endpoint(self):
        comm, _, _ = _build_comm()
        mock_r = MagicMock()
        mock_r.status_code = 200
        mock_r.json.return_value = {"accepted": 1, "rejected": 0}
        mock_r.raise_for_status = MagicMock()

        with patch("httpx.Client") as mock_cls:
            mc = _mock_client([])
            mc.post.return_value = mock_r
            mock_cls.return_value = mc
            comm.submit_events([self._event()])
            url = mc.post.call_args[0][0]

        assert f"/api/v1/agents/{comm._agent_id}/events" in url

    def test_events_signed_before_send(self):
        comm, _, _ = _build_comm()
        mock_r = MagicMock()
        mock_r.status_code = 200
        mock_r.json.return_value = {"accepted": 1, "rejected": 0}
        mock_r.raise_for_status = MagicMock()

        with patch("httpx.Client") as mock_cls:
            mc = _mock_client([])
            mc.post.return_value = mock_r
            mock_cls.return_value = mc
            comm.submit_events([self._event()])
            _, kwargs = mc.post.call_args
            body = kwargs.get("json", {})

        events = body.get("events", [])
        assert len(events) == 1
        assert "signature" in events[0]

    def test_x_specter_id_header_sent(self):
        comm, _, _ = _build_comm()
        mock_r = MagicMock()
        mock_r.status_code = 200
        mock_r.json.return_value = {"accepted": 1, "rejected": 0}
        mock_r.raise_for_status = MagicMock()

        with patch("httpx.Client") as mock_cls:
            mc = _mock_client([])
            mc.post.return_value = mock_r
            mock_cls.return_value = mc
            comm.submit_events([self._event()])
            _, kwargs = mc.post.call_args
            headers = kwargs.get("headers", {})

        assert headers.get("X-Specter-ID") == comm._agent_id

    def test_submit_error_returns_error_dict(self):
        comm, _, _ = _build_comm()
        with patch("httpx.Client") as mock_cls:
            mc = _mock_client([])
            mc.post.side_effect = Exception("timeout")
            mock_cls.return_value = mc
            result = comm.submit_events([self._event()])
        assert "error" in result


# ── Poll Commands ─────────────────────────────────────────────────────────────

class TestPollCommands:
    def _signed_cmd(self, backend_key: Ed25519PrivateKey):
        # Sign exactly the fields that remain after poll_commands pops "signature"
        cmd = {
            "id": str(uuid.uuid4()),
            "command_type": "kill_process",
            "params": {"pid": 1234},
        }
        sig = _sign_dict(backend_key, cmd)
        return {**cmd, "signature": sig}

    def test_empty_commands_returns_empty_list(self):
        comm, _, _ = _build_comm()
        mock_r = MagicMock()
        mock_r.status_code = 200
        mock_r.json.return_value = {"poll_interval": 30, "threat_level": "normal", "commands": []}
        mock_r.raise_for_status = MagicMock()

        with patch("httpx.Client") as mock_cls:
            mc = _mock_client([])
            mc.get.return_value = mock_r
            mock_cls.return_value = mc
            result = comm.poll_commands()
        assert result == []

    def test_command_verified_with_backend_key(self):
        backend_priv, backend_pub, backend_key = _make_keypair()
        comm, _, _ = _build_comm(backend_pub)
        cmd = self._signed_cmd(backend_key)
        mock_r = MagicMock()
        mock_r.status_code = 200
        mock_r.json.return_value = {"poll_interval": 30, "threat_level": "normal", "commands": [cmd]}
        mock_r.raise_for_status = MagicMock()

        with patch("httpx.Client") as mock_cls:
            mc = _mock_client([])
            mc.get.return_value = mock_r
            mock_cls.return_value = mc
            result = comm.poll_commands()
        assert len(result) == 1

    def test_invalid_signature_discards_command(self):
        _, backend_pub, _ = _make_keypair()
        comm, _, _ = _build_comm(backend_pub)  # non-empty pub → verification is enforced
        bad_cmd = {
            "id": str(uuid.uuid4()),
            "command_type": "kill_process",
            "params": {},
            "signature": "AAAA",  # garbage sig
            "status": "pending",
        }
        mock_r = MagicMock()
        mock_r.status_code = 200
        mock_r.json.return_value = {"poll_interval": 30, "threat_level": "normal", "commands": [bad_cmd]}
        mock_r.raise_for_status = MagicMock()

        with patch("httpx.Client") as mock_cls:
            mc = _mock_client([])
            mc.get.return_value = mock_r
            mock_cls.return_value = mc
            result = comm.poll_commands()
        assert result == []

    def test_no_backend_key_bypasses_verification(self):
        """When backend_pub_key is empty, all commands pass (bootstrap-safe)."""
        comm, _, _ = _build_comm("")  # empty pub key
        cmd = {
            "id": str(uuid.uuid4()),
            "command_type": "kill_process",
            "params": {},
            "signature": "anything",
            "status": "pending",
        }
        mock_r = MagicMock()
        mock_r.status_code = 200
        mock_r.json.return_value = {"poll_interval": 30, "threat_level": "normal", "commands": [cmd]}
        mock_r.raise_for_status = MagicMock()

        with patch("httpx.Client") as mock_cls:
            mc = _mock_client([])
            mc.get.return_value = mock_r
            mock_cls.return_value = mc
            result = comm.poll_commands()
        assert len(result) == 1

    def test_404_triggers_re_registration(self):
        comm, _, _ = _build_comm()
        mock_r = MagicMock()
        mock_r.status_code = 404
        err = httpx.HTTPStatusError("404", request=MagicMock(), response=mock_r)
        mock_r.raise_for_status.side_effect = err

        with patch("httpx.Client") as mock_cls:
            mc = _mock_client([])
            mc.get.return_value = mock_r
            mock_cls.return_value = mc
            with patch.object(comm, "register", return_value=True) as mock_reg:
                result = comm.poll_commands()
        mock_reg.assert_called_once()
        assert result == []

    def test_updates_poll_interval_from_response(self):
        comm, _, _ = _build_comm()
        mock_r = MagicMock()
        mock_r.status_code = 200
        mock_r.json.return_value = {"poll_interval": 1, "threat_level": "critical", "commands": []}
        mock_r.raise_for_status = MagicMock()

        with patch("httpx.Client") as mock_cls:
            mc = _mock_client([])
            mc.get.return_value = mock_r
            mock_cls.return_value = mc
            comm.poll_commands()

        assert comm.poll_interval == 1
        assert comm.threat_level == "critical"

    def test_exception_returns_empty_list(self):
        comm, _, _ = _build_comm()
        with patch("httpx.Client") as mock_cls:
            mc = _mock_client([])
            mc.get.side_effect = Exception("network error")
            mock_cls.return_value = mc
            result = comm.poll_commands()
        assert result == []


# ── Report Result ─────────────────────────────────────────────────────────────

class TestReportResult:
    def test_result_sent_to_correct_endpoint(self):
        comm, _, _ = _build_comm()
        cmd_id = str(uuid.uuid4())
        mock_r = MagicMock()
        mock_r.status_code = 200
        mock_r.json.return_value = {}
        mock_r.raise_for_status = MagicMock()

        with patch("httpx.Client") as mock_cls:
            mc = _mock_client([])
            mc.post.return_value = mock_r
            mock_cls.return_value = mc
            comm.report_result(cmd_id, success=True, result={"msg": "ok"})
            url = mc.post.call_args[0][0]

        assert f"/api/v1/agents/{comm._agent_id}/results" in url

    def test_result_body_contains_all_fields(self):
        comm, _, _ = _build_comm()
        cmd_id = str(uuid.uuid4())
        mock_r = MagicMock()
        mock_r.status_code = 200
        mock_r.json.return_value = {}
        mock_r.raise_for_status = MagicMock()

        with patch("httpx.Client") as mock_cls:
            mc = _mock_client([])
            mc.post.return_value = mock_r
            mock_cls.return_value = mc
            comm.report_result(cmd_id, success=False, result=None, error="permission denied")
            _, kwargs = mc.post.call_args
            body = kwargs.get("json", {})

        assert body["command_id"] == cmd_id
        assert body["success"] is False
        assert body["error"] == "permission denied"

    def test_report_exception_does_not_raise(self):
        comm, _, _ = _build_comm()
        with patch("httpx.Client") as mock_cls:
            mc = _mock_client([])
            mc.post.side_effect = Exception("network gone")
            mock_cls.return_value = mc
            # Must not propagate — just prints warning
            comm.report_result("some-id", success=True, result={})
