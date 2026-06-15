"""Unit tests — specter/executor/kill_process.py + block_ip.py."""

import platform
from unittest.mock import MagicMock, patch

import psutil
import pytest


class TestKillProcess:
    def test_missing_pid_returns_error(self):
        from specter.executor.kill_process import execute
        result = execute({})
        assert result["success"] is False
        assert "pid" in result["message"].lower()

    def test_nonexistent_pid_returns_error(self):
        from specter.executor.kill_process import execute
        result = execute({"pid": 999999999})
        assert result["success"] is False

    def test_invalid_pid_type_returns_error(self):
        from specter.executor.kill_process import execute
        result = execute({"pid": "not-a-number"})
        assert result["success"] is False

    def test_name_mismatch_blocked_without_force(self):
        from specter.executor.kill_process import execute
        import os
        pid = os.getpid()
        result = execute({"pid": pid, "name": "nonexistent_process_xyz"})
        assert result["success"] is False
        assert "mismatch" in result["message"].lower()

    def test_force_bypasses_name_check(self):
        from specter.executor.kill_process import execute
        with patch("psutil.Process") as mock_proc_cls:
            mock_proc = MagicMock()
            mock_proc.name.return_value = "real_process"
            mock_proc.terminate = MagicMock()
            mock_proc.wait = MagicMock()
            mock_proc_cls.return_value = mock_proc
            result = execute({"pid": 1234, "name": "wrong_name", "force": True})
        assert result["success"] is True

    def test_successful_kill(self):
        from specter.executor.kill_process import execute
        with patch("psutil.Process") as mock_proc_cls:
            mock_proc = MagicMock()
            mock_proc.name.return_value = "target"
            mock_proc.terminate = MagicMock()
            mock_proc.wait = MagicMock()
            mock_proc_cls.return_value = mock_proc
            result = execute({"pid": 9999, "name": "target"})
        assert result["success"] is True
        assert "9999" in result["message"]

    def test_already_dead_process_is_ok(self):
        from specter.executor.kill_process import execute
        with patch("psutil.Process") as mock_proc_cls:
            mock_proc = MagicMock()
            mock_proc.name.return_value = "target"
            mock_proc.terminate = MagicMock()
            mock_proc.wait.side_effect = psutil.NoSuchProcess(pid=9999)
            mock_proc_cls.return_value = mock_proc
            result = execute({"pid": 9999})
        assert result["success"] is True

    def test_sigkill_on_timeout(self):
        from specter.executor.kill_process import execute
        with patch("psutil.Process") as mock_proc_cls:
            mock_proc = MagicMock()
            mock_proc.name.return_value = "stubborn"
            mock_proc.terminate = MagicMock()
            mock_proc.wait.side_effect = [psutil.TimeoutExpired(pid=111, seconds=5), None]
            mock_proc.kill = MagicMock()
            mock_proc_cls.return_value = mock_proc
            result = execute({"pid": 111})
        mock_proc.kill.assert_called_once()
        assert result["success"] is True


class TestBlockIP:
    def test_missing_ip_returns_error(self):
        from specter.executor.block_ip import execute
        result = execute({})
        assert result["success"] is False
        assert "ip" in result["message"].lower()

    def test_unsupported_platform_returns_error(self):
        from specter.executor.block_ip import execute
        with patch("platform.system", return_value="FreeBSD"):
            result = execute({"ip": "1.2.3.4"})
        assert result["success"] is False
        assert "unsupported" in result["message"].lower()

    def test_linux_inbound_iptables_called(self):
        from specter.executor.block_ip import execute, _run
        with patch("platform.system", return_value="Linux"), \
             patch("specter.executor.block_ip._run", return_value=(True, "ok")) as mock_run:
            result = execute({"ip": "10.0.0.1", "direction": "inbound"})
        assert result["success"] is True
        assert result["ip"] == "10.0.0.1"
        assert result["platform"] == "linux"
        assert mock_run.call_count == 1
        cmd = mock_run.call_args[0][0]
        assert "INPUT" in cmd
        assert "10.0.0.1" in cmd

    def test_linux_outbound_iptables_called(self):
        from specter.executor.block_ip import execute
        with patch("platform.system", return_value="Linux"), \
             patch("specter.executor.block_ip._run", return_value=(True, "ok")) as mock_run:
            result = execute({"ip": "10.0.0.2", "direction": "outbound"})
        cmd = mock_run.call_args[0][0]
        assert "OUTPUT" in cmd

    def test_linux_both_directions_calls_twice(self):
        from specter.executor.block_ip import execute
        with patch("platform.system", return_value="Linux"), \
             patch("specter.executor.block_ip._run", return_value=(True, "ok")) as mock_run:
            execute({"ip": "10.0.0.3", "direction": "both"})
        assert mock_run.call_count == 2

    def test_windows_netsh_called(self):
        from specter.executor.block_ip import execute
        with patch("platform.system", return_value="Windows"), \
             patch("specter.executor.block_ip._run", return_value=(True, "ok")) as mock_run:
            result = execute({"ip": "10.0.0.4", "direction": "inbound"})
        assert result["platform"] == "windows"
        cmd = mock_run.call_args[0][0]
        assert "netsh" in cmd

    def test_iptables_failure_propagates(self):
        from specter.executor.block_ip import execute
        with patch("platform.system", return_value="Linux"), \
             patch("specter.executor.block_ip._run", return_value=(False, "iptables: command not found")):
            result = execute({"ip": "10.0.0.5"})
        assert result["success"] is False
