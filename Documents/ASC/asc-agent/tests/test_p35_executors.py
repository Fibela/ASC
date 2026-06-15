"""
P35 — Tests for new SPECTER executors:
  isolate_endpoint, unisolate, log_query, unblock_ip, unblock_domain

All tests mock subprocess.run and filesystem operations — no real
iptables, netsh, or hosts file changes are made during testing.

Test count target: ≥40 tests across 5 classes.
"""

import re
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch, call


# ─────────────────────────────────────────────────────────────────────────────
# TestIsolateEndpoint
# ─────────────────────────────────────────────────────────────────────────────

class TestIsolateEndpoint:
    def _exec(self, params):
        from specter.executor.isolate_endpoint import execute
        return execute(params)

    def test_missing_asc_ip_no_env_returns_error(self):
        with patch.dict("os.environ", {}, clear=True):
            r = self._exec({})
        assert r["success"] is False
        assert "asc_server_ip" in r["message"]

    def test_asc_ip_derived_from_env_url(self):
        with patch("platform.system", return_value="Linux"), \
             patch("specter.executor.isolate_endpoint._run", return_value=(True, "ok")), \
             patch.dict("os.environ", {"SPECTER_BACKEND_URL": "https://10.0.0.99:443"}):
            r = self._exec({})
        assert r["success"] is True
        assert r["asc_server_ip"] == "10.0.0.99"

    def test_linux_applies_eight_rules(self):
        with patch("platform.system", return_value="Linux"), \
             patch("specter.executor.isolate_endpoint._run", return_value=(True, "ok")) as mock_run:
            r = self._exec({"asc_server_ip": "1.2.3.4"})
        assert r["success"] is True
        assert len(r["rules_applied"]) == 8

    def test_linux_loopback_rule_inserted_first(self):
        with patch("platform.system", return_value="Linux"), \
             patch("specter.executor.isolate_endpoint._run", return_value=(True, "ok")) as mock_run:
            self._exec({"asc_server_ip": "1.2.3.4"})
        first_call = mock_run.call_args_list[0][0][0]
        assert "-I" in first_call
        assert "lo" in first_call

    def test_linux_drop_rules_are_appended(self):
        with patch("platform.system", return_value="Linux"), \
             patch("specter.executor.isolate_endpoint._run", return_value=(True, "ok")) as mock_run:
            self._exec({"asc_server_ip": "1.2.3.4"})
        # Last two calls should be DROP -A (append)
        last_calls = mock_run.call_args_list[-2:]
        for c in last_calls:
            assert "-A" in c[0][0]
            assert "DROP" in c[0][0]

    def test_linux_partial_failure_reported(self):
        side_effects = [(True, "ok")] * 6 + [(False, "permission denied")] * 2
        with patch("platform.system", return_value="Linux"), \
             patch("specter.executor.isolate_endpoint._run", side_effect=side_effects):
            r = self._exec({"asc_server_ip": "1.2.3.4"})
        assert r["success"] is False
        assert len(r["errors"]) == 2

    def test_windows_applies_six_rules(self):
        with patch("platform.system", return_value="Windows"), \
             patch("specter.executor.isolate_endpoint._run", return_value=(True, "ok")) as mock_run:
            r = self._exec({"asc_server_ip": "1.2.3.4", "asc_server_port": 8443})
        assert r["success"] is True
        assert r["platform"] == "windows"
        assert len(r["rules_applied"]) == 6

    def test_windows_asc_port_in_rule(self):
        with patch("platform.system", return_value="Windows"), \
             patch("specter.executor.isolate_endpoint._run", return_value=(True, "ok")) as mock_run:
            self._exec({"asc_server_ip": "5.6.7.8", "asc_server_port": 9000})
        calls_flat = [str(c) for c in mock_run.call_args_list]
        assert any("9000" in c for c in calls_flat)

    def test_unsupported_platform_returns_error(self):
        with patch("platform.system", return_value="FreeBSD"):
            r = self._exec({"asc_server_ip": "1.2.3.4"})
        assert r["success"] is False
        assert "unsupported" in r["message"].lower()

    def test_rule_tag_in_all_linux_commands(self):
        with patch("platform.system", return_value="Linux"), \
             patch("specter.executor.isolate_endpoint._run", return_value=(True, "ok")) as mock_run:
            self._exec({"asc_server_ip": "1.2.3.4"})
        for c in mock_run.call_args_list:
            cmd = c[0][0]
            # All rules must have --comment SPECTER-ISOLATE (or be a DROP that has it)
            assert "SPECTER-ISOLATE" in cmd, f"Missing tag in: {cmd}"


# ─────────────────────────────────────────────────────────────────────────────
# TestUnisolate
# ─────────────────────────────────────────────────────────────────────────────

class TestUnisolate:
    def _exec(self, params):
        from specter.executor.unisolate import execute
        return execute(params)

    def test_linux_no_rules_returns_empty(self):
        iptables_output = "Chain INPUT (policy ACCEPT)\nnum  target  prot  source\n1 ACCEPT all 0.0.0.0/0"
        with patch("platform.system", return_value="Linux"), \
             patch("specter.executor.unisolate._run", return_value=(True, iptables_output)):
            r = self._exec({})
        assert r["success"] is True
        assert r["rules_removed"] == []

    def test_linux_finds_and_removes_tagged_rules(self):
        # Only INPUT chain has tagged rules — OUTPUT is clean — so exactly 2 removals
        def mock_run(cmd):
            if "-L" in cmd and "INPUT" in cmd:
                return (True,
                    "Chain INPUT (policy ACCEPT)\n"
                    "num  target prot\n"
                    "1 DROP all -- 0.0.0.0/0  /* SPECTER-ISOLATE */\n"
                    "2 ACCEPT all\n"
                    "3 DROP all -- 0.0.0.0/0  /* SPECTER-ISOLATE */\n")
            if "-L" in cmd and "OUTPUT" in cmd:
                return (True, "Chain OUTPUT (policy ACCEPT)\nnum  target prot\n2 ACCEPT all\n")
            return (True, "ok")

        with patch("platform.system", return_value="Linux"), \
             patch("specter.executor.unisolate._run", side_effect=mock_run):
            r = self._exec({})

        assert r["success"] is True
        assert len(r["rules_removed"]) == 2  # INPUT#3 + INPUT#1; OUTPUT chain clean

    def test_linux_deletes_in_descending_order(self):
        # INPUT has rules at lines 1 and 3 — must delete 3 before 1
        deleted_nums: list[int] = []

        def mock_run(cmd):
            if "-L" in cmd and "INPUT" in cmd:
                return (True, "Chain INPUT\n1 DROP all /* SPECTER-ISOLATE */\n3 DROP all /* SPECTER-ISOLATE */\n")
            if "-L" in cmd and "OUTPUT" in cmd:
                return (True, "Chain OUTPUT\n")
            if "-D" in cmd and "INPUT" in cmd:
                # cmd = ["iptables", "-D", "INPUT", "<num>"]
                deleted_nums.append(int(cmd[3]))
            return (True, "ok")

        with patch("platform.system", return_value="Linux"), \
             patch("specter.executor.unisolate._run", side_effect=mock_run):
            self._exec({})

        assert deleted_nums == sorted(deleted_nums, reverse=True)

    def test_linux_dry_run_does_not_delete(self):
        list_output = "Chain INPUT\n1 DROP all /* SPECTER-ISOLATE */\n"
        calls = []
        def mock_run(cmd):
            calls.append(cmd)
            return (True, list_output if "-L" in cmd else "ok")

        with patch("platform.system", return_value="Linux"), \
             patch("specter.executor.unisolate._run", side_effect=mock_run):
            r = self._exec({"dry_run": True})

        assert r["dry_run"] is True
        delete_calls = [c for c in calls if "-D" in c]
        assert delete_calls == []
        assert "[dry-run]" in r["rules_removed"][0]

    def test_windows_no_rules_returns_ok(self):
        with patch("platform.system", return_value="Windows"), \
             patch("specter.executor.unisolate._run", return_value=(False, "No rules match")):
            r = self._exec({})
        assert r["success"] is True
        assert "already unisolated" in r["message"].lower()

    def test_windows_removes_tagged_rules(self):
        show_output = "Rule Name: SPECTER-ISOLATE-loopback-in\nEnabled: yes\n---\nRule Name: SPECTER-ISOLATE-block-all-out\nEnabled: yes\n"
        def mock_run(cmd):
            if "show" in cmd:
                return (True, show_output)
            return (True, "ok")

        with patch("platform.system", return_value="Windows"), \
             patch("specter.executor.unisolate._run", side_effect=mock_run):
            r = self._exec({})

        assert r["success"] is True
        assert len(r["rules_removed"]) == 2

    def test_unsupported_platform_returns_error(self):
        with patch("platform.system", return_value="Darwin"):
            r = self._exec({})
        assert r["success"] is False


# ─────────────────────────────────────────────────────────────────────────────
# TestLogQuery
# ─────────────────────────────────────────────────────────────────────────────

class TestLogQuery:
    def _exec(self, params):
        from specter.executor.log_query import execute
        return execute(params)

    def test_missing_read_only_rejected(self):
        r = self._exec({"pattern": "sshd"})
        assert r["success"] is False
        assert "read_only" in r["message"].lower()

    def test_read_only_false_rejected(self):
        r = self._exec({"pattern": "sshd", "read_only": False})
        assert r["success"] is False

    def test_missing_pattern_returns_error(self):
        r = self._exec({"read_only": True})
        assert r["success"] is False
        assert "pattern" in r["message"].lower()

    def test_pattern_too_long_returns_error(self):
        r = self._exec({"read_only": True, "pattern": "x" * 300})
        assert r["success"] is False
        assert "too long" in r["message"].lower()

    def test_invalid_regex_returns_error(self):
        r = self._exec({"read_only": True, "pattern": "[invalid", "is_regex": True})
        assert r["success"] is False
        assert "regex" in r["message"].lower()

    def test_linux_journalctl_search(self):
        fake_output = "Jan 01 00:00:01 host sshd[123]: Accepted publickey for admin\nJan 01 00:00:02 host sshd[124]: session opened"
        with patch("platform.system", return_value="Linux"), \
             patch("subprocess.run") as mock_sub:
            mock_sub.return_value = MagicMock(stdout=fake_output, returncode=0)
            r = self._exec({"read_only": True, "pattern": "sshd", "data_source": "system"})
        assert r["success"] is True
        assert r["match_count"] == 2
        assert r["source"] == "journalctl"

    def test_linux_file_source_reads_file(self):
        fake_log = "line1 error found\nline2 normal\nline3 error again\n"
        with patch("platform.system", return_value="Linux"), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.is_file", return_value=True), \
             patch("pathlib.Path.stat") as mock_stat, \
             patch("pathlib.Path.read_text", return_value=fake_log):
            mock_stat.return_value.st_size = 100
            r = self._exec({
                "read_only": True, "pattern": "error",
                "data_source": "file", "log_path": "/var/log/custom.log",
            })
        assert r["success"] is True
        assert r["match_count"] == 2

    def test_linux_file_not_found_returns_error(self):
        with patch("platform.system", return_value="Linux"), \
             patch("pathlib.Path.exists", return_value=False):
            r = self._exec({
                "read_only": True, "pattern": "error",
                "data_source": "file", "log_path": "/nonexistent.log",
            })
        assert r["success"] is False
        assert "not found" in r["message"].lower()

    def test_max_results_cap_respected(self):
        # 1000 matching lines — should be capped at 500
        lines = "\n".join([f"error line {i}" for i in range(1000)])
        with patch("platform.system", return_value="Linux"), \
             patch("subprocess.run") as mock_sub:
            mock_sub.return_value = MagicMock(stdout=lines, returncode=0)
            r = self._exec({"read_only": True, "pattern": "error", "max_results": 500})
        assert r["match_count"] <= 500
        assert r["truncated"] is True

    def test_truncated_false_when_under_limit(self):
        lines = "sshd login attempt\nsshd success"
        with patch("platform.system", return_value="Linux"), \
             patch("subprocess.run") as mock_sub:
            mock_sub.return_value = MagicMock(stdout=lines, returncode=0)
            r = self._exec({"read_only": True, "pattern": "sshd"})
        assert r["truncated"] is False

    def test_regex_pattern_matches_correctly(self):
        lines = "ERROR: disk full\nINFO: all good\nERROR: timeout"
        with patch("platform.system", return_value="Linux"), \
             patch("subprocess.run") as mock_sub:
            mock_sub.return_value = MagicMock(stdout=lines, returncode=0)
            r = self._exec({"read_only": True, "pattern": r"^ERROR", "is_regex": True})
        assert r["match_count"] == 2

    def test_windows_calls_powershell(self):
        with patch("platform.system", return_value="Windows"), \
             patch("subprocess.run") as mock_sub:
            mock_sub.return_value = MagicMock(stdout="2026-01-01 00:00:00 login success", returncode=0)
            r = self._exec({"read_only": True, "pattern": "login"})
        assert r["success"] is True
        cmd = mock_sub.call_args[0][0]
        assert "powershell" in cmd[0].lower()

    def test_unsupported_platform_returns_error(self):
        with patch("platform.system", return_value="FreeBSD"):
            r = self._exec({"read_only": True, "pattern": "error"})
        assert r["success"] is False


# ─────────────────────────────────────────────────────────────────────────────
# TestUnblockIP
# ─────────────────────────────────────────────────────────────────────────────

class TestUnblockIP:
    def _exec(self, params):
        from specter.executor.unblock_ip import execute
        return execute(params)

    def test_missing_ip_returns_error(self):
        r = self._exec({})
        assert r["success"] is False
        assert "ip" in r["message"].lower()

    def test_linux_inbound_removes_input_rule(self):
        with patch("platform.system", return_value="Linux"), \
             patch("specter.executor.unblock_ip._run", return_value=(True, "ok")) as mock_run:
            r = self._exec({"ip": "1.2.3.4", "direction": "inbound"})
        assert r["success"] is True
        cmd = mock_run.call_args[0][0]
        assert "INPUT" in cmd
        assert "1.2.3.4" in cmd
        assert "-D" in cmd

    def test_linux_outbound_removes_output_rule(self):
        with patch("platform.system", return_value="Linux"), \
             patch("specter.executor.unblock_ip._run", return_value=(True, "ok")) as mock_run:
            r = self._exec({"ip": "1.2.3.4", "direction": "outbound"})
        cmd = mock_run.call_args[0][0]
        assert "OUTPUT" in cmd

    def test_linux_both_calls_twice(self):
        with patch("platform.system", return_value="Linux"), \
             patch("specter.executor.unblock_ip._run", return_value=(True, "ok")) as mock_run:
            r = self._exec({"ip": "1.2.3.4", "direction": "both"})
        assert mock_run.call_count == 2
        assert r["success"] is True

    def test_linux_failure_propagated(self):
        with patch("platform.system", return_value="Linux"), \
             patch("specter.executor.unblock_ip._run", return_value=(False, "No such rule")):
            r = self._exec({"ip": "9.9.9.9"})
        assert r["success"] is False

    def test_windows_deletes_named_rules(self):
        with patch("platform.system", return_value="Windows"), \
             patch("specter.executor.unblock_ip._run", return_value=(True, "ok")) as mock_run:
            r = self._exec({"ip": "5.6.7.8", "direction": "both"})
        assert r["success"] is True
        calls_flat = [str(c) for c in mock_run.call_args_list]
        assert any("SPECTER-BLOCK-5.6.7.8" in c for c in calls_flat)

    def test_windows_inbound_only_one_rule(self):
        with patch("platform.system", return_value="Windows"), \
             patch("specter.executor.unblock_ip._run", return_value=(True, "ok")) as mock_run:
            r = self._exec({"ip": "5.6.7.8", "direction": "inbound"})
        assert mock_run.call_count == 1

    def test_unsupported_platform_returns_error(self):
        with patch("platform.system", return_value="SunOS"):
            r = self._exec({"ip": "1.2.3.4"})
        assert r["success"] is False


# ─────────────────────────────────────────────────────────────────────────────
# TestUnblockDomain
# ─────────────────────────────────────────────────────────────────────────────

class TestUnblockDomain:
    def _exec(self, params):
        from specter.executor.unblock_domain import execute
        return execute(params)

    def _hosts_with_block(self, domain: str) -> str:
        return (
            "127.0.0.1 localhost\n"
            f"0.0.0.0 {domain}   # SPECTER-BLOCK\n"
            "255.255.255.255 broadcasthost\n"
        )

    def test_missing_domain_returns_error(self):
        r = self._exec({})
        assert r["success"] is False
        assert "domain" in r["message"].lower()

    def test_invalid_domain_format_rejected(self):
        r = self._exec({"domain": "../../etc/passwd"})
        assert r["success"] is False
        assert "invalid" in r["message"].lower()

    def test_domain_with_path_traversal_rejected(self):
        r = self._exec({"domain": "evil.com/../../etc"})
        assert r["success"] is False

    def test_removes_specter_block_line(self):
        domain = "evil.com"
        hosts_content = self._hosts_with_block(domain)
        written = []

        with patch("platform.system", return_value="Linux"), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_text", return_value=hosts_content), \
             patch("pathlib.Path.write_text", side_effect=lambda c, **kw: written.append(c)):
            r = self._exec({"domain": domain})

        assert r["success"] is True
        assert r["lines_removed"] == 1
        assert domain not in written[0] or "SPECTER-BLOCK" not in written[0]

    def test_does_not_remove_non_specter_lines(self):
        domain = "evil.com"
        hosts_content = (
            "127.0.0.1 localhost\n"
            f"192.168.1.1 {domain}\n"          # manual entry — NOT tagged
            f"0.0.0.0 {domain}  # SPECTER-BLOCK\n"
        )
        written = []

        with patch("platform.system", return_value="Linux"), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_text", return_value=hosts_content), \
             patch("pathlib.Path.write_text", side_effect=lambda c, **kw: written.append(c)):
            r = self._exec({"domain": domain})

        assert r["lines_removed"] == 1
        # Manual line preserved
        assert f"192.168.1.1 {domain}" in written[0]

    def test_already_unblocked_returns_ok(self):
        hosts_content = "127.0.0.1 localhost\n"
        with patch("platform.system", return_value="Linux"), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_text", return_value=hosts_content), \
             patch("pathlib.Path.write_text"):
            r = self._exec({"domain": "never-blocked.com"})

        assert r["success"] is True
        assert r["lines_removed"] == 0
        assert "already unblocked" in r["message"].lower()

    def test_hosts_file_not_found_returns_error(self):
        with patch("platform.system", return_value="Linux"), \
             patch("pathlib.Path.exists", return_value=False):
            r = self._exec({"domain": "evil.com"})
        assert r["success"] is False
        assert "not found" in r["message"].lower()

    def test_permission_denied_on_read_returns_error(self):
        with patch("platform.system", return_value="Linux"), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_text", side_effect=PermissionError):
            r = self._exec({"domain": "evil.com"})
        assert r["success"] is False
        assert "permission" in r["message"].lower()

    def test_windows_uses_windows_hosts_path(self):
        domain = "bad.com"
        hosts_content = f"0.0.0.0 {domain}  # SPECTER-BLOCK\n"
        written = []

        with patch("platform.system", return_value="Windows"), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_text", return_value=hosts_content), \
             patch("pathlib.Path.write_text", side_effect=lambda c, **kw: written.append(c)):
            r = self._exec({"domain": domain})

        assert r["success"] is True
        assert "windows" in r["hosts_path"].lower() or "drivers" in r["hosts_path"].lower()


# ─────────────────────────────────────────────────────────────────────────────
# TestAgentDispatcherRegistration (integration — verifies agent.py EXECUTORS)
# ─────────────────────────────────────────────────────────────────────────────

class TestAgentDispatcherRegistration:
    """Verify all P35 executors are registered in the EXECUTORS dispatch table."""

    def _get_executors(self):
        import importlib
        import sys
        # Remove cached module to get fresh import
        for mod in list(sys.modules.keys()):
            if "specter.agent" in mod:
                del sys.modules[mod]
        # Stub celery in case it's not installed
        from unittest.mock import MagicMock
        import specter.agent as ag
        return ag.EXECUTORS

    def test_kill_process_registered(self):
        from specter.agent import EXECUTORS
        assert "kill_process" in EXECUTORS

    def test_block_ip_registered(self):
        from specter.agent import EXECUTORS
        assert "block_ip" in EXECUTORS

    def test_isolate_endpoint_registered(self):
        from specter.agent import EXECUTORS
        assert "isolate_endpoint" in EXECUTORS

    def test_unisolate_registered(self):
        from specter.agent import EXECUTORS
        assert "unisolate" in EXECUTORS

    def test_unblock_ip_registered(self):
        from specter.agent import EXECUTORS
        assert "unblock_ip" in EXECUTORS

    def test_unblock_domain_registered(self):
        from specter.agent import EXECUTORS
        assert "unblock_domain" in EXECUTORS

    def test_log_query_registered(self):
        from specter.agent import EXECUTORS
        assert "log_query" in EXECUTORS

    def test_all_executors_are_callable(self):
        from specter.agent import EXECUTORS
        for name, fn in EXECUTORS.items():
            assert callable(fn), f"EXECUTORS[{name!r}] is not callable"

    def test_unknown_command_returns_error_not_exception(self):
        """_execute_command must never raise — unknown type returns failure tuple."""
        from specter.agent import _execute_command
        success, result, error = _execute_command({"command_type": "rm_-rf", "params": {}})
        assert success is False
        assert error is not None
        assert "unknown" in error.lower()
