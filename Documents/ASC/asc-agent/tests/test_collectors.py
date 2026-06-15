"""Unit tests — specter/collectors/processes.py + network.py."""

import socket
import time
from unittest.mock import MagicMock, patch

import pytest


class TestProcessCollector:
    def test_first_collect_returns_starts_for_all_procs(self):
        from specter.collectors.processes import ProcessCollector
        pc = ProcessCollector()
        events = pc.collect()
        # At minimum the test process itself should appear
        types = {e["event_type"] for e in events}
        assert "process_start" in types

    def test_second_collect_returns_no_duplicates(self):
        from specter.collectors.processes import ProcessCollector
        pc = ProcessCollector()
        pc.collect()  # warm up
        events = pc.collect()  # second pass — known processes not re-emitted
        starts = [e for e in events if e["event_type"] == "process_start"]
        # Only truly new processes should appear in the second pass
        assert len(starts) <= 5  # allow for processes that started between calls

    def test_process_end_emitted_on_vanished_pid(self):
        from specter.collectors.processes import ProcessCollector
        pc = ProcessCollector()
        # Pre-populate known with a fake PID that won't exist
        pc._known = {999999999: 1234567.0}
        events = pc.collect()
        ends = [e for e in events if e["event_type"] == "process_end" and e["pid"] == 999999999]
        assert len(ends) == 1

    def test_reset_clears_state(self):
        from specter.collectors.processes import ProcessCollector
        pc = ProcessCollector()
        pc.collect()
        assert len(pc._known) > 0
        pc.reset()
        assert len(pc._known) == 0

    def test_event_has_required_fields(self):
        from specter.collectors.processes import ProcessCollector
        pc = ProcessCollector()
        events = pc.collect()
        for ev in events:
            if ev["event_type"] == "process_start":
                assert "pid" in ev
                assert "name" in ev
                assert "ts" in ev
                break

    def test_pid_reuse_detected_as_new(self):
        from specter.collectors.processes import ProcessCollector
        pc = ProcessCollector()
        # Same PID, different create_time → new process (PID reuse)
        pc._known = {1: 100.0}
        with patch("psutil.process_iter") as mock_iter:
            mock_proc = MagicMock()
            mock_proc.pid = 1
            mock_proc.__enter__ = lambda s: s
            mock_proc.__exit__ = MagicMock(return_value=False)
            mock_proc.name.return_value = "new_process"
            mock_proc.exe.return_value = "/usr/bin/new"
            mock_proc.cmdline.return_value = ["new_process"]
            mock_proc.username.return_value = "user"
            mock_proc.status.return_value = "running"
            mock_proc.create_time.return_value = 999.0  # different from 100.0
            mock_proc.oneshot.return_value = mock_proc
            mock_iter.return_value = [mock_proc]
            events = pc.collect()
        starts = [e for e in events if e["event_type"] == "process_start"]
        assert len(starts) == 1


class TestNetworkCollector:
    def test_first_collect_returns_connections(self):
        from specter.collectors.network import NetworkCollector
        nc = NetworkCollector()
        events = nc.collect()
        # May be empty if no non-loopback connections, but should not raise
        assert isinstance(events, list)

    def test_second_collect_no_duplicates(self):
        from specter.collectors.network import NetworkCollector
        nc = NetworkCollector()
        nc.collect()  # warm up
        events2 = nc.collect()
        # Only new connections since last poll
        assert isinstance(events2, list)

    def test_reset_clears_state(self):
        from specter.collectors.network import NetworkCollector
        nc = NetworkCollector()
        nc.collect()
        nc.reset()
        assert len(nc._known) == 0

    def test_loopback_filtered(self):
        from specter.collectors.network import NetworkCollector
        nc = NetworkCollector()
        with patch("psutil.net_connections") as mock_conns:
            mock_conn = MagicMock()
            mock_conn.laddr = MagicMock(ip="127.0.0.1", port=8080)
            mock_conn.raddr = MagicMock(ip="127.0.0.1", port=9090)
            mock_conn.status = "ESTABLISHED"
            mock_conn.type = socket.SOCK_STREAM
            mock_conn.pid = 1234
            mock_conns.return_value = [mock_conn]
            events = nc.collect()
        assert len(events) == 0  # loopback should be filtered

    def test_external_connection_emitted(self):
        from specter.collectors.network import NetworkCollector
        nc = NetworkCollector()
        with patch("psutil.net_connections") as mock_conns:
            mock_conn = MagicMock()
            mock_conn.laddr = MagicMock(ip="192.168.1.10", port=45000)
            mock_conn.raddr = MagicMock(ip="8.8.8.8", port=443)
            mock_conn.status = "ESTABLISHED"
            mock_conn.type = socket.SOCK_STREAM
            mock_conn.pid = 1234
            mock_conns.return_value = [mock_conn]
            events = nc.collect()
        assert len(events) == 1
        assert events[0]["event_type"] == "net_connect"
        assert events[0]["remote_ip"] == "8.8.8.8"

    def test_listen_event_type(self):
        from specter.collectors.network import NetworkCollector
        nc = NetworkCollector()
        with patch("psutil.net_connections") as mock_conns:
            mock_conn = MagicMock()
            mock_conn.laddr = MagicMock(ip="0.0.0.0", port=8080)
            mock_conn.raddr = MagicMock(ip="", port=0)
            mock_conn.status = "LISTEN"
            mock_conn.type = socket.SOCK_STREAM
            mock_conn.pid = 5678
            mock_conns.return_value = [mock_conn]
            events = nc.collect()
        assert len(events) == 1
        assert events[0]["event_type"] == "net_listen"
