"""
SPECTER Agent — main loop (P13 + P14 Security Hardening).

Lifecycle:
  1. Load/generate Ed25519 keypair
  2. Enforce HTTPS on backend URL (warn or raise)
  3. Register with ASC backend (idempotent, enrollment token from env)
  4. Loop:
     a. Collect delta events
     b. Submit signed event batch
     c. Poll for commands → validate (freshness + fields) → injection check
     d. Dispatch: canary_ping → security handler, others → executor
     e. Report command results
     f. Sleep for adaptive poll_interval (30s/5s/1s by threat level)

P14 security layers active in this agent:
  - HTTPS enforcement on init (warn / raise configurable)
  - Command freshness validation (rejects commands >300s old)
  - Shell injection detection in params before executor dispatch
  - Canary ping handler (Ed25519 proof-of-private-key)
  - Enrollment token included in registration (from SPECTER_ENROLLMENT_TOKEN env)
"""

import os
import signal
import sys
import time
from typing import Any

from specter import __product__, __version__
from specter import security
from specter.collectors.network import NetworkCollector
from specter.collectors.processes import ProcessCollector
from specter.communicator import SprecterComm
from specter.executor import (
    block_ip,
    isolate_endpoint,
    kill_process,
    log_query,
    unblock_domain,
    unblock_ip,
    unisolate,
)


# ── Command dispatcher ─────────────────────────────────────────────────────────

EXECUTORS: dict[str, Any] = {
    # Neutralization (P13)
    "kill_process":      kill_process.execute,
    "block_ip":          block_ip.execute,
    # Isolation / rollback (P35)
    "isolate_endpoint":  isolate_endpoint.execute,
    "unisolate":         unisolate.execute,
    "unblock_ip":        unblock_ip.execute,
    "unblock_domain":    unblock_domain.execute,
    # Passive hunt dispatch (P24/P35)
    "log_query":         log_query.execute,
}


def _execute_command(cmd: dict) -> tuple[bool, dict, str | None]:
    """Dispatch a validated command to its executor. Returns (success, result, error)."""
    ctype  = cmd.get("command_type", "")
    params = cmd.get("params", {})
    fn = EXECUTORS.get(ctype)
    if fn is None:
        return False, {}, f"Unknown command_type: {ctype}"
    try:
        result = fn(params)
        return result.get("success", False), result, result.get("message")
    except Exception as exc:
        return False, {}, str(exc)


# ── Main agent loop ────────────────────────────────────────────────────────────

class SprecterAgent:
    def __init__(self, backend_url: str, verify_ssl: bool = True) -> None:
        self._comm   = SprecterComm(backend_url, verify_ssl)
        self._procs  = ProcessCollector()
        self._net    = NetworkCollector()
        self._running = True

        # Barrier: HTTPS enforcement — configurable strict mode
        strict_https = os.environ.get("SPECTER_STRICT_HTTPS", "false").lower() == "true"
        security.enforce_https(backend_url, strict=strict_https)

        signal.signal(signal.SIGINT,  self._shutdown)
        signal.signal(signal.SIGTERM, self._shutdown)

    def _shutdown(self, *_: Any) -> None:
        print("\n[SPECTER] Shutdown signal received. Stopping…")
        self._running = False

    def run(self) -> None:
        print(f"[SPECTER] {__product__} v{__version__} starting…")

        if not self._comm.register():
            print("[SPECTER] FATAL: could not register with backend. Exiting.")
            sys.exit(1)

        print(f"[SPECTER] Registered. Agent ID: {self._comm.agent_id}")
        print(f"[SPECTER] Initial threat level: {self._comm.threat_level}")
        print(f"[SPECTER] Initial poll interval: {self._comm.poll_interval}s")

        # Warm up collectors — take initial snapshot silently
        self._procs.collect()
        self._net.collect()

        while self._running:
            try:
                self._tick()
            except Exception as exc:
                print(f"[SPECTER] Tick error: {exc}")
            time.sleep(self._comm.poll_interval)

        print("[SPECTER] Agent stopped.")

    def _tick(self) -> None:
        # 1. Collect events
        events: list[dict] = []
        # S108.2 — si se recuperó contacto tras un hueco, reportar el gap primero
        gap = self._comm.pop_pending_gap()
        if gap:
            events.append(gap)
            print(f"[SPECTER] Reportando gap de conectividad ({gap.get('ticks')} ticks sin contacto)")
        events.extend(self._procs.collect())
        events.extend(self._net.collect())

        # 2. Submit telemetry (only if there's something to report)
        if events:
            result = self._comm.submit_events(events)
            rejected = result.get("rejected", 0)
            if rejected:
                print(f"[SPECTER] {rejected} events rejected by backend (replay/sig)")

        # 3. Poll for commands
        commands = self._comm.poll_commands()

        # 4. Execute + report results
        for cmd in commands:
            cmd_id = cmd.get("id", "?")
            ctype  = cmd.get("command_type", "?")

            # Filter: validate command structure and freshness
            valid, reason = security.validate_command(cmd)
            if not valid:
                print(f"[SPECTER-GUARD] Command {cmd_id} rejected: {reason}")
                self._comm.report_result(cmd_id, False, {}, f"Security validation failed: {reason}")
                continue

            # Filter: injection detection in params
            params = cmd.get("params", {})
            flagged = security.check_param_injection(params)
            if flagged:
                print(f"[SPECTER-GUARD] Injection detected in command {cmd_id} params: {flagged}")
                self._comm.report_result(
                    cmd_id, False, {}, f"Injection pattern detected in params: {flagged}"
                )
                continue

            # Trap: canary ping — prove we hold the original private key
            if ctype == "canary_ping":
                print(f"[SPECTER] Responding to canary ping (id={cmd_id})")
                pong = security.handle_canary_ping(self._comm.priv_key, params)
                self._comm.report_result(cmd_id, True, pong)
                continue

            print(f"[SPECTER] Executing command: {ctype} (id={cmd_id})")
            success, result, error = _execute_command(cmd)
            self._comm.report_result(cmd_id, success, result, error)
            status_str = "OK" if success else f"FAILED: {error}"
            print(f"[SPECTER] Command {ctype}: {status_str}")


def main() -> None:
    backend = os.environ.get("SPECTER_BACKEND_URL", "https://asc.premoscorp.com")
    verify  = os.environ.get("SPECTER_VERIFY_SSL", "true").lower() != "false"
    SprecterAgent(backend, verify).run()


if __name__ == "__main__":
    main()
