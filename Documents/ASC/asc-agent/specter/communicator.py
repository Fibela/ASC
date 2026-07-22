"""
SPECTER Communicator — HTTPS client for ASC backend communication (P13 + P14).

Responsibilities:
  - Register agent with enrollment token (SPECTER_ENROLLMENT_TOKEN env var)
  - Submit signed telemetry event batches
  - Poll for pending commands (adaptive interval)
  - Report command execution results
  - Self-heal: re-register if backend returns 404 on our agent_id
"""

import os
import time
from typing import Any

import httpx

from specter import __version__
from specter.identity import (
    get_host_info,
    load_agent_id,
    load_or_generate_keypair,
    save_agent_id,
    sign_event,
    verify_command,
)


class SprecterComm:
    def __init__(self, backend_url: str, verify_ssl: bool = True) -> None:
        self._url = backend_url.rstrip("/")
        self._verify = verify_ssl
        self._priv_key, self._pub_key = load_or_generate_keypair()
        self._agent_id: str | None = load_agent_id()
        self._backend_pub_key: str = ""
        self._poll_interval: int = 30
        self._threat_level: str = "normal"
        # S108.2 — seguimiento de conectividad (Capa 3, monitor distribuido)
        self._offline_since = None
        self._offline_ticks: int = 0
        self._pending_gap: dict[str, Any] | None = None

    # ── Registration ───────────────────────────────────────────────────────────

    def register(self) -> bool:
        """Register (or re-register) with the ASC backend. Returns True on success."""
        host = get_host_info()
        payload = {
            **host,
            "public_key":      self._pub_key,
            "specter_version": __version__,
        }
        # Barrier: include enrollment token from env if configured
        extra_headers: dict[str, str] = {}
        token = os.environ.get("SPECTER_ENROLLMENT_TOKEN", "")
        if token:
            extra_headers["X-Specter-Token"] = token

        try:
            r = self._post(
                "/api/v1/agents/register",
                payload,
                auth=False,
                extra_headers=extra_headers or None,
            )
            self._agent_id        = r["agent_id"]
            self._poll_interval   = r.get("poll_interval", 30)
            self._threat_level    = r.get("threat_level", "normal")
            self._backend_pub_key = r.get("backend_pub_key", "")
            save_agent_id(self._agent_id)
            return True
        except Exception as exc:
            print(f"[SPECTER] Registration failed: {exc}")
            return False

    # ── Telemetry ──────────────────────────────────────────────────────────────

    def submit_events(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        """Sign each event and submit the batch to the backend."""
        signed: list[dict[str, Any]] = []
        for ev in events:
            payload = dict(ev)
            sig = sign_event(self._priv_key, payload)
            payload["signature"] = sig
            signed.append(payload)

        try:
            result = self._post(f"/api/v1/agents/{self._agent_id}/events",
                                {"events": signed})
            self._mark_reachable(True)
            return result
        except httpx.HTTPStatusError as exc:
            self._mark_reachable(True)   # respondió (error de app) → la red funciona
            return {"error": str(exc)}
        except Exception as exc:
            self._mark_reachable(False)  # sin respuesta → outage de red/backend
            return {"error": str(exc)}

    # ── Command polling ────────────────────────────────────────────────────────

    def poll_commands(self) -> list[dict[str, Any]]:
        """
        Poll for pending commands. Updates adaptive poll_interval and threat_level.
        Verifies backend Ed25519 signature; invalid-signature commands are discarded.
        """
        try:
            resp = self._get(f"/api/v1/agents/{self._agent_id}/commands")
            self._poll_interval = resp.get("poll_interval", self._poll_interval)
            self._threat_level  = resp.get("threat_level", self._threat_level)

            verified: list[dict[str, Any]] = []
            for cmd in resp.get("commands", []):
                sig = cmd.pop("signature", "")
                if not self._backend_pub_key or verify_command(
                    self._backend_pub_key, cmd, sig
                ):
                    cmd["signature"] = sig
                    verified.append(cmd)
                else:
                    print(f"[SPECTER] WARNING: command {cmd.get('id')} has invalid signature — discarded")
            self._mark_reachable(True)
            return verified
        except httpx.HTTPStatusError as exc:
            self._mark_reachable(True)   # respondió → red OK
            if exc.response.status_code == 404:
                print("[SPECTER] Agent not found — re-registering…")
                self.register()
            return []
        except Exception as exc:
            self._mark_reachable(False)  # sin respuesta → outage
            print(f"[SPECTER] Poll error: {exc}")
            return []

    # ── Command results ────────────────────────────────────────────────────────

    def report_result(
        self,
        command_id: str,
        success: bool,
        result: dict[str, Any],
        error: str | None = None,
    ) -> None:
        try:
            self._post(
                f"/api/v1/agents/{self._agent_id}/results",
                {
                    "command_id": command_id,
                    "success":    success,
                    "result":     result,
                    "error":      error,
                },
            )
        except Exception as exc:
            print(f"[SPECTER] Failed to report result: {exc}")

    # ── Connectivity tracking (S108.2 — red SPECTER como monitor distribuido) ────

    def _mark_reachable(self, ok: bool) -> None:
        """Registra si el backend respondió. Al recuperar contacto tras un hueco,
        deja un reporte de gap pendiente para enviarlo como telemetría firmada."""
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        if ok:
            if self._offline_since is not None:
                self._pending_gap = {
                    "event_type":       "specter.connectivity_gap",
                    "severity":         "info",
                    "unreachable_from": self._offline_since.isoformat(),
                    "unreachable_to":   now.isoformat(),
                    "ticks":            self._offline_ticks,
                    "ts":               now.timestamp(),
                }
                self._offline_since = None
                self._offline_ticks = 0
        else:
            if self._offline_since is None:
                self._offline_since = now
            self._offline_ticks += 1

    def pop_pending_gap(self) -> dict[str, Any] | None:
        """Devuelve (y limpia) el reporte de gap pendiente, si lo hay."""
        gap, self._pending_gap = self._pending_gap, None
        return gap

    # ── HTTP helpers ───────────────────────────────────────────────────────────

    def _headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self._agent_id:
            h["X-Specter-ID"] = self._agent_id
        return h

    def _post(
        self,
        path: str,
        body: dict,
        auth: bool = True,
        extra_headers: dict[str, str] | None = None,
    ) -> dict:
        headers = self._headers() if auth else {"Content-Type": "application/json"}
        if extra_headers:
            headers.update(extra_headers)
        with httpx.Client(verify=self._verify, timeout=15) as client:
            r = client.post(f"{self._url}{path}", json=body, headers=headers)
            r.raise_for_status()
            return r.json()

    def _get(self, path: str) -> dict:
        with httpx.Client(verify=self._verify, timeout=15) as client:
            r = client.get(f"{self._url}{path}", headers=self._headers())
            r.raise_for_status()
            return r.json()

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def poll_interval(self) -> int:
        return self._poll_interval

    @property
    def threat_level(self) -> str:
        return self._threat_level

    @property
    def agent_id(self) -> str | None:
        return self._agent_id

    @property
    def priv_key(self) -> str:
        """Ed25519 private key (base64). Used by security.handle_canary_ping."""
        return self._priv_key
