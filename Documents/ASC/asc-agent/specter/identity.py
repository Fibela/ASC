"""
SPECTER identity — Ed25519 keypair lifecycle.

The agent's keypair is its cryptographic identity:
  - Generated once on first run, persisted to disk.
  - Public key is registered with the ASC backend.
  - Private key never leaves the endpoint.
  - All telemetry events are signed with the private key.
  - All commands from backend are verified with the backend's public key.
"""

import base64
import json
import os
import platform
import socket
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat,
)


# ── Storage ────────────────────────────────────────────────────────────────────

def _state_dir() -> Path:
    """Platform-appropriate state directory for SPECTER persistence."""
    if platform.system() == "Windows":
        base = Path(os.environ.get("PROGRAMDATA", "C:/ProgramData"))
    else:
        base = Path("/var/lib")
    d = base / "specter"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _state_file() -> Path:
    return _state_dir() / "identity.json"


# ── Keypair ────────────────────────────────────────────────────────────────────

def load_or_generate_keypair() -> tuple[str, str]:
    """
    Load existing Ed25519 keypair from disk, or generate a new one.
    Returns (private_key_b64, public_key_b64).
    """
    state = _state_file()
    if state.exists():
        try:
            data = json.loads(state.read_text())
            return data["private_key"], data["public_key"]
        except Exception:
            pass  # corrupted state — regenerate

    # Generate fresh keypair
    key = Ed25519PrivateKey.generate()
    priv = base64.b64encode(
        key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    ).decode()
    pub = base64.b64encode(
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()

    state.write_text(json.dumps({"private_key": priv, "public_key": pub}))
    # Restrict permissions on Unix
    if platform.system() != "Windows":
        state.chmod(0o600)

    return priv, pub


def sign_event(private_key_b64: str, payload: dict[str, Any]) -> str:
    """
    Sign a telemetry event payload with the agent's private key.
    Returns base64-encoded signature.
    """
    priv_bytes = base64.b64decode(private_key_b64)
    key = Ed25519PrivateKey.from_private_bytes(priv_bytes)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return base64.b64encode(key.sign(canonical)).decode()


def verify_command(backend_pub_key_b64: str, payload: dict[str, Any], signature_b64: str) -> bool:
    """
    Verify a command signed by the ASC backend before executing it.
    Returns True only if the signature is valid.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    try:
        pub_bytes = base64.b64decode(backend_pub_key_b64)
        pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        sig = base64.b64decode(signature_b64)
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        pub_key.verify(sig, canonical)
        return True
    except (InvalidSignature, Exception):
        return False


# ── Host metadata ──────────────────────────────────────────────────────────────

def get_host_info() -> dict[str, str]:
    """Collect static host metadata for agent registration."""
    uname = platform.uname()
    return {
        "hostname":    socket.gethostname(),
        "os_type":     platform.system().lower(),   # windows | linux | darwin
        "os_version":  uname.version or uname.release,
        "arch":        uname.machine or platform.machine(),
        "ip_address":  _get_primary_ip(),
    }


def _get_primary_ip() -> str:
    """Determine the primary outbound IP without making an actual connection."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


# ── Agent ID persistence ───────────────────────────────────────────────────────

def load_agent_id() -> str | None:
    state = _state_dir() / "agent_id.txt"
    if state.exists():
        return state.read_text().strip() or None
    return None


def save_agent_id(agent_id: str) -> None:
    state = _state_dir() / "agent_id.txt"
    state.write_text(agent_id)
