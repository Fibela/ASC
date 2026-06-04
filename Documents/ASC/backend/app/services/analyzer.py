"""
Artifact Analysis Service — hashing, magic detection, IoC matching, YARA scanning.
"""
import hashlib
import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO

from app.core.config import get_settings
from app.core.logging import get_logger

settings = get_settings()
log = get_logger(__name__)

# Inline YARA-style signature patterns (simplified regex-based engine)
SIGNATURES = [
    {"name": "Mimikatz_strings",       "pattern": b"sekurlsa::logonpasswords",  "severity": "critical", "threat": "credential_dumping"},
    {"name": "Metasploit_payload",     "pattern": b"meterpreter",               "severity": "critical", "threat": "exploit"},
    {"name": "Cobalt_Strike_beacon",   "pattern": b"ReflectiveDll",             "severity": "critical", "threat": "c2"},
    {"name": "Ransomware_extension",   "pattern": b".encrypted",                "severity": "high",     "threat": "ransomware"},
    {"name": "PowerShell_encoded",     "pattern": b"powershell -enc",           "severity": "high",     "threat": "execution"},
    {"name": "Base64_shellcode",       "pattern": b"TVqQAAMAAAAEAAAA",          "severity": "high",     "threat": "shellcode"},
    {"name": "Reverse_shell_bash",     "pattern": b"/bin/bash -i >& /dev/tcp", "severity": "critical", "threat": "reverse_shell"},
    {"name": "Cmd_execution",          "pattern": b"cmd.exe /c",               "severity": "medium",   "threat": "execution"},
    {"name": "Registry_run_key",       "pattern": b"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "severity": "high", "threat": "persistence"},
    {"name": "Scheduled_task_persist", "pattern": b"schtasks /create",         "severity": "high",     "threat": "persistence"},
    {"name": "LSASS_dump",             "pattern": b"lsass.dmp",                "severity": "critical", "threat": "credential_dumping"},
    {"name": "WMI_lateral_movement",   "pattern": b"wmic process call create", "severity": "high",     "threat": "lateral_movement"},
]

SUSPICIOUS_EXTENSIONS = {".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".hta", ".scr", ".com", ".pif"}
TRUSTED_EXTENSIONS = {".txt", ".jpg", ".png", ".pdf", ".docx", ".xlsx"}


def _compute_hashes(data: bytes) -> dict:
    return {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _scan_signatures(data: bytes) -> list[dict]:
    hits = []
    data_lower = data.lower()
    for sig in SIGNATURES:
        if sig["pattern"].lower() in data_lower:
            hits.append({
                "rule":     sig["name"],
                "severity": sig["severity"],
                "threat":   sig["threat"],
            })
    return hits


def _detect_file_type(data: bytes, filename: str) -> str:
    """Magic-byte detection for common file types."""
    magic = {
        b"MZ":         "PE Executable (Windows)",
        b"\x7fELF":    "ELF Executable (Linux)",
        b"PK\x03\x04": "ZIP/Office Document",
        b"%PDF":       "PDF Document",
        b"\xd0\xcf\x11\xe0": "OLE2 (Office 97)",
        b"<!DOCTYPE":  "HTML Document",
        b"<script":    "Script",
    }
    for signature, label in magic.items():
        if data[:len(signature)] == signature:
            return label
    ext = Path(filename).suffix.lower()
    return f"Unknown ({ext})"


def _calculate_risk_score(hashes: dict, sig_hits: list, file_type: str, filename: str) -> float:
    score = 0.0
    ext = Path(filename).suffix.lower()

    # Suspicious extension
    if ext in SUSPICIOUS_EXTENSIONS:
        score += 0.25
    # PE executable
    if "PE Executable" in file_type or "ELF" in file_type:
        score += 0.15

    # Signature hits
    severity_weights = {"critical": 0.40, "high": 0.25, "medium": 0.15, "low": 0.05}
    for hit in sig_hits:
        score += severity_weights.get(hit["severity"], 0.05)

    # Double extension trick
    parts = filename.split(".")
    if len(parts) > 2 and parts[-1].lower() in ["exe", "dll", "bat"]:
        score += 0.20

    return min(round(score, 3), 1.0)


async def analyze_artifact(filename: str, data: bytes) -> dict:
    """Full artifact analysis pipeline. Returns analysis result dict."""
    log.info("artifact_analysis_start", filename=filename, size=len(data))

    hashes    = _compute_hashes(data)
    file_type = _detect_file_type(data, filename)
    sig_hits  = _scan_signatures(data)
    risk      = _calculate_risk_score(hashes, sig_hits, file_type, filename)

    verdict = "clean"
    if risk >= settings.ALERT_CRITICAL_THRESHOLD:
        verdict = "malicious"
    elif risk >= settings.ALERT_MEDIUM_THRESHOLD:
        verdict = "suspicious"

    result = {
        "filename":       filename,
        "file_type":      file_type,
        "size_bytes":     len(data),
        "hashes":         hashes,
        "risk_score":     risk,
        "verdict":        verdict,
        "signature_hits": sig_hits,
        "analyzed_at":    datetime.now(timezone.utc).isoformat(),
        "ttps":           list({h["threat"] for h in sig_hits}),
    }
    log.info("artifact_analysis_done", filename=filename, verdict=verdict, risk=risk)
    return result


async def analyze_domain(domain: str) -> dict:
    """Basic domain reputation check."""
    suspicious_tlds = {".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw"}
    risk = 0.0
    flags = []

    tld = "." + domain.split(".")[-1].lower()
    if tld in suspicious_tlds:
        risk += 0.30
        flags.append("suspicious_tld")

    # Entropy-based DGA detection
    import math
    freq = {}
    for c in domain.lower():
        freq[c] = freq.get(c, 0) + 1
    entropy = -sum((f / len(domain)) * math.log2(f / len(domain)) for f in freq.values())
    if entropy > 3.8:
        risk += 0.35
        flags.append("high_entropy_dga")

    if len(domain) > 40:
        risk += 0.15
        flags.append("long_domain")

    return {
        "domain":     domain,
        "risk_score": min(round(risk, 3), 1.0),
        "flags":      flags,
        "verdict":    "suspicious" if risk > 0.4 else "clean",
    }


async def analyze_ip(ip: str) -> dict:
    """Basic IP reputation check (local heuristics only, ABUSEIPDB optional)."""
    import ipaddress
    flags = []
    risk = 0.0
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private:
            flags.append("private_ip")
        if addr.is_loopback:
            flags.append("loopback")
        if addr.is_multicast:
            flags.append("multicast")
            risk += 0.1
    except ValueError:
        risk = 0.5
        flags.append("invalid_ip")

    return {
        "ip":         ip,
        "risk_score": min(round(risk, 3), 1.0),
        "flags":      flags,
        "verdict":    "suspicious" if risk > 0.4 else "clean",
    }
