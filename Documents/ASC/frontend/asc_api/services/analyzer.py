"""
Artifact Analysis Service — hashing, magic detection, signature scanning,
PE import analysis, and mutex extraction (P7).

Pipeline for analyze_artifact():
  1. Hash computation (MD5 / SHA1 / SHA256)
  2. Magic-byte file-type detection
  3. YARA-style signature scan
  4. String extraction — ASCII + UTF-16LE wide strings
  5. PE import table parsing — mutex APIs + suspicious APIs (pure Python, no deps)
  6. Mutex candidate extraction and classification
  7. Risk score aggregation (signatures + mutex + imports)
"""
import hashlib
import re
import struct
import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Any

import httpx

from asc_api.core.config import get_settings
from asc_api.core.logging import get_logger

settings = get_settings()
log = get_logger(__name__)


# ─── Signature database ───────────────────────────────────────────────────────

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
TRUSTED_EXTENSIONS    = {".txt", ".jpg", ".png", ".pdf", ".docx", ".xlsx"}


# ─── P7: String extraction constants ──────────────────────────────────────────

_MIN_STRING_LEN = 4


# ─── P7: PE import constants ──────────────────────────────────────────────────

# Windows mutex-related API names (as bytes for fast lookup)
_MUTEX_APIS: frozenset[bytes] = frozenset({
    b"CreateMutexA", b"CreateMutexW",
    b"OpenMutexA",   b"OpenMutexW",
    b"CreateMutexExA", b"CreateMutexExW",
})

# High-risk API names and their ATT&CK TTP + severity
_SUSPICIOUS_IMPORT_APIS: dict[bytes, tuple[str, str]] = {
    b"VirtualAllocEx":              ("process_injection",    "high"),
    b"WriteProcessMemory":          ("process_injection",    "high"),
    b"CreateRemoteThread":          ("process_injection",    "critical"),
    b"NtCreateThreadEx":            ("process_injection",    "critical"),
    b"RtlCreateUserThread":         ("process_injection",    "critical"),
    b"AdjustTokenPrivileges":       ("privilege_escalation", "high"),
    b"IsDebuggerPresent":           ("anti_debug",           "medium"),
    b"CheckRemoteDebuggerPresent":  ("anti_debug",           "medium"),
    b"NtQueryInformationProcess":   ("anti_debug",           "medium"),
    b"VirtualProtect":              ("shellcode_prep",       "medium"),
    b"WinExec":                     ("execution",            "high"),
    b"ShellExecuteA":               ("execution",            "medium"),
    b"ShellExecuteW":               ("execution",            "medium"),
    b"ShellExecuteExA":             ("execution",            "medium"),
    b"ShellExecuteExW":             ("execution",            "medium"),
    b"RegSetValueExA":              ("persistence",          "medium"),
    b"RegSetValueExW":              ("persistence",          "medium"),
    b"RegCreateKeyExA":             ("persistence",          "medium"),
    b"RegCreateKeyExW":             ("persistence",          "medium"),
    b"CryptEncrypt":                ("encryption",           "medium"),
    b"CryptDecrypt":                ("encryption",           "medium"),
    b"NetShareAdd":                 ("lateral_movement",     "high"),
    b"WNetAddConnection2A":         ("lateral_movement",     "medium"),
    b"WNetAddConnection2W":         ("lateral_movement",     "medium"),
}


# ─── P7: Known malware mutex signatures ───────────────────────────────────────

_KNOWN_MALWARE_MUTEXES: list[dict] = [
    # ── Exact matches ──────────────────────────────────────────────────────
    {
        "pattern": "{1D6FC66E-D1F3-422C-8A53-C0BBCF3D900D}", "match": "exact",
        "family": "Cobalt Strike Beacon", "severity": "critical", "ttp": "c2",
    },
    {
        "pattern": "Global\\MsWinZonesCacheCounterMutexA", "match": "exact",
        "family": "WannaCry/NotPetya", "severity": "critical", "ttp": "ransomware",
    },
    {
        "pattern": "Global\\MsWinZonesCacheCounterMutexW", "match": "exact",
        "family": "WannaCry/NotPetya", "severity": "critical", "ttp": "ransomware",
    },
    {
        "pattern": "WNcry@2ol7", "match": "exact",
        "family": "WannaCry", "severity": "critical", "ttp": "ransomware",
    },
    {
        "pattern": "MsMpEngMutex", "match": "exact",
        "family": "AV Evasion (Defender)", "severity": "medium", "ttp": "defense_evasion",
    },
    {
        "pattern": "DCRAT_MUTEX", "match": "exact",
        "family": "NjRAT/DarkComet", "severity": "high", "ttp": "rat",
    },
    {
        "pattern": "NANOCORE_V.1", "match": "exact",
        "family": "NanoCore RAT", "severity": "high", "ttp": "rat",
    },
    {
        "pattern": "AZOR_MUTEX", "match": "exact",
        "family": "AZORult Stealer", "severity": "high", "ttp": "infostealer",
    },
    {
        "pattern": "Global\\NetWire", "match": "exact",
        "family": "NetWire RAT", "severity": "high", "ttp": "rat",
    },
    {
        "pattern": "ESET_KERNEL_MUTEX", "match": "exact",
        "family": "AV Evasion (ESET)", "severity": "medium", "ttp": "defense_evasion",
    },
    {
        "pattern": "Global\\SynFlooder", "match": "exact",
        "family": "SYN Flooder", "severity": "high", "ttp": "ddos",
    },
    # ── Prefix matches ─────────────────────────────────────────────────────
    {
        "pattern": "DC_MUTEX-", "match": "prefix",
        "family": "DarkComet RAT", "severity": "high", "ttp": "rat",
    },
    {
        "pattern": "NANOCORE", "match": "prefix",
        "family": "NanoCore RAT", "severity": "high", "ttp": "rat",
    },
    {
        "pattern": "Global\\njRAT", "match": "prefix",
        "family": "NjRAT", "severity": "high", "ttp": "rat",
    },
]

# Pre-compiled regex patterns
_GUID_RE = re.compile(
    r'\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}',
    re.IGNORECASE,
)
_HEX_RE = re.compile(r'^[0-9A-Fa-f]{16,64}$')

# Strings to unconditionally exclude from mutex candidates (API names, DLL names)
_EXCLUDE_FROM_MUTEX: frozenset[str] = frozenset({
    "CreateMutexA", "CreateMutexW", "OpenMutexA", "OpenMutexW",
    "CreateMutexExA", "CreateMutexExW",
    "kernel32.dll", "user32.dll", "ntdll.dll", "advapi32.dll",
    "msvcrt.dll", "ws2_32.dll", "shell32.dll", "ole32.dll",
    "wininet.dll", "winhttp.dll", "psapi.dll", "shlwapi.dll",
})


# ─── Existing helpers ─────────────────────────────────────────────────────────

def _compute_hashes(data: bytes) -> dict:
    # usedforsecurity=False: these hashes are for artifact identification and
    # IOC matching (threat intel databases use MD5/SHA1), not for auth/crypto.
    return {
        "md5":    hashlib.md5(data, usedforsecurity=False).hexdigest(),    # nosec B324
        "sha1":   hashlib.sha1(data, usedforsecurity=False).hexdigest(),   # nosec B324
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
    magic = {
        b"MZ":              "PE Executable (Windows)",
        b"\x7fELF":         "ELF Executable (Linux)",
        b"PK\x03\x04":      "ZIP/Office Document",
        b"%PDF":            "PDF Document",
        b"\xd0\xcf\x11\xe0":"OLE2 (Office 97)",
        b"<!DOCTYPE":       "HTML Document",
        b"<script":         "Script",
    }
    for signature, label in magic.items():
        if data[: len(signature)] == signature:
            return label
    ext = Path(filename).suffix.lower()
    return f"Unknown ({ext})"


# ─── P7: String extraction ────────────────────────────────────────────────────

def _extract_strings(data: bytes, min_len: int = _MIN_STRING_LEN) -> list[str]:
    """
    Extract printable ASCII and UTF-16LE wide strings from binary data.
    Equivalent to the Unix `strings` utility with wide-string support.

    ASCII:    consecutive printable bytes (0x20–0x7E) of length >= min_len.
    Wide:     alternating printable_byte + 0x00 pairs, at least min_len pairs,
              decoded as UTF-16LE.
    """
    results: set[str] = set()

    # ASCII strings
    ascii_pat = re.compile(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}")
    for m in ascii_pat.finditer(data):
        results.add(m.group().decode("ascii", errors="replace"))

    # Wide strings (UTF-16LE): each char = printable_byte + \x00
    wide_pat = re.compile(rb"(?:[\x20-\x7e]\x00){" + str(min_len).encode() + rb",}")
    for m in wide_pat.finditer(data):
        try:
            results.add(m.group().decode("utf-16-le", errors="replace"))
        except Exception:  # nosec B110 — intentional: malformed wide-char strings are silently skipped
            pass

    return sorted(results)


# ─── P7: PE import table parser ───────────────────────────────────────────────

def _parse_pe_imports(data: bytes) -> dict:
    """
    Parse the import directory table of a Portable Executable (PE) binary.
    Supports both PE32 (32-bit) and PE32+ (64-bit) formats.

    Returns:
      is_pe          — True if MZ magic + valid PE signature found
      arch           — "PE32" | "PE32+" | "unknown"
      mutex_apis     — list of mutex-related APIs in the import table
      suspicious_apis— list of {name, ttp, severity} for high-risk imports
      all_imports    — dict mapping DLL name → list of imported function names

    Always returns the base dict (never raises).  All struct access is
    bounds-checked; any parse error logs a warning and returns what was
    collected up to that point.
    """
    base: dict = {
        "is_pe": False, "arch": "unknown",
        "mutex_apis": [], "suspicious_apis": [], "all_imports": {},
    }
    try:
        if len(data) < 64:
            return base

        # DOS header: MZ magic at offset 0
        if data[0:2] != b"MZ":
            return base
        base["is_pe"] = True

        # e_lfanew at offset 0x3C (file offset of PE signature)
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_off + 24 > len(data):
            return base
        if data[pe_off: pe_off + 4] != b"PE\x00\x00":
            return base   # MZ but no valid PE header (bare DOS stub)

        # IMAGE_FILE_HEADER (20 bytes starting at pe_off + 4)
        fh             = pe_off + 4
        num_sections   = struct.unpack_from("<H", data, fh + 2)[0]
        size_opt_hdr   = struct.unpack_from("<H", data, fh + 16)[0]

        # OptionalHeader starts at pe_off + 24
        opt = pe_off + 24
        if opt + 4 > len(data):
            return base
        opt_magic = struct.unpack_from("<H", data, opt)[0]

        # DataDirectory[1] (Import) byte offset within OptionalHeader:
        #   PE32  (0x010B): fixed header fields = 96 bytes before DataDirectory
        #   PE32+ (0x020B): fixed header fields = 112 bytes before DataDirectory
        if opt_magic == 0x010B:
            base["arch"] = "PE32"
            dd_base = opt + 96
        elif opt_magic == 0x020B:
            base["arch"] = "PE32+"
            dd_base = opt + 112
        else:
            return base

        # Skip DataDirectory[0] (Export); read DataDirectory[1] (Import)
        import_dd = dd_base + 8
        if import_dd + 8 > len(data):
            return base
        import_rva, _ = struct.unpack_from("<II", data, import_dd)
        if import_rva == 0:
            return base  # No imports

        # Section headers start immediately after OptionalHeader
        secs_off = opt + size_opt_hdr
        sections: list[tuple[int, int, int, int]] = []  # (vaddr, vsize, raw_ptr, raw_size)
        for i in range(min(num_sections, 96)):          # max 96 sections (PE spec)
            sh = secs_off + i * 40
            if sh + 40 > len(data):
                break
            vsize    = struct.unpack_from("<I", data, sh + 8)[0]
            vaddr    = struct.unpack_from("<I", data, sh + 12)[0]
            raw_size = struct.unpack_from("<I", data, sh + 16)[0]
            raw_ptr  = struct.unpack_from("<I", data, sh + 20)[0]
            sections.append((vaddr, vsize, raw_ptr, raw_size))

        def rva_to_off(rva: int) -> int | None:
            """Convert a Relative Virtual Address to a file offset."""
            for (va, vs, rp, rs) in sections:
                span = max(vs, rs)
                if span and va <= rva < va + span:
                    off = rp + (rva - va)
                    return off if 0 < off < len(data) else None
            return None

        def read_cstr(off: int, limit: int = 256) -> str:
            """Read a null-terminated ASCII string from the binary."""
            end = data.find(b"\x00", off, off + limit)
            raw = data[off: end if end != -1 else off + limit]
            return raw.decode("ascii", errors="replace")

        # Parse IMAGE_IMPORT_DESCRIPTOR array (terminated by all-zeros entry)
        import_off = rva_to_off(import_rva)
        if import_off is None:
            return base

        # INT entry width: 4 bytes for PE32, 8 bytes for PE32+
        entry_size = 8 if opt_magic == 0x020B else 4

        all_imports: dict[str, list[str]] = {}
        for desc_idx in range(500):          # safety cap
            desc = import_off + desc_idx * 20
            if desc + 20 > len(data):
                break

            orig_thunk, _ts, _fwd, name_rva, first_thunk = struct.unpack_from(
                "<IIIII", data, desc
            )
            if name_rva == 0 and first_thunk == 0:
                break  # null terminator

            dll_off  = rva_to_off(name_rva)
            dll_name = read_cstr(dll_off) if dll_off is not None else f"unknown_{desc_idx}"

            thunk_rva = orig_thunk if orig_thunk else first_thunk
            thunk_off = rva_to_off(thunk_rva) if thunk_rva else None

            functions: list[str] = []
            if thunk_off is not None:
                for fn_idx in range(2_000):   # safety cap per DLL
                    t = thunk_off + fn_idx * entry_size
                    if t + entry_size > len(data):
                        break

                    if entry_size == 8:
                        val    = struct.unpack_from("<Q", data, t)[0]
                        by_ord = bool(val & (1 << 63))
                        fn_rva = int(val & 0x7FFF_FFFF_FFFF_FFFF)
                    else:
                        val    = struct.unpack_from("<I", data, t)[0]
                        by_ord = bool(val & (1 << 31))
                        fn_rva = int(val & 0x7FFF_FFFF)

                    if val == 0:
                        break
                    if not by_ord and fn_rva:
                        fn_off = rva_to_off(fn_rva)
                        if fn_off is not None and fn_off + 2 < len(data):
                            fn_name = read_cstr(fn_off + 2)  # skip 2-byte Hint field
                            if fn_name:
                                functions.append(fn_name)

            all_imports[dll_name] = functions

        # Classify imported functions
        mutex_apis: list[str] = []
        suspicious_apis: list[dict] = []
        for _, funcs in all_imports.items():
            for fn in funcs:
                fb = fn.encode("ascii", errors="replace")
                if fb in _MUTEX_APIS:
                    mutex_apis.append(fn)
                if fb in _SUSPICIOUS_IMPORT_APIS:
                    ttp, sev = _SUSPICIOUS_IMPORT_APIS[fb]
                    suspicious_apis.append({"name": fn, "ttp": ttp, "severity": sev})

        base["mutex_apis"]       = sorted(set(mutex_apis))
        base["suspicious_apis"]  = suspicious_apis
        base["all_imports"]      = all_imports

    except Exception as exc:
        log.warning("pe_parse_error", error=str(exc))

    return base


# ─── P7: Mutex candidate classification ──────────────────────────────────────

def _classify_mutex_candidate(s: str) -> dict:
    """
    Classify a single string as a potential mutex name.

    Returns a dict with:
      value       — the original string
      is_guid     — True if it matches GUID pattern {xxxxxxxx-...}
      is_hex      — True if it is a 16–64 character hexadecimal string
      confidence  — float 0.0–1.0  (0.95 known malware, 0.70 GUID, 0.55 hex, 0.30 generic)
      known_match — the matching entry from _KNOWN_MALWARE_MUTEXES, or None
    """
    is_guid = bool(_GUID_RE.fullmatch(s))
    is_hex  = bool(_HEX_RE.fullmatch(s))

    known_match: dict | None = None
    s_lower = s.lower()
    for sig in _KNOWN_MALWARE_MUTEXES:
        if sig["match"] == "exact":
            if s == sig["pattern"] or s_lower == sig["pattern"].lower():
                known_match = sig
                break
        elif sig["match"] == "prefix":
            if s.startswith(sig["pattern"]) or s_lower.startswith(sig["pattern"].lower()):
                known_match = sig
                break

    if known_match:
        confidence = 0.95
    elif is_guid:
        confidence = 0.70
    elif is_hex and len(s) >= 16:
        confidence = 0.55
    else:
        confidence = 0.30

    return {
        "value":       s,
        "is_guid":     is_guid,
        "is_hex":      is_hex,
        "confidence":  confidence,
        "known_match": known_match,
    }


# ─── P7: Mutex candidate extraction ──────────────────────────────────────────

def _extract_mutex_candidates(
    strings: list[str],
    import_info: dict,
) -> list[dict]:
    """
    Identify likely mutex name candidates from extracted strings.

    Inclusion strategy:
    - Known malware mutex signatures: always included regardless of context.
    - When mutex APIs are present in the import table (high recall mode):
        include any 4–80-char string that isn't a DLL/path/API name.
    - When no mutex APIs detected (high precision mode):
        include only GUID-like and hex strings.

    Returns at most 50 candidates sorted by confidence descending.
    """
    has_mutex_api = bool(import_info.get("mutex_apis"))
    candidates: list[dict] = []
    seen: set[str] = set()

    for s in strings:
        if s in seen or s in _EXCLUDE_FROM_MUTEX:
            continue
        seen.add(s)

        # Mutex names are rarely >128 chars
        if len(s) > 128:
            continue
        # Skip file extension suffixes (DLL, driver names, etc.)
        if any(s.lower().endswith(ext) for ext in (".dll", ".exe", ".sys", ".drv", ".ocx")):
            continue
        # Skip obvious absolute path strings
        if (s.startswith(("C:\\", "c:\\", "\\\\")) and s.count("\\") >= 2) or s.startswith("/"):
            continue

        c = _classify_mutex_candidate(s)

        include = False
        if c["known_match"]:
            include = True
        elif has_mutex_api and 4 <= len(s) <= 80:
            include = c["is_guid"] or c["is_hex"] or c["confidence"] > 0.25
        else:
            include = c["is_guid"] or c["is_hex"]

        if include:
            candidates.append(c)

    candidates.sort(key=lambda x: (-x["confidence"], x["value"]))
    return candidates[:50]


# ─── Risk score (updated for P7) ─────────────────────────────────────────────

def _calculate_risk_score(
    hashes: dict,
    sig_hits: list,
    file_type: str,
    filename: str,
    mutex_candidates: list[dict] | None = None,
    suspicious_apis: list[dict] | None = None,
) -> float:
    """
    Aggregate risk score (0.0–1.0) from all analysis signals.

    Contributors:
      +0.25  — suspicious file extension (.exe, .dll, etc.)
      +0.15  — PE or ELF executable file type
      +0.20  — double-extension masquerade (doc.pdf.exe)
      +0.05–0.40 per signature hit (severity weighted)
      +0.05–0.40 — single worst known-malware mutex match (severity weighted)
      ≤ 0.25  — suspicious import APIs (40% weight each, capped)
    """
    score = 0.0
    sev_w = {"critical": 0.40, "high": 0.25, "medium": 0.15, "low": 0.05}
    ext   = Path(filename).suffix.lower()

    if ext in SUSPICIOUS_EXTENSIONS:
        score += 0.25
    if "PE Executable" in file_type or "ELF" in file_type:
        score += 0.15

    for hit in sig_hits:
        score += sev_w.get(hit["severity"], 0.05)

    # Double-extension masquerade: report.pdf.exe
    parts = filename.split(".")
    if len(parts) > 2 and parts[-1].lower() in {"exe", "dll", "bat"}:
        score += 0.20

    # Known malware mutex — count only the single worst match
    if mutex_candidates:
        matched = [c for c in mutex_candidates if c.get("known_match")]
        if matched:
            worst = max(
                matched,
                key=lambda c: sev_w.get(c["known_match"].get("severity", "low"), 0.05),
            )
            score += sev_w.get(worst["known_match"].get("severity", "low"), 0.05)

    # Suspicious import APIs — each contributes 40% of its severity weight, capped at 0.25
    if suspicious_apis:
        import_score = sum(
            sev_w.get(a.get("severity", "low"), 0.05) * 0.4
            for a in suspicious_apis
        )
        score += min(import_score, 0.25)

    return min(round(score, 3), 1.0)


# ─── Main analysis pipeline ───────────────────────────────────────────────────

async def analyze_artifact(filename: str, data: bytes) -> dict:
    """
    Full artifact analysis pipeline.

    Returns a dict with hashes, file type, signatures, PE import analysis,
    mutex candidates, suggested IoCs, and aggregated risk score/verdict.
    """
    log.info("artifact_analysis_start", filename=filename, size=len(data))

    hashes    = _compute_hashes(data)
    file_type = _detect_file_type(data, filename)
    sig_hits  = _scan_signatures(data)

    # P7: String + PE + mutex pipeline
    all_strings      = _extract_strings(data)
    import_info      = _parse_pe_imports(data)
    mutex_candidates = _extract_mutex_candidates(all_strings, import_info)

    risk = _calculate_risk_score(
        hashes, sig_hits, file_type, filename,
        mutex_candidates=mutex_candidates,
        suspicious_apis=import_info.get("suspicious_apis", []),
    )

    verdict = "clean"
    if risk >= settings.ALERT_CRITICAL_THRESHOLD:
        verdict = "malicious"
    elif risk >= settings.ALERT_MEDIUM_THRESHOLD:
        verdict = "suspicious"

    # Aggregate TTPs from all sources
    ttps: set[str] = {h["threat"] for h in sig_hits}
    for c in mutex_candidates:
        if c.get("known_match"):
            ttps.add(c["known_match"]["ttp"])
    for api in import_info.get("suspicious_apis", []):
        ttps.add(api["ttp"])

    known_malware_mutexes = [
        {
            "value":    c["value"],
            "family":   c["known_match"]["family"],
            "severity": c["known_match"]["severity"],
            "ttp":      c["known_match"]["ttp"],
        }
        for c in mutex_candidates if c.get("known_match")
    ]

    result = {
        "filename":       filename,
        "file_type":      file_type,
        "size_bytes":     len(data),
        "hashes":         hashes,
        "risk_score":     risk,
        "verdict":        verdict,
        "signature_hits": sig_hits,
        "analyzed_at":    datetime.now(timezone.utc).isoformat(),
        "ttps":           sorted(ttps),
        # ── P7 additions ─────────────────────────────────────────────────
        "strings_count": len(all_strings),
        "pe_analysis": {
            "is_pe":           import_info.get("is_pe", False),
            "arch":            import_info.get("arch", "unknown"),
            "mutex_apis":      import_info.get("mutex_apis", []),
            "suspicious_apis": import_info.get("suspicious_apis", []),
        },
        "mutex_analysis": {
            "candidates_count": len(mutex_candidates),
            "has_mutex_api":    bool(import_info.get("mutex_apis")),
            "mutex_apis":       import_info.get("mutex_apis", []),
            "candidates":       mutex_candidates,
            "known_malware":    known_malware_mutexes,
        },
        # High-confidence mutex candidates ready for IoC creation
        "suggested_iocs": [
            {"type": "mutex", "value": c["value"], "confidence": c["confidence"]}
            for c in mutex_candidates
            if c["confidence"] >= 0.55
        ],
    }

    log.info(
        "artifact_analysis_done",
        filename=filename, verdict=verdict, risk=risk,
        strings=len(all_strings),
        mutex_candidates=len(mutex_candidates),
        known_malware=len(known_malware_mutexes),
    )
    return result


# ─── External threat-feed helpers ─────────────────────────────────────────────

async def _vt_lookup(resource_type: str, resource: str, api_key: str) -> dict[str, Any]:
    """
    Query VirusTotal API v3 for a domain or IP.
    Returns {} gracefully on error or missing key.
    resource_type: 'domains' | 'ip_addresses'
    """
    if not api_key:
        return {}
    url = f"https://www.virustotal.com/api/v3/{resource_type}/{resource}"
    try:
        async with httpx.AsyncClient(timeout=6) as client:
            r = await client.get(url, headers={"x-apikey": api_key})
            if r.status_code == 200:
                attrs = r.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                return {
                    "vt_malicious":   stats.get("malicious", 0),
                    "vt_suspicious":  stats.get("suspicious", 0),
                    "vt_harmless":    stats.get("harmless", 0),
                    "vt_undetected":  stats.get("undetected", 0),
                    "vt_reputation":  attrs.get("reputation", None),
                }
    except Exception:  # nosec B110 — VT is best-effort enrichment, non-fatal
        pass
    return {}


async def _abuseipdb_lookup(ip: str, api_key: str) -> dict[str, Any]:
    """Query AbuseIPDB for IP abuse confidence score. Returns {} on error."""
    if not api_key:
        return {}
    try:
        async with httpx.AsyncClient(timeout=6) as client:
            r = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
            )
            if r.status_code == 200:
                data = r.json().get("data", {})
                return {
                    "abuse_confidence_score": data.get("abuseConfidenceScore"),
                    "abuse_total_reports":    data.get("totalReports"),
                    "abuse_country_code":     data.get("countryCode"),
                    "abuse_isp":              data.get("isp"),
                    "abuse_usage_type":       data.get("usageType"),
                }
    except Exception:  # nosec B110 — AbuseIPDB is best-effort enrichment, non-fatal
        pass
    return {}


# ─── Domain + IP analysis ─────────────────────────────────────────────────────

async def analyze_domain(domain: str) -> dict:
    """
    Domain reputation check — local heuristics + VirusTotal enrichment.
    VT enrichment only fires when VIRUSTOTAL_API_KEY is configured.
    """
    import math
    suspicious_tlds = {".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw"}
    risk  = 0.0
    flags: list[str] = []

    tld = "." + domain.split(".")[-1].lower()
    if tld in suspicious_tlds:
        risk += 0.30
        flags.append("suspicious_tld")

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

    # External enrichment
    vt = await _vt_lookup("domains", domain, settings.VIRUSTOTAL_API_KEY)
    if vt:
        malicious = vt.get("vt_malicious", 0) or 0
        suspicious_vt = vt.get("vt_suspicious", 0) or 0
        if malicious > 0:
            risk = min(risk + 0.4 + malicious * 0.02, 1.0)
            flags.append(f"vt_malicious_detections:{malicious}")
        elif suspicious_vt > 0:
            risk = min(risk + 0.2, 1.0)
            flags.append(f"vt_suspicious_detections:{suspicious_vt}")
        if (vt.get("vt_reputation") or 0) < -5:
            risk = min(risk + 0.15, 1.0)
            flags.append("vt_negative_reputation")

    return {
        "domain":       domain,
        "risk_score":   min(round(risk, 3), 1.0),
        "flags":        flags,
        "verdict":      "malicious" if risk > 0.7 else ("suspicious" if risk > 0.4 else "clean"),
        "enrichment":   vt or None,
    }


async def analyze_ip(ip: str) -> dict:
    """
    IP reputation check — local heuristics + VirusTotal + AbuseIPDB enrichment.
    External feeds only fire when API keys are configured.
    """
    import ipaddress
    flags: list[str] = []
    risk  = 0.0
    is_private = False

    try:
        addr = ipaddress.ip_address(ip)
        is_private = addr.is_private
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

    vt: dict[str, Any] = {}
    abuse: dict[str, Any] = {}

    if not is_private:
        vt, abuse = await asyncio.gather(
            _vt_lookup("ip_addresses", ip, settings.VIRUSTOTAL_API_KEY),
            _abuseipdb_lookup(ip, settings.ABUSEIPDB_API_KEY),
        )

    if vt:
        malicious = vt.get("vt_malicious", 0) or 0
        if malicious > 0:
            risk = min(risk + 0.4 + malicious * 0.02, 1.0)
            flags.append(f"vt_malicious_detections:{malicious}")
        if (vt.get("vt_reputation") or 0) < -5:
            risk = min(risk + 0.15, 1.0)
            flags.append("vt_negative_reputation")

    if abuse:
        score = abuse.get("abuse_confidence_score") or 0
        if score >= 80:
            risk = min(risk + 0.5, 1.0)
            flags.append(f"abuseipdb_high_confidence:{score}")
        elif score >= 25:
            risk = min(risk + 0.2, 1.0)
            flags.append(f"abuseipdb_moderate_confidence:{score}")

    enrichment = {**(vt or {}), **(abuse or {})} or None

    return {
        "ip":           ip,
        "risk_score":   min(round(risk, 3), 1.0),
        "flags":        flags,
        "verdict":      "malicious" if risk > 0.7 else ("suspicious" if risk > 0.4 else "clean"),
        "enrichment":   enrichment,
    }
