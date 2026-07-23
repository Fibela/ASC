"""
Data-driven detection rule evaluator (S117.4).

The detection engine keeps 4 hardcoded rules (DET-001..004) for backward
compatibility; this module adds rules defined as DATA (conditions stored in the
DB), so new rules can be added/edited without code.

SAFETY: there is NO eval/exec. Conditions are interpreted by a fixed whitelist
of operators. This module imports nothing heavy, so it can be unit-tested in
isolation (and runs on Python 3.10+ unlike detection.py which uses datetime.UTC).

A rule condition is a dict: {"field": <event field>, "op": <operator>, "value": <x>}.
A rule matches when match_type == "all" (every condition true) or "any" (at least one).
"""

from __future__ import annotations

import re


def _s(v: object) -> str:
    return "" if v is None else str(v).lower()


def _num(v: object) -> float | None:
    try:
        return float(v)  # type: ignore[arg-type]
    except (ValueError, TypeError):
        return None


def eval_condition(event: dict, cond: dict) -> bool:
    """Evaluate a single condition against the event. Unknown op → False (safe)."""
    field = cond.get("field", "")
    op = cond.get("op", "")
    value = cond.get("value")
    fv = event.get(field)
    fs = _s(fv)
    vlist = value if isinstance(value, list) else []
    try:
        if op == "equals":
            return fs == _s(value)
        if op == "not_equals":
            return fs != _s(value)
        if op == "contains":
            return _s(value) in fs
        if op == "not_contains":
            return _s(value) not in fs
        if op == "contains_any":
            return any(_s(v) in fs for v in vlist)
        if op == "contains_all":
            return bool(vlist) and all(_s(v) in fs for v in vlist)
        if op == "token_any":  # match on whitespace-split tokens (e.g. arg flags "/s /o")
            toks = set(fs.split())
            return any(_s(v) in toks for v in vlist)
        if op == "in":
            return fs in [_s(v) for v in vlist]
        if op == "startswith":
            return fs.startswith(_s(value))
        if op == "endswith":
            return fs.endswith(_s(value))
        if op == "exists":
            return fs != ""
        if op == "empty":
            return fs == ""
        if op == "regex":
            return re.search(str(value), fs, re.IGNORECASE) is not None
        if op == "gt":
            a, b = _num(fv), _num(value)
            return a is not None and b is not None and a > b
        if op == "lt":
            a, b = _num(fv), _num(value)
            return a is not None and b is not None and a < b
    except (re.error, ValueError, TypeError):
        return False
    return False


def evaluate_conditions(event: dict, conditions: list, match_type: str = "all") -> bool:
    """True if the event satisfies the rule's conditions under match_type (all|any)."""
    if not conditions:
        return False
    results = [eval_condition(event, c) for c in conditions if isinstance(c, dict)]
    if not results:
        return False
    return any(results) if match_type == "any" else all(results)


# ─── Seed catalogue: DET-005..014 (single source of truth for migration + tests) ──
# Cobertura MITRE ancha y reconocible. Cada regla evalúa un solo evento normalizado.
SEED_RULES: list[dict] = [
    {
        "rule_id": "DET-005",
        "name": "PowerShell con comando codificado/ofuscado",
        "mitre_ttp": "T1059.001",
        "severity": "high",
        "description": "PowerShell invocado con comando Base64/oculto (-enc, FromBase64String, -w hidden, IEX). Técnica de ejecución ofuscada usada por la mayoría del malware moderno.",
        "tags": ["execution", "powershell", "obfuscation"],
        "risk_score": 0.8,
        "match_type": "all",
        "conditions": [
            {"field": "process", "op": "contains", "value": "powershell"},
            {
                "field": "command_line",
                "op": "contains_any",
                "value": [
                    "-enc",
                    "-encodedcommand",
                    "frombase64string",
                    "-w hidden",
                    "-windowstyle hidden",
                    "-nop",
                    "iex ",
                    "invoke-expression",
                ],
            },
        ],
    },
    {
        "rule_id": "DET-006",
        "name": "Abuso de LOLBin (certutil/mshta/regsvr32/rundll32)",
        "mitre_ttp": "T1218",
        "severity": "high",
        "description": "Binario legítimo del sistema (LOLBin) usado para descargar o ejecutar código: certutil -urlcache, mshta javascript, regsvr32 scrobj. Evasión de listas blancas.",
        "tags": ["defense-evasion", "lolbin"],
        "risk_score": 0.75,
        "match_type": "all",
        "conditions": [
            {
                "field": "process",
                "op": "contains_any",
                "value": ["certutil.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe", "bitsadmin.exe"],
            },
            {
                "field": "command_line",
                "op": "contains_any",
                "value": ["http", "-urlcache", "javascript:", "scrobj", ".sct", "downloadstring", "/i:"],
            },
        ],
    },
    {
        "rule_id": "DET-007",
        "name": "Volcado de credenciales / acceso a LSASS",
        "mitre_ttp": "T1003",
        "severity": "critical",
        "description": "Indicadores de volcado de credenciales: mimikatz/sekurlsa, procdump sobre lsass, comsvcs.dll MiniDump. Acceso al proceso LSASS para robar hashes/tickets.",
        "tags": ["credential-access", "lsass"],
        "risk_score": 0.95,
        "match_type": "any",
        "conditions": [
            {"field": "process", "op": "contains_any", "value": ["mimikatz", "procdump"]},
            {
                "field": "command_line",
                "op": "contains_any",
                "value": ["sekurlsa", "lsass.dmp", "comsvcs.dll", "minidump", "lsass.exe"],
            },
        ],
    },
    {
        "rule_id": "DET-008",
        "name": "Tarea programada sospechosa (persistencia)",
        "mitre_ttp": "T1053.005",
        "severity": "medium",
        "description": "Creación de tarea programada (schtasks /create) — mecanismo común de persistencia y ejecución diferida.",
        "tags": ["persistence", "scheduled-task"],
        "risk_score": 0.55,
        "match_type": "all",
        "conditions": [
            {"field": "command_line", "op": "contains", "value": "schtasks"},
            {"field": "command_line", "op": "contains_any", "value": ["/create", "-create"]},
        ],
    },
    {
        "rule_id": "DET-009",
        "name": "Creación de servicio para persistencia",
        "mitre_ttp": "T1543.003",
        "severity": "medium",
        "description": "Alta de servicio de Windows (sc create / New-Service) usada para persistencia con privilegios de sistema.",
        "tags": ["persistence", "service"],
        "risk_score": 0.55,
        "match_type": "any",
        "conditions": [
            {"field": "command_line", "op": "contains", "value": "sc create"},
            {"field": "command_line", "op": "contains", "value": "sc.exe create"},
            {"field": "command_line", "op": "contains", "value": "new-service"},
        ],
    },
    {
        "rule_id": "DET-010",
        "name": "Desactivación de defensas (AV/Firewall)",
        "mitre_ttp": "T1562.001",
        "severity": "high",
        "description": "Intento de desactivar Windows Defender o el firewall: Set-MpPreference -DisableRealtimeMonitoring, netsh advfirewall off, Stop-Service WinDefend.",
        "tags": ["defense-evasion", "impair-defenses"],
        "risk_score": 0.8,
        "match_type": "any",
        "conditions": [
            {"field": "command_line", "op": "contains", "value": "disablerealtimemonitoring"},
            {"field": "command_line", "op": "contains", "value": "advfirewall set allprofiles state off"},
            {"field": "command_line", "op": "contains", "value": "stop-service windefend"},
            {"field": "command_line", "op": "contains", "value": "add-mppreference -exclusionpath"},
        ],
    },
    {
        "rule_id": "DET-011",
        "name": "Borrado de registros de eventos",
        "mitre_ttp": "T1070.001",
        "severity": "high",
        "description": "Limpieza de logs de Windows (wevtutil cl / Clear-EventLog) — anti-forense para borrar rastros tras el compromiso.",
        "tags": ["defense-evasion", "indicator-removal"],
        "risk_score": 0.8,
        "match_type": "any",
        "conditions": [
            {"field": "command_line", "op": "contains", "value": "wevtutil cl"},
            {"field": "command_line", "op": "contains", "value": "wevtutil clear-log"},
            {"field": "command_line", "op": "contains", "value": "clear-eventlog"},
        ],
    },
    {
        "rule_id": "DET-012",
        "name": "Ejecución vía WMI",
        "mitre_ttp": "T1047",
        "severity": "medium",
        "description": "Ejecución de procesos mediante WMI (wmic process call create / Invoke-WmiMethod Win32_Process) — usado para movimiento lateral y ejecución sigilosa.",
        "tags": ["execution", "wmi", "lateral-movement"],
        "risk_score": 0.6,
        "match_type": "any",
        "conditions": [
            {"field": "command_line", "op": "contains", "value": "process call create"},
            {"field": "command_line", "op": "contains", "value": "invoke-wmimethod"},
            {"field": "command_line", "op": "contains", "value": "win32_process"},
        ],
    },
    {
        "rule_id": "DET-013",
        "name": "Abuso de BITS para transferencia",
        "mitre_ttp": "T1197",
        "severity": "medium",
        "description": "Uso de BITS (bitsadmin /transfer, Start-BitsTransfer) para descargar cargas evadiendo controles de red.",
        "tags": ["defense-evasion", "bits"],
        "risk_score": 0.6,
        "match_type": "any",
        "conditions": [
            {"field": "command_line", "op": "contains", "value": "bitsadmin /transfer"},
            {"field": "command_line", "op": "contains", "value": "start-bitstransfer"},
        ],
    },
    {
        "rule_id": "DET-014",
        "name": "Indicadores de reverse shell / C2 interactivo",
        "mitre_ttp": "T1059",
        "severity": "high",
        "description": "Patrones de shell inverso: TcpClient de PowerShell, /dev/tcp, netcat -e. Canal de comando y control interactivo.",
        "tags": ["command-and-control", "reverse-shell"],
        "risk_score": 0.85,
        "match_type": "any",
        "conditions": [
            {"field": "command_line", "op": "contains", "value": "system.net.sockets.tcpclient"},
            {"field": "command_line", "op": "contains", "value": "/dev/tcp/"},
            {"field": "command_line", "op": "contains", "value": "nc -e"},
            {"field": "command_line", "op": "contains", "value": "ncat -e"},
        ],
    },
]
