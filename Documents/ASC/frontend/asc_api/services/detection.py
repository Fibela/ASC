"""
Detection Engine — process monitoring, hook detection, registry auditing, deferred traffic.

Receives normalized events (ECS format) and evaluates them against specific
detection rules defined in the ASC spec. Does NOT run as an agent on endpoints;
it analyses events forwarded by EDR/SIEM agents.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Literal

from asc_api.core.logging import get_logger

log = get_logger(__name__)

# ─── Severity levels mapped to semaphore colours ─────────────────────────────
SEVERITY_SEMAPHORE: dict[str, str] = {
    "critical": "red",
    "high": "red",
    "medium": "yellow",
    "low": "green",
}

# ─── Data classes ─────────────────────────────────────────────────────────────


@dataclass
class DetectionResult:
    rule_id: str
    rule_name: str
    severity: Literal["critical", "high", "medium", "low"]
    semaphore: str  # green | yellow | red
    risk_score: float
    description: str
    evidence: dict = field(default_factory=dict)
    mitre_ttp: str = ""
    detected_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "semaphore": self.semaphore,
            "risk_score": self.risk_score,
            "description": self.description,
            "evidence": self.evidence,
            "mitre_ttp": self.mitre_ttp,
            "detected_at": self.detected_at,
        }


# ─── Rule 1: Suspicious process — acord32.exe with hidden params ─────────────

# acord32.exe is the legitimate ACORD forms viewer. The params /s /o are
# non-standard and are used by malware that masquerades as this binary.
ACORD_SUSPICIOUS_PARAMS = {"/s", "/o", "/q", "/silent", "/noui"}


def check_suspicious_process(event: dict) -> DetectionResult | None:
    process = str(event.get("process", "")).lower().strip()
    args = str(event.get("args", event.get("command_line", ""))).lower()

    if "acord32" not in process:
        return None

    # Split on whitespace so "/s" does not substring-match inside "/silent"
    arg_tokens = set(args.split())
    found_params = [p for p in ACORD_SUSPICIOUS_PARAMS if p in arg_tokens]
    if not found_params:
        return None

    severity = "critical" if len(found_params) >= 2 else "high"
    log.warning("detection_suspicious_process", process=process, params=found_params, host=event.get("host"))

    return DetectionResult(
        rule_id="DET-001",
        rule_name="Suspicious acord32.exe Execution",
        severity=severity,
        semaphore=SEVERITY_SEMAPHORE[severity],
        risk_score=0.88 if len(found_params) >= 2 else 0.70,
        description=(
            f"acord32.exe ejecutado con parámetros ocultos: {', '.join(found_params)}. "
            "Técnica común de malware que suplanta el visor ACORD."
        ),
        evidence={
            "process": process,
            "suspicious_params": found_params,
            "host": event.get("host"),
            "pid": event.get("pid"),
            "parent_process": event.get("parent_process"),
        },
        mitre_ttp="T1036.005",  # Masquerading: Match Legitimate Name or Location
    )


# ─── Rule 2: Windows Hook API detection ───────────────────────────────────────

# SetWindowsHookExW intercepts keyboard/mouse/UI events system-wide.
# FindWindowW is used to locate specific windows for injection or monitoring.
HOOK_APIS = {
    "SetWindowsHookExW": "WH_KEYBOARD_LL (0x0D) or WH_MOUSE_LL (0x0E) — global keyboard/mouse hook",
    "SetWindowsHookExA": "ANSI variant of SetWindowsHookEx — keyboard/UI hook",
    "FindWindowW": "Locates windows by class/title — recon for UI injection",
    "FindWindowA": "ANSI variant of FindWindowW",
    "FindWindowExW": "Extended window search — child window enumeration for injection",
}


def check_hook_detection(event: dict) -> DetectionResult | None:
    api_call = str(event.get("api_call", event.get("action", ""))).strip()
    syscall = str(event.get("syscall", "")).strip()
    target = api_call or syscall

    matched_api = next((api for api in HOOK_APIS if api.lower() in target.lower()), None)
    if not matched_api:
        return None

    # FindWindow alone is lower severity; SetWindowsHookEx is critical
    severity = "critical" if "Hook" in matched_api else "medium"
    log.warning("detection_hook_api", api=matched_api, host=event.get("host"))

    return DetectionResult(
        rule_id="DET-002",
        rule_name="Windows Hook API Detected",
        severity=severity,
        semaphore=SEVERITY_SEMAPHORE[severity],
        risk_score=0.85 if "Hook" in matched_api else 0.55,
        description=(
            f"API de intercepción detectada: {matched_api}. "
            f"{HOOK_APIS[matched_api]}. "
            "Indicador de keylogger o inyección de interfaz."
        ),
        evidence={
            "api_call": matched_api,
            "api_detail": HOOK_APIS[matched_api],
            "host": event.get("host"),
            "process": event.get("process"),
            "pid": event.get("pid"),
        },
        mitre_ttp="T1056.001",  # Input Capture: Keylogging
    )


# ─── Rule 3: Registry persistence ─────────────────────────────────────────────

# RegCreateKeyW / RegDeleteKeyW targeting Run keys = persistence mechanism.
REGISTRY_APIS = {
    "RegCreateKeyW",
    "RegCreateKeyA",
    "RegSetValueExW",
    "RegSetValueExA",
    "RegDeleteKeyW",
    "RegDeleteKeyA",
    "RegDeleteValueW",
    "RegDeleteValueA",
}

PERSISTENCE_KEYS = [
    r"software\microsoft\windows\currentversion\run",
    r"software\microsoft\windows\currentversion\runonce",
    r"system\currentcontrolset\services",
    r"software\microsoft\windows nt\currentversion\winlogon",
    r"software\microsoft\windows\currentversion\explorer\shell folders",
    r"software\microsoft\windows\currentversion\policies\explorer\run",
]


def check_registry_persistence(event: dict) -> DetectionResult | None:
    api_call = str(event.get("api_call", event.get("action", ""))).strip()
    reg_key = str(event.get("reg_key", event.get("registry_key", ""))).lower()

    api_matched = any(api.lower() in api_call.lower() for api in REGISTRY_APIS)
    key_matched = any(pk in reg_key for pk in PERSISTENCE_KEYS)

    if not api_matched or not key_matched:
        return None

    is_delete = "delete" in api_call.lower()
    severity = "high"
    log.warning("detection_registry_persistence", api=api_call, key=reg_key, host=event.get("host"))

    return DetectionResult(
        rule_id="DET-003",
        rule_name="Registry Persistence Mechanism",
        severity=severity,
        semaphore=SEVERITY_SEMAPHORE[severity],
        risk_score=0.80,
        description=(
            f"{'Eliminación' if is_delete else 'Escritura'} en clave de registro de persistencia: {reg_key}. "
            f"API: {api_call}. Indica intento de {'limpiar huellas' if is_delete else 'establecer persistencia'}."
        ),
        evidence={
            "api_call": api_call,
            "registry_key": reg_key,
            "operation": "delete" if is_delete else "write",
            "host": event.get("host"),
            "process": event.get("process"),
            "pid": event.get("pid"),
        },
        mitre_ttp="T1547.001",  # Boot or Logon Autostart Execution: Registry Run Keys
    )


# ─── Rule 4: Deferred traffic detection ───────────────────────────────────────

# Connections that appear hours/days after initial analysis are a C2 beacon
# indicator — the malware waited to avoid sandbox detection windows.
DEFERRED_THRESHOLD_HOURS = 2  # connections appearing more than 2h after event ingestion


def check_deferred_traffic(
    connection_event: dict,
    original_analysis_ts: datetime,
) -> DetectionResult | None:
    conn_ts_raw = connection_event.get("timestamp")
    if not conn_ts_raw:
        return None

    try:
        conn_ts = datetime.fromisoformat(str(conn_ts_raw).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None

    if conn_ts.tzinfo is None:
        conn_ts = conn_ts.replace(tzinfo=UTC)

    delta_hours = (conn_ts - original_analysis_ts).total_seconds() / 3600

    if delta_hours <= DEFERRED_THRESHOLD_HOURS:
        return None

    severity = "critical" if delta_hours > 24 else "high"
    log.warning("detection_deferred_traffic", dst=connection_event.get("dst_ip"), delay_hours=round(delta_hours, 1))

    return DetectionResult(
        rule_id="DET-004",
        rule_name="Deferred Network Traffic",
        severity=severity,
        semaphore=SEVERITY_SEMAPHORE[severity],
        risk_score=0.90 if delta_hours > 24 else 0.75,
        description=(
            f"Conexión detectada {round(delta_hours, 1)}h después del análisis inicial. "
            "El malware retrasó la comunicación para evadir sandbox de tiempo limitado. "
            f"Destino: {connection_event.get('dst_ip', 'unknown')}:{connection_event.get('dst_port', '?')}."
        ),
        evidence={
            "dst_ip": connection_event.get("dst_ip"),
            "dst_port": connection_event.get("dst_port"),
            "delay_hours": round(delta_hours, 1),
            "connection_time": conn_ts.isoformat(),
            "analysis_time": original_analysis_ts.isoformat(),
            "host": connection_event.get("host"),
            "protocol": connection_event.get("protocol", "unknown"),
        },
        mitre_ttp="T1071.001",  # Application Layer Protocol: Web Protocols (C2)
    )


# ─── Master evaluation function ───────────────────────────────────────────────


def evaluate_event(
    event: dict,
    original_analysis_ts: datetime | None = None,
) -> list[DetectionResult]:
    """Evaluate a single normalized event against all detection rules.
    Returns list of DetectionResult (empty = no matches)."""
    results: list[DetectionResult] = []

    r = check_suspicious_process(event)
    if r:
        results.append(r)

    r = check_hook_detection(event)
    if r:
        results.append(r)

    r = check_registry_persistence(event)
    if r:
        results.append(r)

    if original_analysis_ts and event.get("category") == "network":
        r = check_deferred_traffic(event, original_analysis_ts)
        if r:
            results.append(r)

    if results:
        log.info(
            "detection_rules_matched", count=len(results), rules=[r.rule_id for r in results], host=event.get("host")
        )

    return results


def evaluate_bulk(
    events: list[dict],
    original_analysis_ts: datetime | None = None,
) -> list[DetectionResult]:
    """Evaluate multiple events and return all matches, deduplicated by rule+host."""
    seen: set[str] = set()
    all_results: list[DetectionResult] = []

    for event in events:
        for result in evaluate_event(event, original_analysis_ts):
            key = f"{result.rule_id}:{event.get('host', '')}"
            if key not in seen:
                seen.add(key)
                all_results.append(result)

    return all_results


def evaluate_dynamic(event: dict, rules) -> list[DetectionResult]:
    """Evaluate data-driven DB rules (conditions) against an event (S117.4).

    `rules` is any iterable of objects exposing rule_id, name, mitre_ttp, severity,
    description, risk_score_default, conditions, match_type. Rules with empty
    conditions are skipped (legacy DET-001..004 fire via their hardcoded check_*).
    The condition logic lives in services/detection_rules (pure, unit-tested in
    isolation) — this only maps a match to a DetectionResult.
    """
    from asc_api.services.detection_rules import evaluate_conditions

    out: list[DetectionResult] = []
    for r in rules:
        conditions = getattr(r, "conditions", None) or []
        if not conditions:
            continue
        match_type = getattr(r, "match_type", "all") or "all"
        if not evaluate_conditions(event, conditions, match_type):
            continue
        severity = getattr(r, "severity", "medium")
        sev = severity if severity in ("critical", "high", "medium", "low") else "medium"
        out.append(
            DetectionResult(
                rule_id=getattr(r, "rule_id", ""),
                rule_name=getattr(r, "name", ""),
                severity=sev,
                semaphore=SEVERITY_SEMAPHORE.get(sev, "yellow"),
                risk_score=float(getattr(r, "risk_score_default", 0.5) or 0.5),
                description=getattr(r, "description", ""),
                evidence={"engine": "data-driven", "conditions_matched": len(conditions)},
                mitre_ttp=getattr(r, "mitre_ttp", ""),
            )
        )
    return out
