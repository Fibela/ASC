"""
Environmental Fingerprinting Service — Environmental Keying Detection.

Detects whether a malware sample is designed to activate ONLY within the
PremosCorp network environment (environmental keying / targeted malware).

Environmental keying is a sophisticated evasion technique where malware
checks for specific host/domain/registry/network markers before activating,
making it appear benign in sandboxes that don't replicate the target environment.
"""

import math
import re
from dataclasses import dataclass

from asc_api.core.logging import get_logger

log = get_logger(__name__)


@dataclass
class FingerprintResult:
    environmental_keying_detected: bool
    confidence: float  # 0.0 – 1.0
    risk_score: float
    triggers: list[str]  # which checks fired
    details: list[dict]  # each finding with context
    recommendation: str

    def to_dict(self) -> dict:
        return {
            "environmental_keying_detected": self.environmental_keying_detected,
            "confidence": self.confidence,
            "risk_score": self.risk_score,
            "triggers": self.triggers,
            "details": self.details,
            "recommendation": self.recommendation,
        }


# ─── PremosCorp environment identifiers ───────────────────────────────────────
# These are the markers the malware would check to confirm it's running
# inside the PremosCorp infrastructure before activating.

HOSTNAME_PATTERNS = [
    re.compile(rb"PREMOS", re.IGNORECASE),
    re.compile(rb"PremosCorp", re.IGNORECASE),
    re.compile(rb"PREMOS-\w+", re.IGNORECASE),  # e.g. PREMOS-WS-042
    re.compile(rb"WS-PREMOS-\d+", re.IGNORECASE),  # workstation naming convention
    re.compile(rb"SRV-PREMOS-\d+", re.IGNORECASE),  # server naming convention
]

DOMAIN_PATTERNS = [
    re.compile(rb"premoscorp\.com", re.IGNORECASE),
    re.compile(rb"premos\.local", re.IGNORECASE),
    re.compile(rb"corp\.premoscorp", re.IGNORECASE),
    re.compile(rb"premoscorp\.internal", re.IGNORECASE),
]

REGISTRY_PATTERNS = [
    re.compile(rb"PREMOS", re.IGNORECASE),
    re.compile(rb"PremosCorp", re.IGNORECASE),
    # Common registry paths a targeted malware might check
    re.compile(rb"SOFTWARE\\PremosCorp", re.IGNORECASE),
    re.compile(rb"SOFTWARE\\Premos", re.IGNORECASE),
]

NETWORK_CHECKS = [
    # GetAdaptersInfo / WSAStartup patterns suggest network environment check
    re.compile(rb"GetAdaptersInfo", re.IGNORECASE),
    re.compile(rb"GetNetworkParams", re.IGNORECASE),
    re.compile(rb"DnsQueryA", re.IGNORECASE),
    re.compile(rb"DnsQueryW", re.IGNORECASE),
]

AD_PATTERNS = [
    # Active Directory / domain membership checks
    re.compile(rb"NetGetJoinInformation", re.IGNORECASE),
    re.compile(rb"DsGetDcName", re.IGNORECASE),
    re.compile(rb"NetUserGetInfo", re.IGNORECASE),
    re.compile(rb"LsaQueryInformationPolicy", re.IGNORECASE),
]

USERNAME_PATTERNS = [
    re.compile(rb"GetUserName", re.IGNORECASE),
    re.compile(rb"GetUserNameEx", re.IGNORECASE),
]

# Environment variable checks
ENV_CHECK_PATTERNS = [
    re.compile(rb"GetEnvironmentVariable", re.IGNORECASE),
    re.compile(rb"USERDOMAIN", re.IGNORECASE),
    re.compile(rb"COMPUTERNAME", re.IGNORECASE),
    re.compile(rb"LOGONSERVER", re.IGNORECASE),
]

# Anti-sandbox: specific delay / sleep calls combined with environment checks
SLEEP_PATTERNS = [
    re.compile(rb"Sleep\x00", re.IGNORECASE),
    re.compile(rb"SleepEx", re.IGNORECASE),
    re.compile(rb"WaitForSingleObject", re.IGNORECASE),
    re.compile(rb"NtDelayExecution", re.IGNORECASE),
]


# ─── Individual check functions ───────────────────────────────────────────────


def _check_hostname_patterns(data: bytes) -> list[dict]:
    findings = []
    for pattern in HOSTNAME_PATTERNS:
        matches = pattern.findall(data)
        if matches:
            findings.append(
                {
                    "check": "hostname_pattern",
                    "pattern": pattern.pattern.decode(errors="replace"),
                    "matches": len(matches),
                    "context": "Malware references PremosCorp hostname pattern — targeted check",
                }
            )
    return findings


def _check_domain_patterns(data: bytes) -> list[dict]:
    findings = []
    for pattern in DOMAIN_PATTERNS:
        matches = pattern.findall(data)
        if matches:
            findings.append(
                {
                    "check": "domain_check",
                    "pattern": pattern.pattern.decode(errors="replace"),
                    "matches": len(matches),
                    "context": "Malware references PremosCorp domain — targeted activation check",
                }
            )
    return findings


def _check_registry_patterns(data: bytes) -> list[dict]:
    findings = []
    for pattern in REGISTRY_PATTERNS:
        matches = pattern.findall(data)
        if matches:
            findings.append(
                {
                    "check": "registry_pattern",
                    "pattern": pattern.pattern.decode(errors="replace"),
                    "matches": len(matches),
                    "context": "Registry key referencing PremosCorp namespace — environment verification",
                }
            )
    return findings


def _check_ad_enumeration(data: bytes) -> list[dict]:
    findings = []
    ad_hits = [p for p in AD_PATTERNS if p.search(data)]
    env_hits = [p for p in ENV_CHECK_PATTERNS if p.search(data)]

    if ad_hits:
        findings.append(
            {
                "check": "active_directory_enum",
                "apis": [p.pattern.decode(errors="replace") for p in ad_hits],
                "count": len(ad_hits),
                "context": "Active Directory enumeration APIs — domain membership verification before activation",
            }
        )

    if env_hits and (ad_hits or len(env_hits) >= 3):
        findings.append(
            {
                "check": "environment_variable_check",
                "apis": [p.pattern.decode(errors="replace") for p in env_hits],
                "count": len(env_hits),
                "context": "Multiple environment variable reads combined with domain checks — fingerprinting pattern",
            }
        )

    return findings


def _check_network_fingerprinting(data: bytes) -> list[dict]:
    findings = []
    net_hits = [p for p in NETWORK_CHECKS if p.search(data)]

    if net_hits:
        findings.append(
            {
                "check": "network_fingerprinting",
                "apis": [p.pattern.decode(errors="replace") for p in net_hits],
                "count": len(net_hits),
                "context": "Network adapter/DNS enumeration — checking network topology before activation",
            }
        )
    return findings


def _check_timing_evasion(data: bytes) -> list[dict]:
    """Detect sleep/delay combined with environment checks — sandbox evasion."""
    findings = []
    sleep_hits = [p for p in SLEEP_PATTERNS if p.search(data)]
    env_hits = sum(1 for p in ENV_CHECK_PATTERNS if p.search(data))
    ad_hits = sum(1 for p in AD_PATTERNS if p.search(data))

    # High confidence of targeted malware when sleep + env checks coexist
    if sleep_hits and (env_hits + ad_hits) >= 2:
        findings.append(
            {
                "check": "timing_evasion_with_env_check",
                "sleep_apis": [p.pattern.decode(errors="replace") for p in sleep_hits],
                "env_checks": env_hits + ad_hits,
                "context": (
                    "Delay/sleep calls combined with environment checks — "
                    "classic sandbox evasion + conditional activation pattern"
                ),
            }
        )
    return findings


def _check_string_obfuscation(data: bytes) -> dict | None:
    """Detect high entropy sections that may conceal encrypted environment strings."""
    chunk_size = 256
    high_entropy_chunks = 0

    for i in range(0, min(len(data), 65536), chunk_size):
        chunk = data[i : i + chunk_size]
        if len(chunk) < 16:
            continue
        freq: dict[int, int] = {}
        for b in chunk:
            freq[b] = freq.get(b, 0) + 1
        entropy = -sum((f / len(chunk)) * math.log2(f / len(chunk)) for f in freq.values())
        if entropy > 7.2:
            high_entropy_chunks += 1

    if high_entropy_chunks >= 3:
        return {
            "check": "high_entropy_sections",
            "chunks": high_entropy_chunks,
            "context": (
                f"{high_entropy_chunks} secciones de alta entropía detectadas — "
                "posible cifrado de strings de entorno para evadir análisis estático"
            ),
        }
    return None


# ─── Master fingerprint function ─────────────────────────────────────────────


def analyze_environmental_keying(filename: str, data: bytes) -> FingerprintResult:
    """
    Full environmental fingerprinting pipeline.
    Returns FingerprintResult with confidence score and details.
    """
    log.info("fingerprint_start", filename=filename, size=len(data))

    all_findings: list[dict] = []
    triggers: list[str] = []

    # Run all checks
    hostname_findings = _check_hostname_patterns(data)
    domain_findings = _check_domain_patterns(data)
    registry_findings = _check_registry_patterns(data)
    ad_findings = _check_ad_enumeration(data)
    net_findings = _check_network_fingerprinting(data)
    timing_findings = _check_timing_evasion(data)

    entropy_finding = _check_string_obfuscation(data)

    all_findings.extend(hostname_findings)
    all_findings.extend(domain_findings)
    all_findings.extend(registry_findings)
    all_findings.extend(ad_findings)
    all_findings.extend(net_findings)
    all_findings.extend(timing_findings)
    if entropy_finding:
        all_findings.append(entropy_finding)

    # Build trigger list
    if hostname_findings:
        triggers.append("hostname_pattern")
    if domain_findings:
        triggers.append("domain_check")
    if registry_findings:
        triggers.append("registry_pattern")
    if ad_findings:
        triggers.append("active_directory_enum")
    if net_findings:
        triggers.append("network_fingerprinting")
    if timing_findings:
        triggers.append("timing_evasion")
    if entropy_finding:
        triggers.append("high_entropy_sections")

    # Confidence scoring — weighted by trigger severity
    weights = {
        "hostname_pattern": 0.40,
        "domain_check": 0.40,
        "registry_pattern": 0.25,
        "active_directory_enum": 0.30,
        "network_fingerprinting": 0.20,
        "timing_evasion": 0.25,
        "high_entropy_sections": 0.15,
    }
    raw_confidence = sum(weights.get(t, 0.10) for t in triggers)
    confidence = min(round(raw_confidence, 3), 1.0)

    # Direct PremosCorp references are high confidence by themselves
    direct_reference = bool(hostname_findings or domain_findings or registry_findings)
    if direct_reference and confidence < 0.70:
        confidence = 0.70

    risk_score = round(min(confidence * 1.1, 1.0), 3)
    detected = confidence >= 0.30 or direct_reference

    if detected:
        log.warning(
            "fingerprint_environmental_keying_detected", filename=filename, confidence=confidence, triggers=triggers
        )
        recommendation = (
            "ALERTA CRÍTICA: El malware contiene referencias directas al entorno PremosCorp. "
            "Este artefacto es potencialmente una amenaza dirigida específicamente a esta organización. "
            "Recomendación: aislamiento inmediato, análisis forense completo y notificación al equipo de respuesta a incidentes."
        )
    elif triggers:
        log.info("fingerprint_partial_match", filename=filename, triggers=triggers)
        recommendation = (
            "Indicadores parciales de environmental keying detectados. "
            "Monitorear el artefacto en sandbox extendido (72h). "
            "Verificar si se realizan conexiones de red diferidas."
        )
    else:
        recommendation = (
            "Sin indicadores de environmental keying. "
            "El artefacto no parece tener activación condicional específica para PremosCorp."
        )

    log.info(
        "fingerprint_complete", filename=filename, detected=detected, confidence=confidence, triggers=len(triggers)
    )

    return FingerprintResult(
        environmental_keying_detected=detected,
        confidence=confidence,
        risk_score=risk_score,
        triggers=triggers,
        details=all_findings,
        recommendation=recommendation,
    )
