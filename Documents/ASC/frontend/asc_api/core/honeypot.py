"""
SPECTER Honeypot Engine — P14.5 Advanced Threat Intelligence.

PremosCorp proprietary attacker intelligence collection via legal means:

  Canary Token System    — Unique traceable URLs embedded in decoy content.
                           When an attacker uses stolen "credentials", the
                           canary URL is fetched → we capture their real IP,
                           headers, timing — even behind a VPN if they reuse
                           the canary in a browser or tool that follows URLs.

  Attacker Fingerprinting — HTTP headers, User-Agent, Accept-Language, timing,
                            X-Forwarded-For chain, referer, connection patterns.
                            Builds a profile usable for cross-session correlation.

  Decoy Content Generator — Realistic-looking but completely inert fake data:
                            database connection strings, fake API keys, fake
                            agent inventories. Everything references internal
                            hostnames that don't resolve externally.

  Signed Evidence Reports — Every honeypot event generates a tamper-evident
                            JSON report signed with HMAC-SHA256. Suitable for
                            submission to law enforcement, CERT, AbuseIPDB,
                            and hosting provider abuse departments.

  IP Reputation Lookup    — Optional async lookup against AbuseIPDB and ip-api.
                            Activated when ABUSEIPDB_API_KEY is configured.

LEGAL NOTE:
  All techniques implemented here are PASSIVE intelligence collection on
  systems and sessions that have already accessed PremosCorp infrastructure.
  No code is sent to attacker devices. No unauthorized access is performed.
  Evidence is collected for legal reporting under applicable computer crime
  statutes (CFAA, Computer Misuse Act, LSSICE, Colombian Law 1273/2009, etc.).
"""

import hashlib
import hmac
import json
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

from asc_api.core.audit import log_security_action


# ── Canary Token System ────────────────────────────────────────────────────────

@dataclass
class CanaryAccess:
    """Single access record for a canary token."""
    ts: str
    client_ip: str
    user_agent: str
    referer: str
    headers_snapshot: dict[str, str]


@dataclass
class CanaryToken:
    """A traceable token embedded in decoy content."""
    token_id: str
    endpoint: str          # which honeypot endpoint generated this
    created_at: str
    label: str             # human-readable context (e.g. "fake-db-password")
    accesses: list[CanaryAccess] = field(default_factory=list)

    @property
    def access_count(self) -> int:
        return len(self.accesses)

    @property
    def first_access(self) -> Optional[str]:
        return self.accesses[0].ts if self.accesses else None

    @property
    def last_access(self) -> Optional[str]:
        return self.accesses[-1].ts if self.accesses else None


class CanaryTokenStore:
    """
    Thread-safe in-process registry of active canary tokens.

    Production note: for multi-process deployments, back this with Redis.
    For single-process (Docker single container), in-memory is sufficient.
    """

    def __init__(self) -> None:
        self._tokens: dict[str, CanaryToken] = {}
        self._lock = threading.Lock()

    def create(self, endpoint: str, label: str = "") -> CanaryToken:
        token = CanaryToken(
            token_id=str(uuid.uuid4()).replace("-", ""),
            endpoint=endpoint,
            created_at=datetime.now(timezone.utc).isoformat(),
            label=label,
        )
        with self._lock:
            self._tokens[token.token_id] = token
        return token

    def record_access(
        self,
        token_id: str,
        client_ip: str,
        headers: dict[str, str],
    ) -> Optional[CanaryToken]:
        with self._lock:
            token = self._tokens.get(token_id)
            if not token:
                return None
            access = CanaryAccess(
                ts=datetime.now(timezone.utc).isoformat(),
                client_ip=client_ip,
                user_agent=headers.get("user-agent", "unknown")[:256],
                referer=headers.get("referer", "")[:256],
                headers_snapshot={k: v[:128] for k, v in headers.items()},
            )
            token.accesses.append(access)
            return token

    def get(self, token_id: str) -> Optional[CanaryToken]:
        with self._lock:
            return self._tokens.get(token_id)

    def list_all(self) -> list[CanaryToken]:
        with self._lock:
            return list(self._tokens.values())

    def active_count(self) -> int:
        with self._lock:
            return len(self._tokens)


# Module-level singleton
canary_store = CanaryTokenStore()


# ── Attacker Fingerprinting ────────────────────────────────────────────────────

@dataclass
class AttackerFingerprint:
    """Passive fingerprint of an attacker session."""
    client_ip: str
    user_agent: str
    accept_language: str
    accept_encoding: str
    referer: str
    x_forwarded_for: str        # may reveal real IP behind proxy
    connection_type: str         # keep-alive | close
    all_headers: dict[str, str]
    timestamp: str
    fingerprint_hash: str        # SHA-256 of key fields for cross-session correlation

    def to_dict(self) -> dict:
        return {
            "client_ip":       self.client_ip,
            "user_agent":      self.user_agent,
            "accept_language": self.accept_language,
            "accept_encoding": self.accept_encoding,
            "referer":         self.referer,
            "x_forwarded_for": self.x_forwarded_for,
            "connection_type": self.connection_type,
            "all_headers":     self.all_headers,
            "timestamp":       self.timestamp,
            "fingerprint_hash": self.fingerprint_hash,
        }


def fingerprint_request(
    client_ip: str,
    headers: dict[str, str],
) -> AttackerFingerprint:
    """
    Build a passive fingerprint from request metadata.

    Does NOT inject or execute anything — purely reads what the attacker
    already sent in their HTTP request.
    """
    ua  = headers.get("user-agent", "")[:512]
    lang = headers.get("accept-language", "")[:128]
    enc  = headers.get("accept-encoding", "")[:128]
    ref  = headers.get("referer", "")[:256]
    xff  = headers.get("x-forwarded-for", "")[:256]
    conn = headers.get("connection", "")[:64]

    # Fingerprint hash for cross-session correlation
    raw = f"{ua}|{lang}|{enc}|{client_ip}"
    fp_hash = hashlib.sha256(raw.encode()).hexdigest()

    clean_headers = {
        k.lower(): v[:128]
        for k, v in headers.items()
        if k.lower() not in ("cookie", "authorization", "x-specter-id", "x-specter-token")
    }

    return AttackerFingerprint(
        client_ip=client_ip,
        user_agent=ua,
        accept_language=lang,
        accept_encoding=enc,
        referer=ref,
        x_forwarded_for=xff,
        connection_type=conn,
        all_headers=clean_headers,
        timestamp=datetime.now(timezone.utc).isoformat(),
        fingerprint_hash=fp_hash,
    )


# ── IP Reputation Lookup ───────────────────────────────────────────────────────

async def lookup_ip_reputation(ip: str, abuseipdb_key: str = "") -> dict[str, Any]:
    """
    Async IP reputation lookup — graceful fallback if services unavailable.

    Sources:
      ip-api.com      — geolocation + ASN + ISP (free, no key required)
      AbuseIPDB       — abuse confidence score (requires API key)

    Returns a merged dict. Missing fields are null, never raises.
    """
    result: dict[str, Any] = {
        "ip": ip,
        "country": None,
        "country_code": None,
        "city": None,
        "isp": None,
        "asn": None,
        "org": None,
        "is_proxy": None,
        "is_hosting": None,
        "abuse_confidence_score": None,
        "abuse_reports": None,
    }

    # Skip private / loopback IPs
    if ip.startswith(("127.", "10.", "192.168.", "172.16.", "::1", "localhost")):
        result["country"] = "PRIVATE_NETWORK"
        return result

    try:
        async with httpx.AsyncClient(timeout=4) as client:
            r = await client.get(f"http://ip-api.com/json/{ip}?fields=country,countryCode,city,isp,as,org,proxy,hosting")
            if r.status_code == 200:
                data = r.json()
                result.update({
                    "country":      data.get("country"),
                    "country_code": data.get("countryCode"),
                    "city":         data.get("city"),
                    "isp":          data.get("isp"),
                    "asn":          data.get("as"),
                    "org":          data.get("org"),
                    "is_proxy":     data.get("proxy"),
                    "is_hosting":   data.get("hosting"),
                })
    except Exception:  # nosec B110 — external threat-intel API failure is non-fatal; attacker info is best-effort
        pass

    if abuseipdb_key:
        try:
            async with httpx.AsyncClient(timeout=4) as client:
                r = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": abuseipdb_key, "Accept": "application/json"},
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                )
                if r.status_code == 200:
                    data = r.json().get("data", {})
                    result.update({
                        "abuse_confidence_score": data.get("abuseConfidenceScore"),
                        "abuse_reports":          data.get("totalReports"),
                    })
        except Exception:  # nosec B110 — AbuseIPDB API failure is non-fatal; enrichment is best-effort
            pass

    return result


# ── Decoy Content Generator ────────────────────────────────────────────────────

def _canary_url(base_url: str, token_id: str) -> str:
    """Build the canary callback URL embedded in decoy content."""
    return f"{base_url.rstrip('/')}/api/v1/c/{token_id}"


def build_probe_decoy(base_url: str) -> tuple[dict, CanaryToken]:
    """
    Build decoy response for GET /agents/probe.
    Looks like an internal system status page.
    Contains a canary token URL embedded in the 'diagnostics_url' field.
    """
    token = canary_store.create("/agents/probe", label="probe-diagnostics-link")
    return {
        "status":          "operational",
        "agents_online":   0,
        "agents_total":    0,
        "backend_version": "1.0.0",
        "db_status":       "connected",
        "probe_ts":        datetime.now(timezone.utc).isoformat(),
        "diagnostics_url": _canary_url(base_url, token.token_id),
        "support_id":      token.token_id[:8],
    }, token


def build_dump_decoy(base_url: str) -> tuple[dict, CanaryToken]:
    """
    Build decoy response for GET /agents/dump.
    Looks like an agent inventory dump with connection details.
    Contains a canary token embedded in a 'report_url' field.
    """
    token = canary_store.create("/agents/dump", label="dump-report-link")
    return {
        "dump_id":    token.token_id[:12],
        "generated":  datetime.now(timezone.utc).isoformat(),
        "agents": [
            {
                "id":          "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "hostname":    "ws-corp-01.premoscorp.local",
                "ip":          "10.10.0.101",
                "os":          "windows",
                "status":      "active",
                "last_seen":   datetime.now(timezone.utc).isoformat(),
            },
            {
                "id":          "f0e1d2c3-b4a5-6789-0fed-cba987654321",
                "hostname":    "srv-linux-prod.premoscorp.local",
                "ip":          "10.10.0.201",
                "os":          "linux",
                "status":      "active",
                "last_seen":   datetime.now(timezone.utc).isoformat(),
            },
        ],
        "report_url":   _canary_url(base_url, token.token_id),
        "total":        2,
    }, token


def build_export_decoy(base_url: str) -> tuple[dict, CanaryToken]:
    """
    Build decoy response for GET /agents/export.
    Looks like a credentials/config export.
    Fake DB strings and API keys are completely inert — they reference
    non-routable internal hostnames. The canary token URL triggers on access.
    """
    token = canary_store.create("/agents/export", label="export-config-link")
    cred_token = canary_store.create("/agents/export", label="export-embedded-credential")
    return {
        "export_id":    token.token_id[:16],
        "export_ts":    datetime.now(timezone.utc).isoformat(),
        "status":       "ready",
        "format":       "json",
        "config": {
            "database": {
                "host":     "db-primary.premoscorp.local",
                "port":     5432,
                "name":     "asc_prod",
                "user":     f"svc_specter_{cred_token.token_id[:8]}",
                "password": f"Sp3ct3r!{cred_token.token_id[8:16]}@2026",
                "schema":   "public",
            },
            "redis": {
                "host":     "redis-cache.premoscorp.local",
                "port":     6379,
                "password": cred_token.token_id[16:32],
            },
            "signing_key": cred_token.token_id,
        },
        "download_url": _canary_url(base_url, token.token_id),
        "expires_in":   3600,
    }, token


# ── Signed Evidence Report ─────────────────────────────────────────────────────

def generate_evidence_report(
    event_type: str,
    fingerprint: AttackerFingerprint,
    token: Optional[CanaryToken],
    ip_reputation: Optional[dict],
    secret_key: str,
    additional_context: dict | None = None,
) -> dict[str, Any]:
    """
    Generate a tamper-evident evidence report suitable for:
      - Law enforcement incident reports
      - CERT / CSIRT submissions
      - AbuseIPDB manual reports
      - Hosting provider abuse complaints
      - Internal incident documentation

    The report is signed with HMAC-SHA256 so any modification of the
    payload after generation is detectable.

    Returns: {"report_id": str, "report": dict, "signature": str}
    """
    report_id = str(uuid.uuid4())
    report: dict[str, Any] = {
        "report_id":     report_id,
        "generated_at":  datetime.now(timezone.utc).isoformat(),
        "generated_by":  "SPECTER-Honeypot-Engine-PremosCorp-v1",
        "event_type":    event_type,
        "incident_summary": {
            "description":    f"Unauthorized access to PremosCorp honeypot endpoint detected.",
            "severity":       "medium" if ((ip_reputation or {}).get("abuse_confidence_score") or 0) < 50 else "high",
            "attacker_ip":    fingerprint.client_ip,
            "x_forwarded_for": fingerprint.x_forwarded_for or None,
            "attack_ts":      fingerprint.timestamp,
        },
        "attacker_fingerprint": fingerprint.to_dict(),
        "ip_reputation":   ip_reputation or {},
        "canary_evidence": {
            "token_id":     token.token_id if token else None,
            "endpoint":     token.endpoint if token else None,
            "label":        token.label if token else None,
            "access_count": token.access_count if token else 0,
            "first_access": token.first_access if token else None,
            "last_access":  token.last_access if token else None,
        } if token else None,
        "evidence_chain": [
            {
                "ts":       access.ts,
                "ip":       access.client_ip,
                "ua":       access.user_agent,
                "action":   "canary_callback_triggered",
                "endpoint": token.endpoint if token else "unknown",
            }
            for access in (token.accesses if token else [])
        ],
        "additional_context": additional_context or {},
        "legal_notice": (
            "This report documents unauthorized access to PremosCorp security "
            "infrastructure. All evidence was collected passively on PremosCorp-owned "
            "systems. No unauthorized access to attacker systems was performed. "
            "Report generated for potential submission to relevant authorities."
        ),
        "reporting_guidelines": {
            "abuseipdb":   "https://www.abuseipdb.com/report",
            "cert_co":     "https://colcert.gov.co/",
            "cert_es":     "https://www.incibe-cert.es/",
            "interpol":    "https://www.interpol.int/Crimes/Cybercrime",
        },
    }

    # Sign the report — any tampering invalidates the signature
    report_json = json.dumps(report, sort_keys=True, separators=(",", ":"))
    sig = hmac.new(secret_key.encode(), report_json.encode(), hashlib.sha256).hexdigest()

    log_security_action(
        "honeypot_evidence_report_generated",
        user_id="system",
        role="system",
        resource="honeypot_report",
        resource_id=report_id,
        detail=f"event={event_type} ip={fingerprint.client_ip} fp={fingerprint.fingerprint_hash[:12]}",
    )

    return {
        "report_id": report_id,
        "report":    report,
        "signature": sig,
    }


def verify_report_signature(report: dict, signature: str, secret_key: str) -> bool:
    """Verify a previously generated evidence report has not been tampered with."""
    report_json = json.dumps(report, sort_keys=True, separators=(",", ":"))
    expected = hmac.new(secret_key.encode(), report_json.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature, expected)
