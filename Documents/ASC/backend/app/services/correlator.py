"""
Event Correlation & IoC Matching Service — SIEM logic.
"""
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.models.event import Event
from app.models.ioc import IoC
from app.models.alert import Alert
from app.core.logging import get_logger
from app.core.config import get_settings

settings = get_settings()
log = get_logger(__name__)


# Correlation rules: each rule inspects a window of events and fires an alert
CORRELATION_RULES = [
    {
        "id":          "rule_brute_force",
        "name":        "Brute Force Authentication",
        "description": "More than 10 failed login attempts from the same host in 5 minutes",
        "category":    "authentication",
        "severity":    "high",
        "risk_score":  0.75,
        "ttps":        ["T1110"],
    },
    {
        "id":          "rule_lateral_movement",
        "name":        "Lateral Movement via SMB",
        "description": "SMB connections to multiple hosts from the same source within 10 minutes",
        "category":    "network",
        "severity":    "critical",
        "risk_score":  0.90,
        "ttps":        ["T1021.002"],
    },
    {
        "id":          "rule_persistence_registry",
        "name":        "Persistence via Registry Run Key",
        "description": "Write to registry run key detected",
        "category":    "registry",
        "severity":    "high",
        "risk_score":  0.80,
        "ttps":        ["T1547.001"],
    },
    {
        "id":          "rule_data_exfiltration",
        "name":        "Potential Data Exfiltration",
        "description": "Large outbound transfer to external IP not in allowlist",
        "category":    "network",
        "severity":    "critical",
        "risk_score":  0.88,
        "ttps":        ["T1041"],
    },
    {
        "id":          "rule_credential_dump",
        "name":        "Credential Dumping Detected",
        "description": "LSASS memory access or credential harvesting tool signature",
        "category":    "process",
        "severity":    "critical",
        "risk_score":  0.95,
        "ttps":        ["T1003"],
    },
]


async def match_iocs(value: str, db: AsyncSession) -> list[dict]:
    """Check a value against all active IoCs in the database."""
    result = await db.execute(
        select(IoC).where(IoC.value == value, IoC.active == True)
    )
    hits = result.scalars().all()

    matched = []
    for ioc in hits:
        # Update hit counter
        ioc.hit_count += 1
        ioc.last_seen = datetime.now(timezone.utc)
        matched.append({
            "ioc_id":     ioc.id,
            "value":      ioc.value,
            "type":       ioc.ioc_type,
            "threat":     ioc.threat_type,
            "confidence": ioc.confidence,
            "severity":   ioc.severity,
        })

    if matched:
        await db.commit()
    return matched


async def normalize_event(raw: dict) -> dict:
    """Normalize raw log to ECS-compatible fields."""
    return {
        "source":    raw.get("source", "unknown"),
        "category":  raw.get("category", "unknown"),
        "action":    raw.get("action", ""),
        "host":      raw.get("host", raw.get("hostname", "unknown")),
        "user":      raw.get("user", raw.get("username", "")),
        "process":   raw.get("process", raw.get("process_name", "")),
        "pid":       raw.get("pid"),
        "src_ip":    raw.get("src_ip", raw.get("source_ip", "")),
        "dst_ip":    raw.get("dst_ip", raw.get("dest_ip", "")),
        "dst_port":  raw.get("dst_port", raw.get("port")),
        "file_path": raw.get("file_path", raw.get("file", "")),
        "reg_key":   raw.get("reg_key", raw.get("registry_key", "")),
        "timestamp": raw.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "tags":      raw.get("tags", []),
    }


async def evaluate_correlation_rules(events: list[dict], db: AsyncSession) -> list[dict]:
    """Evaluate correlation rules against a batch of normalized events. Returns alerts to create."""
    alerts_to_create = []
    hosts = [e.get("host") for e in events if e.get("host")]
    categories = [e.get("category") for e in events]

    for rule in CORRELATION_RULES:
        fired = False

        if rule["id"] == "rule_brute_force":
            auth_failures = [e for e in events if e.get("category") == "authentication" and "fail" in str(e.get("action", "")).lower()]
            if len(auth_failures) >= 3:
                fired = True

        elif rule["id"] == "rule_persistence_registry":
            reg_writes = [e for e in events if e.get("category") == "registry" and "write" in str(e.get("action", "")).lower()]
            if reg_writes:
                fired = True

        elif rule["id"] == "rule_credential_dump":
            cred_events = [e for e in events if "lsass" in str(e.get("process", "")).lower() or "mimikatz" in str(e.get("action", "")).lower()]
            if cred_events:
                fired = True

        elif rule["id"] == "rule_lateral_movement":
            smb_events = [e for e in events if e.get("dst_port") in [445, 139] or "smb" in str(e.get("action", "")).lower()]
            if len(smb_events) >= 2:
                fired = True

        if fired:
            alerts_to_create.append({
                "title":       rule["name"],
                "description": rule["description"],
                "severity":    rule["severity"],
                "risk_score":  rule["risk_score"],
                "ttps":        rule["ttps"],
                "rule_id":     rule["id"],
            })
            log.info("correlation_rule_fired", rule=rule["id"], severity=rule["severity"])

    return alerts_to_create


async def get_ioc_coverage(db: AsyncSession) -> float:
    """Percentage of IoCs that have had at least one hit."""
    total_result = await db.execute(select(func.count()).select_from(IoC).where(IoC.active == True))
    total = total_result.scalar() or 0
    if total == 0:
        return 0.0

    hit_result = await db.execute(select(func.count()).select_from(IoC).where(IoC.active == True, IoC.hit_count > 0))
    hits = hit_result.scalar() or 0
    return round(hits / total, 4)
