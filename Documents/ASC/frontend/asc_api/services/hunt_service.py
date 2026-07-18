"""
P22 — Threat Hunting Service

All operations are PASSIVE (read-only analysis of already-collected data).
No active probing or outbound connections are initiated here.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.core.logging import get_logger
from asc_api.core.tenant_context import get_tenant_id
from asc_api.models.hunt import Hunt, HuntFinding, HuntQuery

log = get_logger("asc.hunt")

# ── Constants ──────────────────────────────────────────────────────────────────

VALID_STATUSES = frozenset({"draft", "active", "completed", "archived"})
VALID_PRIORITIES = frozenset({"critical", "high", "medium", "low"})
VALID_SCOPES = frozenset({"host", "network", "cloud", "all"})
VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
VALID_DATA_SOURCES = frozenset({"elk", "wazuh", "specter_agent", "manual"})
VALID_INDICATOR_TYPES = frozenset({
    "ip", "cidr", "domain", "url", "email",
    "hash_md5", "hash_sha1", "hash_sha256",
    "file_path", "mutex", "registry_key", "cve", "other",
})

# Status transition rules
_ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    "draft": {"active", "archived"},
    "active": {"completed", "archived"},
    "completed": {"archived"},
    "archived": set(),
}

_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


# ── Serializers ────────────────────────────────────────────────────────────────

def _hunt_to_dict(h: Hunt, *, include_relations: bool = False) -> dict:
    d: dict[str, Any] = {
        "id": h.id,
        "name": h.name,
        "description": h.description,
        "hypothesis": h.hypothesis,
        "status": h.status,
        "mitre_technique": h.mitre_technique,
        "mitre_tactic": h.mitre_tactic,
        "scope": h.scope,
        "priority": h.priority,
        "created_by": h.created_by,
        "assigned_to": h.assigned_to,
        "created_at": h.created_at.isoformat(),
        "started_at": h.started_at.isoformat() if h.started_at else None,
        "completed_at": h.completed_at.isoformat() if h.completed_at else None,
        "updated_at": h.updated_at.isoformat(),
        "conclusion": h.conclusion,
        "findings_count": h.findings_count,
        "true_positive_count": h.true_positive_count,
        "tags": h.tags or [],
    }
    if include_relations:
        d["findings"] = [_finding_to_dict(f) for f in (h.findings or [])]
        d["queries"] = [_query_to_dict(q) for q in (h.queries or [])]
    return d


def _finding_to_dict(f: HuntFinding) -> dict:
    return {
        "id": f.id,
        "hunt_id": f.hunt_id,
        "title": f.title,
        "description": f.description,
        "severity": f.severity,
        "indicator_value": f.indicator_value,
        "indicator_type": f.indicator_type,
        "affected_host": f.affected_host,
        "affected_user": f.affected_user,
        "data_source": f.data_source,
        "mitre_technique": f.mitre_technique,
        "mitre_tactic": f.mitre_tactic,
        "evidence": f.evidence,
        "is_confirmed": f.is_confirmed,
        "is_false_positive": f.is_false_positive,
        "analyst_notes": f.analyst_notes,
        "created_by": f.created_by,
        "created_at": f.created_at.isoformat(),
        "updated_at": f.updated_at.isoformat(),
    }


def _query_to_dict(q: HuntQuery) -> dict:
    return {
        "id": q.id,
        "hunt_id": q.hunt_id,
        "name": q.name,
        "query_text": q.query_text,
        "data_source": q.data_source,
        "description": q.description,
        "last_executed_at": q.last_executed_at.isoformat() if q.last_executed_at else None,
        "last_result_count": q.last_result_count,
        "last_execution_ms": q.last_execution_ms,
        "created_by": q.created_by,
        "created_at": q.created_at.isoformat(),
    }


# ── Hunt CRUD ──────────────────────────────────────────────────────────────────

async def create_hunt(
    db: AsyncSession,
    *,
    name: str,
    created_by: str,
    description: str | None = None,
    hypothesis: str | None = None,
    mitre_technique: str | None = None,
    mitre_tactic: str | None = None,
    scope: str = "all",
    priority: str = "medium",
    assigned_to: str | None = None,
    tags: list[str] | None = None,
) -> Hunt:
    if scope not in VALID_SCOPES:
        raise ValueError(f"Invalid scope '{scope}'. Valid: {VALID_SCOPES}")
    if priority not in VALID_PRIORITIES:
        raise ValueError(f"Invalid priority '{priority}'. Valid: {VALID_PRIORITIES}")
    if not name or not name.strip():
        raise ValueError("Hunt name cannot be empty")

    now = datetime.now(timezone.utc)
    hunt = Hunt(
        id=str(uuid.uuid4()),
        name=name.strip(),
        description=description,
        hypothesis=hypothesis,
        status="draft",
        mitre_technique=mitre_technique,
        mitre_tactic=mitre_tactic,
        scope=scope,
        priority=priority,
        created_by=created_by,
        assigned_to=assigned_to,
        created_at=now,
        updated_at=now,
        tags=tags or [],
    )
    db.add(hunt)
    await db.commit()
    await db.refresh(hunt)
    log.info("hunt_created", hunt_id=hunt.id, name=name, created_by=created_by)
    return hunt


async def list_hunts(
    db: AsyncSession,
    *,
    status: str | None = None,
    priority: str | None = None,
    scope: str | None = None,
    created_by: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[Hunt], int]:
    stmt = select(Hunt)
    count_stmt = select(func.count(Hunt.id))

    if status:
        stmt = stmt.where(Hunt.status == status)
        count_stmt = count_stmt.where(Hunt.status == status)
    if priority:
        stmt = stmt.where(Hunt.priority == priority)
        count_stmt = count_stmt.where(Hunt.priority == priority)
    if scope:
        stmt = stmt.where(Hunt.scope == scope)
        count_stmt = count_stmt.where(Hunt.scope == scope)
    if created_by:
        stmt = stmt.where(Hunt.created_by == created_by)
        count_stmt = count_stmt.where(Hunt.created_by == created_by)

    stmt = stmt.order_by(Hunt.created_at.desc()).offset(offset).limit(limit)

    total = (await db.execute(count_stmt)).scalar_one()
    hunts = (await db.execute(stmt)).scalars().all()
    return list(hunts), total


async def get_hunt(db: AsyncSession, hunt_id: str) -> Hunt | None:
    # SECURITY (S103.7): aislamiento cross-tenant. Choke point: las 5 mutaciones
    # de hunt cargan por aquí. ContextVar ligado al usuario autenticado (S103.2).
    stmt = select(Hunt).where(Hunt.id == hunt_id)
    _tid = get_tenant_id()
    if _tid is not None:
        stmt = stmt.where(Hunt.tenant_id == _tid)
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def update_hunt(
    db: AsyncSession,
    hunt_id: str,
    updates: dict,
    *,
    updated_by: str,
) -> Hunt | None:
    hunt = await get_hunt(db, hunt_id)
    if hunt is None:
        return None

    # Status transition validation
    if "status" in updates:
        new_status = updates["status"]
        if new_status not in VALID_STATUSES:
            raise ValueError(f"Invalid status '{new_status}'")
        allowed = _ALLOWED_TRANSITIONS.get(hunt.status, set())
        if new_status not in allowed:
            raise ValueError(
                f"Cannot transition hunt from '{hunt.status}' to '{new_status}'. "
                f"Allowed: {allowed or 'none'}"
            )
        now = datetime.now(timezone.utc)
        if new_status == "active" and hunt.started_at is None:
            hunt.started_at = now
        elif new_status == "completed" and hunt.completed_at is None:
            hunt.completed_at = now

    allowed_fields = {
        "name", "description", "hypothesis", "mitre_technique", "mitre_tactic",
        "scope", "priority", "assigned_to", "conclusion", "tags", "status",
    }
    for field, value in updates.items():
        if field not in allowed_fields:
            continue
        if field == "scope" and value not in VALID_SCOPES:
            raise ValueError(f"Invalid scope '{value}'")
        if field == "priority" and value not in VALID_PRIORITIES:
            raise ValueError(f"Invalid priority '{value}'")
        setattr(hunt, field, value)

    hunt.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(hunt)
    log.info("hunt_updated", hunt_id=hunt_id, fields=list(updates.keys()), updated_by=updated_by)
    return hunt


async def archive_hunt(db: AsyncSession, hunt_id: str) -> bool:
    """Soft-delete: set status to 'archived'."""
    hunt = await get_hunt(db, hunt_id)
    if hunt is None:
        return False
    hunt.status = "archived"
    hunt.updated_at = datetime.now(timezone.utc)
    await db.commit()
    log.info("hunt_archived", hunt_id=hunt_id)
    return True


# ── Findings ──────────────────────────────────────────────────────────────────

async def add_finding(
    db: AsyncSession,
    hunt_id: str,
    *,
    title: str,
    created_by: str,
    severity: str = "medium",
    description: str | None = None,
    indicator_value: str | None = None,
    indicator_type: str | None = None,
    affected_host: str | None = None,
    affected_user: str | None = None,
    data_source: str | None = None,
    mitre_technique: str | None = None,
    mitre_tactic: str | None = None,
    evidence: dict | None = None,
    analyst_notes: str | None = None,
) -> HuntFinding:
    if severity not in VALID_SEVERITIES:
        raise ValueError(f"Invalid severity '{severity}'. Valid: {VALID_SEVERITIES}")
    if not title or not title.strip():
        raise ValueError("Finding title cannot be empty")
    if indicator_type and indicator_type not in VALID_INDICATOR_TYPES:
        raise ValueError(f"Invalid indicator_type '{indicator_type}'")

    now = datetime.now(timezone.utc)
    finding = HuntFinding(
        id=str(uuid.uuid4()),
        hunt_id=hunt_id,
        title=title.strip(),
        description=description,
        severity=severity,
        indicator_value=indicator_value,
        indicator_type=indicator_type,
        affected_host=affected_host,
        affected_user=affected_user,
        data_source=data_source,
        mitre_technique=mitre_technique,
        mitre_tactic=mitre_tactic,
        evidence=evidence,
        analyst_notes=analyst_notes,
        created_by=created_by,
        created_at=now,
        updated_at=now,
    )
    db.add(finding)

    # Increment hunt findings_count
    hunt = await get_hunt(db, hunt_id)
    if hunt:
        hunt.findings_count = (hunt.findings_count or 0) + 1
        hunt.updated_at = now

    await db.commit()
    await db.refresh(finding)
    log.info("finding_added", hunt_id=hunt_id, finding_id=finding.id, severity=severity)
    return finding


async def list_findings(
    db: AsyncSession,
    hunt_id: str,
    *,
    severity: str | None = None,
    confirmed_only: bool = False,
) -> list[HuntFinding]:
    stmt = select(HuntFinding).where(HuntFinding.hunt_id == hunt_id)
    if severity:
        stmt = stmt.where(HuntFinding.severity == severity)
    if confirmed_only:
        stmt = stmt.where(HuntFinding.is_confirmed.is_(True))
    stmt = stmt.order_by(HuntFinding.created_at.desc())
    result = await db.execute(stmt)
    return list(result.scalars().all())


async def get_finding(db: AsyncSession, finding_id: str) -> HuntFinding | None:
    result = await db.execute(select(HuntFinding).where(HuntFinding.id == finding_id))
    return result.scalar_one_or_none()


async def update_finding(
    db: AsyncSession,
    finding_id: str,
    updates: dict,
) -> HuntFinding | None:
    finding = await get_finding(db, finding_id)
    if finding is None:
        return None

    allowed_fields = {
        "title", "description", "severity", "indicator_value", "indicator_type",
        "affected_host", "affected_user", "data_source", "mitre_technique",
        "mitre_tactic", "evidence", "analyst_notes",
    }
    for field, value in updates.items():
        if field in allowed_fields:
            setattr(finding, field, value)

    finding.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(finding)
    return finding


async def set_finding_verdict(
    db: AsyncSession,
    finding_id: str,
    *,
    is_confirmed: bool,
    is_false_positive: bool = False,
    analyst_notes: str | None = None,
) -> HuntFinding | None:
    finding = await get_finding(db, finding_id)
    if finding is None:
        return None

    was_confirmed = finding.is_confirmed

    finding.is_confirmed = is_confirmed
    finding.is_false_positive = is_false_positive
    if analyst_notes is not None:
        finding.analyst_notes = analyst_notes
    finding.updated_at = datetime.now(timezone.utc)

    # Update hunt true_positive_count
    hunt = await get_hunt(db, finding.hunt_id)
    if hunt:
        if is_confirmed and not was_confirmed:
            hunt.true_positive_count = (hunt.true_positive_count or 0) + 1
        elif not is_confirmed and was_confirmed:
            hunt.true_positive_count = max(0, (hunt.true_positive_count or 1) - 1)
        hunt.updated_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(finding)
    log.info("finding_verdict", finding_id=finding_id, confirmed=is_confirmed, fp=is_false_positive)
    return finding


# ── Queries ───────────────────────────────────────────────────────────────────

async def save_query(
    db: AsyncSession,
    hunt_id: str,
    *,
    name: str,
    query_text: str,
    data_source: str = "elk",
    created_by: str,
    description: str | None = None,
) -> HuntQuery:
    if data_source not in VALID_DATA_SOURCES:
        raise ValueError(f"Invalid data_source '{data_source}'. Valid: {VALID_DATA_SOURCES}")
    if not query_text or not query_text.strip():
        raise ValueError("query_text cannot be empty")

    now = datetime.now(timezone.utc)
    query = HuntQuery(
        id=str(uuid.uuid4()),
        hunt_id=hunt_id,
        name=name.strip(),
        query_text=query_text.strip(),
        data_source=data_source,
        description=description,
        created_by=created_by,
        created_at=now,
    )
    db.add(query)
    await db.commit()
    await db.refresh(query)
    log.info("query_saved", hunt_id=hunt_id, query_id=query.id, data_source=data_source)
    return query


async def list_queries(db: AsyncSession, hunt_id: str) -> list[HuntQuery]:
    result = await db.execute(
        select(HuntQuery)
        .where(HuntQuery.hunt_id == hunt_id)
        .order_by(HuntQuery.created_at.desc())
    )
    return list(result.scalars().all())


async def delete_query(db: AsyncSession, query_id: str) -> bool:
    _stmt = select(HuntQuery).where(HuntQuery.id == query_id)
    _tid = get_tenant_id()  # SECURITY (S103.7)
    if _tid is not None:
        _stmt = _stmt.where(HuntQuery.tenant_id == _tid)
    result = await db.execute(_stmt)
    q = result.scalar_one_or_none()
    if q is None:
        return False
    await db.delete(q)
    await db.commit()
    return True


# ── Stats ─────────────────────────────────────────────────────────────────────

async def get_hunt_stats(db: AsyncSession) -> dict:
    total = (await db.execute(select(func.count(Hunt.id)))).scalar_one()

    # By status
    status_rows = (await db.execute(
        select(Hunt.status, func.count(Hunt.id)).group_by(Hunt.status)
    )).all()
    by_status = {row[0]: row[1] for row in status_rows}

    # By priority
    priority_rows = (await db.execute(
        select(Hunt.priority, func.count(Hunt.id)).group_by(Hunt.priority)
    )).all()
    by_priority = {row[0]: row[1] for row in priority_rows}

    # Findings stats
    total_findings = (await db.execute(select(func.count(HuntFinding.id)))).scalar_one()
    confirmed_findings = (await db.execute(
        select(func.count(HuntFinding.id)).where(HuntFinding.is_confirmed.is_(True))
    )).scalar_one()

    sev_rows = (await db.execute(
        select(HuntFinding.severity, func.count(HuntFinding.id)).group_by(HuntFinding.severity)
    )).all()
    findings_by_severity = {row[0]: row[1] for row in sev_rows}

    # Top techniques
    technique_rows = (await db.execute(
        select(Hunt.mitre_technique, func.count(Hunt.id))
        .where(Hunt.mitre_technique.isnot(None))
        .group_by(Hunt.mitre_technique)
        .order_by(func.count(Hunt.id).desc())
        .limit(10)
    )).all()
    top_techniques = [{"technique": r[0], "count": r[1]} for r in technique_rows]

    return {
        "total_hunts": total,
        "by_status": by_status,
        "by_priority": by_priority,
        "active_hunts": by_status.get("active", 0),
        "completed_hunts": by_status.get("completed", 0),
        "total_findings": total_findings,
        "confirmed_findings": confirmed_findings,
        "false_positive_rate": round(
            1.0 - (confirmed_findings / total_findings) if total_findings > 0 else 0.0, 3
        ),
        "findings_by_severity": findings_by_severity,
        "top_techniques": top_techniques,
    }


# ── P23-F2: Hunt from Alert ───────────────────────────────────────────────────

async def create_hunt_from_alert(
    db: AsyncSession,
    alert_id: str,
    *,
    created_by: str,
) -> Hunt | None:
    """
    Bootstrap a threat-hunting session from an existing alert.

    - Hunt name derived from alert title
    - Hypothesis auto-generated from alert severity + TTPs
    - First finding pre-populated from alert data
    - Hunt starts in 'active' status (alert already triggered investigation)
    """
    from asc_api.models.alert import Alert

    _astmt = select(Alert).where(Alert.id == alert_id)
    _tid = get_tenant_id()  # SECURITY (S103.8): no crear hunt desde alerta de otro tenant
    if _tid is not None:
        _astmt = _astmt.where(Alert.tenant_id == _tid)
    result = await db.execute(_astmt)
    alert = result.scalar_one_or_none()
    if alert is None:
        return None

    now = datetime.now(timezone.utc)

    # Map alert severity → hunt priority
    priority_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
    priority = priority_map.get(alert.severity, "medium")

    # Auto-generate hypothesis from alert metadata
    ttps_str = ", ".join(alert.ttps[:3]) if alert.ttps else "unknown TTPs"
    hypothesis = (
        f"Alert '{alert.title}' (severity={alert.severity}, risk={alert.risk_score:.2f}) "
        f"indicates potential threat activity involving {ttps_str}. "
        f"Investigating scope and lateral movement."
    )

    # Extract first MITRE technique from TTPs
    mitre_technique: str | None = None
    mitre_tactic: str | None = None
    for ttp in (alert.ttps or []):
        if isinstance(ttp, str) and ttp.startswith("T"):
            mitre_technique = ttp[:6]  # e.g. "T1055"
            break

    hunt = Hunt(
        id=str(uuid.uuid4()),
        name=f"Hunt: {alert.title[:200]}",
        description=f"Automatically created from alert ID {alert_id}",
        hypothesis=hypothesis,
        status="active",
        mitre_technique=mitre_technique,
        mitre_tactic=mitre_tactic,
        scope="all",
        priority=priority,
        created_by=created_by,
        assigned_to=created_by,
        created_at=now,
        started_at=now,
        updated_at=now,
        tags=["from-alert", alert.severity],
        findings_count=0,
        true_positive_count=0,
    )
    db.add(hunt)
    await db.flush()  # get hunt.id without committing yet

    # Pre-populate first finding from alert data
    host = (alert.affected_hosts or [""])[0] if alert.affected_hosts else None
    finding = HuntFinding(
        id=str(uuid.uuid4()),
        hunt_id=hunt.id,
        title=f"Initial indicator from alert: {alert.title[:200]}",
        description=alert.description[:1000] if alert.description else None,
        severity=alert.severity,
        affected_host=host,
        data_source="elk",
        mitre_technique=mitre_technique,
        mitre_tactic=mitre_tactic,
        analyst_notes=f"Auto-created from alert {alert_id}. Risk score: {alert.risk_score:.2f}",
        created_by=created_by,
        created_at=now,
        updated_at=now,
    )
    db.add(finding)
    hunt.findings_count = 1

    await db.commit()
    await db.refresh(hunt)
    log.info(
        "hunt_created_from_alert",
        hunt_id=hunt.id,
        alert_id=alert_id,
        created_by=created_by,
    )
    return hunt


# ── P23-F3: TI Auto-Enrichment on Findings ───────────────────────────────────

async def enrich_finding(
    db: AsyncSession,
    finding_id: str,
) -> dict:
    """
    Auto-enrich a finding's indicator_value against the ThreatIntel table.
    Passive — read-only lookup, no external calls.
    Returns match list and updates finding.analyst_notes if matches found.
    """
    from asc_api.services.threat_intel import enrich as ti_enrich

    finding = await get_finding(db, finding_id)
    if finding is None:
        return {"error": "Finding not found", "enriched": False, "matches": []}

    if not finding.indicator_value:
        return {
            "finding_id": finding_id,
            "enriched": False,
            "matches": [],
            "note": "Finding has no indicator_value to enrich",
        }

    matches = await ti_enrich(
        db,
        finding.indicator_value,
        finding.indicator_type,
        track_hit=True,
    )

    enriched = len(matches) > 0
    if enriched:
        ti_summary = "; ".join(
            f"{m.indicator_type}:{m.value} [{m.severity}] src={m.source}"
            for m in matches[:5]
        )
        existing_notes = finding.analyst_notes or ""
        separator = "\n\n" if existing_notes else ""
        finding.analyst_notes = (
            f"{existing_notes}{separator}"
            f"[TI Enrichment] {len(matches)} match(es): {ti_summary}"
        )
        finding.updated_at = datetime.now(timezone.utc)
        await db.commit()

    log.info(
        "finding_enriched",
        finding_id=finding_id,
        hunt_id=finding.hunt_id,
        indicator=finding.indicator_value,
        match_count=len(matches),
    )

    from asc_api.services.threat_intel import _indicator_to_dict
    return {
        "finding_id": finding_id,
        "hunt_id": finding.hunt_id,
        "indicator_value": finding.indicator_value,
        "indicator_type": finding.indicator_type,
        "enriched": enriched,
        "match_count": len(matches),
        "matches": [_indicator_to_dict(m) for m in matches],
        "is_known_bad": enriched,
        "max_severity": _max_severity_from_matches(matches),
    }


def _max_severity_from_matches(matches: list) -> str | None:
    if not matches:
        return None
    _SEV = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    return max(matches, key=lambda m: _SEV.get(m.severity, 0)).severity


# ── P23-F4: Hunt Report Export ────────────────────────────────────────────────

async def generate_report(db: AsyncSession, hunt_id: str) -> dict | None:
    """
    Generate a structured JSON report of a complete hunt session.
    Includes: metadata, hypothesis, timeline, findings (by severity), queries, conclusion.
    """
    hunt = await get_hunt(db, hunt_id)
    if hunt is None:
        return None

    findings = await list_findings(db, hunt_id)
    queries = await list_queries(db, hunt_id)

    # Group findings by severity
    sev_order = ["critical", "high", "medium", "low", "info"]
    findings_by_sev: dict[str, list] = {s: [] for s in sev_order}
    for f in findings:
        bucket = f.severity if f.severity in findings_by_sev else "info"
        findings_by_sev[bucket].append(_finding_to_dict(f))

    tp_count = sum(1 for f in findings if f.is_confirmed)
    fp_count = sum(1 for f in findings if f.is_false_positive)
    unverified = len(findings) - tp_count - fp_count

    # Timeline events
    timeline = []
    timeline.append({"event": "hunt_created", "ts": hunt.created_at.isoformat(), "note": f"Created by {hunt.created_by}"})
    if hunt.started_at:
        timeline.append({"event": "hunt_started", "ts": hunt.started_at.isoformat(), "note": "Status set to active"})
    for f in sorted(findings, key=lambda x: x.created_at):
        timeline.append({
            "event": "finding_added",
            "ts": f.created_at.isoformat(),
            "note": f"[{f.severity.upper()}] {f.title}",
            "confirmed": f.is_confirmed,
            "false_positive": f.is_false_positive,
        })
    if hunt.completed_at:
        timeline.append({"event": "hunt_completed", "ts": hunt.completed_at.isoformat(), "note": "Status set to completed"})

    return {
        "report_generated_at": datetime.now(timezone.utc).isoformat(),
        "hunt": _hunt_to_dict(hunt),
        "executive_summary": {
            "total_findings": len(findings),
            "true_positives": tp_count,
            "false_positives": fp_count,
            "unverified": unverified,
            "false_positive_rate": round(fp_count / len(findings) if findings else 0.0, 3),
            "scope": hunt.scope,
            "priority": hunt.priority,
            "mitre_technique": hunt.mitre_technique,
            "mitre_tactic": hunt.mitre_tactic,
            "duration_hours": _duration_hours(hunt),
        },
        "hypothesis": hunt.hypothesis,
        "conclusion": hunt.conclusion,
        "findings_by_severity": findings_by_sev,
        "findings_total": len(findings),
        "queries_used": [_query_to_dict(q) for q in queries],
        "timeline": timeline,
        "tags": hunt.tags,
    }


def _duration_hours(hunt: Hunt) -> float | None:
    start = hunt.started_at
    end = hunt.completed_at or datetime.now(timezone.utc)
    if start is None:
        return None
    delta = end - start if end.tzinfo else (end.replace(tzinfo=timezone.utc) - start)
    return round(delta.total_seconds() / 3600, 2)
