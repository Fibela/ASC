"""
Incident Response Management Service — P28-B

Implements the formal NIST 800-61 incident lifecycle:

  Detection/Analysis → Containment → Eradication → Recovery
  → Post-Incident Activity → Closed | Dismissed

Security posture
----------------
- State machine enforces VALID_TRANSITIONS — no arbitrary status jumps
- All writes produce immutable IncidentTimeline audit events
- Forensic SHA3-512 hash sealed at close time
- SLA breach flag computed on every status transition
- auto_create_from_cluster() called passively by correlation sweep — no
  external mutation; it only creates Incident rows when a cluster is promoted
  to campaign status
"""
from __future__ import annotations

import math
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.core.audit import log_security_action
from asc_api.core.logging import get_logger
from asc_api.models.incident import (
    DEFAULT_SLA_MINUTES,
    NIST_PHASE,
    VALID_TRANSITIONS,
    Incident,
    IncidentLink,
    IncidentTimeline,
)

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _minutes_between(start: datetime | None, end: datetime | None) -> int | None:
    if start is None or end is None:
        return None
    # SQLite returns timezone-naive datetimes; normalise both to UTC-naive before subtraction.
    if start.tzinfo is not None:
        start = start.replace(tzinfo=None)
    if end.tzinfo is not None:
        end = end.replace(tzinfo=None)
    delta = end - start
    return max(0, math.ceil(delta.total_seconds() / 60))


def _sla_for(severity: str) -> int:
    return DEFAULT_SLA_MINUTES.get(severity, 1440)


def _check_sla_breach(incident: Incident) -> bool:
    """Return True if elapsed time since detected_at exceeds sla_minutes."""
    if incident.detected_at is None:
        return False
    elapsed = _minutes_between(incident.detected_at, _utcnow())
    if elapsed is None:
        return False
    return elapsed > incident.sla_minutes


def _add_timeline(
    db: AsyncSession,
    incident_id: str,
    event_type: str,
    actor: str,
    detail: dict[str, Any],
) -> IncidentTimeline:
    entry = IncidentTimeline(
        id=str(uuid.uuid4()),
        incident_id=incident_id,
        event_type=event_type,
        actor=actor,
        detail=detail,
        created_at=_utcnow(),
    )
    db.add(entry)
    return entry


# ---------------------------------------------------------------------------
# Read operations
# ---------------------------------------------------------------------------


async def get_incident(db: AsyncSession, incident_id: str) -> Incident | None:
    result = await db.execute(
        select(Incident).where(Incident.id == incident_id)
    )
    return result.scalar_one_or_none()


async def list_incidents(
    db: AsyncSession,
    *,
    status: str | None = None,
    severity: str | None = None,
    incident_type: str | None = None,
    assigned_to: str | None = None,
    sla_breach: bool | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[Incident]:
    q = select(Incident).order_by(Incident.created_at.desc())
    if status:
        q = q.where(Incident.status == status)
    if severity:
        q = q.where(Incident.severity == severity)
    if incident_type:
        q = q.where(Incident.incident_type == incident_type)
    if assigned_to:
        q = q.where(Incident.assigned_to == assigned_to)
    if sla_breach is not None:
        q = q.where(Incident.sla_breach == sla_breach)
    q = q.limit(limit).offset(offset)
    result = await db.execute(q)
    return list(result.scalars().all())


async def get_incident_links(db: AsyncSession, incident_id: str) -> list[IncidentLink]:
    result = await db.execute(
        select(IncidentLink)
        .where(IncidentLink.incident_id == incident_id)
        .order_by(IncidentLink.created_at.asc())
    )
    return list(result.scalars().all())


async def get_incident_timeline(db: AsyncSession, incident_id: str) -> list[IncidentTimeline]:
    result = await db.execute(
        select(IncidentTimeline)
        .where(IncidentTimeline.incident_id == incident_id)
        .order_by(IncidentTimeline.created_at.asc())
    )
    return list(result.scalars().all())


async def get_incident_summary(db: AsyncSession) -> dict[str, Any]:
    """KPI dashboard stats: counts by status/severity, SLA breach count, avg MTTD/MTTR."""
    now = _utcnow()

    # Total count
    total_r = await db.execute(select(func.count()).select_from(Incident))
    total = total_r.scalar_one()

    # By status
    status_r = await db.execute(
        select(Incident.status, func.count()).group_by(Incident.status)
    )
    by_status: dict[str, int] = {row[0]: row[1] for row in status_r.all()}

    # By severity
    sev_r = await db.execute(
        select(Incident.severity, func.count()).group_by(Incident.severity)
    )
    by_severity: dict[str, int] = {row[0]: row[1] for row in sev_r.all()}

    # SLA breach count
    breach_r = await db.execute(
        select(func.count()).select_from(Incident).where(Incident.sla_breach.is_(True))
    )
    sla_breach_count = breach_r.scalar_one()

    # Average MTTD (minutes) — incidents that have triaged_at
    mttd_r = await db.execute(
        select(func.avg(Incident.mttd_minutes)).where(Incident.mttd_minutes.isnot(None))
    )
    avg_mttd = mttd_r.scalar_one()

    # Average MTTR (minutes) — closed incidents
    mttr_r = await db.execute(
        select(func.avg(Incident.mttr_minutes)).where(Incident.mttr_minutes.isnot(None))
    )
    avg_mttr = mttr_r.scalar_one()

    # Average MTTC (minutes)
    mttc_r = await db.execute(
        select(func.avg(Incident.mttc_minutes)).where(Incident.mttc_minutes.isnot(None))
    )
    avg_mttc = mttc_r.scalar_one()

    # Open campaigns (incidents with cluster links that are not closed/dismissed)
    open_r = await db.execute(
        select(func.count()).select_from(Incident).where(
            Incident.status.not_in(["closed", "dismissed"])
        )
    )
    open_count = open_r.scalar_one()

    return {
        "total": total,
        "open": open_count,
        "by_status": by_status,
        "by_severity": by_severity,
        "sla_breach_count": sla_breach_count,
        "avg_mttd_minutes": round(avg_mttd, 1) if avg_mttd is not None else None,
        "avg_mttc_minutes": round(avg_mttc, 1) if avg_mttc is not None else None,
        "avg_mttr_minutes": round(avg_mttr, 1) if avg_mttr is not None else None,
        "generated_at": now.isoformat(),
    }


# ---------------------------------------------------------------------------
# Write operations
# ---------------------------------------------------------------------------


async def create_incident(
    db: AsyncSession,
    *,
    title: str,
    incident_type: str,
    severity: str,
    created_by: str,
    description: str | None = None,
    assigned_to: str | None = None,
    mitre_tactics: list[str] | None = None,
    mitre_techniques: list[str] | None = None,
    tags: list[str] | None = None,
    risk_score: float = 0.0,
    linked_entity_type: str | None = None,
    linked_entity_id: str | None = None,
    linked_entity_notes: str | None = None,
) -> Incident:
    now = _utcnow()
    incident = Incident(
        id=str(uuid.uuid4()),
        title=title,
        description=description,
        incident_type=incident_type,
        status="detected",
        nist_phase=NIST_PHASE["detected"],
        severity=severity,
        risk_score=risk_score,
        created_by=created_by,
        assigned_to=assigned_to,
        mitre_tactics=mitre_tactics or [],
        mitre_techniques=mitre_techniques or [],
        tags=tags or [],
        false_positive=False,
        sla_minutes=_sla_for(severity),
        sla_breach=False,
        detected_at=now,
        created_at=now,
        updated_at=now,
    )
    db.add(incident)

    # Initial timeline entry
    _add_timeline(db, incident.id, "created", created_by, {
        "title": title,
        "incident_type": incident_type,
        "severity": severity,
        "sla_minutes": incident.sla_minutes,
    })

    # Optional initial entity link
    if linked_entity_type and linked_entity_id:
        link = IncidentLink(
            id=str(uuid.uuid4()),
            incident_id=incident.id,
            entity_type=linked_entity_type,
            entity_id=linked_entity_id,
            notes=linked_entity_notes,
            added_by=created_by,
            created_at=now,
        )
        db.add(link)
        _add_timeline(db, incident.id, "link_added", created_by, {
            "entity_type": linked_entity_type,
            "entity_id": linked_entity_id,
        })

    await db.commit()
    await db.refresh(incident)

    log_security_action(
        "incident_created",
        actor=created_by,
        resource_id=incident.id,
        detail={"title": title, "severity": severity, "incident_type": incident_type},
    )
    log.info("incident_created id=%s title=%r severity=%s", incident.id, title, severity)
    return incident


async def transition_status(
    db: AsyncSession,
    incident_id: str,
    new_status: str,
    actor: str,
) -> Incident:
    incident = await get_incident(db, incident_id)
    if incident is None:
        raise ValueError(f"Incident {incident_id} not found")

    old_status = incident.status
    allowed = VALID_TRANSITIONS.get(old_status, set())
    if new_status not in allowed:
        raise ValueError(
            f"Transition {old_status!r} → {new_status!r} is not allowed. "
            f"Valid next states: {sorted(allowed)}"
        )

    now = _utcnow()

    # Stamp phase timestamps
    if new_status == "triaged" and incident.triaged_at is None:
        incident.triaged_at = now
        incident.mttd_minutes = _minutes_between(incident.detected_at, now)

    elif new_status == "contained" and incident.contained_at is None:
        incident.contained_at = now
        incident.mttc_minutes = _minutes_between(incident.detected_at, now)

    elif new_status == "eradicated" and incident.eradicated_at is None:
        incident.eradicated_at = now

    elif new_status == "recovered" and incident.recovered_at is None:
        incident.recovered_at = now
        incident.mttr_minutes = _minutes_between(incident.detected_at, now)

    incident.status = new_status
    incident.nist_phase = NIST_PHASE[new_status]
    incident.sla_breach = _check_sla_breach(incident)
    incident.updated_at = now

    _add_timeline(db, incident_id, "status_change", actor, {
        "from": old_status,
        "to": new_status,
        "nist_phase": incident.nist_phase,
        "sla_breach": incident.sla_breach,
    })

    await db.commit()
    await db.refresh(incident)

    log_security_action(
        "incident_status_changed",
        actor=actor,
        resource_id=incident_id,
        detail={"from": old_status, "to": new_status},
    )
    log.info("incident_transition id=%s %s→%s actor=%s", incident_id, old_status, new_status, actor)

    # PIIL Adaptive SOAR Binding — non-blocking, never raises
    try:
        from asc_api.services.soar_incident_bridge import evaluate_soar_for_incident
        await evaluate_soar_for_incident(db, incident, new_status, actor)
    except Exception as _bridge_exc:
        log.warning("PIIL bridge call failed (non-fatal): %s", _bridge_exc)

    return incident


async def assign_incident(
    db: AsyncSession,
    incident_id: str,
    assigned_to: str,
    actor: str,
) -> Incident:
    incident = await get_incident(db, incident_id)
    if incident is None:
        raise ValueError(f"Incident {incident_id} not found")

    prev = incident.assigned_to
    incident.assigned_to = assigned_to
    incident.updated_at = _utcnow()

    _add_timeline(db, incident_id, "assignment", actor, {
        "previous_assignee": prev,
        "new_assignee": assigned_to,
    })

    await db.commit()
    await db.refresh(incident)
    log.info("incident_assigned id=%s to=%s actor=%s", incident_id, assigned_to, actor)
    return incident


async def link_entity(
    db: AsyncSession,
    incident_id: str,
    entity_type: str,
    entity_id: str,
    added_by: str,
    notes: str | None = None,
) -> IncidentLink:
    incident = await get_incident(db, incident_id)
    if incident is None:
        raise ValueError(f"Incident {incident_id} not found")

    now = _utcnow()
    link = IncidentLink(
        id=str(uuid.uuid4()),
        incident_id=incident_id,
        entity_type=entity_type,
        entity_id=entity_id,
        notes=notes,
        added_by=added_by,
        created_at=now,
    )
    db.add(link)

    incident.updated_at = now
    _add_timeline(db, incident_id, "link_added", added_by, {
        "entity_type": entity_type,
        "entity_id": entity_id,
        "notes": notes,
    })

    await db.commit()
    await db.refresh(link)
    log.info("incident_link_added id=%s entity=%s:%s", incident_id, entity_type, entity_id)
    return link


async def remove_link(
    db: AsyncSession,
    incident_id: str,
    link_id: str,
    actor: str,
) -> bool:
    result = await db.execute(
        select(IncidentLink).where(
            IncidentLink.id == link_id,
            IncidentLink.incident_id == incident_id,
        )
    )
    link = result.scalar_one_or_none()
    if link is None:
        return False

    _add_timeline(db, incident_id, "link_removed", actor, {
        "entity_type": link.entity_type,
        "entity_id": link.entity_id,
    })
    await db.delete(link)
    await db.commit()
    log.info("incident_link_removed id=%s link_id=%s actor=%s", incident_id, link_id, actor)
    return True


async def add_note(
    db: AsyncSession,
    incident_id: str,
    actor: str,
    text: str,
) -> IncidentTimeline:
    incident = await get_incident(db, incident_id)
    if incident is None:
        raise ValueError(f"Incident {incident_id} not found")
    if incident.status in ("closed", "dismissed"):
        raise ValueError(f"Cannot add notes to a {incident.status} incident")

    entry = _add_timeline(db, incident_id, "note_added", actor, {"text": text})
    incident.updated_at = _utcnow()

    await db.commit()
    await db.refresh(entry)
    return entry


async def close_incident(
    db: AsyncSession,
    incident_id: str,
    actor: str,
    *,
    lessons_learned: str | None = None,
    root_cause: str | None = None,
    executive_summary: str | None = None,
    false_positive: bool = False,
) -> Incident:
    """
    Transition to post_incident then closed, compute KPIs, seal forensic hash.
    Can be called from post_incident or recovered (auto-advances through phases).
    """
    incident = await get_incident(db, incident_id)
    if incident is None:
        raise ValueError(f"Incident {incident_id} not found")

    # Auto-advance through required intermediate states to reach closed
    path_to_close = {
        "recovered":     ["post_incident", "closed"],
        "eradicated":    ["recovered", "post_incident", "closed"],
        "post_incident": ["closed"],
    }
    if incident.status in path_to_close:
        for next_status in path_to_close[incident.status]:
            incident = await transition_status(db, incident_id, next_status, actor)
    elif incident.status == "closed":
        raise ValueError("Incident is already closed")
    elif incident.status == "dismissed":
        raise ValueError("Dismissed incidents cannot be closed; create a new incident")
    else:
        raise ValueError(
            f"Cannot close from status {incident.status!r}. "
            "Advance to at least 'recovered' first."
        )

    # Populate post-incident fields
    now = _utcnow()
    incident.lessons_learned = lessons_learned
    incident.root_cause = root_cause
    incident.executive_summary = executive_summary
    incident.false_positive = false_positive
    incident.closed_at = now

    # Final MTTR if not yet set (edge: closed from post_incident directly)
    if incident.mttr_minutes is None and incident.detected_at:
        incident.mttr_minutes = _minutes_between(incident.detected_at, now)

    incident.sla_breach = _check_sla_breach(incident)
    incident.forensic_hash = incident.compute_forensic_hash()
    incident.updated_at = now

    _add_timeline(db, incident_id, "closed", actor, {
        "mttd_minutes": incident.mttd_minutes,
        "mttc_minutes": incident.mttc_minutes,
        "mttr_minutes": incident.mttr_minutes,
        "sla_breach": incident.sla_breach,
        "false_positive": false_positive,
        "forensic_hash": incident.forensic_hash[:16] + "…",
    })

    await db.commit()
    await db.refresh(incident)

    log_security_action(
        "incident_closed",
        actor=actor,
        resource_id=incident_id,
        detail={
            "mttd": incident.mttd_minutes,
            "mttc": incident.mttc_minutes,
            "mttr": incident.mttr_minutes,
            "false_positive": false_positive,
            "forensic_hash": incident.forensic_hash,
        },
    )
    log.info(
        "incident_closed id=%s mttd=%s mttc=%s mttr=%s sla_breach=%s",
        incident_id,
        incident.mttd_minutes,
        incident.mttc_minutes,
        incident.mttr_minutes,
        incident.sla_breach,
    )
    return incident


async def dismiss_incident(
    db: AsyncSession,
    incident_id: str,
    actor: str,
    reason: str | None = None,
) -> Incident:
    incident = await get_incident(db, incident_id)
    if incident is None:
        raise ValueError(f"Incident {incident_id} not found")

    allowed = VALID_TRANSITIONS.get(incident.status, set())
    if "dismissed" not in allowed:
        raise ValueError(
            f"Cannot dismiss incident in status {incident.status!r}"
        )

    now = _utcnow()
    incident.status = "dismissed"
    incident.nist_phase = NIST_PHASE["dismissed"]
    incident.false_positive = True
    incident.closed_at = now
    incident.forensic_hash = incident.compute_forensic_hash()
    incident.updated_at = now

    _add_timeline(db, incident_id, "status_change", actor, {
        "from": incident.status,
        "to": "dismissed",
        "reason": reason,
        "forensic_hash": incident.forensic_hash[:16] + "…",
    })

    await db.commit()
    await db.refresh(incident)

    log_security_action(
        "incident_dismissed",
        actor=actor,
        resource_id=incident_id,
        detail={"reason": reason},
    )
    return incident


async def update_mitre(
    db: AsyncSession,
    incident_id: str,
    actor: str,
    mitre_tactics: list[str] | None = None,
    mitre_techniques: list[str] | None = None,
) -> Incident:
    incident = await get_incident(db, incident_id)
    if incident is None:
        raise ValueError(f"Incident {incident_id} not found")

    prev_tactics = list(incident.mitre_tactics or [])
    prev_techniques = list(incident.mitre_techniques or [])

    if mitre_tactics is not None:
        incident.mitre_tactics = mitre_tactics
    if mitre_techniques is not None:
        incident.mitre_techniques = mitre_techniques

    incident.updated_at = _utcnow()
    _add_timeline(db, incident_id, "note_added", actor, {
        "mitre_tactics_prev": prev_tactics,
        "mitre_techniques_prev": prev_techniques,
        "mitre_tactics_new": incident.mitre_tactics,
        "mitre_techniques_new": incident.mitre_techniques,
    })

    await db.commit()
    await db.refresh(incident)
    return incident


# ---------------------------------------------------------------------------
# Correlation integration
# ---------------------------------------------------------------------------


async def auto_create_from_cluster(db: AsyncSession, cluster: Any) -> Incident | None:
    """
    Called by the correlation sweep when a CorrelationCluster is promoted to
    campaign status (is_campaign=True).  Creates one Incident per campaign
    cluster, deduplicating on cluster_id so re-runs are idempotent.

    Security note: READ-ONLY on correlation tables — only incident_* tables
    are written.  This function is PASSIVE; it does not modify the cluster.
    """
    # Dedup: check if an incident already links to this cluster
    existing = await db.execute(
        select(IncidentLink).where(
            IncidentLink.entity_type == "cluster",
            IncidentLink.entity_id == cluster.id,
        )
    )
    if existing.scalar_one_or_none() is not None:
        log.debug("auto_create_from_cluster: cluster %s already linked, skipping", cluster.id)
        return None

    title = f"[Campaign] {cluster.cluster_type.replace('_', ' ').title()}: {cluster.cluster_key}"
    incident = await create_incident(
        db,
        title=title,
        incident_type="apt",
        severity=cluster.severity or "high",
        created_by="system:correlation_engine",
        description=(
            f"Automatically promoted from correlation cluster {cluster.id}. "
            f"Signal count: {cluster.signal_count}. "
            f"Cluster type: {cluster.cluster_type}. "
            f"Pivot key: {cluster.cluster_key}."
        ),
        risk_score=float(_SEV_RANK.get(cluster.severity or "high", 3)) / 4.0,
        linked_entity_type="cluster",
        linked_entity_id=cluster.id,
        linked_entity_notes=f"Auto-promoted campaign cluster — {cluster.signal_count} signals",
    )
    log.info(
        "auto_create_from_cluster: created incident %s for campaign cluster %s",
        incident.id,
        cluster.id,
    )
    return incident
