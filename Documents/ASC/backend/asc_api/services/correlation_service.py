"""
Correlation Engine Service — P27-B

Cross-domain signal correlation that detects threat clusters and campaigns by
pivoting on shared observables (host, identity, IP, domain, TTP) across every
domain in the ASC platform:

  Events · Alerts · HuntFindings · IdentityActions · NeutralizationActions
  ThreatIntelIndicators · AgentCommands

Architecture
------------
run_correlation_sweep()
  └─ for each enabled CorrelationRule:
       gather signals within time_window_minutes
       group by pivot_value
       for pivot groups with count >= min_signals:
         upsert CorrelationCluster + CorrelationSignal rows
         recompute severity, is_campaign, forensic_hash

A cluster becomes a *campaign* when its signals span 3+ distinct signal_type
domains, indicating coordinated multi-stage attacker activity.

Security posture: ALL queries are READ-ONLY (SELECT).  No domain record is
modified by correlation.  Only correlation_* tables are written.
"""
from __future__ import annotations

import json
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select, func, or_
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.core.audit import log_security_action
from asc_api.core.logging import get_logger
from asc_api.models.alert import Alert
from asc_api.models.correlation import (
    CorrelationCluster,
    CorrelationRule,
    CorrelationSignal,
    SIGNAL_TYPES,
)
from asc_api.models.event import Event
from asc_api.models.hunt import HuntFinding
from asc_api.models.identity_action import IdentityAction
from asc_api.models.neutralization import NeutralizationAction
from asc_api.models.threat_intel import ThreatIntelIndicator

log = get_logger(__name__)

# Severity rank used for "max severity wins" logic
_SEV = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_SEV_REV = {v: k for k, v in _SEV.items()}


def _max_severity(severities: list[str]) -> str:
    if not severities:
        return "low"
    ranks = [_SEV.get(s, 0) for s in severities]
    return _SEV_REV.get(max(ranks), "low")


def _meets_threshold(severity: str, threshold: str) -> bool:
    return _SEV.get(severity, 0) >= _SEV.get(threshold, 0)


# ---------------------------------------------------------------------------
# Signal gathering — one function per pivot type
# ---------------------------------------------------------------------------

async def _gather_host_signals(db: AsyncSession, window_start: datetime) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []

    # Events with non-null host
    r = await db.execute(
        select(Event.id, Event.host, Event.severity, Event.timestamp)
        .where(Event.host.isnot(None))
        .where(Event.timestamp >= window_start)
    )
    for row in r.all():
        signals.append({
            "signal_type": "event",
            "signal_id": row.id,
            "pivot_value": row.host.lower(),
            "severity": row.severity or "low",
            "timestamp": row.timestamp,
            "meta": {"host": row.host},
        })

    # Alerts — affected_hosts is a JSON list
    r = await db.execute(
        select(Alert.id, Alert.affected_hosts, Alert.severity, Alert.detected_at)
        .where(Alert.affected_hosts.isnot(None))
        .where(Alert.detected_at >= window_start)
        .where(Alert.false_positive.is_(False))
    )
    for row in r.all():
        hosts = row.affected_hosts or []
        if isinstance(hosts, str):
            try:
                hosts = json.loads(hosts)
            except Exception:
                hosts = [hosts]
        for h in hosts:
            if h:
                signals.append({
                    "signal_type": "alert",
                    "signal_id": row.id,
                    "pivot_value": str(h).lower(),
                    "severity": row.severity or "low",
                    "timestamp": row.detected_at,
                    "meta": {"host": h},
                })

    # HuntFindings with affected_host
    r = await db.execute(
        select(HuntFinding.id, HuntFinding.affected_host, HuntFinding.severity, HuntFinding.created_at)
        .where(HuntFinding.affected_host.isnot(None))
        .where(HuntFinding.created_at >= window_start)
        .where(HuntFinding.is_false_positive.is_(False))
    )
    for row in r.all():
        signals.append({
            "signal_type": "finding",
            "signal_id": row.id,
            "pivot_value": row.affected_host.lower(),
            "severity": row.severity or "low",
            "timestamp": row.created_at,
            "meta": {"host": row.affected_host},
        })

    # PANL — isolate_endpoint actions
    r = await db.execute(
        select(NeutralizationAction.id, NeutralizationAction.target,
               NeutralizationAction.severity, NeutralizationAction.executed_at)
        .where(NeutralizationAction.action_type == "isolate_endpoint")
        .where(NeutralizationAction.executed_at >= window_start)
        .where(NeutralizationAction.executed_at.isnot(None))
    )
    for row in r.all():
        signals.append({
            "signal_type": "panl_action",
            "signal_id": row.id,
            "pivot_value": row.target.lower(),
            "severity": row.severity or "medium",
            "timestamp": row.executed_at,
            "meta": {"host": row.target, "action_type": "isolate_endpoint"},
        })

    return signals


async def _gather_identity_signals(db: AsyncSession, window_start: datetime) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []

    # IdentityAction — every IAM enforcement action has a username
    r = await db.execute(
        select(IdentityAction.id, IdentityAction.username, IdentityAction.domain,
               IdentityAction.action_type, IdentityAction.executed_at)
        .where(IdentityAction.executed_at >= window_start)
    )
    for row in r.all():
        pivot = f"{row.username}@{row.domain}".lower()
        signals.append({
            "signal_type": "identity_action",
            "signal_id": row.id,
            "pivot_value": pivot,
            "severity": "high",  # identity actions are always high-interest
            "timestamp": row.executed_at,
            "meta": {"username": row.username, "domain": row.domain, "action_type": row.action_type},
        })

    # HuntFindings with affected_user
    r = await db.execute(
        select(HuntFinding.id, HuntFinding.affected_user, HuntFinding.severity, HuntFinding.created_at)
        .where(HuntFinding.affected_user.isnot(None))
        .where(HuntFinding.created_at >= window_start)
        .where(HuntFinding.is_false_positive.is_(False))
    )
    for row in r.all():
        signals.append({
            "signal_type": "finding",
            "signal_id": row.id,
            "pivot_value": row.affected_user.lower(),
            "severity": row.severity or "medium",
            "timestamp": row.created_at,
            "meta": {"user": row.affected_user},
        })

    return signals


async def _gather_ip_signals(db: AsyncSession, window_start: datetime) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []

    # Events — extract src_ip / dst_ip from normalized JSON
    r = await db.execute(
        select(Event.id, Event.normalized, Event.severity, Event.timestamp)
        .where(Event.normalized.isnot(None))
        .where(Event.timestamp >= window_start)
    )
    for row in r.all():
        norm = row.normalized or {}
        if isinstance(norm, str):
            try:
                norm = json.loads(norm)
            except Exception:
                norm = {}
        for ip_key in ("src_ip", "dst_ip", "source_ip", "destination_ip", "ip"):
            ip_val = norm.get(ip_key)
            if ip_val and isinstance(ip_val, str):
                signals.append({
                    "signal_type": "event",
                    "signal_id": row.id,
                    "pivot_value": ip_val,
                    "severity": row.severity or "low",
                    "timestamp": row.timestamp,
                    "meta": {"ip_field": ip_key, "ip": ip_val},
                })

    # ThreatIntelIndicator type=ip
    r = await db.execute(
        select(ThreatIntelIndicator.id, ThreatIntelIndicator.value,
               ThreatIntelIndicator.severity, ThreatIntelIndicator.last_seen)
        .where(ThreatIntelIndicator.indicator_type == "ip")
        .where(ThreatIntelIndicator.active.is_(True))
        .where(ThreatIntelIndicator.last_seen >= window_start)
    )
    for row in r.all():
        signals.append({
            "signal_type": "ti_indicator",
            "signal_id": row.id,
            "pivot_value": row.value,
            "severity": row.severity or "medium",
            "timestamp": row.last_seen,
            "meta": {"indicator_type": "ip", "value": row.value},
        })

    # PANL — block_ip actions
    r = await db.execute(
        select(NeutralizationAction.id, NeutralizationAction.target,
               NeutralizationAction.severity, NeutralizationAction.executed_at)
        .where(NeutralizationAction.action_type == "block_ip")
        .where(NeutralizationAction.executed_at >= window_start)
        .where(NeutralizationAction.executed_at.isnot(None))
    )
    for row in r.all():
        signals.append({
            "signal_type": "panl_action",
            "signal_id": row.id,
            "pivot_value": row.target,
            "severity": row.severity or "high",
            "timestamp": row.executed_at,
            "meta": {"ip": row.target, "action_type": "block_ip"},
        })

    return signals


async def _gather_domain_signals(db: AsyncSession, window_start: datetime) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []

    # ThreatIntelIndicator type=domain|url
    r = await db.execute(
        select(ThreatIntelIndicator.id, ThreatIntelIndicator.value,
               ThreatIntelIndicator.indicator_type, ThreatIntelIndicator.severity,
               ThreatIntelIndicator.last_seen)
        .where(ThreatIntelIndicator.indicator_type.in_(["domain", "url"]))
        .where(ThreatIntelIndicator.active.is_(True))
        .where(ThreatIntelIndicator.last_seen >= window_start)
    )
    for row in r.all():
        signals.append({
            "signal_type": "ti_indicator",
            "signal_id": row.id,
            "pivot_value": row.value.lower(),
            "severity": row.severity or "medium",
            "timestamp": row.last_seen,
            "meta": {"indicator_type": row.indicator_type, "value": row.value},
        })

    # PANL — block_domain
    r = await db.execute(
        select(NeutralizationAction.id, NeutralizationAction.target,
               NeutralizationAction.severity, NeutralizationAction.executed_at)
        .where(NeutralizationAction.action_type == "block_domain")
        .where(NeutralizationAction.executed_at >= window_start)
        .where(NeutralizationAction.executed_at.isnot(None))
    )
    for row in r.all():
        signals.append({
            "signal_type": "panl_action",
            "signal_id": row.id,
            "pivot_value": row.target.lower(),
            "severity": row.severity or "high",
            "timestamp": row.executed_at,
            "meta": {"domain": row.target, "action_type": "block_domain"},
        })

    # HuntFindings with indicator_type=domain
    r = await db.execute(
        select(HuntFinding.id, HuntFinding.indicator_value, HuntFinding.severity,
               HuntFinding.created_at)
        .where(HuntFinding.indicator_type == "domain")
        .where(HuntFinding.indicator_value.isnot(None))
        .where(HuntFinding.created_at >= window_start)
        .where(HuntFinding.is_false_positive.is_(False))
    )
    for row in r.all():
        signals.append({
            "signal_type": "finding",
            "signal_id": row.id,
            "pivot_value": row.indicator_value.lower(),
            "severity": row.severity or "medium",
            "timestamp": row.created_at,
            "meta": {"domain": row.indicator_value},
        })

    return signals


async def _gather_ttp_signals(db: AsyncSession, window_start: datetime) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []

    # Events — tags JSON list (filter for T#### MITRE patterns)
    r = await db.execute(
        select(Event.id, Event.tags, Event.severity, Event.timestamp)
        .where(Event.tags.isnot(None))
        .where(Event.timestamp >= window_start)
    )
    for row in r.all():
        tags = row.tags or []
        if isinstance(tags, str):
            try:
                tags = json.loads(tags)
            except Exception:
                tags = []
        for tag in tags:
            if isinstance(tag, str) and tag.upper().startswith("T"):
                signals.append({
                    "signal_type": "event",
                    "signal_id": row.id,
                    "pivot_value": tag.upper(),
                    "severity": row.severity or "low",
                    "timestamp": row.timestamp,
                    "meta": {"ttp": tag},
                })

    # Alerts — ttps JSON list
    r = await db.execute(
        select(Alert.id, Alert.ttps, Alert.severity, Alert.detected_at)
        .where(Alert.ttps.isnot(None))
        .where(Alert.detected_at >= window_start)
        .where(Alert.false_positive.is_(False))
    )
    for row in r.all():
        ttps = row.ttps or []
        if isinstance(ttps, str):
            try:
                ttps = json.loads(ttps)
            except Exception:
                ttps = []
        for ttp in ttps:
            if ttp:
                signals.append({
                    "signal_type": "alert",
                    "signal_id": row.id,
                    "pivot_value": str(ttp).upper(),
                    "severity": row.severity or "medium",
                    "timestamp": row.detected_at,
                    "meta": {"ttp": ttp},
                })

    return signals


_GATHER_FN = {
    "host_pivot": _gather_host_signals,
    "identity_pivot": _gather_identity_signals,
    "ip_pivot": _gather_ip_signals,
    "domain_pivot": _gather_domain_signals,
    "ttp_pivot": _gather_ttp_signals,
}


# ---------------------------------------------------------------------------
# Cluster upsert
# ---------------------------------------------------------------------------

async def _upsert_cluster(
    db: AsyncSession,
    rule: CorrelationRule,
    pivot_value: str,
    new_signals: list[dict[str, Any]],
) -> CorrelationCluster:
    now = datetime.now(timezone.utc)

    # Find or create the active cluster for this rule + pivot_value
    r = await db.execute(
        select(CorrelationCluster)
        .where(CorrelationCluster.rule_id == rule.id)
        .where(CorrelationCluster.cluster_key == pivot_value)
        .where(CorrelationCluster.status == "active")
    )
    cluster: CorrelationCluster | None = r.scalar_one_or_none()

    if cluster is None:
        cluster = CorrelationCluster(
            id=str(uuid.uuid4()),
            rule_id=rule.id,
            cluster_key=pivot_value,
            cluster_type=rule.pivot_type,
            first_seen=now,
            last_seen=now,
            status="active",
        )
        db.add(cluster)
        await db.flush()  # populate cluster.id

    # Determine which signals are already recorded for this cluster
    r = await db.execute(
        select(CorrelationSignal.signal_type, CorrelationSignal.signal_id)
        .where(CorrelationSignal.cluster_id == cluster.id)
    )
    existing_keys = {(row.signal_type, row.signal_id) for row in r.all()}

    added = 0
    for sig in new_signals:
        key = (sig["signal_type"], sig["signal_id"])
        if key in existing_keys:
            continue
        cs = CorrelationSignal(
            id=str(uuid.uuid4()),
            cluster_id=cluster.id,
            signal_type=sig["signal_type"],
            signal_id=sig["signal_id"],
            pivot_value=sig["pivot_value"],
            severity=sig["severity"],
            timestamp=sig["timestamp"],
            meta=sig.get("meta", {}),
        )
        db.add(cs)
        existing_keys.add(key)
        added += 1

    if added > 0:
        await db.flush()

    # Re-aggregate from all signals in this cluster
    r = await db.execute(
        select(CorrelationSignal.severity, CorrelationSignal.signal_type,
               CorrelationSignal.timestamp)
        .where(CorrelationSignal.cluster_id == cluster.id)
    )
    all_sigs = r.all()

    severities = [s.severity for s in all_sigs]
    signal_types = {s.signal_type for s in all_sigs}
    timestamps = [s.timestamp for s in all_sigs if s.timestamp]

    cluster.signal_count = len(all_sigs)
    cluster.severity = _max_severity(severities)
    cluster.distinct_signal_domains = len(signal_types)
    cluster.is_campaign = len(signal_types) >= 3
    cluster.last_seen = max(timestamps) if timestamps else now
    cluster.updated_at = now
    cluster.confidence_score = min(1.0, cluster.signal_count / max(rule.min_signals * 3, 1))

    if cluster.is_campaign and not cluster.campaign_name:
        cluster.campaign_name = f"Campaign-{cluster.cluster_key[:20]}-{cluster.id[:8]}"

    cluster.forensic_hash = cluster.compute_forensic_hash()

    return cluster


# ---------------------------------------------------------------------------
# Main sweep
# ---------------------------------------------------------------------------

async def run_correlation_sweep(db: AsyncSession) -> dict[str, Any]:
    """
    Iterate all enabled rules, gather cross-domain signals, and upsert clusters.
    Returns a summary dict suitable for task logging.
    """
    now = datetime.now(timezone.utc)

    r = await db.execute(
        select(CorrelationRule).where(CorrelationRule.enabled.is_(True))
    )
    rules: list[CorrelationRule] = list(r.scalars().all())

    stats = {
        "rules_evaluated": len(rules),
        "clusters_created": 0,
        "clusters_updated": 0,
        "signals_added": 0,
        "campaigns_detected": 0,
    }

    for rule in rules:
        window_start = now - timedelta(minutes=rule.time_window_minutes)
        gather_fn = _GATHER_FN.get(rule.pivot_type)
        if gather_fn is None:
            log.warning("correlation_sweep: unknown pivot_type %s for rule %s", rule.pivot_type, rule.id)
            continue

        raw_signals = await gather_fn(db, window_start)

        # Filter by severity threshold
        filtered = [
            s for s in raw_signals
            if _meets_threshold(s["severity"], rule.severity_threshold)
        ]

        # Group by pivot_value
        groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for sig in filtered:
            groups[sig["pivot_value"]].append(sig)

        for pivot_value, group_signals in groups.items():
            # De-duplicate by (signal_type, signal_id) within this group
            seen: set[tuple[str, str]] = set()
            deduped = []
            for s in group_signals:
                k = (s["signal_type"], s["signal_id"])
                if k not in seen:
                    seen.add(k)
                    deduped.append(s)

            if len(deduped) < rule.min_signals:
                continue

            was_existing = await _cluster_exists(db, rule.id, pivot_value)
            cluster = await _upsert_cluster(db, rule, pivot_value, deduped)

            if was_existing:
                stats["clusters_updated"] += 1
            else:
                stats["clusters_created"] += 1
            if cluster.is_campaign:
                stats["campaigns_detected"] += 1
            stats["signals_added"] += len(deduped)

    await db.commit()

    log.info("correlation_sweep done: %s", stats)
    await log_security_action(
        db, "SYSTEM", "correlation_sweep_completed",
        detail=json.dumps(stats),
    )

    return stats


async def _cluster_exists(db: AsyncSession, rule_id: str, pivot_value: str) -> bool:
    r = await db.execute(
        select(func.count(CorrelationCluster.id))
        .where(CorrelationCluster.rule_id == rule_id)
        .where(CorrelationCluster.cluster_key == pivot_value)
        .where(CorrelationCluster.status == "active")
    )
    return (r.scalar() or 0) > 0


# ---------------------------------------------------------------------------
# Query API helpers
# ---------------------------------------------------------------------------

async def list_rules(db: AsyncSession) -> list[CorrelationRule]:
    r = await db.execute(select(CorrelationRule).order_by(CorrelationRule.created_at))
    return list(r.scalars().all())


async def get_rule(db: AsyncSession, rule_id: str) -> CorrelationRule | None:
    r = await db.execute(select(CorrelationRule).where(CorrelationRule.id == rule_id))
    return r.scalar_one_or_none()


async def create_rule(
    db: AsyncSession,
    name: str,
    pivot_type: str,
    min_signals: int = 2,
    time_window_minutes: int = 60,
    severity_threshold: str = "low",
    description: str | None = None,
) -> CorrelationRule:
    rule = CorrelationRule(
        id=str(uuid.uuid4()),
        name=name,
        description=description,
        pivot_type=pivot_type,
        min_signals=min_signals,
        time_window_minutes=time_window_minutes,
        severity_threshold=severity_threshold,
        enabled=True,
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return rule


async def update_rule(
    db: AsyncSession,
    rule_id: str,
    **kwargs: Any,
) -> CorrelationRule | None:
    rule = await get_rule(db, rule_id)
    if rule is None:
        return None
    allowed = {"name", "description", "pivot_type", "min_signals", "time_window_minutes",
                "severity_threshold", "enabled"}
    for k, v in kwargs.items():
        if k in allowed:
            setattr(rule, k, v)
    rule.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(rule)
    return rule


async def delete_rule(db: AsyncSession, rule_id: str) -> bool:
    rule = await get_rule(db, rule_id)
    if rule is None:
        return False
    await db.delete(rule)
    await db.commit()
    return True


async def list_clusters(
    db: AsyncSession,
    status: str | None = None,
    cluster_type: str | None = None,
    is_campaign: bool | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[CorrelationCluster]:
    q = select(CorrelationCluster).order_by(CorrelationCluster.last_seen.desc())
    if status:
        q = q.where(CorrelationCluster.status == status)
    if cluster_type:
        q = q.where(CorrelationCluster.cluster_type == cluster_type)
    if is_campaign is not None:
        q = q.where(CorrelationCluster.is_campaign.is_(is_campaign))
    q = q.limit(limit).offset(offset)
    r = await db.execute(q)
    return list(r.scalars().all())


async def get_cluster(db: AsyncSession, cluster_id: str) -> CorrelationCluster | None:
    r = await db.execute(
        select(CorrelationCluster).where(CorrelationCluster.id == cluster_id)
    )
    return r.scalar_one_or_none()


async def update_cluster_status(
    db: AsyncSession,
    cluster_id: str,
    status: str,
    analyst_notes: str | None = None,
    assigned_to: str | None = None,
) -> CorrelationCluster | None:
    cluster = await get_cluster(db, cluster_id)
    if cluster is None:
        return None
    cluster.status = status
    cluster.updated_at = datetime.now(timezone.utc)
    if analyst_notes is not None:
        cluster.analyst_notes = analyst_notes
    if assigned_to is not None:
        cluster.assigned_to = assigned_to
    await db.commit()
    await db.refresh(cluster)
    return cluster


async def get_cluster_signals(db: AsyncSession, cluster_id: str) -> list[CorrelationSignal]:
    r = await db.execute(
        select(CorrelationSignal)
        .where(CorrelationSignal.cluster_id == cluster_id)
        .order_by(CorrelationSignal.timestamp)
    )
    return list(r.scalars().all())


async def get_cluster_graph(db: AsyncSession, cluster_id: str) -> dict[str, Any] | None:
    """
    Build a graph representation of a cluster for the frontend visualizer.

    Nodes:
      - One central cluster node
      - One node per signal (labeled by signal_type + pivot_value)

    Edges:
      - Cluster → signal (pivot_type + pivot_value as edge label)
    """
    cluster = await get_cluster(db, cluster_id)
    if cluster is None:
        return None

    signals = await get_cluster_signals(db, cluster_id)

    # Rule info
    rule = await get_rule(db, cluster.rule_id)
    pivot_type = rule.pivot_type if rule else cluster.cluster_type

    nodes: list[dict[str, Any]] = [
        {
            "id": cluster.id,
            "type": "cluster",
            "label": cluster.cluster_key,
            "severity": cluster.severity,
            "is_campaign": cluster.is_campaign,
            "status": cluster.status,
            "ts": cluster.last_seen.isoformat() if cluster.last_seen else None,
        }
    ]
    edges: list[dict[str, Any]] = []

    seen_signal_nodes: set[str] = set()
    for sig in signals:
        node_id = f"{sig.signal_type}:{sig.signal_id}"
        if node_id not in seen_signal_nodes:
            nodes.append({
                "id": node_id,
                "type": sig.signal_type,
                "label": f"{sig.signal_type} / {sig.pivot_value}",
                "severity": sig.severity,
                "ts": sig.timestamp.isoformat() if sig.timestamp else None,
                "meta": sig.meta,
            })
            seen_signal_nodes.add(node_id)

        edges.append({
            "source": cluster.id,
            "target": node_id,
            "pivot": sig.pivot_value,
            "pivot_type": pivot_type,
        })

    return {
        "cluster_id": cluster.id,
        "pivot_type": pivot_type,
        "pivot_value": cluster.cluster_key,
        "is_campaign": cluster.is_campaign,
        "campaign_name": cluster.campaign_name,
        "nodes": nodes,
        "edges": edges,
    }


async def get_correlation_summary(db: AsyncSession, tenant_id: str | None = None) -> dict[str, Any]:
    """KPI summary for the /correlation page header strip."""

    def _c(q):
        return q.where(CorrelationCluster.tenant_id == tenant_id) if tenant_id else q

    def _r(q):
        return q.where(CorrelationRule.tenant_id == tenant_id) if tenant_id else q

    def _s(q):
        return q.where(CorrelationSignal.tenant_id == tenant_id) if tenant_id else q

    total_r = await db.execute(_c(select(func.count(CorrelationCluster.id))))
    active_r = await db.execute(
        _c(select(func.count(CorrelationCluster.id)).where(CorrelationCluster.status == "active"))
    )
    campaign_r = await db.execute(
        _c(select(func.count(CorrelationCluster.id)).where(CorrelationCluster.is_campaign.is_(True)))
    )
    critical_r = await db.execute(
        _c(
            select(func.count(CorrelationCluster.id))
            .where(CorrelationCluster.status == "active")
            .where(CorrelationCluster.severity == "critical")
        )
    )
    signal_r = await db.execute(_s(select(func.count(CorrelationSignal.id))))
    rules_r = await db.execute(
        _r(select(func.count(CorrelationRule.id)).where(CorrelationRule.enabled.is_(True)))
    )

    return {
        "total_clusters": total_r.scalar() or 0,
        "active_clusters": active_r.scalar() or 0,
        "campaigns_detected": campaign_r.scalar() or 0,
        "critical_clusters": critical_r.scalar() or 0,
        "total_signals": signal_r.scalar() or 0,
        "active_rules": rules_r.scalar() or 0,
    }
