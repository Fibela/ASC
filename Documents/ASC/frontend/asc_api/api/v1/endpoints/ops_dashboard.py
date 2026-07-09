"""
Operational Dashboard API — P20 / P24+

Real-time SOC operational metrics: fleet health, command pipeline stats,
in-flight commands, neutralization action summary, and cross-domain intelligence.

Endpoints
---------
GET /ops/fleet/summary         — Fleet health by status + threat level (analyst+)
GET /ops/commands/metrics      — Command pipeline: counts by status + latency (analyst+)
GET /ops/commands/inflight     — In-flight commands (pending/executing), last 100 (analyst+)
GET /ops/neutralizations/metrics — Action counts by status/type + recent escalations (analyst+)
GET /ops/cross-domain          — Unified TI + Hunting + PANL + Fleet + PCDI metrics (analyst+)

All endpoints require a valid JWT (analyst or admin).
Data is computed on-demand from the live DB (no caching layer needed at SOC scale).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select, case, cast, Float
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.api.deps import get_analyst_or_admin
from asc_api.core.rate_limit import limiter
from asc_api.core.config import get_settings
from asc_api.db.session import get_db
from asc_api.models.agent import Agent, AgentCommand
from asc_api.models.neutralization import NeutralizationAction
from asc_api.models.user import User

router = APIRouter(prefix="/ops", tags=["Operational Dashboard"])
_s = get_settings()


# ── Fleet summary ──────────────────────────────────────────────────────────────

@router.get("/fleet/summary", summary="Resumen de estado de la flota SPECTER")
@limiter.limit(_s.RATE_LIMIT_OPS)
async def fleet_summary(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
):
    """
    Returns:
    - Total agent count + breakdown by status and threat_level
    - Agents seen in last 5 min (online), last 1 h, offline
    - Count of agents with elevated/critical threat
    """
    now = datetime.now(timezone.utc)
    tid = current_user.tenant_id

    rows = (await db.execute(
        select(Agent).where(Agent.tenant_id == tid)
    )).scalars().all()

    total = len(rows)
    by_status: dict[str, int] = {}
    by_threat: dict[str, int] = {}
    online_5m = 0
    online_1h = 0
    offline = 0

    for a in rows:
        by_status[a.status] = by_status.get(a.status, 0) + 1
        by_threat[a.threat_level] = by_threat.get(a.threat_level, 0) + 1

        if a.last_seen:
            delta_s = (now - a.last_seen).total_seconds()
            if delta_s <= 300:
                online_5m += 1
            elif delta_s <= 3600:
                online_1h += 1
            else:
                offline += 1
        else:
            offline += 1

    return {
        "total_agents": total,
        "by_status": by_status,
        "by_threat_level": by_threat,
        "connectivity": {
            "online_5m":  online_5m,
            "online_1h":  online_1h,
            "offline":    offline,
        },
        "at_risk": (by_threat.get("elevated", 0) + by_threat.get("critical", 0)),
        "ts": now.isoformat(),
    }


# ── Command metrics ────────────────────────────────────────────────────────────

@router.get("/commands/metrics", summary="Métricas del pipeline de comandos SPECTER")
@limiter.limit(_s.RATE_LIMIT_OPS)
async def commands_metrics(
    request: Request,
    hours: int = Query(default=24, ge=1, le=168, description="Ventana de tiempo en horas"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
):
    """
    Returns command counts by status and latency stats (avg, min, max, p50 approx)
    for commands issued in the last `hours` hours.
    Latency = completed_at - issued_at in milliseconds.
    """
    from datetime import timedelta

    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    tid = current_user.tenant_id

    result = await db.execute(
        select(AgentCommand).where(
            AgentCommand.tenant_id == tid,
            AgentCommand.issued_at >= since,
        )
    )
    commands = result.scalars().all()

    by_status: dict[str, int] = {}
    by_type: dict[str, int] = {}
    latencies_ms: list[float] = []

    for cmd in commands:
        by_status[cmd.status] = by_status.get(cmd.status, 0) + 1
        by_type[cmd.command_type] = by_type.get(cmd.command_type, 0) + 1

        if cmd.completed_at and cmd.issued_at:
            ms = (cmd.completed_at - cmd.issued_at).total_seconds() * 1000
            if ms >= 0:
                latencies_ms.append(ms)

    latency_stats: dict[str, Any] = {"samples": len(latencies_ms)}
    if latencies_ms:
        sorted_lat = sorted(latencies_ms)
        n = len(sorted_lat)
        latency_stats.update({
            "min_ms":  round(sorted_lat[0], 1),
            "max_ms":  round(sorted_lat[-1], 1),
            "avg_ms":  round(sum(sorted_lat) / n, 1),
            "p50_ms":  round(sorted_lat[int(n * 0.50)], 1),
            "p95_ms":  round(sorted_lat[min(int(n * 0.95), n - 1)], 1),
        })

    total = len(commands)
    success_rate = None
    completed = by_status.get("completed", 0)
    failed = by_status.get("failed", 0)
    terminal = completed + failed
    if terminal > 0:
        success_rate = round(completed / terminal * 100, 1)

    return {
        "window_hours":  hours,
        "total_commands": total,
        "by_status":     by_status,
        "by_type":       by_type,
        "latency":       latency_stats,
        "success_rate_pct": success_rate,
        "ts": datetime.now(timezone.utc).isoformat(),
    }


# ── In-flight commands ─────────────────────────────────────────────────────────

@router.get("/commands/inflight", summary="Comandos en vuelo (pendientes/ejecutando)")
@limiter.limit(_s.RATE_LIMIT_OPS)
async def commands_inflight(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
):
    """
    Returns commands currently in flight (status = pending, delivered, executing).
    Sorted by issued_at descending (most recent first).
    Each entry includes agent_id, command_type, status, issued_by, age_seconds.
    """
    now = datetime.now(timezone.utc)
    tid = current_user.tenant_id

    result = await db.execute(
        select(AgentCommand)
        .where(
            AgentCommand.tenant_id == tid,
            AgentCommand.status.in_(["pending", "delivered", "executing"]),
        )
        .order_by(AgentCommand.issued_at.desc())
        .limit(limit)
    )
    commands = result.scalars().all()

    items = []
    for cmd in commands:
        age_s = None
        if cmd.issued_at:
            age_s = round((now - cmd.issued_at).total_seconds(), 1)
        items.append({
            "id":           cmd.id,
            "agent_id":     cmd.agent_id,
            "command_type": cmd.command_type,
            "status":       cmd.status,
            "issued_by":    cmd.issued_by,
            "issued_at":    cmd.issued_at.isoformat() if cmd.issued_at else None,
            "age_seconds":  age_s,
            "params":       cmd.params,
        })

    return {
        "total_inflight": len(items),
        "commands":       items,
        "ts":             now.isoformat(),
    }


# ── Neutralization metrics ─────────────────────────────────────────────────────

@router.get("/neutralizations/metrics", summary="Métricas de acciones de neutralización")
@limiter.limit(_s.RATE_LIMIT_OPS)
async def neutralizations_metrics(
    request: Request,
    hours: int = Query(default=24, ge=1, le=168),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
):
    """
    Returns neutralization action counts by status and type for the given window.
    Also returns recent escalations (actions that expired without approval).
    """
    from datetime import timedelta

    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    tid = current_user.tenant_id

    result = await db.execute(
        select(NeutralizationAction).where(
            NeutralizationAction.tenant_id == tid,
            NeutralizationAction.created_at >= since,
        )
    )
    actions = result.scalars().all()

    by_status: dict[str, int] = {}
    by_type: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    recent_escalations: list[dict] = []

    for a in actions:
        by_status[a.status] = by_status.get(a.status, 0) + 1
        by_type[a.action_type] = by_type.get(a.action_type, 0) + 1
        by_severity[a.severity] = by_severity.get(a.severity, 0) + 1

        if a.status == "escalated":
            recent_escalations.append({
                "id":           a.id,
                "action_type":  a.action_type,
                "severity":     a.severity,
                "target":       a.target,
                "initiated_by": a.initiated_by,
                "escalated_at": a.escalated_at.isoformat() if a.escalated_at else None,
            })

    total = len(actions)
    approval_rate = None
    approved = by_status.get("completed", 0) + by_status.get("executing", 0)
    rejected = by_status.get("rejected", 0)
    decided = approved + rejected
    if decided > 0:
        approval_rate = round(approved / decided * 100, 1)

    return {
        "window_hours":       hours,
        "total_actions":      total,
        "by_status":          by_status,
        "by_type":            by_type,
        "by_severity":        by_severity,
        "approval_rate_pct":  approval_rate,
        "escalations":        recent_escalations[-10:],  # last 10
        "escalation_count":   len(recent_escalations),
        "ts": datetime.now(timezone.utc).isoformat(),
    }


# ── Cross-Domain Intelligence Dashboard ───────────────────────────────────────

@router.get("/cross-domain", summary="Panel unificado TI + Hunting + PANL + Fleet + PCDI")
@limiter.limit("20/minute")
async def cross_domain_dashboard(
    request: Request,
    hours: int = Query(default=24, ge=1, le=168, description="Ventana de tiempo en horas"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
):
    """
    Unified cross-domain metrics aggregating all ASC intelligence pillars:

    - **Fleet**: active agents, at-risk agents, recent command success rate
    - **Threat Hunting**: active/completed hunts, critical priority, high-severity findings
    - **PANL**: neutralization actions in window, pending approvals, approval rate
    - **Threat Intelligence**: total indicators, by severity, recent additions
    - **PCDI**: signed reports, high-score findings (≥80), auto-escalated hunts

    Designed for the SOC manager's single-pane-of-glass view.
    """
    from datetime import timedelta
    from asc_api.models.hunt import Hunt, HuntFinding
    from asc_api.models.threat_intel import ThreatIntelIndicator
    from asc_api.models.pcdi import PCDISignedReport
    from asc_api.models.soar import PlaybookTrigger, ScheduledReport
    from asc_api.models.identity_action import IdentityAction
    from asc_api.models.correlation import CorrelationCluster, CorrelationRule

    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=hours)
    tid = current_user.tenant_id

    # ── Fleet ──────────────────────────────────────────────────────────────────
    agents = (await db.execute(
        select(Agent).where(Agent.tenant_id == tid)
    )).scalars().all()
    fleet_total = len(agents)
    fleet_active = sum(1 for a in agents if a.status == "active")
    fleet_at_risk = sum(1 for a in agents if a.threat_level in ("elevated", "critical"))
    fleet_online_5m = 0
    for a in agents:
        if a.last_seen and (now - a.last_seen).total_seconds() <= 300:
            fleet_online_5m += 1

    cmd_result = await db.execute(
        select(AgentCommand).where(
            AgentCommand.tenant_id == tid,
            AgentCommand.issued_at >= since,
        )
    )
    recent_cmds = list(cmd_result.scalars().all())
    cmd_completed = sum(1 for c in recent_cmds if c.status == "completed")
    cmd_failed = sum(1 for c in recent_cmds if c.status == "failed")
    cmd_terminal = cmd_completed + cmd_failed
    cmd_success_rate = round(cmd_completed / cmd_terminal * 100, 1) if cmd_terminal else None

    # ── Threat Hunting ────────────────────────────────────────────────────────
    hunts = (await db.execute(
        select(Hunt).where(Hunt.tenant_id == tid)
    )).scalars().all()
    active_hunts = [h for h in hunts if h.status == "active"]
    critical_hunts = [h for h in active_hunts if h.priority == "critical"]

    # High-severity unconfirmed findings across all active hunts
    findings_result = await db.execute(
        select(HuntFinding).where(
            HuntFinding.tenant_id == tid,
            HuntFinding.hunt_id.in_([h.id for h in active_hunts]),
            HuntFinding.severity.in_(["critical", "high"]),
            HuntFinding.is_false_positive.is_(False),
        ).limit(200)
    )
    high_sev_findings = list(findings_result.scalars().all())

    completed_hunts_window = [
        h for h in hunts
        if h.completed_at and h.completed_at >= since
    ]
    hunt_true_positives = sum(h.true_positive_count for h in completed_hunts_window)

    # ── PANL ──────────────────────────────────────────────────────────────────
    panl_result = await db.execute(
        select(NeutralizationAction).where(
            NeutralizationAction.tenant_id == tid,
            NeutralizationAction.created_at >= since,
        )
    )
    panl_actions = list(panl_result.scalars().all())
    panl_by_status: dict[str, int] = {}
    for a in panl_actions:
        panl_by_status[a.status] = panl_by_status.get(a.status, 0) + 1
    panl_pending = panl_by_status.get("pending_approval", 0)
    panl_approved = panl_by_status.get("completed", 0) + panl_by_status.get("executing", 0)
    panl_rejected = panl_by_status.get("rejected", 0)
    panl_decided = panl_approved + panl_rejected
    panl_approval_rate = round(panl_approved / panl_decided * 100, 1) if panl_decided else None

    # ── Threat Intelligence ───────────────────────────────────────────────────
    ti_result = await db.execute(
        select(ThreatIntelIndicator).where(ThreatIntelIndicator.tenant_id == tid)
    )
    ti_all = list(ti_result.scalars().all())
    ti_by_severity: dict[str, int] = {}
    ti_by_type: dict[str, int] = {}
    for ti in ti_all:
        sev = ti.severity or "unknown"
        ti_by_severity[sev] = ti_by_severity.get(sev, 0) + 1
        ti_by_type[ti.type] = ti_by_type.get(ti.type, 0) + 1

    ti_recent = [ti for ti in ti_all if ti.last_seen and ti.last_seen >= since]

    # ── PCDI ─────────────────────────────────────────────────────────────────
    pcdi_result = await db.execute(
        select(PCDISignedReport)
        .where(PCDISignedReport.tenant_id == tid)
        .order_by(PCDISignedReport.signed_at.desc())
        .limit(100)
    )
    signed_reports = list(pcdi_result.scalars().all())
    pcdi_high_score = [r for r in signed_reports if r.adaptive_score and r.adaptive_score >= 80]
    pcdi_avg_score = None
    scored = [r.adaptive_score for r in signed_reports if r.adaptive_score is not None]
    if scored:
        pcdi_avg_score = round(sum(scored) / len(scored), 1)

    # Auto-escalated hunts: hunts escalated to critical by PCDI
    auto_escalated_critical = len([
        h for h in hunts
        if h.priority == "critical" and h.status == "active"
    ])

    # ── SOAR + PIDS (P26) ─────────────────────────────────────────────────────
    soar_trigger_result = await db.execute(
        select(PlaybookTrigger).where(PlaybookTrigger.tenant_id == tid)
    )
    soar_triggers = list(soar_trigger_result.scalars().all())
    soar_enabled = sum(1 for t in soar_triggers if t.enabled)

    soar_fired_result = await db.execute(
        select(PlaybookTrigger).where(
            PlaybookTrigger.tenant_id == tid,
            PlaybookTrigger.last_triggered_at.isnot(None),
            PlaybookTrigger.last_triggered_at >= since,
        )
    )
    soar_triggers_fired_24h = len(list(soar_fired_result.scalars().all()))

    pids_result = await db.execute(
        select(IdentityAction).where(
            IdentityAction.tenant_id == tid,
            IdentityAction.executed_at >= since,
        )
    )
    pids_recent = list(pids_result.scalars().all())
    pids_successful = sum(1 for a in pids_recent if a.success)

    return {
        "window_hours": hours,
        "ts": now.isoformat(),
        "fleet": {
            "total_agents": fleet_total,
            "active_agents": fleet_active,
            "online_5m": fleet_online_5m,
            "at_risk_agents": fleet_at_risk,
            "commands_in_window": len(recent_cmds),
            "command_success_rate_pct": cmd_success_rate,
        },
        "hunting": {
            "active_hunts": len(active_hunts),
            "critical_priority_hunts": len(critical_hunts),
            "total_hunts": len(hunts),
            "completed_in_window": len(completed_hunts_window),
            "true_positives_in_window": hunt_true_positives,
            "high_severity_findings": len(high_sev_findings),
            "active_hunt_ids": [h.id for h in critical_hunts],
        },
        "panl": {
            "actions_in_window": len(panl_actions),
            "pending_approval": panl_pending,
            "by_status": panl_by_status,
            "approval_rate_pct": panl_approval_rate,
        },
        "threat_intel": {
            "total_indicators": len(ti_all),
            "by_severity": ti_by_severity,
            "by_type": ti_by_type,
            "new_in_window": len(ti_recent),
        },
        "pcdi": {
            "total_signed_reports": len(signed_reports),
            "high_score_reports": len(pcdi_high_score),
            "avg_adaptive_score": pcdi_avg_score,
            "active_critical_hunts": auto_escalated_critical,
            "top_reports": [
                {
                    "report_id": r.id,
                    "hunt_id": r.hunt_id,
                    "hunt_name": r.hunt_name,
                    "adaptive_score": r.adaptive_score,
                    "signed_at": r.signed_at.isoformat() if r.signed_at else None,
                }
                for r in sorted(
                    [r for r in signed_reports if r.adaptive_score],
                    key=lambda r: r.adaptive_score,
                    reverse=True,
                )[:5]
            ],
        },
        "soar_pids": {
            "total_triggers": len(soar_triggers),
            "enabled_triggers": soar_enabled,
            "triggers_fired_24h": soar_triggers_fired_24h,
            "identity_actions_24h": len(pids_recent),
            "identity_actions_successful_24h": pids_successful,
            "identity_success_rate_pct": (
                round(pids_successful / len(pids_recent) * 100, 1) if pids_recent else None
            ),
        },
        "correlation": await _correlation_summary_inline(db, tid),
        "incidents": await _incident_summary_inline(db, tid),
    }


async def _correlation_summary_inline(db: AsyncSession, tenant_id: str) -> dict:
    from asc_api.services.correlation_service import get_correlation_summary
    summary = await get_correlation_summary(db, tenant_id=tenant_id)
    return {
        "active_clusters": summary["active_clusters"],
        "campaigns_detected": summary["campaigns_detected"],
        "critical_clusters": summary["critical_clusters"],
        "active_rules": summary["active_rules"],
    }


async def _incident_summary_inline(db: AsyncSession, tenant_id: str) -> dict:
    from asc_api.services.incident_service import get_incident_summary
    summary = await get_incident_summary(db, tenant_id=tenant_id)
    return {
        "total": summary["total"],
        "open": summary["open"],
        "sla_breach_count": summary["sla_breach_count"],
        "avg_mttd_minutes": summary["avg_mttd_minutes"],
        "avg_mttr_minutes": summary["avg_mttr_minutes"],
    }
