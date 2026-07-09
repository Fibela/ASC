"""
Correlation Engine Endpoints — P27-B

REST API for the PremosCorp Correlation Engine.

Endpoints:
  GET    /correlation/summary             Global KPI stats
  GET    /correlation/rules               List all correlation rules
  POST   /correlation/rules               Create a custom rule
  GET    /correlation/rules/{rule_id}     Single rule
  PATCH  /correlation/rules/{rule_id}     Update rule fields
  DELETE /correlation/rules/{rule_id}     Delete rule (cascades clusters)
  GET    /correlation/clusters            List clusters (filterable)
  GET    /correlation/clusters/{id}       Single cluster + stats
  PATCH  /correlation/clusters/{id}/status  Update status / assign analyst
  GET    /correlation/clusters/{id}/signals  All signals in cluster
  GET    /correlation/clusters/{id}/graph    Graph JSON for visualization
  POST   /correlation/sweep               Manually trigger a sweep (admin only)

Security: all endpoints require analyst or admin role.
Rate-limiting: writes/mutations 10/min, reads 60/min.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.api.deps import get_analyst_or_admin, get_current_admin
from asc_api.core.rate_limit import limiter
from asc_api.core.logging import get_logger
from asc_api.db.session import get_db
from asc_api.models.correlation import PIVOT_TYPES, CLUSTER_STATUSES
from asc_api.models.user import User
from asc_api.services import correlation_service

log = get_logger(__name__)
router = APIRouter(prefix="/correlation", tags=["Correlation"])

_VALID_SEVERITY = {"info", "low", "medium", "high", "critical"}


# ── Request schemas ───────────────────────────────────────────────────────────

class CreateRuleRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=256)
    pivot_type: str = Field(..., description="host_pivot | identity_pivot | ip_pivot | domain_pivot | ttp_pivot")
    min_signals: int = Field(2, ge=2, le=100)
    time_window_minutes: int = Field(60, ge=5, le=10080)
    severity_threshold: str = Field("low")
    description: str | None = Field(None, max_length=2048)

    @field_validator("pivot_type")
    @classmethod
    def validate_pivot_type(cls, v: str) -> str:
        if v not in PIVOT_TYPES:
            raise ValueError(f"pivot_type must be one of {sorted(PIVOT_TYPES)}")
        return v

    @field_validator("severity_threshold")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        if v not in _VALID_SEVERITY:
            raise ValueError(f"severity_threshold must be one of {sorted(_VALID_SEVERITY)}")
        return v


class UpdateRuleRequest(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=256)
    pivot_type: str | None = None
    min_signals: int | None = Field(None, ge=2, le=100)
    time_window_minutes: int | None = Field(None, ge=5, le=10080)
    severity_threshold: str | None = None
    description: str | None = None
    enabled: bool | None = None

    @field_validator("pivot_type")
    @classmethod
    def validate_pivot_type(cls, v: str | None) -> str | None:
        if v is not None and v not in PIVOT_TYPES:
            raise ValueError(f"pivot_type must be one of {sorted(PIVOT_TYPES)}")
        return v

    @field_validator("severity_threshold")
    @classmethod
    def validate_severity(cls, v: str | None) -> str | None:
        if v is not None and v not in _VALID_SEVERITY:
            raise ValueError(f"severity_threshold must be one of {sorted(_VALID_SEVERITY)}")
        return v


class UpdateClusterStatusRequest(BaseModel):
    status: str = Field(..., description="active | resolved | dismissed")
    analyst_notes: str | None = Field(None, max_length=4096)
    assigned_to: str | None = Field(None, max_length=256)

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        if v not in CLUSTER_STATUSES:
            raise ValueError(f"status must be one of {sorted(CLUSTER_STATUSES)}")
        return v


# ── Helpers ───────────────────────────────────────────────────────────────────

def _rule_out(rule) -> dict[str, Any]:
    return {
        "id": rule.id,
        "name": rule.name,
        "description": rule.description,
        "pivot_type": rule.pivot_type,
        "min_signals": rule.min_signals,
        "time_window_minutes": rule.time_window_minutes,
        "severity_threshold": rule.severity_threshold,
        "enabled": rule.enabled,
        "is_global": rule.tenant_id is None,
        "created_at": rule.created_at.isoformat() if rule.created_at else None,
        "updated_at": rule.updated_at.isoformat() if rule.updated_at else None,
    }


def _cluster_out(c) -> dict[str, Any]:
    return {
        "id": c.id,
        "rule_id": c.rule_id,
        "cluster_key": c.cluster_key,
        "cluster_type": c.cluster_type,
        "signal_count": c.signal_count,
        "severity": c.severity,
        "confidence_score": round(c.confidence_score, 3),
        "first_seen": c.first_seen.isoformat() if c.first_seen else None,
        "last_seen": c.last_seen.isoformat() if c.last_seen else None,
        "status": c.status,
        "is_campaign": c.is_campaign,
        "campaign_name": c.campaign_name,
        "distinct_signal_domains": c.distinct_signal_domains,
        "analyst_notes": c.analyst_notes,
        "assigned_to": c.assigned_to,
        "forensic_hash": c.forensic_hash,
        "meta": c.meta,
        "created_at": c.created_at.isoformat() if c.created_at else None,
        "updated_at": c.updated_at.isoformat() if c.updated_at else None,
    }


def _signal_out(s) -> dict[str, Any]:
    return {
        "id": s.id,
        "cluster_id": s.cluster_id,
        "signal_type": s.signal_type,
        "signal_id": s.signal_id,
        "pivot_value": s.pivot_value,
        "severity": s.severity,
        "timestamp": s.timestamp.isoformat() if s.timestamp else None,
        "meta": s.meta,
        "created_at": s.created_at.isoformat() if s.created_at else None,
    }


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/summary")
@limiter.limit("60/minute")
async def get_summary(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
):
    return await correlation_service.get_correlation_summary(db, tenant_id=current_user.tenant_id)


# ── Rules ─────────────────────────────────────────────────────────────────────

@router.get("/rules")
@limiter.limit("60/minute")
async def list_rules(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
):
    rules = await correlation_service.list_rules(db, tenant_id=current_user.tenant_id)
    return [_rule_out(r) for r in rules]


@router.post("/rules", status_code=status.HTTP_201_CREATED)
@limiter.limit("10/minute")
async def create_rule(
    body: CreateRuleRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
):
    try:
        rule = await correlation_service.create_rule(
            db,
            name=body.name,
            pivot_type=body.pivot_type,
            min_signals=body.min_signals,
            time_window_minutes=body.time_window_minutes,
            severity_threshold=body.severity_threshold,
            description=body.description,
            tenant_id=current_user.tenant_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return _rule_out(rule)


@router.get("/rules/{rule_id}")
@limiter.limit("60/minute")
async def get_rule(
    rule_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
):
    rule = await correlation_service.get_rule(db, rule_id, tenant_id=current_user.tenant_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    return _rule_out(rule)


@router.patch("/rules/{rule_id}")
@limiter.limit("10/minute")
async def update_rule(
    rule_id: str,
    body: UpdateRuleRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
):
    updates = body.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=422, detail="No fields to update")
    try:
        rule = await correlation_service.update_rule(
            db, rule_id, tenant_id=current_user.tenant_id, **updates
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    return _rule_out(rule)


@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit("10/minute")
async def delete_rule(
    rule_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    try:
        ok = await correlation_service.delete_rule(db, rule_id, tenant_id=current_user.tenant_id)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    if not ok:
        raise HTTPException(status_code=404, detail="Rule not found")


# ── Clusters ──────────────────────────────────────────────────────────────────

@router.get("/clusters")
@limiter.limit("60/minute")
async def list_clusters(
    request: Request,
    status_filter: str | None = Query(None, alias="status"),
    cluster_type: str | None = Query(None),
    campaigns_only: bool = Query(False),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
):
    clusters = await correlation_service.list_clusters(
        db,
        status=status_filter,
        cluster_type=cluster_type,
        is_campaign=True if campaigns_only else None,
        limit=limit,
        offset=offset,
        tenant_id=current_user.tenant_id,
    )
    return [_cluster_out(c) for c in clusters]


@router.get("/clusters/{cluster_id}")
@limiter.limit("60/minute")
async def get_cluster(
    cluster_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
):
    cluster = await correlation_service.get_cluster(db, cluster_id, tenant_id=current_user.tenant_id)
    if cluster is None:
        raise HTTPException(status_code=404, detail="Cluster not found")
    return _cluster_out(cluster)


@router.patch("/clusters/{cluster_id}/status")
@limiter.limit("10/minute")
async def update_cluster_status(
    cluster_id: str,
    body: UpdateClusterStatusRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
):
    cluster = await correlation_service.update_cluster_status(
        db,
        cluster_id=cluster_id,
        status=body.status,
        analyst_notes=body.analyst_notes,
        assigned_to=body.assigned_to,
        tenant_id=current_user.tenant_id,
    )
    if cluster is None:
        raise HTTPException(status_code=404, detail="Cluster not found")
    return _cluster_out(cluster)


@router.get("/clusters/{cluster_id}/signals")
@limiter.limit("60/minute")
async def get_cluster_signals(
    cluster_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
):
    # Verify tenant ownership before returning signals
    cluster = await correlation_service.get_cluster(db, cluster_id, tenant_id=current_user.tenant_id)
    if cluster is None:
        raise HTTPException(status_code=404, detail="Cluster not found")
    signals = await correlation_service.get_cluster_signals(db, cluster_id)
    return [_signal_out(s) for s in signals]


@router.get("/clusters/{cluster_id}/graph")
@limiter.limit("30/minute")
async def get_cluster_graph(
    cluster_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
):
    graph = await correlation_service.get_cluster_graph(db, cluster_id, tenant_id=current_user.tenant_id)
    if graph is None:
        raise HTTPException(status_code=404, detail="Cluster not found")
    return graph


@router.post("/sweep", status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("5/minute")
async def trigger_sweep(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    """Manually enqueue a correlation sweep scoped to the requesting tenant."""
    try:
        from asc_api.tasks.correlation_sweep import run_sweep
        task = run_sweep.delay()
        return {"status": "queued", "task_id": task.id}
    except Exception:
        # Celery not available — run inline (dev/test mode)
        log.warning("Celery not available — running correlation sweep inline")
        stats = await correlation_service.run_correlation_sweep(db, tenant_id=current_user.tenant_id)
        return {"status": "completed_inline", "stats": stats}
