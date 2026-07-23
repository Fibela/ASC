"""
PremosCorp Threat Hunting API â€” P22-F3 + P23

Endpoints (P22)
---------------
GET    /hunt/stats                           â€” aggregate stats (analyst+)
GET    /hunt/                                â€” list hunt sessions (analyst+)
POST   /hunt/                                â€” create hunt session (analyst+)
GET    /hunt/{hunt_id}                       â€” get hunt detail (analyst+)
PUT    /hunt/{hunt_id}                       â€” update hunt / change status (analyst+)
DELETE /hunt/{hunt_id}                       â€” archive hunt (admin only)

GET    /hunt/{hunt_id}/findings              â€” list findings for hunt (analyst+)
POST   /hunt/{hunt_id}/findings              â€” add finding (analyst+)
GET    /hunt/{hunt_id}/findings/{fid}        â€” get finding (analyst+)
PUT    /hunt/{hunt_id}/findings/{fid}        â€” update finding (analyst+)
POST   /hunt/{hunt_id}/findings/{fid}/verdict â€” set confirmed/false_positive (analyst+)

GET    /hunt/{hunt_id}/queries               â€” list saved queries (analyst+)
POST   /hunt/{hunt_id}/queries               â€” save a query (analyst+)
DELETE /hunt/{hunt_id}/queries/{qid}         â€” delete saved query (analyst+)

Endpoints (P23)
---------------
POST   /hunt/from-alert/{alert_id}                      â€” create hunt from alert (analyst+)
POST   /hunt/{hunt_id}/queries/{query_id}/execute        â€” execute query read-only (analyst+)
POST   /hunt/{hunt_id}/findings/{fid}/enrich             â€” TI auto-enrichment (analyst+)
GET    /hunt/{hunt_id}/report                            â€” export structured report (analyst+)

All hunting is PASSIVE â€” no active probing of external systems.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.api.deps import get_analyst_or_admin, get_current_admin
from asc_api.core.config import get_settings
from asc_api.core.rate_limit import limiter
from asc_api.db.session import get_db
from asc_api.models.user import User
from asc_api.services import hunt_service as svc

router = APIRouter(prefix="/hunt", tags=["threat-hunting"])
_s = get_settings()

# â”€â”€ Pydantic Schemas â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


class HuntCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=256)
    description: str | None = None
    hypothesis: str | None = None
    mitre_technique: str | None = Field(None, max_length=20)
    mitre_tactic: str | None = Field(None, max_length=100)
    scope: str = Field("all")
    priority: str = Field("medium")
    assigned_to: str | None = None
    tags: list[str] = Field(default_factory=list)

    @field_validator("scope")
    @classmethod
    def validate_scope(cls, v: str) -> str:
        if v not in svc.VALID_SCOPES:
            raise ValueError(f"Invalid scope. Valid: {sorted(svc.VALID_SCOPES)}")
        return v

    @field_validator("priority")
    @classmethod
    def validate_priority(cls, v: str) -> str:
        if v not in svc.VALID_PRIORITIES:
            raise ValueError(f"Invalid priority. Valid: {sorted(svc.VALID_PRIORITIES)}")
        return v


class HuntUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=256)
    description: str | None = None
    hypothesis: str | None = None
    mitre_technique: str | None = None
    mitre_tactic: str | None = None
    scope: str | None = None
    priority: str | None = None
    assigned_to: str | None = None
    conclusion: str | None = None
    tags: list[str] | None = None
    status: str | None = None


class FindingCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=512)
    description: str | None = None
    severity: str = Field("medium")
    indicator_value: str | None = Field(None, max_length=1024)
    indicator_type: str | None = None
    affected_host: str | None = Field(None, max_length=256)
    affected_user: str | None = Field(None, max_length=256)
    data_source: str | None = None
    mitre_technique: str | None = Field(None, max_length=20)
    mitre_tactic: str | None = Field(None, max_length=100)
    evidence: dict | None = None
    analyst_notes: str | None = None

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        if v not in svc.VALID_SEVERITIES:
            raise ValueError(f"Invalid severity. Valid: {sorted(svc.VALID_SEVERITIES)}")
        return v

    @field_validator("indicator_type")
    @classmethod
    def validate_indicator_type(cls, v: str | None) -> str | None:
        if v and v not in svc.VALID_INDICATOR_TYPES:
            raise ValueError(f"Invalid indicator_type. Valid: {sorted(svc.VALID_INDICATOR_TYPES)}")
        return v


class FindingUpdate(BaseModel):
    title: str | None = Field(None, min_length=1, max_length=512)
    description: str | None = None
    severity: str | None = None
    indicator_value: str | None = None
    indicator_type: str | None = None
    affected_host: str | None = None
    affected_user: str | None = None
    data_source: str | None = None
    mitre_technique: str | None = None
    mitre_tactic: str | None = None
    evidence: dict | None = None
    analyst_notes: str | None = None


class VerdictRequest(BaseModel):
    is_confirmed: bool
    is_false_positive: bool = False
    analyst_notes: str | None = None


class QueryCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=256)
    query_text: str = Field(..., min_length=1)
    data_source: str = Field("elk")
    description: str | None = None

    @field_validator("data_source")
    @classmethod
    def validate_data_source(cls, v: str) -> str:
        if v not in svc.VALID_DATA_SOURCES:
            raise ValueError(f"Invalid data_source. Valid: {sorted(svc.VALID_DATA_SOURCES)}")
        return v


# â”€â”€ Helper â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


def _require_not_archived(hunt_dict: dict) -> None:
    if hunt_dict.get("status") == "archived":
        raise HTTPException(status_code=409, detail="Hunt is archived and cannot be modified")


# â”€â”€ Hunt Endpoints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


@router.get("/stats", summary="Hunt corpus stats (analyst+) â€” P22")
@limiter.limit("60/minute")
async def hunt_stats(
    request: Request,
    _: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    return await svc.get_hunt_stats(db)


@router.get("", summary="List hunt sessions (analyst+) â€” P22")
@limiter.limit("60/minute")
async def list_hunts(
    request: Request,
    status: str | None = Query(None),
    priority: str | None = Query(None),
    scope: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    _: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    hunts, total = await svc.list_hunts(db, status=status, priority=priority, scope=scope, limit=limit, offset=offset)
    return {
        "hunts": [svc._hunt_to_dict(h) for h in hunts],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.post("", status_code=201, summary="Create hunt session (analyst+) â€” P22")
@limiter.limit("30/minute")
async def create_hunt(
    request: Request,
    body: HuntCreate,
    current_user: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    try:
        hunt = await svc.create_hunt(
            db,
            name=body.name,
            created_by=current_user.email,
            description=body.description,
            hypothesis=body.hypothesis,
            mitre_technique=body.mitre_technique,
            mitre_tactic=body.mitre_tactic,
            scope=body.scope,
            priority=body.priority,
            assigned_to=body.assigned_to,
            tags=body.tags,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return svc._hunt_to_dict(hunt)


@router.get("/{hunt_id}", summary="Get hunt detail (analyst+) â€” P22")
@limiter.limit("120/minute")
async def get_hunt(
    request: Request,
    hunt_id: str,
    include_relations: bool = Query(False),
    _: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    hunt = await svc.get_hunt(db, hunt_id)
    if hunt is None:
        raise HTTPException(status_code=404, detail="Hunt not found")
    return svc._hunt_to_dict(hunt, include_relations=include_relations)


@router.put("/{hunt_id}", summary="Update hunt (analyst+) â€” P22")
@limiter.limit("60/minute")
async def update_hunt(
    request: Request,
    hunt_id: str,
    body: HuntUpdate,
    current_user: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    updates = body.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=422, detail="No fields to update")
    try:
        hunt = await svc.update_hunt(db, hunt_id, updates, updated_by=current_user.email)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    if hunt is None:
        raise HTTPException(status_code=404, detail="Hunt not found")
    return svc._hunt_to_dict(hunt)


@router.delete("/{hunt_id}", status_code=204, summary="Archive hunt (admin only) â€” P22")
@limiter.limit("30/minute")
async def archive_hunt(
    request: Request,
    hunt_id: str,
    _: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> None:
    ok = await svc.archive_hunt(db, hunt_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Hunt not found")


# â”€â”€ Finding Endpoints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


@router.get("/{hunt_id}/findings", summary="List findings for hunt (analyst+) â€” P22")
@limiter.limit("120/minute")
async def list_findings(
    request: Request,
    hunt_id: str,
    severity: str | None = Query(None),
    confirmed_only: bool = Query(False),
    _: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    hunt = await svc.get_hunt(db, hunt_id)
    if hunt is None:
        raise HTTPException(status_code=404, detail="Hunt not found")
    findings = await svc.list_findings(db, hunt_id, severity=severity, confirmed_only=confirmed_only)
    return {"findings": [svc._finding_to_dict(f) for f in findings], "total": len(findings)}


@router.post("/{hunt_id}/findings", status_code=201, summary="Add finding (analyst+) â€” P22")
@limiter.limit("60/minute")
async def add_finding(
    request: Request,
    hunt_id: str,
    body: FindingCreate,
    current_user: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    hunt = await svc.get_hunt(db, hunt_id)
    if hunt is None:
        raise HTTPException(status_code=404, detail="Hunt not found")
    if hunt.status == "archived":
        raise HTTPException(status_code=409, detail="Cannot add findings to an archived hunt")
    try:
        finding = await svc.add_finding(
            db,
            hunt_id,
            title=body.title,
            created_by=current_user.email,
            severity=body.severity,
            description=body.description,
            indicator_value=body.indicator_value,
            indicator_type=body.indicator_type,
            affected_host=body.affected_host,
            affected_user=body.affected_user,
            data_source=body.data_source,
            mitre_technique=body.mitre_technique,
            mitre_tactic=body.mitre_tactic,
            evidence=body.evidence,
            analyst_notes=body.analyst_notes,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return svc._finding_to_dict(finding)


@router.get("/{hunt_id}/findings/{finding_id}", summary="Get finding (analyst+) â€” P22")
@limiter.limit("120/minute")
async def get_finding(
    request: Request,
    hunt_id: str,
    finding_id: str,
    _: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    finding = await svc.get_finding(db, finding_id)
    if finding is None or finding.hunt_id != hunt_id:
        raise HTTPException(status_code=404, detail="Finding not found")
    return svc._finding_to_dict(finding)


@router.put("/{hunt_id}/findings/{finding_id}", summary="Update finding (analyst+) â€” P22")
@limiter.limit("60/minute")
async def update_finding(
    request: Request,
    hunt_id: str,
    finding_id: str,
    body: FindingUpdate,
    _: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    finding = await svc.get_finding(db, finding_id)
    if finding is None or finding.hunt_id != hunt_id:
        raise HTTPException(status_code=404, detail="Finding not found")
    updates = body.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=422, detail="No fields to update")
    updated = await svc.update_finding(db, finding_id, updates)
    return svc._finding_to_dict(updated)


@router.post(
    "/{hunt_id}/findings/{finding_id}/verdict",
    summary="Set finding verdict â€” confirmed/false-positive (analyst+) â€” P22",
)
@limiter.limit("60/minute")
async def set_verdict(
    request: Request,
    hunt_id: str,
    finding_id: str,
    body: VerdictRequest,
    current_user: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    finding = await svc.get_finding(db, finding_id)
    if finding is None or finding.hunt_id != hunt_id:
        raise HTTPException(status_code=404, detail="Finding not found")
    updated = await svc.set_finding_verdict(
        db,
        finding_id,
        is_confirmed=body.is_confirmed,
        is_false_positive=body.is_false_positive,
        analyst_notes=body.analyst_notes,
    )
    return svc._finding_to_dict(updated)


# â”€â”€ Query Endpoints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


@router.get("/{hunt_id}/queries", summary="List saved queries for hunt (analyst+) â€” P22")
@limiter.limit("120/minute")
async def list_queries(
    request: Request,
    hunt_id: str,
    _: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    hunt = await svc.get_hunt(db, hunt_id)
    if hunt is None:
        raise HTTPException(status_code=404, detail="Hunt not found")
    queries = await svc.list_queries(db, hunt_id)
    return {"queries": [svc._query_to_dict(q) for q in queries], "total": len(queries)}


@router.post("/{hunt_id}/queries", status_code=201, summary="Save a query for hunt (analyst+) â€” P22")
@limiter.limit("30/minute")
async def save_query(
    request: Request,
    hunt_id: str,
    body: QueryCreate,
    current_user: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    hunt = await svc.get_hunt(db, hunt_id)
    if hunt is None:
        raise HTTPException(status_code=404, detail="Hunt not found")
    try:
        query = await svc.save_query(
            db,
            hunt_id,
            name=body.name,
            query_text=body.query_text,
            data_source=body.data_source,
            description=body.description,
            created_by=current_user.email,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return svc._query_to_dict(query)


@router.delete(
    "/{hunt_id}/queries/{query_id}",
    status_code=204,
    summary="Delete saved query (analyst+) â€” P22",
)
@limiter.limit("30/minute")
async def delete_query(
    request: Request,
    hunt_id: str,
    query_id: str,
    _: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> None:
    ok = await svc.delete_query(db, query_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Query not found")


# â”€â”€ P23 Endpoints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


@router.post(
    "/from-alert/{alert_id}",
    status_code=201,
    summary="Create hunt from alert â€” auto-populate hypothesis and first finding (analyst+) â€” P23",
)
@limiter.limit("20/minute")
async def create_hunt_from_alert(
    request: Request,
    alert_id: str,
    current_user: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    hunt = await svc.create_hunt_from_alert(db, alert_id, created_by=current_user.email)
    if hunt is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return svc._hunt_to_dict(hunt)


@router.post(
    "/{hunt_id}/queries/{query_id}/execute",
    summary="Execute a saved query read-only against ELK/Wazuh (analyst+) â€” P23",
)
@limiter.limit("10/minute")
async def execute_query(
    request: Request,
    hunt_id: str,
    query_id: str,
    current_user: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    from asc_api.services.query_executor import execute_hunt_query

    # Verify hunt exists and query belongs to it
    hunt = await svc.get_hunt(db, hunt_id)
    if hunt is None:
        raise HTTPException(status_code=404, detail="Hunt not found")

    queries = await svc.list_queries(db, hunt_id)
    if not any(q.id == query_id for q in queries):
        raise HTTPException(status_code=404, detail="Query not found in this hunt")

    result = await execute_hunt_query(db, query_id, executed_by=current_user.email)
    return result


@router.post(
    "/{hunt_id}/findings/{finding_id}/enrich",
    summary="Auto-enrich finding indicator against ThreatIntel (analyst+) â€” P23",
)
@limiter.limit("30/minute")
async def enrich_finding(
    request: Request,
    hunt_id: str,
    finding_id: str,
    _: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    finding = await svc.get_finding(db, finding_id)
    if finding is None or finding.hunt_id != hunt_id:
        raise HTTPException(status_code=404, detail="Finding not found")

    result = await svc.enrich_finding(db, finding_id)
    if "error" in result and not result.get("enriched", True) and result.get("error") == "Finding not found":
        raise HTTPException(status_code=404, detail="Finding not found")
    return result


@router.get(
    "/{hunt_id}/report",
    summary="Export structured hunt report (analyst+) â€” P23",
)
@limiter.limit("30/minute")
async def export_report(
    request: Request,
    hunt_id: str,
    _: User = Depends(get_analyst_or_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    report = await svc.generate_report(db, hunt_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Hunt not found")
    return report
