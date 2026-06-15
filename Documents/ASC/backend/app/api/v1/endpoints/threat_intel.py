"""
PremosCorp Threat Intelligence API — P21-F1

Endpoints
---------
GET    /threat-intel/stats                   — corpus stats (analyst+)
GET    /threat-intel/                        — list indicators, paginated (analyst+)
POST   /threat-intel/                        — create single indicator (analyst+)
POST   /threat-intel/bulk                    — bulk import list (analyst+)
POST   /threat-intel/enrich                  — enrich a single value (analyst+)
POST   /threat-intel/enrich/bulk             — enrich multiple values (analyst+)
GET    /threat-intel/{indicator_id}          — get indicator (analyst+)
PATCH  /threat-intel/{indicator_id}          — update indicator fields (analyst+)
DELETE /threat-intel/{indicator_id}          — deactivate indicator (admin only)
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_analyst_or_admin, get_current_admin
from app.core.rate_limit import limiter
from app.db.session import get_db
from app.models.user import User
from app.services import threat_intel as ti_svc

router = APIRouter(prefix="/threat-intel", tags=["Threat Intelligence"])


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class IndicatorCreate(BaseModel):
    indicator_type: str = Field(..., description="ip|domain|url|hash_md5|hash_sha256|hash_sha1|email|file_path|mutex|registry_key|cidr|asn|cve")
    value: str = Field(..., min_length=1, max_length=1024)
    severity: str = Field("medium", pattern="^(critical|high|medium|low|info)$")
    confidence: float = Field(0.5, ge=0.0, le=1.0)
    source: str = Field("internal", max_length=200)
    threat_actor: str | None = None
    malware_family: str | None = None
    campaign: str | None = None
    ttps: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    description: str | None = None
    source_reference: str | None = None
    expires_at: datetime | None = None

    @field_validator("indicator_type")
    @classmethod
    def validate_type(cls, v: str) -> str:
        if v not in ti_svc.VALID_TYPES:
            raise ValueError(f"Invalid indicator_type '{v}'. Valid: {sorted(ti_svc.VALID_TYPES)}")
        return v


class IndicatorUpdate(BaseModel):
    severity: str | None = Field(None, pattern="^(critical|high|medium|low|info)$")
    confidence: float | None = Field(None, ge=0.0, le=1.0)
    active: bool | None = None
    description: str | None = None
    tags: list[str] | None = None
    ttps: list[str] | None = None
    threat_actor: str | None = None
    malware_family: str | None = None
    campaign: str | None = None
    source_reference: str | None = None
    expires_at: datetime | None = None


class EnrichRequest(BaseModel):
    value: str = Field(..., min_length=1, max_length=1024)
    indicator_type: str | None = None

    @field_validator("indicator_type")
    @classmethod
    def validate_type(cls, v: str | None) -> str | None:
        if v is not None and v not in ti_svc.VALID_TYPES:
            raise ValueError(f"Invalid indicator_type '{v}'")
        return v


class BulkEnrichRequest(BaseModel):
    values: list[EnrichRequest] = Field(..., min_length=1, max_length=500)


class BulkImportRequest(BaseModel):
    indicators: list[dict[str, Any]] = Field(..., min_length=1, max_length=10_000)


# ── Stats ─────────────────────────────────────────────────────────────────────

@router.get("/stats", summary="Estadísticas del corpus TI local")
@limiter.limit("60/minute")
async def get_stats(
    request: Request,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_analyst_or_admin),
):
    return await ti_svc.get_stats(db)


# ── List ──────────────────────────────────────────────────────────────────────

@router.get("/", summary="Listar indicadores TI (paginado)")
@limiter.limit("120/minute")
async def list_indicators(
    request: Request,
    indicator_type: str | None = Query(None),
    severity: str | None = Query(None),
    active_only: bool = Query(True),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_analyst_or_admin),
):
    rows, total = await ti_svc.list_indicators(
        db,
        indicator_type=indicator_type,
        severity=severity,
        active_only=active_only,
        limit=limit,
        offset=offset,
    )
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "indicators": [ti_svc._indicator_to_dict(r) for r in rows],
    }


# ── Create ────────────────────────────────────────────────────────────────────

@router.post("/", summary="Crear indicador TI", status_code=201)
@limiter.limit("30/minute")
async def create_indicator(
    request: Request,
    body: IndicatorCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
):
    try:
        ind = await ti_svc.create_indicator(
            db,
            indicator_type=body.indicator_type,
            value=body.value,
            severity=body.severity,
            confidence=body.confidence,
            source=body.source,
            created_by=current_user.email,
            threat_actor=body.threat_actor,
            malware_family=body.malware_family,
            campaign=body.campaign,
            ttps=body.ttps,
            tags=body.tags,
            description=body.description,
            source_reference=body.source_reference,
            expires_at=body.expires_at,
        )
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    return ti_svc._indicator_to_dict(ind)


# ── Bulk import ───────────────────────────────────────────────────────────────

@router.post("/bulk", summary="Importación masiva de indicadores TI")
@limiter.limit("10/minute")
async def bulk_import(
    request: Request,
    body: BulkImportRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
):
    result = await ti_svc.bulk_import(db, body.indicators, created_by=current_user.email)
    return result


# ── Enrich ────────────────────────────────────────────────────────────────────

@router.post("/enrich", summary="Enriquecer un valor con TI local")
@limiter.limit("300/minute")
async def enrich_single(
    request: Request,
    body: EnrichRequest,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_analyst_or_admin),
):
    matches = await ti_svc.enrich(db, body.value, body.indicator_type)
    return {
        "value": body.value,
        "indicator_type": body.indicator_type,
        "matches": [ti_svc._indicator_to_dict(m) for m in matches],
        "match_count": len(matches),
        "is_known_bad": len(matches) > 0,
        "max_severity": _max_severity(matches),
    }


@router.post("/enrich/bulk", summary="Enriquecer múltiples valores con TI local")
@limiter.limit("60/minute")
async def enrich_bulk(
    request: Request,
    body: BulkEnrichRequest,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_analyst_or_admin),
):
    items = [{"value": v.value, "indicator_type": v.indicator_type} for v in body.values]
    results = await ti_svc.enrich_bulk(db, items)
    return {
        "results": results,
        "total_values": len(items),
        "matched_values": sum(1 for v in results.values() if v),
    }


# ── Get by ID ─────────────────────────────────────────────────────────────────

@router.get("/{indicator_id}", summary="Obtener indicador TI por ID")
@limiter.limit("120/minute")
async def get_indicator(
    request: Request,
    indicator_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_analyst_or_admin),
):
    ind = await ti_svc.get_indicator(db, indicator_id)
    if not ind:
        raise HTTPException(status_code=404, detail="Indicator not found")
    return ti_svc._indicator_to_dict(ind)


# ── Update ────────────────────────────────────────────────────────────────────

@router.patch("/{indicator_id}", summary="Actualizar campos del indicador")
@limiter.limit("30/minute")
async def update_indicator(
    request: Request,
    indicator_id: str,
    body: IndicatorUpdate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_analyst_or_admin),
):
    updates = body.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=422, detail="No fields to update")
    ind = await ti_svc.update_indicator(db, indicator_id, updates)
    if not ind:
        raise HTTPException(status_code=404, detail="Indicator not found")
    return ti_svc._indicator_to_dict(ind)


# ── Delete (soft) — admin only ────────────────────────────────────────────────

@router.delete("/{indicator_id}", summary="Desactivar indicador TI (admin)")
@limiter.limit("30/minute")
async def delete_indicator(
    request: Request,
    indicator_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_admin),
):
    ok = await ti_svc.delete_indicator(db, indicator_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Indicator not found")
    return {"message": "Indicator deactivated", "indicator_id": indicator_id}


# ── Helper ────────────────────────────────────────────────────────────────────

_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _max_severity(indicators: list) -> str | None:
    if not indicators:
        return None
    return max((i.severity for i in indicators), key=lambda s: _SEV_ORDER.get(s, 0))
