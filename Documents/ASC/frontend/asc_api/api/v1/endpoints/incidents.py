"""
Incident Response Management Endpoints — P28-B / P30

NIST 800-61 formal incident lifecycle REST API.

Endpoints
---------
  GET    /incidents/summary                  KPI dashboard (MTTD/MTTC/MTTR, SLA)
  GET    /incidents                          List incidents (filterable, paginated)
  POST   /incidents                          Create incident
  GET    /incidents/{id}                     Single incident
  PATCH  /incidents/{id}/status              Transition status via state machine
  PATCH  /incidents/{id}/assign             Assign incident to analyst
  PATCH  /incidents/{id}/mitre             Update MITRE ATT&CK mappings
  POST   /incidents/{id}/links               Add entity link
  GET    /incidents/{id}/links               List entity links
  DELETE /incidents/{id}/links/{link_id}     Remove entity link
  GET    /incidents/{id}/timeline            Chronological timeline
  POST   /incidents/{id}/notes              Add analyst note
  POST   /incidents/{id}/close              Close with post-incident data (admin+)
  POST   /incidents/{id}/dismiss            Dismiss as false positive
  GET    /incidents/{id}/piil-binding        PIIL forensic SOAR binding ledger entries (P30)
  GET    /incidents/{id}/soar-events         SOAR-triggered timeline entries for incident (P30)

Security: analyst+ for reads/writes; close/dismiss requires analyst+ (actor is recorded).
Rate-limiting: writes 10/min, reads 60/min.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.api.deps import get_analyst_or_admin, get_current_admin
from asc_api.core.rate_limit import limiter
from asc_api.core.logging import get_logger
from asc_api.db.session import get_db
from asc_api.models.forensic_entry import ForensicEntry
from asc_api.models.incident import (
    INCIDENT_STATUSES,
    INCIDENT_TYPES,
    LINK_ENTITY_TYPES,
    IncidentTimeline,
    VALID_TRANSITIONS,
)
from asc_api.models.user import User
from asc_api.services import incident_service

log = get_logger(__name__)
router = APIRouter(prefix="/incidents", tags=["Incident Response"])

_VALID_SEVERITY = {"info", "low", "medium", "high", "critical"}


# ── Request schemas ───────────────────────────────────────────────────────────

class CreateIncidentRequest(BaseModel):
    title: str = Field(..., min_length=3, max_length=512)
    incident_type: str = Field("other")
    severity: str = Field("medium")
    description: str | None = Field(None, max_length=8192)
    assigned_to: str | None = Field(None, max_length=256)
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    risk_score: float = Field(0.0, ge=0.0, le=1.0)
    linked_entity_type: str | None = None
    linked_entity_id: str | None = Field(None, min_length=1, max_length=36)
    linked_entity_notes: str | None = None

    @field_validator("incident_type")
    @classmethod
    def validate_incident_type(cls, v: str) -> str:
        if v not in INCIDENT_TYPES:
            raise ValueError(f"incident_type must be one of {sorted(INCIDENT_TYPES)}")
        return v

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        if v not in _VALID_SEVERITY:
            raise ValueError(f"severity must be one of {sorted(_VALID_SEVERITY)}")
        return v

    @field_validator("linked_entity_type")
    @classmethod
    def validate_entity_type(cls, v: str | None) -> str | None:
        if v is not None and v not in LINK_ENTITY_TYPES:
            raise ValueError(f"linked_entity_type must be one of {sorted(LINK_ENTITY_TYPES)}")
        return v


class TransitionStatusRequest(BaseModel):
    new_status: str = Field(...)

    @field_validator("new_status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        if v not in INCIDENT_STATUSES:
            raise ValueError(f"new_status must be one of {sorted(INCIDENT_STATUSES)}")
        return v


class AssignRequest(BaseModel):
    assigned_to: str = Field(..., min_length=1, max_length=256)


class MitreUpdateRequest(BaseModel):
    mitre_tactics: list[str] | None = None
    mitre_techniques: list[str] | None = None


class AddLinkRequest(BaseModel):
    entity_type: str = Field(...)
    entity_id: str = Field(..., min_length=1, max_length=36)
    notes: str | None = None

    @field_validator("entity_type")
    @classmethod
    def validate_entity_type(cls, v: str) -> str:
        if v not in LINK_ENTITY_TYPES:
            raise ValueError(f"entity_type must be one of {sorted(LINK_ENTITY_TYPES)}")
        return v


class AddNoteRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=8192)


class CloseIncidentRequest(BaseModel):
    lessons_learned: str | None = Field(None, max_length=8192)
    root_cause: str | None = Field(None, max_length=4096)
    executive_summary: str | None = Field(None, max_length=4096)
    false_positive: bool = False


class DismissIncidentRequest(BaseModel):
    reason: str | None = Field(None, max_length=2048)


# ── Serializers ───────────────────────────────────────────────────────────────

def _inc(inc: Any) -> dict:
    return {
        "id": inc.id,
        "title": inc.title,
        "description": inc.description,
        "incident_type": inc.incident_type,
        "status": inc.status,
        "nist_phase": inc.nist_phase,
        "severity": inc.severity,
        "risk_score": inc.risk_score,
        "created_by": inc.created_by,
        "assigned_to": inc.assigned_to,
        "mitre_tactics": inc.mitre_tactics or [],
        "mitre_techniques": inc.mitre_techniques or [],
        "tags": inc.tags or [],
        "executive_summary": inc.executive_summary,
        "lessons_learned": inc.lessons_learned,
        "root_cause": inc.root_cause,
        "false_positive": inc.false_positive,
        "sla_minutes": inc.sla_minutes,
        "sla_breach": inc.sla_breach,
        "detected_at": inc.detected_at.isoformat() if inc.detected_at else None,
        "triaged_at": inc.triaged_at.isoformat() if inc.triaged_at else None,
        "contained_at": inc.contained_at.isoformat() if inc.contained_at else None,
        "eradicated_at": inc.eradicated_at.isoformat() if inc.eradicated_at else None,
        "recovered_at": inc.recovered_at.isoformat() if inc.recovered_at else None,
        "closed_at": inc.closed_at.isoformat() if inc.closed_at else None,
        "mttd_minutes": inc.mttd_minutes,
        "mttc_minutes": inc.mttc_minutes,
        "mttr_minutes": inc.mttr_minutes,
        "forensic_hash": inc.forensic_hash,
        "created_at": inc.created_at.isoformat() if inc.created_at else None,
        "updated_at": inc.updated_at.isoformat() if inc.updated_at else None,
    }


def _link(lnk: Any) -> dict:
    return {
        "id": lnk.id,
        "incident_id": lnk.incident_id,
        "entity_type": lnk.entity_type,
        "entity_id": lnk.entity_id,
        "notes": lnk.notes,
        "added_by": lnk.added_by,
        "created_at": lnk.created_at.isoformat() if lnk.created_at else None,
    }


def _tl(entry: Any) -> dict:
    return {
        "id": entry.id,
        "incident_id": entry.incident_id,
        "event_type": entry.event_type,
        "actor": entry.actor,
        "detail": entry.detail or {},
        "created_at": entry.created_at.isoformat() if entry.created_at else None,
    }


def _fe(entry: Any) -> dict:
    return {
        "id": entry.id,
        "action_id": entry.action_id,
        "action_type": entry.action_type,
        "target": entry.target,
        "canonical_data": entry.canonical_data,
        "hash_sha3_512": entry.hash_sha3_512,
        "signature_ed25519": entry.signature_ed25519,
        "signed_by_email": entry.signed_by_email,
        "signed_by_user_id": entry.signed_by_user_id,
        "signed_at": entry.signed_at.isoformat() if entry.signed_at else None,
        "verified": entry.verified,
        "last_verified_at": entry.last_verified_at.isoformat() if entry.last_verified_at else None,
    }


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/summary", summary="KPI dashboard — MTTD/MTTC/MTTR, SLA, breach counts")
@limiter.limit("60/minute")
async def incident_summary(
    request: Request,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_analyst_or_admin),
) -> dict:
    return await incident_service.get_incident_summary(db)


@router.get("", summary="Listar incidentes (filtrable, paginado)")
@limiter.limit("60/minute")
async def list_incidents(
    request: Request,
    status_filter: str | None = Query(None, alias="status"),
    severity: str | None = Query(None),
    incident_type: str | None = Query(None),
    assigned_to: str | None = Query(None),
    sla_breach: bool | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_analyst_or_admin),
) -> dict:
    if status_filter and status_filter not in INCIDENT_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"status must be one of {sorted(INCIDENT_STATUSES)}",
        )
    incidents = await incident_service.list_incidents(
        db,
        status=status_filter,
        severity=severity,
        incident_type=incident_type,
        assigned_to=assigned_to,
        sla_breach=sla_breach,
        limit=limit,
        offset=offset,
    )
    return {
        "items": [_inc(i) for i in incidents],
        "count": len(incidents),
        "limit": limit,
        "offset": offset,
    }


@router.post("", status_code=status.HTTP_201_CREATED, summary="Crear nuevo incidente")
@limiter.limit("10/minute")
async def create_incident(
    request: Request,
    body: CreateIncidentRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
) -> dict:
    try:
        incident = await incident_service.create_incident(
            db,
            title=body.title,
            incident_type=body.incident_type,
            severity=body.severity,
            created_by=current_user.email,
            description=body.description,
            assigned_to=body.assigned_to,
            mitre_tactics=body.mitre_tactics,
            mitre_techniques=body.mitre_techniques,
            tags=body.tags,
            risk_score=body.risk_score,
            linked_entity_type=body.linked_entity_type,
            linked_entity_id=body.linked_entity_id,
            linked_entity_notes=body.linked_entity_notes,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
    return _inc(incident)


@router.get("/{incident_id}", summary="Detalle de un incidente")
@limiter.limit("60/minute")
async def get_incident(
    request: Request,
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_analyst_or_admin),
) -> dict:
    inc = await incident_service.get_incident(db, incident_id)
    if inc is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    return _inc(inc)


@router.patch("/{incident_id}/status", summary="Transicionar estado (máquina de estados NIST)")
@limiter.limit("10/minute")
async def transition_status(
    request: Request,
    incident_id: str,
    body: TransitionStatusRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
) -> dict:
    try:
        inc = await incident_service.transition_status(
            db, incident_id, body.new_status, current_user.email
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
    return _inc(inc)


@router.patch("/{incident_id}/assign", summary="Asignar incidente a un analista")
@limiter.limit("10/minute")
async def assign_incident(
    request: Request,
    incident_id: str,
    body: AssignRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
) -> dict:
    try:
        inc = await incident_service.assign_incident(
            db, incident_id, body.assigned_to, current_user.email
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    return _inc(inc)


@router.patch("/{incident_id}/mitre", summary="Actualizar mapeo MITRE ATT&CK")
@limiter.limit("10/minute")
async def update_mitre(
    request: Request,
    incident_id: str,
    body: MitreUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
) -> dict:
    try:
        inc = await incident_service.update_mitre(
            db,
            incident_id,
            current_user.email,
            mitre_tactics=body.mitre_tactics,
            mitre_techniques=body.mitre_techniques,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    return _inc(inc)


@router.post("/{incident_id}/links", status_code=status.HTTP_201_CREATED,
             summary="Vincular entidad al incidente")
@limiter.limit("10/minute")
async def add_link(
    request: Request,
    incident_id: str,
    body: AddLinkRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
) -> dict:
    try:
        link = await incident_service.link_entity(
            db,
            incident_id,
            body.entity_type,
            body.entity_id,
            current_user.email,
            notes=body.notes,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
    return _link(link)


@router.get("/{incident_id}/links", summary="Entidades vinculadas al incidente")
@limiter.limit("60/minute")
async def list_links(
    request: Request,
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_analyst_or_admin),
) -> dict:
    inc = await incident_service.get_incident(db, incident_id)
    if inc is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    links = await incident_service.get_incident_links(db, incident_id)
    return {"incident_id": incident_id, "items": [_link(l) for l in links], "count": len(links)}


@router.delete("/{incident_id}/links/{link_id}", status_code=status.HTTP_204_NO_CONTENT,
               summary="Eliminar vínculo de entidad")
@limiter.limit("10/minute")
async def remove_link(
    request: Request,
    incident_id: str,
    link_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
):
    removed = await incident_service.remove_link(db, incident_id, link_id, current_user.email)
    if not removed:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Link not found")


@router.get("/{incident_id}/timeline", summary="Línea de tiempo del incidente (cronológica)")
@limiter.limit("60/minute")
async def get_timeline(
    request: Request,
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_analyst_or_admin),
) -> dict:
    inc = await incident_service.get_incident(db, incident_id)
    if inc is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    entries = await incident_service.get_incident_timeline(db, incident_id)
    return {
        "incident_id": incident_id,
        "items": [_tl(e) for e in entries],
        "count": len(entries),
    }


@router.post("/{incident_id}/notes", status_code=status.HTTP_201_CREATED,
             summary="Agregar nota de analista")
@limiter.limit("10/minute")
async def add_note(
    request: Request,
    incident_id: str,
    body: AddNoteRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
) -> dict:
    try:
        entry = await incident_service.add_note(
            db, incident_id, current_user.email, body.text
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
    return _tl(entry)


@router.post("/{incident_id}/close", summary="Cerrar incidente con datos post-incidente")
@limiter.limit("10/minute")
async def close_incident(
    request: Request,
    incident_id: str,
    body: CloseIncidentRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
) -> dict:
    try:
        inc = await incident_service.close_incident(
            db,
            incident_id,
            current_user.email,
            lessons_learned=body.lessons_learned,
            root_cause=body.root_cause,
            executive_summary=body.executive_summary,
            false_positive=body.false_positive,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
    return _inc(inc)


@router.post("/{incident_id}/dismiss", summary="Descartar incidente como falso positivo")
@limiter.limit("10/minute")
async def dismiss_incident(
    request: Request,
    incident_id: str,
    body: DismissIncidentRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
) -> dict:
    try:
        inc = await incident_service.dismiss_incident(
            db,
            incident_id,
            current_user.email,
            reason=body.reason,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
    return _inc(inc)


@router.get("/{incident_id}/piil-binding",
            summary="PIIL Forensic Ledger — entradas SOAR binding del incidente (P30)")
@limiter.limit("60/minute")
async def get_piil_binding(
    request: Request,
    incident_id: str,
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_analyst_or_admin),
) -> dict:
    inc = await incident_service.get_incident(db, incident_id)
    if inc is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    result = await db.execute(
        select(ForensicEntry)
        .where(
            ForensicEntry.action_type == "piil_soar_binding",
            ForensicEntry.action_id == incident_id,
        )
        .order_by(ForensicEntry.signed_at.desc())
        .limit(limit)
    )
    entries = list(result.scalars().all())
    return {
        "incident_id": incident_id,
        "items": [_fe(e) for e in entries],
        "count": len(entries),
    }


@router.get("/{incident_id}/soar-events",
            summary="Eventos SOAR disparados durante el ciclo de vida del incidente (P30)")
@limiter.limit("60/minute")
async def get_soar_events(
    request: Request,
    incident_id: str,
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_analyst_or_admin),
) -> dict:
    inc = await incident_service.get_incident(db, incident_id)
    if inc is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    result = await db.execute(
        select(IncidentTimeline)
        .where(
            IncidentTimeline.incident_id == incident_id,
            IncidentTimeline.event_type == "soar_triggered",
        )
        .order_by(IncidentTimeline.created_at.desc())
        .limit(limit)
    )
    entries = list(result.scalars().all())
    return {
        "incident_id": incident_id,
        "items": [_tl(e) for e in entries],
        "count": len(entries),
    }
