from fastapi import APIRouter, HTTPException, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from datetime import datetime, timezone
from typing import Any
import uuid

from app.db.session import get_db
from app.models.event import Event
from app.models.alert import Alert
from app.services.correlator import normalize_event, evaluate_correlation_rules, match_iocs
from app.core.config import get_settings
from pydantic import BaseModel

router = APIRouter(prefix="/events", tags=["Events"])
settings = get_settings()


class EventIngest(BaseModel):
    source: str
    category: str
    action: str
    host: str
    raw_log: str | None = None
    data: dict[str, Any] = {}


class BulkEventIngest(BaseModel):
    events: list[EventIngest]


@router.post("/ingest", summary="Ingest a single security event")
async def ingest_event(payload: EventIngest, db: AsyncSession = Depends(get_db)):
    normalized = await normalize_event({**payload.data, "source": payload.source, "category": payload.category, "action": payload.action, "host": payload.host})

    # IoC matching on key fields
    matched = []
    for field in ["src_ip", "dst_ip", "file_path", "process"]:
        val = normalized.get(field, "")
        if val:
            hits = await match_iocs(val, db)
            matched.extend(hits)

    # Risk score heuristic
    risk = min(sum(m["confidence"] for m in matched), 1.0)
    severity = "low"
    if risk >= settings.ALERT_CRITICAL_THRESHOLD:
        severity = "critical"
    elif risk >= settings.ALERT_HIGH_THRESHOLD:
        severity = "high"
    elif risk >= settings.ALERT_MEDIUM_THRESHOLD:
        severity = "medium"

    event = Event(
        id=str(uuid.uuid4()),
        source=payload.source,
        category=payload.category,
        action=payload.action,
        host=payload.host,
        raw_log=payload.raw_log,
        normalized=normalized,
        severity=severity,
        risk_score=risk,
        correlated=bool(matched),
    )
    db.add(event)
    await db.commit()
    return {"event_id": event.id, "severity": severity, "risk_score": risk, "matched_iocs": matched}


@router.post("/ingest/bulk", summary="Ingest multiple events and run correlation")
async def ingest_bulk(payload: BulkEventIngest, db: AsyncSession = Depends(get_db)):
    normalized_events = []
    created_ids = []

    for e in payload.events:
        norm = await normalize_event({**e.data, "source": e.source, "category": e.category, "action": e.action, "host": e.host})
        normalized_events.append(norm)
        event = Event(
            id=str(uuid.uuid4()),
            source=e.source, category=e.category, action=e.action, host=e.host,
            raw_log=e.raw_log, normalized=norm,
        )
        db.add(event)
        created_ids.append(event.id)

    # Run correlation rules
    alerts_to_create = await evaluate_correlation_rules(normalized_events, db)
    created_alerts = []
    for alert_data in alerts_to_create:
        alert = Alert(
            id=str(uuid.uuid4()),
            title=alert_data["title"],
            description=alert_data["description"],
            severity=alert_data["severity"],
            risk_score=alert_data["risk_score"],
            ttps=alert_data["ttps"],
            source_events=created_ids,
        )
        db.add(alert)
        created_alerts.append(alert.id)

    await db.commit()
    return {"events_ingested": len(created_ids), "alerts_created": len(created_alerts), "alert_ids": created_alerts}


@router.get("/", summary="List recent events")
async def list_events(
    limit: int = Query(50, le=500),
    offset: int = Query(0),
    severity: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
):
    q = select(Event).order_by(desc(Event.timestamp)).offset(offset).limit(limit)
    if severity:
        q = q.where(Event.severity == severity)
    result = await db.execute(q)
    events = result.scalars().all()
    return [{"id": e.id, "source": e.source, "category": e.category, "action": e.action, "host": e.host, "severity": e.severity, "risk_score": e.risk_score, "timestamp": e.timestamp} for e in events]
