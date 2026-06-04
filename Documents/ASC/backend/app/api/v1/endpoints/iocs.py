from fastapi import APIRouter, HTTPException, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from datetime import datetime, timezone
import uuid

from app.db.session import get_db
from app.models.ioc import IoC
from pydantic import BaseModel

router = APIRouter(prefix="/iocs", tags=["IoCs"])


class IoCCreate(BaseModel):
    value: str
    ioc_type: str        # hash_md5, hash_sha256, ip, domain, url, mutex
    threat_type: str | None = None
    confidence: float = 0.7
    severity: str = "medium"
    source: str = "internal"
    description: str | None = None
    tags: list[str] = []
    ttps: list[str] = []


class IoCBulkCreate(BaseModel):
    iocs: list[IoCCreate]


@router.post("/", summary="Add a new IoC")
async def create_ioc(payload: IoCCreate, db: AsyncSession = Depends(get_db)):
    ioc = IoC(id=str(uuid.uuid4()), **payload.model_dump())
    db.add(ioc)
    await db.commit()
    await db.refresh(ioc)
    return {"id": ioc.id, "value": ioc.value, "type": ioc.ioc_type}


@router.post("/bulk", summary="Import IoC feed (bulk)")
async def bulk_create_iocs(payload: IoCBulkCreate, db: AsyncSession = Depends(get_db)):
    created = 0
    for item in payload.iocs:
        existing = await db.execute(select(IoC).where(IoC.value == item.value))
        if existing.scalar_one_or_none():
            continue
        ioc = IoC(id=str(uuid.uuid4()), **item.model_dump())
        db.add(ioc)
        created += 1
    await db.commit()
    return {"created": created, "total_submitted": len(payload.iocs)}


@router.get("/", summary="List IoCs")
async def list_iocs(
    limit: int = Query(100, le=1000),
    offset: int = Query(0),
    ioc_type: str | None = Query(None),
    active: bool = Query(True),
    db: AsyncSession = Depends(get_db),
):
    q = select(IoC).where(IoC.active == active).order_by(desc(IoC.last_seen)).offset(offset).limit(limit)
    if ioc_type:
        q = q.where(IoC.ioc_type == ioc_type)
    result = await db.execute(q)
    iocs = result.scalars().all()
    return [{"id": i.id, "value": i.value, "type": i.ioc_type, "threat": i.threat_type, "confidence": i.confidence, "severity": i.severity, "hits": i.hit_count, "last_seen": i.last_seen} for i in iocs]


@router.get("/search", summary="Search IoC by value")
async def search_ioc(value: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(IoC).where(IoC.value.contains(value)))
    iocs = result.scalars().all()
    return [{"id": i.id, "value": i.value, "type": i.ioc_type, "severity": i.severity} for i in iocs]


@router.delete("/{ioc_id}", summary="Deactivate an IoC")
async def deactivate_ioc(ioc_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(IoC).where(IoC.id == ioc_id))
    ioc = result.scalar_one_or_none()
    if not ioc:
        raise HTTPException(status_code=404, detail="IoC not found")
    ioc.active = False
    await db.commit()
    return {"status": "deactivated", "id": ioc_id}
