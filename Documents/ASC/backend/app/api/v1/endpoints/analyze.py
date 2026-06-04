from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timezone
import uuid

from app.db.session import get_db
from app.models.artifact import Artifact
from app.services import analyzer
from app.core.config import get_settings

router = APIRouter(prefix="/analyze", tags=["Analysis"])
settings = get_settings()


@router.post("/file", summary="Analyze a suspicious file/artifact")
async def analyze_file(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    """Submit a file for full analysis: hashing, magic detection, signature scan, IoC matching."""
    if file.size and file.size > settings.MAX_FILE_SIZE_MB * 1024 * 1024:
        raise HTTPException(status_code=413, detail=f"File exceeds {settings.MAX_FILE_SIZE_MB} MB limit")

    data = await file.read()
    result = await analyzer.analyze_artifact(file.filename or "unknown", data)

    # Persist artifact record
    artifact = Artifact(
        id=str(uuid.uuid4()),
        filename=file.filename or "unknown",
        file_type=result["file_type"],
        size_bytes=result["size_bytes"],
        md5=result["hashes"]["md5"],
        sha1=result["hashes"]["sha1"],
        sha256=result["hashes"]["sha256"],
        analysis_status="analyzed",
        risk_score=result["risk_score"],
        verdict=result["verdict"],
        analysis_result=result,
        yara_matches=result["signature_hits"],
        analyzed_at=datetime.now(timezone.utc),
    )
    db.add(artifact)
    await db.commit()
    await db.refresh(artifact)

    return {"artifact_id": artifact.id, **result}


@router.post("/domain", summary="Analyze a domain for reputation / DGA detection")
async def analyze_domain(domain: str):
    result = await analyzer.analyze_domain(domain)
    return result


@router.post("/ip", summary="Analyze an IP address for reputation")
async def analyze_ip(ip: str):
    result = await analyzer.analyze_ip(ip)
    return result


@router.get("/artifact/{artifact_id}", summary="Get analysis result for a previously submitted artifact")
async def get_artifact(artifact_id: str, db: AsyncSession = Depends(get_db)):
    from sqlalchemy import select
    result = await db.execute(select(Artifact).where(Artifact.id == artifact_id))
    artifact = result.scalar_one_or_none()
    if not artifact:
        raise HTTPException(status_code=404, detail="Artifact not found")
    return artifact.analysis_result
