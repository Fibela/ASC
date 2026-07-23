"""
Analysis endpoints — P21-F2 rate limiting + P21-F5 MIME pre-validation added.

MIME pre-validation (P21-F5):
  - Allowed MIME types are checked BEFORE any analysis runs (fail-fast, no wasted CPU)
  - python-magic is used for server-side type detection (not trusting Content-Type)
  - Per-type file size caps applied after MIME check
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.api.deps import get_analyst_or_admin, get_current_user
from asc_api.core.config import get_settings
from asc_api.core.rate_limit import limiter
from asc_api.db.session import get_db
from asc_api.models.artifact import Artifact
from asc_api.models.user import User
from asc_api.services import analyzer

router = APIRouter(prefix="/analyze", tags=["Analysis"])
settings = get_settings()

# ── P21-F5: MIME pre-validation ───────────────────────────────────────────────

# Maps detected MIME type → max allowed size in bytes
_ALLOWED_MIME_TYPES: dict[str, int] = {
    # Windows PE / ELF / Mach-O binaries
    "application/x-dosexec": 50 * 1024 * 1024,
    "application/x-executable": 50 * 1024 * 1024,
    "application/x-sharedlib": 50 * 1024 * 1024,
    "application/x-mach-binary": 50 * 1024 * 1024,
    # Archives (for unpacking malware samples)
    "application/zip": 50 * 1024 * 1024,
    "application/x-rar-compressed": 50 * 1024 * 1024,
    "application/x-tar": 50 * 1024 * 1024,
    "application/gzip": 50 * 1024 * 1024,
    "application/x-7z-compressed": 50 * 1024 * 1024,
    # Office documents (macro analysis)
    "application/msword": 20 * 1024 * 1024,
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": 20 * 1024 * 1024,
    "application/vnd.ms-excel": 20 * 1024 * 1024,
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": 20 * 1024 * 1024,
    "application/vnd.ms-powerpoint": 20 * 1024 * 1024,
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": 20 * 1024 * 1024,
    # PDF
    "application/pdf": 20 * 1024 * 1024,
    # Scripts
    "text/x-python": 5 * 1024 * 1024,
    "text/x-shellscript": 5 * 1024 * 1024,
    "application/x-sh": 5 * 1024 * 1024,
    "text/x-powershell": 5 * 1024 * 1024,
    # Generic binary / octet-stream (last resort — accept but apply strict size)
    "application/octet-stream": 50 * 1024 * 1024,
    # Plain text (config dumps, log snippets)
    "text/plain": 5 * 1024 * 1024,
}


def _detect_mime(data: bytes) -> str:
    """Detect MIME type from file bytes using python-magic. Falls back gracefully."""
    try:
        import magic

        return magic.from_buffer(data[:4096], mime=True)
    except Exception:
        return "application/octet-stream"


def _validate_file(filename: str, data: bytes) -> str:
    """
    Detect MIME type, reject disallowed types, enforce per-type size cap.
    Returns the detected MIME string on success; raises HTTPException on failure.
    """
    detected_mime = _detect_mime(data)
    max_size = _ALLOWED_MIME_TYPES.get(detected_mime)
    if max_size is None:
        raise HTTPException(
            status_code=415,
            detail=(
                f"Unsupported file type '{detected_mime}'. "
                "ASC accepts: PE/ELF binaries, archives, Office documents, PDFs, scripts, and plain text."
            ),
        )
    if len(data) > max_size:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds {max_size // (1024 * 1024)} MB limit for type '{detected_mime}'.",
        )
    return detected_mime


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.post("/file", summary="Analyze a suspicious file/artifact")
@limiter.limit(settings.RATE_LIMIT_ANALYZE_FILE)
async def analyze_file(
    request: Request,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
):
    """
    Submit a file for full analysis: MIME validation, hashing, magic detection,
    signature scan (YARA), IoC matching.  Rejects unsupported or oversized files
    before analysis begins.
    """
    # Hard cap from settings before reading (prevents OOM on enormous uploads)
    if file.size and file.size > settings.MAX_FILE_SIZE_MB * 1024 * 1024:
        raise HTTPException(status_code=413, detail=f"File exceeds {settings.MAX_FILE_SIZE_MB} MB global limit")

    data = await file.read()

    # P21-F5: server-side MIME pre-validation + per-type size cap
    detected_mime = _validate_file(file.filename or "unknown", data)

    result = await analyzer.analyze_artifact(file.filename or "unknown", data)

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
        analyzed_at=datetime.now(UTC),
        submitted_by=current_user.id,
        tenant_id=current_user.tenant_id,
    )
    db.add(artifact)
    await db.commit()
    await db.refresh(artifact)

    return {"artifact_id": artifact.id, "detected_mime": detected_mime, **result}


@router.post("/domain", summary="Analyze a domain for reputation / DGA detection")
@limiter.limit(settings.RATE_LIMIT_ANALYZE_LOOKUP)
async def analyze_domain(
    request: Request,
    domain: str,
    current_user: User = Depends(get_current_user),
):
    result = await analyzer.analyze_domain(domain)
    return result


@router.post("/ip", summary="Analyze an IP address for reputation")
@limiter.limit(settings.RATE_LIMIT_ANALYZE_LOOKUP)
async def analyze_ip(
    request: Request,
    ip: str,
    current_user: User = Depends(get_current_user),
):
    result = await analyzer.analyze_ip(ip)
    return result


@router.get("/artifact/{artifact_id}", summary="Get analysis result for a previously submitted artifact")
@limiter.limit(settings.RATE_LIMIT_ANALYZE_LOOKUP)
async def get_artifact(
    request: Request,
    artifact_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    from sqlalchemy import select

    # SEC-6: scope by tenant_id — same NULL-vs-value semantics as tenant_filter.py
    tenant_filter = (
        Artifact.tenant_id.is_(None) if current_user.tenant_id is None else Artifact.tenant_id == current_user.tenant_id
    )
    result = await db.execute(select(Artifact).where(Artifact.id == artifact_id, tenant_filter))
    artifact = result.scalar_one_or_none()
    if not artifact:
        raise HTTPException(status_code=404, detail="Artifact not found")
    return artifact.analysis_result
