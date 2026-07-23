from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.api.deps import get_analyst_or_admin, get_current_user
from asc_api.core.logging import get_logger
from asc_api.db.session import get_db
from asc_api.models.detection_rule import DetectionRule
from asc_api.models.user import User
from asc_api.services.detection import DetectionResult, evaluate_bulk, evaluate_event
from asc_api.services.fingerprint import analyze_environmental_keying

log = get_logger(__name__)

router = APIRouter(prefix="/detection", tags=["Detection"])


# ─── Request/Response schemas ─────────────────────────────────────────────────


class EventPayload(BaseModel):
    """Single normalized event in ECS-like format."""

    host: str | None = None
    process: str | None = None
    pid: int | None = None
    parent_process: str | None = None
    args: str | None = None
    command_line: str | None = None
    api_call: str | None = None
    action: str | None = None
    syscall: str | None = None
    reg_key: str | None = None
    registry_key: str | None = None
    category: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    protocol: str | None = None
    timestamp: str | None = None


class BulkEvaluationRequest(BaseModel):
    events: list[EventPayload] = Field(..., min_length=1, max_length=500)
    original_analysis_ts: str | None = Field(
        None,
        description="ISO-8601 timestamp of initial artifact analysis (used for deferred traffic detection)",
    )


class FingerprintRequest(BaseModel):
    filename: str = Field(..., min_length=1, max_length=255)
    data_hex: str = Field(
        ...,
        description="Artifact bytes encoded as a hex string (max 64KB for static scan)",
        min_length=2,
    )


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _parse_ts(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Timestamp inválido: {raw!r}. Usar formato ISO-8601.",
        )


def _result_list(results: list[DetectionResult]) -> dict:
    return {
        "total": len(results),
        "results": [r.to_dict() for r in results],
    }


# ─── Endpoints ────────────────────────────────────────────────────────────────


@router.post(
    "/evaluate",
    summary="Evaluar un evento individual contra las reglas de detección",
    dependencies=[Depends(get_analyst_or_admin)],
)
async def evaluate_single_event(
    payload: EventPayload,
    original_analysis_ts: str | None = None,
    current_user: User = Depends(get_analyst_or_admin),
):
    """
    Evaluate one normalized event against all ASC detection rules.

    Rules applied: DET-001 (acord32), DET-002 (Windows hooks),
    DET-003 (registry persistence), DET-004 (deferred traffic).
    """
    ts = _parse_ts(original_analysis_ts)
    event = payload.model_dump(exclude_none=True)
    results = evaluate_event(event, ts)
    log.info("api_detection_evaluate", user=current_user.email, host=payload.host, matches=len(results))
    return _result_list(results)


@router.post(
    "/evaluate/bulk",
    summary="Evaluar múltiples eventos en lote",
    dependencies=[Depends(get_analyst_or_admin)],
)
async def evaluate_bulk_events(
    body: BulkEvaluationRequest,
    current_user: User = Depends(get_analyst_or_admin),
):
    """
    Evaluate up to 500 events in one request.
    Results are deduplicated by rule_id + host.
    """
    ts = _parse_ts(body.original_analysis_ts)
    events = [e.model_dump(exclude_none=True) for e in body.events]
    results = evaluate_bulk(events, ts)
    log.info("api_detection_bulk", user=current_user.email, events=len(events), matches=len(results))
    return {
        **_result_list(results),
        "events_submitted": len(events),
    }


@router.post(
    "/fingerprint",
    summary="Análisis de environmental keying en artefacto binario",
    dependencies=[Depends(get_analyst_or_admin)],
)
async def fingerprint_artifact(
    body: FingerprintRequest,
    current_user: User = Depends(get_analyst_or_admin),
):
    """
    Scan artifact bytes (provided as hex) for PremosCorp-specific
    environmental keying indicators.

    Max input: 64 KB (128 000 hex chars). For larger files, use /analyze/file
    which streams the bytes server-side.
    """
    hex_str = body.data_hex.replace(" ", "").replace("\n", "")
    if len(hex_str) > 131072:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="data_hex excede 64 KB. Use /analyze/file para artefactos grandes.",
        )
    try:
        data = bytes.fromhex(hex_str)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="data_hex no es un string hexadecimal válido.",
        )

    result = analyze_environmental_keying(body.filename, data)
    log.info(
        "api_fingerprint",
        user=current_user.email,
        filename=body.filename,
        detected=result.environmental_keying_detected,
        confidence=result.confidence,
    )
    return result.to_dict()


@router.get(
    "/rules",
    summary="Listar las reglas de detección activas",
    dependencies=[Depends(get_current_user)],
)
async def list_rules(db: AsyncSession = Depends(get_db)):
    """Return metadata for all active detection rules sourced from the DB."""
    result = await db.execute(
        select(DetectionRule).where(DetectionRule.is_active == True).order_by(DetectionRule.rule_id)
    )
    rules = result.scalars().all()
    return {
        "rules": [
            {
                "rule_id": r.rule_id,
                "name": r.name,
                "mitre_ttp": r.mitre_ttp,
                "severity": r.severity,
                "description": r.description,
                "tags": r.tags,
                "risk_score": r.risk_score_default,
            }
            for r in rules
        ],
        "fingerprint_checks": [
            "hostname_pattern",
            "domain_check",
            "registry_pattern",
            "active_directory_enum",
            "network_fingerprinting",
            "timing_evasion",
            "high_entropy_sections",
        ],
    }
