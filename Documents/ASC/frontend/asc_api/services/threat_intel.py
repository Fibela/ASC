"""
PremosCorp Threat Intelligence Service — P21-F1

Manages the local TI indicator corpus.  Provides:
  - CRUD for individual indicators
  - Bulk import (list of dicts — from MISP/CSV/manual)
  - Enrichment lookup: given a value, return matching active indicators
  - Hit tracking: every enrichment match bumps hit_count + last_hit_at
  - Expiry purge: soft-delete (active=False) indicators past expires_at

Design principles (Calidad sobre Comodidad):
  - Enrichment is case-insensitive for domains/emails; exact for hashes/IPs
  - Bulk import is idempotent: duplicate (type, value) updates instead of inserting
  - All DB ops are async, no blocking calls
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select, func, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.core.logging import get_logger
from asc_api.models.threat_intel import ThreatIntelIndicator

log = get_logger("asc.threat_intel")

# ── Indicator types that use case-insensitive matching ────────────────────────
_ICASE_TYPES = frozenset({"domain", "email", "url", "file_path", "mutex", "registry_key"})

# ── Valid indicator types ──────────────────────────────────────────────────────
VALID_TYPES = frozenset({
    "ip", "cidr", "asn",
    "domain", "url", "email",
    "hash_md5", "hash_sha1", "hash_sha256",
    "file_path", "mutex", "registry_key", "cve",
})

VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})


# ── Internal helpers ──────────────────────────────────────────────────────────

def _normalize(value: str, indicator_type: str) -> str:
    if indicator_type in _ICASE_TYPES:
        return value.strip().lower()
    return value.strip()


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ── Visibilidad de tenant (S105.1) ───────────────────────────────────────────
# Modelo de 2 CAPAS (aprobado 2026-07-21):
#   CAPA 0 GLOBAL  → tenant_id IS NULL  : corpus compartido, visible a todos.
#   CAPA 2 PRIVADA → tenant_id == <mío> : solo el tenant dueño lo ve/edita.
# La CAPA 1 SHARED (sharing_group_id, grupos tipo ISAC) queda DOCUMENTADA como
# roadmap en docs/roadmap/threat-intel-3-capas.md; se activará al haber 2+ tenants.
# Nota: si tenant_id es None, la rama "== None" colapsa a IS NULL (SQLAlchemy) →
# el scope None ve únicamente la CAPA 0 global, consistente con apply_tenant_filter.

def _visible(tenant_id: str | None):
    """Cláusula de LECTURA: global (NULL) OR propio (== tenant_id)."""
    return or_(
        ThreatIntelIndicator.tenant_id.is_(None),
        ThreatIntelIndicator.tenant_id == tenant_id,
    )


def _own_scope(tenant_id: str | None):
    """Cláusula de ESCRITURA/idempotencia: exactamente el scope del que escribe."""
    if tenant_id is None:
        return ThreatIntelIndicator.tenant_id.is_(None)
    return ThreatIntelIndicator.tenant_id == tenant_id


# ── CRUD ──────────────────────────────────────────────────────────────────────

async def create_indicator(
    db: AsyncSession,
    *,
    indicator_type: str,
    value: str,
    severity: str = "medium",
    confidence: float = 0.5,
    source: str = "internal",
    created_by: str = "system",
    tenant_id: str | None = None,
    threat_actor: str | None = None,
    malware_family: str | None = None,
    campaign: str | None = None,
    ttps: list[str] | None = None,
    tags: list[str] | None = None,
    description: str | None = None,
    source_reference: str | None = None,
    expires_at: datetime | None = None,
) -> ThreatIntelIndicator:
    if indicator_type not in VALID_TYPES:
        raise ValueError(f"Unknown indicator_type '{indicator_type}'. Valid: {sorted(VALID_TYPES)}")
    if severity not in VALID_SEVERITIES:
        raise ValueError(f"Unknown severity '{severity}'. Valid: {sorted(VALID_SEVERITIES)}")
    if not 0.0 <= confidence <= 1.0:
        raise ValueError("confidence must be in [0.0, 1.0]")

    value = _normalize(value, indicator_type)
    now = _now()

    indicator = ThreatIntelIndicator(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        indicator_type=indicator_type,
        value=value,
        severity=severity,
        confidence=confidence,
        source=source,
        created_by=created_by,
        threat_actor=threat_actor,
        malware_family=malware_family,
        campaign=campaign,
        ttps=ttps or [],
        tags=tags or [],
        description=description,
        source_reference=source_reference,
        expires_at=expires_at,
        first_seen=now,
        last_seen=now,
        updated_at=now,
    )
    db.add(indicator)
    await db.commit()
    await db.refresh(indicator)
    log.info("ti_indicator_created", id=indicator.id, type=indicator_type, value=value)
    return indicator


async def get_indicator(
    db: AsyncSession, indicator_id: str, tenant_id: str | None = None
) -> ThreatIntelIndicator | None:
    result = await db.execute(
        select(ThreatIntelIndicator).where(
            ThreatIntelIndicator.id == indicator_id,
            _visible(tenant_id),
        )
    )
    return result.scalar_one_or_none()


async def list_indicators(
    db: AsyncSession,
    *,
    tenant_id: str | None = None,
    indicator_type: str | None = None,
    severity: str | None = None,
    active_only: bool = True,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[ThreatIntelIndicator], int]:
    filters = [_visible(tenant_id)]
    if active_only:
        filters.append(ThreatIntelIndicator.active == True)
    if indicator_type:
        filters.append(ThreatIntelIndicator.indicator_type == indicator_type)
    if severity:
        filters.append(ThreatIntelIndicator.severity == severity)

    q = select(ThreatIntelIndicator).where(*filters) if filters else select(ThreatIntelIndicator)
    total_q = select(func.count()).select_from(
        select(ThreatIntelIndicator).where(*filters).subquery() if filters
        else select(ThreatIntelIndicator).subquery()
    )

    total = (await db.execute(total_q)).scalar_one()
    rows = (await db.execute(q.order_by(ThreatIntelIndicator.last_seen.desc()).limit(limit).offset(offset))).scalars().all()
    return list(rows), total


async def update_indicator(
    db: AsyncSession,
    indicator_id: str,
    updates: dict[str, Any],
    tenant_id: str | None = None,
) -> ThreatIntelIndicator | None:
    indicator = await get_indicator(db, indicator_id, tenant_id)
    if not indicator:
        return None

    allowed = {
        "severity", "confidence", "active", "description", "tags", "ttps",
        "threat_actor", "malware_family", "campaign", "source_reference", "expires_at",
    }
    for k, v in updates.items():
        if k in allowed:
            setattr(indicator, k, v)

    indicator.updated_at = _now()
    await db.commit()
    await db.refresh(indicator)
    log.info("ti_indicator_updated", id=indicator_id, fields=list(updates.keys()))
    return indicator


async def delete_indicator(
    db: AsyncSession, indicator_id: str, tenant_id: str | None = None
) -> bool:
    indicator = await get_indicator(db, indicator_id, tenant_id)
    if not indicator:
        return False
    indicator.active = False
    indicator.updated_at = _now()
    await db.commit()
    log.info("ti_indicator_deactivated", id=indicator_id)
    return True


# ── Bulk import ───────────────────────────────────────────────────────────────

async def bulk_import(
    db: AsyncSession,
    items: list[dict[str, Any]],
    created_by: str = "system",
    tenant_id: str | None = None,
) -> dict[str, int]:
    created = updated = skipped = 0
    now = _now()

    for item in items:
        try:
            itype = str(item.get("indicator_type", "")).strip()
            value = str(item.get("value", "")).strip()
            if not itype or not value or itype not in VALID_TYPES:
                skipped += 1
                continue

            value = _normalize(value, itype)

            # Idempotent: update existing (type, value) pair
            result = await db.execute(
                select(ThreatIntelIndicator).where(
                    ThreatIntelIndicator.indicator_type == itype,
                    ThreatIntelIndicator.value == value,
                    _own_scope(tenant_id),
                )
            )
            existing = result.scalar_one_or_none()

            if existing:
                existing.last_seen = now
                existing.updated_at = now
                existing.active = True
                if "severity" in item and item["severity"] in VALID_SEVERITIES:
                    existing.severity = item["severity"]
                if "confidence" in item:
                    try:
                        c = float(item["confidence"])
                        if 0.0 <= c <= 1.0:
                            existing.confidence = c
                    except (TypeError, ValueError):
                        pass
                updated += 1
            else:
                severity = item.get("severity", "medium")
                if severity not in VALID_SEVERITIES:
                    severity = "medium"
                confidence = 0.5
                try:
                    confidence = max(0.0, min(1.0, float(item.get("confidence", 0.5))))
                except (TypeError, ValueError):
                    pass

                ind = ThreatIntelIndicator(
                    id=str(uuid.uuid4()),
                    tenant_id=tenant_id,
                    indicator_type=itype,
                    value=value,
                    severity=severity,
                    confidence=confidence,
                    source=str(item.get("source", "bulk_import")),
                    created_by=created_by,
                    threat_actor=item.get("threat_actor"),
                    malware_family=item.get("malware_family"),
                    campaign=item.get("campaign"),
                    ttps=item.get("ttps") or [],
                    tags=item.get("tags") or [],
                    description=item.get("description"),
                    source_reference=item.get("source_reference"),
                    first_seen=now,
                    last_seen=now,
                    updated_at=now,
                )
                db.add(ind)
                created += 1
        except Exception as exc:
            log.warning("ti_bulk_import_item_error", error=str(exc))
            skipped += 1

    await db.commit()
    log.info("ti_bulk_import_done", created=created, updated=updated, skipped=skipped)
    return {"created": created, "updated": updated, "skipped": skipped, "total": len(items)}


# ── Enrichment ────────────────────────────────────────────────────────────────

async def enrich(
    db: AsyncSession,
    value: str,
    indicator_type: str | None = None,
    *,
    tenant_id: str | None = None,
    track_hit: bool = True,
) -> list[ThreatIntelIndicator]:
    """
    Look up a value against the active TI corpus.

    Returns all matching active indicators (may be more than one if the same
    value appears in multiple sources with different attribution).
    Automatically normalizes the value for case-insensitive types.
    Bumps hit_count + last_hit_at on every match when track_hit=True.
    """
    now = _now()
    value_stripped = value.strip()

    # Build candidate queries — try exact + normalized
    candidates: list[str] = [value_stripped]
    if indicator_type and indicator_type in _ICASE_TYPES:
        candidates.append(value_stripped.lower())
    elif not indicator_type:
        candidates.append(value_stripped.lower())

    filters: list = [
        _visible(tenant_id),
        ThreatIntelIndicator.active == True,
        or_(*(ThreatIntelIndicator.value == c for c in set(candidates))),
    ]
    if indicator_type:
        filters.append(ThreatIntelIndicator.indicator_type == indicator_type)

    # Filter out expired indicators
    filters.append(
        or_(
            ThreatIntelIndicator.expires_at == None,
            ThreatIntelIndicator.expires_at > now,
        )
    )

    result = await db.execute(
        select(ThreatIntelIndicator).where(and_(*filters))
    )
    matches = result.scalars().all()

    if matches and track_hit:
        for m in matches:
            m.hit_count += 1
            m.last_hit_at = now
            m.last_seen = now
        await db.commit()

    log.info("ti_enrich", value=value_stripped, matches=len(matches))
    return list(matches)


async def enrich_bulk(
    db: AsyncSession,
    values: list[dict[str, str]],
    tenant_id: str | None = None,
) -> dict[str, list[dict]]:
    """
    Enrich multiple values in one call.
    Input: [{"value": "1.2.3.4", "indicator_type": "ip"}, ...]
    Output: {"1.2.3.4": [<indicator dicts>], ...}
    """
    results: dict[str, list[dict]] = {}
    for item in values:
        v = item.get("value", "")
        t = item.get("indicator_type")
        if not v:
            continue
        matches = await enrich(db, v, t, tenant_id=tenant_id, track_hit=True)
        results[v] = [_indicator_to_dict(m) for m in matches]
    return results


def _indicator_to_dict(ind: ThreatIntelIndicator) -> dict:
    return {
        "id": ind.id,
        "indicator_type": ind.indicator_type,
        "value": ind.value,
        "severity": ind.severity,
        "confidence": ind.confidence,
        "threat_actor": ind.threat_actor,
        "malware_family": ind.malware_family,
        "campaign": ind.campaign,
        "ttps": ind.ttps,
        "tags": ind.tags,
        "source": ind.source,
        "description": ind.description,
        "hit_count": ind.hit_count,
        "first_seen": ind.first_seen.isoformat() if ind.first_seen else None,
        "last_seen": ind.last_seen.isoformat() if ind.last_seen else None,
    }


# ── Stats ─────────────────────────────────────────────────────────────────────

async def get_stats(db: AsyncSession, tenant_id: str | None = None) -> dict:
    total = (await db.execute(select(func.count(ThreatIntelIndicator.id)).where(_visible(tenant_id)))).scalar_one()
    active = (await db.execute(
        select(func.count(ThreatIntelIndicator.id)).where(_visible(tenant_id), ThreatIntelIndicator.active == True)
    )).scalar_one()

    by_type_rows = (await db.execute(
        select(ThreatIntelIndicator.indicator_type, func.count(ThreatIntelIndicator.id))
        .where(_visible(tenant_id), ThreatIntelIndicator.active == True)
        .group_by(ThreatIntelIndicator.indicator_type)
    )).all()

    by_severity_rows = (await db.execute(
        select(ThreatIntelIndicator.severity, func.count(ThreatIntelIndicator.id))
        .where(_visible(tenant_id), ThreatIntelIndicator.active == True)
        .group_by(ThreatIntelIndicator.severity)
    )).all()

    top_hits = (await db.execute(
        select(ThreatIntelIndicator)
        .where(_visible(tenant_id), ThreatIntelIndicator.active == True, ThreatIntelIndicator.hit_count > 0)
        .order_by(ThreatIntelIndicator.hit_count.desc())
        .limit(10)
    )).scalars().all()

    return {
        "total": total,
        "active": active,
        "inactive": total - active,
        "by_type": dict(by_type_rows),
        "by_severity": dict(by_severity_rows),
        "top_hits": [_indicator_to_dict(i) for i in top_hits],
    }
