"""
TheHive Hunt Export Service — P25-TH1

Exports a complete ASC hunt as a TheHive case with observables.

Flow:
  1. Load hunt + findings from DB.
  2. Build a TheHive case body from hunt metadata.
  3. Create the case via TheHiveAdapter.
  4. For each confirmed or high-severity finding with an indicator_value,
     add it as an observable (IoC type → TheHive dataType).
  5. Return {case_id, case_number, observables_added, errors}.

All operations are best-effort: observable creation failures do NOT abort
the export — they are collected in `errors[]` and returned to the caller.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.adapters.thehive import TheHiveAdapter, _IOC_TYPE_MAP
from asc_api.core.tenant_context import get_tenant_id
from asc_api.core.audit import log_security_action
from asc_api.core.logging import get_logger
from asc_api.models.hunt import Hunt, HuntFinding

log = get_logger("asc.thehive_service")

_PRIORITY_SEVERITY = {"low": "low", "medium": "medium", "high": "high", "critical": "critical"}
_FINDING_TYPE_MAP: dict[str, str] = {
    "ip":     "ip",
    "domain": "domain",
    "url":    "url",
    "hash":   "hash",
    "user":   "other",
    "host":   "other",
}


def _hunt_to_alert_dict(hunt: Hunt, findings: list[HuntFinding]) -> dict:
    """Build an ASC alert-like dict from a hunt for TheHiveAdapter.alert_to_case()."""
    confirmed = [f for f in findings if f.is_confirmed]
    high_sev   = [f for f in findings if f.severity in ("high", "critical")]

    affected_hosts: list[str] = list({
        f.affected_host for f in findings if f.affected_host
    })
    ttps: list[str] = list({
        t for f in findings if f.ttps for t in (f.ttps or [])
    })

    # Escalate severity if there are critical/high confirmed findings
    severity = "low"
    if confirmed or high_sev:
        severity = "high"
    if any(f.severity == "critical" for f in confirmed):
        severity = "critical"

    risk_score = min(1.0, len(confirmed) * 0.15 + len(high_sev) * 0.10)

    description_parts = [
        f"**Hunt:** {hunt.name}",
        f"**Status:** {hunt.status}  |  **Priority:** {hunt.priority}",
        f"**Started:** {hunt.started_at.isoformat() if hunt.started_at else 'N/A'}",
        f"**Total findings:** {len(findings)}  |  **Confirmed:** {len(confirmed)}",
        "",
        hunt.description or "No description provided.",
    ]
    if ttps:
        description_parts += ["", "**MITRE ATT&CK TTPs:**", *[f"- {t}" for t in ttps]]
    if affected_hosts:
        description_parts += ["", "**Affected Hosts:**", *[f"- `{h}`" for h in affected_hosts[:20]]]

    return {
        "id": hunt.id,
        "title": f"Hunt: {hunt.name}",
        "description": "\n".join(description_parts),
        "severity": severity,
        "risk_score": risk_score,
        "affected_hosts": affected_hosts,
        "ttps": ttps,
        "status": hunt.status,
    }


def _finding_to_observable(finding: HuntFinding) -> dict | None:
    """Convert a HuntFinding with indicator_value to a TheHive observable body."""
    if not finding.indicator_value:
        return None

    indicator_type = (finding.indicator_type or "other").lower()
    data_type = _FINDING_TYPE_MAP.get(indicator_type, "other")

    tags = ["asc", "hunt-finding"]
    if finding.severity:
        tags.append(f"severity:{finding.severity}")
    if finding.is_confirmed:
        tags.append("confirmed")

    return {
        "dataType": data_type,
        "data": finding.indicator_value,
        "message": finding.title or f"Hunt finding: {indicator_type}",
        "tlp": 2,
        "ioc": True,
        "sighted": finding.is_confirmed,
        "tags": tags,
    }


async def export_hunt_to_thehive(
    db: AsyncSession,
    hunt_id: str,
    *,
    exported_by: str,
    include_unconfirmed: bool = False,
) -> dict:
    """
    Export a hunt to TheHive as a case with observables.

    Parameters
    ----------
    hunt_id          : UUID of the hunt to export.
    exported_by      : Email/username of the analyst triggering the export.
    include_unconfirmed : If True, adds observables for all findings, not just
                         confirmed / high-severity ones.

    Returns
    -------
    {
      success: bool,
      case_id: str,
      case_number: int,
      hunt_id: str,
      observables_added: int,
      errors: list[str],
      exported_at: str,
    }
    """
    adapter = TheHiveAdapter()
    if not adapter.is_configured():
        return {
            "success": False,
            "error": "TheHive adapter not configured. Set THEHIVE_URL and THEHIVE_API_KEY.",
            "hunt_id": hunt_id,
        }

    # Load hunt
    _hstmt = select(Hunt).where(Hunt.id == hunt_id)
    _tid = get_tenant_id()  # SECURITY (S103.8): no exportar hunt de otro tenant a TheHive
    if _tid is not None:
        _hstmt = _hstmt.where(Hunt.tenant_id == _tid)
    hunt_result = await db.execute(_hstmt)
    hunt = hunt_result.scalar_one_or_none()
    if not hunt:
        return {"success": False, "error": f"Hunt {hunt_id} not found", "hunt_id": hunt_id}

    # Load findings
    findings_result = await db.execute(
        select(HuntFinding).where(HuntFinding.hunt_id == hunt_id)
    )
    all_findings = findings_result.scalars().all()

    alert_dict = _hunt_to_alert_dict(hunt, list(all_findings))

    # Create TheHive case
    case_result = await adapter.create_case(alert_dict)
    if not case_result.get("success"):
        log.warning("thehive_export_case_failed", hunt_id=hunt_id, error=case_result.get("error"))
        return {
            "success": False,
            "error": case_result.get("error", "Case creation failed"),
            "hunt_id": hunt_id,
        }

    case_id = case_result["case_id"]
    case_number = case_result.get("case_number", 0)
    errors: list[str] = []
    observables_added = 0

    # Add findings as observables
    for finding in all_findings:
        if finding.is_false_positive:
            continue
        if not include_unconfirmed:
            if not finding.is_confirmed and finding.severity not in ("high", "critical"):
                continue

        obs_body = _finding_to_observable(finding)
        if not obs_body:
            continue

        obs_result = await adapter.create_observable(case_id, obs_body)
        if obs_result.get("success"):
            observables_added += 1
        else:
            errors.append(
                f"Finding {finding.id} ({finding.indicator_value}): {obs_result.get('error')}"
            )

    log_security_action(
        "thehive_hunt_exported",
        user_id=exported_by,
        role="analyst",
        resource="hunt",
        resource_id=hunt_id,
        detail=(
            f"Exported hunt '{hunt.name}' → TheHive case #{case_number} ({case_id}). "
            f"Observables: {observables_added}. Errors: {len(errors)}"
        ),
        status="ok" if not errors else "partial",
    )

    log.info(
        "thehive_export_complete",
        hunt_id=hunt_id,
        case_id=case_id,
        observables_added=observables_added,
        errors=len(errors),
    )

    return {
        "success": True,
        "hunt_id": hunt_id,
        "hunt_name": hunt.name,
        "case_id": case_id,
        "case_number": case_number,
        "observables_added": observables_added,
        "errors": errors,
        "exported_at": datetime.now(timezone.utc).isoformat(),
    }
