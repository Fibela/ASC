"""
Adapters REST API â€” SIEM/EDR/SOAR/Firewall/IAM integration endpoints.

All endpoints require JWT authentication (analyst+ role).
Adapters that are not configured return HTTP 503 with a clear message.

Routes:
  GET  /adapters/                                    â€” list all adapters + configuration status
  GET  /adapters/{adapter}/status                    â€” live connection test for one adapter
  POST /adapters/elk/push/alert/{alert_id}           â€” index alert into Elasticsearch
  POST /adapters/elk/push/event/{event_id}           â€” index event into Elasticsearch
  POST /adapters/elk/pull/events                     â€” pull events from ELK into ASC
  POST /adapters/wazuh/pull/alerts                   â€” pull Wazuh alerts and ingest into ASC
  GET  /adapters/wazuh/agents                        â€” list active Wazuh agents
  POST /adapters/thehive/cases                       â€” create TheHive case from ASC alert
  POST /adapters/thehive/cases/{case_id}/observables â€” add IoC as observable
  GET  /adapters/thehive/cases/{case_id}             â€” get TheHive case status
  POST /adapters/firewall/block/ip                   â€” block IP via active firewall adapter
  POST /adapters/firewall/unblock/ip                 â€” unblock IP via active firewall adapter
  POST /adapters/firewall/block/domain               â€” block domain via active firewall adapter
  POST /adapters/firewall/unblock/domain             â€” unblock domain via active firewall adapter
  POST /adapters/identity/disable                    â€” disable AD account
  POST /adapters/identity/enable                     â€” enable AD account
  POST /adapters/identity/force-reset                â€” force password reset for AD account
  POST /adapters/identity/quarantine                 â€” move AD account to quarantine OU
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timezone, timedelta
from pydantic import BaseModel

from asc_api.db.session import get_db
from asc_api.models.alert import Alert
from asc_api.models.event import Event
from asc_api.models.ioc   import IoC
from asc_api.models.user  import User
from asc_api.api.deps import get_analyst_or_admin
from asc_api.adapters import (
    ELKAdapter, WazuhAdapter, TheHiveAdapter, ADAPTERS,
    PaloAltoAdapter, FortinetAdapter, ActiveDirectoryAdapter,
    get_firewall_adapter, get_identity_adapter,
)

router = APIRouter(prefix="/adapters", tags=["Adapters â€” SIEM/EDR/SOAR"])


# â”€â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _raise_if_failed(result: dict, http_status: int = 503) -> None:
    """Raise HTTPException if adapter call failed."""
    if not result.get("success"):
        raise HTTPException(
            status_code=http_status,
            detail=result.get("error", "Adapter call failed"),
        )


def _alert_to_dict(a: Alert) -> dict:
    return {
        "id":              a.id,
        "title":           a.title,
        "description":     a.description,
        "severity":        a.severity,
        "status":          a.status,
        "risk_score":      a.risk_score,
        "ttps":            a.ttps or [],
        "affected_hosts":  a.affected_hosts or [],
        "detected_at":     a.detected_at.isoformat() if a.detected_at else None,
        "acknowledged_at": a.acknowledged_at.isoformat() if a.acknowledged_at else None,
        "resolved_at":     a.resolved_at.isoformat() if a.resolved_at else None,
    }


def _event_to_dict(e: Event) -> dict:
    return {
        "id":        e.id,
        "timestamp": e.timestamp.isoformat() if e.timestamp else None,
        "source":    e.source,
        "category":  e.category,
        "action":    e.action,
        "host":      e.host,
        "severity":  e.severity,
        "risk_score": e.risk_score,
    }


def _ioc_to_dict(i: IoC) -> dict:
    return {
        "id":          i.id,
        "ioc_type":    i.ioc_type,
        "value":       i.value,
        "description": getattr(i, "description", ""),
        "threat_type": getattr(i, "threat_type", ""),
        "confidence":  i.confidence,
        "hit_count":   i.hit_count,
    }


# â”€â”€â”€ Models â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class PullEventsRequest(BaseModel):
    since_hours: int = 1
    size: int = 100


class WazuhPullRequest(BaseModel):
    since_hours: int = 1
    limit: int = 100


class TheHiveCaseRequest(BaseModel):
    alert_id: str


class FirewallIPRequest(BaseModel):
    ip: str
    reason: str = ""


class FirewallDomainRequest(BaseModel):
    domain: str
    reason: str = ""


class IdentityAccountRequest(BaseModel):
    username: str
    domain: str
    reason: str = ""


# â”€â”€â”€ Adapter catalog â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@router.get("", summary="List all adapters and their configuration status")
async def list_adapters(_: User = Depends(get_analyst_or_admin)):
    elk      = ELKAdapter()
    wazuh    = WazuhAdapter()
    thehive  = TheHiveAdapter()
    paloalto = PaloAltoAdapter()
    fortinet = FortinetAdapter()
    ad       = ActiveDirectoryAdapter()
    return {
        "adapters": [
            {
                "name":         "elk",
                "label":        "Elasticsearch / ELK Stack",
                "type":         "SIEM",
                "configured":   elk.is_configured(),
                "description":  "Index alerts and events into Elasticsearch; pull events for ingestion.",
            },
            {
                "name":         "wazuh",
                "label":        "Wazuh Manager",
                "type":         "EDR/HIDS",
                "configured":   wazuh.is_configured(),
                "description":  "Pull Wazuh HIDS alerts and query agent inventory.",
            },
            {
                "name":         "thehive",
                "label":        "TheHive 5.x",
                "type":         "SOAR",
                "configured":   thehive.is_configured(),
                "description":  "Create cases and observables from ASC alerts and IoCs.",
            },
            {
                "name":         "paloalto",
                "label":        "Palo Alto PAN-OS",
                "type":         "Firewall",
                "configured":   paloalto.is_configured(),
                "description":  "Block/unblock IPs and domains via PAN-OS XML API (preferred firewall).",
            },
            {
                "name":         "fortinet",
                "label":        "Fortinet FortiGate",
                "type":         "Firewall",
                "configured":   fortinet.is_configured(),
                "description":  "Block/unblock IPs and domains via FortiOS REST API (fallback firewall).",
            },
            {
                "name":         "active_directory",
                "label":        "Active Directory",
                "type":         "IAM",
                "configured":   ad.is_configured(),
                "description":  "Disable accounts, force password resets, and quarantine users in AD.",
            },
        ]
    }


@router.get("/{adapter}/status", summary="Live connection test for one adapter")
async def adapter_status(adapter: str, _: User = Depends(get_analyst_or_admin)):
    if adapter not in ADAPTERS:
        raise HTTPException(status_code=404, detail=f"Unknown adapter: {adapter}")
    instance = ADAPTERS[adapter]()
    if not instance.is_configured():
        raise HTTPException(
            status_code=503,
            detail=f"Adapter '{adapter}' is not configured. Set required environment variables.",
        )
    result = await instance.test_connection()
    if not result.get("success"):
        raise HTTPException(status_code=502, detail=result.get("error", "Connection failed"))
    return result


# â”€â”€â”€ ELK endpoints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@router.post("/elk/push/alert/{alert_id}", summary="Push ASC alert to Elasticsearch")
async def elk_push_alert(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_analyst_or_admin),
):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert  = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    adapter = ELKAdapter()
    if not adapter.is_configured():
        raise HTTPException(status_code=503, detail="ELK adapter not configured")

    outcome = await adapter.push_alert(_alert_to_dict(alert))
    _raise_if_failed(outcome, http_status=502)
    return outcome


@router.post("/elk/push/event/{event_id}", summary="Push ASC event to Elasticsearch")
async def elk_push_event(
    event_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_analyst_or_admin),
):
    result = await db.execute(select(Event).where(Event.id == event_id))
    event  = result.scalar_one_or_none()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    adapter = ELKAdapter()
    if not adapter.is_configured():
        raise HTTPException(status_code=503, detail="ELK adapter not configured")

    outcome = await adapter.push_event(_event_to_dict(event))
    _raise_if_failed(outcome, http_status=502)
    return outcome


@router.post("/elk/pull/events", summary="Pull events from Elasticsearch into ASC")
async def elk_pull_events(
    body: PullEventsRequest,
    _: User = Depends(get_analyst_or_admin),
):
    since   = datetime.now(timezone.utc) - timedelta(hours=body.since_hours)
    adapter = ELKAdapter()
    if not adapter.is_configured():
        raise HTTPException(status_code=503, detail="ELK adapter not configured")

    outcome = await adapter.search_events(since=since, size=body.size)
    _raise_if_failed(outcome, http_status=502)
    return outcome


# â”€â”€â”€ Wazuh endpoints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@router.post("/wazuh/pull/alerts", summary="Pull Wazuh HIDS alerts and return as ASC events")
async def wazuh_pull_alerts(
    body: WazuhPullRequest,
    _: User = Depends(get_analyst_or_admin),
):
    since   = datetime.now(timezone.utc) - timedelta(hours=body.since_hours)
    adapter = WazuhAdapter()
    if not adapter.is_configured():
        raise HTTPException(status_code=503, detail="Wazuh adapter not configured")

    outcome = await adapter.get_alerts(since=since, limit=body.limit)
    _raise_if_failed(outcome, http_status=502)
    return outcome


@router.get("/wazuh/agents", summary="List active Wazuh agents")
async def wazuh_agents(
    status: str = Query("active", description="Agent status filter"),
    _: User = Depends(get_analyst_or_admin),
):
    adapter = WazuhAdapter()
    if not adapter.is_configured():
        raise HTTPException(status_code=503, detail="Wazuh adapter not configured")

    outcome = await adapter.get_agents(status=status)
    _raise_if_failed(outcome, http_status=502)
    return outcome


# â”€â”€â”€ TheHive endpoints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@router.post("/thehive/cases", summary="Create TheHive case from ASC alert")
async def thehive_create_case(
    body: TheHiveCaseRequest,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_analyst_or_admin),
):
    result = await db.execute(select(Alert).where(Alert.id == body.alert_id))
    alert  = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    adapter = TheHiveAdapter()
    if not adapter.is_configured():
        raise HTTPException(status_code=503, detail="TheHive adapter not configured")

    outcome = await adapter.create_case(_alert_to_dict(alert))
    _raise_if_failed(outcome, http_status=502)
    return outcome


@router.post(
    "/thehive/cases/{case_id}/observables",
    summary="Add an ASC IoC as observable to a TheHive case",
)
async def thehive_add_observable(
    case_id: str,
    ioc_id: str = Query(..., description="ASC IoC ID"),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_analyst_or_admin),
):
    result = await db.execute(select(IoC).where(IoC.id == ioc_id))
    ioc    = result.scalar_one_or_none()
    if not ioc:
        raise HTTPException(status_code=404, detail="IoC not found")

    adapter = TheHiveAdapter()
    if not adapter.is_configured():
        raise HTTPException(status_code=503, detail="TheHive adapter not configured")

    outcome = await adapter.create_observable(case_id, _ioc_to_dict(ioc))
    _raise_if_failed(outcome, http_status=502)
    return outcome


@router.get("/thehive/cases/{case_id}", summary="Get TheHive case status")
async def thehive_get_case(
    case_id: str,
    _: User = Depends(get_analyst_or_admin),
):
    adapter = TheHiveAdapter()
    if not adapter.is_configured():
        raise HTTPException(status_code=503, detail="TheHive adapter not configured")

    outcome = await adapter.get_case(case_id)
    if not outcome.get("success"):
        status_code = 404 if "not found" in (outcome.get("error") or "").lower() else 502
        raise HTTPException(status_code=status_code, detail=outcome.get("error"))
    return outcome


@router.post("/thehive/hunt/{hunt_id}", summary="Export a hunt to TheHive as a case with observables")
async def thehive_export_hunt(
    hunt_id: str,
    include_unconfirmed: bool = Query(False, description="Include unconfirmed findings as observables"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_analyst_or_admin),
):
    from asc_api.services.thehive_service import export_hunt_to_thehive

    result = await export_hunt_to_thehive(
        db,
        hunt_id,
        exported_by=current_user.email,
        include_unconfirmed=include_unconfirmed,
    )
    if not result.get("success"):
        error = result.get("error", "Export failed")
        status_code = 404 if "not found" in error.lower() else 503
        raise HTTPException(status_code=status_code, detail=error)
    return result


# â”€â”€â”€ Firewall endpoints (F1 â€” PAN-OS preferred, Fortinet fallback) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

_NO_FIREWALL = (
    "No firewall adapter configured. "
    "Set PALOALTO_* or FORTINET_* environment variables."
)


@router.post("/firewall/block/ip", summary="Block an IP via the active firewall adapter")
async def firewall_block_ip(
    body: FirewallIPRequest,
    _: User = Depends(get_analyst_or_admin),
):
    adapter = get_firewall_adapter()
    if adapter is None:
        raise HTTPException(status_code=503, detail=_NO_FIREWALL)
    outcome = await adapter.block_ip(body.ip, reason=body.reason)
    _raise_if_failed(outcome, http_status=502)
    return outcome


@router.post("/firewall/unblock/ip", summary="Unblock an IP via the active firewall adapter")
async def firewall_unblock_ip(
    body: FirewallIPRequest,
    _: User = Depends(get_analyst_or_admin),
):
    adapter = get_firewall_adapter()
    if adapter is None:
        raise HTTPException(status_code=503, detail=_NO_FIREWALL)
    outcome = await adapter.unblock_ip(body.ip)
    _raise_if_failed(outcome, http_status=502)
    return outcome


@router.post("/firewall/block/domain", summary="Block a domain via the active firewall adapter")
async def firewall_block_domain(
    body: FirewallDomainRequest,
    _: User = Depends(get_analyst_or_admin),
):
    adapter = get_firewall_adapter()
    if adapter is None:
        raise HTTPException(status_code=503, detail=_NO_FIREWALL)
    outcome = await adapter.block_domain(body.domain, reason=body.reason)
    _raise_if_failed(outcome, http_status=502)
    return outcome


@router.post("/firewall/unblock/domain", summary="Unblock a domain via the active firewall adapter")
async def firewall_unblock_domain(
    body: FirewallDomainRequest,
    _: User = Depends(get_analyst_or_admin),
):
    adapter = get_firewall_adapter()
    if adapter is None:
        raise HTTPException(status_code=503, detail=_NO_FIREWALL)
    outcome = await adapter.unblock_domain(body.domain)
    _raise_if_failed(outcome, http_status=502)
    return outcome


# â”€â”€â”€ Identity endpoints (F1 â€” Active Directory) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

_NO_IDENTITY = (
    "Active Directory adapter not configured. "
    "Set AD_* environment variables."
)


@router.post("/identity/disable", summary="Disable an Active Directory account")
async def identity_disable(
    body: IdentityAccountRequest,
    _: User = Depends(get_analyst_or_admin),
):
    adapter = get_identity_adapter()
    if adapter is None:
        raise HTTPException(status_code=503, detail=_NO_IDENTITY)
    outcome = await adapter.disable_account(body.username, body.domain, reason=body.reason)
    _raise_if_failed(outcome, http_status=502)
    return outcome


@router.post("/identity/enable", summary="Enable an Active Directory account")
async def identity_enable(
    body: IdentityAccountRequest,
    _: User = Depends(get_analyst_or_admin),
):
    adapter = get_identity_adapter()
    if adapter is None:
        raise HTTPException(status_code=503, detail=_NO_IDENTITY)
    outcome = await adapter.enable_account(body.username, body.domain)
    _raise_if_failed(outcome, http_status=502)
    return outcome


@router.post("/identity/force-reset", summary="Force password reset for an AD account")
async def identity_force_reset(
    body: IdentityAccountRequest,
    _: User = Depends(get_analyst_or_admin),
):
    adapter = get_identity_adapter()
    if adapter is None:
        raise HTTPException(status_code=503, detail=_NO_IDENTITY)
    outcome = await adapter.force_password_reset(body.username, body.domain)
    _raise_if_failed(outcome, http_status=502)
    return outcome


@router.post("/identity/quarantine", summary="Move an AD account to the quarantine OU")
async def identity_quarantine(
    body: IdentityAccountRequest,
    _: User = Depends(get_analyst_or_admin),
):
    adapter = get_identity_adapter()
    if adapter is None:
        raise HTTPException(status_code=503, detail=_NO_IDENTITY)
    outcome = await adapter.move_to_quarantine_ou(body.username, body.domain)
    _raise_if_failed(outcome, http_status=502)
    return outcome


@router.get("/identity/search", summary="Search for an AD user by sAMAccountName")
async def identity_search_user(
    username: str = Query(..., description="sAMAccountName (Windows login name)"),
    _: User = Depends(get_analyst_or_admin),
):
    adapter = get_identity_adapter()
    if adapter is None:
        raise HTTPException(status_code=503, detail=_NO_IDENTITY)
    outcome = await adapter.search_user(username)
    if not outcome.get("success"):
        status_code = 404 if "user_not_found" in (outcome.get("error") or "") else 502
        raise HTTPException(status_code=status_code, detail=outcome.get("error"))
    return outcome


@router.get("/identity/groups/{group_name}/members", summary="List members of an AD group by CN")
async def identity_group_members(
    group_name: str,
    _: User = Depends(get_analyst_or_admin),
):
    adapter = get_identity_adapter()
    if adapter is None:
        raise HTTPException(status_code=503, detail=_NO_IDENTITY)
    outcome = await adapter.list_group_members(group_name)
    if not outcome.get("success"):
        status_code = 404 if "group_not_found" in (outcome.get("error") or "") else 502
        raise HTTPException(status_code=status_code, detail=outcome.get("error"))
    return outcome
