"""
P58 — Tenant Adapter Registry API.

Allows admins to configure per-tenant integration adapters (EDR, firewall,
identity, SIEM, SOAR). Each tenant can have at most one config per adapter_type.

Security invariants:
  - Only admin role can write (create/update/delete) adapter configs.
  - Analyst role can read (list/get) configs — credentials are NEVER exposed.
  - Tenant isolation: non-admin users can only access their own tenant's configs.
  - Credentials stored Fernet-encrypted; only credential_hint returned in responses.

Endpoints:
  GET    /adapter-registry/types               — list supported types + providers
  GET    /adapter-registry/{tenant_id}         — list tenant's adapter configs
  GET    /adapter-registry/{tenant_id}/{type}  — get specific adapter config
  POST   /adapter-registry/{tenant_id}         — create adapter config
  PUT    /adapter-registry/{tenant_id}/{type}  — update adapter config
  DELETE /adapter-registry/{tenant_id}/{type}  — remove adapter config
  POST   /adapter-registry/{tenant_id}/{type}/test — live connectivity test
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, model_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.api.deps import get_analyst_or_admin, get_current_admin
from asc_api.core.adapter_crypto import credential_hint as make_hint
from asc_api.core.adapter_crypto import encrypt_credential
from asc_api.core.config import get_settings
from asc_api.db.session import get_db
from asc_api.models.tenant import Tenant
from asc_api.models.tenant_adapter_config import (
    ADAPTER_PROVIDERS,
    ADAPTER_TYPES,
    TenantAdapterConfig,
)

router = APIRouter(prefix="/adapter-registry", tags=["Adapter Registry"])

_settings = get_settings()


# ── Schemas ───────────────────────────────────────────────────────────────────


class AdapterConfigCreate(BaseModel):
    adapter_type: str
    provider: str = "none"
    is_enabled: bool = True
    host: str | None = None
    settings_json: dict[str, Any] | None = None
    credential: str | None = None  # raw credential — encrypted before storage

    @model_validator(mode="after")
    def _validate_type_provider(self) -> AdapterConfigCreate:
        if self.adapter_type not in ADAPTER_TYPES:
            raise ValueError(f"adapter_type must be one of {sorted(ADAPTER_TYPES)}")
        allowed = ADAPTER_PROVIDERS.get(self.adapter_type, frozenset())
        if self.provider not in allowed:
            raise ValueError(
                f"provider '{self.provider}' not valid for type '{self.adapter_type}'. Allowed: {sorted(allowed)}"
            )
        return self


class AdapterConfigUpdate(BaseModel):
    provider: str | None = None
    is_enabled: bool | None = None
    host: str | None = None
    settings_json: dict[str, Any] | None = None
    credential: str | None = None  # None = keep existing; "" = clear credential


class AdapterConfigResponse(BaseModel):
    id: str
    tenant_id: str
    adapter_type: str
    provider: str
    is_enabled: bool
    host: str | None
    settings_json: dict[str, Any] | None
    is_configured: bool
    credential_hint: str | None
    display_provider: str
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class AdapterTypeInfo(BaseModel):
    adapter_type: str
    providers: list[str]
    description: str


# ── Helpers ───────────────────────────────────────────────────────────────────

_TYPE_DESCRIPTIONS: dict[str, str] = {
    "edr": "Endpoint Detection & Response — agent fleet management",
    "firewall": "Network firewall / perimeter — IP/domain blocking",
    "identity": "Identity & Access — Active Directory / LDAP account control",
    "siem": "SIEM — alert/event ingestion and indexing",
    "soar": "SOAR — case management and automated response",
}


async def _get_tenant_or_404(tenant_id: str, db: AsyncSession) -> Tenant:
    result = await db.execute(select(Tenant).where(Tenant.id == tenant_id))
    tenant = result.scalar_one_or_none()
    if not tenant:
        raise HTTPException(status_code=404, detail={"code": "tenant_not_found"})
    return tenant


async def _get_config_or_404(tenant_id: str, adapter_type: str, db: AsyncSession) -> TenantAdapterConfig:
    result = await db.execute(
        select(TenantAdapterConfig).where(
            TenantAdapterConfig.tenant_id == tenant_id,
            TenantAdapterConfig.adapter_type == adapter_type,
        )
    )
    cfg = result.scalar_one_or_none()
    if not cfg:
        raise HTTPException(
            status_code=404,
            detail={"code": "adapter_config_not_found", "adapter_type": adapter_type},
        )
    return cfg


def _to_response(cfg: TenantAdapterConfig) -> AdapterConfigResponse:
    return AdapterConfigResponse(
        id=cfg.id,
        tenant_id=cfg.tenant_id,
        adapter_type=cfg.adapter_type,
        provider=cfg.provider,
        is_enabled=cfg.is_enabled,
        host=cfg.host,
        settings_json=cfg.settings_json,
        is_configured=cfg.is_configured,
        credential_hint=cfg.credential_hint,
        display_provider=cfg.display_provider,
        created_at=cfg.created_at,
        updated_at=cfg.updated_at,
    )


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.get("/types", response_model=list[AdapterTypeInfo])
async def list_adapter_types(
    _current=Depends(get_analyst_or_admin),
) -> list[AdapterTypeInfo]:
    """Return all supported adapter types and their available providers."""
    return [
        AdapterTypeInfo(
            adapter_type=t,
            providers=sorted(ADAPTER_PROVIDERS[t]),
            description=_TYPE_DESCRIPTIONS.get(t, ""),
        )
        for t in sorted(ADAPTER_TYPES)
    ]


@router.get("/{tenant_id}", response_model=list[AdapterConfigResponse])
async def list_tenant_adapters(
    tenant_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_analyst_or_admin),
) -> list[AdapterConfigResponse]:
    """List all adapter configs for a tenant. Credentials are never returned."""
    await _get_tenant_or_404(tenant_id, db)
    result = await db.execute(
        select(TenantAdapterConfig)
        .where(TenantAdapterConfig.tenant_id == tenant_id)
        .order_by(TenantAdapterConfig.adapter_type)
    )
    configs = result.scalars().all()
    return [_to_response(c) for c in configs]


@router.get("/{tenant_id}/{adapter_type}", response_model=AdapterConfigResponse)
async def get_tenant_adapter(
    tenant_id: str,
    adapter_type: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_analyst_or_admin),
) -> AdapterConfigResponse:
    """Get a specific adapter config. Credential is never returned."""
    if adapter_type not in ADAPTER_TYPES:
        raise HTTPException(
            status_code=422,
            detail={"code": "invalid_adapter_type", "valid": sorted(ADAPTER_TYPES)},
        )
    await _get_tenant_or_404(tenant_id, db)
    cfg = await _get_config_or_404(tenant_id, adapter_type, db)
    return _to_response(cfg)


@router.post("/{tenant_id}", response_model=AdapterConfigResponse, status_code=201)
async def create_tenant_adapter(
    tenant_id: str,
    body: AdapterConfigCreate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_admin),
) -> AdapterConfigResponse:
    """Create an adapter config for a tenant. Only one config per adapter_type allowed."""
    await _get_tenant_or_404(tenant_id, db)

    # Enforce uniqueness (UniqueConstraint at DB level; give a readable error here)
    existing = await db.execute(
        select(TenantAdapterConfig).where(
            TenantAdapterConfig.tenant_id == tenant_id,
            TenantAdapterConfig.adapter_type == body.adapter_type,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=409,
            detail={
                "code": "adapter_config_exists",
                "message": f"Adapter '{body.adapter_type}' already configured for this tenant. Use PUT to update.",
            },
        )

    now = datetime.now(UTC)
    encrypted = None
    hint = None
    if body.credential:
        encrypted = encrypt_credential(body.credential, _settings.SECRET_KEY)
        hint = make_hint(body.credential)

    cfg = TenantAdapterConfig(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        adapter_type=body.adapter_type,
        provider=body.provider,
        is_enabled=body.is_enabled,
        host=body.host,
        settings_json=body.settings_json,
        credential_encrypted=encrypted,
        credential_hint=hint,
        created_at=now,
        updated_at=now,
    )
    db.add(cfg)
    await db.commit()
    await db.refresh(cfg)
    return _to_response(cfg)


@router.put("/{tenant_id}/{adapter_type}", response_model=AdapterConfigResponse)
async def update_tenant_adapter(
    tenant_id: str,
    adapter_type: str,
    body: AdapterConfigUpdate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_admin),
) -> AdapterConfigResponse:
    """Update an adapter config. Pass credential=null to keep existing; credential='' to clear."""
    if adapter_type not in ADAPTER_TYPES:
        raise HTTPException(
            status_code=422,
            detail={"code": "invalid_adapter_type", "valid": sorted(ADAPTER_TYPES)},
        )
    await _get_tenant_or_404(tenant_id, db)
    cfg = await _get_config_or_404(tenant_id, adapter_type, db)

    if body.provider is not None:
        allowed = ADAPTER_PROVIDERS.get(adapter_type, frozenset())
        if body.provider not in allowed:
            raise HTTPException(
                status_code=422,
                detail={"code": "invalid_provider", "valid": sorted(allowed)},
            )
        cfg.provider = body.provider
    if body.is_enabled is not None:
        cfg.is_enabled = body.is_enabled
    if body.host is not None:
        cfg.host = body.host
    if body.settings_json is not None:
        cfg.settings_json = body.settings_json

    # credential handling: None → keep; "" → clear; value → encrypt + update hint
    if body.credential is not None:
        if body.credential == "":
            cfg.credential_encrypted = None
            cfg.credential_hint = None
        else:
            cfg.credential_encrypted = encrypt_credential(body.credential, _settings.SECRET_KEY)
            cfg.credential_hint = make_hint(body.credential)

    cfg.updated_at = datetime.now(UTC)
    await db.commit()
    await db.refresh(cfg)
    return _to_response(cfg)


@router.delete("/{tenant_id}/{adapter_type}", status_code=204)
async def delete_tenant_adapter(
    tenant_id: str,
    adapter_type: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_admin),
) -> None:
    """Remove an adapter config and its encrypted credential."""
    if adapter_type not in ADAPTER_TYPES:
        raise HTTPException(
            status_code=422,
            detail={"code": "invalid_adapter_type"},
        )
    await _get_tenant_or_404(tenant_id, db)
    cfg = await _get_config_or_404(tenant_id, adapter_type, db)
    await db.delete(cfg)
    await db.commit()


@router.post("/{tenant_id}/{adapter_type}/test")
async def test_tenant_adapter(
    tenant_id: str,
    adapter_type: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_admin),
) -> dict:
    """
    Test live connectivity for a configured adapter.

    Decrypts the stored credential and dispatches to a provider-specific
    connectivity check:
      fortinet        → GET /api/v2/monitor/sys/status (Bearer token)
      paloalto        → GET /api/?type=version (API key)
      active_directory→ LDAP bind + base search (ldap3)
      elasticsearch   → GET / (HTTP basic auth)
      wazuh           → GET /security/user/authenticate (basic auth)
      thehive         → GET /api/status (Bearer token)
      specter         → GET /api/v1/health (enrollment secret)
    """
    if adapter_type not in ADAPTER_TYPES:
        raise HTTPException(
            status_code=422,
            detail={"code": "invalid_adapter_type"},
        )
    await _get_tenant_or_404(tenant_id, db)
    cfg = await _get_config_or_404(tenant_id, adapter_type, db)

    if not cfg.is_enabled:
        return {
            "status": "skipped",
            "reason": "adapter_disabled",
            "adapter_type": adapter_type,
            "provider": cfg.provider,
        }
    if not cfg.is_configured:
        return {
            "status": "not_configured",
            "reason": "no_credential_stored",
            "adapter_type": adapter_type,
            "provider": cfg.provider,
        }

    from asc_api.core.adapter_crypto import decrypt_credential

    try:
        credential = decrypt_credential(cfg.credential_encrypted, _settings.SECRET_KEY)
    except Exception as exc:
        return {
            "status": "error",
            "reason": "credential_decrypt_failed",
            "detail": str(exc),
            "adapter_type": adapter_type,
            "provider": cfg.provider,
        }

    result = await _live_connectivity_check(cfg, credential)
    return result


async def _live_connectivity_check(cfg, credential: str) -> dict:
    """Dispatch a real connectivity check based on provider."""
    import httpx

    base = {
        "adapter_type": cfg.adapter_type,
        "provider": cfg.provider,
        "host": cfg.host,
    }
    host = (cfg.host or "").rstrip("/")
    settings_json = cfg.settings_json or {}
    timeout = 10.0

    # ── Fortinet FortiGate ────────────────────────────────────────────────────
    if cfg.provider == "fortinet":
        vdom = settings_json.get("vdom", "root")
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=True) as client:
                r = await client.get(
                    f"https://{host}/api/v2/monitor/sys/status",
                    headers={"Authorization": f"Bearer {credential}"},
                    params={"vdom": vdom},
                )
            if r.status_code == 200:
                data = r.json().get("results", {})
                return {
                    **base,
                    "status": "ok",
                    "serial": data.get("Serial-Number"),
                    "version": data.get("Version"),
                    "hostname": data.get("Hostname"),
                }
            return {**base, "status": "error", "http_status": r.status_code, "detail": r.text[:200]}
        except Exception as exc:
            return {**base, "status": "error", "detail": str(exc)}

    # ── Palo Alto Networks PAN-OS ────────────────────────────────────────────
    if cfg.provider == "paloalto":
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=True) as client:
                r = await client.get(
                    f"https://{host}/api/",
                    params={"type": "version", "key": credential},
                )
            if r.status_code == 200 and "success" in r.text:
                return {**base, "status": "ok", "detail": "PAN-OS version command succeeded"}
            return {**base, "status": "error", "http_status": r.status_code, "detail": r.text[:200]}
        except Exception as exc:
            return {**base, "status": "error", "detail": str(exc)}

    # ── Active Directory / LDAP ──────────────────────────────────────────────
    if cfg.provider == "active_directory":
        import asyncio

        bind_dn = settings_json.get("bind_dn", "")
        base_dn = settings_json.get("base_dn", "")
        use_ssl = settings_json.get("use_ssl", True)

        def _ldap_check() -> dict:
            try:
                import ldap3
            except ImportError:
                return {**base, "status": "error", "detail": "ldap3 not installed — run: pip install ldap3"}
            try:
                server = ldap3.Server(host, use_ssl=use_ssl, connect_timeout=timeout)
                with ldap3.Connection(
                    server, user=bind_dn, password=credential, auto_bind=True, read_only=True
                ) as conn:
                    conn.search(
                        base_dn, "(objectClass=domain)", search_scope=ldap3.BASE, attributes=["distinguishedName"]
                    )
                    return {**base, "status": "ok", "server": host, "ssl": use_ssl, "base_dn_found": bool(conn.entries)}
            except Exception as exc:
                return {**base, "status": "error", "detail": str(exc)}

        return await asyncio.to_thread(_ldap_check)

    # ── Elasticsearch ────────────────────────────────────────────────────────
    if cfg.provider == "elasticsearch":
        username = settings_json.get("username", "elastic")
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=False) as client:  # nosec B501  # noqa: S501 — appliance on-prem, cert autofirmado
                r = await client.get(
                    f"https://{host}/",
                    auth=(username, credential),
                )
            if r.status_code == 200:
                data = r.json()
                return {
                    **base,
                    "status": "ok",
                    "cluster_name": data.get("cluster_name"),
                    "version": data.get("version", {}).get("number"),
                }
            return {**base, "status": "error", "http_status": r.status_code, "detail": r.text[:200]}
        except Exception as exc:
            return {**base, "status": "error", "detail": str(exc)}

    # ── Wazuh ───────────────────────────────────────────────────────────────
    if cfg.provider == "wazuh":
        username = settings_json.get("username", "wazuh-wui")
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=False) as client:  # nosec B501  # noqa: S501 — appliance on-prem, cert autofirmado
                r = await client.get(
                    f"https://{host}:55000/security/user/authenticate",
                    auth=(username, credential),
                )
            if r.status_code in (200, 401):
                return {**base, "status": "ok" if r.status_code == 200 else "auth_failed", "http_status": r.status_code}
            return {**base, "status": "error", "http_status": r.status_code, "detail": r.text[:200]}
        except Exception as exc:
            return {**base, "status": "error", "detail": str(exc)}

    # ── TheHive ──────────────────────────────────────────────────────────────
    if cfg.provider == "thehive":
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=True) as client:
                r = await client.get(
                    f"https://{host}/api/status",
                    headers={"Authorization": f"Bearer {credential}"},
                )
            if r.status_code == 200:
                data = r.json()
                return {**base, "status": "ok", "hive_version": data.get("versions", {}).get("TheHive")}
            return {**base, "status": "error", "http_status": r.status_code, "detail": r.text[:200]}
        except Exception as exc:
            return {**base, "status": "error", "detail": str(exc)}

    # ── SPECTER (ASC agent) ───────────────────────────────────────────────────
    if cfg.provider == "specter":
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                r = await client.get(
                    f"https://{host}/api/v1/health",
                    headers={"X-Specter-Secret": credential},
                )
            if r.status_code == 200:
                return {**base, "status": "ok"}
            return {**base, "status": "error", "http_status": r.status_code, "detail": r.text[:200]}
        except Exception as exc:
            return {**base, "status": "error", "detail": str(exc)}

    # ── Provider "none" or unknown ────────────────────────────────────────────
    return {
        **base,
        "status": "skipped",
        "reason": "no_connectivity_check_for_provider",
    }
