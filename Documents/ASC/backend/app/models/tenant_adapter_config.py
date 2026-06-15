"""
P58 — Tenant Adapter Registry.

Each Tenant can configure its own integration adapters for EDR, firewall,
identity, SIEM and SOAR. This enables true multi-tenant SaaS where each
customer brings their own security stack.

Security design:
  - Non-sensitive settings (host, vsys, indices) stored as JSON.
  - Credentials stored Fernet-encrypted (AES-128-CBC + HMAC-SHA256).
  - Credential is NEVER returned in API responses — only is_configured + hint.
  - Unique constraint: one config per (tenant_id, adapter_type).

Credential storage plan:
  FASE 5 (current): Fernet AES encryption, key derived from SECRET_KEY.
  FASE 6 (future): Vault/AWS Secrets Manager — credential_encrypted becomes
                   a Vault path reference, encryption happens at Vault level.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Boolean, DateTime, JSON, UniqueConstraint, Text
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base

# Supported adapter types and their allowed providers
ADAPTER_TYPES: frozenset[str] = frozenset({
    "edr",       # Endpoint Detection & Response
    "firewall",  # Network firewall / perimeter
    "identity",  # Identity & Access (AD / LDAP)
    "siem",      # Security Information & Event Management
    "soar",      # Security Orchestration, Automation & Response
})

ADAPTER_PROVIDERS: dict[str, frozenset[str]] = {
    "edr":      frozenset({"specter", "none"}),
    "firewall": frozenset({"paloalto", "fortinet", "none"}),
    "identity": frozenset({"active_directory", "none"}),
    "siem":     frozenset({"elasticsearch", "wazuh", "none"}),
    "soar":     frozenset({"thehive", "none"}),
}


class TenantAdapterConfig(Base):
    __tablename__ = "tenant_adapter_configs"

    __table_args__ = (
        UniqueConstraint("tenant_id", "adapter_type", name="uq_tenant_adapter_type"),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(
        String(36), nullable=False, index=True
    )
    # Category: edr | firewall | identity | siem | soar
    adapter_type: Mapped[str] = mapped_column(String(50), nullable=False)
    # Specific provider within the category
    provider: Mapped[str] = mapped_column(String(50), nullable=False, default="none")
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    # Non-sensitive configuration (host, vsys, indices, etc.)
    host: Mapped[str | None] = mapped_column(String(512), nullable=True)
    settings_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # Credential stored Fernet-encrypted — never exposed via API
    credential_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    # First 4 chars of the original credential (display only, never the full value)
    credential_hint: Mapped[str | None] = mapped_column(String(8), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    @property
    def is_configured(self) -> bool:
        """True if a credential has been stored for this adapter."""
        return self.credential_encrypted is not None

    @property
    def display_provider(self) -> str:
        return self.provider if self.provider != "none" else "disabled"
