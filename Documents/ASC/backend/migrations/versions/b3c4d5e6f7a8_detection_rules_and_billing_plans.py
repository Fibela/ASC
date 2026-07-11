"""detection_rules_and_billing_plans — eliminate hardcoded catalogs

Revision ID: b3c4d5e6f7a8
Revises: z6t89u7x1s14
Create Date: 2026-07-10

Creates two catalog tables that replace hardcoded Python dicts:
  - detection_rules: DET-001…DET-004 seeded from the original spec
  - billing_plans:   free / pro / enterprise seeded from the original _PLANS list

These tables are append-only catalogs; existing rows are never deleted by
application code — only deactivated via is_active=False so audit trails remain.
"""
import uuid
from datetime import datetime, timezone

import sqlalchemy as sa
from alembic import op

revision = "b3c4d5e6f7a8"
down_revision = "z6t89u7x1s14"
branch_labels = None
depends_on = None

_NOW = datetime(2026, 7, 10, 0, 0, 0, tzinfo=timezone.utc)


def upgrade() -> None:
    # ── detection_rules ──────────────────────────────────────────────────────
    op.create_table(
        "detection_rules",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("rule_id", sa.String(20), nullable=False, unique=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("mitre_ttp", sa.String(50), nullable=False),
        sa.Column("severity", sa.String(30), nullable=False),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("tags", sa.JSON, nullable=False, server_default="[]"),
        sa.Column("risk_score_default", sa.Float, nullable=False, server_default="0.5"),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_detection_rules_rule_id", "detection_rules", ["rule_id"])

    # ── billing_plans ────────────────────────────────────────────────────────
    op.create_table(
        "billing_plans",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("slug", sa.String(50), nullable=False, unique=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("tagline", sa.Text, nullable=True),
        sa.Column("cta", sa.String(100), nullable=True),
        sa.Column("price_usd", sa.Integer, nullable=True),
        sa.Column("price_usd_annual", sa.Integer, nullable=True),
        sa.Column("billing_period", sa.String(20), nullable=False, server_default="month"),
        sa.Column("highlight", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("features", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("features_list", sa.JSON, nullable=False, server_default="[]"),
        sa.Column("sort_order", sa.Integer, nullable=False, server_default="0"),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_billing_plans_slug", "billing_plans", ["slug"])

    # ── Seed: detection rules (DET-001 … DET-004) ────────────────────────────
    rules_tbl = sa.table(
        "detection_rules",
        sa.column("id", sa.String),
        sa.column("rule_id", sa.String),
        sa.column("name", sa.String),
        sa.column("mitre_ttp", sa.String),
        sa.column("severity", sa.String),
        sa.column("description", sa.Text),
        sa.column("tags", sa.JSON),
        sa.column("risk_score_default", sa.Float),
        sa.column("is_active", sa.Boolean),
        sa.column("created_at", sa.DateTime),
        sa.column("updated_at", sa.DateTime),
    )
    op.bulk_insert(rules_tbl, [
        {
            "id": str(uuid.uuid4()),
            "rule_id": "DET-001",
            "name": "Suspicious acord32.exe Execution",
            "mitre_ttp": "T1036.005",
            "severity": "critical/high",
            "description": (
                "acord32.exe ejecutado con parámetros ocultos (/s, /o, /q, /silent, /noui). "
                "acord32.exe es el visor legítimo de formularios ACORD; estos parámetros no estándar "
                "son utilizados por malware que suplanta este binario."
            ),
            "tags": ["masquerading", "process", "windows"],
            "risk_score_default": 0.88,
            "is_active": True,
            "created_at": _NOW,
            "updated_at": _NOW,
        },
        {
            "id": str(uuid.uuid4()),
            "rule_id": "DET-002",
            "name": "Windows Hook API Detected",
            "mitre_ttp": "T1056.001",
            "severity": "critical/medium",
            "description": (
                "Uso de SetWindowsHookExW/A o FindWindowW/A detectado — indica posible keylogger "
                "o inyección de UI. Técnica común en malware de espionaje e infostealer."
            ),
            "tags": ["keylogger", "hook", "windows", "credential-access"],
            "risk_score_default": 0.80,
            "is_active": True,
            "created_at": _NOW,
            "updated_at": _NOW,
        },
        {
            "id": str(uuid.uuid4()),
            "rule_id": "DET-003",
            "name": "Registry Persistence Mechanism",
            "mitre_ttp": "T1547.001",
            "severity": "high",
            "description": (
                "Escritura o eliminación en claves Run/RunOnce del registro de Windows para "
                "establecer persistencia. Técnica ampliamente utilizada por ransomware y APTs."
            ),
            "tags": ["persistence", "registry", "windows", "boot-autostart"],
            "risk_score_default": 0.75,
            "is_active": True,
            "created_at": _NOW,
            "updated_at": _NOW,
        },
        {
            "id": str(uuid.uuid4()),
            "rule_id": "DET-004",
            "name": "Deferred Network Traffic",
            "mitre_ttp": "T1071.001",
            "severity": "critical/high",
            "description": (
                "Conexión de red detectada más de 2 horas después del análisis inicial del artefacto. "
                "Patrón característico de implantes C2 con beacon diferido para evadir sandbox de corta duración."
            ),
            "tags": ["c2", "network", "beacon", "evasion"],
            "risk_score_default": 0.82,
            "is_active": True,
            "created_at": _NOW,
            "updated_at": _NOW,
        },
    ])

    # ── Seed: billing plans (free / pro / enterprise) ────────────────────────
    plans_tbl = sa.table(
        "billing_plans",
        sa.column("id", sa.String),
        sa.column("slug", sa.String),
        sa.column("name", sa.String),
        sa.column("tagline", sa.Text),
        sa.column("cta", sa.String),
        sa.column("price_usd", sa.Integer),
        sa.column("price_usd_annual", sa.Integer),
        sa.column("billing_period", sa.String),
        sa.column("highlight", sa.Boolean),
        sa.column("features", sa.JSON),
        sa.column("features_list", sa.JSON),
        sa.column("sort_order", sa.Integer),
        sa.column("is_active", sa.Boolean),
        sa.column("created_at", sa.DateTime),
        sa.column("updated_at", sa.DateTime),
    )
    op.bulk_insert(plans_tbl, [
        {
            "id": str(uuid.uuid4()),
            "slug": "free",
            "name": "Free",
            "tagline": "Para equipos que empiezan en ciberseguridad",
            "cta": "Comenzar gratis",
            "price_usd": 0,
            "price_usd_annual": 0,
            "billing_period": "month",
            "highlight": False,
            "features": {
                "max_users": 5,
                "max_api_keys_per_user": 3,
                "data_retention_days": 30,
                "siem_integration": False,
                "threat_hunting": False,
                "executive_reports": False,
                "soar_playbooks": False,
                "correlation_engine": False,
                "artifact_analysis": True,
                "honeypot": False,
                "custom_adapters": False,
                "audit_log": True,
                "support": "community",
                "uptime_sla": None,
            },
            "features_list": [
                "Monitoreo de eventos en tiempo real",
                "Detección básica de alertas",
                "Análisis de artefactos (5/mes)",
                "Auditoría de acciones",
                "Panel SOC unificado",
                "5 usuarios · 3 API keys por usuario",
                "30 días de retención de datos",
                "Soporte comunidad",
            ],
            "sort_order": 0,
            "is_active": True,
            "created_at": _NOW,
            "updated_at": _NOW,
        },
        {
            "id": str(uuid.uuid4()),
            "slug": "pro",
            "name": "Pro",
            "tagline": "El stack SOC completo para equipos de seguridad activos",
            "cta": "Empezar con Pro",
            "price_usd": 299,
            "price_usd_annual": 239,
            "billing_period": "month",
            "highlight": True,
            "features": {
                "max_users": 50,
                "max_api_keys_per_user": 20,
                "data_retention_days": 90,
                "siem_integration": True,
                "threat_hunting": True,
                "executive_reports": True,
                "soar_playbooks": True,
                "correlation_engine": True,
                "artifact_analysis": True,
                "honeypot": True,
                "custom_adapters": False,
                "audit_log": True,
                "support": "email (24 h SLA)",
                "uptime_sla": "99.5%",
            },
            "features_list": [
                "Todo lo de Free",
                "SIEM: CrowdStrike · Palo Alto · Fortinet",
                "Motor de correlación de amenazas",
                "Threat Hunting avanzado",
                "Playbooks SOAR con Human-in-the-Loop",
                "Reportes ejecutivos en PDF",
                "Honeypots + detección de intrusión",
                "50 usuarios · 20 API keys por usuario",
                "90 días de retención de datos",
                "SLA 99.5% uptime · soporte email 24h",
            ],
            "sort_order": 1,
            "is_active": True,
            "created_at": _NOW,
            "updated_at": _NOW,
        },
        {
            "id": str(uuid.uuid4()),
            "slug": "enterprise",
            "name": "Enterprise",
            "tagline": "Para organizaciones con requisitos de seguridad críticos",
            "cta": "Hablar con ventas",
            "price_usd": None,
            "price_usd_annual": None,
            "billing_period": "month",
            "highlight": False,
            "features": {
                "max_users": None,
                "max_api_keys_per_user": None,
                "data_retention_days": 365,
                "siem_integration": True,
                "threat_hunting": True,
                "executive_reports": True,
                "soar_playbooks": True,
                "correlation_engine": True,
                "artifact_analysis": True,
                "honeypot": True,
                "custom_adapters": True,
                "audit_log": True,
                "support": "24/7 dedicated",
                "uptime_sla": "99.9%",
            },
            "features_list": [
                "Todo lo de Pro",
                "Integraciones personalizadas (adaptadores custom)",
                "Analista de seguridad dedicado",
                "Soporte 24/7 — teléfono + Slack privado",
                "Usuarios y API keys ilimitados",
                "1 año de retención + archivo frío",
                "SLA 99.9% uptime garantizado por contrato",
                "Reportes de compliance (SOC 2, ISO 27001)",
                "Opción de despliegue on-premise",
            ],
            "sort_order": 2,
            "is_active": True,
            "created_at": _NOW,
            "updated_at": _NOW,
        },
    ])


def downgrade() -> None:
    op.drop_table("billing_plans")
    op.drop_table("detection_rules")
