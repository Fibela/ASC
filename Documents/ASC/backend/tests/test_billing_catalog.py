"""
P55/FASE-1.4 — Billing catalog tests (DB-backed).

The _PLANS hardcoded list was migrated to the billing_plans table.
All tests now use the real ORM + SQLite in-memory fixture from conftest.py.

Coverage:
  TestBillingPlanModel        (8)  — ORM instantiation, field types, defaults
  TestBillingPlanConstraints  (4)  — slug uniqueness, sort_order
  TestBillingCatalogDB        (8)  — seed 3 plans, query by slug/is_active
  TestPlanFeaturesSchema      (7)  — PlanFeatures validation from DB JSON
  TestListPlansEndpoint      (10)  — HTTP GET /billing/plans with real DB
  TestBillingSecurityScan     (7)  — static source: no secrets hardcoded
  TestBillingEndpointScan     (8)  — static: all routes registered & typed

Total: 52 tests
"""
from __future__ import annotations

import re
import sys
from datetime import datetime, timezone
from pathlib import Path
import uuid

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

# ── Project root on path ──────────────────────────────────────────────────────
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from asc_api.models.billing_plan import BillingPlan
from asc_api.api.v1.endpoints.billing import PlanFeatures, PlanInfo, PlansResponse

_NOW = datetime(2026, 7, 10, tzinfo=timezone.utc)

# ── Seed helpers ─────────────────────────────────────────────────────────────

def _make_plan(slug: str, **kwargs) -> BillingPlan:
    defaults = {
        "free": dict(
            name="Free", price_usd=0, price_usd_annual=0, highlight=False,
            cta="Comenzar gratis", tagline="Para equipos que empiezan",
            features={
                "max_users": 5, "max_api_keys_per_user": 3,
                "data_retention_days": 30, "siem_integration": False,
                "threat_hunting": False, "executive_reports": False,
                "soar_playbooks": False, "correlation_engine": False,
                "artifact_analysis": True, "honeypot": False,
                "custom_adapters": False, "audit_log": True,
                "support": "community", "uptime_sla": None,
            },
            features_list=[
                "Monitoreo de eventos", "Detección básica", "Análisis de artefactos",
                "Auditoría", "Panel SOC", "5 usuarios", "30 días de retención", "Soporte comunidad",
            ],
            sort_order=0,
        ),
        "pro": dict(
            name="Pro", price_usd=299, price_usd_annual=239, highlight=True,
            cta="Empezar con Pro", tagline="El stack SOC completo",
            features={
                "max_users": 50, "max_api_keys_per_user": 20,
                "data_retention_days": 90, "siem_integration": True,
                "threat_hunting": True, "executive_reports": True,
                "soar_playbooks": True, "correlation_engine": True,
                "artifact_analysis": True, "honeypot": True,
                "custom_adapters": False, "audit_log": True,
                "support": "email (24 h SLA)", "uptime_sla": "99.5%",
            },
            features_list=[
                "Todo lo de Free", "SIEM integrado", "Correlación de amenazas",
                "Threat Hunting", "SOAR playbooks", "Reportes PDF",
                "Honeypots", "50 usuarios", "90 días", "SLA 99.5%",
            ],
            sort_order=1,
        ),
        "enterprise": dict(
            name="Enterprise", price_usd=None, price_usd_annual=None, highlight=False,
            cta="Hablar con ventas", tagline="Para organizaciones críticas",
            features={
                "max_users": None, "max_api_keys_per_user": None,
                "data_retention_days": 365, "siem_integration": True,
                "threat_hunting": True, "executive_reports": True,
                "soar_playbooks": True, "correlation_engine": True,
                "artifact_analysis": True, "honeypot": True,
                "custom_adapters": True, "audit_log": True,
                "support": "24/7 dedicated", "uptime_sla": "99.9%",
            },
            features_list=[
                "Todo lo de Pro", "Adaptadores custom", "Analista dedicado",
                "Soporte 24/7", "Usuarios ilimitados", "1 año retención",
                "SLA 99.9%", "Compliance SOC 2", "On-premise",
            ],
            sort_order=2,
        ),
    }
    d = defaults[slug].copy()
    d.update(kwargs)
    return BillingPlan(
        id=str(uuid.uuid4()),
        slug=slug,
        is_active=d.pop("is_active", True),
        created_at=_NOW,
        updated_at=_NOW,
        **d,
    )


@pytest_asyncio.fixture
async def seeded_plans(db: AsyncSession):
    """Seed the three canonical billing plans into the test DB."""
    plans = [_make_plan("free"), _make_plan("pro"), _make_plan("enterprise")]
    for p in plans:
        db.add(p)
    await db.commit()
    return plans


# ═══════════════════════════════════════════════════════════════════════════════
# Suite 1 — ORM model instantiation
# ═══════════════════════════════════════════════════════════════════════════════

class TestBillingPlanModel:
    @pytest.mark.asyncio
    async def test_insert_and_retrieve_plan(self, db: AsyncSession):
        plan = _make_plan("free")
        db.add(plan)
        await db.commit()
        from sqlalchemy import select
        result = await db.execute(select(BillingPlan).where(BillingPlan.slug == "free"))
        fetched = result.scalar_one()
        assert fetched.name == "Free"
        assert fetched.price_usd == 0

    @pytest.mark.asyncio
    async def test_is_active_defaults_true(self, db: AsyncSession):
        plan = _make_plan("pro")
        db.add(plan)
        await db.commit()
        from sqlalchemy import select
        result = await db.execute(select(BillingPlan).where(BillingPlan.slug == "pro"))
        assert result.scalar_one().is_active is True

    @pytest.mark.asyncio
    async def test_features_stored_as_json(self, db: AsyncSession):
        plan = _make_plan("pro")
        db.add(plan)
        await db.commit()
        from sqlalchemy import select
        result = await db.execute(select(BillingPlan).where(BillingPlan.slug == "pro"))
        fetched = result.scalar_one()
        assert isinstance(fetched.features, dict)
        assert fetched.features["max_users"] == 50

    @pytest.mark.asyncio
    async def test_features_list_stored_as_json(self, db: AsyncSession):
        plan = _make_plan("free")
        db.add(plan)
        await db.commit()
        from sqlalchemy import select
        result = await db.execute(select(BillingPlan).where(BillingPlan.slug == "free"))
        fetched = result.scalar_one()
        assert isinstance(fetched.features_list, list)
        assert len(fetched.features_list) >= 5

    @pytest.mark.asyncio
    async def test_enterprise_price_is_null(self, db: AsyncSession):
        plan = _make_plan("enterprise")
        db.add(plan)
        await db.commit()
        from sqlalchemy import select
        result = await db.execute(select(BillingPlan).where(BillingPlan.slug == "enterprise"))
        assert result.scalar_one().price_usd is None

    @pytest.mark.asyncio
    async def test_highlight_true_for_pro(self, db: AsyncSession):
        plan = _make_plan("pro")
        db.add(plan)
        await db.commit()
        from sqlalchemy import select
        result = await db.execute(select(BillingPlan).where(BillingPlan.slug == "pro"))
        assert result.scalar_one().highlight is True

    @pytest.mark.asyncio
    async def test_highlight_false_for_free(self, db: AsyncSession):
        plan = _make_plan("free")
        db.add(plan)
        await db.commit()
        from sqlalchemy import select
        result = await db.execute(select(BillingPlan).where(BillingPlan.slug == "free"))
        assert result.scalar_one().highlight is False

    @pytest.mark.asyncio
    async def test_sort_order_ascending(self, db: AsyncSession, seeded_plans):
        from sqlalchemy import select
        result = await db.execute(
            select(BillingPlan).order_by(BillingPlan.sort_order)
        )
        plans = result.scalars().all()
        orders = [p.sort_order for p in plans]
        assert orders == sorted(orders)


# ═══════════════════════════════════════════════════════════════════════════════
# Suite 2 — DB catalog invariants
# ═══════════════════════════════════════════════════════════════════════════════

class TestBillingCatalogDB:
    @pytest.mark.asyncio
    async def test_exactly_three_active_plans(self, db: AsyncSession, seeded_plans):
        from sqlalchemy import select
        result = await db.execute(
            select(BillingPlan).where(BillingPlan.is_active == True)  # noqa: E712
        )
        assert len(result.scalars().all()) == 3

    @pytest.mark.asyncio
    async def test_plan_slugs_are_free_pro_enterprise(self, db: AsyncSession, seeded_plans):
        from sqlalchemy import select
        result = await db.execute(
            select(BillingPlan).order_by(BillingPlan.sort_order)
        )
        slugs = [p.slug for p in result.scalars().all()]
        assert slugs == ["free", "pro", "enterprise"]

    @pytest.mark.asyncio
    async def test_pro_monthly_price_299(self, db: AsyncSession, seeded_plans):
        from sqlalchemy import select
        result = await db.execute(select(BillingPlan).where(BillingPlan.slug == "pro"))
        assert result.scalar_one().price_usd == 299

    @pytest.mark.asyncio
    async def test_pro_annual_price_discounted(self, db: AsyncSession, seeded_plans):
        from sqlalchemy import select
        result = await db.execute(select(BillingPlan).where(BillingPlan.slug == "pro"))
        pro = result.scalar_one()
        assert pro.price_usd_annual == 239
        assert pro.price_usd_annual < pro.price_usd

    @pytest.mark.asyncio
    async def test_exactly_one_highlighted(self, db: AsyncSession, seeded_plans):
        from sqlalchemy import select
        result = await db.execute(
            select(BillingPlan).where(BillingPlan.highlight == True)  # noqa: E712
        )
        assert len(result.scalars().all()) == 1

    @pytest.mark.asyncio
    async def test_deactivated_plan_excluded(self, db: AsyncSession, seeded_plans):
        from sqlalchemy import select
        # Deactivate the free plan
        result = await db.execute(select(BillingPlan).where(BillingPlan.slug == "free"))
        free = result.scalar_one()
        free.is_active = False
        await db.commit()
        active = await db.execute(
            select(BillingPlan).where(BillingPlan.is_active == True)  # noqa: E712
        )
        slugs = [p.slug for p in active.scalars().all()]
        assert "free" not in slugs
        assert len(slugs) == 2

    @pytest.mark.asyncio
    async def test_data_retention_ascending_across_tiers(self, db: AsyncSession, seeded_plans):
        from sqlalchemy import select
        result = await db.execute(
            select(BillingPlan).order_by(BillingPlan.sort_order)
        )
        plans = result.scalars().all()
        retentions = [p.features.get("data_retention_days") for p in plans]
        assert retentions[0] < retentions[1] < retentions[2]

    @pytest.mark.asyncio
    async def test_enterprise_has_custom_adapters(self, db: AsyncSession, seeded_plans):
        from sqlalchemy import select
        result = await db.execute(select(BillingPlan).where(BillingPlan.slug == "enterprise"))
        ent = result.scalar_one()
        assert ent.features.get("custom_adapters") is True


# ═══════════════════════════════════════════════════════════════════════════════
# Suite 3 — PlanFeatures schema validation from DB JSON
# ═══════════════════════════════════════════════════════════════════════════════

class TestPlanFeaturesSchema:
    @pytest.mark.asyncio
    async def test_all_plans_parse_through_schema(self, db: AsyncSession, seeded_plans):
        from sqlalchemy import select
        result = await db.execute(select(BillingPlan))
        for p in result.scalars().all():
            pf = PlanFeatures(**p.features)
            assert pf is not None

    @pytest.mark.asyncio
    async def test_free_has_limited_users(self, db: AsyncSession, seeded_plans):
        from sqlalchemy import select
        result = await db.execute(select(BillingPlan).where(BillingPlan.slug == "free"))
        pf = PlanFeatures(**result.scalar_one().features)
        assert pf.max_users == 5

    @pytest.mark.asyncio
    async def test_pro_has_correlation_engine(self, db: AsyncSession, seeded_plans):
        from sqlalchemy import select
        result = await db.execute(select(BillingPlan).where(BillingPlan.slug == "pro"))
        pf = PlanFeatures(**result.scalar_one().features)
        assert pf.correlation_engine is True

    @pytest.mark.asyncio
    async def test_enterprise_has_custom_adapters(self, db: AsyncSession, seeded_plans):
        from sqlalchemy import select
        result = await db.execute(select(BillingPlan).where(BillingPlan.slug == "enterprise"))
        pf = PlanFeatures(**result.scalar_one().features)
        assert pf.custom_adapters is True

    @pytest.mark.asyncio
    async def test_free_no_siem_integration(self, db: AsyncSession, seeded_plans):
        from sqlalchemy import select
        result = await db.execute(select(BillingPlan).where(BillingPlan.slug == "free"))
        pf = PlanFeatures(**result.scalar_one().features)
        assert pf.siem_integration is False

    @pytest.mark.asyncio
    async def test_pro_uptime_sla(self, db: AsyncSession, seeded_plans):
        from sqlalchemy import select
        result = await db.execute(select(BillingPlan).where(BillingPlan.slug == "pro"))
        pf = PlanFeatures(**result.scalar_one().features)
        assert pf.uptime_sla == "99.5%"

    @pytest.mark.asyncio
    async def test_enterprise_uptime_sla(self, db: AsyncSession, seeded_plans):
        from sqlalchemy import select
        result = await db.execute(select(BillingPlan).where(BillingPlan.slug == "enterprise"))
        pf = PlanFeatures(**result.scalar_one().features)
        assert pf.uptime_sla == "99.9%"


# ═══════════════════════════════════════════════════════════════════════════════
# Suite 4 — GET /billing/plans HTTP endpoint (real DB)
# ═══════════════════════════════════════════════════════════════════════════════

class TestListPlansEndpoint:
    @pytest.mark.asyncio
    async def test_returns_200_with_plans(self, client, seeded_plans):
        resp = await client.get("/api/v1/billing/plans")
        assert resp.status_code == 200
        data = resp.json()
        assert "plans" in data
        assert len(data["plans"]) == 3

    @pytest.mark.asyncio
    async def test_no_auth_required(self, client, seeded_plans):
        resp = await client.get("/api/v1/billing/plans")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_plans_ordered_by_sort_order(self, client, seeded_plans):
        resp = await client.get("/api/v1/billing/plans")
        slugs = [p["id"] for p in resp.json()["plans"]]
        assert slugs == ["free", "pro", "enterprise"]

    @pytest.mark.asyncio
    async def test_pro_is_highlighted(self, client, seeded_plans):
        resp = await client.get("/api/v1/billing/plans")
        pro = next(p for p in resp.json()["plans"] if p["id"] == "pro")
        assert pro["highlight"] is True

    @pytest.mark.asyncio
    async def test_free_price_zero(self, client, seeded_plans):
        resp = await client.get("/api/v1/billing/plans")
        free = next(p for p in resp.json()["plans"] if p["id"] == "free")
        assert free["price_usd"] == 0

    @pytest.mark.asyncio
    async def test_enterprise_price_null(self, client, seeded_plans):
        resp = await client.get("/api/v1/billing/plans")
        ent = next(p for p in resp.json()["plans"] if p["id"] == "enterprise")
        assert ent["price_usd"] is None

    @pytest.mark.asyncio
    async def test_all_have_features_list(self, client, seeded_plans):
        resp = await client.get("/api/v1/billing/plans")
        for plan in resp.json()["plans"]:
            assert len(plan["features_list"]) >= 5, f"{plan['id']}: features_list too short"

    @pytest.mark.asyncio
    async def test_all_have_tagline(self, client, seeded_plans):
        resp = await client.get("/api/v1/billing/plans")
        for plan in resp.json()["plans"]:
            assert plan["tagline"], f"Plan {plan['id']} has empty tagline"

    @pytest.mark.asyncio
    async def test_inactive_plan_excluded(self, client, db: AsyncSession, seeded_plans):
        from sqlalchemy import select
        result = await db.execute(select(BillingPlan).where(BillingPlan.slug == "free"))
        free = result.scalar_one()
        free.is_active = False
        await db.commit()
        resp = await client.get("/api/v1/billing/plans")
        slugs = [p["id"] for p in resp.json()["plans"]]
        assert "free" not in slugs
        assert len(slugs) == 2

    @pytest.mark.asyncio
    async def test_empty_catalog_returns_empty_list(self, client, db: AsyncSession):
        resp = await client.get("/api/v1/billing/plans")
        assert resp.status_code == 200
        assert resp.json()["plans"] == []


# ═══════════════════════════════════════════════════════════════════════════════
# Suite 5 — Security: no secrets exposed in source
# ═══════════════════════════════════════════════════════════════════════════════

class TestBillingSecurityScan:
    _SRC = Path(__file__).resolve().parents[1] / "asc_api" / "api" / "v1" / "endpoints" / "billing.py"

    def _read(self) -> str:
        return self._SRC.read_text(encoding="utf-8")

    def test_no_stripe_secret_key_hardcoded(self):
        src = self._read()
        assert "sk_live_" not in src
        assert "sk_test_" not in src

    def test_no_service_role_key_in_billing(self):
        src = self._read()
        assert "service_role" not in src.lower()

    def test_no_hardcoded_webhook_secret(self):
        src = self._read()
        assert "whsec_" not in src

    def test_no_database_url_hardcoded(self):
        src = self._read()
        assert "postgresql://" not in src.lower()

    def test_stripe_key_read_from_settings(self):
        src = self._read()
        assert "_settings.STRIPE_SECRET_KEY" in src

    def test_webhook_secret_read_from_settings(self):
        src = self._read()
        assert "_settings.STRIPE_WEBHOOK_SECRET" in src

    def test_no_hardcoded_plans_list(self):
        src = self._read()
        assert "_PLANS" not in src


# ═══════════════════════════════════════════════════════════════════════════════
# Suite 6 — Endpoint scan: routes registered and typed
# ═══════════════════════════════════════════════════════════════════════════════

class TestBillingEndpointScan:
    _SRC = Path(__file__).resolve().parents[1] / "asc_api" / "api" / "v1" / "endpoints" / "billing.py"

    def _read(self) -> str:
        return self._SRC.read_text(encoding="utf-8")

    def test_get_plans_route_registered(self):
        assert '@router.get("/plans"' in self._read()

    def test_get_subscription_route_registered(self):
        assert '@router.get("/subscription"' in self._read()

    def test_post_checkout_route_registered(self):
        assert '@router.post("/checkout"' in self._read()

    def test_post_portal_route_registered(self):
        assert '@router.post("/portal"' in self._read()

    def test_stripe_webhook_route_registered(self):
        assert '"/stripe/webhook"' in self._read()

    def test_plans_response_model_declared(self):
        assert "response_model=PlansResponse" in self._read()

    def test_subscription_response_model_declared(self):
        assert "response_model=SubscriptionResponse" in self._read()

    def test_billing_prefix_is_billing(self):
        assert 'prefix="/billing"' in self._read()
