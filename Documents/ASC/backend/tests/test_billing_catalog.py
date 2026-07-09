"""
P55/P-CATALOG — Billing catalog unit tests.

Tests:
  - GET /billing/plans structure, field completeness, and pricing
  - PlanInfo schema validation (new fields added in catalog enhancement)
  - Security scan: no secrets or SERVICE_ROLE_KEY exposed in billing source
  - Plan identity invariants: Pro highlight, Free/Enterprise not highlighted
  - Annual pricing, features_list coverage
  - Endpoint scan: billing routes exist and are correctly typed

Audit: 2026-07-09 | Session 92 | Author: ASC CI
"""

from __future__ import annotations

import importlib
import re
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ── Project root on path ──────────────────────────────────────────────────────
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# ── Import billing module ─────────────────────────────────────────────────────
import asc_api.api.v1.endpoints.billing as billing_module
from asc_api.api.v1.endpoints.billing import (
    PlanFeatures,
    PlanInfo,
    PlansResponse,
    _PLANS,
    list_plans,
)

# ═══════════════════════════════════════════════════════════════════════════════
# Suite 1 — _PLANS catalog structure
# ═══════════════════════════════════════════════════════════════════════════════

class TestPlansCatalogStructure:
    """Validate the raw _PLANS list before schema serialization."""

    def test_exactly_three_plans(self):
        assert len(_PLANS) == 3

    def test_plan_ids_are_free_pro_enterprise(self):
        ids = [p["id"] for p in _PLANS]
        assert ids == ["free", "pro", "enterprise"]

    def test_all_plans_have_required_top_level_keys(self):
        required = {"id", "name", "price_usd", "billing_period", "highlight", "cta", "tagline", "features", "features_list"}
        for plan in _PLANS:
            missing = required - plan.keys()
            assert not missing, f"Plan '{plan['id']}' missing keys: {missing}"

    def test_all_plans_have_features_list_non_empty(self):
        for plan in _PLANS:
            assert isinstance(plan["features_list"], list), f"{plan['id']}: features_list not a list"
            assert len(plan["features_list"]) >= 5, f"{plan['id']}: features_list has < 5 items"

    def test_all_plans_have_tagline(self):
        for plan in _PLANS:
            assert plan["tagline"], f"Plan '{plan['id']}' has empty tagline"

    def test_all_plans_have_cta(self):
        for plan in _PLANS:
            assert plan["cta"], f"Plan '{plan['id']}' has empty cta"


# ═══════════════════════════════════════════════════════════════════════════════
# Suite 2 — Plan pricing invariants
# ═══════════════════════════════════════════════════════════════════════════════

class TestPlanPricing:
    def _get(self, plan_id: str) -> dict:
        return next(p for p in _PLANS if p["id"] == plan_id)

    def test_free_price_is_zero(self):
        free = self._get("free")
        assert free["price_usd"] == 0

    def test_pro_monthly_price(self):
        pro = self._get("pro")
        assert pro["price_usd"] == 299

    def test_pro_annual_price_is_discounted(self):
        pro = self._get("pro")
        assert pro.get("price_usd_annual") == 239
        assert pro["price_usd_annual"] < pro["price_usd"]

    def test_enterprise_price_is_none_contact_sales(self):
        ent = self._get("enterprise")
        assert ent["price_usd"] is None

    def test_enterprise_annual_price_none(self):
        ent = self._get("enterprise")
        assert ent.get("price_usd_annual") is None

    def test_billing_period_month_for_all(self):
        for plan in _PLANS:
            assert plan["billing_period"] == "month"


# ═══════════════════════════════════════════════════════════════════════════════
# Suite 3 — Highlight / popular flag
# ═══════════════════════════════════════════════════════════════════════════════

class TestHighlightFlag:
    def _get(self, plan_id: str) -> dict:
        return next(p for p in _PLANS if p["id"] == plan_id)

    def test_pro_is_highlighted(self):
        assert self._get("pro")["highlight"] is True

    def test_free_is_not_highlighted(self):
        assert self._get("free")["highlight"] is False

    def test_enterprise_is_not_highlighted(self):
        assert self._get("enterprise")["highlight"] is False

    def test_exactly_one_plan_highlighted(self):
        highlighted = [p for p in _PLANS if p["highlight"]]
        assert len(highlighted) == 1


# ═══════════════════════════════════════════════════════════════════════════════
# Suite 4 — PlanFeatures schema validation
# ═══════════════════════════════════════════════════════════════════════════════

class TestPlanFeaturesSchema:
    def test_all_plans_parse_through_schema(self):
        for plan in _PLANS:
            pf = PlanFeatures(**plan["features"])
            assert pf is not None

    def test_free_has_limited_users(self):
        free_features = next(p for p in _PLANS if p["id"] == "free")["features"]
        pf = PlanFeatures(**free_features)
        assert pf.max_users == 5

    def test_pro_has_correlation_engine(self):
        pro_features = next(p for p in _PLANS if p["id"] == "pro")["features"]
        pf = PlanFeatures(**pro_features)
        assert pf.correlation_engine is True

    def test_enterprise_has_custom_adapters(self):
        ent_features = next(p for p in _PLANS if p["id"] == "enterprise")["features"]
        pf = PlanFeatures(**ent_features)
        assert pf.custom_adapters is True

    def test_free_has_no_siem_integration(self):
        free_features = next(p for p in _PLANS if p["id"] == "free")["features"]
        pf = PlanFeatures(**free_features)
        assert pf.siem_integration is False

    def test_pro_uptime_sla(self):
        pro_features = next(p for p in _PLANS if p["id"] == "pro")["features"]
        pf = PlanFeatures(**pro_features)
        assert pf.uptime_sla == "99.5%"

    def test_enterprise_uptime_sla(self):
        ent_features = next(p for p in _PLANS if p["id"] == "enterprise")["features"]
        pf = PlanFeatures(**ent_features)
        assert pf.uptime_sla == "99.9%"

    def test_data_retention_days_ascending(self):
        plans_by_tier = ["free", "pro", "enterprise"]
        retentions = []
        for pid in plans_by_tier:
            f = next(p for p in _PLANS if p["id"] == pid)["features"]
            retentions.append(f.get("data_retention_days"))
        # free=30, pro=90, enterprise=365
        assert retentions[0] < retentions[1] < retentions[2]


# ═══════════════════════════════════════════════════════════════════════════════
# Suite 5 — PlanInfo schema (full plan serialization)
# ═══════════════════════════════════════════════════════════════════════════════

class TestPlanInfoSchema:
    def test_all_plans_serialize_to_plan_info(self):
        for plan in _PLANS:
            pi = PlanInfo(**plan)
            assert pi.id in ("free", "pro", "enterprise")

    def test_plan_info_includes_features_list(self):
        for plan in _PLANS:
            pi = PlanInfo(**plan)
            assert isinstance(pi.features_list, list)
            assert len(pi.features_list) > 0

    def test_plan_info_includes_annual_price(self):
        pro = next(p for p in _PLANS if p["id"] == "pro")
        pi = PlanInfo(**pro)
        assert pi.price_usd_annual == 239

    def test_plans_response_wraps_correctly(self):
        pr = PlansResponse(plans=[PlanInfo(**p) for p in _PLANS])
        assert len(pr.plans) == 3


# ═══════════════════════════════════════════════════════════════════════════════
# Suite 6 — list_plans() endpoint (no DB required)
# ═══════════════════════════════════════════════════════════════════════════════

class TestListPlansEndpoint:
    @pytest.mark.asyncio
    async def test_list_plans_returns_plans_response(self):
        result = await list_plans()
        assert isinstance(result, PlansResponse)
        assert len(result.plans) == 3

    @pytest.mark.asyncio
    async def test_list_plans_pro_is_highlight(self):
        result = await list_plans()
        pro = next(p for p in result.plans if p.id == "pro")
        assert pro.highlight is True

    @pytest.mark.asyncio
    async def test_list_plans_free_price_zero(self):
        result = await list_plans()
        free = next(p for p in result.plans if p.id == "free")
        assert free.price_usd == 0

    @pytest.mark.asyncio
    async def test_list_plans_enterprise_price_none(self):
        result = await list_plans()
        ent = next(p for p in result.plans if p.id == "enterprise")
        assert ent.price_usd is None

    @pytest.mark.asyncio
    async def test_list_plans_all_have_tagline(self):
        result = await list_plans()
        for plan in result.plans:
            assert plan.tagline, f"Plan {plan.id} has empty tagline"

    @pytest.mark.asyncio
    async def test_list_plans_features_list_populated(self):
        result = await list_plans()
        for plan in result.plans:
            assert len(plan.features_list) >= 5, f"{plan.id}: features_list too short"


# ═══════════════════════════════════════════════════════════════════════════════
# Suite 7 — Security: no secrets exposed in source
# ═══════════════════════════════════════════════════════════════════════════════

class TestBillingSecurityScan:
    """Static scan of billing.py source to ensure no secrets are hardcoded."""

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
        assert "postgres://" not in src.lower()

    def test_stripe_key_read_from_settings(self):
        src = self._read()
        # Key must come from settings, never a literal
        assert "_settings.STRIPE_SECRET_KEY" in src

    def test_webhook_secret_read_from_settings(self):
        src = self._read()
        assert "_settings.STRIPE_WEBHOOK_SECRET" in src

    def test_no_exposed_price_ids(self):
        src = self._read()
        # Stripe live price IDs should not be hardcoded
        assert "price_" not in src or "_settings.STRIPE_PRICE_" in src


# ═══════════════════════════════════════════════════════════════════════════════
# Suite 8 — Endpoint scan: routes registered and typed
# ═══════════════════════════════════════════════════════════════════════════════

class TestBillingEndpointScan:
    _SRC = Path(__file__).resolve().parents[1] / "asc_api" / "api" / "v1" / "endpoints" / "billing.py"

    def _read(self) -> str:
        return self._SRC.read_text(encoding="utf-8")

    def test_get_plans_route_registered(self):
        src = self._read()
        assert '@router.get("/plans"' in src

    def test_get_subscription_route_registered(self):
        src = self._read()
        assert '@router.get("/subscription"' in src

    def test_post_checkout_route_registered(self):
        src = self._read()
        assert '@router.post("/checkout"' in src

    def test_post_portal_route_registered(self):
        src = self._read()
        assert '@router.post("/portal"' in src

    def test_stripe_webhook_route_registered(self):
        src = self._read()
        assert '@router.post(\n    "/stripe/webhook"' in src or '"/stripe/webhook"' in src

    def test_plans_response_model_declared(self):
        src = self._read()
        assert "response_model=PlansResponse" in src

    def test_subscription_response_model_declared(self):
        src = self._read()
        assert "response_model=SubscriptionResponse" in src

    def test_billing_prefix_is_billing(self):
        src = self._read()
        assert 'prefix="/billing"' in src

    def test_no_get_current_user_on_list_plans(self):
        """list_plans is public — must not require auth."""
        src = self._read()
        # The list_plans function should have no Depends in its signature
        # Find the function definition after the @router.get("/plans") decorator
        match = re.search(r'@router\.get\("/plans".*?\nasync def list_plans\((.*?)\)', src, re.DOTALL)
        assert match is not None, "list_plans route not found"
        params = match.group(1)
        assert "get_current_user" not in params
        assert "get_current_admin" not in params
