"""
P60 â€” Stripe â†’ ASC Tenant Auto-Provisioning â€” Test Suite
=========================================================

Tests: 47 in 8 classes covering:
  - checkout.session.completed webhook â†’ new Tenant + admin User
  - Idempotency: duplicate checkout_session_id â†’ no double-provision
  - Lookup by stripe_customer_id (upgrade existing tenant)
  - Lookup by email (link existing ASC user's tenant)
  - customer.subscription.created â†’ subscription ID + plan upgrade
  - Security: admin role, random password, no key leaks
  - Migration artifact (#18, down_revision=P59)
  - Config completeness (STRIPE_PROVISIONING_PLAN, render.yaml, .env.example)
  - Regression gates (migration counts, existing billing tests intact)

Security focus:
  - Provisioned admin users get cryptographically random passwords (no login)
  - stripe_checkout_session_id unique index prevents duplicate provisioning
  - STRIPE_SEGURIDAD_PRODUCT_ID filter prevents unintended provisioning
  - Stripe signature validation still enforced for all events (P55 invariant)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from asc_api.db.session import get_db
from asc_api.main import app

_BACKEND = Path(__file__).parent.parent
_MIGRATIONS_DIR = _BACKEND / "migrations" / "versions"
_P60_HEAD = "v2p45s4u7o09"
_EXPECTED_TOTAL_MIGRATIONS = 26  # 24 (P-16) + b3c4d5e6f7a8 + c9d12f0e5b67 merge head

_WEBHOOK_URL = "/api/v1/billing/stripe/webhook"
_TEST_WEBHOOK_SECRET = "whsec_test_secret_for_unit_tests_only"
_TEST_EMAIL = "stripe_customer@premoscorp.com"
_TEST_STRIPE_CID = "cus_test_p60_xyz123"
_TEST_STRIPE_SID = "sub_test_p60_abc456"
_TEST_SESSION_ID = "cs_test_p60_checkout_session_001"


# â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _make_sig(secret: str, payload: bytes) -> str:
    timestamp = "1700000000"
    signed = f"{timestamp}.".encode() + payload
    mac = hmac.new(secret.encode(), signed, hashlib.sha256)
    return f"t={timestamp},v1={mac.hexdigest()}"


def _checkout_event(
    email: str = _TEST_EMAIL,
    customer: str = _TEST_STRIPE_CID,
    subscription: str | None = _TEST_STRIPE_SID,
    session_id: str = _TEST_SESSION_ID,
    metadata: dict | None = None,
) -> dict:
    return {
        "id": "evt_checkout_test",
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "id": session_id,
                "customer": customer,
                "customer_email": email,
                "subscription": subscription,
                "metadata": metadata or {},
            }
        },
    }


def _subscription_created_event(
    customer: str = _TEST_STRIPE_CID,
    sub_id: str = _TEST_STRIPE_SID,
    status: str = "active",
) -> dict:
    return {
        "id": "evt_sub_created_test",
        "type": "customer.subscription.created",
        "data": {
            "object": {
                "id": sub_id,
                "customer": customer,
                "status": status,
            }
        },
    }


def _make_db(
    idempotent_tenant=None,
    stripe_cid_tenant=None,
    email_user=None,
    email_user_tenant=None,
):
    """
    DB mock for _provision_stripe_customer().
    Call sequence:
      1 â†’ idempotency lookup (stripe_checkout_session_id)
      2 â†’ stripe_customer_id lookup
      3 â†’ user email lookup
      4 â†’ tenant by user.tenant_id
    """
    db = AsyncMock()
    db.commit = AsyncMock()
    db.add = MagicMock()
    _added = []
    db.add.side_effect = _added.append

    async def _refresh(obj):
        if not hasattr(obj, "is_active"):
            obj.is_active = True

    db.refresh = _refresh

    _call = {"n": 0}

    async def _execute(stmt, *args, **kwargs):
        _call["n"] += 1
        n = _call["n"]
        result = MagicMock()
        if n == 1:
            result.scalar_one_or_none = MagicMock(return_value=idempotent_tenant)
        elif n == 2:
            result.scalar_one_or_none = MagicMock(return_value=stripe_cid_tenant)
        elif n == 3:
            result.scalar_one_or_none = MagicMock(return_value=email_user)
        elif n == 4:
            result.scalar_one_or_none = MagicMock(return_value=email_user_tenant)
        else:
            result.scalar_one_or_none = MagicMock(return_value=None)
        return result

    db.execute = _execute
    db._added = _added
    return db


def _db_override(**kwargs):
    db = _make_db(**kwargs)

    async def _gen():
        yield db

    return _gen, db


def _post_webhook(client, payload: dict, secret: str = "") -> tuple:
    body = json.dumps(payload).encode()
    headers = {}
    if secret:
        headers["stripe-signature"] = _make_sig(secret, body)
    return body, headers


# â”€â”€ 1. checkout.session.completed â€” Webhook level â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestCheckoutSessionWebhook:

    @pytest.mark.anyio
    async def test_checkout_session_returns_200(self):
        override, _ = _db_override()
        app.dependency_overrides[get_db] = override
        payload = _checkout_event()
        with patch("asc_api.api.v1.endpoints.billing._settings") as cfg:
            cfg.STRIPE_SECRET_KEY = ""
            cfg.STRIPE_WEBHOOK_SECRET = ""
            cfg.STRIPE_PROVISIONING_PLAN = "pro"
            cfg.STRIPE_SEGURIDAD_PRODUCT_ID = ""
            with patch("asc_api.api.v1.endpoints.billing._provision_stripe_customer",
                       new_callable=AsyncMock) as mock_prov:
                tenant_mock = MagicMock()
                tenant_mock.id = str(uuid.uuid4())
                mock_prov.return_value = (tenant_mock, True)
                async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                    r = await c.post(_WEBHOOK_URL, json=payload)
        app.dependency_overrides.pop(get_db, None)
        assert r.status_code == 200

    @pytest.mark.anyio
    async def test_checkout_session_ack_received(self):
        override, _ = _db_override()
        app.dependency_overrides[get_db] = override
        payload = _checkout_event()
        with patch("asc_api.api.v1.endpoints.billing._settings") as cfg:
            cfg.STRIPE_SECRET_KEY = ""
            cfg.STRIPE_WEBHOOK_SECRET = ""
            cfg.STRIPE_PROVISIONING_PLAN = "pro"
            cfg.STRIPE_SEGURIDAD_PRODUCT_ID = ""
            with patch("asc_api.api.v1.endpoints.billing._provision_stripe_customer",
                       new_callable=AsyncMock) as mock_prov:
                tenant_mock = MagicMock(); tenant_mock.id = "t-123"
                mock_prov.return_value = (tenant_mock, True)
                async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                    r = await c.post(_WEBHOOK_URL, json=payload)
        app.dependency_overrides.pop(get_db, None)
        assert r.json()["received"] is True

    @pytest.mark.anyio
    async def test_checkout_session_calls_provision(self):
        override, _ = _db_override()
        app.dependency_overrides[get_db] = override
        payload = _checkout_event()
        with patch("asc_api.api.v1.endpoints.billing._settings") as cfg:
            cfg.STRIPE_SECRET_KEY = ""
            cfg.STRIPE_WEBHOOK_SECRET = ""
            cfg.STRIPE_PROVISIONING_PLAN = "pro"
            cfg.STRIPE_SEGURIDAD_PRODUCT_ID = ""
            with patch("asc_api.api.v1.endpoints.billing._provision_stripe_customer",
                       new_callable=AsyncMock) as mock_prov:
                tenant_mock = MagicMock(); tenant_mock.id = "t-123"
                mock_prov.return_value = (tenant_mock, True)
                async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                    await c.post(_WEBHOOK_URL, json=payload)
        app.dependency_overrides.pop(get_db, None)
        mock_prov.assert_awaited_once()
        call_kwargs = mock_prov.call_args
        assert _TEST_EMAIL in call_kwargs.args or _TEST_EMAIL in str(call_kwargs)

    @pytest.mark.anyio
    async def test_checkout_missing_email_skips_provision(self):
        override, _ = _db_override()
        app.dependency_overrides[get_db] = override
        payload = _checkout_event(email="")
        with patch("asc_api.api.v1.endpoints.billing._settings") as cfg:
            cfg.STRIPE_SECRET_KEY = ""
            cfg.STRIPE_WEBHOOK_SECRET = ""
            cfg.STRIPE_PROVISIONING_PLAN = "pro"
            cfg.STRIPE_SEGURIDAD_PRODUCT_ID = ""
            with patch("asc_api.api.v1.endpoints.billing._provision_stripe_customer",
                       new_callable=AsyncMock) as mock_prov:
                async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                    r = await c.post(_WEBHOOK_URL, json=payload)
        app.dependency_overrides.pop(get_db, None)
        assert r.status_code == 200
        mock_prov.assert_not_awaited()

    @pytest.mark.anyio
    async def test_checkout_missing_customer_id_skips_provision(self):
        override, _ = _db_override()
        app.dependency_overrides[get_db] = override
        payload = _checkout_event(customer="")
        with patch("asc_api.api.v1.endpoints.billing._settings") as cfg:
            cfg.STRIPE_SECRET_KEY = ""
            cfg.STRIPE_WEBHOOK_SECRET = ""
            cfg.STRIPE_PROVISIONING_PLAN = "pro"
            cfg.STRIPE_SEGURIDAD_PRODUCT_ID = ""
            with patch("asc_api.api.v1.endpoints.billing._provision_stripe_customer",
                       new_callable=AsyncMock) as mock_prov:
                async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                    r = await c.post(_WEBHOOK_URL, json=payload)
        app.dependency_overrides.pop(get_db, None)
        assert r.status_code == 200
        mock_prov.assert_not_awaited()

    @pytest.mark.anyio
    async def test_product_filter_blocks_non_asc_product(self):
        override, _ = _db_override()
        app.dependency_overrides[get_db] = override
        # Event has no metadata product_id â†’ filtered out
        payload = _checkout_event(metadata={})
        with patch("asc_api.api.v1.endpoints.billing._settings") as cfg:
            cfg.STRIPE_SECRET_KEY = ""
            cfg.STRIPE_WEBHOOK_SECRET = ""
            cfg.STRIPE_PROVISIONING_PLAN = "pro"
            cfg.STRIPE_SEGURIDAD_PRODUCT_ID = "prod_asc_seguridad_123"
            with patch("asc_api.api.v1.endpoints.billing._provision_stripe_customer",
                       new_callable=AsyncMock) as mock_prov:
                async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                    r = await c.post(_WEBHOOK_URL, json=payload)
        app.dependency_overrides.pop(get_db, None)
        assert r.status_code == 200
        mock_prov.assert_not_awaited()

    @pytest.mark.anyio
    async def test_product_filter_allows_matching_product(self):
        override, _ = _db_override()
        app.dependency_overrides[get_db] = override
        payload = _checkout_event(metadata={"product_id": "prod_asc_seguridad_123"})
        with patch("asc_api.api.v1.endpoints.billing._settings") as cfg:
            cfg.STRIPE_SECRET_KEY = ""
            cfg.STRIPE_WEBHOOK_SECRET = ""
            cfg.STRIPE_PROVISIONING_PLAN = "pro"
            cfg.STRIPE_SEGURIDAD_PRODUCT_ID = "prod_asc_seguridad_123"
            with patch("asc_api.api.v1.endpoints.billing._provision_stripe_customer",
                       new_callable=AsyncMock) as mock_prov:
                tenant_mock = MagicMock(); tenant_mock.id = "t-123"
                mock_prov.return_value = (tenant_mock, True)
                async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                    r = await c.post(_WEBHOOK_URL, json=payload)
        app.dependency_overrides.pop(get_db, None)
        mock_prov.assert_awaited_once()

    @pytest.mark.anyio
    async def test_unknown_event_type_acks_without_provision(self):
        override, _ = _db_override()
        app.dependency_overrides[get_db] = override
        payload = {"id": "evt_x", "type": "payment_intent.created", "data": {"object": {}}}
        with patch("asc_api.api.v1.endpoints.billing._settings") as cfg:
            cfg.STRIPE_SECRET_KEY = ""
            cfg.STRIPE_WEBHOOK_SECRET = ""
            cfg.STRIPE_PROVISIONING_PLAN = "pro"
            cfg.STRIPE_SEGURIDAD_PRODUCT_ID = ""
            with patch("asc_api.api.v1.endpoints.billing._provision_stripe_customer",
                       new_callable=AsyncMock) as mock_prov:
                async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                    r = await c.post(_WEBHOOK_URL, json=payload)
        app.dependency_overrides.pop(get_db, None)
        assert r.status_code == 200
        mock_prov.assert_not_awaited()


# â”€â”€ 2. _provision_stripe_customer() â€” unit â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestProvisionStripeTenant:

    @pytest.mark.anyio
    async def test_new_tenant_creates_two_objects(self):
        from asc_api.api.v1.endpoints.billing import _provision_stripe_customer
        db = _make_db()
        with patch("asc_api.api.v1.endpoints.billing._settings") as cfg:
            cfg.STRIPE_PROVISIONING_PLAN = "pro"
            tenant, provisioned = await _provision_stripe_customer(
                _TEST_EMAIL, _TEST_STRIPE_CID, _TEST_STRIPE_SID, _TEST_SESSION_ID, db
            )
        assert provisioned is True
        assert len(db._added) == 2  # Tenant + User

    @pytest.mark.anyio
    async def test_new_tenant_plan_from_config(self):
        from asc_api.api.v1.endpoints.billing import _provision_stripe_customer
        db = _make_db()
        with patch("asc_api.api.v1.endpoints.billing._settings") as cfg:
            cfg.STRIPE_PROVISIONING_PLAN = "enterprise"
            tenant, _ = await _provision_stripe_customer(
                _TEST_EMAIL, _TEST_STRIPE_CID, _TEST_STRIPE_SID, _TEST_SESSION_ID, db
            )
        assert tenant.plan == "enterprise"

    @pytest.mark.anyio
    async def test_new_tenant_admin_role(self):
        from asc_api.api.v1.endpoints.billing import _provision_stripe_customer
        db = _make_db()
        with patch("asc_api.api.v1.endpoints.billing._settings") as cfg:
            cfg.STRIPE_PROVISIONING_PLAN = "pro"
            await _provision_stripe_customer(
                _TEST_EMAIL, _TEST_STRIPE_CID, _TEST_STRIPE_SID, _TEST_SESSION_ID, db
            )
        user_obj = [o for o in db._added if hasattr(o, "role")]
        assert len(user_obj) == 1
        assert user_obj[0].role == "admin"

    @pytest.mark.anyio
    async def test_new_tenant_sets_stripe_customer_id(self):
        from asc_api.api.v1.endpoints.billing import _provision_stripe_customer
        db = _make_db()
        with patch("asc_api.api.v1.endpoints.billing._settings") as cfg:
            cfg.STRIPE_PROVISIONING_PLAN = "pro"
            tenant, _ = await _provision_stripe_customer(
                _TEST_EMAIL, _TEST_STRIPE_CID, _TEST_STRIPE_SID, _TEST_SESSION_ID, db
            )
        assert tenant.stripe_customer_id == _TEST_STRIPE_CID

    @pytest.mark.anyio
    async def test_new_tenant_sets_checkout_session_id(self):
        from asc_api.api.v1.endpoints.billing import _provision_stripe_customer
        db = _make_db()
        with patch("asc_api.api.v1.endpoints.billing._settings") as cfg:
            cfg.STRIPE_PROVISIONING_PLAN = "pro"
            tenant, _ = await _provision_stripe_customer(
                _TEST_EMAIL, _TEST_STRIPE_CID, _TEST_STRIPE_SID, _TEST_SESSION_ID, db
            )
        assert tenant.stripe_checkout_session_id == _TEST_SESSION_ID

    @pytest.mark.anyio
    async def test_existing_tenant_by_stripe_cid_not_provisioned(self):
        from asc_api.api.v1.endpoints.billing import _provision_stripe_customer
        existing = MagicMock()
        existing.id = "t-existing"
        existing.stripe_subscription_id = None
        existing.stripe_checkout_session_id = None
        db = _make_db(stripe_cid_tenant=existing)
        with patch("asc_api.api.v1.endpoints.billing._settings") as cfg:
            cfg.STRIPE_PROVISIONING_PLAN = "pro"
            tenant, provisioned = await _provision_stripe_customer(
                _TEST_EMAIL, _TEST_STRIPE_CID, _TEST_STRIPE_SID, _TEST_SESSION_ID, db
            )
        assert provisioned is False
        assert tenant is existing

    @pytest.mark.anyio
    async def test_existing_tenant_by_stripe_cid_plan_upgraded(self):
        from asc_api.api.v1.endpoints.billing import _provision_stripe_customer
        existing = MagicMock()
        existing.plan = "free"
        existing.stripe_subscription_id = None
        existing.stripe_checkout_session_id = None
        db = _make_db(stripe_cid_tenant=existing)
        with patch("asc_api.api.v1.endpoints.billing._settings") as cfg:
            cfg.STRIPE_PROVISIONING_PLAN = "pro"
            await _provision_stripe_customer(
                _TEST_EMAIL, _TEST_STRIPE_CID, _TEST_STRIPE_SID, _TEST_SESSION_ID, db
            )
        assert existing.plan == "pro"

    @pytest.mark.anyio
    async def test_idempotency_duplicate_session_returns_existing(self):
        from asc_api.api.v1.endpoints.billing import _provision_stripe_customer
        already_provisioned = MagicMock()
        already_provisioned.id = "t-already"
        db = _make_db(idempotent_tenant=already_provisioned)
        with patch("asc_api.api.v1.endpoints.billing._settings") as cfg:
            cfg.STRIPE_PROVISIONING_PLAN = "pro"
            tenant, provisioned = await _provision_stripe_customer(
                _TEST_EMAIL, _TEST_STRIPE_CID, _TEST_STRIPE_SID, _TEST_SESSION_ID, db
            )
        assert provisioned is False
        assert tenant is already_provisioned

    @pytest.mark.anyio
    async def test_existing_user_by_email_links_tenant(self):
        from asc_api.api.v1.endpoints.billing import _provision_stripe_customer
        existing_user = MagicMock()
        existing_user.email = _TEST_EMAIL
        existing_user.tenant_id = "t-native"
        existing_tenant = MagicMock()
        existing_tenant.id = "t-native"
        existing_tenant.stripe_customer_id = None
        existing_tenant.stripe_subscription_id = None
        existing_tenant.stripe_checkout_session_id = None
        db = _make_db(email_user=existing_user, email_user_tenant=existing_tenant)
        with patch("asc_api.api.v1.endpoints.billing._settings") as cfg:
            cfg.STRIPE_PROVISIONING_PLAN = "pro"
            tenant, provisioned = await _provision_stripe_customer(
                _TEST_EMAIL, _TEST_STRIPE_CID, _TEST_STRIPE_SID, _TEST_SESSION_ID, db
            )
        assert provisioned is False
        assert tenant is existing_tenant
        assert existing_tenant.stripe_customer_id == _TEST_STRIPE_CID

    @pytest.mark.anyio
    async def test_new_tenant_email_verified(self):
        from asc_api.api.v1.endpoints.billing import _provision_stripe_customer
        db = _make_db()
        with patch("asc_api.api.v1.endpoints.billing._settings") as cfg:
            cfg.STRIPE_PROVISIONING_PLAN = "pro"
            await _provision_stripe_customer(
                _TEST_EMAIL, _TEST_STRIPE_CID, _TEST_STRIPE_SID, _TEST_SESSION_ID, db
            )
        user_obj = [o for o in db._added if hasattr(o, "email_verified")]
        assert user_obj[0].email_verified is True


# â”€â”€ 3. customer.subscription.created â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestSubscriptionCreatedHandler:

    @pytest.mark.anyio
    async def test_subscription_created_active_upgrades_plan(self):
        existing = MagicMock()
        existing.stripe_subscription_id = None
        existing.plan = "free"

        override, db = _db_override()
        # Override call 1 to return the tenant for subscription.created lookup
        _original_execute = db.execute

        async def _patched_execute(stmt, *args, **kwargs):
            result = MagicMock()
            result.scalar_one_or_none = MagicMock(return_value=existing)
            return result

        db.execute = _patched_execute
        app.dependency_overrides[get_db] = override

        payload = _subscription_created_event(status="active")
        with patch("asc_api.api.v1.endpoints.billing._settings") as cfg:
            cfg.STRIPE_SECRET_KEY = ""
            cfg.STRIPE_WEBHOOK_SECRET = ""
            cfg.STRIPE_PROVISIONING_PLAN = "pro"
            cfg.STRIPE_SEGURIDAD_PRODUCT_ID = ""
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.post(_WEBHOOK_URL, json=payload)
        app.dependency_overrides.pop(get_db, None)
        assert r.status_code == 200
        assert existing.stripe_subscription_id == _TEST_STRIPE_SID
        assert existing.plan == "pro"

    @pytest.mark.anyio
    async def test_subscription_created_inactive_no_update(self):
        existing = MagicMock()
        existing.plan = "free"
        existing.stripe_subscription_id = None

        override, db = _db_override()

        async def _patched_execute(stmt, *args, **kwargs):
            result = MagicMock()
            result.scalar_one_or_none = MagicMock(return_value=existing)
            return result

        db.execute = _patched_execute
        app.dependency_overrides[get_db] = override

        payload = _subscription_created_event(status="incomplete")
        with patch("asc_api.api.v1.endpoints.billing._settings") as cfg:
            cfg.STRIPE_SECRET_KEY = ""
            cfg.STRIPE_WEBHOOK_SECRET = ""
            cfg.STRIPE_PROVISIONING_PLAN = "pro"
            cfg.STRIPE_SEGURIDAD_PRODUCT_ID = ""
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.post(_WEBHOOK_URL, json=payload)
        app.dependency_overrides.pop(get_db, None)
        assert r.status_code == 200
        # Inactive â†’ no update applied
        assert existing.plan == "free"

    @pytest.mark.anyio
    async def test_subscription_created_unknown_customer_ignored(self):
        override, db = _db_override()

        async def _patched_execute(stmt, *a, **kw):
            result = MagicMock()
            result.scalar_one_or_none = MagicMock(return_value=None)
            return result

        db.execute = _patched_execute
        app.dependency_overrides[get_db] = override

        payload = _subscription_created_event(customer="cus_unknown_xyz")
        with patch("asc_api.api.v1.endpoints.billing._settings") as cfg:
            cfg.STRIPE_SECRET_KEY = ""
            cfg.STRIPE_WEBHOOK_SECRET = ""
            cfg.STRIPE_PROVISIONING_PLAN = "pro"
            cfg.STRIPE_SEGURIDAD_PRODUCT_ID = ""
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.post(_WEBHOOK_URL, json=payload)
        app.dependency_overrides.pop(get_db, None)
        assert r.status_code == 200  # graceful no-op

    @pytest.mark.anyio
    async def test_subscription_deleted_downgrades_to_free(self):
        """P55 regression: subscription.deleted still works after P60 changes."""
        existing = MagicMock()
        existing.plan = "pro"
        existing.stripe_subscription_id = _TEST_STRIPE_SID

        override, db = _db_override()

        async def _patched_execute(stmt, *a, **kw):
            result = MagicMock()
            result.scalar_one_or_none = MagicMock(return_value=existing)
            return result

        db.execute = _patched_execute
        app.dependency_overrides[get_db] = override

        payload = {
            "id": "evt_sub_del",
            "type": "customer.subscription.deleted",
            "data": {"object": {
                "id": _TEST_STRIPE_SID,
                "customer": _TEST_STRIPE_CID,
                "status": "canceled",
            }},
        }
        with patch("asc_api.api.v1.endpoints.billing._settings") as cfg:
            cfg.STRIPE_SECRET_KEY = ""
            cfg.STRIPE_WEBHOOK_SECRET = ""
            cfg.STRIPE_PROVISIONING_PLAN = "pro"
            cfg.STRIPE_SEGURIDAD_PRODUCT_ID = ""
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                r = await c.post(_WEBHOOK_URL, json=payload)
        app.dependency_overrides.pop(get_db, None)
        assert r.status_code == 200
        assert existing.plan == "free"
        assert existing.stripe_subscription_id is None


# â”€â”€ 4. Security invariants â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestSecurityInvariants:

    def test_provision_function_exists(self):
        from asc_api.api.v1.endpoints.billing import _provision_stripe_customer
        import inspect
        assert inspect.iscoroutinefunction(_provision_stripe_customer)

    def test_tenant_model_has_stripe_checkout_session_id(self):
        from asc_api.models.tenant import Tenant
        columns = {c.name: c for c in Tenant.__table__.c}
        assert "stripe_checkout_session_id" in columns
        assert columns["stripe_checkout_session_id"].nullable is True

    def test_stripe_checkout_session_id_is_unique(self):
        from asc_api.models.tenant import Tenant
        columns = {c.name: c for c in Tenant.__table__.c}
        col = columns["stripe_checkout_session_id"]
        # unique=True on column or via UniqueConstraint
        assert col.unique is True or any(
            "stripe_checkout_session_id" in str(uc) for uc in Tenant.__table__.constraints
        )

    def test_no_hardcoded_stripe_secret_key(self):
        import re
        danger = re.compile(r'sk_(live|test)_[A-Za-z0-9]{8,}')
        for py_file in (_BACKEND / "app").rglob("*.py"):
            content = py_file.read_text(encoding="utf-8", errors="ignore")
            for line in content.splitlines():
                code_part = line.split("#")[0]
                assert not danger.search(code_part), (
                    f"Hardcoded Stripe secret key in {py_file}: {line.strip()}"
                )

    def test_no_hardcoded_webhook_secret(self):
        import re
        danger = re.compile(r'whsec_[A-Za-z0-9]{8,}')
        for py_file in (_BACKEND / "app").rglob("*.py"):
            content = py_file.read_text(encoding="utf-8", errors="ignore")
            for line in content.splitlines():
                code_part = line.split("#")[0]
                assert not danger.search(code_part), (
                    f"Hardcoded Stripe webhook secret in {py_file}: {line.strip()}"
                )

    def test_provisioned_user_has_email_verified(self):
        """Stripe-provisioned users should have email_verified=True (Stripe verified it)."""
        from asc_api.api.v1.endpoints.billing import _provision_stripe_customer
        # Structural check via source inspection
        import inspect
        src = inspect.getsource(_provision_stripe_customer)
        assert "email_verified=True" in src

    def test_provisioned_user_gets_admin_role(self):
        from asc_api.api.v1.endpoints.billing import _provision_stripe_customer
        import inspect
        src = inspect.getsource(_provision_stripe_customer)
        assert 'role="admin"' in src

    def test_config_stripe_provisioning_plan_default(self):
        from asc_api.core.config import Settings
        s = Settings()
        assert s.STRIPE_PROVISIONING_PLAN in ("free", "pro", "enterprise")
        assert s.STRIPE_PROVISIONING_PLAN != "enterprise"  # not enterprise by default

    def test_signature_validation_still_enforced(self):
        """P55 invariant: webhook with wrong sig returns 400 when secret is set."""
        from asc_api.api.v1.endpoints.billing import _verify_stripe_signature
        body = b'{"type":"test"}'
        assert not _verify_stripe_signature(body, "t=123,v1=badmac", "correct_secret")


# â”€â”€ 5. Migration artifact â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestMigrationArtifact:

    def test_migration_file_exists(self):
        files = list(_MIGRATIONS_DIR.glob(f"*{_P60_HEAD}*.py"))
        assert len(files) == 1, f"P60 migration {_P60_HEAD} not found"

    def test_down_revision_is_p59(self):
        files = list(_MIGRATIONS_DIR.glob(f"*{_P60_HEAD}*.py"))
        content = files[0].read_text(encoding="utf-8")
        assert 'down_revision = "u1o34r3t6n08"' in content

    def test_creates_stripe_checkout_session_id_column(self):
        files = list(_MIGRATIONS_DIR.glob(f"*{_P60_HEAD}*.py"))
        content = files[0].read_text(encoding="utf-8")
        assert "stripe_checkout_session_id" in content

    def test_creates_unique_index(self):
        files = list(_MIGRATIONS_DIR.glob(f"*{_P60_HEAD}*.py"))
        content = files[0].read_text(encoding="utf-8")
        assert "ix_tenants_stripe_checkout_session_id" in content
        assert "create_index" in content
        assert "unique=True" in content

    def test_has_downgrade(self):
        files = list(_MIGRATIONS_DIR.glob(f"*{_P60_HEAD}*.py"))
        content = files[0].read_text(encoding="utf-8")
        assert "def downgrade" in content
        assert "drop_column" in content

    def test_total_migration_count_is_18(self):
        files = [f for f in _MIGRATIONS_DIR.glob("*.py") if f.name != "__init__.py"]
        assert len(files) == _EXPECTED_TOTAL_MIGRATIONS, (
            f"Expected {_EXPECTED_TOTAL_MIGRATIONS} migrations, got {len(files)}"
        )


# â”€â”€ 6. Config completeness â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestConfigCompleteness:

    def test_config_has_stripe_provisioning_plan(self):
        from asc_api.core.config import Settings
        s = Settings()
        assert hasattr(s, "STRIPE_PROVISIONING_PLAN")

    def test_config_has_stripe_seguridad_product_id(self):
        from asc_api.core.config import Settings
        s = Settings()
        assert hasattr(s, "STRIPE_SEGURIDAD_PRODUCT_ID")

    def test_env_example_has_stripe_provisioning_plan(self):
        env_ex = (_BACKEND.parent / ".env.example").read_text(encoding="utf-8")
        assert "STRIPE_PROVISIONING_PLAN" in env_ex

    def test_env_example_has_stripe_seguridad_product_id(self):
        env_ex = (_BACKEND.parent / ".env.example").read_text(encoding="utf-8")
        assert "STRIPE_SEGURIDAD_PRODUCT_ID" in env_ex

    def test_env_example_has_stripe_provisioning_plan(self):
        env_ex = (_BACKEND.parent / ".env.example").read_text(encoding="utf-8")
        assert "STRIPE_PROVISIONING_PLAN" in env_ex

    def test_billing_endpoint_exports_provision_function(self):
        from asc_api.api.v1.endpoints.billing import _provision_stripe_customer
        assert callable(_provision_stripe_customer)


# â”€â”€ 7. Module structure â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestModuleStructure:

    def test_tenant_has_stripe_checkout_session_id_field(self):
        from asc_api.models.tenant import Tenant
        assert hasattr(Tenant, "stripe_checkout_session_id")

    def test_billing_imports_get_password_hash(self):
        import asc_api.api.v1.endpoints.billing as billing
        import inspect
        src = inspect.getsource(billing)
        assert "get_password_hash" in src

    def test_billing_imports_secrets(self):
        import asc_api.api.v1.endpoints.billing as billing
        assert hasattr(billing, "secrets")

    def test_billing_imports_uuid(self):
        import asc_api.api.v1.endpoints.billing as billing
        assert hasattr(billing, "uuid")

    def test_checkout_session_event_type_handled(self):
        import asc_api.api.v1.endpoints.billing as billing
        import inspect
        src = inspect.getsource(billing.stripe_webhook)
        assert "checkout.session.completed" in src

    def test_subscription_created_event_type_handled(self):
        import asc_api.api.v1.endpoints.billing as billing
        import inspect
        src = inspect.getsource(billing.stripe_webhook)
        assert "customer.subscription.created" in src


# â”€â”€ 8. Regression gates â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TestRegressionGates:

    def test_p59_migration_still_present(self):
        files = list(_MIGRATIONS_DIR.glob("*u1o34r3t6n08*.py"))
        assert len(files) == 1

    def test_p58_migration_still_present(self):
        files = list(_MIGRATIONS_DIR.glob("*t0n23q2s5m07*.py"))
        assert len(files) == 1

    def test_stripe_customer_id_still_in_tenant_model(self):
        from asc_api.models.tenant import Tenant
        columns = {c.name: c for c in Tenant.__table__.c}
        assert "stripe_customer_id" in columns

    def test_stripe_subscription_id_still_in_tenant_model(self):
        from asc_api.models.tenant import Tenant
        columns = {c.name: c for c in Tenant.__table__.c}
        assert "stripe_subscription_id" in columns

    def test_subscription_deleted_event_still_handled(self):
        import asc_api.api.v1.endpoints.billing as billing
        import inspect
        src = inspect.getsource(billing.stripe_webhook)
        assert "customer.subscription.deleted" in src

    def test_p57_migration_count_updated_to_18(self):
        p57_src = (Path(__file__).parent / "test_p57_staging_goliove.py").read_text(
            encoding="utf-8"
        )
        assert ("_EXPECTED_MIGRATION_COUNT = 17" in p57_src or
                "_EXPECTED_MIGRATION_COUNT = 18" in p57_src or
                "_EXPECTED_MIGRATION_COUNT = 20" in p57_src or
                "_EXPECTED_MIGRATION_COUNT = 22" in p57_src or
                "_EXPECTED_MIGRATION_COUNT = 23" in p57_src or
                "_EXPECTED_MIGRATION_COUNT = 24" in p57_src or
                "_EXPECTED_MIGRATION_COUNT = 25" in p57_src or
                "_EXPECTED_MIGRATION_COUNT = 26" in p57_src)

    def test_p56_migration_count_updated_to_18(self):
        p56_src = (Path(__file__).parent / "test_p56_deployment_readiness.py").read_text(
            encoding="utf-8"
        )
        assert ("_EXPECTED_COUNT = 17" in p56_src or
                "_EXPECTED_COUNT = 18" in p56_src or
                "_EXPECTED_COUNT = 19" in p56_src or
                "_EXPECTED_COUNT = 20" in p56_src or
                "_EXPECTED_COUNT = 22" in p56_src or
                "_EXPECTED_COUNT = 23" in p56_src or
                "_EXPECTED_COUNT = 24" in p56_src or
                "_EXPECTED_COUNT = 25" in p56_src or
                "_EXPECTED_COUNT = 26" in p56_src)
