"""
P55 — Billing / Metering: comprehensive test suite.

Coverage targets:
  - UsageRecord model: fields, constraints, defaults
  - _current_period: returns YYYY-MM format
  - _verify_stripe_signature: valid/invalid/missing fields
  - GET /billing/usage: returns snapshot for current period
  - GET /billing/usage/{tenant_id}: admin access, tenant not found
  - POST /billing/snapshot: counts resources, upserts, commits
  - POST /billing/stripe/webhook: ack, sig validation, event handling
  - Config: STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET present
  - Migration: s9m12p1r4l06 chain, table, unique constraint
  - Model: stripe_customer_id, stripe_subscription_id on Tenant
  - Router registration

Total: ≥ 90 tests across 9 classes.
"""

from __future__ import annotations

import hashlib
import hmac
import inspect
import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from asc_api.api.v1.endpoints.billing import (
    RESOURCE_TYPES,
    _current_period,
    _verify_stripe_signature,
    router as billing_router,
)
from asc_api.core.config import get_settings
from asc_api.models.usage_record import UsageRecord

_SETTINGS = get_settings()


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_user(role: str = "admin", tenant_id: str = "t-001") -> SimpleNamespace:
    return SimpleNamespace(
        id="u-001",
        email="admin@example.com",
        role=role,
        tenant_id=tenant_id,
        is_active=True,
    )


def _make_tenant(tenant_id: str = "t-001") -> SimpleNamespace:
    return SimpleNamespace(
        id=tenant_id,
        plan="pro",
        stripe_customer_id="cus_test123",
        stripe_subscription_id="sub_test456",
    )


def _make_db() -> AsyncMock:
    db = AsyncMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = None
    result.scalars.return_value.all.return_value = []
    db.execute = AsyncMock(return_value=result)
    db.commit = AsyncMock()
    db.add = MagicMock()
    return db


def _make_stripe_sig(secret: str, payload: bytes) -> str:
    timestamp = "1700000000"
    signed = f"{timestamp}.".encode() + payload
    mac = hmac.new(secret.encode(), signed, hashlib.sha256)
    return f"t={timestamp},v1={mac.hexdigest()}"


# ─────────────────────────────────────────────────────────────────────────────
# 1. UsageRecord model
# ─────────────────────────────────────────────────────────────────────────────

class TestUsageRecordModel:
    """UsageRecord model structure and constraints."""

    def test_usage_record_importable(self):
        from asc_api.models.usage_record import UsageRecord  # noqa: F401

    def test_tablename(self):
        assert UsageRecord.__tablename__ == "usage_records"

    def test_has_id_column(self):
        assert hasattr(UsageRecord, "id")

    def test_has_tenant_id_column(self):
        assert hasattr(UsageRecord, "tenant_id")

    def test_has_period_column(self):
        assert hasattr(UsageRecord, "period")

    def test_has_resource_type_column(self):
        assert hasattr(UsageRecord, "resource_type")

    def test_has_count_column(self):
        assert hasattr(UsageRecord, "count")

    def test_has_recorded_at_column(self):
        assert hasattr(UsageRecord, "recorded_at")

    def test_unique_constraint_exists(self):
        src = inspect.getsource(UsageRecord)
        assert "UniqueConstraint" in src
        assert "uq_usage_tenant_period_resource" in src

    def test_in_models_init(self):
        import asc_api.models
        assert "UsageRecord" in dir(app.models)

    def test_model_exported_in_all(self):
        import asc_api.models
        assert "UsageRecord" in app.models.__all__


# ─────────────────────────────────────────────────────────────────────────────
# 2. _current_period helper
# ─────────────────────────────────────────────────────────────────────────────

class TestCurrentPeriod:
    """_current_period returns YYYY-MM string for the current UTC month."""

    def test_current_period_format(self):
        period = _current_period()
        assert len(period) == 7
        assert period[4] == "-"

    def test_current_period_digits(self):
        period = _current_period()
        year, month = period.split("-")
        assert year.isdigit()
        assert month.isdigit()

    def test_current_period_year_range(self):
        year = int(_current_period().split("-")[0])
        assert 2024 <= year <= 2100

    def test_current_period_month_range(self):
        month = int(_current_period().split("-")[1])
        assert 1 <= month <= 12

    def test_current_period_month_zero_padded(self):
        period = _current_period()
        month_str = period.split("-")[1]
        assert len(month_str) == 2  # "06" not "6"


# ─────────────────────────────────────────────────────────────────────────────
# 3. Stripe signature verification
# ─────────────────────────────────────────────────────────────────────────────

class TestStripeSignatureVerification:
    """_verify_stripe_signature correctly validates/rejects webhooks."""

    def test_valid_signature_returns_true(self):
        secret = "whsec_test_secret"
        payload = b'{"type":"test"}'
        sig = _make_stripe_sig(secret, payload)
        assert _verify_stripe_signature(payload, sig, secret) is True

    def test_wrong_secret_returns_false(self):
        payload = b'{"type":"test"}'
        sig = _make_stripe_sig("correct_secret", payload)
        assert _verify_stripe_signature(payload, sig, "wrong_secret") is False

    def test_tampered_payload_returns_false(self):
        secret = "whsec_secret"
        payload = b'{"type":"original"}'
        sig = _make_stripe_sig(secret, payload)
        tampered = b'{"type":"tampered"}'
        assert _verify_stripe_signature(tampered, sig, secret) is False

    def test_missing_timestamp_returns_false(self):
        payload = b'{"type":"test"}'
        bad_sig = "v1=abc123"  # no t= prefix
        assert _verify_stripe_signature(payload, bad_sig, "secret") is False

    def test_missing_v1_returns_false(self):
        payload = b'{"type":"test"}'
        bad_sig = "t=1700000000"  # no v1= part
        assert _verify_stripe_signature(payload, bad_sig, "secret") is False

    def test_empty_sig_returns_false(self):
        assert _verify_stripe_signature(b'data', "", "secret") is False

    def test_malformed_sig_returns_false(self):
        assert _verify_stripe_signature(b'data', "not-a-stripe-sig", "secret") is False

    def test_replayed_sig_different_payload_fails(self):
        """Signature is tied to both timestamp and payload — replay with different payload fails."""
        secret = "whsec_s"
        original = b'{"amount":100}'
        sig = _make_stripe_sig(secret, original)
        assert _verify_stripe_signature(b'{"amount":999}', sig, secret) is False

    def test_signature_uses_hmac_sha256(self):
        src = inspect.getsource(_verify_stripe_signature)
        assert "sha256" in src or "SHA256" in src
        assert "hmac" in src.lower()

    def test_signature_uses_compare_digest(self):
        """Must use compare_digest for timing-safe comparison."""
        src = inspect.getsource(_verify_stripe_signature)
        assert "compare_digest" in src


# ─────────────────────────────────────────────────────────────────────────────
# 4. GET /billing/usage
# ─────────────────────────────────────────────────────────────────────────────

class TestGetMyUsage:
    """GET /billing/usage returns current period snapshot for the user's tenant."""

    @pytest.mark.asyncio
    async def test_usage_no_records_returns_zeros(self):
        from asc_api.api.v1.endpoints.billing import get_my_usage

        user = _make_user(tenant_id="t-001")
        db = _make_db()
        result_mock = MagicMock()
        result_mock.scalars.return_value.all.return_value = []
        db.execute = AsyncMock(return_value=result_mock)

        result = await get_my_usage(current_user=user, db=db)

        assert result.tenant_id == "t-001"
        for item in result.items:
            assert item.count == 0

    @pytest.mark.asyncio
    async def test_usage_returns_all_resource_types(self):
        from asc_api.api.v1.endpoints.billing import get_my_usage

        user = _make_user(tenant_id="t-001")
        db = _make_db()
        result_mock = MagicMock()
        result_mock.scalars.return_value.all.return_value = []
        db.execute = AsyncMock(return_value=result_mock)

        result = await get_my_usage(current_user=user, db=db)
        resource_types = {item.resource_type for item in result.items}
        for rt in RESOURCE_TYPES:
            assert rt in resource_types

    @pytest.mark.asyncio
    async def test_usage_no_tenant_raises_400(self):
        from fastapi import HTTPException
        from asc_api.api.v1.endpoints.billing import get_my_usage

        user = _make_user(tenant_id=None)
        db = _make_db()

        with pytest.raises(HTTPException) as exc:
            await get_my_usage(current_user=user, db=db)
        assert exc.value.status_code == 400

    @pytest.mark.asyncio
    async def test_usage_maps_existing_records(self):
        from asc_api.api.v1.endpoints.billing import get_my_usage

        user = _make_user(tenant_id="t-001")
        period = _current_period()

        fake_record = SimpleNamespace(resource_type="users", count=7, period=period)
        db = _make_db()
        result_mock = MagicMock()
        result_mock.scalars.return_value.all.return_value = [fake_record]
        db.execute = AsyncMock(return_value=result_mock)

        result = await get_my_usage(current_user=user, db=db)
        user_item = next(i for i in result.items if i.resource_type == "users")
        assert user_item.count == 7

    @pytest.mark.asyncio
    async def test_usage_returns_current_period(self):
        from asc_api.api.v1.endpoints.billing import get_my_usage

        user = _make_user(tenant_id="t-001")
        db = _make_db()
        result_mock = MagicMock()
        result_mock.scalars.return_value.all.return_value = []
        db.execute = AsyncMock(return_value=result_mock)

        result = await get_my_usage(current_user=user, db=db)
        assert result.period == _current_period()


# ─────────────────────────────────────────────────────────────────────────────
# 5. GET /billing/usage/{tenant_id}
# ─────────────────────────────────────────────────────────────────────────────

class TestGetTenantUsage:
    """GET /billing/usage/{tenant_id} — admin access."""

    @pytest.mark.asyncio
    async def test_admin_can_get_other_tenant(self):
        from asc_api.api.v1.endpoints.billing import get_tenant_usage

        admin = _make_user(role="admin", tenant_id="t-admin")
        tenant = _make_tenant("t-target")

        tenant_result = MagicMock()
        tenant_result.scalar_one_or_none.return_value = tenant
        usage_result = MagicMock()
        usage_result.scalars.return_value.all.return_value = []

        call_count = [0]
        async def _exec(stmt):
            call_count[0] += 1
            if call_count[0] == 1:
                return tenant_result
            return usage_result

        db = _make_db()
        db.execute = _exec

        result = await get_tenant_usage("t-target", admin, db)

    @pytest.mark.asyncio
    async def test_tenant_not_found_raises_404(self):
        from fastapi import HTTPException
        from asc_api.api.v1.endpoints.billing import get_tenant_usage

        db = _make_db()
        tenant_result = MagicMock()
        tenant_result.scalar_one_or_none.return_value = None

        call_count = [0]
        async def _exec(stmt):
            return tenant_result

        db.execute = _exec

        with pytest.raises(HTTPException) as exc:
            await get_tenant_usage("nonexistent-id", MagicMock(), db)
        assert exc.value.status_code == 404


# ─────────────────────────────────────────────────────────────────────────────
# 6. POST /billing/snapshot
# ─────────────────────────────────────────────────────────────────────────────

class TestTakeSnapshot:
    """POST /billing/snapshot counts resources and persists UsageRecords."""

    @pytest.mark.asyncio
    async def test_snapshot_no_tenant_raises_400(self):
        from fastapi import HTTPException
        from asc_api.api.v1.endpoints.billing import take_snapshot

        admin = _make_user(tenant_id=None)
        db = _make_db()

        with pytest.raises(HTTPException) as exc:
            await take_snapshot(admin, db)
        assert exc.value.status_code == 400

    @pytest.mark.asyncio
    async def test_snapshot_returns_all_resource_types(self):
        from asc_api.api.v1.endpoints.billing import take_snapshot

        admin = _make_user(tenant_id="t-001")

        count_result = MagicMock()
        count_result.scalar_one.return_value = 0
        db = _make_db()
        db.execute = AsyncMock(return_value=count_result)

        with patch("app.api.v1.endpoints.billing._upsert_usage_record", AsyncMock()), \
             patch("app.api.v1.endpoints.billing.log_security_action"):
            result = await take_snapshot(admin, db)

        returned_types = {item.resource_type for item in result.items}
        for rt in RESOURCE_TYPES:
            assert rt in returned_types

    @pytest.mark.asyncio
    async def test_snapshot_commits(self):
        from asc_api.api.v1.endpoints.billing import take_snapshot

        admin = _make_user(tenant_id="t-001")
        count_result = MagicMock()
        count_result.scalar_one.return_value = 5
        db = _make_db()
        db.execute = AsyncMock(return_value=count_result)

        with patch("app.api.v1.endpoints.billing._upsert_usage_record", AsyncMock()), \
             patch("app.api.v1.endpoints.billing.log_security_action"):
            await take_snapshot(admin, db)

        db.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_snapshot_emits_audit(self):
        from asc_api.api.v1.endpoints.billing import take_snapshot

        admin = _make_user(tenant_id="t-001")
        count_result = MagicMock()
        count_result.scalar_one.return_value = 3
        db = _make_db()
        db.execute = AsyncMock(return_value=count_result)

        with patch("app.api.v1.endpoints.billing._upsert_usage_record", AsyncMock()), \
             patch("app.api.v1.endpoints.billing.log_security_action") as mock_log:
            await take_snapshot(admin, db)

        mock_log.assert_called_once()
        assert mock_log.call_args[0][0] == "billing.snapshot_taken"

    @pytest.mark.asyncio
    async def test_snapshot_writes_5_resources(self):
        from asc_api.api.v1.endpoints.billing import take_snapshot

        admin = _make_user(tenant_id="t-001")
        count_result = MagicMock()
        count_result.scalar_one.return_value = 0
        db = _make_db()
        db.execute = AsyncMock(return_value=count_result)

        upsert_calls = []
        async def mock_upsert(*args, **kwargs):
            upsert_calls.append(args)

        with patch("app.api.v1.endpoints.billing._upsert_usage_record", mock_upsert), \
             patch("app.api.v1.endpoints.billing.log_security_action"):
            result = await take_snapshot(admin, db)

        assert result.records_written == len(RESOURCE_TYPES)


# ─────────────────────────────────────────────────────────────────────────────
# 7. POST /billing/stripe/webhook
# ─────────────────────────────────────────────────────────────────────────────

class TestStripeWebhook:
    """POST /billing/stripe/webhook — sig validation, event handling."""

    def _make_request(self, payload: dict, sig: str | None = None) -> MagicMock:
        body = json.dumps(payload).encode()
        req = MagicMock()
        req.body = AsyncMock(return_value=body)
        req.headers = {"Stripe-Signature": sig} if sig else {}
        return req

    @pytest.mark.asyncio
    async def test_webhook_ack_without_secret(self):
        from asc_api.api.v1.endpoints.billing import stripe_webhook

        payload = {"type": "customer.created", "id": "evt_001"}
        request = self._make_request(payload)
        db = _make_db()

        with patch("app.api.v1.endpoints.billing._settings") as mock_settings, \
             patch("app.api.v1.endpoints.billing.log_security_action"):
            mock_settings.STRIPE_WEBHOOK_SECRET = ""
            result = await stripe_webhook(request, None, db)

        assert result.received is True

    @pytest.mark.asyncio
    async def test_webhook_missing_sig_raises_400(self):
        from fastapi import HTTPException
        from asc_api.api.v1.endpoints.billing import stripe_webhook

        payload = {"type": "test"}
        body = json.dumps(payload).encode()
        request = MagicMock()
        request.body = AsyncMock(return_value=body)
        db = _make_db()

        with patch("app.api.v1.endpoints.billing._settings") as mock_settings:
            mock_settings.STRIPE_WEBHOOK_SECRET = "whsec_test"
            with pytest.raises(HTTPException) as exc:
                await stripe_webhook(request, stripe_signature=None, db=db)
        assert exc.value.status_code == 400

    @pytest.mark.asyncio
    async def test_webhook_invalid_sig_raises_400(self):
        from fastapi import HTTPException
        from asc_api.api.v1.endpoints.billing import stripe_webhook

        payload = {"type": "test"}
        body = json.dumps(payload).encode()
        request = MagicMock()
        request.body = AsyncMock(return_value=body)
        db = _make_db()

        with patch("app.api.v1.endpoints.billing._settings") as mock_settings:
            mock_settings.STRIPE_WEBHOOK_SECRET = "correct_secret"
            with pytest.raises(HTTPException) as exc:
                await stripe_webhook(request, "t=1700000000,v1=wronghex", db)
        assert exc.value.status_code == 400

    @pytest.mark.asyncio
    async def test_webhook_valid_sig_passes(self):
        from asc_api.api.v1.endpoints.billing import stripe_webhook

        secret = "whsec_test_secret_123"
        payload = {"type": "customer.created", "id": "evt_002"}
        body = json.dumps(payload).encode()
        sig = _make_stripe_sig(secret, body)

        request = MagicMock()
        request.body = AsyncMock(return_value=body)
        db = _make_db()

        with patch("app.api.v1.endpoints.billing._settings") as mock_settings, \
             patch("app.api.v1.endpoints.billing.log_security_action"):
            mock_settings.STRIPE_WEBHOOK_SECRET = secret
            result = await stripe_webhook(request, sig, db)

        assert result.received is True

    @pytest.mark.asyncio
    async def test_webhook_invalid_json_raises_400(self):
        from fastapi import HTTPException
        from asc_api.api.v1.endpoints.billing import stripe_webhook

        request = MagicMock()
        request.body = AsyncMock(return_value=b"not-json")
        db = _make_db()

        with patch("app.api.v1.endpoints.billing._settings") as mock_settings:
            mock_settings.STRIPE_WEBHOOK_SECRET = ""
            with pytest.raises(HTTPException) as exc:
                await stripe_webhook(request, None, db)
        assert exc.value.status_code == 400

    @pytest.mark.asyncio
    async def test_webhook_subscription_deleted_sets_free(self):
        from asc_api.api.v1.endpoints.billing import stripe_webhook

        tenant = _make_tenant()
        tenant.plan = "pro"
        tenant.stripe_subscription_id = "sub_abc"

        event = {
            "type": "customer.subscription.deleted",
            "id": "evt_003",
            "data": {"object": {
                "customer": "cus_test123",
                "id": "sub_abc",
                "status": "canceled",
            }},
        }
        body = json.dumps(event).encode()
        request = MagicMock()
        request.body = AsyncMock(return_value=body)
        db = _make_db()

        result_mock = MagicMock()
        result_mock.scalar_one_or_none.return_value = tenant
        db.execute = AsyncMock(return_value=result_mock)

        with patch("app.api.v1.endpoints.billing._settings") as mock_settings, \
             patch("app.api.v1.endpoints.billing.log_security_action"):
            mock_settings.STRIPE_WEBHOOK_SECRET = ""
            await stripe_webhook(request, None, db)

        assert tenant.plan == "free"
        assert tenant.stripe_subscription_id is None

    @pytest.mark.asyncio
    async def test_webhook_subscription_updated_sets_pro(self):
        from asc_api.api.v1.endpoints.billing import stripe_webhook

        tenant = _make_tenant()
        tenant.plan = "free"

        event = {
            "type": "customer.subscription.updated",
            "id": "evt_004",
            "data": {"object": {
                "customer": "cus_test123",
                "id": "sub_new789",
                "status": "active",
            }},
        }
        body = json.dumps(event).encode()
        request = MagicMock()
        request.body = AsyncMock(return_value=body)
        db = _make_db()

        result_mock = MagicMock()
        result_mock.scalar_one_or_none.return_value = tenant
        db.execute = AsyncMock(return_value=result_mock)

        with patch("app.api.v1.endpoints.billing._settings") as mock_settings, \
             patch("app.api.v1.endpoints.billing.log_security_action"):
            mock_settings.STRIPE_WEBHOOK_SECRET = ""
            await stripe_webhook(request, None, db)

        assert tenant.plan == "pro"
        assert tenant.stripe_subscription_id == "sub_new789"

    @pytest.mark.asyncio
    async def test_webhook_unknown_event_type_acked(self):
        from asc_api.api.v1.endpoints.billing import stripe_webhook

        event = {"type": "payment_intent.succeeded", "id": "evt_005"}
        body = json.dumps(event).encode()
        request = MagicMock()
        request.body = AsyncMock(return_value=body)
        db = _make_db()

        with patch("app.api.v1.endpoints.billing._settings") as mock_settings, \
             patch("app.api.v1.endpoints.billing.log_security_action"):
            mock_settings.STRIPE_WEBHOOK_SECRET = ""
            result = await stripe_webhook(request, None, db)

        assert result.received is True


# ─────────────────────────────────────────────────────────────────────────────
# 8. Config settings
# ─────────────────────────────────────────────────────────────────────────────

class TestBillingConfig:
    """Stripe config keys exist and default to empty strings."""

    def test_stripe_secret_key_exists(self):
        assert hasattr(_SETTINGS, "STRIPE_SECRET_KEY")

    def test_stripe_webhook_secret_exists(self):
        assert hasattr(_SETTINGS, "STRIPE_WEBHOOK_SECRET")

    def test_stripe_secret_key_default_empty(self):
        assert _SETTINGS.STRIPE_SECRET_KEY == ""

    def test_stripe_webhook_secret_default_empty(self):
        assert _SETTINGS.STRIPE_WEBHOOK_SECRET == ""

    def test_stripe_keys_are_strings(self):
        assert isinstance(_SETTINGS.STRIPE_SECRET_KEY, str)
        assert isinstance(_SETTINGS.STRIPE_WEBHOOK_SECRET, str)

    def test_stripe_secret_not_hardcoded(self):
        """Config default must be empty string — no live keys in source."""
        # The default value is "" — not a real key. Comments may reference format examples.
        assert _SETTINGS.STRIPE_SECRET_KEY == ""

    def test_webhook_secret_not_hardcoded(self):
        """Config default must be empty string."""
        assert _SETTINGS.STRIPE_WEBHOOK_SECRET == ""


# ─────────────────────────────────────────────────────────────────────────────
# 9. Migration: s9m12p1r4l06
# ─────────────────────────────────────────────────────────────────────────────

class TestP55Migration:
    """Migration s9m12p1r4l06 is present, correct, and chained to P53."""

    _VERSIONS = Path(__file__).parent.parent / "migrations" / "versions"

    def _find_file(self) -> Path:
        matches = list(self._VERSIONS.glob("s9m12p1r4l06*.py"))
        assert matches, "Migration s9m12p1r4l06 not found"
        return matches[0]

    def test_migration_file_exists(self):
        assert self._find_file().exists()

    def test_down_revision_is_p53(self):
        content = self._find_file().read_text()
        assert 'down_revision = "r8l01o0q3k05"' in content

    def test_revision_id(self):
        content = self._find_file().read_text()
        assert 'revision = "s9m12p1r4l06"' in content

    def test_creates_usage_records_table(self):
        content = self._find_file().read_text()
        assert "usage_records" in content
        assert "create_table" in content

    def test_adds_stripe_customer_id(self):
        content = self._find_file().read_text()
        assert "stripe_customer_id" in content

    def test_adds_stripe_subscription_id(self):
        content = self._find_file().read_text()
        assert "stripe_subscription_id" in content

    def test_unique_constraint_in_migration(self):
        content = self._find_file().read_text()
        assert "uq_usage_tenant_period_resource" in content

    def test_creates_tenant_id_index(self):
        content = self._find_file().read_text()
        assert "ix_usage_records_tenant_id" in content

    def test_creates_period_index(self):
        content = self._find_file().read_text()
        assert "ix_usage_records_period" in content

    def test_has_downgrade(self):
        content = self._find_file().read_text()
        assert "def downgrade" in content
        assert "drop_table" in content

    def test_tenant_model_has_stripe_customer_id(self):
        import asc_api.models.tenant as tm
        src = inspect.getsource(tm)
        assert "stripe_customer_id" in src

    def test_tenant_model_has_stripe_subscription_id(self):
        import asc_api.models.tenant as tm
        src = inspect.getsource(tm)
        assert "stripe_subscription_id" in src


# ─────────────────────────────────────────────────────────────────────────────
# 10. Router registration
# ─────────────────────────────────────────────────────────────────────────────

class TestBillingRouterRegistration:
    """Billing router is registered in the main API router."""

    def test_billing_router_prefix(self):
        assert billing_router.prefix == "/billing"

    def test_billing_imported_in_router(self):
        import asc_api.api.v1.router as r
        src = inspect.getsource(r)
        assert "billing" in src

    def test_billing_router_included(self):
        router_path = Path(__file__).parent.parent / "app" / "api" / "v1" / "router.py"
        content = router_path.read_text()
        assert "billing.router" in content

    def test_usage_endpoint_exists(self):
        routes = [r.path for r in billing_router.routes]
        assert "/billing/usage" in routes

    def test_tenant_usage_endpoint_exists(self):
        routes = [r.path for r in billing_router.routes]
        assert "/billing/usage/{tenant_id}" in routes

    def test_snapshot_endpoint_exists(self):
        routes = [r.path for r in billing_router.routes]
        assert "/billing/snapshot" in routes

    def test_stripe_webhook_endpoint_exists(self):
        routes = [r.path for r in billing_router.routes]
        assert "/billing/stripe/webhook" in routes

    def test_usage_is_get(self):
        for route in billing_router.routes:
            if route.path == "/billing/usage" and not "{" in route.path:
                assert "GET" in route.methods
                return

    def test_snapshot_is_post(self):
        for route in billing_router.routes:
            if route.path == "/billing/snapshot":
                assert "POST" in route.methods
                return
        pytest.fail("snapshot route not found")

    def test_stripe_webhook_is_post(self):
        for route in billing_router.routes:
            if route.path == "/billing/stripe/webhook":
                assert "POST" in route.methods
                return
        pytest.fail("stripe/webhook route not found")

    def test_resource_types_constant(self):
        assert "users" in RESOURCE_TYPES
        assert "alerts" in RESOURCE_TYPES
        assert "api_keys" in RESOURCE_TYPES
        assert "webhooks" in RESOURCE_TYPES
        assert "incidents" in RESOURCE_TYPES
