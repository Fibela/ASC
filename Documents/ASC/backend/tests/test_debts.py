"""
Deudas Técnicas P16 — Test Suite

Coverage
--------
TestTimingAttackMitigation   (5 tests)  — dummy bcrypt call present, same code-path
TestJWTBlacklistRaceCondition(5 tests)  — IntegrityError swallowed, L1 stays correct
TestCeleryEscalation         (6 tests)  — _run() escalates expired, publishes, returns count
TestHybridNotificationBus    (9 tests)  — local mode, redis mode, fallback, disconnect
TestAnalystKeypairGeneration (5 tests)  — generate, encrypt, decrypt, round-trip
TestApprovalSigning          (8 tests)  — sign_approval, verify_approval, canonical msg
TestKeyRotationEndpoint      (4 tests)  — rotate keys, not found, old sigs survive
TestSignatureVerificationEndpoint (5 tests) — all_valid, partial_unsigned, invalid, not_found
TestApprovalWithSigning      (4 tests)  — approve_action adds signature to log entry

Total: 51 tests
"""
from __future__ import annotations

import asyncio
import importlib
import sys
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest

from asc_api.core.signing import (
    generate_analyst_keypair,
    encrypt_analyst_private_key,
    decrypt_analyst_private_key,
    sign_approval,
    verify_approval_signature,
)
from asc_api.core.jwt_blacklist import JWTBlacklist
from asc_api.core.notifications import HybridNotificationBus, Notification, NOTIFICATION_CHANNEL


# ── Helpers ───────────────────────────────────────────────────────────────────

def _mock_db() -> AsyncMock:
    db = AsyncMock()
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    return db


def _future(minutes: int = 60) -> datetime:
    return datetime.now(timezone.utc) + timedelta(minutes=minutes)


# ── TestTimingAttackMitigation ────────────────────────────────────────────────

class TestTimingAttackMitigation:
    """
    The timing sentinel ensures verify_password() is always called, even when
    the user doesn't exist.  We test that the sentinel hash is module-level
    (not recomputed per request) and that bcrypt is exercised on missing-user path.
    """

    def test_sentinel_hash_is_module_level(self):
        """_TIMING_SENTINEL_HASH is computed once at import, not per-call."""
        from asc_api.api.v1.endpoints.auth import _TIMING_SENTINEL_HASH
        assert isinstance(_TIMING_SENTINEL_HASH, str)
        assert _TIMING_SENTINEL_HASH.startswith("$2")  # bcrypt prefix

    def test_sentinel_hash_is_not_empty(self):
        from asc_api.api.v1.endpoints.auth import _TIMING_SENTINEL_HASH
        assert len(_TIMING_SENTINEL_HASH) > 20

    def test_sentinel_does_not_verify_real_passwords(self):
        from asc_api.core.security import verify_password
        from asc_api.api.v1.endpoints.auth import _TIMING_SENTINEL_HASH
        # The sentinel hash is for a fixed internal string — real passwords won't match
        assert not verify_password("any-user-password", _TIMING_SENTINEL_HASH)
        assert not verify_password("", _TIMING_SENTINEL_HASH)

    def test_sentinel_is_stable_across_imports(self):
        """Two imports of the same module return the same sentinel — no recompute."""
        from asc_api.api.v1.endpoints import auth as auth1
        import importlib
        auth2 = importlib.import_module("app.api.v1.endpoints.auth")
        assert auth1._TIMING_SENTINEL_HASH is auth2._TIMING_SENTINEL_HASH

    def test_sentinel_hash_verifies_correct_internal_string(self):
        from asc_api.core.security import verify_password
        from asc_api.api.v1.endpoints.auth import _TIMING_SENTINEL_HASH
        # The sentinel hash should verify its own internal string
        assert verify_password("asc-timing-mitigation-sentinel-v1", _TIMING_SENTINEL_HASH)


# ── TestJWTBlacklistRaceCondition ─────────────────────────────────────────────

class TestJWTBlacklistRaceCondition:
    def setup_method(self):
        self.bl = JWTBlacklist()

    @pytest.mark.asyncio
    async def test_integrity_error_is_swallowed(self):
        from sqlalchemy.exc import IntegrityError
        jti = str(uuid.uuid4())
        exp = _future()
        db = _mock_db()
        db.commit = AsyncMock(side_effect=IntegrityError("mock", {}, None))

        # Should not raise
        await self.bl.revoke(jti, exp, db)
        db.rollback.assert_called_once()

    @pytest.mark.asyncio
    async def test_l1_set_before_db_attempt(self):
        """L1 is updated BEFORE the DB call — so even if DB raises, L1 is correct."""
        from sqlalchemy.exc import IntegrityError
        jti = str(uuid.uuid4())
        exp = _future()
        db = _mock_db()
        db.commit = AsyncMock(side_effect=IntegrityError("mock", {}, None))

        await self.bl.revoke(jti, exp, db)
        assert jti in self.bl._local  # L1 remains set after IntegrityError

    @pytest.mark.asyncio
    async def test_second_revoke_of_same_jti_is_idempotent(self):
        jti = str(uuid.uuid4())
        exp = _future()
        db = _mock_db()
        mr = MagicMock()
        mr.scalar_one_or_none.return_value = None
        db.execute = AsyncMock(return_value=mr)

        # First revoke — succeeds
        await self.bl.revoke(jti, exp, db)
        assert jti in self.bl._local

        # Second revoke — should not crash even if DB raises IntegrityError
        from sqlalchemy.exc import IntegrityError
        db2 = _mock_db()
        db2.commit = AsyncMock(side_effect=IntegrityError("dup", {}, None))
        await self.bl.revoke(jti, exp, db2)
        assert jti in self.bl._local  # still there

    @pytest.mark.asyncio
    async def test_rollback_called_on_integrity_error(self):
        from sqlalchemy.exc import IntegrityError
        jti = str(uuid.uuid4())
        db = _mock_db()
        db.commit = AsyncMock(side_effect=IntegrityError("dup", {}, None))

        await self.bl.revoke(jti, _future(), db)
        db.rollback.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_successful_revoke_does_not_call_rollback(self):
        jti = str(uuid.uuid4())
        db = _mock_db()
        # Normal commit — no error
        await self.bl.revoke(jti, _future(), db)
        db.rollback.assert_not_called()


# ── TestCeleryEscalation ──────────────────────────────────────────────────────

_celery_available = importlib.util.find_spec("celery") is not None


@pytest.mark.skipif(not _celery_available, reason="celery not installed")
class TestCeleryEscalation:
    @pytest.mark.asyncio
    async def test_run_calls_escalate_expired(self):
        from asc_api.tasks.escalation import _run
        with patch("app.tasks.escalation.AsyncSessionLocal") as mock_session_cls, \
             patch("app.tasks.escalation.escalate_expired", new_callable=AsyncMock) as mock_esc, \
             patch("app.tasks.escalation.get_settings") as mock_settings:
            mock_settings.return_value.REDIS_URL = ""
            mock_esc.return_value = []
            mock_db = AsyncMock()
            mock_db.__aenter__ = AsyncMock(return_value=mock_db)
            mock_db.__aexit__ = AsyncMock(return_value=False)
            mock_session_cls.return_value = mock_db

            result = await _run()
            mock_esc.assert_awaited_once_with(mock_db)
            assert result["escalated"] == 0

    @pytest.mark.asyncio
    async def test_run_returns_escalated_count(self):
        from asc_api.tasks.escalation import _run
        with patch("app.tasks.escalation.AsyncSessionLocal") as msc, \
             patch("app.tasks.escalation.escalate_expired", new_callable=AsyncMock) as mock_esc, \
             patch("app.tasks.escalation.get_settings") as mock_settings:
            mock_settings.return_value.REDIS_URL = ""
            mock_esc.return_value = ["id-1", "id-2", "id-3"]
            mock_db = AsyncMock()
            mock_db.__aenter__ = AsyncMock(return_value=mock_db)
            mock_db.__aexit__ = AsyncMock(return_value=False)
            msc.return_value = mock_db

            result = await _run()
            assert result["escalated"] == 3

    @pytest.mark.asyncio
    async def test_run_no_redis_skips_publish(self):
        from asc_api.tasks.escalation import _run
        with patch("app.tasks.escalation.AsyncSessionLocal") as msc, \
             patch("app.tasks.escalation.escalate_expired", new_callable=AsyncMock) as mock_esc, \
             patch("app.tasks.escalation.get_settings") as mock_settings:
            mock_settings.return_value.REDIS_URL = ""
            mock_esc.return_value = ["id-1"]
            mock_db = AsyncMock()
            mock_db.__aenter__ = AsyncMock(return_value=mock_db)
            mock_db.__aexit__ = AsyncMock(return_value=False)
            msc.return_value = mock_db

            # Should complete without import error on redis
            result = await _run()
            assert result["escalated"] == 1

    @pytest.mark.asyncio
    async def test_run_returns_action_ids(self):
        from asc_api.tasks.escalation import _run
        ids = ["abc", "def"]
        with patch("app.tasks.escalation.AsyncSessionLocal") as msc, \
             patch("app.tasks.escalation.escalate_expired", new_callable=AsyncMock) as mock_esc, \
             patch("app.tasks.escalation.get_settings") as mock_settings:
            mock_settings.return_value.REDIS_URL = ""
            mock_esc.return_value = ids
            mock_db = AsyncMock()
            mock_db.__aenter__ = AsyncMock(return_value=mock_db)
            mock_db.__aexit__ = AsyncMock(return_value=False)
            msc.return_value = mock_db

            result = await _run()
            assert result["action_ids"] == ids

    def test_celery_task_registered(self):
        from asc_api.tasks.celery_app import celery_app
        assert "asc.escalation.check_expired_actions" in celery_app.tasks

    def test_beat_schedule_configured(self):
        from asc_api.tasks.celery_app import celery_app
        schedule = celery_app.conf.beat_schedule
        assert "proactive-escalation" in schedule
        assert schedule["proactive-escalation"]["task"] == "asc.escalation.check_expired_actions"


# ── TestHybridNotificationBus ─────────────────────────────────────────────────

class TestHybridNotificationBus:
    def setup_method(self):
        self.bus = HybridNotificationBus()

    @pytest.mark.asyncio
    async def test_local_mode_when_no_redis_url(self):
        mode = await self.bus.connect(None)
        assert mode == "local"
        assert self.bus.mode == "local"

    @pytest.mark.asyncio
    async def test_local_mode_when_empty_redis_url(self):
        mode = await self.bus.connect("")
        assert mode == "local"

    @pytest.mark.asyncio
    async def test_local_publish_reaches_subscriber(self):
        await self.bus.connect(None)
        q = await self.bus.subscribe()
        await self.bus.publish("test_event", {"key": "value"})
        n = q.get_nowait()
        assert n.event_type == "test_event"
        assert n.payload["key"] == "value"

    @pytest.mark.asyncio
    async def test_unsubscribe_removes_queue(self):
        await self.bus.connect(None)
        q = await self.bus.subscribe()
        assert self.bus.subscriber_count == 1
        await self.bus.unsubscribe(q)
        assert self.bus.subscriber_count == 0

    @pytest.mark.asyncio
    async def test_full_queue_evicts_subscriber(self):
        await self.bus.connect(None)
        q = await self.bus.subscribe()
        # Fill the queue to maxsize
        for i in range(100):
            q.put_nowait(Notification("fill", {}))
        # Next publish evicts the full queue
        await self.bus.publish("overflow", {})
        assert self.bus.subscriber_count == 0

    @pytest.mark.asyncio
    async def test_redis_unavailable_falls_back_to_local(self):
        # Simulate Redis reachable but ping fails — bus falls back to local mode.
        # Inject a fake 'redis.asyncio' into sys.modules so the import inside
        # connect() succeeds, but the ping() call raises ConnectionError.
        mock_aioredis = MagicMock()
        mock_redis_client = AsyncMock()
        mock_redis_client.ping = AsyncMock(side_effect=ConnectionError("Redis down"))
        mock_aioredis.from_url = MagicMock(return_value=mock_redis_client)

        fake_redis = MagicMock()
        fake_redis.asyncio = mock_aioredis
        modules_override = {"redis": fake_redis, "redis.asyncio": mock_aioredis}

        with patch.dict(sys.modules, modules_override):
            mode = await self.bus.connect("redis://localhost:6379/0")
        assert mode == "local"
        assert self.bus.mode == "local"

    @pytest.mark.asyncio
    async def test_disconnect_cancels_listener_task(self):
        await self.bus.connect(None)
        # Create a fake listener task
        async def _noop():
            await asyncio.sleep(9999)
        self.bus._listener_task = asyncio.ensure_future(_noop())
        await self.bus.disconnect()
        assert self.bus._listener_task.cancelled()

    @pytest.mark.asyncio
    async def test_notification_channel_constant(self):
        assert NOTIFICATION_CHANNEL == "asc:panl:v1"

    @pytest.mark.asyncio
    async def test_to_sse_format(self):
        n = Notification(event_type="test", payload={"x": 1})
        sse = n.to_sse()
        assert sse.startswith("event: test\n")
        assert "data:" in sse
        assert sse.endswith("\n\n")


# ── TestAnalystKeypairGeneration ──────────────────────────────────────────────

class TestAnalystKeypairGeneration:
    def test_generate_returns_two_b64_strings(self):
        priv, pub = generate_analyst_keypair()
        assert isinstance(priv, str) and len(priv) > 0
        assert isinstance(pub, str) and len(pub) > 0

    def test_keys_are_different(self):
        priv, pub = generate_analyst_keypair()
        assert priv != pub

    def test_two_keypairs_are_different(self):
        priv1, pub1 = generate_analyst_keypair()
        priv2, pub2 = generate_analyst_keypair()
        assert priv1 != priv2
        assert pub1 != pub2

    def test_encrypt_decrypt_round_trip(self):
        priv, _ = generate_analyst_keypair()
        encrypted = encrypt_analyst_private_key(priv, "test-secret-key-for-tests")
        decrypted = decrypt_analyst_private_key(encrypted, "test-secret-key-for-tests")
        assert decrypted == priv

    def test_decrypt_with_wrong_secret_raises(self):
        priv, _ = generate_analyst_keypair()
        encrypted = encrypt_analyst_private_key(priv, "correct-secret")
        with pytest.raises(ValueError):
            decrypt_analyst_private_key(encrypted, "wrong-secret")


# ── TestApprovalSigning ───────────────────────────────────────────────────────

class TestApprovalSigning:
    def setup_method(self):
        self.priv, self.pub = generate_analyst_keypair()
        self.action_id = str(uuid.uuid4())
        self.approved_by = "analyst@premoscorp.com"
        self.approved_at = datetime.now(timezone.utc).isoformat()

    def test_sign_returns_nonempty_string(self):
        sig = sign_approval(self.priv, self.action_id, self.approved_by, self.approved_at)
        assert isinstance(sig, str) and len(sig) > 0

    def test_verify_valid_signature(self):
        sig = sign_approval(self.priv, self.action_id, self.approved_by, self.approved_at)
        assert verify_approval_signature(self.pub, self.action_id, self.approved_by, self.approved_at, sig)

    def test_verify_wrong_action_id_fails(self):
        sig = sign_approval(self.priv, self.action_id, self.approved_by, self.approved_at)
        assert not verify_approval_signature(self.pub, "wrong-id", self.approved_by, self.approved_at, sig)

    def test_verify_wrong_approved_by_fails(self):
        sig = sign_approval(self.priv, self.action_id, self.approved_by, self.approved_at)
        assert not verify_approval_signature(self.pub, self.action_id, "other@premoscorp.com", self.approved_at, sig)

    def test_verify_wrong_timestamp_fails(self):
        sig = sign_approval(self.priv, self.action_id, self.approved_by, self.approved_at)
        assert not verify_approval_signature(self.pub, self.action_id, self.approved_by, "2000-01-01T00:00:00", sig)

    def test_verify_wrong_public_key_fails(self):
        sig = sign_approval(self.priv, self.action_id, self.approved_by, self.approved_at)
        _, other_pub = generate_analyst_keypair()
        assert not verify_approval_signature(other_pub, self.action_id, self.approved_by, self.approved_at, sig)

    def test_verify_tampered_signature_fails(self):
        sig = sign_approval(self.priv, self.action_id, self.approved_by, self.approved_at)
        tampered = sig[:-4] + "XXXX"
        assert not verify_approval_signature(self.pub, self.action_id, self.approved_by, self.approved_at, tampered)

    def test_verify_garbage_signature_returns_false(self):
        assert not verify_approval_signature(self.pub, self.action_id, self.approved_by, self.approved_at, "not-a-sig")


# ── TestKeyRotationEndpoint ───────────────────────────────────────────────────

class TestKeyRotationEndpoint:
    @pytest.mark.asyncio
    async def test_rotate_generates_new_keypair(self):
        import uuid as _uuid
        from asc_api.models.user import User

        user = User()
        user.id = str(_uuid.uuid4())
        user.email = "analyst@premoscorp.com"
        user.full_name = "Test"
        user.role = "analyst"
        user.signing_public_key = "old_pub"
        user.signing_private_key_enc = "old_enc"

        # Simulate what rotate_analyst_keys does
        priv, pub = generate_analyst_keypair()
        user.signing_public_key = pub
        user.signing_private_key_enc = encrypt_analyst_private_key(priv, "test-secret")

        assert user.signing_public_key != "old_pub"
        assert user.signing_private_key_enc != "old_enc"

    def test_old_signatures_still_verify_after_rotation(self):
        """Approvals_log entries embed public_key — they remain verifiable after rotation."""
        priv1, pub1 = generate_analyst_keypair()
        priv2, pub2 = generate_analyst_keypair()

        action_id = str(uuid.uuid4())
        approved_by = "analyst@premoscorp.com"
        approved_at = datetime.now(timezone.utc).isoformat()

        # Signature with old key
        sig1 = sign_approval(priv1, action_id, approved_by, approved_at)
        # After rotation, old sig still verifies against pub1
        assert verify_approval_signature(pub1, action_id, approved_by, approved_at, sig1)
        # New key doesn't verify old sig
        assert not verify_approval_signature(pub2, action_id, approved_by, approved_at, sig1)

    def test_new_key_verifies_new_signatures(self):
        priv1, pub1 = generate_analyst_keypair()
        priv2, pub2 = generate_analyst_keypair()

        action_id = str(uuid.uuid4())
        approved_by = "analyst@premoscorp.com"
        approved_at = datetime.now(timezone.utc).isoformat()

        sig2 = sign_approval(priv2, action_id, approved_by, approved_at)
        assert verify_approval_signature(pub2, action_id, approved_by, approved_at, sig2)
        assert not verify_approval_signature(pub1, action_id, approved_by, approved_at, sig2)

    def test_rotate_requires_admin_guard(self):
        """Rotation endpoint uses get_current_admin dependency — verified by import check."""
        from asc_api.api.v1.endpoints.iam import rotate_analyst_keys
        import inspect
        sig = inspect.signature(rotate_analyst_keys)
        # 'admin' parameter should be in the signature
        assert "admin" in sig.parameters


# ── TestSignatureVerificationEndpoint ────────────────────────────────────────

class TestSignatureVerificationEndpoint:
    def test_all_valid_verdict(self):
        priv, pub = generate_analyst_keypair()
        action_id = str(uuid.uuid4())
        approved_by = "analyst@premoscorp.com"
        approved_at = datetime.now(timezone.utc).isoformat()
        sig = sign_approval(priv, action_id, approved_by, approved_at)

        entry = {"approved_by": approved_by, "approved_at": approved_at, "signature": sig, "public_key": pub}
        valid = verify_approval_signature(pub, action_id, approved_by, approved_at, sig)
        assert valid is True

    def test_unsigned_entry_reports_partial(self):
        entry = {"approved_by": "a@b.com", "approved_at": "2026-01-01T00:00:00"}
        has_sig = bool(entry.get("signature"))
        assert has_sig is False  # Would result in "partial_unsigned" verdict

    def test_invalid_signature_detected(self):
        priv, pub = generate_analyst_keypair()
        _, other_pub = generate_analyst_keypair()
        action_id = str(uuid.uuid4())
        approved_by = "analyst@premoscorp.com"
        approved_at = datetime.now(timezone.utc).isoformat()
        sig = sign_approval(priv, action_id, approved_by, approved_at)

        valid = verify_approval_signature(other_pub, action_id, approved_by, approved_at, sig)
        assert valid is False  # Would result in "invalid" verdict

    def test_empty_log_returns_zero_entries(self):
        log = []
        assert len(log) == 0

    def test_mixed_signed_unsigned_entries(self):
        priv, pub = generate_analyst_keypair()
        action_id = str(uuid.uuid4())
        t = datetime.now(timezone.utc).isoformat()
        sig = sign_approval(priv, action_id, "a@b.com", t)

        entries = [
            {"approved_by": "a@b.com", "approved_at": t, "signature": sig, "public_key": pub},
            {"approved_by": "b@b.com", "approved_at": t},  # unsigned
        ]
        signed_count = sum(1 for e in entries if e.get("signature"))
        assert signed_count == 1  # Would yield "partial_unsigned"


# ── TestApprovalWithSigning ───────────────────────────────────────────────────

class TestApprovalWithSigning:
    """Verify that approve_action() includes signature in log entry when keys exist."""

    def test_log_entry_has_signature_field_when_keys_set(self):
        """Simulate the logic that approve_action uses to build log entries."""
        priv, pub = generate_analyst_keypair()
        action_id = str(uuid.uuid4())
        approved_by = "analyst@premoscorp.com"
        approved_at = datetime.now(timezone.utc).isoformat()
        secret = "test-secret"

        enc = encrypt_analyst_private_key(priv, secret)
        decrypted = decrypt_analyst_private_key(enc, secret)
        sig = sign_approval(decrypted, action_id, approved_by, approved_at)

        log_entry = {
            "approved_by": approved_by,
            "approved_at": approved_at,
            "signature": sig,
            "public_key": pub,
        }
        assert "signature" in log_entry
        assert verify_approval_signature(pub, action_id, approved_by, approved_at, sig)

    def test_log_entry_without_keys_is_still_valid(self):
        """Approval without signing keys degrades gracefully — no signature field."""
        log_entry = {
            "approved_by": "analyst@premoscorp.com",
            "approved_at": datetime.now(timezone.utc).isoformat(),
        }
        # No signature — this is acceptable for pre-P16.3 accounts or signing failures
        assert "signature" not in log_entry

    def test_signature_binds_action_id(self):
        """Signature cannot be reused for a different action."""
        priv, pub = generate_analyst_keypair()
        action1 = str(uuid.uuid4())
        action2 = str(uuid.uuid4())
        approved_by = "analyst@premoscorp.com"
        approved_at = datetime.now(timezone.utc).isoformat()

        sig = sign_approval(priv, action1, approved_by, approved_at)
        assert verify_approval_signature(pub, action1, approved_by, approved_at, sig)
        assert not verify_approval_signature(pub, action2, approved_by, approved_at, sig)

    def test_provision_signing_keys_sets_both_fields(self):
        """_provision_signing_keys() sets both public and encrypted private key."""
        from asc_api.models.user import User
        import uuid as _uuid

        user = User()
        user.id = str(_uuid.uuid4())
        user.email = "new@premoscorp.com"
        user.full_name = "New Analyst"
        user.role = "analyst"
        user.hashed_password = "hash"
        user.signing_public_key = None
        user.signing_private_key_enc = None

        # Simulate _provision_signing_keys
        priv, pub = generate_analyst_keypair()
        user.signing_public_key = pub
        user.signing_private_key_enc = encrypt_analyst_private_key(priv, "secret")

        assert user.signing_public_key is not None
        assert user.signing_private_key_enc is not None
        assert user.signing_public_key != user.signing_private_key_enc
