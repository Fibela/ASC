"""
PIDS Service — unit + integration tests (Session 83).

Coverage targets:
  _build_canonical          — determinism, all fields bound
  _compute_hash             — SHA3-512 correctness, stability
  _sign_hash                — no-key path returns None
  _verify_signature         — no-key path returns None
  _action_to_dict           — serialization completeness
  create_identity_action    — happy path, invalid type, all action types
  verify_identity_action    — found/not-found, hash match, tamper detection
  get_identity_action       — found/not-found
  list_identity_actions     — filters (username, type, hunt, success), limit
  get_identity_timeline     — ordering, hunt filter
  get_pids_summary          — total/successful/failed, 24h, hunt-scoped

All DB tests use the in-memory SQLite fixture from conftest.py.
"""

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.identity_action import IdentityAction
from app.services.pids_service import (
    _build_canonical,
    _compute_hash,
    _sign_hash,
    _verify_signature,
    _action_to_dict,
    create_identity_action,
    get_identity_action,
    get_identity_timeline,
    get_pids_summary,
    list_identity_actions,
    verify_identity_action,
)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_action_kwargs(**overrides) -> dict:
    base = dict(
        action_type="disable_account",
        username="jdoe",
        domain="corp.local",
        reason="Suspicious login from TOR exit node",
        initiated_by="analyst@premoscorp.com",
    )
    base.update(overrides)
    return base


def _bare_action(**overrides) -> IdentityAction:
    """Build an IdentityAction without DB for pure-unit tests."""
    now = datetime.now(timezone.utc)
    defaults = dict(
        id=str(uuid.uuid4()),
        action_type="disable_account",
        username="jdoe",
        domain="corp.local",
        reason="Test reason",
        hunt_id=None,
        finding_id=None,
        trigger_id=None,
        playbook_run_id=None,
        success=False,
        result_detail=None,
        initiated_by="analyst@premoscorp.com",
        signed_by_email="analyst@premoscorp.com",
        executed_at=now,
        hash_sha3_512=None,
        signature_ed25519=None,
        signed_at=None,
    )
    defaults.update(overrides)
    return IdentityAction(**defaults)


# ══════════════════════════════════════════════════════════════════════════════
#  Pure unit tests — no DB required
# ══════════════════════════════════════════════════════════════════════════════

class TestBuildCanonical:
    def test_contains_all_immutable_fields(self):
        action = _bare_action()
        c = _build_canonical(action)
        expected_keys = {
            "pids_version", "action_id", "action_type", "username", "domain",
            "reason", "hunt_id", "finding_id", "trigger_id", "playbook_run_id",
            "success", "result_detail", "initiated_by", "executed_at",
        }
        assert expected_keys == set(c.keys())

    def test_deterministic_same_action(self):
        action = _bare_action()
        assert _build_canonical(action) == _build_canonical(action)

    def test_version_is_string_1(self):
        action = _bare_action()
        assert _build_canonical(action)["pids_version"] == "1"

    def test_executed_at_iso_format(self):
        now = datetime.now(timezone.utc)
        action = _bare_action(executed_at=now)
        c = _build_canonical(action)
        assert c["executed_at"] == now.isoformat()

    def test_none_executed_at(self):
        action = _bare_action(executed_at=None)
        action.executed_at = None  # override
        c = _build_canonical(action)
        assert c["executed_at"] is None

    def test_nullable_fields_preserved(self):
        action = _bare_action(hunt_id="h1", finding_id="f1", trigger_id="t1")
        c = _build_canonical(action)
        assert c["hunt_id"] == "h1"
        assert c["finding_id"] == "f1"
        assert c["trigger_id"] == "t1"


class TestComputeHash:
    def test_returns_128_hex_chars(self):
        action = _bare_action()
        h = _compute_hash(_build_canonical(action))
        assert len(h) == 128
        assert all(c in "0123456789abcdef" for c in h)

    def test_stable_across_calls(self):
        action = _bare_action()
        c = _build_canonical(action)
        assert _compute_hash(c) == _compute_hash(c)

    def test_different_username_different_hash(self):
        a1 = _bare_action(username="alice")
        a2 = _bare_action(username="bob")
        h1 = _compute_hash(_build_canonical(a1))
        h2 = _compute_hash(_build_canonical(a2))
        assert h1 != h2

    def test_matches_sha3_512_manually(self):
        action = _bare_action()
        canonical = _build_canonical(action)
        payload = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
        expected = hashlib.sha3_512(payload).hexdigest()
        assert _compute_hash(canonical) == expected

    def test_order_independence(self):
        """sort_keys=True guarantees key ordering is irrelevant."""
        c1 = {"a": 1, "b": 2}
        c2 = {"b": 2, "a": 1}
        assert _compute_hash(c1) == _compute_hash(c2)


class TestSignHash:
    def test_no_key_returns_none(self, monkeypatch):
        monkeypatch.delenv("PIDS_SIGNING_PRIVATE_KEY", raising=False)
        monkeypatch.delenv("SPECTER_SIGNING_PRIVATE_KEY", raising=False)
        assert _sign_hash("deadbeef" * 16) is None

    def test_invalid_key_returns_none(self, monkeypatch):
        monkeypatch.setenv("PIDS_SIGNING_PRIVATE_KEY", "not-valid-base64!!!")
        result = _sign_hash("deadbeef" * 16)
        assert result is None


class TestVerifySignature:
    def test_no_key_returns_none(self, monkeypatch):
        monkeypatch.delenv("PIDS_SIGNING_PUBLIC_KEY", raising=False)
        monkeypatch.delenv("SPECTER_SIGNING_PUBLIC_KEY", raising=False)
        assert _verify_signature("deadbeef" * 16, "c2lnbmF0dXJl") is None

    def test_invalid_pub_key_returns_false(self, monkeypatch):
        monkeypatch.setenv("PIDS_SIGNING_PUBLIC_KEY", "bm90YXJlYWxrZXk=")
        result = _verify_signature("deadbeef" * 16, "c2lnbmF0dXJl")
        assert result is False


class TestActionToDict:
    def test_all_keys_present(self):
        action = _bare_action()
        d = _action_to_dict(action)
        expected = {
            "id", "action_type", "username", "domain", "reason",
            "hunt_id", "finding_id", "trigger_id", "playbook_run_id",
            "success", "result_detail", "hash_sha3_512", "signature_ed25519",
            "signed_at", "signed_by_email", "initiated_by", "executed_at",
        }
        assert expected == set(d.keys())

    def test_signed_at_iso_when_set(self):
        now = datetime.now(timezone.utc)
        action = _bare_action(signed_at=now)
        action.signed_at = now
        d = _action_to_dict(action)
        assert d["signed_at"] == now.isoformat()

    def test_signed_at_none_when_unset(self):
        action = _bare_action()
        action.signed_at = None
        d = _action_to_dict(action)
        assert d["signed_at"] is None

    def test_executed_at_iso(self):
        now = datetime.now(timezone.utc)
        action = _bare_action(executed_at=now)
        d = _action_to_dict(action)
        assert d["executed_at"] == now.isoformat()


# ══════════════════════════════════════════════════════════════════════════════
#  Integration tests — require DB fixture
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
class TestCreateIdentityAction:
    async def test_happy_path_returns_action(self, db: AsyncSession):
        action = await create_identity_action(db, **_make_action_kwargs())
        assert action.id is not None
        assert action.action_type == "disable_account"
        assert action.username == "jdoe"

    async def test_hash_is_128_hex_chars(self, db: AsyncSession):
        action = await create_identity_action(db, **_make_action_kwargs())
        assert action.hash_sha3_512 is not None
        assert len(action.hash_sha3_512) == 128

    async def test_signed_at_is_set(self, db: AsyncSession):
        action = await create_identity_action(db, **_make_action_kwargs())
        assert action.signed_at is not None

    async def test_invalid_action_type_raises(self, db: AsyncSession):
        with pytest.raises(ValueError, match="Invalid action_type"):
            await create_identity_action(
                db,
                action_type="nuke_server",
                username="jdoe",
                reason="testing",
                initiated_by="analyst@premoscorp.com",
            )

    async def test_all_valid_action_types_accepted(self, db: AsyncSession):
        valid_types = [
            "disable_account",
            "enable_account",
            "force_password_reset",
            "quarantine_account",
            "enrich_user",
        ]
        for at in valid_types:
            a = await create_identity_action(
                db,
                action_type=at,
                username=f"user_{at}",
                reason="coverage test",
                initiated_by="soar_auto",
            )
            assert a.action_type == at

    async def test_optional_links_stored(self, db: AsyncSession):
        hid = str(uuid.uuid4())
        fid = str(uuid.uuid4())
        action = await create_identity_action(
            db,
            **_make_action_kwargs(hunt_id=hid, finding_id=fid),
        )
        assert action.hunt_id == hid
        assert action.finding_id == fid

    async def test_success_flag_stored(self, db: AsyncSession):
        action = await create_identity_action(
            db, **_make_action_kwargs(success=True, result_detail="account disabled in AD")
        )
        assert action.success is True
        assert action.result_detail == "account disabled in AD"

    async def test_hash_is_deterministic_recomputable(self, db: AsyncSession):
        action = await create_identity_action(db, **_make_action_kwargs())
        canonical = _build_canonical(action)
        recomputed = _compute_hash(canonical)
        assert recomputed == action.hash_sha3_512

    async def test_no_signing_key_signature_is_none(self, db: AsyncSession, monkeypatch):
        monkeypatch.delenv("PIDS_SIGNING_PRIVATE_KEY", raising=False)
        monkeypatch.delenv("SPECTER_SIGNING_PRIVATE_KEY", raising=False)
        action = await create_identity_action(db, **_make_action_kwargs())
        assert action.signature_ed25519 is None
        assert action.hash_sha3_512 is not None


@pytest.mark.asyncio
class TestVerifyIdentityAction:
    async def test_not_found_returns_verified_false(self, db: AsyncSession):
        result = await verify_identity_action(db, str(uuid.uuid4()))
        assert result["verified"] is False
        assert "not found" in result["error"].lower()

    async def test_happy_path_hash_match(self, db: AsyncSession, monkeypatch):
        monkeypatch.delenv("PIDS_SIGNING_PRIVATE_KEY", raising=False)
        monkeypatch.delenv("SPECTER_SIGNING_PRIVATE_KEY", raising=False)
        action = await create_identity_action(db, **_make_action_kwargs())
        result = await verify_identity_action(db, action.id)
        assert result["verified"] is True
        assert result["hash_match"] is True
        assert result["action_id"] == action.id

    async def test_tampered_record_fails_hash(self, db: AsyncSession, monkeypatch):
        monkeypatch.delenv("PIDS_SIGNING_PRIVATE_KEY", raising=False)
        monkeypatch.delenv("SPECTER_SIGNING_PRIVATE_KEY", raising=False)
        action = await create_identity_action(db, **_make_action_kwargs())
        # Tamper: manually overwrite stored hash with wrong value
        action.hash_sha3_512 = "00" * 64
        await db.commit()
        result = await verify_identity_action(db, action.id)
        assert result["verified"] is False
        assert result["hash_match"] is False

    async def test_signature_ok_is_none_without_pub_key(self, db: AsyncSession, monkeypatch):
        monkeypatch.delenv("PIDS_SIGNING_PRIVATE_KEY", raising=False)
        monkeypatch.delenv("SPECTER_SIGNING_PRIVATE_KEY", raising=False)
        monkeypatch.delenv("PIDS_SIGNING_PUBLIC_KEY", raising=False)
        monkeypatch.delenv("SPECTER_SIGNING_PUBLIC_KEY", raising=False)
        action = await create_identity_action(db, **_make_action_kwargs())
        result = await verify_identity_action(db, action.id)
        assert result["signature_ok"] is None

    async def test_returns_action_fields(self, db: AsyncSession, monkeypatch):
        monkeypatch.delenv("PIDS_SIGNING_PRIVATE_KEY", raising=False)
        monkeypatch.delenv("SPECTER_SIGNING_PRIVATE_KEY", raising=False)
        action = await create_identity_action(
            db, **_make_action_kwargs(username="alice", action_type="enable_account")
        )
        result = await verify_identity_action(db, action.id)
        assert result["username"] == "alice"
        assert result["action_type"] == "enable_account"


@pytest.mark.asyncio
class TestGetIdentityAction:
    async def test_returns_none_for_unknown_id(self, db: AsyncSession):
        result = await get_identity_action(db, str(uuid.uuid4()))
        assert result is None

    async def test_returns_dict_for_known_id(self, db: AsyncSession, monkeypatch):
        monkeypatch.delenv("PIDS_SIGNING_PRIVATE_KEY", raising=False)
        monkeypatch.delenv("SPECTER_SIGNING_PRIVATE_KEY", raising=False)
        action = await create_identity_action(db, **_make_action_kwargs())
        result = await get_identity_action(db, action.id)
        assert result is not None
        assert result["id"] == action.id
        assert result["username"] == "jdoe"


@pytest.mark.asyncio
class TestListIdentityActions:
    async def _seed(self, db: AsyncSession, monkeypatch) -> list[IdentityAction]:
        monkeypatch.delenv("PIDS_SIGNING_PRIVATE_KEY", raising=False)
        monkeypatch.delenv("SPECTER_SIGNING_PRIVATE_KEY", raising=False)
        hunt_id = str(uuid.uuid4())
        actions = []
        configs = [
            dict(username="alice", action_type="disable_account", success=True, hunt_id=hunt_id),
            dict(username="alice", action_type="enable_account", success=False, hunt_id=hunt_id),
            dict(username="bob",   action_type="disable_account", success=True),
            dict(username="carol", action_type="quarantine_account", success=False),
        ]
        for c in configs:
            a = await create_identity_action(
                db,
                reason="filter test",
                initiated_by="soar_auto",
                **c,
            )
            actions.append(a)
        return actions, hunt_id

    async def test_returns_all_without_filters(self, db: AsyncSession, monkeypatch):
        actions, _ = await self._seed(db, monkeypatch)
        result = await list_identity_actions(db)
        assert len(result) == 4

    async def test_filter_by_username(self, db: AsyncSession, monkeypatch):
        await self._seed(db, monkeypatch)
        result = await list_identity_actions(db, username="alice")
        assert all(r["username"] == "alice" for r in result)
        assert len(result) == 2

    async def test_filter_by_action_type(self, db: AsyncSession, monkeypatch):
        await self._seed(db, monkeypatch)
        result = await list_identity_actions(db, action_type="disable_account")
        assert all(r["action_type"] == "disable_account" for r in result)
        assert len(result) == 2

    async def test_filter_by_hunt_id(self, db: AsyncSession, monkeypatch):
        actions, hunt_id = await self._seed(db, monkeypatch)
        result = await list_identity_actions(db, hunt_id=hunt_id)
        assert len(result) == 2
        assert all(r["hunt_id"] == hunt_id for r in result)

    async def test_filter_by_success_true(self, db: AsyncSession, monkeypatch):
        await self._seed(db, monkeypatch)
        result = await list_identity_actions(db, success=True)
        assert all(r["success"] is True for r in result)
        assert len(result) == 2

    async def test_filter_by_success_false(self, db: AsyncSession, monkeypatch):
        await self._seed(db, monkeypatch)
        result = await list_identity_actions(db, success=False)
        assert all(r["success"] is False for r in result)
        assert len(result) == 2

    async def test_limit_respected(self, db: AsyncSession, monkeypatch):
        await self._seed(db, monkeypatch)
        result = await list_identity_actions(db, limit=2)
        assert len(result) == 2

    async def test_combined_filters(self, db: AsyncSession, monkeypatch):
        await self._seed(db, monkeypatch)
        result = await list_identity_actions(
            db, username="alice", action_type="disable_account", success=True
        )
        assert len(result) == 1
        assert result[0]["username"] == "alice"
        assert result[0]["action_type"] == "disable_account"
        assert result[0]["success"] is True

    async def test_empty_db_returns_empty_list(self, db: AsyncSession):
        result = await list_identity_actions(db)
        assert result == []


@pytest.mark.asyncio
class TestGetIdentityTimeline:
    async def test_returns_empty_list_for_unknown_hunt(self, db: AsyncSession):
        result = await get_identity_timeline(db, str(uuid.uuid4()))
        assert result == []

    async def test_returns_actions_for_hunt_in_asc_order(self, db: AsyncSession, monkeypatch):
        monkeypatch.delenv("PIDS_SIGNING_PRIVATE_KEY", raising=False)
        monkeypatch.delenv("SPECTER_SIGNING_PRIVATE_KEY", raising=False)
        hunt_id = str(uuid.uuid4())
        for at in ["disable_account", "enable_account", "quarantine_account"]:
            await create_identity_action(
                db,
                action_type=at,
                username="timeline_user",
                reason="timeline test",
                hunt_id=hunt_id,
                initiated_by="soar_auto",
            )
        result = await get_identity_timeline(db, hunt_id)
        assert len(result) == 3
        timestamps = [r["executed_at"] for r in result]
        assert timestamps == sorted(timestamps)

    async def test_only_returns_matching_hunt(self, db: AsyncSession, monkeypatch):
        monkeypatch.delenv("PIDS_SIGNING_PRIVATE_KEY", raising=False)
        monkeypatch.delenv("SPECTER_SIGNING_PRIVATE_KEY", raising=False)
        hunt_a = str(uuid.uuid4())
        hunt_b = str(uuid.uuid4())
        for h in [hunt_a, hunt_b]:
            await create_identity_action(
                db, action_type="disable_account", username="u", reason="r",
                hunt_id=h, initiated_by="soar_auto",
            )
        result = await get_identity_timeline(db, hunt_a)
        assert len(result) == 1
        assert result[0]["hunt_id"] == hunt_a


@pytest.mark.asyncio
class TestGetPidsSummary:
    async def _seed_actions(self, db, monkeypatch, n_success=2, n_fail=3):
        monkeypatch.delenv("PIDS_SIGNING_PRIVATE_KEY", raising=False)
        monkeypatch.delenv("SPECTER_SIGNING_PRIVATE_KEY", raising=False)
        hunt_id = str(uuid.uuid4())
        for i in range(n_success):
            await create_identity_action(
                db, action_type="disable_account", username=f"u_ok_{i}",
                reason="r", success=True, hunt_id=hunt_id, initiated_by="auto",
            )
        for i in range(n_fail):
            await create_identity_action(
                db, action_type="enable_account", username=f"u_fail_{i}",
                reason="r", success=False, hunt_id=hunt_id, initiated_by="auto",
            )
        return hunt_id

    async def test_empty_db_returns_zeros(self, db: AsyncSession):
        result = await get_pids_summary(db)
        assert result["total_actions"] == 0
        assert result["successful_actions"] == 0
        assert result["failed_actions"] == 0
        assert result["success_rate_pct"] == 0.0

    async def test_totals_correct(self, db: AsyncSession, monkeypatch):
        await self._seed_actions(db, monkeypatch, n_success=2, n_fail=3)
        result = await get_pids_summary(db)
        assert result["total_actions"] == 5
        assert result["successful_actions"] == 2
        assert result["failed_actions"] == 3

    async def test_success_rate_pct(self, db: AsyncSession, monkeypatch):
        await self._seed_actions(db, monkeypatch, n_success=1, n_fail=3)
        result = await get_pids_summary(db)
        assert result["success_rate_pct"] == 25.0

    async def test_hunt_scoped_filters_correctly(self, db: AsyncSession, monkeypatch):
        hunt_id = await self._seed_actions(db, monkeypatch, n_success=2, n_fail=1)
        # Add actions under a different hunt
        other_hunt = str(uuid.uuid4())
        await create_identity_action(
            db, action_type="disable_account", username="x",
            reason="other", hunt_id=other_hunt, initiated_by="auto",
        )
        result = await get_pids_summary(db, hunt_id=hunt_id)
        assert result["total_actions"] == 3
        assert result["hunt_id"] == hunt_id

    async def test_actions_24h_counts_recent(self, db: AsyncSession, monkeypatch):
        await self._seed_actions(db, monkeypatch, n_success=2, n_fail=2)
        result = await get_pids_summary(db)
        assert result["actions_24h"] == 4
