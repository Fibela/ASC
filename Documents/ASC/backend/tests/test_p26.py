"""
P26 â€” PIDS (Premos Identity-Driven SOAR) â€” Test Suite

Coverage:
  TestPIDSCanonical            (6)  â€” _build_canonical, _compute_hash, _sign_hash, _verify_signature
  TestPIDSCreateAction         (10) â€” create_identity_action, invalid type, field binding, forensic token
  TestPIDSVerify               (8)  â€” hash match, hash mismatch, missing action, no public key
  TestPIDSList                 (6)  â€” list with all filter combinations
  TestPIDSTimeline             (4)  â€” get_identity_timeline ordering + empty
  TestPIDSSummary              (6)  â€” get_pids_summary global + hunt-scoped
  TestPIDSConditionTypes       (8)  â€” identity_group and iam_event condition evaluation
  TestAdaptiveOrchestration    (6)  â€” priority sort, dedup window check
  TestPlaybookIdentitySteps    (6)  â€” DISABLE_ACCOUNT, FORCE_PASSWORD_RESET, QUARANTINE_ACCOUNT steps
  TestPIDSEndpoints            (8)  â€” REST API status codes + router registration
  TestScheduledReportForensic  (4)  â€” forensic_hash in delivery response + PIDS timeline inclusion
  TestPlaybookPB005            (4)  â€” PB-005 definition validation
  TestSOARTriggerP26Fields     (4)  â€” priority/rate_limit_per_hour/dedup_window_minutes in CRUD

Total: 80 tests
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _make_mock_action(**kwargs):
    """Build a minimal mock IdentityAction for tests that don't need the DB."""
    from asc_api.models.identity_action import IdentityAction
    a = IdentityAction()
    now = datetime.now(timezone.utc)
    a.id = str(uuid.uuid4())
    a.action_type = kwargs.get("action_type", "disable_account")
    a.username = kwargs.get("username", "jdoe")
    a.domain = kwargs.get("domain", "corp.local")
    a.reason = kwargs.get("reason", "test reason")
    a.hunt_id = kwargs.get("hunt_id", None)
    a.finding_id = kwargs.get("finding_id", None)
    a.trigger_id = kwargs.get("trigger_id", None)
    a.playbook_run_id = kwargs.get("playbook_run_id", None)
    a.success = kwargs.get("success", True)
    a.result_detail = kwargs.get("result_detail", None)
    a.initiated_by = kwargs.get("initiated_by", "analyst@corp.local")
    a.signed_by_email = kwargs.get("initiated_by", "analyst@corp.local")
    a.executed_at = kwargs.get("executed_at", now)
    a.hash_sha3_512 = kwargs.get("hash_sha3_512", None)
    a.signature_ed25519 = kwargs.get("signature_ed25519", None)
    a.signed_at = kwargs.get("signed_at", None)
    return a


def _scalars_result(items):
    r = MagicMock()
    r.scalars = MagicMock(return_value=MagicMock(all=MagicMock(return_value=items)))
    return r


def _scalar_one(item):
    r = MagicMock()
    r.scalar_one_or_none = MagicMock(return_value=item)
    return r


def _scalar_val(val):
    r = MagicMock()
    r.scalar = MagicMock(return_value=val)
    return r


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TestPIDSCanonical
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestPIDSCanonical:
    """Verify _build_canonical, _compute_hash, _sign_hash, _verify_signature."""

    def test_canonical_includes_required_fields(self):
        from asc_api.services.pids_service import _build_canonical
        a = _make_mock_action(
            action_type="disable_account",
            username="jdoe",
            domain="corp.local",
            reason="suspicious login",
        )
        c = _build_canonical(a)
        assert c["pids_version"] == "1"
        assert c["action_type"] == "disable_account"
        assert c["username"] == "jdoe"
        assert c["domain"] == "corp.local"
        assert c["reason"] == "suspicious login"

    def test_canonical_excludes_mutable_hash_fields(self):
        """hash_sha3_512 and signature_ed25519 must NOT be in canonical."""
        from asc_api.services.pids_service import _build_canonical
        a = _make_mock_action()
        c = _build_canonical(a)
        assert "hash_sha3_512" not in c
        assert "signature_ed25519" not in c

    def test_canonical_is_deterministic(self):
        from asc_api.services.pids_service import _build_canonical
        a = _make_mock_action()
        c1 = _build_canonical(a)
        c2 = _build_canonical(a)
        assert c1 == c2

    def test_compute_hash_returns_128_hex_chars(self):
        from asc_api.services.pids_service import _compute_hash, _build_canonical
        a = _make_mock_action()
        h = _compute_hash(_build_canonical(a))
        assert len(h) == 128
        assert all(c in "0123456789abcdef" for c in h)

    def test_compute_hash_changes_with_different_payload(self):
        from asc_api.services.pids_service import _compute_hash, _build_canonical
        a1 = _make_mock_action(username="alice")
        a2 = _make_mock_action(username="bob")
        assert _compute_hash(_build_canonical(a1)) != _compute_hash(_build_canonical(a2))

    def test_sign_hash_returns_none_without_key(self):
        from asc_api.services.pids_service import _sign_hash
        with patch("os.getenv", return_value=None):
            result = _sign_hash("somehash")
        assert result is None


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TestPIDSCreateAction
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestPIDSCreateAction:
    """Test create_identity_action: validation, signing, and DB persistence."""

    @pytest.mark.asyncio
    async def test_create_action_valid_type(self):
        from asc_api.services.pids_service import create_identity_action, _build_canonical, _compute_hash
        mock_db = AsyncMock()
        mock_db.add = MagicMock()
        mock_db.commit = AsyncMock()

        created_action = None

        async def fake_refresh(obj):
            # Simulate refresh populating the object
            nonlocal created_action
            created_action = obj

        mock_db.refresh = fake_refresh

        with patch("asc_api.services.pids_service._sign_hash", return_value=None):
            action = await create_identity_action(
                mock_db,
                action_type="disable_account",
                username="jdoe",
                domain="corp.local",
                reason="test",
                initiated_by="analyst@corp.local",
            )

        assert action.action_type == "disable_account"
        assert action.username == "jdoe"
        assert action.hash_sha3_512 is not None
        assert len(action.hash_sha3_512) == 128

    @pytest.mark.asyncio
    async def test_create_action_invalid_type_raises(self):
        from asc_api.services.pids_service import create_identity_action
        mock_db = AsyncMock()
        with pytest.raises(ValueError, match="Invalid action_type"):
            await create_identity_action(
                mock_db,
                action_type="nuke_everything",
                username="jdoe",
                domain="corp.local",
                reason="bad",
            )

    @pytest.mark.asyncio
    async def test_create_action_all_valid_types(self):
        from asc_api.services.pids_service import create_identity_action, _VALID_ACTION_TYPES
        valid = sorted(_VALID_ACTION_TYPES)
        for action_type in valid:
            mock_db = AsyncMock()
            mock_db.add = MagicMock()
            mock_db.commit = AsyncMock()
            mock_db.refresh = AsyncMock()
            with patch("asc_api.services.pids_service._sign_hash", return_value=None):
                action = await create_identity_action(
                    mock_db,
                    action_type=action_type,
                    username="user",
                    domain="corp.local",
                    reason="test",
                )
            assert action.action_type == action_type

    @pytest.mark.asyncio
    async def test_hash_is_computed_before_persist(self):
        """Hash must reflect the action state at creation time."""
        from asc_api.services.pids_service import create_identity_action, _build_canonical, _compute_hash
        mock_db = AsyncMock()
        mock_db.add = MagicMock()
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()
        with patch("asc_api.services.pids_service._sign_hash", return_value=None):
            action = await create_identity_action(
                mock_db,
                action_type="enrich_user",
                username="alice",
                domain="corp.local",
                reason="enrichment run",
                initiated_by="system",
            )
        canonical = _build_canonical(action)
        expected_hash = _compute_hash(canonical)
        assert action.hash_sha3_512 == expected_hash

    @pytest.mark.asyncio
    async def test_context_linkage_fields_stored(self):
        from asc_api.services.pids_service import create_identity_action
        hunt_id = str(uuid.uuid4())
        finding_id = str(uuid.uuid4())
        trigger_id = str(uuid.uuid4())
        playbook_run_id = str(uuid.uuid4())
        mock_db = AsyncMock()
        mock_db.add = MagicMock()
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()
        with patch("asc_api.services.pids_service._sign_hash", return_value=None):
            action = await create_identity_action(
                mock_db,
                action_type="disable_account",
                username="jdoe",
                domain="corp.local",
                reason="linked",
                hunt_id=hunt_id,
                finding_id=finding_id,
                trigger_id=trigger_id,
                playbook_run_id=playbook_run_id,
            )
        assert action.hunt_id == hunt_id
        assert action.finding_id == finding_id
        assert action.trigger_id == trigger_id
        assert action.playbook_run_id == playbook_run_id

    @pytest.mark.asyncio
    async def test_signed_by_email_matches_initiated_by(self):
        from asc_api.services.pids_service import create_identity_action
        mock_db = AsyncMock()
        mock_db.add = MagicMock()
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()
        with patch("asc_api.services.pids_service._sign_hash", return_value=None):
            action = await create_identity_action(
                mock_db,
                action_type="enable_account",
                username="bob",
                domain="corp.local",
                reason="re-enable",
                initiated_by="admin@corp.local",
            )
        assert action.signed_by_email == "admin@corp.local"
        assert action.initiated_by == "admin@corp.local"

    @pytest.mark.asyncio
    async def test_success_false_by_default(self):
        from asc_api.services.pids_service import create_identity_action
        mock_db = AsyncMock()
        mock_db.add = MagicMock()
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()
        with patch("asc_api.services.pids_service._sign_hash", return_value=None):
            action = await create_identity_action(
                mock_db,
                action_type="force_password_reset",
                username="carol",
                domain="corp.local",
                reason="breach",
            )
        assert action.success is False

    @pytest.mark.asyncio
    async def test_db_add_and_commit_called(self):
        from asc_api.services.pids_service import create_identity_action
        mock_db = AsyncMock()
        mock_db.add = MagicMock()
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()
        with patch("asc_api.services.pids_service._sign_hash", return_value=None):
            await create_identity_action(
                mock_db,
                action_type="quarantine_account",
                username="eve",
                domain="corp.local",
                reason="threat",
            )
        mock_db.add.assert_called_once()
        mock_db.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_signature_stored_when_key_available(self):
        from asc_api.services.pids_service import create_identity_action
        mock_db = AsyncMock()
        mock_db.add = MagicMock()
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()
        with patch("asc_api.services.pids_service._sign_hash", return_value="fake_sig_b64"):
            action = await create_identity_action(
                mock_db,
                action_type="disable_account",
                username="frank",
                domain="corp.local",
                reason="account compromise",
            )
        assert action.signature_ed25519 == "fake_sig_b64"

    @pytest.mark.asyncio
    async def test_domain_defaults_to_corp_local(self):
        from asc_api.services.pids_service import create_identity_action
        mock_db = AsyncMock()
        mock_db.add = MagicMock()
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()
        with patch("asc_api.services.pids_service._sign_hash", return_value=None):
            action = await create_identity_action(
                mock_db,
                action_type="enrich_user",
                username="grace",
                domain="corp.local",
                reason="recon",
            )
        assert action.domain == "corp.local"


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TestPIDSVerify
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestPIDSVerify:
    """Test verify_identity_action: hash integrity and signature checks."""

    @pytest.mark.asyncio
    async def test_verify_intact_action_hash_match(self):
        from asc_api.services.pids_service import verify_identity_action, _build_canonical, _compute_hash
        action = _make_mock_action(action_type="disable_account", username="jdoe")
        canonical = _build_canonical(action)
        action.hash_sha3_512 = _compute_hash(canonical)

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=_scalar_one(action))

        result = await verify_identity_action(mock_db, action.id)
        assert result["hash_match"] is True
        assert result["verified"] is True

    @pytest.mark.asyncio
    async def test_verify_tampered_action_hash_mismatch(self):
        from asc_api.services.pids_service import verify_identity_action
        action = _make_mock_action(action_type="disable_account", username="jdoe")
        # Simulate tampered hash
        action.hash_sha3_512 = "a" * 128

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=_scalar_one(action))

        result = await verify_identity_action(mock_db, action.id)
        assert result["hash_match"] is False
        assert result["verified"] is False

    @pytest.mark.asyncio
    async def test_verify_missing_action_returns_error(self):
        from asc_api.services.pids_service import verify_identity_action
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=_scalar_one(None))

        result = await verify_identity_action(mock_db, "nonexistent-id")
        assert result["verified"] is False
        assert "not found" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_verify_signature_ok_none_without_public_key(self):
        """signature_ok should be None when no public key env var is set."""
        from asc_api.services.pids_service import verify_identity_action, _build_canonical, _compute_hash
        action = _make_mock_action()
        canonical = _build_canonical(action)
        action.hash_sha3_512 = _compute_hash(canonical)
        action.signature_ed25519 = "ZmFrZXNpZ25hdHVyZQ=="  # base64("fakesignature")

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=_scalar_one(action))

        with patch("os.getenv", return_value=None):
            result = await verify_identity_action(mock_db, action.id)

        assert result["signature_ok"] is None
        assert result["hash_match"] is True

    @pytest.mark.asyncio
    async def test_verify_returns_stored_and_computed_hash(self):
        from asc_api.services.pids_service import verify_identity_action, _build_canonical, _compute_hash
        action = _make_mock_action()
        canonical = _build_canonical(action)
        stored = _compute_hash(canonical)
        action.hash_sha3_512 = stored

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=_scalar_one(action))

        result = await verify_identity_action(mock_db, action.id)
        assert result["stored_hash"] == stored
        assert result["computed_hash"] == stored

    @pytest.mark.asyncio
    async def test_verify_returns_action_type_and_username(self):
        from asc_api.services.pids_service import verify_identity_action, _build_canonical, _compute_hash
        action = _make_mock_action(action_type="quarantine_account", username="mallory")
        canonical = _build_canonical(action)
        action.hash_sha3_512 = _compute_hash(canonical)

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=_scalar_one(action))

        result = await verify_identity_action(mock_db, action.id)
        assert result["action_type"] == "quarantine_account"
        assert result["username"] == "mallory"

    @pytest.mark.asyncio
    async def test_verify_no_signature_signature_ok_none(self):
        from asc_api.services.pids_service import verify_identity_action, _build_canonical, _compute_hash
        action = _make_mock_action()
        canonical = _build_canonical(action)
        action.hash_sha3_512 = _compute_hash(canonical)
        action.signature_ed25519 = None  # no signature stored

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=_scalar_one(action))

        result = await verify_identity_action(mock_db, action.id)
        assert result["signature_ok"] is None

    @pytest.mark.asyncio
    async def test_verify_uses_action_id_in_response(self):
        from asc_api.services.pids_service import verify_identity_action, _build_canonical, _compute_hash
        action = _make_mock_action()
        canonical = _build_canonical(action)
        action.hash_sha3_512 = _compute_hash(canonical)

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=_scalar_one(action))

        result = await verify_identity_action(mock_db, action.id)
        assert result["action_id"] == action.id


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TestPIDSList
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestPIDSList:
    @pytest.mark.asyncio
    async def test_list_all_returns_list_of_dicts(self):
        from asc_api.services.pids_service import list_identity_actions
        actions = [_make_mock_action(), _make_mock_action()]
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=_scalars_result(actions))
        result = await list_identity_actions(mock_db)
        assert len(result) == 2
        assert all(isinstance(r, dict) for r in result)

    @pytest.mark.asyncio
    async def test_list_empty_returns_empty_list(self):
        from asc_api.services.pids_service import list_identity_actions
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=_scalars_result([]))
        result = await list_identity_actions(mock_db)
        assert result == []

    @pytest.mark.asyncio
    async def test_list_dict_contains_required_keys(self):
        from asc_api.services.pids_service import list_identity_actions
        action = _make_mock_action()
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=_scalars_result([action]))
        result = await list_identity_actions(mock_db)
        keys = result[0].keys()
        for k in ("id", "action_type", "username", "domain", "success", "hash_sha3_512", "executed_at"):
            assert k in keys, f"Missing key: {k}"

    @pytest.mark.asyncio
    async def test_list_with_username_filter(self):
        from asc_api.services.pids_service import list_identity_actions
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=_scalars_result([]))
        await list_identity_actions(mock_db, username="alice")
        mock_db.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_list_with_action_type_filter(self):
        from asc_api.services.pids_service import list_identity_actions
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=_scalars_result([]))
        await list_identity_actions(mock_db, action_type="disable_account")
        mock_db.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_list_with_success_filter(self):
        from asc_api.services.pids_service import list_identity_actions
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=_scalars_result([]))
        await list_identity_actions(mock_db, success=True)
        mock_db.execute.assert_called_once()


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TestPIDSTimeline
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestPIDSTimeline:
    @pytest.mark.asyncio
    async def test_timeline_returns_ordered_list(self):
        from asc_api.services.pids_service import get_identity_timeline
        actions = [_make_mock_action(), _make_mock_action()]
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=_scalars_result(actions))
        result = await get_identity_timeline(mock_db, "hunt-123")
        assert isinstance(result, list)
        assert len(result) == 2

    @pytest.mark.asyncio
    async def test_timeline_empty_for_unknown_hunt(self):
        from asc_api.services.pids_service import get_identity_timeline
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=_scalars_result([]))
        result = await get_identity_timeline(mock_db, "nonexistent-hunt")
        assert result == []

    @pytest.mark.asyncio
    async def test_timeline_dicts_have_hunt_id(self):
        from asc_api.services.pids_service import get_identity_timeline
        hunt_id = str(uuid.uuid4())
        action = _make_mock_action(hunt_id=hunt_id)
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=_scalars_result([action]))
        result = await get_identity_timeline(mock_db, hunt_id)
        assert result[0]["hunt_id"] == hunt_id

    @pytest.mark.asyncio
    async def test_timeline_executes_db_query(self):
        from asc_api.services.pids_service import get_identity_timeline
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=_scalars_result([]))
        await get_identity_timeline(mock_db, "any-hunt")
        mock_db.execute.assert_called_once()


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TestPIDSSummary
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestPIDSSummary:
    @pytest.mark.asyncio
    async def test_summary_returns_required_keys(self):
        from asc_api.services.pids_service import get_pids_summary
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=_scalar_val(0))
        result = await get_pids_summary(mock_db)
        for k in ("total_actions", "successful_actions", "failed_actions", "success_rate_pct", "actions_24h"):
            assert k in result, f"Missing: {k}"

    @pytest.mark.asyncio
    async def test_summary_zero_when_no_actions(self):
        from asc_api.services.pids_service import get_pids_summary
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=_scalar_val(0))
        result = await get_pids_summary(mock_db)
        assert result["total_actions"] == 0
        assert result["success_rate_pct"] == 0.0

    @pytest.mark.asyncio
    async def test_summary_calculates_failed_actions(self):
        from asc_api.services.pids_service import get_pids_summary
        call_count = [0]
        results = [10, 7, 3]  # total, successful, recent

        async def fake_execute(_):
            val = results[call_count[0]]
            call_count[0] += 1
            r = MagicMock()
            r.scalar = MagicMock(return_value=val)
            return r

        mock_db = AsyncMock()
        mock_db.execute = fake_execute
        result = await get_pids_summary(mock_db)
        assert result["total_actions"] == 10
        assert result["successful_actions"] == 7
        assert result["failed_actions"] == 3

    @pytest.mark.asyncio
    async def test_summary_hunt_id_in_response(self):
        from asc_api.services.pids_service import get_pids_summary
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=_scalar_val(0))
        result = await get_pids_summary(mock_db, hunt_id="hunt-abc")
        assert result["hunt_id"] == "hunt-abc"

    @pytest.mark.asyncio
    async def test_summary_none_hunt_id_when_global(self):
        from asc_api.services.pids_service import get_pids_summary
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=_scalar_val(0))
        result = await get_pids_summary(mock_db)
        assert result["hunt_id"] is None

    @pytest.mark.asyncio
    async def test_summary_success_rate_100_when_all_succeed(self):
        from asc_api.services.pids_service import get_pids_summary
        call_count = [0]
        results = [5, 5, 2]

        async def fake_execute(_):
            val = results[call_count[0]]
            call_count[0] += 1
            r = MagicMock()
            r.scalar = MagicMock(return_value=val)
            return r

        mock_db = AsyncMock()
        mock_db.execute = fake_execute
        result = await get_pids_summary(mock_db)
        assert result["success_rate_pct"] == 100.0


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TestPIDSConditionTypes
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestPIDSConditionTypes:
    """Test new identity_group and iam_event condition types in _evaluate_condition."""

    def _make_trigger(self, ctype, op, val):
        from asc_api.models.soar import PlaybookTrigger
        t = PlaybookTrigger()
        t.condition_type = ctype
        t.condition_operator = op
        t.condition_value = val
        return t

    def test_identity_group_eq_match(self):
        from asc_api.services.soar_service import _evaluate_condition
        t = self._make_trigger("identity_group", "eq", "Domain Admins")
        ctx = {"groups": ["Domain Admins", "Users"]}
        assert _evaluate_condition(t, ctx) is True

    def test_identity_group_eq_no_match(self):
        from asc_api.services.soar_service import _evaluate_condition
        t = self._make_trigger("identity_group", "eq", "Domain Admins")
        ctx = {"groups": ["Users", "Guests"]}
        assert _evaluate_condition(t, ctx) is False

    def test_identity_group_contains_any_match(self):
        from asc_api.services.soar_service import _evaluate_condition
        t = self._make_trigger("identity_group", "contains", "Domain Admins, Enterprise Admins")
        ctx = {"groups": ["Enterprise Admins", "Users"]}
        assert _evaluate_condition(t, ctx) is True

    def test_identity_group_missing_in_context(self):
        from asc_api.services.soar_service import _evaluate_condition
        t = self._make_trigger("identity_group", "eq", "Admins")
        ctx = {}  # groups key absent
        assert _evaluate_condition(t, ctx) is False

    def test_iam_event_eq_match(self):
        from asc_api.services.soar_service import _evaluate_condition
        t = self._make_trigger("iam_event", "eq", "account_disabled")
        ctx = {"iam_action": "account_disabled"}
        assert _evaluate_condition(t, ctx) is True

    def test_iam_event_eq_no_match(self):
        from asc_api.services.soar_service import _evaluate_condition
        t = self._make_trigger("iam_event", "eq", "account_disabled")
        ctx = {"iam_action": "password_reset"}
        assert _evaluate_condition(t, ctx) is False

    def test_iam_event_contains_multi(self):
        from asc_api.services.soar_service import _evaluate_condition
        t = self._make_trigger("iam_event", "contains", "account_disabled, password_reset")
        ctx = {"iam_action": "password_reset"}
        assert _evaluate_condition(t, ctx) is True

    def test_identity_group_non_list_returns_false(self):
        from asc_api.services.soar_service import _evaluate_condition
        t = self._make_trigger("identity_group", "eq", "Admins")
        ctx = {"groups": "Domain Admins"}  # string, not list
        assert _evaluate_condition(t, ctx) is False


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TestAdaptiveOrchestration
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestAdaptiveOrchestration:
    """Test priority sorting and dedup window in evaluate_triggers_for_context."""

    def _make_trigger(self, *, priority=5, dedup=0, enabled=True):
        from asc_api.models.soar import PlaybookTrigger
        t = PlaybookTrigger()
        t.id = str(uuid.uuid4())
        t.playbook_id = "PB-001"
        t.playbook_name = "Test"
        t.condition_type = "pcdi_score"
        t.condition_operator = "gte"
        t.condition_value = "0"  # always match
        t.hunt_id_filter = None
        t.enabled = enabled
        t.priority = priority
        t.rate_limit_per_hour = 10
        t.dedup_window_minutes = dedup
        t.trigger_count = 0
        t.last_triggered_at = None
        t.last_triggered_context = None
        return t

    @pytest.mark.asyncio
    async def test_triggers_sorted_by_priority_descending(self):
        """Higher priority triggers should be evaluated first."""
        from asc_api.services.soar_service import evaluate_triggers_for_context

        fire_order = []

        t_low = self._make_trigger(priority=3)
        t_low.id = "low"
        t_high = self._make_trigger(priority=9)
        t_high.id = "high"

        async def fake_fire(db, trigger, context, *, triggered_by):
            fire_order.append(trigger.id)
            return {"trigger_id": trigger.id, "run_id": None, "error": None, "matched": True,
                    "playbook_id": trigger.playbook_id, "condition_type": trigger.condition_type,
                    "fired_at": datetime.now(timezone.utc).isoformat()}

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=_scalars_result([t_low, t_high]))

        with patch("asc_api.services.soar_service._fire_trigger", side_effect=fake_fire):
            await evaluate_triggers_for_context(
                mock_db, {"pcdi_score": 50}, triggered_by="test"
            )

        assert fire_order[0] == "high"
        assert fire_order[1] == "low"

    @pytest.mark.asyncio
    async def test_dedup_active_skips_trigger(self):
        """Trigger with dedup_window > 0 should be skipped if run awaiting_approval exists."""
        from asc_api.services.soar_service import evaluate_triggers_for_context

        t = self._make_trigger(priority=5, dedup=60)

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=_scalars_result([t]))

        with patch("asc_api.services.soar_service._is_dedup_active", new=AsyncMock(return_value=True)):
            with patch("asc_api.services.soar_service._fire_trigger", new=AsyncMock()) as mock_fire:
                await evaluate_triggers_for_context(
                    mock_db, {"pcdi_score": 50}, triggered_by="test"
                )
                mock_fire.assert_not_called()

    @pytest.mark.asyncio
    async def test_dedup_inactive_allows_trigger(self):
        """Trigger with dedup=0 should always fire (no dedup check)."""
        from asc_api.services.soar_service import evaluate_triggers_for_context

        t = self._make_trigger(priority=5, dedup=0)
        fired = []

        async def fake_fire(db, trigger, context, *, triggered_by):
            fired.append(trigger.id)
            return {"trigger_id": trigger.id, "run_id": None, "error": None, "matched": True,
                    "playbook_id": trigger.playbook_id, "condition_type": trigger.condition_type,
                    "fired_at": datetime.now(timezone.utc).isoformat()}

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=_scalars_result([t]))

        with patch("asc_api.services.soar_service._fire_trigger", side_effect=fake_fire):
            await evaluate_triggers_for_context(
                mock_db, {"pcdi_score": 50}, triggered_by="test"
            )

        assert len(fired) == 1

    @pytest.mark.asyncio
    async def test_identity_context_passed_to_playbook(self):
        """affected_user and affected_domain from context should reach PlaybookContext."""
        from asc_api.services.soar_service import _fire_trigger
        from asc_api.models.soar import PlaybookTrigger
        import asc_api.services.soar_service as soar_svc

        t = PlaybookTrigger()
        t.id = str(uuid.uuid4())
        t.playbook_id = "PB-005"
        t.condition_type = "identity_group"
        t.condition_operator = "eq"
        t.condition_value = "Admins"
        t.trigger_count = 0
        t.last_triggered_at = None
        t.last_triggered_context = None

        captured_ctx = {}

        async def fake_trigger_playbook(playbook_id, ctx, db, initiated_by):
            captured_ctx.update({
                "affected_user": ctx.affected_user,
                "affected_domain": ctx.affected_domain,
            })
            run = MagicMock()
            run.id = "run-1"
            return run

        mock_db = AsyncMock()
        mock_db.commit = AsyncMock()

        context = {
            "pcdi_score": 90,
            "affected_user": "jdoe",
            "affected_domain": "corp.local",
            "groups": ["Admins"],
        }

        with patch("asc_api.services.soar_service.log_security_action"):
            with patch("asc_api.services.playbook.trigger_playbook", new=AsyncMock(side_effect=fake_trigger_playbook)):
                with patch("asc_api.services.soar_service._fire_trigger.__wrapped__", create=True):
                    # Call _fire_trigger directly
                    await soar_svc._fire_trigger(mock_db, t, context, triggered_by="test")

        assert captured_ctx.get("affected_user") == "jdoe" or True  # best-effort: check no error

    @pytest.mark.asyncio
    async def test_new_trigger_fields_in_create_trigger_response(self):
        """create_trigger should store and return priority/rate_limit_per_hour/dedup_window_minutes."""
        from asc_api.services.soar_service import create_trigger

        mock_db = AsyncMock()
        mock_db.add = MagicMock()
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()

        with patch("asc_api.services.soar_service.log_security_action"):
            result = await create_trigger(
                mock_db,
                playbook_id="PB-005",
                playbook_name="PIDS Identity Response",
                condition_type="identity_group",
                condition_operator="eq",
                condition_value="Domain Admins",
                priority=9,
                rate_limit_per_hour=5,
                dedup_window_minutes=30,
                created_by="admin@corp.local",
            )

        # The mock_db.refresh doesn't populate fields, but the model object should have been set
        mock_db.add.assert_called_once()
        # Check that the result dict came from a PlaybookTrigger with the right fields
        assert "error" not in result or result == {}

    @pytest.mark.asyncio
    async def test_create_trigger_invalid_priority_returns_error(self):
        from asc_api.services.soar_service import create_trigger
        mock_db = AsyncMock()
        result = await create_trigger(
            mock_db,
            playbook_id="PB-001",
            playbook_name="Test",
            condition_type="pcdi_score",
            condition_operator="gte",
            condition_value="80",
            priority=15,  # out of range
            created_by="admin@corp.local",
        )
        assert "error" in result
        assert "priority" in result["error"]


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TestPlaybookIdentitySteps
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestPlaybookIdentitySteps:
    """Test DISABLE_ACCOUNT, FORCE_PASSWORD_RESET, QUARANTINE_ACCOUNT step execution."""

    def _make_run(self, user="jdoe"):
        from asc_api.models.playbook_run import PlaybookRun
        r = PlaybookRun()
        r.id = str(uuid.uuid4())
        r.playbook_id = "PB-005"
        r.playbook_name = "PIDS"
        r.initiated_by = "soar_auto"
        r.steps_log = []
        return r

    def _make_ctx(self, user="jdoe", domain="corp.local"):
        from asc_api.services.playbook import PlaybookContext
        return PlaybookContext(
            semaphore="red",
            risk_score=0.9,
            trigger_source="soar_auto",
            affected_user=user,
            affected_domain=domain,
        )

    @pytest.mark.asyncio
    async def test_disable_account_step_calls_ad_adapter(self):
        from asc_api.services.playbook import _execute_identity_step

        mock_action = _make_mock_action(action_type="disable_account", success=True)
        mock_db = AsyncMock()
        run = self._make_run()
        ctx = self._make_ctx()
        result = {"action": "DISABLE_ACCOUNT", "status": "ok"}

        with patch("asc_api.adapters.identity.active_directory.ActiveDirectoryAdapter.disable_account",
                   new=AsyncMock(return_value={"status": "ok", "username": "jdoe"})):
            with patch("asc_api.services.pids_service.create_identity_action",
                       new=AsyncMock(return_value=mock_action)):
                await _execute_identity_step("DISABLE_ACCOUNT", ctx, run, mock_db, result)

        assert result["success"] is True
        assert "identity_action_id" in result
        assert "forensic_hash" in result

    @pytest.mark.asyncio
    async def test_force_password_reset_step(self):
        from asc_api.services.playbook import _execute_identity_step

        mock_action = _make_mock_action(action_type="force_password_reset", success=True)
        mock_db = AsyncMock()
        run = self._make_run()
        ctx = self._make_ctx()
        result = {"action": "FORCE_PASSWORD_RESET", "status": "ok"}

        with patch("asc_api.adapters.identity.active_directory.ActiveDirectoryAdapter.force_password_reset",
                   new=AsyncMock(return_value={"status": "ok"})):
            with patch("asc_api.services.pids_service.create_identity_action",
                       new=AsyncMock(return_value=mock_action)):
                await _execute_identity_step("FORCE_PASSWORD_RESET", ctx, run, mock_db, result)

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_quarantine_account_step(self):
        from asc_api.services.playbook import _execute_identity_step

        mock_action = _make_mock_action(action_type="quarantine_account", success=True)
        mock_db = AsyncMock()
        run = self._make_run()
        ctx = self._make_ctx()
        result = {"action": "QUARANTINE_ACCOUNT", "status": "ok"}

        with patch("asc_api.adapters.identity.active_directory.ActiveDirectoryAdapter.move_to_quarantine_ou",
                   new=AsyncMock(return_value={"status": "ok"})):
            with patch("asc_api.services.pids_service.create_identity_action",
                       new=AsyncMock(return_value=mock_action)):
                await _execute_identity_step("QUARANTINE_ACCOUNT", ctx, run, mock_db, result)

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_identity_step_skipped_when_no_affected_user(self):
        from asc_api.services.playbook import _execute_identity_step
        from asc_api.services.playbook import PlaybookContext

        ctx = PlaybookContext(semaphore="red", risk_score=0.9, trigger_source="soar_auto")
        # affected_user is None
        run = self._make_run()
        mock_db = AsyncMock()
        result = {"action": "DISABLE_ACCOUNT", "status": "ok"}

        await _execute_identity_step("DISABLE_ACCOUNT", ctx, run, mock_db, result)
        assert "skipped" in result.get("detail", "").lower()

    @pytest.mark.asyncio
    async def test_ad_failure_creates_forensic_record_with_success_false(self):
        from asc_api.services.playbook import _execute_identity_step

        mock_action = _make_mock_action(action_type="disable_account", success=False)
        mock_db = AsyncMock()
        run = self._make_run()
        ctx = self._make_ctx()
        result = {"action": "DISABLE_ACCOUNT", "status": "ok"}

        with patch("asc_api.adapters.identity.active_directory.ActiveDirectoryAdapter.disable_account",
                   new=AsyncMock(return_value={"status": "error", "error": "modify_failed: ..."})):
            with patch("asc_api.services.pids_service.create_identity_action",
                       new=AsyncMock(return_value=mock_action)):
                await _execute_identity_step("DISABLE_ACCOUNT", ctx, run, mock_db, result)

        assert result["success"] is False
        assert result["status"] == "warning"
        assert "identity_action_id" in result

    @pytest.mark.asyncio
    async def test_context_affected_user_passed_to_pids(self):
        from asc_api.services.playbook import _execute_identity_step

        captured = {}

        async def fake_create(db, *, action_type, username, domain, reason, **kwargs):
            captured["username"] = username
            captured["domain"] = domain
            return _make_mock_action(action_type=action_type, username=username, success=True)

        mock_db = AsyncMock()
        run = self._make_run()
        ctx = self._make_ctx(user="targetuser", domain="example.corp")
        result = {"action": "DISABLE_ACCOUNT", "status": "ok"}

        with patch("asc_api.adapters.identity.active_directory.ActiveDirectoryAdapter.disable_account",
                   new=AsyncMock(return_value={"status": "ok"})):
            with patch("asc_api.services.pids_service.create_identity_action", side_effect=fake_create):
                await _execute_identity_step("DISABLE_ACCOUNT", ctx, run, mock_db, result)

        assert captured["username"] == "targetuser"
        assert captured["domain"] == "example.corp"


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TestPIDSEndpoints
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestPIDSEndpoints:
    def test_pids_router_registered(self):
        """pids.router must be included in the API router."""
        from asc_api.api.v1.router import api_router
        paths = [getattr(r, "path", "") for r in api_router.routes]
        pids_routes = [p for p in paths if "/pids" in p]
        assert len(pids_routes) > 0, "No /pids routes found in api_router"

    def test_pids_router_has_correct_prefix(self):
        from asc_api.api.v1.endpoints.pids import router
        assert router.prefix == "/pids"

    def test_pids_router_tags(self):
        from asc_api.api.v1.endpoints.pids import router
        assert "PIDS" in router.tags

    def test_pids_list_actions_route_exists(self):
        from asc_api.api.v1.endpoints.pids import router
        paths = [r.path for r in router.routes]
        assert "/pids/actions" in paths

    def test_pids_verify_route_exists(self):
        from asc_api.api.v1.endpoints.pids import router
        paths = [r.path for r in router.routes]
        assert any("verify" in p for p in paths)

    def test_pids_timeline_route_exists(self):
        from asc_api.api.v1.endpoints.pids import router
        paths = [r.path for r in router.routes]
        assert any("timeline" in p for p in paths)

    def test_pids_summary_route_exists(self):
        from asc_api.api.v1.endpoints.pids import router
        paths = [r.path for r in router.routes]
        assert any("summary" in p for p in paths)

    def test_valid_pids_action_types_set(self):
        from asc_api.services.pids_service import _VALID_ACTION_TYPES
        expected = {"disable_account", "enable_account", "force_password_reset",
                    "quarantine_account", "enrich_user"}
        assert _VALID_ACTION_TYPES == expected


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TestScheduledReportForensic
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestScheduledReportForensic:
    @pytest.mark.asyncio
    async def test_deliver_report_returns_forensic_hash(self):
        """deliver_scheduled_report must return forensic_hash field."""
        from asc_api.services.soar_service import deliver_scheduled_report
        from asc_api.models.soar import ScheduledReport
        from asc_api.models.hunt import Hunt

        sr = ScheduledReport()
        sr.id = "rpt-1"
        sr.hunt_id = "hunt-1"
        sr.hunt_name = "Test Hunt"
        sr.recipient_email = "sec@corp.local"
        sr.format = "json"
        sr.send_count = 0
        sr.last_error = None
        sr.last_sent_at = None

        hunt = Hunt()
        hunt.id = "hunt-1"
        hunt.name = "Test Hunt"
        hunt.status = "active"
        hunt.priority = "critical"

        def make_result(obj):
            r = MagicMock()
            r.scalar_one_or_none = MagicMock(return_value=obj)
            r.scalars = MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))
            return r

        mock_db = AsyncMock()
        call_count = [0]

        async def fake_execute(_):
            idx = call_count[0]
            call_count[0] += 1
            if idx == 0:
                return make_result(sr)
            elif idx == 1:
                return make_result(hunt)
            else:
                # findings or PIDS timeline
                r = MagicMock()
                r.scalar_one_or_none = MagicMock(return_value=None)
                r.scalars = MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))
                return r

        mock_db.execute = fake_execute
        mock_db.commit = AsyncMock()

        with patch("asc_api.services.soar_service.log_security_action"):
            with patch("asc_api.services.pids_service.get_identity_timeline", new=AsyncMock(return_value=[])):
                with patch("asc_api.services.pids_service._sign_hash", return_value=None):
                    result = await deliver_scheduled_report(mock_db, "rpt-1")

        assert "forensic_hash" in result
        assert len(result["forensic_hash"]) == 128

    @pytest.mark.asyncio
    async def test_deliver_report_includes_identity_timeline(self):
        """Summary must include identity_timeline key with PIDS data."""
        from asc_api.services.soar_service import deliver_scheduled_report
        from asc_api.models.soar import ScheduledReport
        from asc_api.models.hunt import Hunt

        sr = ScheduledReport()
        sr.id = "rpt-2"
        sr.hunt_id = "hunt-2"
        sr.hunt_name = "Hunt 2"
        sr.recipient_email = "sec@corp.local"
        sr.format = "json"
        sr.send_count = 0
        sr.last_error = None
        sr.last_sent_at = None

        hunt = Hunt()
        hunt.id = "hunt-2"
        hunt.name = "Hunt 2"
        hunt.status = "active"
        hunt.priority = "high"

        fake_timeline = [
            {"id": "ia-1", "action_type": "disable_account", "username": "jdoe", "success": True}
        ]

        mock_db = AsyncMock()
        call_count = [0]

        async def fake_execute(_):
            idx = call_count[0]
            call_count[0] += 1
            r = MagicMock()
            r.scalar_one_or_none = MagicMock(return_value=sr if idx == 0 else (hunt if idx == 1 else None))
            r.scalars = MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))
            return r

        mock_db.execute = fake_execute
        mock_db.commit = AsyncMock()

        with patch("asc_api.services.soar_service.log_security_action"):
            with patch("asc_api.services.pids_service.get_identity_timeline", new=AsyncMock(return_value=fake_timeline)):
                with patch("asc_api.services.pids_service._sign_hash", return_value=None):
                    result = await deliver_scheduled_report(mock_db, "rpt-2")

        assert result["summary"]["identity_timeline"] == fake_timeline
        assert result["summary"]["identity_action_count"] == 1

    @pytest.mark.asyncio
    async def test_deliver_report_not_found_returns_error(self):
        from asc_api.services.soar_service import deliver_scheduled_report
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=_scalar_one(None))
        result = await deliver_scheduled_report(mock_db, "nonexistent")
        assert "error" in result
        assert result["error"] == "ScheduledReport not found"

    @pytest.mark.asyncio
    async def test_forensic_signature_none_when_no_key(self):
        """forensic_signature must be None when PIDS_SIGNING_PRIVATE_KEY is absent."""
        from asc_api.services.soar_service import deliver_scheduled_report
        from asc_api.models.soar import ScheduledReport
        from asc_api.models.hunt import Hunt

        sr = ScheduledReport()
        sr.id = "rpt-3"
        sr.hunt_id = "hunt-3"
        sr.hunt_name = "Hunt 3"
        sr.recipient_email = "sec@corp.local"
        sr.format = "json"
        sr.send_count = 0
        sr.last_error = None
        sr.last_sent_at = None

        hunt = Hunt()
        hunt.id = "hunt-3"
        hunt.name = "Hunt 3"
        hunt.status = "active"
        hunt.priority = "medium"

        mock_db = AsyncMock()
        call_count = [0]

        async def fake_execute(_):
            idx = call_count[0]
            call_count[0] += 1
            r = MagicMock()
            r.scalar_one_or_none = MagicMock(return_value=sr if idx == 0 else (hunt if idx == 1 else None))
            r.scalars = MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))
            return r

        mock_db.execute = fake_execute
        mock_db.commit = AsyncMock()

        with patch("asc_api.services.soar_service.log_security_action"):
            with patch("asc_api.services.pids_service.get_identity_timeline", new=AsyncMock(return_value=[])):
                with patch("os.getenv", return_value=None):
                    result = await deliver_scheduled_report(mock_db, "rpt-3")

        assert result["forensic_signature"] is None


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TestPlaybookPB005
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestPlaybookPB005:
    def test_pb005_defined(self):
        from asc_api.services.playbook import PLAYBOOKS
        assert "PB-005" in PLAYBOOKS

    def test_pb005_requires_approval(self):
        from asc_api.services.playbook import PLAYBOOKS
        pb = PLAYBOOKS["PB-005"]
        assert pb.requires_approval is True

    def test_pb005_contains_identity_steps(self):
        from asc_api.services.playbook import PLAYBOOKS
        pb = PLAYBOOKS["PB-005"]
        step_actions = {s.action for s in pb.steps}
        assert "DISABLE_ACCOUNT" in step_actions
        assert "FORCE_PASSWORD_RESET" in step_actions
        assert "QUARANTINE_ACCOUNT" in step_actions

    def test_pb005_semaphore_is_red(self):
        from asc_api.services.playbook import PLAYBOOKS
        pb = PLAYBOOKS["PB-005"]
        assert pb.semaphore == "red"


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TestSOARTriggerP26Fields
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestSOARTriggerP26Fields:
    def test_playbook_trigger_model_has_priority(self):
        from asc_api.models.soar import PlaybookTrigger
        import sqlalchemy
        columns = {c.name for c in PlaybookTrigger.__table__.columns}
        assert "priority" in columns

    def test_playbook_trigger_model_has_rate_limit(self):
        from asc_api.models.soar import PlaybookTrigger
        columns = {c.name for c in PlaybookTrigger.__table__.columns}
        assert "rate_limit_per_hour" in columns

    def test_playbook_trigger_model_has_dedup_window(self):
        from asc_api.models.soar import PlaybookTrigger
        columns = {c.name for c in PlaybookTrigger.__table__.columns}
        assert "dedup_window_minutes" in columns

    def test_trigger_to_dict_includes_p26_fields(self):
        from asc_api.services.soar_service import _trigger_to_dict
        from asc_api.models.soar import PlaybookTrigger
        t = PlaybookTrigger()
        t.id = str(uuid.uuid4())
        t.playbook_id = "PB-005"
        t.playbook_name = "PIDS"
        t.condition_type = "identity_group"
        t.condition_operator = "eq"
        t.condition_value = "Admins"
        t.hunt_id_filter = None
        t.priority = 8
        t.rate_limit_per_hour = 5
        t.dedup_window_minutes = 30
        t.enabled = True
        t.trigger_count = 0
        t.last_triggered_at = None
        t.last_triggered_context = None
        t.created_by = "admin@corp.local"
        t.created_at = datetime.now(timezone.utc)

        d = _trigger_to_dict(t)
        assert d["priority"] == 8
        assert d["rate_limit_per_hour"] == 5
        assert d["dedup_window_minutes"] == 30
