"""
P32-COV-IAM — IAM endpoint coverage boost.

Targets:
  - All IAM success paths (lock/unlock/disable/enable/force-reset/purge/rotate-keys)
  - verify_action_signatures (lines 220-263): empty log, unsigned entries,
    valid signature, invalid signature, 404 path
  - analyst_blocked on all admin-only endpoints

IAM endpoints have no @limiter.limit decorator — coverage blind-spot from
slowapi does NOT apply here. Success paths should be fully coverable.
"""
import uuid
import base64
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from asc_api.models.neutralization import NeutralizationAction
from asc_api.models.user import User
from asc_api.core.signing import (
    generate_analyst_keypair,
    sign_approval,
    encrypt_analyst_private_key,
)
from asc_api.core.config import get_settings

pytestmark = pytest.mark.asyncio

# ── helpers ───────────────────────────────────────────────────────────────────

async def _seed_action(db, *, log=None, action_type="block_ip") -> NeutralizationAction:
    action = NeutralizationAction(
        id=str(uuid.uuid4()),
        action_type=action_type,
        target="192.168.1.100",
        target_type="ip",
        severity="high",
        status="completed",
        approvals_log=log if log is not None else [],
    )
    db.add(action)
    await db.commit()
    await db.refresh(action)
    return action


async def _fresh_analyst(db) -> User:
    """Create an extra analyst distinct from the main fixture."""
    u = User(
        email=f"analyst2_{uuid.uuid4().hex[:6]}@premoscorp.com",
        full_name="Analyst 2",
        hashed_password="x",
        role="analyst",
        is_active=True,
    )
    db.add(u)
    await db.commit()
    await db.refresh(u)
    return u


# ══════════════════════════════════════════════════════════════════════════════
# IAM user lifecycle — success paths
# ══════════════════════════════════════════════════════════════════════════════

class TestIAMStatusSuccess:
    async def test_get_status_found(self, client, admin_headers, analyst_user):
        resp = await client.get(
            f"/api/v1/iam/users/{analyst_user.email}/status",
            headers=admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["email"] == analyst_user.email
        assert "is_active" in body

    async def test_get_status_not_found(self, client, admin_headers):
        resp = await client.get(
            "/api/v1/iam/users/ghost@nowhere.com/status",
            headers=admin_headers,
        )
        assert resp.status_code == 404

    async def test_get_status_analyst_blocked(self, client, analyst_headers, analyst_user):
        resp = await client.get(
            f"/api/v1/iam/users/{analyst_user.email}/status",
            headers=analyst_headers,
        )
        assert resp.status_code == 403


class TestIAMLock:
    async def test_lock_success(self, client, admin_headers, analyst_user):
        resp = await client.post(
            f"/api/v1/iam/users/{analyst_user.email}/lock",
            json={"minutes": 30},
            headers=admin_headers,
        )
        assert resp.status_code == 200
        assert "message" in resp.json()

    async def test_lock_default_minutes(self, client, admin_headers, analyst_user):
        resp = await client.post(
            f"/api/v1/iam/users/{analyst_user.email}/lock",
            json={},
            headers=admin_headers,
        )
        assert resp.status_code == 200

    async def test_lock_not_found(self, client, admin_headers):
        resp = await client.post(
            "/api/v1/iam/users/ghost@nowhere.com/lock",
            json={"minutes": 15},
            headers=admin_headers,
        )
        assert resp.status_code == 404


class TestIAMUnlock:
    async def test_unlock_success(self, client, admin_headers, analyst_user):
        resp = await client.post(
            f"/api/v1/iam/users/{analyst_user.email}/unlock",
            headers=admin_headers,
        )
        assert resp.status_code == 200
        assert "message" in resp.json()

    async def test_unlock_not_found(self, client, admin_headers):
        resp = await client.post(
            "/api/v1/iam/users/ghost@nowhere.com/unlock",
            headers=admin_headers,
        )
        assert resp.status_code == 404


class TestIAMDisable:
    async def test_disable_self_rejected(self, client, admin_headers, admin_user):
        resp = await client.post(
            f"/api/v1/iam/users/{admin_user.email}/disable",
            headers=admin_headers,
        )
        assert resp.status_code == 422

    async def test_disable_success(self, client, admin_headers, analyst_user):
        resp = await client.post(
            f"/api/v1/iam/users/{analyst_user.email}/disable",
            headers=admin_headers,
        )
        assert resp.status_code == 200

    async def test_disable_not_found(self, client, admin_headers):
        resp = await client.post(
            "/api/v1/iam/users/ghost@nowhere.com/disable",
            headers=admin_headers,
        )
        assert resp.status_code == 404


class TestIAMEnable:
    async def test_enable_success(self, client, admin_headers, analyst_user):
        resp = await client.post(
            f"/api/v1/iam/users/{analyst_user.email}/enable",
            headers=admin_headers,
        )
        assert resp.status_code == 200
        assert "message" in resp.json()

    async def test_enable_not_found(self, client, admin_headers):
        resp = await client.post(
            "/api/v1/iam/users/ghost@nowhere.com/enable",
            headers=admin_headers,
        )
        assert resp.status_code == 404


class TestIAMForceReset:
    async def test_force_reset_success(self, client, admin_headers, analyst_user):
        resp = await client.post(
            f"/api/v1/iam/users/{analyst_user.email}/force-reset",
            headers=admin_headers,
        )
        assert resp.status_code == 200
        assert "message" in resp.json()

    async def test_force_reset_not_found(self, client, admin_headers):
        resp = await client.post(
            "/api/v1/iam/users/ghost@nowhere.com/force-reset",
            headers=admin_headers,
        )
        assert resp.status_code == 404


class TestIAMPurge:
    async def test_purge_tokens(self, client, admin_headers):
        resp = await client.delete("/api/v1/iam/tokens/purge", headers=admin_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "purged" in body
        assert "l1_cache_size" in body

    async def test_purge_analyst_blocked(self, client, analyst_headers):
        resp = await client.delete("/api/v1/iam/tokens/purge", headers=analyst_headers)
        assert resp.status_code == 403


# ══════════════════════════════════════════════════════════════════════════════
# rotate-keys  (lines 177-197)
# ══════════════════════════════════════════════════════════════════════════════

class TestIAMRotateKeys:
    async def test_rotate_keys_not_found(self, client, admin_headers):
        resp = await client.post(
            "/api/v1/iam/users/ghost@nowhere.com/rotate-keys",
            headers=admin_headers,
        )
        assert resp.status_code == 404

    async def test_rotate_keys_success(self, client, admin_headers, db, analyst_user):
        resp = await client.post(
            f"/api/v1/iam/users/{analyst_user.email}/rotate-keys",
            headers=admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "public_key" in body
        assert "message" in body
        assert analyst_user.email in body["message"]

    async def test_rotate_keys_analyst_blocked(self, client, analyst_headers, analyst_user):
        resp = await client.post(
            f"/api/v1/iam/users/{analyst_user.email}/rotate-keys",
            headers=analyst_headers,
        )
        assert resp.status_code == 403


# ══════════════════════════════════════════════════════════════════════════════
# verify_action_signatures  (lines 220-263)
# ══════════════════════════════════════════════════════════════════════════════

class TestVerifyActionSignatures:
    async def test_action_not_found(self, client, admin_headers):
        resp = await client.get(
            f"/api/v1/iam/actions/{uuid.uuid4()}/verify-signatures",
            headers=admin_headers,
        )
        assert resp.status_code == 404

    async def test_empty_log_all_valid(self, client, admin_headers, db):
        """Action with no approvals → verdict partial_unsigned (all_signed=False)."""
        action = await _seed_action(db, log=[])
        resp = await client.get(
            f"/api/v1/iam/actions/{action.id}/verify-signatures",
            headers=admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["action_id"] == action.id
        assert body["approvals_count"] == 0
        assert body["entries"] == []

    async def test_unsigned_entries(self, client, admin_headers, db):
        """Entries missing signature → status 'unsigned', all_signed=False → partial_unsigned."""
        approvals = [
            {"approved_by": "analyst@premoscorp.com", "approved_at": "2026-06-12T10:00:00Z"},
            {"approved_by": "analyst2@premoscorp.com", "approved_at": "2026-06-12T10:01:00Z"},
        ]
        action = await _seed_action(db, log=approvals)
        resp = await client.get(
            f"/api/v1/iam/actions/{action.id}/verify-signatures",
            headers=admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["approvals_count"] == 2
        assert body["verdict"] == "partial_unsigned"
        assert all(e["status"] == "unsigned" for e in body["entries"])

    async def test_valid_signature_entry(self, client, admin_headers, db):
        """Entry with a real Ed25519 signature → status 'valid', verdict 'all_valid'."""
        priv_b64, pub_b64 = generate_analyst_keypair()
        action_id = str(uuid.uuid4())
        approved_by = "analyst@premoscorp.com"
        approved_at = "2026-06-12T12:00:00Z"
        sig = sign_approval(priv_b64, action_id, approved_by, approved_at)

        approvals = [
            {
                "approved_by": approved_by,
                "approved_at": approved_at,
                "signature": sig,
                "public_key": pub_b64,
            }
        ]
        action = await _seed_action(db, log=approvals)
        # Override the action id to match the one we signed
        action.id = action_id
        await db.commit()

        resp = await client.get(
            f"/api/v1/iam/actions/{action_id}/verify-signatures",
            headers=admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["verdict"] == "all_valid"
        assert body["entries"][0]["status"] == "valid"
        assert body["entries"][0]["valid"] is True

    async def test_invalid_signature_entry(self, client, admin_headers, db):
        """Entry with tampered signature → status 'invalid', verdict 'invalid'."""
        _, pub_b64 = generate_analyst_keypair()
        bad_sig = base64.b64encode(b"X" * 64).decode()
        action_id = str(uuid.uuid4())
        approvals = [
            {
                "approved_by": "analyst@premoscorp.com",
                "approved_at": "2026-06-12T12:00:00Z",
                "signature": bad_sig,
                "public_key": pub_b64,
            }
        ]
        action = await _seed_action(db, log=approvals)
        action.id = action_id
        await db.commit()

        resp = await client.get(
            f"/api/v1/iam/actions/{action_id}/verify-signatures",
            headers=admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["verdict"] == "invalid"
        assert body["entries"][0]["status"] == "invalid"
        assert body["entries"][0]["valid"] is False

    async def test_mixed_signed_unsigned(self, client, admin_headers, db):
        """Mix of signed and unsigned entries → partial_unsigned verdict."""
        priv_b64, pub_b64 = generate_analyst_keypair()
        action_id = str(uuid.uuid4())
        approved_at = "2026-06-12T12:30:00Z"
        sig = sign_approval(priv_b64, action_id, "analyst@premoscorp.com", approved_at)

        approvals = [
            {
                "approved_by": "analyst@premoscorp.com",
                "approved_at": approved_at,
                "signature": sig,
                "public_key": pub_b64,
            },
            {
                "approved_by": "analyst2@premoscorp.com",
                "approved_at": "2026-06-12T12:31:00Z",
            },
        ]
        action = await _seed_action(db, log=approvals)
        action.id = action_id
        await db.commit()

        resp = await client.get(
            f"/api/v1/iam/actions/{action_id}/verify-signatures",
            headers=admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["verdict"] == "partial_unsigned"
        assert body["approvals_count"] == 2

    async def test_verify_analyst_blocked(self, client, analyst_headers, db):
        action = await _seed_action(db)
        resp = await client.get(
            f"/api/v1/iam/actions/{action.id}/verify-signatures",
            headers=analyst_headers,
        )
        assert resp.status_code == 403
