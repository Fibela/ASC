"""
Premos Forensic Neutralization (PFN) — P19.3 Test Suite

Covers:
  - Unit: canonical builder, SHA3-512 hash, Ed25519 sign/verify
  - Integration: create_forensic_entry, verify_forensic_entry (DB)
  - API: GET /forensic/actions/{id}, POST /forensic/actions/{id}/verify,
         GET /forensic/ledger
  - Security: auth enforcement, admin-only ledger, tamper detection
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch
import uuid

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.core.security import create_access_token
from asc_api.core.signing import (
    generate_analyst_keypair,
    encrypt_analyst_private_key,
    decrypt_analyst_private_key,
)
from asc_api.core.config import get_settings
from asc_api.models.forensic_entry import ForensicEntry
from asc_api.models.neutralization import NeutralizationAction
from asc_api.models.user import User
from asc_api.services.pfn import (
    _build_canonical,
    _compute_hash,
    _sign_hash,
    _verify_signature,
    create_forensic_entry,
    verify_forensic_entry,
    get_entry_by_action,
    list_entries,
)

settings = get_settings()


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_action(**kwargs) -> NeutralizationAction:
    defaults = dict(
        id=str(uuid.uuid4()),
        action_type="block_ip",
        target="10.0.0.99",
        target_type="ip",
        severity="high",
        status="completed",
        approved_by="analyst@premoscorp.com",
        approved_at=datetime(2026, 6, 10, 12, 0, 0, tzinfo=timezone.utc),
        executed_at=datetime(2026, 6, 10, 12, 0, 1, tzinfo=timezone.utc),
        params={"reason": "malicious traffic"},
        result={"success": True},
    )
    defaults.update(kwargs)
    return NeutralizationAction(**defaults)


def _make_user_with_keys(email: str, role: str = "analyst") -> User:
    priv_b64, pub_b64 = generate_analyst_keypair()
    enc_priv = encrypt_analyst_private_key(priv_b64, settings.SECRET_KEY)
    return User(
        id=str(uuid.uuid4()),
        email=email,
        full_name="Test Analyst",
        hashed_password="x",
        role=role,
        is_active=True,
        signing_public_key=pub_b64,
        signing_private_key_enc=enc_priv,
    )


# ── Unit: canonical + hash ─────────────────────────────────────────────────────

class TestCanonicalAndHash:
    def test_build_canonical_has_required_fields(self):
        action = _make_action()
        canon = _build_canonical(action, "analyst@premoscorp.com")
        assert canon["action_id"] == action.id
        assert canon["action_type"] == "block_ip"
        assert canon["target"] == "10.0.0.99"
        assert canon["approved_by"] == "analyst@premoscorp.com"
        assert canon["pfn_version"] == "1"

    def test_build_canonical_is_deterministic(self):
        action = _make_action(id="fixed-id-111")
        c1 = _build_canonical(action, "a@b.com")
        c2 = _build_canonical(action, "a@b.com")
        assert c1 == c2

    def test_build_canonical_email_changes_output(self):
        action = _make_action()
        c1 = _build_canonical(action, "alice@corp.com")
        c2 = _build_canonical(action, "bob@corp.com")
        assert c1["approved_by"] != c2["approved_by"]

    def test_compute_hash_returns_128_hex_chars(self):
        action = _make_action()
        canon = _build_canonical(action, "analyst@premoscorp.com")
        h = _compute_hash(canon)
        assert len(h) == 128
        int(h, 16)  # must be valid hex

    def test_compute_hash_matches_manual_sha3_512(self):
        action = _make_action(id="stable-id-xyz")
        canon = _build_canonical(action, "analyst@premoscorp.com")
        h = _compute_hash(canon)
        # Manual reference
        payload = json.dumps(canon, sort_keys=True, separators=(",", ":")).encode()
        expected = hashlib.sha3_512(payload).hexdigest()
        assert h == expected

    def test_compute_hash_changes_on_field_change(self):
        action1 = _make_action(target="10.0.0.1")
        action2 = _make_action(id=action1.id, target="10.0.0.2")
        c1 = _build_canonical(action1, "a@b.com")
        c2 = _build_canonical(action2, "a@b.com")
        assert _compute_hash(c1) != _compute_hash(c2)


# ── Unit: sign / verify ────────────────────────────────────────────────────────

class TestSignVerify:
    def test_sign_and_verify_roundtrip(self):
        priv_b64, pub_b64 = generate_analyst_keypair()
        action = _make_action()
        canon = _build_canonical(action, "a@b.com")
        h = _compute_hash(canon)
        sig = _sign_hash(h, priv_b64)
        assert _verify_signature(h, sig, pub_b64) is True

    def test_wrong_key_fails_verification(self):
        priv1, _ = generate_analyst_keypair()
        _, pub2 = generate_analyst_keypair()
        action = _make_action()
        canon = _build_canonical(action, "a@b.com")
        h = _compute_hash(canon)
        sig = _sign_hash(h, priv1)
        assert _verify_signature(h, sig, pub2) is False

    def test_tampered_hash_fails_verification(self):
        priv, pub = generate_analyst_keypair()
        action = _make_action()
        canon = _build_canonical(action, "a@b.com")
        h = _compute_hash(canon)
        sig = _sign_hash(h, priv)
        # Tamper: flip first char
        tampered = ("a" if h[0] != "a" else "b") + h[1:]
        assert _verify_signature(tampered, sig, pub) is False

    def test_verify_signature_never_raises(self):
        # Garbage inputs should return False, not raise
        result = _verify_signature("badhex", "badsig==", "badkey==")
        assert result is False


# ── Integration: create_forensic_entry ────────────────────────────────────────

@pytest.mark.asyncio
class TestCreateForensicEntry:
    async def test_creates_entry_in_db(self, db: AsyncSession):
        user = _make_user_with_keys("analyst@premoscorp.com")
        db.add(user)
        action = _make_action()
        db.add(action)
        await db.commit()
        await db.refresh(user)
        await db.refresh(action)

        entry = await create_forensic_entry(db, action, user)

        assert entry is not None
        assert entry.action_id == action.id
        assert entry.action_type == "block_ip"
        assert len(entry.hash_sha3_512) == 128
        assert entry.signed_by_email == user.email
        assert entry.signed_by_user_id == str(user.id)
        assert entry.signature_ed25519 != ""
        assert entry.verified is False

    async def test_returns_none_when_user_has_no_keys(self, db: AsyncSession):
        user = User(
            id=str(uuid.uuid4()),
            email="nokey@corp.com",
            full_name="No Key",
            hashed_password="x",
            role="analyst",
            is_active=True,
            # No signing keys
        )
        db.add(user)
        action = _make_action()
        db.add(action)
        await db.commit()
        await db.refresh(user)
        await db.refresh(action)

        entry = await create_forensic_entry(db, action, user)
        assert entry is None

    async def test_entry_retrievable_by_action_id(self, db: AsyncSession):
        user = _make_user_with_keys("analyst@premoscorp.com")
        db.add(user)
        action = _make_action()
        db.add(action)
        await db.commit()
        await db.refresh(user)
        await db.refresh(action)

        await create_forensic_entry(db, action, user)
        fetched = await get_entry_by_action(db, action.id)
        assert fetched is not None
        assert fetched.action_id == action.id

    async def test_list_entries_returns_latest_first(self, db: AsyncSession):
        user = _make_user_with_keys("analyst@premoscorp.com")
        db.add(user)
        await db.commit()
        await db.refresh(user)

        for _ in range(3):
            action = _make_action()
            db.add(action)
            await db.commit()
            await db.refresh(action)
            await create_forensic_entry(db, action, user)

        entries = await list_entries(db, limit=10)
        assert len(entries) == 3
        # Should be ordered by signed_at descending
        for i in range(len(entries) - 1):
            assert entries[i].signed_at >= entries[i + 1].signed_at


# ── Integration: verify_forensic_entry ────────────────────────────────────────

@pytest.mark.asyncio
class TestVerifyForensicEntry:
    async def test_verify_valid_entry(self, db: AsyncSession):
        user = _make_user_with_keys("analyst@premoscorp.com")
        db.add(user)
        action = _make_action()
        db.add(action)
        await db.commit()
        await db.refresh(user)
        await db.refresh(action)

        entry = await create_forensic_entry(db, action, user)
        assert entry is not None

        result = await verify_forensic_entry(db, entry, user.signing_public_key)
        assert result is True
        assert entry.verified is True
        assert entry.last_verified_at is not None

    async def test_tampered_hash_fails_verification(self, db: AsyncSession):
        user = _make_user_with_keys("analyst@premoscorp.com")
        db.add(user)
        action = _make_action()
        db.add(action)
        await db.commit()
        await db.refresh(user)
        await db.refresh(action)

        entry = await create_forensic_entry(db, action, user)
        assert entry is not None

        # Tamper with stored hash
        original_hash = entry.hash_sha3_512
        entry.hash_sha3_512 = "a" * 128

        result = await verify_forensic_entry(db, entry, user.signing_public_key)
        assert result is False

        # Restore for DB cleanup
        entry.hash_sha3_512 = original_hash

    async def test_wrong_public_key_fails_verification(self, db: AsyncSession):
        user = _make_user_with_keys("analyst@premoscorp.com")
        db.add(user)
        action = _make_action()
        db.add(action)
        await db.commit()
        await db.refresh(user)
        await db.refresh(action)

        entry = await create_forensic_entry(db, action, user)
        assert entry is not None

        _, wrong_pub = generate_analyst_keypair()
        result = await verify_forensic_entry(db, entry, wrong_pub)
        assert result is False


# ── API: GET /forensic/actions/{action_id} ─────────────────────────────────────

@pytest.mark.asyncio
class TestForensicGetProofAPI:
    async def test_returns_404_when_no_entry(
        self, client: AsyncClient, admin_user: User, admin_headers: dict
    ):
        resp = await client.get(
            "/api/v1/forensic/actions/nonexistent-id",
            headers=admin_headers,
        )
        assert resp.status_code == 404

    async def test_returns_401_without_auth(self, client: AsyncClient):
        resp = await client.get("/api/v1/forensic/actions/some-id")
        assert resp.status_code == 401

    async def test_returns_entry_for_valid_action(
        self, client: AsyncClient, db: AsyncSession,
        admin_user: User, admin_headers: dict,
    ):
        # Provision signing keys for admin_user
        priv_b64, pub_b64 = generate_analyst_keypair()
        admin_user.signing_public_key = pub_b64
        admin_user.signing_private_key_enc = encrypt_analyst_private_key(
            priv_b64, settings.SECRET_KEY
        )
        action = _make_action(approved_by=admin_user.email)
        db.add(action)
        await db.commit()
        await db.refresh(action)
        await db.refresh(admin_user)

        entry = await create_forensic_entry(db, action, admin_user)
        assert entry is not None

        resp = await client.get(
            f"/api/v1/forensic/actions/{action.id}",
            headers=admin_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["action_id"] == action.id
        assert data["action_type"] == "block_ip"
        assert len(data["hash_sha3_512"]) == 128
        assert "signature_ed25519" in data
        assert "canonical_data" in data

    async def test_analyst_can_access_proof(
        self, client: AsyncClient, db: AsyncSession,
        analyst_user: User, analyst_headers: dict,
        admin_user: User,
    ):
        priv_b64, pub_b64 = generate_analyst_keypair()
        admin_user.signing_public_key = pub_b64
        admin_user.signing_private_key_enc = encrypt_analyst_private_key(
            priv_b64, settings.SECRET_KEY
        )
        action = _make_action(approved_by=admin_user.email)
        db.add(action)
        await db.commit()
        await db.refresh(action)
        await db.refresh(admin_user)

        entry = await create_forensic_entry(db, action, admin_user)
        assert entry is not None

        resp = await client.get(
            f"/api/v1/forensic/actions/{action.id}",
            headers=analyst_headers,
        )
        # Analysts (non-admin) can also read proofs
        assert resp.status_code == 200


# ── API: POST /forensic/actions/{action_id}/verify ────────────────────────────

@pytest.mark.asyncio
class TestForensicVerifyAPI:
    async def test_verify_valid_entry_returns_valid_true(
        self, client: AsyncClient, db: AsyncSession,
        admin_user: User, admin_headers: dict,
    ):
        priv_b64, pub_b64 = generate_analyst_keypair()
        admin_user.signing_public_key = pub_b64
        admin_user.signing_private_key_enc = encrypt_analyst_private_key(
            priv_b64, settings.SECRET_KEY
        )
        action = _make_action(approved_by=admin_user.email)
        db.add(action)
        await db.commit()
        await db.refresh(action)
        await db.refresh(admin_user)

        entry = await create_forensic_entry(db, action, admin_user)
        assert entry is not None

        resp = await client.post(
            f"/api/v1/forensic/actions/{action.id}/verify",
            headers=admin_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is True
        assert data["action_id"] == action.id
        assert data["signed_by"] == admin_user.email
        assert "hash_sha3_512" in data

    async def test_verify_returns_404_for_unknown_action(
        self, client: AsyncClient, admin_headers: dict
    ):
        resp = await client.post(
            "/api/v1/forensic/actions/ghost-action-id/verify",
            headers=admin_headers,
        )
        assert resp.status_code == 404

    async def test_verify_requires_auth(self, client: AsyncClient):
        resp = await client.post("/api/v1/forensic/actions/any-id/verify")
        assert resp.status_code == 401

    async def test_tampered_canonical_data_returns_valid_false(
        self, client: AsyncClient, db: AsyncSession,
        admin_user: User, admin_headers: dict,
    ):
        priv_b64, pub_b64 = generate_analyst_keypair()
        admin_user.signing_public_key = pub_b64
        admin_user.signing_private_key_enc = encrypt_analyst_private_key(
            priv_b64, settings.SECRET_KEY
        )
        action = _make_action(approved_by=admin_user.email)
        db.add(action)
        await db.commit()
        await db.refresh(action)
        await db.refresh(admin_user)

        entry = await create_forensic_entry(db, action, admin_user)
        assert entry is not None

        # Tamper: corrupt canonical_data in DB so recomputed hash will differ
        entry.canonical_data = {**entry.canonical_data, "target": "tampered-ip"}
        await db.commit()

        resp = await client.post(
            f"/api/v1/forensic/actions/{action.id}/verify",
            headers=admin_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is False


# ── API: GET /forensic/ledger ─────────────────────────────────────────────────

@pytest.mark.asyncio
class TestForensicLedgerAPI:
    async def test_admin_can_access_ledger(
        self, client: AsyncClient, admin_headers: dict
    ):
        resp = await client.get("/api/v1/forensic/ledger", headers=admin_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "entries" in data
        assert "total" in data

    async def test_analyst_cannot_access_ledger(
        self, client: AsyncClient, analyst_headers: dict
    ):
        resp = await client.get("/api/v1/forensic/ledger", headers=analyst_headers)
        assert resp.status_code == 403

    async def test_ledger_requires_auth(self, client: AsyncClient):
        resp = await client.get("/api/v1/forensic/ledger")
        assert resp.status_code == 401

    async def test_ledger_pagination_params(
        self, client: AsyncClient, admin_headers: dict
    ):
        resp = await client.get(
            "/api/v1/forensic/ledger?limit=10&offset=0",
            headers=admin_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["limit"] == 10
        assert data["offset"] == 0

    async def test_ledger_returns_created_entries(
        self, client: AsyncClient, db: AsyncSession,
        admin_user: User, admin_headers: dict,
    ):
        priv_b64, pub_b64 = generate_analyst_keypair()
        admin_user.signing_public_key = pub_b64
        admin_user.signing_private_key_enc = encrypt_analyst_private_key(
            priv_b64, settings.SECRET_KEY
        )
        await db.commit()
        await db.refresh(admin_user)

        for _ in range(2):
            action = _make_action(approved_by=admin_user.email)
            db.add(action)
            await db.commit()
            await db.refresh(action)
            await create_forensic_entry(db, action, admin_user)

        resp = await client.get("/api/v1/forensic/ledger", headers=admin_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 2
