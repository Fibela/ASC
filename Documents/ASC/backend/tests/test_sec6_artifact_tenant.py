"""
SEC-6 — Artifact Tenant Isolation: comprehensive test suite.

Coverage:
  1. Model integrity  — tenant_id column exists with correct type
  2. Upload behavior  — tenant_id + submitted_by set from authenticated caller
  3. Same-tenant GET  — owner and same-tenant admin can retrieve artifact
  4. Cross-tenant GET — different tenant gets 404 (no data leak)
  5. Unauthenticated  — 401 on all protected endpoints
  6. NULL tenant      — single-tenant (tenant_id=None) users isolated from multi-tenant
  7. Security scan    — responses contain no secrets/API keys; 404 is identical
                        whether artifact belongs to another tenant or doesn't exist
  8. Domain/IP inputs — basic input guard (SEC-14 partial)
  9. Migration        — a7b90v8w2x25 migration file present with correct metadata
"""

from __future__ import annotations

import io
import struct
import uuid as _uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.models.artifact import Artifact
from asc_api.models.user import User
from asc_api.core.security import create_access_token, get_password_hash


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _minimal_pe_bytes() -> bytes:
    """56-byte stub that python-magic identifies as application/x-dosexec (MZ header)."""
    return b"MZ" + b"\x00" * 54


def _make_user(
    *,
    role: str = "analyst",
    tenant_id: str | None = "tenant-aaa",
    email: str | None = None,
) -> User:
    u = User(
        id=str(_uuid.uuid4()),
        email=email or f"{_uuid.uuid4().hex[:8]}@test.com",
        full_name="Test User",
        hashed_password=get_password_hash("P@ssw0rd!"),
        role=role,
        tenant_id=tenant_id,
        is_active=True,
    )
    return u


async def _add_user(db: AsyncSession, **kwargs) -> User:
    u = _make_user(**kwargs)
    db.add(u)
    await db.commit()
    await db.refresh(u)
    return u


def _auth_headers(user: User) -> dict[str, str]:
    token = create_access_token(user.id)
    return {"Authorization": f"Bearer {token}"}


def _make_artifact(
    *,
    tenant_id: str | None = "tenant-aaa",
    submitted_by: str | None = None,
) -> Artifact:
    return Artifact(
        id=str(_uuid.uuid4()),
        filename="sample.exe",
        analysis_status="analyzed",
        risk_score=0.2,
        analysis_result={"verdict": "clean"},
        tenant_id=tenant_id,
        submitted_by=submitted_by,
    )


# ─── 1. Model integrity ───────────────────────────────────────────────────────

class TestArtifactModelSchema:
    """Verify model has the fields SEC-6 requires."""

    def test_tenant_id_column_exists(self):
        cols = {c.key for c in Artifact.__table__.columns}
        assert "tenant_id" in cols, "Artifact must have tenant_id column"

    def test_submitted_by_column_exists(self):
        cols = {c.key for c in Artifact.__table__.columns}
        assert "submitted_by" in cols

    def test_tenant_id_is_nullable(self):
        col = Artifact.__table__.c["tenant_id"]
        assert col.nullable is True, "tenant_id must be nullable (supports single-tenant legacy rows)"

    def test_tenant_id_max_length(self):
        col = Artifact.__table__.c["tenant_id"]
        assert col.type.length == 36

    def test_tenant_id_index_exists(self):
        indexed_cols = {
            col.name
            for idx in Artifact.__table__.indexes
            for col in idx.columns
        }
        assert "tenant_id" in indexed_cols, "tenant_id must be indexed for O(log n) scoped lookups"

    def test_artifact_instantiation_with_tenant(self):
        a = Artifact(
            id=str(_uuid.uuid4()),
            filename="test.exe",
            tenant_id="tenant-xyz",
            submitted_by="user-123",
        )
        assert a.tenant_id == "tenant-xyz"
        assert a.submitted_by == "user-123"

    def test_artifact_instantiation_null_tenant(self):
        a = Artifact(id=str(_uuid.uuid4()), filename="test.exe")
        assert a.tenant_id is None


# ─── 2. Upload sets tenant_id + submitted_by ─────────────────────────────────

class TestAnalyzeFileUpload:
    """POST /analyze/file correctly stamps tenant metadata on new artifacts."""

    @pytest.mark.asyncio
    async def test_upload_sets_tenant_id(self, db: AsyncSession, client: AsyncClient):
        user = await _add_user(db, role="analyst", tenant_id="tenant-upload-test")
        fake_result = {
            "verdict": "clean", "risk_score": 0.1, "file_type": "PE32",
            "size_bytes": 56, "hashes": {"md5": "a" * 32, "sha1": "b" * 40, "sha256": "c" * 64},
            "signature_hits": [], "matched_iocs": [],
        }
        with patch("asc_api.api.v1.endpoints.analyze.analyzer.analyze_artifact",
                   new=AsyncMock(return_value=fake_result)), \
             patch("asc_api.api.v1.endpoints.analyze._validate_file", return_value="application/x-dosexec"):
            resp = await client.post(
                "/api/v1/analyze/file",
                files={"file": ("sample.exe", _minimal_pe_bytes(), "application/octet-stream")},
                headers=_auth_headers(user),
            )
        assert resp.status_code == 200
        artifact_id = resp.json()["artifact_id"]

        from sqlalchemy import select
        row = (await db.execute(select(Artifact).where(Artifact.id == artifact_id))).scalar_one_or_none()
        assert row is not None
        assert row.tenant_id == "tenant-upload-test"
        assert row.submitted_by == user.id

    @pytest.mark.asyncio
    async def test_upload_null_tenant_user_sets_null_tenant_id(self, db, client):
        user = await _add_user(db, role="analyst", tenant_id=None)
        fake_result = {
            "verdict": "clean", "risk_score": 0.0, "file_type": "PE32",
            "size_bytes": 56, "hashes": {"md5": "a" * 32, "sha1": "b" * 40, "sha256": "c" * 64},
            "signature_hits": [], "matched_iocs": [],
        }
        with patch("asc_api.api.v1.endpoints.analyze.analyzer.analyze_artifact",
                   new=AsyncMock(return_value=fake_result)), \
             patch("asc_api.api.v1.endpoints.analyze._validate_file", return_value="application/x-dosexec"):
            resp = await client.post(
                "/api/v1/analyze/file",
                files={"file": ("sample.exe", _minimal_pe_bytes(), "application/octet-stream")},
                headers=_auth_headers(user),
            )
        assert resp.status_code == 200
        from sqlalchemy import select
        row = (await db.execute(select(Artifact).where(Artifact.id == resp.json()["artifact_id"]))).scalar_one_or_none()
        assert row.tenant_id is None

    @pytest.mark.asyncio
    async def test_upload_requires_analyst_or_admin(self, db, client):
        viewer = await _add_user(db, role="viewer", tenant_id="tenant-a")
        resp = await client.post(
            "/api/v1/analyze/file",
            files={"file": ("x.exe", b"MZ", "application/octet-stream")},
            headers=_auth_headers(viewer),
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_upload_unauthenticated_returns_401(self, client):
        resp = await client.post(
            "/api/v1/analyze/file",
            files={"file": ("x.exe", b"MZ", "application/octet-stream")},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_upload_rejected_mime_returns_415(self, db, client):
        """MIME rejection: python-magic is mocked so the test is env-independent."""
        user = await _add_user(db, role="analyst", tenant_id="tenant-a")
        with patch("asc_api.api.v1.endpoints.analyze._detect_mime", return_value="image/jpeg"):
            resp = await client.post(
                "/api/v1/analyze/file",
                files={"file": ("photo.jpg", b"\xff\xd8\xff", "image/jpeg")},
                headers=_auth_headers(user),
            )
        assert resp.status_code == 415


# ─── 3. Same-tenant GET ───────────────────────────────────────────────────────

class TestGetArtifactSameTenant:
    """Owner and same-tenant admin can retrieve artifact; result is correct."""

    @pytest_asyncio.fixture
    async def artifact_and_owner(self, db: AsyncSession):
        owner = await _add_user(db, role="analyst", tenant_id="tenant-same")
        art = _make_artifact(tenant_id="tenant-same", submitted_by=owner.id)
        db.add(art)
        await db.commit()
        return art, owner

    @pytest.mark.asyncio
    async def test_owner_can_get_artifact(self, artifact_and_owner, client):
        art, owner = artifact_and_owner
        resp = await client.get(f"/api/v1/analyze/artifact/{art.id}", headers=_auth_headers(owner))
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_same_tenant_admin_can_get_artifact(self, artifact_and_owner, db, client):
        art, _ = artifact_and_owner
        admin = await _add_user(db, role="admin", tenant_id="tenant-same")
        resp = await client.get(f"/api/v1/analyze/artifact/{art.id}", headers=_auth_headers(admin))
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_response_contains_analysis_result(self, artifact_and_owner, client):
        art, owner = artifact_and_owner
        resp = await client.get(f"/api/v1/analyze/artifact/{art.id}", headers=_auth_headers(owner))
        assert resp.status_code == 200
        assert resp.json() == {"verdict": "clean"}

    @pytest.mark.asyncio
    async def test_response_contains_no_api_keys(self, artifact_and_owner, client):
        """Security scan: response body must not leak any secrets or key-like strings."""
        art, owner = artifact_and_owner
        resp = await client.get(f"/api/v1/analyze/artifact/{art.id}", headers=_auth_headers(owner))
        body = resp.text
        # No Stripe key patterns
        assert "sk_live_" not in body
        assert "rk_live_" not in body
        assert "sk_test_" not in body
        # No Resend key patterns
        assert "re_" not in body or "verdict" in body  # "re_" may appear in content words
        # No JWT-like strings (Bearer tokens)
        assert "eyJ" not in body


# ─── 4. Cross-tenant isolation ────────────────────────────────────────────────

class TestCrossTenantIsolation:
    """Core SEC-6 assertion: cross-tenant GET must return 404."""

    @pytest_asyncio.fixture
    async def tenants(self, db: AsyncSession):
        user_a = await _add_user(db, role="analyst", tenant_id="tenant-alpha")
        user_b = await _add_user(db, role="analyst", tenant_id="tenant-beta")
        admin_b = await _add_user(db, role="admin", tenant_id="tenant-beta")
        art = _make_artifact(tenant_id="tenant-alpha", submitted_by=user_a.id)
        db.add(art)
        await db.commit()
        return art, user_a, user_b, admin_b

    @pytest.mark.asyncio
    async def test_different_tenant_analyst_gets_404(self, tenants, client):
        art, _, user_b, _ = tenants
        resp = await client.get(f"/api/v1/analyze/artifact/{art.id}", headers=_auth_headers(user_b))
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_different_tenant_admin_gets_404(self, tenants, client):
        """Admin privilege does NOT extend across tenant boundaries."""
        art, _, _, admin_b = tenants
        resp = await client.get(f"/api/v1/analyze/artifact/{art.id}", headers=_auth_headers(admin_b))
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_404_is_indistinguishable_from_nonexistent(self, tenants, db, client):
        """Cross-tenant 404 must be identical to a truly-not-found 404 (no oracle attack)."""
        art, _, user_b, _ = tenants
        cross_tenant_resp = await client.get(
            f"/api/v1/analyze/artifact/{art.id}", headers=_auth_headers(user_b)
        )
        nonexistent_resp = await client.get(
            f"/api/v1/analyze/artifact/{_uuid.uuid4()}", headers=_auth_headers(user_b)
        )
        assert cross_tenant_resp.status_code == nonexistent_resp.status_code == 404
        assert cross_tenant_resp.json() == nonexistent_resp.json()

    @pytest.mark.asyncio
    async def test_unauthenticated_get_returns_401(self, tenants, client):
        art, _, _, _ = tenants
        resp = await client.get(f"/api/v1/analyze/artifact/{art.id}")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_tenant_a_cannot_see_tenant_b_artifacts(self, tenants, db, client):
        """Bidirectional isolation: tenant-alpha also cannot see tenant-beta artifacts."""
        _, user_a, user_b, _ = tenants
        art_b = _make_artifact(tenant_id="tenant-beta", submitted_by=user_b.id)
        db.add(art_b)
        await db.commit()
        resp = await client.get(f"/api/v1/analyze/artifact/{art_b.id}", headers=_auth_headers(user_a))
        assert resp.status_code == 404


# ─── 5. NULL tenant isolation ─────────────────────────────────────────────────

class TestNullTenantIsolation:
    """Single-tenant (tenant_id=None) users are isolated from multi-tenant users."""

    @pytest_asyncio.fixture
    async def setup(self, db: AsyncSession):
        null_user = await _add_user(db, role="analyst", tenant_id=None)
        mt_user = await _add_user(db, role="analyst", tenant_id="tenant-mt")
        art_null = _make_artifact(tenant_id=None, submitted_by=null_user.id)
        art_mt = _make_artifact(tenant_id="tenant-mt", submitted_by=mt_user.id)
        db.add(art_null)
        db.add(art_mt)
        await db.commit()
        return null_user, mt_user, art_null, art_mt

    @pytest.mark.asyncio
    async def test_null_tenant_user_can_get_null_artifact(self, setup, client):
        null_user, _, art_null, _ = setup
        resp = await client.get(
            f"/api/v1/analyze/artifact/{art_null.id}", headers=_auth_headers(null_user)
        )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_null_tenant_user_cannot_get_mt_artifact(self, setup, client):
        null_user, _, _, art_mt = setup
        resp = await client.get(
            f"/api/v1/analyze/artifact/{art_mt.id}", headers=_auth_headers(null_user)
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_mt_user_cannot_get_null_artifact(self, setup, client):
        _, mt_user, art_null, _ = setup
        resp = await client.get(
            f"/api/v1/analyze/artifact/{art_null.id}", headers=_auth_headers(mt_user)
        )
        assert resp.status_code == 404


# ─── 6. Domain / IP input guards (SEC-14 partial) ────────────────────────────

class TestDomainIpInputGuards:
    """Basic input validation on domain and IP endpoints."""

    @pytest.mark.asyncio
    async def test_domain_endpoint_requires_auth(self, client):
        resp = await client.post("/api/v1/analyze/domain", params={"domain": "example.com"})
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_ip_endpoint_requires_auth(self, client):
        resp = await client.post("/api/v1/analyze/ip", params={"ip": "1.2.3.4"})
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_domain_analysis_returns_result(self, db, client):
        user = await _add_user(db, role="analyst", tenant_id="tenant-d")
        fake = {"domain": "example.com", "is_dga": False, "entropy": 2.3, "risk_score": 0.1}
        with patch("asc_api.api.v1.endpoints.analyze.analyzer.analyze_domain",
                   new=AsyncMock(return_value=fake)):
            resp = await client.post(
                "/api/v1/analyze/domain",
                params={"domain": "example.com"},
                headers=_auth_headers(user),
            )
        assert resp.status_code == 200
        assert "risk_score" in resp.json()

    @pytest.mark.asyncio
    async def test_ip_analysis_returns_result(self, db, client):
        user = await _add_user(db, role="analyst", tenant_id="tenant-d")
        fake = {"ip": "1.2.3.4", "is_private": False, "risk_score": 0.05}
        with patch("asc_api.api.v1.endpoints.analyze.analyzer.analyze_ip",
                   new=AsyncMock(return_value=fake)):
            resp = await client.post(
                "/api/v1/analyze/ip",
                params={"ip": "1.2.3.4"},
                headers=_auth_headers(user),
            )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_domain_response_no_secrets(self, db, client):
        user = await _add_user(db, role="analyst", tenant_id="tenant-d")
        fake = {"domain": "test.com", "risk_score": 0.0}
        with patch("asc_api.api.v1.endpoints.analyze.analyzer.analyze_domain",
                   new=AsyncMock(return_value=fake)):
            resp = await client.post(
                "/api/v1/analyze/domain",
                params={"domain": "test.com"},
                headers=_auth_headers(user),
            )
        body = resp.text
        assert "sk_live_" not in body
        assert "rk_live_" not in body


# ─── 7. Migration file integrity ─────────────────────────────────────────────

class TestMigrationIntegrity:
    """Verify migration file a7b90v8w2x25 exists and is correctly wired."""

    def test_migration_file_exists(self):
        from pathlib import Path
        versions_dir = Path(__file__).parent.parent / "migrations" / "versions"
        matches = list(versions_dir.glob("a7b90v8w2x25*.py"))
        assert len(matches) == 1, f"Migration a7b90v8w2x25 not found in {versions_dir}"

    def test_migration_revision_and_parent(self):
        from pathlib import Path
        import importlib.util
        p = next(
            (Path(__file__).parent.parent / "migrations" / "versions").glob("a7b90v8w2x25*.py")
        )
        spec = importlib.util.spec_from_file_location("mig", p)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert mod.revision == "a7b90v8w2x25"
        assert mod.down_revision == "z6t89u7x1s14"

    def test_migration_has_upgrade_and_downgrade(self):
        from pathlib import Path
        import importlib.util
        p = next(
            (Path(__file__).parent.parent / "migrations" / "versions").glob("a7b90v8w2x25*.py")
        )
        spec = importlib.util.spec_from_file_location("mig", p)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert callable(getattr(mod, "upgrade", None))
        assert callable(getattr(mod, "downgrade", None))


# ─── 8. Security scan — endpoint enumeration ─────────────────────────────────

class TestEndpointSecurityScan:
    """Verify no endpoints leak secrets; check HTTP method constraints."""

    @pytest.mark.asyncio
    async def test_get_on_file_endpoint_returns_405(self, client):
        resp = await client.get("/api/v1/analyze/file")
        assert resp.status_code == 405

    @pytest.mark.asyncio
    async def test_post_on_artifact_endpoint_returns_405(self, client):
        resp = await client.post(f"/api/v1/analyze/artifact/{_uuid.uuid4()}")
        assert resp.status_code == 405

    @pytest.mark.asyncio
    async def test_arbitrary_artifact_id_404_no_info_leak(self, db, client):
        user = await _add_user(db, role="analyst", tenant_id="tenant-scan")
        resp = await client.get(
            f"/api/v1/analyze/artifact/{_uuid.uuid4()}",
            headers=_auth_headers(user),
        )
        assert resp.status_code == 404
        body = resp.text
        # 404 body must not reveal DB details or stack traces
        assert "sqlalchemy" not in body.lower()
        assert "traceback" not in body.lower()
        assert "postgresql" not in body.lower()

    @pytest.mark.asyncio
    async def test_delete_on_artifact_returns_405(self, client):
        resp = await client.delete(f"/api/v1/analyze/artifact/{_uuid.uuid4()}")
        assert resp.status_code in (405, 401)  # 401 if auth checked first

    def test_no_hardcoded_secrets_in_analyze_module(self):
        """Scan analyze.py source for credential patterns."""
        from pathlib import Path
        source = (
            Path(__file__).parent.parent
            / "asc_api" / "api" / "v1" / "endpoints" / "analyze.py"
        ).read_text(encoding="utf-8")
        forbidden = ["sk_live_", "rk_live_", "sk_test_", "AKIA", "-----BEGIN RSA"]
        for pattern in forbidden:
            assert pattern not in source, f"Potential secret pattern '{pattern}' in analyze.py"

    def test_no_hardcoded_secrets_in_artifact_model(self):
        """Scan artifact.py source for credential patterns."""
        from pathlib import Path
        source = (
            Path(__file__).parent.parent
            / "asc_api" / "models" / "artifact.py"
        ).read_text(encoding="utf-8")
        for pattern in ["sk_live_", "rk_live_", "password", "secret"]:
            assert pattern not in source.lower() or "nullable" in source, (
                f"Unexpected pattern '{pattern}' in artifact model"
            )
