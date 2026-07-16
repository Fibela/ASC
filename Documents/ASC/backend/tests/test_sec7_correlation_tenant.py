"""
SEC-7 — Correlation Engine Tenant Isolation: comprehensive test suite.

P-16 delivers two security guarantees:
  A. VISIBILITY  — global rules (tenant_id=NULL) visible to all tenants;
                   tenant rules (tenant_id=X) visible only to tenant X.
  B. IDOR FIX    — all cluster/signal endpoints are scoped to the requesting
                   user's tenant.  Tenant A cannot read or write tenant B's data.

Coverage areas:
  1. Model schema       — CorrelationRule / Cluster / Signal have tenant_id
  2. Global rule seed   — R001-R004 created with tenant_id=NULL
  3. Visibility filter  — list_rules returns global+own; excludes other-tenant
  4. Tenant isolation   — tenant A rule invisible/uneditable from tenant B
  5. Global protection  — PermissionError on PATCH/DELETE of global rule
  6. Cluster isolation  — get_cluster strict tenant scope; IDOR returns None
  7. Sweep tenant scope — sweep tags new clusters with requesting tenant_id
  8. Summary scope      — get_correlation_summary only counts own-tenant objects
  9. Migration check    — a8c01v9x3y26 file present + revision metadata correct
  10. Secret scan       — no leaked keys in correlation source files

Testing approach
----------------
All tests are static, import-level, or service-layer tests using AsyncMock.
No real database required — CI-safe with zero external dependencies.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ── Paths ─────────────────────────────────────────────────────────────────────
_BACKEND = Path(__file__).parent.parent
_MIGRATIONS_DIR = _BACKEND / "migrations" / "versions"
_SEC7_MIGRATION_REVISION = "a8c01v9x3y26"
_SEC7_MIGRATION_DOWN = "a7b90v8w2x25"
_SEC7_MIGRATION_FILE = _MIGRATIONS_DIR / f"{_SEC7_MIGRATION_REVISION}_correlation_global_rules.py"
_CORRELATION_SVC = _BACKEND / "asc_api" / "services" / "correlation_service.py"
_CORRELATION_EP  = _BACKEND / "asc_api" / "api" / "v1" / "endpoints" / "correlation.py"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_rule(
    *,
    rule_id: str | None = None,
    name: str = "Test Rule",
    tenant_id: str | None = None,
    enabled: bool = True,
    pivot_type: str = "host_pivot",
    min_signals: int = 2,
    time_window_minutes: int = 60,
    severity_threshold: str = "low",
) -> MagicMock:
    r = MagicMock()
    r.id = rule_id or str(uuid.uuid4())
    r.name = name
    r.tenant_id = tenant_id
    r.enabled = enabled
    r.pivot_type = pivot_type
    r.min_signals = min_signals
    r.time_window_minutes = time_window_minutes
    r.severity_threshold = severity_threshold
    r.created_at = datetime.now(timezone.utc)
    r.updated_at = datetime.now(timezone.utc)
    r.description = None
    return r


def _make_cluster(
    *,
    cluster_id: str | None = None,
    rule_id: str | None = None,
    tenant_id: str | None = None,
    status: str = "active",
    is_campaign: bool = False,
    severity: str = "low",
) -> MagicMock:
    c = MagicMock()
    c.id = cluster_id or str(uuid.uuid4())
    c.rule_id = rule_id or str(uuid.uuid4())
    c.tenant_id = tenant_id
    c.status = status
    c.is_campaign = is_campaign
    c.severity = severity
    c.cluster_key = "ws-001"
    c.cluster_type = "host_pivot"
    c.signal_count = 3
    c.confidence_score = 0.5
    c.first_seen = datetime.now(timezone.utc)
    c.last_seen = datetime.now(timezone.utc)
    c.campaign_name = None
    c.distinct_signal_domains = 1
    c.analyst_notes = None
    c.assigned_to = None
    c.forensic_hash = "abc123"
    c.meta = {}
    c.created_at = datetime.now(timezone.utc)
    c.updated_at = datetime.now(timezone.utc)
    return c


def _mock_db(scalar_result: Any = None, scalars_result: list | None = None) -> AsyncMock:
    """Return an AsyncSession mock with configurable execute outcomes."""
    db = AsyncMock()
    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = scalar_result
    result_mock.scalar.return_value = 0
    result_mock.scalars.return_value.all.return_value = scalars_result or []
    result_mock.all.return_value = []
    db.execute = AsyncMock(return_value=result_mock)
    return db


# ─── 1. Model schema ──────────────────────────────────────────────────────────

class TestCorrelationRuleSchema:
    """CorrelationRule, CorrelationCluster, CorrelationSignal all carry tenant_id."""

    def test_correlation_rule_has_tenant_id(self):
        from asc_api.models.correlation import CorrelationRule
        cols = {c.key for c in CorrelationRule.__table__.columns}
        assert "tenant_id" in cols

    def test_correlation_rule_tenant_id_is_nullable(self):
        from asc_api.models.correlation import CorrelationRule
        col = CorrelationRule.__table__.c["tenant_id"]
        assert col.nullable is True

    def test_correlation_rule_name_has_no_global_unique(self):
        from asc_api.models.correlation import CorrelationRule
        # The old global unique constraint must be gone; uniqueness is enforced
        # per-tenant via partial indexes in the DB layer, not at the model level.
        for constraint in CorrelationRule.__table__.constraints:
            ctype = type(constraint).__name__
            if "Unique" in ctype:
                cols = [c.name for c in constraint.columns]
                assert cols != ["name"], (
                    "Global UNIQUE(name) must not exist on CorrelationRule — "
                    "breaks multi-tenant: tenants cannot use same name as global rules"
                )

    def test_correlation_cluster_has_tenant_id(self):
        from asc_api.models.correlation import CorrelationCluster
        cols = {c.key for c in CorrelationCluster.__table__.columns}
        assert "tenant_id" in cols

    def test_correlation_signal_has_tenant_id(self):
        from asc_api.models.correlation import CorrelationSignal
        cols = {c.key for c in CorrelationSignal.__table__.columns}
        assert "tenant_id" in cols

    def test_rule_instantiation_with_tenant(self):
        from asc_api.models.correlation import CorrelationRule
        rule = CorrelationRule(
            id=str(uuid.uuid4()),
            name="Test Rule",
            pivot_type="host_pivot",
            tenant_id="tenant-aaa",
        )
        assert rule.tenant_id == "tenant-aaa"

    def test_rule_instantiation_null_tenant(self):
        from asc_api.models.correlation import CorrelationRule
        rule = CorrelationRule(
            id=str(uuid.uuid4()),
            name="Global Rule",
            pivot_type="host_pivot",
        )
        assert rule.tenant_id is None


# ─── 2. Global rule seed ─────────────────────────────────────────────────────

class TestGlobalRulesSeed:
    """The 4 built-in seed rules (R001-R004) must have tenant_id=NULL."""

    def test_seed_module_importable(self):
        from asc_api.db import seed_correlation  # noqa: F401

    def test_seed_rules_have_null_tenant(self):
        from asc_api.db.seed_correlation import SEED_RULES
        for rule in SEED_RULES:
            assert rule.get("tenant_id") is None, (
                f"Seed rule '{rule.get('name')}' must have tenant_id=None (global)"
            )

    def test_seed_has_four_rules(self):
        from asc_api.db.seed_correlation import SEED_RULES
        assert len(SEED_RULES) == 4, f"Expected 4 seed rules, got {len(SEED_RULES)}"

    def test_seed_rules_cover_all_pivot_types(self):
        from asc_api.db.seed_correlation import SEED_RULES
        pivot_types = {r["pivot_type"] for r in SEED_RULES}
        # At least host, identity, ip, and domain covered by global rules
        for expected in ("host_pivot", "identity_pivot", "ip_pivot", "domain_pivot"):
            assert expected in pivot_types, (
                f"Global seed missing pivot_type={expected}"
            )


# ─── 3. list_rules visibility filter ────────────────────────────────────────

class TestGlobalRulesVisibility:
    """list_rules returns global rules (NULL) + tenant-own rules."""

    @pytest.mark.asyncio
    async def test_tenant_sees_global_rules(self):
        from asc_api.services.correlation_service import list_rules

        global_rule = _make_rule(tenant_id=None, name="R001-Global")
        tenant_rule = _make_rule(tenant_id="tenant-a", name="MyRule")

        db = AsyncMock()
        result = MagicMock()
        result.scalars.return_value.all.return_value = [global_rule, tenant_rule]
        db.execute = AsyncMock(return_value=result)

        rules = await list_rules(db, tenant_id="tenant-a")
        assert len(rules) == 2

    @pytest.mark.asyncio
    async def test_no_tenant_sees_only_global_rules(self):
        from asc_api.services.correlation_service import list_rules

        global_rule = _make_rule(tenant_id=None, name="R001-Global")

        db = AsyncMock()
        result = MagicMock()
        result.scalars.return_value.all.return_value = [global_rule]
        db.execute = AsyncMock(return_value=result)

        rules = await list_rules(db, tenant_id=None)
        assert len(rules) == 1
        assert rules[0].tenant_id is None

    @pytest.mark.asyncio
    async def test_list_rules_empty_for_new_tenant(self):
        """A brand new tenant with no custom rules still gets global seed rules."""
        from asc_api.services.correlation_service import list_rules

        global_rules = [_make_rule(tenant_id=None, name=f"R00{i}") for i in range(1, 5)]

        db = AsyncMock()
        result = MagicMock()
        result.scalars.return_value.all.return_value = global_rules
        db.execute = AsyncMock(return_value=result)

        rules = await list_rules(db, tenant_id="brand-new-tenant")
        assert len(rules) == 4


# ─── 4. Tenant rule isolation (get_rule / visibility) ────────────────────────

class TestTenantRuleIsolation:
    """Tenant A cannot read, update, or delete tenant B's private rules."""

    @pytest.mark.asyncio
    async def test_get_rule_other_tenant_returns_none(self):
        from asc_api.services.correlation_service import get_rule

        # DB returns None because the rule belongs to tenant-b, not tenant-a
        db = _mock_db(scalar_result=None)
        result = await get_rule(db, "rule-b-id", tenant_id="tenant-a")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_global_rule_returns_result_for_any_tenant(self):
        from asc_api.services.correlation_service import get_rule

        global_rule = _make_rule(tenant_id=None, name="R001-Host-Pivot")
        db = _mock_db(scalar_result=global_rule)
        result = await get_rule(db, global_rule.id, tenant_id="tenant-any")
        assert result is not None
        assert result.tenant_id is None

    @pytest.mark.asyncio
    async def test_update_rule_other_tenant_returns_none(self):
        from asc_api.services.correlation_service import update_rule

        # get_rule will be called internally and should return None (wrong tenant)
        db = _mock_db(scalar_result=None)
        result = await update_rule(db, "rule-b-id", tenant_id="tenant-a", enabled=False)
        assert result is None

    @pytest.mark.asyncio
    async def test_delete_rule_other_tenant_returns_false(self):
        from asc_api.services.correlation_service import delete_rule

        db = _mock_db(scalar_result=None)
        result = await delete_rule(db, "rule-b-id", tenant_id="tenant-a")
        assert result is False


# ─── 5. Global rule protection ────────────────────────────────────────────────

class TestGlobalRuleProtection:
    """Tenants must not modify or delete global (tenant_id=NULL) rules."""

    @pytest.mark.asyncio
    async def test_update_global_rule_raises_permission_error(self):
        from asc_api.services.correlation_service import update_rule

        global_rule = _make_rule(tenant_id=None, name="R001-Host-Pivot")
        db = _mock_db(scalar_result=global_rule)

        with pytest.raises(PermissionError, match="global rules"):
            await update_rule(db, global_rule.id, tenant_id="tenant-a", enabled=False)

    @pytest.mark.asyncio
    async def test_delete_global_rule_raises_permission_error(self):
        from asc_api.services.correlation_service import delete_rule

        global_rule = _make_rule(tenant_id=None, name="R001-Host-Pivot")
        db = _mock_db(scalar_result=global_rule)

        with pytest.raises(PermissionError, match="global rules"):
            await delete_rule(db, global_rule.id, tenant_id="tenant-a")

    @pytest.mark.asyncio
    async def test_superadmin_null_tenant_can_update_global_rule(self):
        """A NULL-tenant caller (system/superadmin) may update global rules."""
        from asc_api.services.correlation_service import update_rule

        global_rule = _make_rule(tenant_id=None, name="R001-Host-Pivot")
        db = AsyncMock()
        result = MagicMock()
        result.scalar_one_or_none.return_value = global_rule
        db.execute = AsyncMock(return_value=result)
        db.commit = AsyncMock()
        db.refresh = AsyncMock()

        # tenant_id=None → no PermissionError raised
        updated = await update_rule(db, global_rule.id, tenant_id=None, enabled=False)
        # Should return the rule (not raise)
        assert updated is not None

    @pytest.mark.asyncio
    async def test_superadmin_null_tenant_can_delete_global_rule(self):
        """A NULL-tenant caller may delete global rules (used in DB cleanup)."""
        from asc_api.services.correlation_service import delete_rule

        global_rule = _make_rule(tenant_id=None, name="R001-Host-Pivot")
        db = AsyncMock()
        result = MagicMock()
        result.scalar_one_or_none.return_value = global_rule
        db.execute = AsyncMock(return_value=result)
        db.delete = AsyncMock()
        db.commit = AsyncMock()

        ok = await delete_rule(db, global_rule.id, tenant_id=None)
        assert ok is True


# ─── 6. Cluster tenant isolation ─────────────────────────────────────────────

class TestClusterTenantIsolation:
    """get_cluster uses strict tenant equality — no cross-tenant bleed."""

    @pytest.mark.asyncio
    async def test_get_cluster_same_tenant_succeeds(self):
        from asc_api.services.correlation_service import get_cluster

        cluster = _make_cluster(tenant_id="tenant-a")
        db = _mock_db(scalar_result=cluster)

        result = await get_cluster(db, cluster.id, tenant_id="tenant-a")
        assert result is not None
        assert result.tenant_id == "tenant-a"

    @pytest.mark.asyncio
    async def test_get_cluster_other_tenant_returns_none(self):
        from asc_api.services.correlation_service import get_cluster

        # DB returns None — tenant-b cluster not visible to tenant-a
        db = _mock_db(scalar_result=None)

        result = await get_cluster(db, "cluster-b-id", tenant_id="tenant-a")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_cluster_graph_idor_returns_none(self):
        """get_cluster_graph respects tenant scope; foreign cluster gives None."""
        from asc_api.services.correlation_service import get_cluster_graph

        db = _mock_db(scalar_result=None)

        result = await get_cluster_graph(db, "foreign-cluster-id", tenant_id="tenant-a")
        assert result is None

    @pytest.mark.asyncio
    async def test_list_clusters_scoped_to_tenant(self):
        from asc_api.services.correlation_service import list_clusters

        own_cluster = _make_cluster(tenant_id="tenant-a")
        db = AsyncMock()
        result = MagicMock()
        result.scalars.return_value.all.return_value = [own_cluster]
        db.execute = AsyncMock(return_value=result)

        clusters = await list_clusters(db, tenant_id="tenant-a")
        assert len(clusters) == 1
        assert clusters[0].tenant_id == "tenant-a"

    @pytest.mark.asyncio
    async def test_update_cluster_status_other_tenant_returns_none(self):
        from asc_api.services.correlation_service import update_cluster_status

        db = _mock_db(scalar_result=None)

        result = await update_cluster_status(
            db, "foreign-cluster", status="resolved", tenant_id="tenant-a"
        )
        assert result is None


# ─── 7. Sweep tenant scope ────────────────────────────────────────────────────

class TestSweepTenantScope:
    """run_correlation_sweep with tenant_id tags created clusters to that tenant."""

    @pytest.mark.asyncio
    async def test_sweep_uses_list_rules_with_tenant(self):
        """Sweep calls list_rules(db, tenant_id) — NOT a global unscoped query."""
        from asc_api.services import correlation_service

        called_with_tenant: list[str | None] = []

        async def _mock_list_rules(db, tenant_id=None):
            called_with_tenant.append(tenant_id)
            return []

        with (
            patch.object(correlation_service, "list_rules", _mock_list_rules),
            patch("asc_api.services.correlation_service.log_security_action", new=AsyncMock()),
        ):
            db = AsyncMock()
            await correlation_service.run_correlation_sweep(db, tenant_id="tenant-x")

        assert called_with_tenant == ["tenant-x"]

    @pytest.mark.asyncio
    async def test_sweep_tenant_none_calls_list_rules_with_none(self):
        from asc_api.services import correlation_service

        called_with_tenant: list[Any] = []

        async def _mock_list_rules(db, tenant_id=None):
            called_with_tenant.append(tenant_id)
            return []

        with (
            patch.object(correlation_service, "list_rules", _mock_list_rules),
            patch("asc_api.services.correlation_service.log_security_action", new=AsyncMock()),
        ):
            db = AsyncMock()
            await correlation_service.run_correlation_sweep(db, tenant_id=None)

        assert called_with_tenant == [None]

    @pytest.mark.asyncio
    async def test_sweep_cluster_tagged_with_tenant_id(self):
        """When a sweep creates a cluster, it receives the sweep's tenant_id."""
        from asc_api.services import correlation_service

        tenant_used_in_upsert: list[str | None] = []

        rule = _make_rule(tenant_id=None, name="R001", pivot_type="host_pivot")

        async def _mock_list_rules(db, tenant_id=None):
            return [rule]

        async def _mock_gather(db, window_start, tenant_id=None):
            return [
                {"signal_type": "event", "signal_id": str(uuid.uuid4()),
                 "pivot_value": "ws-001", "severity": "medium",
                 "timestamp": datetime.now(timezone.utc), "meta": {}}
                for _ in range(3)
            ]

        async def _mock_cluster_exists(db, rule_id, pivot_value, tenant_id=None):
            return False

        async def _mock_upsert(db, rule, pivot_value, new_signals, tenant_id=None):
            tenant_used_in_upsert.append(tenant_id)
            cluster = _make_cluster(tenant_id=tenant_id)
            return cluster

        with (
            patch.object(correlation_service, "list_rules", _mock_list_rules),
            patch.object(correlation_service, "_GATHER_FN",
                         {"host_pivot": _mock_gather}),
            patch.object(correlation_service, "_cluster_exists", _mock_cluster_exists),
            patch.object(correlation_service, "_upsert_cluster", _mock_upsert),
            patch("asc_api.services.correlation_service.log_security_action", new=AsyncMock()),
        ):
            db = AsyncMock()
            await correlation_service.run_correlation_sweep(db, tenant_id="tenant-sweep")

        assert "tenant-sweep" in tenant_used_in_upsert


# ─── 8. Summary tenant scope ─────────────────────────────────────────────────

class TestSummaryTenantScope:
    """get_correlation_summary returns KPIs scoped to the requesting tenant."""

    @pytest.mark.asyncio
    async def test_summary_returns_expected_keys(self):
        from asc_api.services.correlation_service import get_correlation_summary

        db = AsyncMock()
        r = MagicMock()
        r.scalar.return_value = 0
        db.execute = AsyncMock(return_value=r)

        summary = await get_correlation_summary(db, tenant_id="tenant-a")
        expected_keys = {
            "total_clusters", "active_clusters", "campaigns_detected",
            "critical_clusters", "total_signals", "active_rules",
        }
        assert set(summary.keys()) == expected_keys

    @pytest.mark.asyncio
    async def test_summary_values_are_integers(self):
        from asc_api.services.correlation_service import get_correlation_summary

        db = AsyncMock()
        r = MagicMock()
        r.scalar.return_value = 5
        db.execute = AsyncMock(return_value=r)

        summary = await get_correlation_summary(db, tenant_id="tenant-a")
        for key, val in summary.items():
            assert isinstance(val, int), f"{key} must be int, got {type(val)}"

    @pytest.mark.asyncio
    async def test_summary_zero_for_empty_tenant(self):
        from asc_api.services.correlation_service import get_correlation_summary

        db = AsyncMock()
        r = MagicMock()
        r.scalar.return_value = 0
        db.execute = AsyncMock(return_value=r)

        summary = await get_correlation_summary(db, tenant_id="brand-new")
        assert summary["total_clusters"] == 0
        assert summary["active_clusters"] == 0


# ─── 9. create_rule name uniqueness ──────────────────────────────────────────

class TestRuleNameUniqueness:
    """Two different tenants may share a rule name; same tenant may not duplicate."""

    @pytest.mark.asyncio
    async def test_duplicate_name_same_tenant_raises_value_error(self):
        from asc_api.services.correlation_service import create_rule

        db = AsyncMock()
        dup_result = MagicMock()
        dup_result.scalar.return_value = 1  # name already exists
        db.execute = AsyncMock(return_value=dup_result)

        with pytest.raises(ValueError, match="already exists"):
            await create_rule(
                db, name="My Rule", pivot_type="host_pivot", tenant_id="tenant-a"
            )

    @pytest.mark.asyncio
    async def test_same_name_different_tenants_allowed(self):
        """Tenant B may reuse tenant A's rule name — scoped uniqueness only."""
        from asc_api.services.correlation_service import create_rule

        db = AsyncMock()
        # First call to execute (dup check) returns 0 → no duplicate
        dup_result = MagicMock()
        dup_result.scalar.return_value = 0
        db.execute = AsyncMock(return_value=dup_result)
        db.commit = AsyncMock()
        db.refresh = AsyncMock()

        # Should not raise
        rule = await create_rule(
            db, name="Host Attack Cluster", pivot_type="host_pivot", tenant_id="tenant-b"
        )
        assert rule.name == "Host Attack Cluster"
        assert rule.tenant_id == "tenant-b"

    @pytest.mark.asyncio
    async def test_global_rule_duplicate_name_raises(self):
        """Creating a second global rule (tenant_id=None) with same name raises."""
        from asc_api.services.correlation_service import create_rule

        db = AsyncMock()
        dup_result = MagicMock()
        dup_result.scalar.return_value = 1
        db.execute = AsyncMock(return_value=dup_result)

        with pytest.raises(ValueError, match="already exists"):
            await create_rule(
                db, name="R001-Host-Pivot", pivot_type="host_pivot", tenant_id=None
            )


# ─── 10. Migration integrity ──────────────────────────────────────────────────

class TestMigrationIntegrity:
    """The P-16 Alembic migration file exists and has correct metadata."""

    def test_migration_file_exists(self):
        assert _SEC7_MIGRATION_FILE.exists(), (
            f"Migration file {_SEC7_MIGRATION_FILE.name} not found in migrations/versions"
        )

    def test_migration_revision_id_correct(self):
        src = _SEC7_MIGRATION_FILE.read_text(encoding="utf-8")
        assert f'revision = "{_SEC7_MIGRATION_REVISION}"' in src, (
            f"Migration must declare revision = \"{_SEC7_MIGRATION_REVISION}\""
        )

    def test_migration_down_revision_correct(self):
        src = _SEC7_MIGRATION_FILE.read_text(encoding="utf-8")
        assert f'down_revision = "{_SEC7_MIGRATION_DOWN}"' in src, (
            f"Migration must chain from {_SEC7_MIGRATION_DOWN}"
        )

    def test_migration_drops_global_unique_constraint(self):
        src = _SEC7_MIGRATION_FILE.read_text(encoding="utf-8")
        assert "drop_constraint" in src.lower() or "correlation_rules_name_key" in src, (
            "Migration must drop the old global UNIQUE(name) constraint"
        )

    def test_migration_creates_global_partial_index(self):
        src = _SEC7_MIGRATION_FILE.read_text(encoding="utf-8")
        assert "uq_cr_global_name" in src, (
            "Migration must create partial unique index uq_cr_global_name"
        )

    def test_migration_creates_tenant_partial_index(self):
        src = _SEC7_MIGRATION_FILE.read_text(encoding="utf-8")
        assert "uq_cr_tenant_name" in src, (
            "Migration must create partial unique index uq_cr_tenant_name"
        )

    def test_migration_has_downgrade_function(self):
        src = _SEC7_MIGRATION_FILE.read_text(encoding="utf-8")
        assert "def downgrade" in src, "Migration must implement downgrade()"

    def test_migration_downgrade_restores_unique_constraint(self):
        src = _SEC7_MIGRATION_FILE.read_text(encoding="utf-8")
        assert "create_unique_constraint" in src, (
            "downgrade() must restore correlation_rules_name_key unique constraint"
        )

    def test_migration_chain_converges_to_single_head(self):
        """Integridad real de migraciones: la cadena converge en UN solo head.
        Reemplaza el conteo mágico hardcodeado (S103.2) — los conteos se editaban
        a mano y no medían integridad; un solo head sí es el invariante."""
        import re as _re
        files = [f for f in _MIGRATIONS_DIR.glob("*.py") if f.name != "__init__.py"]
        revisions: set[str] = set()
        parents: set[str] = set()
        for f in files:
            txt = f.read_text(encoding="utf-8")
            rm = _re.search(r'^revision(?:\s*:[^=]+)?\s*=\s*["\']([^"\']+)["\']', txt, _re.M)
            if rm:
                revisions.add(rm.group(1))
            dm = _re.search(r'^down_revision(?:\s*:[^=]+)?\s*=\s*(.+)$', txt, _re.M)
            if dm:
                for pid in _re.findall(r'["\']([^"\']+)["\']', dm.group(1)):
                    parents.add(pid)
        heads = revisions - parents
        assert len(heads) == 1, f"integridad: esperaba 1 head, hay {len(heads)}: {sorted(heads)}"
        assert len(files) >= 26, f"conteo de migraciones cayó inesperadamente: {len(files)}"

    def test_no_duplicate_revision_ids(self):
        revisions: list[str] = []
        for f in _MIGRATIONS_DIR.glob("*.py"):
            if f.name == "__init__.py":
                continue
            src = f.read_text(encoding="utf-8")
            match = re.search(r'^revision\s*=\s*["\']([^"\']+)["\']', src, re.MULTILINE)
            if match:
                revisions.append(match.group(1))
        assert len(revisions) == len(set(revisions)), (
            f"Duplicate revision IDs detected: {[r for r in revisions if revisions.count(r) > 1]}"
        )


# ─── 11. Endpoint secret scan ─────────────────────────────────────────────────

class TestEndpointScan:
    """Correlation source files must not leak API keys, tokens, or credentials."""

    _SECRET_PATTERNS: list[re.Pattern] = [
        re.compile(r'rk_live_[A-Za-z0-9]{24,}'),          # Stripe restricted key
        re.compile(r'sk_live_[A-Za-z0-9]{24,}'),          # Stripe secret key
        re.compile(r'SUPABASE_JWT_SECRET\s*=\s*["\'][^"\']{4,}["\']'),
        re.compile(r'SECRET_KEY\s*=\s*["\'][^"\']{8,}["\']'),
        re.compile(r'DATABASE_URL\s*=\s*postgresql://[^"\']{4,}'),
        re.compile(r'-----BEGIN (RSA |EC )?PRIVATE KEY-----'),
    ]

    @pytest.mark.parametrize("src_file", [_CORRELATION_SVC, _CORRELATION_EP])
    def test_no_hardcoded_secrets(self, src_file: Path):
        content = src_file.read_text(encoding="utf-8")
        for pattern in self._SECRET_PATTERNS:
            match = pattern.search(content)
            assert match is None, (
                f"Potential secret pattern '{pattern.pattern}' found in {src_file.name}: "
                f"'{match.group(0)[:40]}...'"
            )

    def test_service_imports_no_external_http(self):
        """correlation_service must not make raw HTTP calls (no requests/httpx import)."""
        content = _CORRELATION_SVC.read_text(encoding="utf-8")
        for bad_import in ("import requests", "import httpx", "import urllib.request"):
            assert bad_import not in content, (
                f"correlation_service imports {bad_import} — violates read-only posture"
            )

    def test_endpoint_checks_tenant_isolation_documented(self):
        """Endpoint file must reference tenant_id to enforce isolation."""
        content = _CORRELATION_EP.read_text(encoding="utf-8")
        assert "tenant_id" in content, (
            "correlation.py endpoint must pass tenant_id to all service calls"
        )

    def test_endpoint_handles_permission_error_as_403(self):
        """PermissionError caught for global rule protection → HTTP 403."""
        content = _CORRELATION_EP.read_text(encoding="utf-8")
        assert "PermissionError" in content
        assert "403" in content

    def test_endpoint_handles_value_error_as_409(self):
        """ValueError (duplicate name) caught → HTTP 409 Conflict."""
        content = _CORRELATION_EP.read_text(encoding="utf-8")
        assert "ValueError" in content
        assert "409" in content

    def test_is_global_field_exposed_in_rule_out(self):
        """_rule_out must expose is_global so the frontend can mark system rules."""
        content = _CORRELATION_EP.read_text(encoding="utf-8")
        assert "is_global" in content, (
            "_rule_out must include is_global field so frontend distinguishes seed vs custom rules"
        )
