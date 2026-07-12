"""
FASE 4.2 — Correlation Engine Integration Tests (P27).

Replaces the AsyncMock-based DB tests from test_p27.py with real SQLite
in-memory tests.  All DB queries hit the real SQLAlchemy + SQLite stack.

Suite breakdown:
  TestCorrelationRulesCRUDDB     (8)  — create / get / update / delete rules,
                                        dup-name guard, global-rule tenant guard
  TestUpsertClusterDB            (6)  — new cluster, signal update, campaign
                                        detection, dedup, confidence, forensic hash
  TestClusterStatusUpdateDB      (4)  — resolve, analyst_notes, assigned_to,
                                        unknown cluster
  TestGetClusterSignalsDB        (3)  — signals returned, timestamp order, empty
  TestClusterGraphDB             (4)  — nodes + edges, 404, campaign name
  TestListClustersDB             (5)  — list all, filter status, filter campaign,
                                        limit / offset
  TestCorrelationSummaryDB       (6)  — all keys, zeros, active/campaign/critical counts
  TestRunCorrelationSweepDB      (5)  — stats dict keys, no-rules zero, host sweep
                                        creates cluster, dedup within run, signals_added
  TestCorrelationRestEndpointsDB (10) — 401 anon, list rules, create, dup-409,
                                        get/404, patch, delete admin/analyst, sweep inline

Total: 51 tests
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta
from typing import Any

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.core.security import create_access_token
from asc_api.models.correlation import (
    CorrelationCluster,
    CorrelationRule,
    CorrelationSignal,
)
from asc_api.models.event import Event
from asc_api.models.user import User


# ── Helpers ────────────────────────────────────────────────────────────────────

def _auth(user: User) -> dict:
    return {"Authorization": f"Bearer {create_access_token(user.id)}"}


_NOW = datetime.now(timezone.utc)


async def _make_rule(
    db: AsyncSession,
    *,
    name: str | None = None,
    pivot_type: str = "host_pivot",
    min_signals: int = 2,
    time_window_minutes: int = 60,
    severity_threshold: str = "low",
    enabled: bool = True,
    tenant_id: str | None = None,
) -> CorrelationRule:
    from asc_api.services.correlation_service import create_rule
    return await create_rule(
        db,
        name=name or f"Rule-{uuid.uuid4().hex[:8]}",
        pivot_type=pivot_type,
        min_signals=min_signals,
        time_window_minutes=time_window_minutes,
        severity_threshold=severity_threshold,
        tenant_id=tenant_id,
    )


async def _make_cluster(
    db: AsyncSession,
    rule: CorrelationRule,
    *,
    cluster_key: str = "ws-001",
    status: str = "active",
    is_campaign: bool = False,
    severity: str = "medium",
    signal_count: int = 2,
    tenant_id: str | None = None,
) -> CorrelationCluster:
    c = CorrelationCluster(
        id=str(uuid.uuid4()),
        rule_id=rule.id,
        cluster_key=cluster_key,
        cluster_type=rule.pivot_type,
        tenant_id=tenant_id,
        status=status,
        is_campaign=is_campaign,
        severity=severity,
        signal_count=signal_count,
        confidence_score=0.5,
        first_seen=_NOW,
        last_seen=_NOW,
        meta={},
    )
    c.forensic_hash = c.compute_forensic_hash()
    db.add(c)
    await db.commit()
    await db.refresh(c)
    return c


async def _make_signal(
    db: AsyncSession,
    cluster: CorrelationCluster,
    *,
    signal_type: str = "event",
    signal_id: str | None = None,
    pivot_value: str = "ws-001",
    severity: str = "medium",
    ts: datetime | None = None,
) -> CorrelationSignal:
    s = CorrelationSignal(
        id=str(uuid.uuid4()),
        cluster_id=cluster.id,
        tenant_id=cluster.tenant_id,
        signal_type=signal_type,
        signal_id=signal_id or str(uuid.uuid4()),
        pivot_value=pivot_value,
        severity=severity,
        timestamp=ts or _NOW,
        meta={},
    )
    db.add(s)
    await db.commit()
    await db.refresh(s)
    return s


def _raw_signals(
    pivot_value: str,
    count: int = 2,
    *,
    signal_types: list[str] | None = None,
) -> list[dict[str, Any]]:
    types = signal_types or ["event"] * count
    if len(types) < count:
        types = types + ["alert"] * (count - len(types))
    return [
        {
            "signal_type": types[i],
            "signal_id": str(uuid.uuid4()),
            "pivot_value": pivot_value,
            "severity": "high",
            "timestamp": _NOW,
            "meta": {},
        }
        for i in range(count)
    ]


# ── TestCorrelationRulesCRUDDB ─────────────────────────────────────────────────

class TestCorrelationRulesCRUDDB:
    """Real-DB CRUD tests for CorrelationRule via correlation_service."""

    @pytest.mark.asyncio
    async def test_create_rule_persists(self, db: AsyncSession):
        from asc_api.services.correlation_service import create_rule, get_rule
        rule = await create_rule(db, name="Host Pivot Rule", pivot_type="host_pivot")
        assert rule.id is not None
        fetched = await get_rule(db, rule.id)
        assert fetched is not None
        assert fetched.name == "Host Pivot Rule"
        assert fetched.pivot_type == "host_pivot"
        assert fetched.enabled is True

    @pytest.mark.asyncio
    async def test_create_rule_duplicate_name_raises(self, db: AsyncSession):
        from asc_api.services.correlation_service import create_rule
        await create_rule(db, name="Dup Rule", pivot_type="ip_pivot")
        with pytest.raises(ValueError, match="already exists"):
            await create_rule(db, name="Dup Rule", pivot_type="host_pivot")

    @pytest.mark.asyncio
    async def test_get_rule_returns_correct(self, db: AsyncSession):
        from asc_api.services.correlation_service import create_rule, get_rule
        r = await create_rule(db, name="TTP Pivot", pivot_type="ttp_pivot", min_signals=3)
        fetched = await get_rule(db, r.id)
        assert fetched.min_signals == 3
        assert fetched.pivot_type == "ttp_pivot"

    @pytest.mark.asyncio
    async def test_get_rule_unknown_returns_none(self, db: AsyncSession):
        from asc_api.services.correlation_service import get_rule
        result = await get_rule(db, str(uuid.uuid4()))
        assert result is None

    @pytest.mark.asyncio
    async def test_update_rule_fields(self, db: AsyncSession):
        from asc_api.services.correlation_service import update_rule
        rule = await _make_rule(db, min_signals=2)
        updated = await update_rule(db, rule.id, min_signals=5, enabled=False)
        assert updated.min_signals == 5
        assert updated.enabled is False

    @pytest.mark.asyncio
    async def test_update_global_rule_by_tenant_raises_permission_error(self, db: AsyncSession):
        from asc_api.services.correlation_service import update_rule
        global_rule = await _make_rule(db, tenant_id=None)
        with pytest.raises(PermissionError, match="global"):
            await update_rule(db, global_rule.id, tenant_id="some-tenant", enabled=False)

    @pytest.mark.asyncio
    async def test_delete_rule_removes_it(self, db: AsyncSession):
        from asc_api.services.correlation_service import delete_rule, get_rule
        rule = await _make_rule(db)
        ok = await delete_rule(db, rule.id)
        assert ok is True
        assert await get_rule(db, rule.id) is None

    @pytest.mark.asyncio
    async def test_delete_global_rule_by_tenant_raises_permission_error(self, db: AsyncSession):
        from asc_api.services.correlation_service import delete_rule
        global_rule = await _make_rule(db, tenant_id=None)
        with pytest.raises(PermissionError, match="global"):
            await delete_rule(db, global_rule.id, tenant_id="some-tenant")


# ── TestUpsertClusterDB ────────────────────────────────────────────────────────

class TestUpsertClusterDB:
    """Real-DB tests for _upsert_cluster internals."""

    @pytest.mark.asyncio
    async def test_creates_new_cluster_persisted(self, db: AsyncSession):
        from asc_api.services.correlation_service import _upsert_cluster, get_cluster
        rule = await _make_rule(db)
        signals = _raw_signals("ws-corp-01", 2)
        cluster = await _upsert_cluster(db, rule, "ws-corp-01", signals)
        await db.commit()

        from_db = await get_cluster(db, cluster.id)
        assert from_db is not None
        assert from_db.cluster_key == "ws-corp-01"
        assert from_db.signal_count == 2
        assert from_db.status == "active"

    @pytest.mark.asyncio
    async def test_updates_existing_cluster_with_new_signals(self, db: AsyncSession):
        from asc_api.services.correlation_service import _upsert_cluster, get_cluster
        rule = await _make_rule(db)
        first_signals = _raw_signals("ws-corp-02", 2)
        cluster = await _upsert_cluster(db, rule, "ws-corp-02", first_signals)
        await db.commit()
        initial_count = cluster.signal_count

        # Add 2 more signals (different signal_ids, will not duplicate)
        more_signals = _raw_signals("ws-corp-02", 2)
        cluster2 = await _upsert_cluster(db, rule, "ws-corp-02", more_signals)
        await db.commit()

        assert cluster2.id == cluster.id
        assert cluster2.signal_count == initial_count + 2

    @pytest.mark.asyncio
    async def test_campaign_detected_when_3_signal_domains(self, db: AsyncSession):
        from asc_api.services.correlation_service import _upsert_cluster
        rule = await _make_rule(db, min_signals=3)
        # 3 distinct signal_types → is_campaign=True
        signals = _raw_signals(
            "ws-corp-03", 3,
            signal_types=["event", "identity_action", "panl_action"],
        )
        cluster = await _upsert_cluster(db, rule, "ws-corp-03", signals)
        await db.commit()
        assert cluster.is_campaign is True
        assert cluster.campaign_name is not None

    @pytest.mark.asyncio
    async def test_deduplicates_signals_same_key(self, db: AsyncSession):
        from asc_api.services.correlation_service import _upsert_cluster
        rule = await _make_rule(db)
        sig_id = str(uuid.uuid4())
        # Two entries with the same (signal_type, signal_id) — duplicates
        dup_signals = [
            {"signal_type": "event", "signal_id": sig_id, "pivot_value": "ws-004",
             "severity": "high", "timestamp": _NOW, "meta": {}},
            {"signal_type": "event", "signal_id": sig_id, "pivot_value": "ws-004",
             "severity": "high", "timestamp": _NOW, "meta": {}},
            # One unique extra to meet min_signals=2
            {"signal_type": "alert", "signal_id": str(uuid.uuid4()), "pivot_value": "ws-004",
             "severity": "medium", "timestamp": _NOW, "meta": {}},
        ]
        cluster = await _upsert_cluster(db, rule, "ws-004", dup_signals)
        await db.commit()
        # signal_count should be 2 (deduped: event+alert), not 3
        assert cluster.signal_count == 2

    @pytest.mark.asyncio
    async def test_confidence_score_increases_with_signal_count(self, db: AsyncSession):
        from asc_api.services.correlation_service import _upsert_cluster
        rule = await _make_rule(db, min_signals=2)
        # min_signals * 3 = 6 signals needed for score=1.0
        signals_low = _raw_signals("ws-005", 2)
        c1 = await _upsert_cluster(db, rule, "ws-005", signals_low)
        await db.commit()
        score_low = c1.confidence_score

        more_signals = _raw_signals("ws-005", 4)
        c2 = await _upsert_cluster(db, rule, "ws-005", more_signals)
        await db.commit()
        assert c2.confidence_score >= score_low

    @pytest.mark.asyncio
    async def test_forensic_hash_present_and_non_empty(self, db: AsyncSession):
        from asc_api.services.correlation_service import _upsert_cluster
        rule = await _make_rule(db)
        signals = _raw_signals("ws-006", 2)
        cluster = await _upsert_cluster(db, rule, "ws-006", signals)
        await db.commit()
        assert cluster.forensic_hash is not None
        assert len(cluster.forensic_hash) == 128  # SHA3-512 hex


# ── TestClusterStatusUpdateDB ──────────────────────────────────────────────────

class TestClusterStatusUpdateDB:
    """Real-DB tests for update_cluster_status."""

    @pytest.mark.asyncio
    async def test_update_status_to_resolved(self, db: AsyncSession):
        from asc_api.services.correlation_service import update_cluster_status
        rule = await _make_rule(db)
        cluster = await _make_cluster(db, rule)
        updated = await update_cluster_status(db, cluster.id, status="resolved")
        assert updated is not None
        assert updated.status == "resolved"

    @pytest.mark.asyncio
    async def test_update_saves_analyst_notes(self, db: AsyncSession):
        from asc_api.services.correlation_service import update_cluster_status
        rule = await _make_rule(db)
        cluster = await _make_cluster(db, rule)
        notes = "Confirmed lateral movement — contained"
        updated = await update_cluster_status(db, cluster.id, status="active", analyst_notes=notes)
        assert updated.analyst_notes == notes

    @pytest.mark.asyncio
    async def test_update_saves_assigned_to(self, db: AsyncSession):
        from asc_api.services.correlation_service import update_cluster_status
        rule = await _make_rule(db)
        cluster = await _make_cluster(db, rule)
        updated = await update_cluster_status(
            db, cluster.id, status="active", assigned_to="analyst@premoscorp.com"
        )
        assert updated.assigned_to == "analyst@premoscorp.com"

    @pytest.mark.asyncio
    async def test_update_unknown_cluster_returns_none(self, db: AsyncSession):
        from asc_api.services.correlation_service import update_cluster_status
        result = await update_cluster_status(db, str(uuid.uuid4()), status="resolved")
        assert result is None


# ── TestGetClusterSignalsDB ────────────────────────────────────────────────────

class TestGetClusterSignalsDB:
    """Real-DB tests for get_cluster_signals."""

    @pytest.mark.asyncio
    async def test_returns_all_signals_in_cluster(self, db: AsyncSession):
        from asc_api.services.correlation_service import get_cluster_signals
        rule = await _make_rule(db)
        cluster = await _make_cluster(db, rule)
        for i in range(3):
            await _make_signal(db, cluster, signal_type="event", pivot_value="ws-007")
        signals = await get_cluster_signals(db, cluster.id)
        assert len(signals) == 3

    @pytest.mark.asyncio
    async def test_signals_ordered_by_timestamp(self, db: AsyncSession):
        from asc_api.services.correlation_service import get_cluster_signals
        rule = await _make_rule(db)
        cluster = await _make_cluster(db, rule)
        t1 = _NOW - timedelta(minutes=10)
        t2 = _NOW - timedelta(minutes=5)
        t3 = _NOW
        await _make_signal(db, cluster, ts=t2)
        await _make_signal(db, cluster, ts=t3)
        await _make_signal(db, cluster, ts=t1)
        signals = await get_cluster_signals(db, cluster.id)
        timestamps = [s.timestamp for s in signals]
        assert timestamps == sorted(timestamps)

    @pytest.mark.asyncio
    async def test_empty_cluster_returns_empty_list(self, db: AsyncSession):
        from asc_api.services.correlation_service import get_cluster_signals
        rule = await _make_rule(db)
        cluster = await _make_cluster(db, rule)
        signals = await get_cluster_signals(db, cluster.id)
        assert signals == []


# ── TestClusterGraphDB ─────────────────────────────────────────────────────────

class TestClusterGraphDB:
    """Real-DB tests for get_cluster_graph."""

    @pytest.mark.asyncio
    async def test_graph_returns_nodes_and_edges(self, db: AsyncSession):
        from asc_api.services.correlation_service import get_cluster_graph
        rule = await _make_rule(db)
        cluster = await _make_cluster(db, rule)
        await _make_signal(db, cluster, signal_type="event", pivot_value="ws-001")
        await _make_signal(db, cluster, signal_type="alert", pivot_value="ws-001")

        graph = await get_cluster_graph(db, cluster.id)
        assert graph is not None
        assert "nodes" in graph
        assert "edges" in graph
        # 1 cluster node + 2 signal nodes
        assert len(graph["nodes"]) == 3
        assert len(graph["edges"]) == 2

    @pytest.mark.asyncio
    async def test_graph_returns_none_for_unknown_cluster(self, db: AsyncSession):
        from asc_api.services.correlation_service import get_cluster_graph
        result = await get_cluster_graph(db, str(uuid.uuid4()))
        assert result is None

    @pytest.mark.asyncio
    async def test_graph_campaign_name_in_metadata(self, db: AsyncSession):
        from asc_api.services.correlation_service import get_cluster_graph
        rule = await _make_rule(db)
        cluster = await _make_cluster(
            db, rule, is_campaign=True,
        )
        cluster.campaign_name = "Campaign-ws-001-deadbeef"
        await db.commit()

        graph = await get_cluster_graph(db, cluster.id)
        assert graph["is_campaign"] is True
        assert "Campaign-ws-001" in graph["campaign_name"]

    @pytest.mark.asyncio
    async def test_graph_cluster_node_first_and_central(self, db: AsyncSession):
        from asc_api.services.correlation_service import get_cluster_graph
        rule = await _make_rule(db)
        cluster = await _make_cluster(db, rule, cluster_key="10.0.0.5")
        await _make_signal(db, cluster, signal_type="event")

        graph = await get_cluster_graph(db, cluster.id)
        first_node = graph["nodes"][0]
        assert first_node["type"] == "cluster"
        assert first_node["id"] == cluster.id
        assert first_node["label"] == "10.0.0.5"


# ── TestListClustersDB ─────────────────────────────────────────────────────────

class TestListClustersDB:
    """Real-DB tests for list_clusters filtering."""

    @pytest.mark.asyncio
    async def test_list_clusters_empty_returns_empty_list(self, db: AsyncSession):
        from asc_api.services.correlation_service import list_clusters
        result = await list_clusters(db)
        assert result == []

    @pytest.mark.asyncio
    async def test_list_clusters_returns_all(self, db: AsyncSession):
        from asc_api.services.correlation_service import list_clusters
        rule = await _make_rule(db)
        for i in range(3):
            await _make_cluster(db, rule, cluster_key=f"host-{i}")
        result = await list_clusters(db)
        assert len(result) == 3

    @pytest.mark.asyncio
    async def test_list_clusters_filter_by_status(self, db: AsyncSession):
        from asc_api.services.correlation_service import list_clusters, update_cluster_status
        rule = await _make_rule(db)
        c_active = await _make_cluster(db, rule, cluster_key="active-host", status="active")
        c_resolved = await _make_cluster(db, rule, cluster_key="resolved-host")
        await update_cluster_status(db, c_resolved.id, status="resolved")

        active_list = await list_clusters(db, status="active")
        assert len(active_list) == 1
        assert active_list[0].id == c_active.id

    @pytest.mark.asyncio
    async def test_list_clusters_filter_campaigns_only(self, db: AsyncSession):
        from asc_api.services.correlation_service import list_clusters
        rule = await _make_rule(db)
        await _make_cluster(db, rule, cluster_key="regular-host", is_campaign=False)
        await _make_cluster(db, rule, cluster_key="campaign-host", is_campaign=True)

        campaigns = await list_clusters(db, is_campaign=True)
        assert len(campaigns) == 1
        assert campaigns[0].cluster_key == "campaign-host"

    @pytest.mark.asyncio
    async def test_list_clusters_limit_respected(self, db: AsyncSession):
        from asc_api.services.correlation_service import list_clusters
        rule = await _make_rule(db)
        for i in range(5):
            await _make_cluster(db, rule, cluster_key=f"lhost-{i}")
        result = await list_clusters(db, limit=2)
        assert len(result) == 2


# ── TestCorrelationSummaryDB ───────────────────────────────────────────────────

class TestCorrelationSummaryDB:
    """Real-DB tests for get_correlation_summary."""

    @pytest.mark.asyncio
    async def test_summary_has_all_required_keys(self, db: AsyncSession):
        from asc_api.services.correlation_service import get_correlation_summary
        result = await get_correlation_summary(db)
        expected = {
            "total_clusters", "active_clusters", "campaigns_detected",
            "critical_clusters", "total_signals", "active_rules",
        }
        assert expected == set(result.keys())

    @pytest.mark.asyncio
    async def test_summary_all_zeros_on_empty_db(self, db: AsyncSession):
        from asc_api.services.correlation_service import get_correlation_summary
        result = await get_correlation_summary(db)
        assert all(v == 0 for v in result.values())

    @pytest.mark.asyncio
    async def test_summary_counts_total_clusters(self, db: AsyncSession):
        from asc_api.services.correlation_service import get_correlation_summary
        rule = await _make_rule(db)
        for i in range(3):
            await _make_cluster(db, rule, cluster_key=f"sc-host-{i}")
        result = await get_correlation_summary(db)
        assert result["total_clusters"] == 3

    @pytest.mark.asyncio
    async def test_summary_counts_campaigns(self, db: AsyncSession):
        from asc_api.services.correlation_service import get_correlation_summary
        rule = await _make_rule(db)
        await _make_cluster(db, rule, cluster_key="campaign-a", is_campaign=True)
        await _make_cluster(db, rule, cluster_key="normal-b", is_campaign=False)
        result = await get_correlation_summary(db)
        assert result["campaigns_detected"] == 1

    @pytest.mark.asyncio
    async def test_summary_counts_critical_active_clusters(self, db: AsyncSession):
        from asc_api.services.correlation_service import get_correlation_summary
        rule = await _make_rule(db)
        await _make_cluster(db, rule, cluster_key="crit-1", severity="critical", status="active")
        await _make_cluster(db, rule, cluster_key="crit-2", severity="critical", status="resolved")
        await _make_cluster(db, rule, cluster_key="high-1", severity="high", status="active")
        result = await get_correlation_summary(db)
        assert result["critical_clusters"] == 1  # only active critical

    @pytest.mark.asyncio
    async def test_summary_counts_active_rules(self, db: AsyncSession):
        from asc_api.services.correlation_service import get_correlation_summary, update_rule
        r1 = await _make_rule(db, name="Active Rule A")
        r2 = await _make_rule(db, name="Active Rule B")
        await _make_rule(db, name="Active Rule C")
        # Disable r1 and r2 → only r3 remains active
        await update_rule(db, r1.id, enabled=False)
        await update_rule(db, r2.id, enabled=False)
        result = await get_correlation_summary(db)
        assert result["active_rules"] == 1


# ── TestRunCorrelationSweepDB ──────────────────────────────────────────────────

class TestRunCorrelationSweepDB:
    """Real-DB tests for run_correlation_sweep."""

    @pytest.mark.asyncio
    async def test_sweep_returns_stats_dict_with_all_keys(self, db: AsyncSession):
        from asc_api.services.correlation_service import run_correlation_sweep
        stats = await run_correlation_sweep(db)
        expected = {
            "rules_evaluated", "clusters_created", "clusters_updated",
            "signals_added", "campaigns_detected",
        }
        assert expected == set(stats.keys())

    @pytest.mark.asyncio
    async def test_sweep_with_no_rules_returns_zero_stats(self, db: AsyncSession):
        from asc_api.services.correlation_service import run_correlation_sweep
        stats = await run_correlation_sweep(db)
        assert stats["rules_evaluated"] == 0
        assert stats["clusters_created"] == 0

    @pytest.mark.asyncio
    async def test_sweep_with_host_rule_creates_cluster(self, db: AsyncSession):
        from asc_api.services.correlation_service import run_correlation_sweep, list_clusters
        # Seed a host_pivot rule with min_signals=2
        await _make_rule(db, name="Host Sweep Rule", pivot_type="host_pivot", min_signals=2)
        # Seed 2 Events with the same host within the window
        host = "workstation-premos-01"
        for _ in range(2):
            ev = Event(
                id=str(uuid.uuid4()),
                source="winlog",
                category="process",
                action="process_create",
                host=host,
                severity="high",
                timestamp=datetime.now(timezone.utc),
                normalized={},
                tags=[],
                tenant_id=None,
            )
            db.add(ev)
        await db.commit()

        stats = await run_correlation_sweep(db)
        assert stats["clusters_created"] >= 1
        clusters = await list_clusters(db)
        assert any(c.cluster_key == host for c in clusters)

    @pytest.mark.asyncio
    async def test_sweep_second_run_updates_not_creates(self, db: AsyncSession):
        from asc_api.services.correlation_service import run_correlation_sweep
        await _make_rule(db, name="Sweep Dedup Rule", pivot_type="host_pivot", min_signals=2)
        host = "workstation-premos-02"
        for _ in range(2):
            ev = Event(
                id=str(uuid.uuid4()),
                source="syslog",
                category="network",
                action="connect",
                host=host,
                severity="medium",
                timestamp=datetime.now(timezone.utc),
                normalized={},
                tags=[],
                tenant_id=None,
            )
            db.add(ev)
        await db.commit()

        stats1 = await run_correlation_sweep(db)
        assert stats1["clusters_created"] == 1

        # Second sweep — same events (already deduplicated), cluster exists → update
        stats2 = await run_correlation_sweep(db)
        assert stats2["clusters_created"] == 0
        assert stats2["clusters_updated"] >= 1

    @pytest.mark.asyncio
    async def test_sweep_signals_added_reflects_new_signals(self, db: AsyncSession):
        from asc_api.services.correlation_service import run_correlation_sweep
        await _make_rule(db, name="Signals Count Rule", pivot_type="host_pivot", min_signals=2)
        host = "workstation-premos-03"
        for _ in range(3):
            ev = Event(
                id=str(uuid.uuid4()),
                source="edr",
                category="file",
                action="file_write",
                host=host,
                severity="critical",
                timestamp=datetime.now(timezone.utc),
                normalized={},
                tags=[],
                tenant_id=None,
            )
            db.add(ev)
        await db.commit()

        stats = await run_correlation_sweep(db)
        assert stats["signals_added"] == 3


# ── TestCorrelationRestEndpointsDB ─────────────────────────────────────────────

class TestCorrelationRestEndpointsDB:
    """Full REST API integration tests via conftest client fixture."""

    _BASE = "/api/v1/correlation"

    async def test_401_anonymous_on_list_rules(self, client: AsyncClient):
        r = await client.get(f"{self._BASE}/rules")
        assert r.status_code == 401

    async def test_get_rules_empty_list(self, client: AsyncClient, analyst_user: User):
        r = await client.get(f"{self._BASE}/rules", headers=_auth(analyst_user))
        assert r.status_code == 200
        assert r.json() == []

    async def test_post_create_rule_returns_201(
        self, client: AsyncClient, admin_user: User
    ):
        payload = {
            "name": "REST Identity Rule",
            "pivot_type": "identity_pivot",
            "min_signals": 3,
            "time_window_minutes": 120,
            "severity_threshold": "medium",
        }
        r = await client.post(
            f"{self._BASE}/rules", json=payload, headers=_auth(admin_user)
        )
        assert r.status_code == 201
        data = r.json()
        assert data["name"] == "REST Identity Rule"
        assert data["pivot_type"] == "identity_pivot"
        assert data["min_signals"] == 3
        assert data["id"] is not None

    async def test_post_create_rule_duplicate_returns_409(
        self, client: AsyncClient, admin_user: User
    ):
        payload = {"name": "Dup REST Rule", "pivot_type": "ip_pivot"}
        await client.post(
            f"{self._BASE}/rules", json=payload, headers=_auth(admin_user)
        )
        r = await client.post(
            f"{self._BASE}/rules", json=payload, headers=_auth(admin_user)
        )
        assert r.status_code == 409

    async def test_get_rule_by_id_returns_200(
        self, client: AsyncClient, admin_user: User, db: AsyncSession
    ):
        rule = await _make_rule(db, name="Get By ID Rule")
        r = await client.get(
            f"{self._BASE}/rules/{rule.id}", headers=_auth(admin_user)
        )
        assert r.status_code == 200
        assert r.json()["id"] == rule.id

    async def test_get_rule_not_found_returns_404(
        self, client: AsyncClient, analyst_user: User
    ):
        r = await client.get(
            f"{self._BASE}/rules/{uuid.uuid4()}", headers=_auth(analyst_user)
        )
        assert r.status_code == 404

    async def test_patch_rule_updates_fields(
        self, client: AsyncClient, admin_user: User, db: AsyncSession
    ):
        rule = await _make_rule(db, name="Patch Target Rule")
        r = await client.patch(
            f"{self._BASE}/rules/{rule.id}",
            json={"min_signals": 7, "enabled": False},
            headers=_auth(admin_user),
        )
        assert r.status_code == 200
        data = r.json()
        assert data["min_signals"] == 7
        assert data["enabled"] is False

    async def test_delete_rule_admin_returns_204(
        self, client: AsyncClient, admin_user: User, db: AsyncSession
    ):
        rule = await _make_rule(db, name="Delete Me Rule")
        r = await client.delete(
            f"{self._BASE}/rules/{rule.id}", headers=_auth(admin_user)
        )
        assert r.status_code == 204

    async def test_delete_rule_analyst_returns_403(
        self, client: AsyncClient, analyst_user: User, db: AsyncSession
    ):
        rule = await _make_rule(db, name="Analyst Cannot Delete")
        r = await client.delete(
            f"{self._BASE}/rules/{rule.id}", headers=_auth(analyst_user)
        )
        assert r.status_code == 403

    async def test_sweep_endpoint_runs_inline_when_celery_unavailable(
        self, client: AsyncClient, admin_user: User
    ):
        r = await client.post(
            f"{self._BASE}/sweep", headers=_auth(admin_user)
        )
        assert r.status_code == 202
        data = r.json()
        # Celery is unavailable in tests → inline fallback
        assert data["status"] in ("queued", "completed_inline")
