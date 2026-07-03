"""
Priority 3 — Playbooks Engine unit + integration tests.

Coverage:
  - PlaybookContext construction (from_detection, from_fingerprint, manual)
  - select_playbook_id (risk-based + fingerprint routing)
  - get_playbook_catalog (catalog structure)
  - trigger_playbook — all 4 playbooks (PB-001..PB-004)
  - auto_trigger — risk-score routing + fingerprint routing
  - approve_playbook_run — HitL resume, invalid token, wrong status
  - abort_playbook_run — valid abort, abort completed run (error)
  - _context_from_run — reconstruction from stored data
  - API endpoints — /playbooks/, /trigger, /auto-trigger, /runs, /approve, /abort
  - RBAC — viewer cannot trigger/approve; analyst can
"""

import pytest
import pytest_asyncio
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.models.playbook_run import PlaybookRun
from asc_api.services.playbook import (
    PLAYBOOKS,
    PlaybookContext,
    abort_playbook_run,
    approve_playbook_run,
    auto_trigger,
    get_playbook_catalog,
    select_playbook_id,
    trigger_playbook,
    _context_from_run,
)


# ─── PlaybookContext ──────────────────────────────────────────────────────────

class TestPlaybookContext:
    def test_from_detection_basic(self):
        event = {"host": "PREMOS-WS-01", "dst_ip": "192.168.1.1"}
        ctx = PlaybookContext.from_detection(event, risk_score=0.60, semaphore="yellow")
        assert ctx.semaphore == "yellow"
        assert ctx.risk_score == 0.60
        assert ctx.trigger_source == "auto_detection"
        assert ctx.host == "PREMOS-WS-01"
        assert ctx.dst_ip is None  # dst_ip in event root but not in nested destination dict

    def test_from_detection_nested_host(self):
        event = {"host": {"hostname": "SRV-PREMOS-01"}, "process": {"name": "acord32.exe"}}
        ctx = PlaybookContext.from_detection(event, risk_score=0.75, semaphore="yellow")
        assert ctx.host == "SRV-PREMOS-01"
        assert ctx.process_name == "acord32.exe"

    def test_from_detection_nested_destination(self):
        event = {"destination": {"ip": "10.0.0.5", "domain": "c2.evil.com"}}
        ctx = PlaybookContext.from_detection(event, risk_score=0.85, semaphore="red")
        assert ctx.dst_ip == "10.0.0.5"
        assert ctx.dst_domain == "c2.evil.com"

    def test_from_detection_ttps(self):
        event = {"ttps": ["T1036.005", "T1056.001"]}
        ctx = PlaybookContext.from_detection(event, risk_score=0.50, semaphore="yellow")
        assert "T1036.005" in ctx.ttps

    def test_from_fingerprint_high_confidence(self):
        result = {"confidence": 0.92, "risk_score": 0.90, "triggers": ["PREMOS hostname"]}
        ctx = PlaybookContext.from_fingerprint(result)
        assert ctx.semaphore == "red"
        assert ctx.risk_score == 0.90
        assert ctx.fingerprint_confidence == 0.92
        assert ctx.trigger_source == "auto_fingerprint"

    def test_from_fingerprint_low_confidence(self):
        result = {"confidence": 0.35, "risk_score": 0.40, "triggers": ["timing evasion"]}
        ctx = PlaybookContext.from_fingerprint(result)
        assert ctx.semaphore == "yellow"  # confidence 0.35 < 0.50

    def test_from_fingerprint_exactly_half(self):
        result = {"confidence": 0.50, "risk_score": 0.50, "triggers": []}
        ctx = PlaybookContext.from_fingerprint(result)
        assert ctx.semaphore == "red"

    def test_manual_context(self):
        ctx = PlaybookContext(
            semaphore="green",
            risk_score=0.10,
            trigger_source="manual",
            host="PREMOS-WS-99",
        )
        assert ctx.trigger_source == "manual"
        assert ctx.host == "PREMOS-WS-99"
        assert ctx.fingerprint_confidence is None


# ─── Playbook Selection ───────────────────────────────────────────────────────

class TestSelectPlaybook:
    def _ctx(self, risk: float, source: str = "auto_detection", confidence: float | None = None):
        sem = "red" if risk >= 0.85 else ("yellow" if risk >= 0.40 else "green")
        return PlaybookContext(
            semaphore=sem,
            risk_score=risk,
            trigger_source=source,
            fingerprint_confidence=confidence,
        )

    def test_low_risk_selects_pb001(self):
        assert select_playbook_id(self._ctx(0.10)) == "PB-001"

    def test_zero_risk_selects_pb001(self):
        assert select_playbook_id(self._ctx(0.0)) == "PB-001"

    def test_boundary_039_selects_pb001(self):
        assert select_playbook_id(self._ctx(0.39)) == "PB-001"

    def test_boundary_040_selects_pb002(self):
        assert select_playbook_id(self._ctx(0.40)) == "PB-002"

    def test_medium_risk_selects_pb002(self):
        assert select_playbook_id(self._ctx(0.60)) == "PB-002"

    def test_boundary_084_selects_pb002(self):
        assert select_playbook_id(self._ctx(0.84)) == "PB-002"

    def test_boundary_085_selects_pb003(self):
        assert select_playbook_id(self._ctx(0.85)) == "PB-003"

    def test_max_risk_selects_pb003(self):
        assert select_playbook_id(self._ctx(1.0)) == "PB-003"

    def test_fingerprint_above_030_selects_pb004(self):
        ctx = self._ctx(0.90, source="auto_fingerprint", confidence=0.50)
        assert select_playbook_id(ctx) == "PB-004"

    def test_fingerprint_exactly_030_selects_pb004(self):
        ctx = self._ctx(0.90, source="auto_fingerprint", confidence=0.30)
        assert select_playbook_id(ctx) == "PB-004"

    def test_fingerprint_below_030_falls_through_to_risk(self):
        ctx = self._ctx(0.90, source="auto_fingerprint", confidence=0.10)
        # confidence 0.10 < 0.30 → falls through to risk-based → PB-003
        assert select_playbook_id(ctx) == "PB-003"

    def test_fingerprint_source_no_confidence_falls_through(self):
        ctx = self._ctx(0.20, source="auto_fingerprint", confidence=None)
        assert select_playbook_id(ctx) == "PB-001"


# ─── Catalog ──────────────────────────────────────────────────────────────────

class TestCatalog:
    def test_catalog_has_four_playbooks(self):
        catalog = get_playbook_catalog()
        assert len(catalog) >= 4  # PB-001..PB-004 minimum; PB-005 (PIDS) added in P26

    def test_catalog_ids(self):
        ids = {p["id"] for p in get_playbook_catalog()}
        # PB-001..PB-004 are core; PB-005 (PIDS Identity Response) added in P26
        assert {"PB-001", "PB-002", "PB-003", "PB-004"}.issubset(ids)

    def test_catalog_has_required_fields(self):
        for pb in get_playbook_catalog():
            assert "id" in pb
            assert "name" in pb
            assert "description" in pb
            assert "semaphore" in pb
            assert "requires_approval" in pb
            assert "step_count" in pb
            assert "steps" in pb

    def test_pb001_does_not_require_approval(self):
        pb = next(p for p in get_playbook_catalog() if p["id"] == "PB-001")
        assert pb["requires_approval"] is False

    def test_pb002_requires_approval(self):
        pb = next(p for p in get_playbook_catalog() if p["id"] == "PB-002")
        assert pb["requires_approval"] is True

    def test_pb003_requires_approval(self):
        pb = next(p for p in get_playbook_catalog() if p["id"] == "PB-003")
        assert pb["requires_approval"] is True

    def test_pb004_requires_approval(self):
        pb = next(p for p in get_playbook_catalog() if p["id"] == "PB-004")
        assert pb["requires_approval"] is True


# ─── Trigger + Engine (service layer, uses in-memory DB) ─────────────────────

class TestTriggerPB001:
    @pytest.mark.asyncio
    async def test_pb001_completes_auto(self, db: AsyncSession, analyst_user):
        ctx = PlaybookContext(semaphore="green", risk_score=0.15, trigger_source="manual")
        run = await trigger_playbook("PB-001", ctx, db, initiated_by=str(analyst_user.id))
        await db.commit()
        assert run.status == "completed"
        assert run.playbook_id == "PB-001"
        assert run.completed_at is not None

    @pytest.mark.asyncio
    async def test_pb001_no_approval_token(self, db: AsyncSession, analyst_user):
        ctx = PlaybookContext(semaphore="green", risk_score=0.10, trigger_source="manual")
        run = await trigger_playbook("PB-001", ctx, db, initiated_by=str(analyst_user.id))
        await db.commit()
        assert run.approval_token is None
        assert run.approved_by is None

    @pytest.mark.asyncio
    async def test_pb001_has_steps_log(self, db: AsyncSession, analyst_user):
        ctx = PlaybookContext(semaphore="green", risk_score=0.05, trigger_source="auto_detection")
        run = await trigger_playbook("PB-001", ctx, db, initiated_by=str(analyst_user.id))
        await db.commit()
        assert len(run.steps_log) == len(PLAYBOOKS["PB-001"].steps)


class TestTriggerPB002:
    @pytest.mark.asyncio
    async def test_pb002_pauses_at_hitl(self, db: AsyncSession, analyst_user):
        ctx = PlaybookContext(semaphore="yellow", risk_score=0.65, trigger_source="auto_detection")
        run = await trigger_playbook("PB-002", ctx, db, initiated_by=str(analyst_user.id))
        await db.commit()
        assert run.status == "awaiting_approval"
        assert run.approval_token is not None

    @pytest.mark.asyncio
    async def test_pb002_stores_next_step(self, db: AsyncSession, analyst_user):
        ctx = PlaybookContext(semaphore="yellow", risk_score=0.50, trigger_source="auto_detection")
        run = await trigger_playbook("PB-002", ctx, db, initiated_by=str(analyst_user.id))
        await db.commit()
        # AWAIT_APPROVAL is step index 3 (0-based: LOG, CREATE_ALERT, NOTIFY, AWAIT_APPROVAL)
        assert run.next_step_index == 4  # resume from step after AWAIT_APPROVAL

    @pytest.mark.asyncio
    async def test_pb002_creates_alert(self, db: AsyncSession, analyst_user):
        ctx = PlaybookContext(semaphore="yellow", risk_score=0.70, trigger_source="auto_detection")
        run = await trigger_playbook("PB-002", ctx, db, initiated_by=str(analyst_user.id))
        await db.commit()
        assert run.alert_id is not None


class TestTriggerPB003:
    @pytest.mark.asyncio
    async def test_pb003_pauses_at_hitl(self, db: AsyncSession, admin_user):
        ctx = PlaybookContext(semaphore="red", risk_score=0.92, trigger_source="auto_detection")
        run = await trigger_playbook("PB-003", ctx, db, initiated_by=str(admin_user.id))
        await db.commit()
        assert run.status == "awaiting_approval"

    @pytest.mark.asyncio
    async def test_pb003_creates_critical_alert(self, db: AsyncSession, admin_user):
        ctx = PlaybookContext(semaphore="red", risk_score=0.95, trigger_source="auto_detection")
        run = await trigger_playbook("PB-003", ctx, db, initiated_by=str(admin_user.id))
        await db.commit()
        assert run.alert_id is not None

    @pytest.mark.asyncio
    async def test_pb003_approval_resumes_and_completes(self, db: AsyncSession, admin_user):
        ctx = PlaybookContext(
            semaphore="red", risk_score=0.90, trigger_source="auto_detection",
            host="PREMOS-WS-01", dst_ip="10.0.0.100", dst_domain="c2.evil.com"
        )
        run = await trigger_playbook("PB-003", ctx, db, initiated_by=str(admin_user.id))
        await db.commit()

        assert run.status == "awaiting_approval"
        token = run.approval_token

        run = await approve_playbook_run(run, approved_by=str(admin_user.id), db=db)
        await db.commit()

        assert run.status == "completed"
        assert run.approved_by == str(admin_user.id)
        assert run.approved_at is not None
        assert run.approval_token is None  # cleared after use


class TestTriggerPB004:
    @pytest.mark.asyncio
    async def test_pb004_pauses_at_hitl(self, db: AsyncSession, analyst_user):
        ctx = PlaybookContext.from_fingerprint({"confidence": 0.75, "risk_score": 0.80, "triggers": ["PREMOS"]})
        run = await trigger_playbook("PB-004", ctx, db, initiated_by=str(analyst_user.id))
        await db.commit()
        assert run.status == "awaiting_approval"

    @pytest.mark.asyncio
    async def test_pb004_skips_isolation_below_080(self, db: AsyncSession, analyst_user):
        ctx = PlaybookContext.from_fingerprint({"confidence": 0.55, "risk_score": 0.60, "triggers": ["registry"]})
        run = await trigger_playbook("PB-004", ctx, db, initiated_by=str(analyst_user.id))
        await db.commit()

        # Approve and resume
        run = await approve_playbook_run(run, approved_by=str(analyst_user.id), db=db)
        await db.commit()

        # Find the isolation step result
        isolate_steps = [s for s in run.steps_log if s.get("action") == "ISOLATE_ENDPOINT"]
        assert len(isolate_steps) == 1
        assert "skipped" in isolate_steps[0].get("detail", "").lower()

    @pytest.mark.asyncio
    async def test_pb004_isolates_above_080(self, db: AsyncSession, analyst_user):
        ctx = PlaybookContext.from_fingerprint({"confidence": 0.85, "risk_score": 0.90, "triggers": ["PremosCorp"]})
        run = await trigger_playbook("PB-004", ctx, db, initiated_by=str(analyst_user.id))
        await db.commit()

        run = await approve_playbook_run(run, approved_by=str(analyst_user.id), db=db)
        await db.commit()

        isolate_steps = [s for s in run.steps_log if s.get("action") == "ISOLATE_ENDPOINT"]
        assert len(isolate_steps) == 1
        assert isolate_steps[0].get("success") is True


# ─── HitL Approval Validation ─────────────────────────────────────────────────

class TestApprovalValidation:
    @pytest.mark.asyncio
    async def test_approve_pb002_service_completes(self, db: AsyncSession, analyst_user):
        """Service-layer approve works — token check is the API layer's responsibility."""
        ctx = PlaybookContext(semaphore="yellow", risk_score=0.60, trigger_source="manual")
        run = await trigger_playbook("PB-002", ctx, db, initiated_by=str(analyst_user.id))
        await db.commit()

        assert run.status == "awaiting_approval"
        run = await approve_playbook_run(run, approved_by=str(analyst_user.id), db=db)
        await db.commit()
        assert run.status == "completed"
        assert run.approved_by == str(analyst_user.id)

    @pytest.mark.asyncio
    async def test_approve_sets_approval_metadata(self, db: AsyncSession, analyst_user):
        ctx = PlaybookContext(semaphore="yellow", risk_score=0.70, trigger_source="auto_detection")
        run = await trigger_playbook("PB-002", ctx, db, initiated_by=str(analyst_user.id))
        await db.commit()

        run = await approve_playbook_run(run, approved_by=str(analyst_user.id), db=db)
        await db.commit()

        assert run.approved_at is not None
        assert run.approval_token is None  # cleared post-approval

    @pytest.mark.asyncio
    async def test_approve_non_awaiting_raises(self, db: AsyncSession, analyst_user):
        ctx = PlaybookContext(semaphore="green", risk_score=0.10, trigger_source="manual")
        run = await trigger_playbook("PB-001", ctx, db, initiated_by=str(analyst_user.id))
        await db.commit()

        # PB-001 completes without HitL — status=completed
        assert run.status == "completed"
        with pytest.raises(ValueError, match="not awaiting approval"):
            await approve_playbook_run(run, approved_by=str(analyst_user.id), db=db)


# ─── Abort ────────────────────────────────────────────────────────────────────

class TestAbort:
    @pytest.mark.asyncio
    async def test_abort_awaiting_approval(self, db: AsyncSession, analyst_user):
        ctx = PlaybookContext(semaphore="yellow", risk_score=0.55, trigger_source="manual")
        run = await trigger_playbook("PB-002", ctx, db, initiated_by=str(analyst_user.id))
        await db.commit()

        assert run.status == "awaiting_approval"
        run = await abort_playbook_run(run, aborted_by=str(analyst_user.id), db=db)
        await db.commit()

        assert run.status == "aborted"
        assert run.completed_at is not None
        assert str(analyst_user.id) in run.error

    @pytest.mark.asyncio
    async def test_abort_completed_run_raises(self, db: AsyncSession, analyst_user):
        ctx = PlaybookContext(semaphore="green", risk_score=0.05, trigger_source="manual")
        run = await trigger_playbook("PB-001", ctx, db, initiated_by=str(analyst_user.id))
        await db.commit()

        assert run.status == "completed"
        with pytest.raises(ValueError):
            await abort_playbook_run(run, aborted_by=str(analyst_user.id), db=db)


# ─── Auto-trigger ─────────────────────────────────────────────────────────────

class TestAutoTrigger:
    @pytest.mark.asyncio
    async def test_auto_trigger_low_risk_pb001(self, db: AsyncSession):
        ctx = PlaybookContext(semaphore="green", risk_score=0.20, trigger_source="auto_detection")
        run = await auto_trigger(ctx, db, initiated_by="system")
        await db.commit()
        assert run.playbook_id == "PB-001"
        assert run.status == "completed"

    @pytest.mark.asyncio
    async def test_auto_trigger_medium_risk_pb002(self, db: AsyncSession):
        ctx = PlaybookContext(semaphore="yellow", risk_score=0.65, trigger_source="auto_detection")
        run = await auto_trigger(ctx, db, initiated_by="system")
        await db.commit()
        assert run.playbook_id == "PB-002"
        assert run.status == "awaiting_approval"

    @pytest.mark.asyncio
    async def test_auto_trigger_high_risk_pb003(self, db: AsyncSession):
        ctx = PlaybookContext(semaphore="red", risk_score=0.95, trigger_source="auto_detection")
        run = await auto_trigger(ctx, db, initiated_by="system")
        await db.commit()
        assert run.playbook_id == "PB-003"
        assert run.status == "awaiting_approval"

    @pytest.mark.asyncio
    async def test_auto_trigger_fingerprint_pb004(self, db: AsyncSession):
        ctx = PlaybookContext.from_fingerprint({"confidence": 0.72, "risk_score": 0.85, "triggers": ["PREMOS"]})
        run = await auto_trigger(ctx, db, initiated_by="system")
        await db.commit()
        assert run.playbook_id == "PB-004"


# ─── Context Reconstruction ───────────────────────────────────────────────────

class TestContextFromRun:
    def test_reconstructs_detection_context(self):
        run = PlaybookRun(
            id=str(uuid.uuid4()),
            playbook_id="PB-002",
            playbook_name="Test",
            trigger_source="auto_detection",
            trigger_data={"host": "WS-01", "dst_ip": "1.2.3.4"},
            semaphore="yellow",
            risk_score=0.60,
            status="awaiting_approval",
            steps_log=[],
            next_step_index=3,
            initiated_by="system",
            started_at=datetime.now(timezone.utc),
        )
        ctx = _context_from_run(run)
        assert ctx.semaphore == "yellow"
        assert ctx.risk_score == 0.60
        assert ctx.host == "WS-01"
        assert ctx.dst_ip == "1.2.3.4"

    def test_reconstructs_fingerprint_context(self):
        run = PlaybookRun(
            id=str(uuid.uuid4()),
            playbook_id="PB-004",
            playbook_name="Test",
            trigger_source="auto_fingerprint",
            trigger_data={"confidence": 0.85, "risk_score": 0.90, "triggers": ["PREMOS"]},
            semaphore="red",
            risk_score=0.90,
            status="awaiting_approval",
            steps_log=[],
            next_step_index=4,
            initiated_by="system",
            started_at=datetime.now(timezone.utc),
        )
        ctx = _context_from_run(run)
        assert ctx.fingerprint_confidence == 0.85
        assert ctx.trigger_source == "auto_fingerprint"


# ─── Unknown Playbook ─────────────────────────────────────────────────────────

class TestUnknownPlaybook:
    @pytest.mark.asyncio
    async def test_trigger_unknown_raises(self, db: AsyncSession):
        ctx = PlaybookContext(semaphore="green", risk_score=0.10, trigger_source="manual")
        with pytest.raises(ValueError, match="Unknown playbook"):
            await trigger_playbook("PB-999", ctx, db, initiated_by="system")


# ─── API Endpoints ────────────────────────────────────────────────────────────

class TestPlaybooksAPI:
    @pytest.mark.asyncio
    async def test_list_playbooks_requires_auth(self, client: AsyncClient):
        # FastAPI's HTTPBearer returns 403 (not 401) when no Bearer token is present
        resp = await client.get("/api/v1/playbooks/")
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_list_playbooks_viewer_ok(self, client: AsyncClient, viewer_headers: dict):
        resp = await client.get("/api/v1/playbooks/", headers=viewer_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) >= 4  # PB-005 added in P26
        ids = {p["id"] for p in data}
        assert "PB-001" in ids

    @pytest.mark.asyncio
    async def test_trigger_requires_analyst(self, client: AsyncClient, viewer_headers: dict):
        payload = {
            "playbook_id": "PB-001",
            "semaphore": "green",
            "risk_score": 0.10,
        }
        resp = await client.post("/api/v1/playbooks/trigger", json=payload, headers=viewer_headers)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_trigger_analyst_pb001(self, client: AsyncClient, analyst_headers: dict):
        payload = {
            "playbook_id": "PB-001",
            "semaphore": "green",
            "risk_score": 0.15,
            "host": "PREMOS-WS-01",
        }
        resp = await client.post("/api/v1/playbooks/trigger", json=payload, headers=analyst_headers)
        assert resp.status_code == 201
        data = resp.json()
        assert data["playbook_id"] == "PB-001"
        assert data["status"] == "completed"

    @pytest.mark.asyncio
    async def test_trigger_pb002_awaiting_approval(self, client: AsyncClient, analyst_headers: dict):
        payload = {
            "playbook_id": "PB-002",
            "semaphore": "yellow",
            "risk_score": 0.65,
        }
        resp = await client.post("/api/v1/playbooks/trigger", json=payload, headers=analyst_headers)
        assert resp.status_code == 201
        data = resp.json()
        assert data["status"] == "awaiting_approval"
        assert data["approval_token"] is not None

    @pytest.mark.asyncio
    async def test_trigger_unknown_playbook_400(self, client: AsyncClient, analyst_headers: dict):
        payload = {
            "playbook_id": "PB-999",
            "semaphore": "green",
            "risk_score": 0.10,
        }
        resp = await client.post("/api/v1/playbooks/trigger", json=payload, headers=analyst_headers)
        assert resp.status_code in (400, 422)

    @pytest.mark.asyncio
    async def test_auto_trigger_selects_pb001(self, client: AsyncClient, analyst_headers: dict):
        payload = {
            "semaphore": "green",
            "risk_score": 0.10,
            "trigger_source": "manual",
        }
        resp = await client.post("/api/v1/playbooks/auto-trigger", json=payload, headers=analyst_headers)
        assert resp.status_code == 201
        data = resp.json()
        assert data["playbook_id"] == "PB-001"

    @pytest.mark.asyncio
    async def test_list_runs_viewer_ok(self, client: AsyncClient, viewer_headers: dict):
        resp = await client.get("/api/v1/playbooks/runs", headers=viewer_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "runs" in data
        assert "total" in data

    @pytest.mark.asyncio
    async def test_get_run_not_found(self, client: AsyncClient, viewer_headers: dict):
        resp = await client.get(f"/api/v1/playbooks/runs/{uuid.uuid4()}", headers=viewer_headers)
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_approve_wrong_token_403(self, client: AsyncClient, analyst_headers: dict):
        # First trigger PB-002 to get a run in awaiting_approval state
        trig_resp = await client.post(
            "/api/v1/playbooks/trigger",
            json={"playbook_id": "PB-002", "semaphore": "yellow", "risk_score": 0.60},
            headers=analyst_headers,
        )
        assert trig_resp.status_code == 201
        run_id = trig_resp.json()["id"]

        # Try to approve with wrong token
        resp = await client.post(
            f"/api/v1/playbooks/runs/{run_id}/approve",
            json={"approval_token": str(uuid.uuid4())},  # wrong
            headers=analyst_headers,
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_approve_correct_token_completes(self, client: AsyncClient, analyst_headers: dict):
        trig_resp = await client.post(
            "/api/v1/playbooks/trigger",
            json={"playbook_id": "PB-002", "semaphore": "yellow", "risk_score": 0.60},
            headers=analyst_headers,
        )
        data = trig_resp.json()
        run_id = data["id"]
        token = data["approval_token"]

        resp = await client.post(
            f"/api/v1/playbooks/runs/{run_id}/approve",
            json={"approval_token": token},
            headers=analyst_headers,
        )
        assert resp.status_code == 200
        result = resp.json()
        assert result["status"] == "completed"
        assert result["approval_token"] is None

    @pytest.mark.asyncio
    async def test_abort_awaiting_approval(self, client: AsyncClient, analyst_headers: dict):
        trig_resp = await client.post(
            "/api/v1/playbooks/trigger",
            json={"playbook_id": "PB-002", "semaphore": "yellow", "risk_score": 0.55},
            headers=analyst_headers,
        )
        run_id = trig_resp.json()["id"]

        resp = await client.post(
            f"/api/v1/playbooks/runs/{run_id}/abort",
            headers=analyst_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "aborted"

    @pytest.mark.asyncio
    async def test_abort_completed_run_409(self, client: AsyncClient, analyst_headers: dict):
        trig_resp = await client.post(
            "/api/v1/playbooks/trigger",
            json={"playbook_id": "PB-001", "semaphore": "green", "risk_score": 0.10},
            headers=analyst_headers,
        )
        run_id = trig_resp.json()["id"]

        resp = await client.post(
            f"/api/v1/playbooks/runs/{run_id}/abort",
            headers=analyst_headers,
        )
        assert resp.status_code == 409
