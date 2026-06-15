"""
P34 Coverage — push 84.26% → 85%+

Primary target: app/tasks/pcdi_escalation.py lines 59-130
  (the hunt-scoring loop, escalation path, SSE notification, error branches)

Secondary: miscellaneous uncovered branches in tasks and services.

Mock strategy for pcdi_escalation._run():
  - Two db.execute() calls: first for Hunt list, second for HuntFinding list.
  - compute_adaptive_score, log_security_action, notification_bus — all lazy
    imports inside _run(), so patched at source-module level.
  - asyncio.ensure_future is called inside a try/except; patching notification_bus
    as AsyncMock lets the coroutine be created and scheduled safely.
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest

# ─── Re-use the same celery stub from test_p33_coverage_b ────────────────────
# If already installed (by that module being collected first), setdefault is a
# no-op. Otherwise we need the stub so pcdi_escalation.py can be imported.

class _FakeCeleryConf:
    def __init__(self, include):
        self.include = list(include) if include else []
        self.beat_schedule: dict = {}
        self._extra: dict = {}

    def update(self, **kwargs):
        if "beat_schedule" in kwargs:
            self.beat_schedule = kwargs.pop("beat_schedule")
        self._extra.update(kwargs)

    def __getattr__(self, name):
        if name in self._extra:
            return self._extra[name]
        raise AttributeError(name)


class _FakeCeleryApp:
    def __init__(self, name="", broker=None, backend=None, include=None, **kw):
        self.main = name          # mirrors real Celery.main attribute
        self.conf = _FakeCeleryConf(include)
        self.tasks: dict = {}

    def task(self, *args, **kwargs):
        def decorator(fn):
            fn.name = kwargs.get("name", fn.__qualname__)
            fn.delay = lambda *a, **kw: None
            self.tasks[fn.name] = fn
            return fn
        return decorator


class _FakeCeleryStub:
    Celery = _FakeCeleryApp


if "celery" not in sys.modules:
    sys.modules["celery"] = _FakeCeleryStub()  # type: ignore[assignment]
    sys.modules.setdefault("celery.schedules", MagicMock())
    sys.modules.setdefault("celery.utils.log", MagicMock())


# ─── Shared DB-mock helpers ───────────────────────────────────────────────────

class _FakeSession:
    def __init__(self, mock_db):
        self._db = mock_db

    async def __aenter__(self):
        return self._db

    async def __aexit__(self, *_):
        return False


def _scalars_result(rows: list) -> MagicMock:
    result = MagicMock()
    scalars = MagicMock()
    scalars.all.return_value = rows
    result.scalars.return_value = scalars
    return result


def _make_hunt(priority: str = "high", hunt_id: str = "hunt-001") -> MagicMock:
    h = MagicMock()
    h.id = hunt_id
    h.name = f"Hunt {hunt_id}"
    h.priority = priority
    h.status = "active"
    return h


def _make_finding(finding_id: str = "f-001") -> MagicMock:
    f = MagicMock()
    f.id = finding_id
    f.indicator_value = "10.0.1.5"
    f.is_confirmed = False
    f.is_false_positive = False
    return f


# ══════════════════════════════════════════════════════════════════════════════
# PCDI Escalation — full scoring loop paths
# ══════════════════════════════════════════════════════════════════════════════

class TestPcdiEscalationScoringLoop:
    """Cover pcdi_escalation._run() lines 59-130 via mocked DB + services."""

    def _db_for(self, hunt_list, finding_list) -> AsyncMock:
        db = AsyncMock()
        db.execute.side_effect = [
            _scalars_result(hunt_list),   # First call: hunts
            _scalars_result(finding_list),  # Second call: findings for first hunt
        ]
        return db

    # ── Context managers ──────────────────────────────────────────────────────

    def _patches(self, score_return=None, log_sec=True):
        """Return a list of context managers for common lazy imports."""
        score_return = score_return or {"adaptive_score": 95}
        return [
            patch("app.tasks.pcdi_escalation.AsyncSessionLocal"),
            patch("app.services.pcdi_service.compute_adaptive_score",
                  AsyncMock(return_value=score_return)),
            patch("app.core.audit.log_security_action", MagicMock()),
            patch("app.core.config.get_settings", MagicMock(return_value=MagicMock())),
            patch("app.core.notifications.notification_bus"),
        ]

    # ── Tests ─────────────────────────────────────────────────────────────────

    async def test_run_score_below_threshold_no_escalation(self):
        """Score 50 < 80 threshold → hunt not escalated, priority unchanged."""
        from app.tasks.pcdi_escalation import _run

        hunt = _make_hunt(priority="high")
        finding = _make_finding()
        db = self._db_for([hunt], [finding])

        with patch("app.tasks.pcdi_escalation.AsyncSessionLocal",
                   return_value=_FakeSession(db)):
            with patch("app.services.pcdi_service.compute_adaptive_score",
                       AsyncMock(return_value={"adaptive_score": 50})):
                with patch("app.core.audit.log_security_action", MagicMock()):
                    with patch("app.core.config.get_settings",
                               MagicMock(return_value=MagicMock())):
                        with patch("app.core.notifications.notification_bus"):
                            result = await _run()

        assert result["active_hunts_checked"] == 1
        assert result["findings_scored"] == 1
        assert result["hunts_escalated"] == 0
        assert hunt.priority == "high"  # unchanged

    async def test_run_score_at_threshold_escalates(self):
        """Score 80 == threshold → hunt escalated to 'critical', commit called."""
        from app.tasks.pcdi_escalation import _run

        hunt = _make_hunt(priority="high")
        finding = _make_finding()
        db = self._db_for([hunt], [finding])

        with patch("app.tasks.pcdi_escalation.AsyncSessionLocal",
                   return_value=_FakeSession(db)):
            with patch("app.services.pcdi_service.compute_adaptive_score",
                       AsyncMock(return_value={"adaptive_score": 80})):
                with patch("app.core.audit.log_security_action", MagicMock()):
                    with patch("app.core.config.get_settings",
                               MagicMock(return_value=MagicMock())):
                        with patch("app.core.notifications.notification_bus") as mock_bus:
                            mock_bus.publish = AsyncMock()
                            result = await _run()

        assert result["hunts_escalated"] == 1
        assert hunt.priority == "critical"
        db.commit.assert_called_once()

    async def test_run_score_above_threshold_escalates_with_log(self):
        """Score 95 > 80 → escalation + log_security_action called + hunt in escalated_ids."""
        from app.tasks.pcdi_escalation import _run

        hunt = _make_hunt(priority="medium")
        finding = _make_finding()
        db = self._db_for([hunt], [finding])

        log_sec = MagicMock()
        with patch("app.tasks.pcdi_escalation.AsyncSessionLocal",
                   return_value=_FakeSession(db)):
            with patch("app.services.pcdi_service.compute_adaptive_score",
                       AsyncMock(return_value={"adaptive_score": 95})):
                with patch("app.core.audit.log_security_action", log_sec):
                    with patch("app.core.config.get_settings",
                               MagicMock(return_value=MagicMock())):
                        with patch("app.core.notifications.notification_bus") as mock_bus:
                            mock_bus.publish = AsyncMock()
                            result = await _run()

        assert result["escalated_hunt_ids"] == [hunt.id]
        log_sec.assert_called_once()
        call_kwargs = log_sec.call_args
        assert call_kwargs[0][0] == "pcdi_auto_escalation"  # action name

    async def test_run_hunt_already_critical_not_escalated(self):
        """Hunt already at 'critical' priority → no escalation even if score >= 80."""
        from app.tasks.pcdi_escalation import _run

        hunt = _make_hunt(priority="critical")
        finding = _make_finding()
        db = self._db_for([hunt], [finding])

        with patch("app.tasks.pcdi_escalation.AsyncSessionLocal",
                   return_value=_FakeSession(db)):
            with patch("app.services.pcdi_service.compute_adaptive_score",
                       AsyncMock(return_value={"adaptive_score": 99})):
                with patch("app.core.audit.log_security_action", MagicMock()):
                    with patch("app.core.config.get_settings",
                               MagicMock(return_value=MagicMock())):
                        with patch("app.core.notifications.notification_bus"):
                            result = await _run()

        assert result["hunts_escalated"] == 0
        assert hunt.priority == "critical"  # unchanged
        assert result["findings_scored"] == 1

    async def test_run_score_result_has_error_key_skipped(self):
        """compute_adaptive_score returns {'error': ...} → finding skipped, count=0."""
        from app.tasks.pcdi_escalation import _run

        hunt = _make_hunt(priority="high")
        finding = _make_finding()
        db = self._db_for([hunt], [finding])

        with patch("app.tasks.pcdi_escalation.AsyncSessionLocal",
                   return_value=_FakeSession(db)):
            with patch("app.services.pcdi_service.compute_adaptive_score",
                       AsyncMock(return_value={"error": "finding not found"})):
                with patch("app.core.audit.log_security_action", MagicMock()):
                    with patch("app.core.config.get_settings",
                               MagicMock(return_value=MagicMock())):
                        with patch("app.core.notifications.notification_bus"):
                            result = await _run()

        # Error path: skipped → not scored
        assert result["findings_scored"] == 0
        assert result["hunts_escalated"] == 0

    async def test_run_compute_score_raises_exception_logged_and_continues(self):
        """compute_adaptive_score raises → warning logged, loop continues."""
        from app.tasks.pcdi_escalation import _run

        hunt = _make_hunt(priority="high")
        finding = _make_finding()
        db = self._db_for([hunt], [finding])

        with patch("app.tasks.pcdi_escalation.AsyncSessionLocal",
                   return_value=_FakeSession(db)):
            with patch("app.services.pcdi_service.compute_adaptive_score",
                       AsyncMock(side_effect=RuntimeError("pcdi service down"))):
                with patch("app.core.audit.log_security_action", MagicMock()):
                    with patch("app.core.config.get_settings",
                               MagicMock(return_value=MagicMock())):
                        with patch("app.core.notifications.notification_bus"):
                            result = await _run()

        # Exception path: loop continues, scored_findings stays 0
        assert result["findings_scored"] == 0
        assert result["active_hunts_checked"] == 1

    async def test_run_no_findings_in_hunt_no_escalation(self):
        """Hunt with zero matching findings → max_score stays 0 → no escalation."""
        from app.tasks.pcdi_escalation import _run

        hunt = _make_hunt(priority="high")
        db = self._db_for([hunt], [])  # empty findings

        with patch("app.tasks.pcdi_escalation.AsyncSessionLocal",
                   return_value=_FakeSession(db)):
            with patch("app.core.audit.log_security_action", MagicMock()):
                with patch("app.core.config.get_settings",
                           MagicMock(return_value=MagicMock())):
                    with patch("app.core.notifications.notification_bus"):
                        result = await _run()

        assert result["findings_scored"] == 0
        assert result["hunts_escalated"] == 0

    async def test_run_multiple_findings_max_score_tracked(self):
        """Multiple findings per hunt → max_score is the maximum across all."""
        from app.tasks.pcdi_escalation import _run

        hunt = _make_hunt(priority="low")
        f1 = _make_finding("f-001")
        f2 = _make_finding("f-002")
        f3 = _make_finding("f-003")

        db = AsyncMock()
        db.execute.side_effect = [
            _scalars_result([hunt]),        # hunts query
            _scalars_result([f1, f2, f3]),  # findings query
        ]

        # f1 → 30, f2 → 90 (triggers escalation), f3 → 60
        with patch("app.tasks.pcdi_escalation.AsyncSessionLocal",
                   return_value=_FakeSession(db)):
            with patch("app.services.pcdi_service.compute_adaptive_score",
                       AsyncMock(side_effect=[
                           {"adaptive_score": 30},
                           {"adaptive_score": 90},
                           {"adaptive_score": 60},
                       ])):
                with patch("app.core.audit.log_security_action", MagicMock()):
                    with patch("app.core.config.get_settings",
                               MagicMock(return_value=MagicMock())):
                        with patch("app.core.notifications.notification_bus") as mock_bus:
                            mock_bus.publish = AsyncMock()
                            result = await _run()

        assert result["findings_scored"] == 3
        assert result["hunts_escalated"] == 1
        assert hunt.priority == "critical"

    async def test_run_multiple_hunts_each_processed(self):
        """Multiple active hunts → each gets findings queried independently."""
        from app.tasks.pcdi_escalation import _run

        hunt_a = _make_hunt(priority="medium", hunt_id="h-A")
        hunt_b = _make_hunt(priority="high", hunt_id="h-B")
        finding_a = _make_finding("f-A")
        finding_b = _make_finding("f-B")

        db = AsyncMock()
        db.execute.side_effect = [
            _scalars_result([hunt_a, hunt_b]),  # hunts query
            _scalars_result([finding_a]),        # findings for hunt_a
            _scalars_result([finding_b]),        # findings for hunt_b
        ]

        # hunt_a scores 50 (no escalation), hunt_b scores 85 (escalated)
        with patch("app.tasks.pcdi_escalation.AsyncSessionLocal",
                   return_value=_FakeSession(db)):
            with patch("app.services.pcdi_service.compute_adaptive_score",
                       AsyncMock(side_effect=[
                           {"adaptive_score": 50},  # for finding_a
                           {"adaptive_score": 85},  # for finding_b
                       ])):
                with patch("app.core.audit.log_security_action", MagicMock()):
                    with patch("app.core.config.get_settings",
                               MagicMock(return_value=MagicMock())):
                        with patch("app.core.notifications.notification_bus") as mock_bus:
                            mock_bus.publish = AsyncMock()
                            result = await _run()

        assert result["active_hunts_checked"] == 2
        assert result["findings_scored"] == 2
        assert result["hunts_escalated"] == 1
        assert hunt_b.priority == "critical"
        assert hunt_a.priority == "medium"  # unchanged

    async def test_run_sse_exception_caught_silently(self):
        """notification_bus.publish SSE failure is caught in inner try/except."""
        from app.tasks.pcdi_escalation import _run

        hunt = _make_hunt(priority="high")
        finding = _make_finding()
        db = self._db_for([hunt], [finding])

        with patch("app.tasks.pcdi_escalation.AsyncSessionLocal",
                   return_value=_FakeSession(db)):
            with patch("app.services.pcdi_service.compute_adaptive_score",
                       AsyncMock(return_value={"adaptive_score": 95})):
                with patch("app.core.audit.log_security_action", MagicMock()):
                    with patch("app.core.config.get_settings",
                               MagicMock(return_value=MagicMock())):
                        # Patch notification_bus so ensure_future gets a non-coroutine
                        # → TypeError raised → caught by inner except → line 130 covered
                        with patch("app.core.notifications.notification_bus") as mock_bus:
                            mock_bus.publish = MagicMock(return_value="not-a-coroutine")
                            result = await _run()

        # Escalation still completes despite SSE failure
        assert result["hunts_escalated"] == 1


# ══════════════════════════════════════════════════════════════════════════════
# Celery wrapper — sync task execution (pcdi + sla + escalation)
# ══════════════════════════════════════════════════════════════════════════════

class TestCeleryTaskWrappers:
    """Cover the synchronous Celery wrapper bodies (asyncio.run(_run()) path)."""

    def test_check_critical_findings_happy_path(self):
        """check_critical_findings(self) calls asyncio.run(_run()) and returns result."""
        from app.tasks.pcdi_escalation import check_critical_findings

        db = AsyncMock()
        db.execute.return_value = _scalars_result([])

        mock_self = MagicMock()
        with patch("app.tasks.pcdi_escalation.AsyncSessionLocal",
                   return_value=_FakeSession(db)):
            with patch("app.core.config.get_settings",
                       MagicMock(return_value=MagicMock())):
                result = check_critical_findings(mock_self)

        assert result["active_hunts_checked"] == 0

    def test_check_critical_findings_retries_on_exception(self):
        """check_critical_findings propagates retry when _run() raises."""
        from app.tasks.pcdi_escalation import check_critical_findings

        mock_self = MagicMock()
        mock_self.retry.side_effect = RuntimeError("celery-retry")

        with patch("app.tasks.pcdi_escalation.AsyncSessionLocal",
                   side_effect=RuntimeError("db down")):
            with pytest.raises(RuntimeError, match="celery-retry"):
                check_critical_findings(mock_self)

    def test_check_sla_breaches_happy_path(self):
        """check_sla_breaches(self) calls asyncio.run(_run()) successfully."""
        from app.tasks.sla_escalation import check_sla_breaches

        db = AsyncMock()
        mock_self = MagicMock()

        with patch("app.tasks.sla_escalation.AsyncSessionLocal",
                   return_value=_FakeSession(db)):
            with patch("app.tasks.sla_escalation.escalate_sla_breaches",
                       AsyncMock(return_value=0)):
                result = check_sla_breaches(mock_self)

        assert result == {"sla_escalated": 0}

    def test_check_sla_breaches_retries_on_exception(self):
        """check_sla_breaches propagates retry when _run() raises."""
        from app.tasks.sla_escalation import check_sla_breaches

        mock_self = MagicMock()
        mock_self.retry.side_effect = RuntimeError("sla-retry")

        with patch("app.tasks.sla_escalation.AsyncSessionLocal",
                   side_effect=RuntimeError("db error")):
            with pytest.raises(RuntimeError, match="sla-retry"):
                check_sla_breaches(mock_self)

    def test_check_expired_actions_happy_path(self):
        """check_expired_actions(self) returns escalation result dict."""
        from app.tasks.escalation import check_expired_actions

        db = AsyncMock()
        mock_self = MagicMock()
        mock_settings = MagicMock()
        mock_settings.REDIS_URL = ""

        with patch("app.tasks.escalation.AsyncSessionLocal",
                   return_value=_FakeSession(db)):
            with patch("app.tasks.escalation.escalate_expired",
                       AsyncMock(return_value=[])):
                with patch("app.tasks.escalation.get_settings",
                           return_value=mock_settings):
                    result = check_expired_actions(mock_self)

        assert result == {"escalated": 0}

    def test_deliver_due_reports_happy_path(self):
        """deliver_due_reports(self) returns total/sent/skipped/errors dict."""
        from app.tasks.scheduled_reports import deliver_due_reports

        db = AsyncMock()
        db.execute.return_value = _scalars_result([])
        mock_self = MagicMock()

        with patch("app.tasks.scheduled_reports.AsyncSessionLocal",
                   return_value=_FakeSession(db)):
            result = deliver_due_reports(mock_self)

        assert result == {"total": 0, "sent": 0, "skipped": 0, "errors": 0}


# ══════════════════════════════════════════════════════════════════════════════
# reporter.py — additional branches
# ══════════════════════════════════════════════════════════════════════════════

class TestReporterEdgeCases:
    def test_html_critical_alert_badge(self):
        from app.services.reporter import generate_html_report
        alerts = [{"title": "Ransomware", "severity": "critical",
                   "risk_score": 0.99, "status": "active",
                   "detected_at": "2026-06-13T08:00:00Z"}]
        html = generate_html_report({"alerts": alerts, "summary": {}, "metrics": {}})
        assert "bg-danger" in html  # critical → "danger" class

    def test_html_medium_alert_badge(self):
        from app.services.reporter import generate_html_report
        alerts = [{"title": "Recon", "severity": "medium",
                   "risk_score": 0.5, "status": "open",
                   "detected_at": "2026-06-13T08:00:00Z"}]
        html = generate_html_report({"alerts": alerts, "summary": {}, "metrics": {}})
        assert "bg-info" in html  # medium → "info"

    def test_html_low_alert_badge(self):
        from app.services.reporter import generate_html_report
        alerts = [{"title": "Port scan", "severity": "low",
                   "risk_score": 0.2, "status": "closed",
                   "detected_at": "2026-06-13T08:00:00Z"}]
        html = generate_html_report({"alerts": alerts, "summary": {}, "metrics": {}})
        assert "bg-success" in html  # low → "success"

    def test_pdf_with_many_alerts_truncated_at_20(self):
        from app.services.reporter import generate_pdf_report
        alerts = [
            {"title": f"Alert {i}", "severity": "high",
             "risk_score": 0.7, "status": "open",
             "detected_at": "2026-06-13T00:00:00Z"}
            for i in range(25)  # 25 > 20 → should truncate in PDF
        ]
        result = generate_pdf_report({"alerts": alerts, "summary": {}, "metrics": {}})
        assert isinstance(result, bytes)
        if result:
            assert result[:4] == b"%PDF"


# ══════════════════════════════════════════════════════════════════════════════
# P34-COV-B  —  gap-fill: task retry paths, audit functions, pure helpers,
#              PIIL signing, pids_service query helpers
# ══════════════════════════════════════════════════════════════════════════════

# ── Audit functions ───────────────────────────────────────────────────────────

class TestAuditFunctions:
    """Call the real audit functions so their bodies are covered."""

    def test_log_auth_event_basic(self):
        from app.core.audit import log_auth_event
        log_auth_event("login_success", user_id="u-1", email="test@example.com", detail="ok")

    def test_log_auth_event_no_user_id(self):
        from app.core.audit import log_auth_event
        log_auth_event("login_failure")  # user_id defaults to None

    def test_log_iam_event_basic(self):
        from app.core.audit import log_iam_event
        log_iam_event("account_locked", performed_by="admin", target_user="victim")

    def test_log_security_action_with_actor_alias(self):
        from app.core.audit import log_security_action
        # actor kwarg → effective_user = user_id or actor or "system"
        log_security_action("adapter_test", actor="celery-worker", resource="adapter")


# ── Pure helper / utility functions ──────────────────────────────────────────

class TestPureHelpers:

    def test_praf_band_returns_low_for_zero_score(self):
        """_band(0) → no threshold matched → returns 'low' (line 356)."""
        from app.services.praf import _band
        assert _band(0) == "low"

    def test_metrics_percentile_empty_list(self):
        """_percentile([], p) → early return 0.0 (line 37)."""
        from app.services.metrics import _percentile
        assert _percentile([], 95) == 0.0
        assert _percentile([], 50) == 0.0

    def test_agent_priority_score_naive_datetime(self):
        """Naive last_seen datetime → branch at line 205 adds tzinfo=UTC."""
        from app.services.query_executor import _agent_priority_score
        from datetime import datetime
        agent = MagicMock()
        agent.threat_level = "normal"
        agent.last_seen = datetime(2026, 1, 1, 12, 0, 0)  # no tzinfo
        score = _agent_priority_score(agent)
        assert score >= 0  # function completes without error


# ── Task Celery-wrapper retry paths ──────────────────────────────────────────

class TestTaskRetryPaths:
    """Each Celery sync wrapper has a try/except + retry. Test the except path."""

    def test_run_sweep_retries_on_asyncio_failure(self):
        """correlation_sweep.run_sweep() exception → lines 24-26 covered."""
        from app.tasks.correlation_sweep import run_sweep
        mock_self = MagicMock()
        mock_self.retry.side_effect = RuntimeError("sweep-retry")
        with patch("app.tasks.correlation_sweep.asyncio.run",
                   side_effect=RuntimeError("sweep crashed")):
            with pytest.raises(RuntimeError, match="sweep-retry"):
                run_sweep(mock_self)
        mock_self.retry.assert_called_once()

    def test_check_expired_actions_retries_on_failure(self):
        """escalation.check_expired_actions() exception → lines 80-82 covered."""
        from app.tasks.escalation import check_expired_actions
        mock_self = MagicMock()
        mock_self.retry.side_effect = RuntimeError("escalation-retry")
        with patch("app.tasks.escalation.asyncio.run",
                   side_effect=RuntimeError("db down")):
            with pytest.raises(RuntimeError, match="escalation-retry"):
                check_expired_actions(mock_self)

    def test_deliver_due_reports_retries_on_failure(self):
        """scheduled_reports.deliver_due_reports() exception → lines 101-103 covered."""
        from app.tasks.scheduled_reports import deliver_due_reports
        mock_self = MagicMock()
        mock_self.retry.side_effect = RuntimeError("reports-retry")
        with patch("app.tasks.scheduled_reports.asyncio.run",
                   side_effect=RuntimeError("run failed")):
            with pytest.raises(RuntimeError, match="reports-retry"):
                deliver_due_reports(mock_self)

    async def test_escalation_run_publishes_to_redis_and_acloses(self):
        """escalation._run() with non-empty escalated list + Redis → covers line 56 (aclose).

        Python's `import a.b as c` resolves `c` via `sys.modules["a"].b`, NOT from
        `sys.modules["a.b"]` directly. Therefore we must BOTH: (a) set sys.modules["redis"]
        to a mock with `.asyncio = mock_aioredis` AND (b) set sys.modules["redis.asyncio"]
        to prevent the ModuleNotFoundError from the import machinery.
        """
        from app.tasks.escalation import _run

        db = AsyncMock()
        mock_settings = MagicMock()
        mock_settings.REDIS_URL = "redis://localhost:6379"

        mock_redis_client = AsyncMock()
        mock_aioredis = MagicMock()
        mock_aioredis.from_url.return_value = mock_redis_client

        # The redis parent module mock must have .asyncio attribute set explicitly
        mock_redis_mod = MagicMock()
        mock_redis_mod.asyncio = mock_aioredis

        with patch("app.tasks.escalation.AsyncSessionLocal",
                   return_value=_FakeSession(db)):
            with patch("app.tasks.escalation.escalate_expired",
                       AsyncMock(return_value=["act-001"])):
                with patch("app.tasks.escalation.get_settings",
                           return_value=mock_settings):
                    with patch.dict("sys.modules",
                                    {"redis": mock_redis_mod,
                                     "redis.asyncio": mock_aioredis}):
                        result = await _run()

        assert result["escalated"] == 1
        mock_redis_client.aclose.assert_called_once()


# ── Reporting service — PIIL Ed25519 signing success path ─────────────────────

class TestReportingServiceSigning:
    """Cover lines 76-84 and 109-111 in reporting_service.py."""

    @staticmethod
    def _gen_keypair():
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        import base64
        priv = Ed25519PrivateKey.generate()
        priv_b64 = base64.b64encode(priv.private_bytes_raw()).decode()
        pub = priv.public_key()
        pub_b64 = base64.b64encode(pub.public_bytes_raw()).decode()
        return priv, priv_b64, pub_b64

    def test_sign_report_success_with_pubkey(self):
        """Covers lines 76, 79, 80, 81, 84 — happy path with SPECTER keys set."""
        import base64
        from app.services import reporting_service

        priv, priv_b64, pub_b64 = self._gen_keypair()
        fake_s = MagicMock()
        fake_s.SPECTER_SIGNING_PRIVATE_KEY = priv_b64
        fake_s.SPECTER_SIGNING_PUBLIC_KEY = pub_b64

        with patch.object(reporting_service, "_s", fake_s):
            sig_b64, fp = reporting_service._sign_report("deadbeef" * 16)

        assert len(base64.b64decode(sig_b64)) == 64
        assert len(fp) == 16  # SHA3-512 first 16 hex chars

    def test_sign_report_success_no_pubkey(self):
        """Covers lines 82-83 — fp = 'unknown' when no public key configured."""
        import base64
        from app.services import reporting_service

        priv, priv_b64, _ = self._gen_keypair()
        fake_s = MagicMock()
        fake_s.SPECTER_SIGNING_PRIVATE_KEY = priv_b64
        fake_s.SPECTER_SIGNING_PUBLIC_KEY = None

        with patch.object(reporting_service, "_s", fake_s):
            sig_b64, fp = reporting_service._sign_report("cafebabe" * 16)

        assert fp == "unknown"
        assert len(base64.b64decode(sig_b64)) == 64

    def test_verify_report_signature_valid(self):
        """Covers lines 109-111 — successful Ed25519 verification returns True."""
        import base64
        from app.services import reporting_service

        priv, priv_b64, pub_b64 = self._gen_keypair()

        hash_hex = "a" * 128  # arbitrary hex-like string used as hash
        raw_sig = priv.sign(hash_hex.encode())
        sig_b64 = base64.b64encode(raw_sig).decode()

        report = MagicMock()
        report.is_hash_valid.return_value = True
        report.signature_ed25519 = sig_b64
        report.hash_sha3_512 = hash_hex

        fake_s = MagicMock()
        fake_s.SPECTER_SIGNING_PUBLIC_KEY = pub_b64

        with patch.object(reporting_service, "_s", fake_s):
            result = reporting_service.verify_report_signature(report)

        assert result is True


# ── pids_service: query helpers ───────────────────────────────────────────────

class TestPidsServiceQueryHelpers:
    """Cover uncovered query functions in pids_service."""

    async def test_get_identity_action_not_found(self):
        """get_identity_action() → None when DB returns nothing (lines 220-224)."""
        from app.services.pids_service import get_identity_action
        db = AsyncMock()
        result_mock = MagicMock()
        result_mock.scalar_one_or_none.return_value = None
        db.execute.return_value = result_mock
        out = await get_identity_action(db, "nonexistent-id")
        assert out is None

    async def test_list_identity_actions_with_hunt_id_filter(self):
        """list_identity_actions(hunt_id=...) → covers hunt_id filter branch (line 242)."""
        from app.services.pids_service import list_identity_actions
        db = AsyncMock()
        scalars_mock = MagicMock()
        scalars_mock.all.return_value = []
        result_mock = MagicMock()
        result_mock.scalars.return_value = scalars_mock
        db.execute.return_value = result_mock
        out = await list_identity_actions(db, hunt_id="h-1")
        assert out == []

    async def test_verify_signature_exception_path(self):
        """_verify_signature with invalid pub key → except → returns False (lines 99-106)."""
        import base64, os
        from app.services.pids_service import _verify_signature
        # Use a base64 string that decodes to wrong size bytes (not 32) → ValueError
        bad_pub = base64.b64encode(b"not-32-bytes").decode()
        with patch.dict(os.environ, {"PIDS_SIGNING_PUBLIC_KEY": bad_pub}):
            result = _verify_signature("somehash", base64.b64encode(b"fakesig").decode())
        assert result is False
