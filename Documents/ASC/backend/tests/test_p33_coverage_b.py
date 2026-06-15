"""
P33 Coverage B — second wave targeting remaining gaps

Targets pushing total coverage from 82.20% toward ≥85%:

1. reporter.py        — _severity_color, generate_html_report, generate_pdf_report
2. scheduled_reports  — _is_due (pure), _run (mocked AsyncSessionLocal)
3. escalation         — _run (mocked)
4. sla_escalation     — _run (mocked)
5. correlation_sweep  — _async_sweep (mocked lazy imports at source)
6. pcdi_escalation    — _run (mocked, empty active_hunts path)
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ─── Celery stub ──────────────────────────────────────────────────────────────
# celery==5.4.0 is in requirements.txt but may not be installed in the local venv
# (runs inside Docker in production). Install a faithful stub so:
#   1. Task modules import without the real package.
#   2. Existing celery-aware tests (test_p27 etc.) still pass when they
#      access celery_app.conf.include, .beat_schedule, task.name, etc.
# No-op if celery IS already installed.

class _FakeCeleryConf:
    """Stores config passed via Celery() constructor + conf.update()."""

    def __init__(self, include):
        self.include = list(include) if include else []
        self.beat_schedule = {}
        # keep remaining config so attribute access doesn't raise
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
    """Minimal Celery app replacement that records tasks and config."""

    def __init__(self, name="", broker=None, backend=None, include=None, **kw):
        self.main = name          # mirrors real Celery.main attribute
        self.conf = _FakeCeleryConf(include)
        self.tasks: dict = {}

    def task(self, *args, **kwargs):
        """Decorator factory: sets fn.name and fn.delay = no-op."""
        def decorator(fn):
            fn.name = kwargs.get("name", fn.__qualname__)
            fn.delay = lambda *a, **kw: None
            self.tasks[fn.name] = fn
            return fn
        return decorator


class _FakeCeleryStub:
    """Top-level 'celery' module replacement."""
    Celery = _FakeCeleryApp


if "celery" not in sys.modules:
    sys.modules["celery"] = _FakeCeleryStub()  # type: ignore[assignment]
    sys.modules.setdefault("celery.schedules", MagicMock())
    sys.modules.setdefault("celery.utils.log", MagicMock())


# ─── Shared helpers ────────────────────────────────────────────────────────────

class _FakeSession:
    """Minimal async context-manager that yields a pre-built mock DB."""

    def __init__(self, mock_db: AsyncMock):
        self._db = mock_db

    async def __aenter__(self) -> AsyncMock:
        return self._db

    async def __aexit__(self, *_):
        return False


def _scalars_result(rows: list) -> MagicMock:
    """Return a MagicMock shaped like a SQLAlchemy execute() result."""
    result = MagicMock()
    scalars = MagicMock()
    scalars.all.return_value = rows
    result.scalars.return_value = scalars
    return result


def _async_db(rows: list | None = None) -> AsyncMock:
    """Return an AsyncMock DB whose execute() returns _scalars_result(rows)."""
    db = AsyncMock()
    db.execute.return_value = _scalars_result(rows if rows is not None else [])
    return db


# ══════════════════════════════════════════════════════════════════════════════
# 1. REPORTER — pure functions + PDF/HTML generation
# ══════════════════════════════════════════════════════════════════════════════

class TestReporterSeverityColor:
    def test_critical_returns_red(self):
        from app.services.reporter import _severity_color
        r, g, b = _severity_color("critical")
        assert r > 0.8 and g < 0.2

    def test_high_returns_orange(self):
        from app.services.reporter import _severity_color
        r, g, b = _severity_color("high")
        assert r > 0.8 and 0.3 < g < 0.6

    def test_medium_returns_yellow(self):
        from app.services.reporter import _severity_color
        r, g, b = _severity_color("medium")
        assert r > 0.8 and g > 0.6

    def test_low_returns_green(self):
        from app.services.reporter import _severity_color
        r, g, b = _severity_color("low")
        assert g > r

    def test_unknown_returns_grey(self):
        from app.services.reporter import _severity_color
        r, g, b = _severity_color("informational")
        assert r == g == b == 0.5

    def test_case_insensitive(self):
        from app.services.reporter import _severity_color
        assert _severity_color("CRITICAL") == _severity_color("critical")


class TestGenerateHtmlReport:
    _BASE = {
        "report_id": "RPT-001",
        "analyst":   "soc@premoscorp.com",
        "period":    "2026-06-01 / 2026-06-12",
        "summary": {
            "total_alerts": 10, "critical_count": 3,
            "risk_posture": "HIGH", "total_events": 500,
        },
        "metrics": {
            "mttd_minutes": 15, "mttr_minutes": 60,
            "total_events": 500, "total_alerts": 10,
            "true_positives": 8, "fp_rate": 0.05,
            "ioc_coverage": 0.80, "endpoint_coverage": 0.90,
        },
        "alerts": [],
    }

    def _data(self, alerts=None):
        d = dict(self._BASE)
        if alerts is not None:
            d = {**d, "alerts": alerts}
        return d

    def test_returns_string(self):
        from app.services.reporter import generate_html_report
        assert isinstance(generate_html_report(self._data()), str)

    def test_doctype_present(self):
        from app.services.reporter import generate_html_report
        assert "<!DOCTYPE html>" in generate_html_report(self._data())

    def test_premoscorp_branding(self):
        from app.services.reporter import generate_html_report
        assert "PremosCorp" in generate_html_report(self._data())

    def test_asc_heading(self):
        from app.services.reporter import generate_html_report
        assert "Advanced Security Center" in generate_html_report(self._data())

    def test_total_alerts_rendered(self):
        from app.services.reporter import generate_html_report
        assert "10" in generate_html_report(self._data())

    def test_mttd_in_metrics(self):
        from app.services.reporter import generate_html_report
        assert "15" in generate_html_report(self._data())

    def test_alert_title_rendered(self):
        from app.services.reporter import generate_html_report
        alerts = [
            {"title": "Mimikatz Detected", "severity": "critical",
             "risk_score": 0.97, "status": "active",
             "detected_at": "2026-06-12T10:00:00Z"},
        ]
        html = generate_html_report(self._data(alerts=alerts))
        assert "Mimikatz Detected" in html

    def test_alert_badge_class_high(self):
        from app.services.reporter import generate_html_report
        alerts = [
            {"title": "Test Alert", "severity": "high",
             "risk_score": 0.8, "status": "open",
             "detected_at": "2026-06-12T00:00:00Z"},
        ]
        html = generate_html_report(self._data(alerts=alerts))
        # severity "high" → sev_class = "warning" → bootstrap badge bg-warning
        assert "bg-warning" in html

    def test_empty_alerts_no_error(self):
        from app.services.reporter import generate_html_report
        html = generate_html_report(self._data(alerts=[]))
        assert "<!DOCTYPE html>" in html

    def test_missing_data_keys_no_error(self):
        from app.services.reporter import generate_html_report
        html = generate_html_report({})
        assert isinstance(html, str)
        assert "N/A" in html  # mttd/mttr fallback

    def test_confidential_footer(self):
        from app.services.reporter import generate_html_report
        assert "CONFIDENTIAL" in generate_html_report(self._data())


class TestGeneratePdfReport:
    _DATA = {
        "report_id": "RPT-PDF-001",
        "analyst":   "analyst@premoscorp.com",
        "period":    "2026-06-01 to 2026-06-12",
        "summary":   {"total_alerts": 5, "critical_count": 2,
                      "risk_posture": "HIGH", "total_events": 200},
        "metrics":   {"mttd_minutes": 12, "mttr_minutes": 45,
                      "total_events": 200, "total_alerts": 5,
                      "true_positives": 4, "fp_rate": 0.10,
                      "ioc_coverage": 0.75, "endpoint_coverage": 0.88},
        "alerts": [
            {"title": "Cobalt Strike Beacon", "severity": "critical",
             "risk_score": 0.98, "status": "active",
             "detected_at": "2026-06-12T08:00:00Z"},
        ],
    }

    def test_returns_bytes(self):
        from app.services.reporter import generate_pdf_report
        assert isinstance(generate_pdf_report(self._DATA), bytes)

    def test_pdf_header_magic_bytes(self):
        from app.services.reporter import generate_pdf_report
        result = generate_pdf_report(self._DATA)
        if result:  # non-empty only when reportlab is installed
            assert result[:4] == b"%PDF"

    def test_empty_alerts_no_error(self):
        from app.services.reporter import generate_pdf_report
        data = {**self._DATA, "alerts": []}
        assert isinstance(generate_pdf_report(data), bytes)

    def test_missing_fields_no_error(self):
        from app.services.reporter import generate_pdf_report
        assert isinstance(generate_pdf_report({}), bytes)

    def test_multiple_alerts(self):
        from app.services.reporter import generate_pdf_report
        data = {**self._DATA, "alerts": [
            {"title": f"Alert {i}", "severity": "high",
             "risk_score": 0.7, "status": "open",
             "detected_at": "2026-06-12T00:00:00Z"}
            for i in range(5)
        ]}
        assert isinstance(generate_pdf_report(data), bytes)


# ══════════════════════════════════════════════════════════════════════════════
# 2. SCHEDULED REPORTS — _is_due pure function + _run mocked
# ══════════════════════════════════════════════════════════════════════════════

class TestScheduledReportIsDue:
    def test_none_last_sent_always_due(self):
        from app.tasks.scheduled_reports import _is_due
        assert _is_due(None, "daily") is True
        assert _is_due(None, "weekly") is True

    def test_recent_daily_not_due(self):
        from app.tasks.scheduled_reports import _is_due
        last = datetime.now(timezone.utc) - timedelta(hours=1)
        assert _is_due(last, "daily") is False

    def test_old_daily_is_due(self):
        from app.tasks.scheduled_reports import _is_due
        last = datetime.now(timezone.utc) - timedelta(hours=25)
        assert _is_due(last, "daily") is True

    def test_recent_weekly_not_due(self):
        from app.tasks.scheduled_reports import _is_due
        last = datetime.now(timezone.utc) - timedelta(days=3)
        assert _is_due(last, "weekly") is False

    def test_old_weekly_is_due(self):
        from app.tasks.scheduled_reports import _is_due
        last = datetime.now(timezone.utc) - timedelta(days=8)
        assert _is_due(last, "weekly") is True

    def test_naive_datetime_handled(self):
        from app.tasks.scheduled_reports import _is_due
        # SQLite returns naive datetimes; _is_due normalises them
        last = datetime.utcnow() - timedelta(hours=25)
        assert _is_due(last, "daily") is True

    def test_exactly_at_24h_boundary_is_due(self):
        from app.tasks.scheduled_reports import _is_due
        last = datetime.now(timezone.utc) - timedelta(hours=24)
        assert _is_due(last, "daily") is True  # >= 24h → due

    def test_exactly_at_7day_boundary_is_due(self):
        from app.tasks.scheduled_reports import _is_due
        last = datetime.now(timezone.utc) - timedelta(days=7)
        assert _is_due(last, "weekly") is True


class TestScheduledReportsRun:
    async def test_run_no_reports(self):
        from app.tasks.scheduled_reports import _run

        db = _async_db([])
        with patch("app.tasks.scheduled_reports.AsyncSessionLocal",
                   return_value=_FakeSession(db)):
            result = await _run()

        assert result == {"total": 0, "sent": 0, "skipped": 0, "errors": 0}

    async def test_run_skips_non_due_report(self):
        from app.tasks.scheduled_reports import _run

        report = MagicMock()
        report.id = "rpt-skip"
        report.enabled = True
        report.frequency = "daily"
        report.last_sent_at = datetime.now(timezone.utc) - timedelta(hours=1)
        report.recipient_email = "soc@premoscorp.com"

        db = _async_db([report])
        with patch("app.tasks.scheduled_reports.AsyncSessionLocal",
                   return_value=_FakeSession(db)):
            result = await _run()

        assert result["skipped"] == 1
        assert result["sent"] == 0

    async def test_run_delivers_due_report(self):
        from app.tasks.scheduled_reports import _run

        report = MagicMock()
        report.id = "rpt-due"
        report.enabled = True
        report.frequency = "daily"
        report.last_sent_at = datetime.now(timezone.utc) - timedelta(hours=26)
        report.recipient_email = "soc@premoscorp.com"

        db = _async_db([report])
        # deliver_scheduled_report is lazily imported inside _run() from soar_service
        with patch("app.tasks.scheduled_reports.AsyncSessionLocal",
                   return_value=_FakeSession(db)):
            with patch("app.services.soar_service.deliver_scheduled_report",
                       AsyncMock(return_value={"status": "delivered"})):
                result = await _run()

        assert result["sent"] == 1
        assert result["errors"] == 0

    async def test_run_counts_delivery_errors(self):
        from app.tasks.scheduled_reports import _run

        report = MagicMock()
        report.id = "rpt-err"
        report.enabled = True
        report.frequency = "weekly"
        report.last_sent_at = datetime.now(timezone.utc) - timedelta(days=8)
        report.recipient_email = "soc@premoscorp.com"

        db = _async_db([report])
        with patch("app.tasks.scheduled_reports.AsyncSessionLocal",
                   return_value=_FakeSession(db)):
            with patch("app.services.soar_service.deliver_scheduled_report",
                       AsyncMock(return_value={"error": "SMTP timeout"})):
                result = await _run()

        assert result["errors"] == 1
        assert result["sent"] == 0

    async def test_run_handles_exception_per_report(self):
        from app.tasks.scheduled_reports import _run

        report = MagicMock()
        report.id = "rpt-exc"
        report.enabled = True
        report.frequency = "daily"
        report.last_sent_at = datetime.now(timezone.utc) - timedelta(hours=25)
        report.recipient_email = "x@y.com"

        db = _async_db([report])
        with patch("app.tasks.scheduled_reports.AsyncSessionLocal",
                   return_value=_FakeSession(db)):
            with patch("app.services.soar_service.deliver_scheduled_report",
                       AsyncMock(side_effect=RuntimeError("connection lost"))):
                result = await _run()

        assert result["errors"] == 1


# ══════════════════════════════════════════════════════════════════════════════
# 3. ESCALATION — _run mocked
# ══════════════════════════════════════════════════════════════════════════════

class TestEscalationRun:
    async def test_run_no_expired_returns_zero(self):
        from app.tasks.escalation import _run

        db = _async_db()
        with patch("app.tasks.escalation.AsyncSessionLocal",
                   return_value=_FakeSession(db)):
            with patch("app.tasks.escalation.escalate_expired",
                       AsyncMock(return_value=[])):
                result = await _run()

        assert result == {"escalated": 0}

    async def test_run_with_escalated_ids_no_redis(self):
        from app.tasks.escalation import _run

        action_ids = ["aa-111", "bb-222", "cc-333"]
        db = _async_db()
        mock_settings = MagicMock()
        mock_settings.REDIS_URL = ""  # empty → skip Redis publish block

        with patch("app.tasks.escalation.AsyncSessionLocal",
                   return_value=_FakeSession(db)):
            with patch("app.tasks.escalation.escalate_expired",
                       AsyncMock(return_value=action_ids)):
                with patch("app.tasks.escalation.get_settings",
                           return_value=mock_settings):
                    result = await _run()

        assert result["escalated"] == 3
        assert set(result["action_ids"]) == set(action_ids)

    async def test_run_redis_failure_is_non_fatal(self):
        """Redis connection error is caught; task still returns escalated count."""
        from app.tasks.escalation import _run

        db = _async_db()
        mock_settings = MagicMock()
        mock_settings.REDIS_URL = "redis://localhost:6379/0"

        mock_aioredis = MagicMock()
        mock_aioredis.from_url.side_effect = RuntimeError("connection refused")

        with patch("app.tasks.escalation.AsyncSessionLocal",
                   return_value=_FakeSession(db)):
            with patch("app.tasks.escalation.escalate_expired",
                       AsyncMock(return_value=["id-x"])):
                with patch("app.tasks.escalation.get_settings",
                           return_value=mock_settings):
                    with patch.dict("sys.modules",
                                   {"redis": MagicMock(),
                                    "redis.asyncio": mock_aioredis}):
                        result = await _run()

        assert result["escalated"] == 1


# ══════════════════════════════════════════════════════════════════════════════
# 4. SLA ESCALATION — _run mocked
# ══════════════════════════════════════════════════════════════════════════════

class TestSlaEscalationRun:
    async def test_run_no_breaches(self):
        from app.tasks.sla_escalation import _run

        db = _async_db()
        with patch("app.tasks.sla_escalation.AsyncSessionLocal",
                   return_value=_FakeSession(db)):
            with patch("app.tasks.sla_escalation.escalate_sla_breaches",
                       AsyncMock(return_value=0)):
                result = await _run()

        assert result == {"sla_escalated": 0}

    async def test_run_with_breaches(self):
        from app.tasks.sla_escalation import _run

        db = _async_db()
        with patch("app.tasks.sla_escalation.AsyncSessionLocal",
                   return_value=_FakeSession(db)):
            with patch("app.tasks.sla_escalation.escalate_sla_breaches",
                       AsyncMock(return_value=5)):
                result = await _run()

        assert result == {"sla_escalated": 5}


# ══════════════════════════════════════════════════════════════════════════════
# 5. CORRELATION SWEEP — _async_sweep (lazy imports; patch at source modules)
# ══════════════════════════════════════════════════════════════════════════════

class TestCorrelationSweepRun:
    async def test_async_sweep_calls_run_correlation_sweep(self):
        from app.tasks.correlation_sweep import _async_sweep

        db = _async_db()
        stats = {"clusters_created": 2, "signals_processed": 45}

        # _async_sweep lazy-imports both symbols; patch at their source modules
        with patch("app.db.session.AsyncSessionLocal",
                   return_value=_FakeSession(db)):
            with patch("app.services.correlation_service.run_correlation_sweep",
                       AsyncMock(return_value=stats)):
                await _async_sweep()  # must not raise

    async def test_async_sweep_empty_stats(self):
        from app.tasks.correlation_sweep import _async_sweep

        db = _async_db()
        with patch("app.db.session.AsyncSessionLocal",
                   return_value=_FakeSession(db)):
            with patch("app.services.correlation_service.run_correlation_sweep",
                       AsyncMock(return_value={})):
                await _async_sweep()


# ══════════════════════════════════════════════════════════════════════════════
# 6. PCDI ESCALATION — _run with empty active_hunts (short-circuit path)
# ══════════════════════════════════════════════════════════════════════════════

class TestPcdiEscalationRun:
    async def test_run_no_active_hunts(self):
        """Zero active hunts → no scoring, no escalations."""
        from app.tasks.pcdi_escalation import _run

        db = _async_db([])  # execute() → scalars().all() = []
        with patch("app.tasks.pcdi_escalation.AsyncSessionLocal",
                   return_value=_FakeSession(db)):
            result = await _run()

        assert isinstance(result, dict)
        assert result["active_hunts_checked"] == 0
        assert result["findings_scored"] == 0
        assert result["hunts_escalated"] == 0
        assert result["escalated_hunt_ids"] == []

    async def test_run_returns_all_expected_keys(self):
        from app.tasks.pcdi_escalation import _run

        db = _async_db([])
        with patch("app.tasks.pcdi_escalation.AsyncSessionLocal",
                   return_value=_FakeSession(db)):
            result = await _run()

        expected_keys = {"active_hunts_checked", "findings_scored",
                         "hunts_escalated", "escalated_hunt_ids"}
        assert expected_keys.issubset(set(result.keys()))
