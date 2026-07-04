"""
P30-COMPLETE â€” SOAR â†” Incident Integration â€” Full Test Suite
=============================================================
Covers:
  TestSlaEscalationCeleryTask     (20) â€” task registration, beat schedule, config,
                                         async runner, retry policy, return value
  TestPiilBindingEndpoint         (20) â€” GET /incidents/{id}/piil-binding: 404, 200,
                                         response shape, auth, item fields, limit param
  TestSoarEventsEndpoint          (20) â€” GET /incidents/{id}/soar-events: 404, 200,
                                         response shape, auth, item fields, limit param
  TestSerializerFe                (12) â€” _fe() serializer: all expected fields present
  TestIncidentsModuleIntegration  (12) â€” imports, route registration, router prefix,
                                         docstring correctness, new route paths
  TestCeleryAppAndConfig          (10) â€” celery includes, beat schedule keys/values,
                                         config field defaults, interval math

Total: 94 tests
"""
from __future__ import annotations

import asyncio
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


# â”€â”€ Mini helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _make_incident(**kw):
    from asc_api.models.incident import Incident
    i = Incident()
    i.id = kw.get("id", str(uuid.uuid4()))
    i.title = kw.get("title", "Test Incident")
    i.description = kw.get("description", None)
    i.incident_type = kw.get("incident_type", "malware")
    i.status = kw.get("status", "detected")
    i.nist_phase = kw.get("nist_phase", "detection_analysis")
    i.severity = kw.get("severity", "high")
    i.risk_score = kw.get("risk_score", 0.8)
    i.created_by = kw.get("created_by", "analyst@premos.com")
    i.assigned_to = kw.get("assigned_to", None)
    i.mitre_tactics = kw.get("mitre_tactics", [])
    i.mitre_techniques = kw.get("mitre_techniques", [])
    i.tags = kw.get("tags", [])
    i.executive_summary = kw.get("executive_summary", None)
    i.lessons_learned = kw.get("lessons_learned", None)
    i.root_cause = kw.get("root_cause", None)
    i.false_positive = kw.get("false_positive", False)
    i.sla_minutes = kw.get("sla_minutes", 1440)
    i.sla_breach = kw.get("sla_breach", False)
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    i.detected_at = kw.get("detected_at", now)
    i.triaged_at = kw.get("triaged_at", None)
    i.contained_at = kw.get("contained_at", None)
    i.eradicated_at = kw.get("eradicated_at", None)
    i.recovered_at = kw.get("recovered_at", None)
    i.closed_at = kw.get("closed_at", None)
    i.mttd_minutes = kw.get("mttd_minutes", None)
    i.mttc_minutes = kw.get("mttc_minutes", None)
    i.mttr_minutes = kw.get("mttr_minutes", None)
    i.forensic_hash = kw.get("forensic_hash", None)
    i.is_campaign = kw.get("is_campaign", False)
    i.created_at = kw.get("created_at", now)
    i.updated_at = kw.get("updated_at", now)
    return i


def _make_fe(**kw):
    from datetime import datetime, timezone
    ns = SimpleNamespace(
        id=kw.get("id", str(uuid.uuid4())),
        action_id=kw.get("action_id", str(uuid.uuid4())),
        action_type=kw.get("action_type", "piil_soar_binding"),
        target=kw.get("target", "incident:test:triaged"),
        canonical_data=kw.get("canonical_data", {"piil_version": "1.0"}),
        hash_sha3_512=kw.get("hash_sha3_512", "a" * 128),
        signature_ed25519=kw.get("signature_ed25519", "PIIL-UNSIGNED"),
        signed_by_email=kw.get("signed_by_email", "system"),
        signed_by_user_id=kw.get("signed_by_user_id", "system"),
        signed_at=kw.get("signed_at", datetime.now(timezone.utc)),
        verified=kw.get("verified", False),
        last_verified_at=kw.get("last_verified_at", None),
    )
    return ns


def _make_tl_entry(**kw):
    from datetime import datetime, timezone
    ns = SimpleNamespace(
        id=kw.get("id", str(uuid.uuid4())),
        incident_id=kw.get("incident_id", str(uuid.uuid4())),
        event_type=kw.get("event_type", "soar_triggered"),
        actor=kw.get("actor", "system:soar"),
        detail=kw.get("detail", {"trigger_name": "t1"}),
        created_at=kw.get("created_at", datetime.now(timezone.utc)),
    )
    return ns


def _mock_scalars(rows):
    result = MagicMock()
    sc = MagicMock()
    sc.all.return_value = rows
    result.scalars.return_value = sc
    return result


def _make_endpoint_app():
    from asc_api.api.v1.endpoints.incidents import router
    from asc_api.api.deps import get_analyst_or_admin, get_current_admin
    from asc_api.db.session import get_db
    from asc_api.models.user import User

    app = FastAPI()
    app.include_router(router)

    def _auth():
        u = MagicMock(spec=User)
        u.email = "analyst@premos.com"
        u.role = "analyst"
        return u

    app.dependency_overrides[get_analyst_or_admin] = _auth
    app.dependency_overrides[get_current_admin] = _auth
    app.dependency_overrides[get_db] = lambda: AsyncMock()
    return app


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TestSlaEscalationCeleryTask
# (Source-inspection approach â€” celery not installed in test env)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def _sla_src():
    import inspect, pathlib
    p = pathlib.Path(__file__).parent.parent / "asc_api" / "tasks" / "sla_escalation.py"
    return p.read_text(encoding="utf-8")


def _celery_app_src():
    import pathlib
    p = pathlib.Path(__file__).parent.parent / "asc_api" / "tasks" / "celery_app.py"
    return p.read_text(encoding="utf-8")


class TestSlaEscalationCeleryTask:

    def test_sla_escalation_file_exists(self):
        import pathlib
        p = pathlib.Path(__file__).parent.parent / "asc_api" / "tasks" / "sla_escalation.py"
        assert p.exists()

    def test_task_name_in_source(self):
        assert "asc.sla_escalation.check_sla_breaches" in _sla_src()

    def test_check_sla_breaches_function_defined(self):
        assert "def check_sla_breaches" in _sla_src()

    def test_run_async_function_defined(self):
        assert "async def _run" in _sla_src()

    def test_bind_true_in_source(self):
        assert "bind=True" in _sla_src()

    def test_max_retries_3_in_source(self):
        assert "max_retries=3" in _sla_src()

    def test_default_retry_delay_30_in_source(self):
        assert "default_retry_delay=30" in _sla_src()

    def test_asyncio_run_in_source(self):
        assert "asyncio.run" in _sla_src()

    def test_escalate_sla_breaches_imported(self):
        assert "escalate_sla_breaches" in _sla_src()

    def test_async_session_local_imported(self):
        assert "AsyncSessionLocal" in _sla_src()

    def test_self_retry_in_source(self):
        assert "self.retry" in _sla_src()

    def test_sla_escalated_key_in_source(self):
        assert "sla_escalated" in _sla_src()

    def test_celery_app_includes_sla_module(self):
        assert "app.tasks.sla_escalation" in _celery_app_src()

    def test_beat_schedule_sla_entry_in_source(self):
        assert "sla-breach-escalation" in _celery_app_src()

    def test_sla_interval_var_in_celery_source(self):
        assert "_SLA_INTERVAL" in _celery_app_src()

    def test_sla_task_name_in_beat_schedule(self):
        assert "asc.sla_escalation.check_sla_breaches" in _celery_app_src()

    def test_sla_config_default_is_120(self):
        from asc_api.core.config import Settings
        s = Settings()
        assert s.SLA_ESCALATION_CHECK_INTERVAL_SECONDS == 120

    def test_sla_config_is_int(self):
        from asc_api.core.config import Settings
        s = Settings()
        assert isinstance(s.SLA_ESCALATION_CHECK_INTERVAL_SECONDS, int)

    def test_five_tasks_in_celery_includes(self):
        assert _celery_app_src().count("app.tasks.") >= 5

    def test_celery_app_task_decorator_in_source(self):
        assert "celery_app.task" in _sla_src()


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TestPiilBindingEndpoint
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestPiilBindingEndpoint:

    def _client(self):
        return TestClient(_make_endpoint_app(), raise_server_exceptions=False)

    def test_returns_404_when_incident_not_found(self):
        client = self._client()
        with patch("asc_api.services.incident_service.get_incident",
                   new_callable=AsyncMock, return_value=None):
            r = client.get("/incidents/no-such-id/piil-binding")
        assert r.status_code == 404

    def test_returns_200_with_empty_list(self):
        inc = _make_incident()
        client = self._client()
        with patch("asc_api.services.incident_service.get_incident",
                   new_callable=AsyncMock, return_value=inc):
            with patch("asc_api.api.v1.endpoints.incidents.AsyncSession") as _:
                app_obj = _make_endpoint_app()
                app_obj.dependency_overrides.update({
                    **app_obj.dependency_overrides,
                })
                # Override get_db to return a real AsyncMock with execute
                db = AsyncMock()
                db.execute = AsyncMock(return_value=_mock_scalars([]))
                from asc_api.db.session import get_db
                app_obj.dependency_overrides[get_db] = lambda: db
                c = TestClient(app_obj, raise_server_exceptions=False)
                r = c.get(f"/incidents/{inc.id}/piil-binding")
        assert r.status_code == 200

    def test_response_has_incident_id(self):
        inc = _make_incident(id="inc-abc-123")
        app_obj = _make_endpoint_app()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([]))
        from asc_api.db.session import get_db
        app_obj.dependency_overrides[get_db] = lambda: db
        with patch("asc_api.services.incident_service.get_incident",
                   new_callable=AsyncMock, return_value=inc):
            c = TestClient(app_obj, raise_server_exceptions=False)
            r = c.get(f"/incidents/{inc.id}/piil-binding")
        assert r.json()["incident_id"] == "inc-abc-123"

    def test_response_has_items_list(self):
        inc = _make_incident()
        app_obj = _make_endpoint_app()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([]))
        from asc_api.db.session import get_db
        app_obj.dependency_overrides[get_db] = lambda: db
        with patch("asc_api.services.incident_service.get_incident",
                   new_callable=AsyncMock, return_value=inc):
            c = TestClient(app_obj, raise_server_exceptions=False)
            r = c.get(f"/incidents/{inc.id}/piil-binding")
        assert isinstance(r.json()["items"], list)

    def test_response_has_count_field(self):
        inc = _make_incident()
        app_obj = _make_endpoint_app()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([]))
        from asc_api.db.session import get_db
        app_obj.dependency_overrides[get_db] = lambda: db
        with patch("asc_api.services.incident_service.get_incident",
                   new_callable=AsyncMock, return_value=inc):
            c = TestClient(app_obj, raise_server_exceptions=False)
            r = c.get(f"/incidents/{inc.id}/piil-binding")
        assert "count" in r.json()

    def test_count_matches_items_length(self):
        inc = _make_incident()
        fe = _make_fe(action_id=inc.id)
        app_obj = _make_endpoint_app()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([fe]))
        from asc_api.db.session import get_db
        app_obj.dependency_overrides[get_db] = lambda: db
        with patch("asc_api.services.incident_service.get_incident",
                   new_callable=AsyncMock, return_value=inc):
            c = TestClient(app_obj, raise_server_exceptions=False)
            r = c.get(f"/incidents/{inc.id}/piil-binding")
        body = r.json()
        assert body["count"] == len(body["items"])

    def test_item_has_id(self):
        inc = _make_incident()
        fe = _make_fe(id="fe-001", action_id=inc.id)
        app_obj = _make_endpoint_app()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([fe]))
        from asc_api.db.session import get_db
        app_obj.dependency_overrides[get_db] = lambda: db
        with patch("asc_api.services.incident_service.get_incident",
                   new_callable=AsyncMock, return_value=inc):
            c = TestClient(app_obj, raise_server_exceptions=False)
            r = c.get(f"/incidents/{inc.id}/piil-binding")
        assert r.json()["items"][0]["id"] == "fe-001"

    def test_item_has_hash_sha3_512(self):
        inc = _make_incident()
        fe = _make_fe(action_id=inc.id, hash_sha3_512="b" * 128)
        app_obj = _make_endpoint_app()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([fe]))
        from asc_api.db.session import get_db
        app_obj.dependency_overrides[get_db] = lambda: db
        with patch("asc_api.services.incident_service.get_incident",
                   new_callable=AsyncMock, return_value=inc):
            c = TestClient(app_obj, raise_server_exceptions=False)
            r = c.get(f"/incidents/{inc.id}/piil-binding")
        assert r.json()["items"][0]["hash_sha3_512"] == "b" * 128

    def test_item_has_action_type(self):
        inc = _make_incident()
        fe = _make_fe(action_id=inc.id)
        app_obj = _make_endpoint_app()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([fe]))
        from asc_api.db.session import get_db
        app_obj.dependency_overrides[get_db] = lambda: db
        with patch("asc_api.services.incident_service.get_incident",
                   new_callable=AsyncMock, return_value=inc):
            c = TestClient(app_obj, raise_server_exceptions=False)
            r = c.get(f"/incidents/{inc.id}/piil-binding")
        assert r.json()["items"][0]["action_type"] == "piil_soar_binding"

    def test_item_has_verified_field(self):
        inc = _make_incident()
        fe = _make_fe(action_id=inc.id, verified=False)
        app_obj = _make_endpoint_app()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([fe]))
        from asc_api.db.session import get_db
        app_obj.dependency_overrides[get_db] = lambda: db
        with patch("asc_api.services.incident_service.get_incident",
                   new_callable=AsyncMock, return_value=inc):
            c = TestClient(app_obj, raise_server_exceptions=False)
            r = c.get(f"/incidents/{inc.id}/piil-binding")
        assert "verified" in r.json()["items"][0]

    def test_item_has_canonical_data(self):
        inc = _make_incident()
        fe = _make_fe(action_id=inc.id, canonical_data={"piil_version": "1.0", "triggers_fired": 3})
        app_obj = _make_endpoint_app()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([fe]))
        from asc_api.db.session import get_db
        app_obj.dependency_overrides[get_db] = lambda: db
        with patch("asc_api.services.incident_service.get_incident",
                   new_callable=AsyncMock, return_value=inc):
            c = TestClient(app_obj, raise_server_exceptions=False)
            r = c.get(f"/incidents/{inc.id}/piil-binding")
        assert r.json()["items"][0]["canonical_data"]["piil_version"] == "1.0"

    def test_item_has_signed_by_email(self):
        inc = _make_incident()
        fe = _make_fe(action_id=inc.id, signed_by_email="analyst@premos.com")
        app_obj = _make_endpoint_app()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([fe]))
        from asc_api.db.session import get_db
        app_obj.dependency_overrides[get_db] = lambda: db
        with patch("asc_api.services.incident_service.get_incident",
                   new_callable=AsyncMock, return_value=inc):
            c = TestClient(app_obj, raise_server_exceptions=False)
            r = c.get(f"/incidents/{inc.id}/piil-binding")
        assert r.json()["items"][0]["signed_by_email"] == "analyst@premos.com"

    def test_item_has_target(self):
        inc = _make_incident()
        fe = _make_fe(action_id=inc.id, target="incident:my-inc:triaged")
        app_obj = _make_endpoint_app()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([fe]))
        from asc_api.db.session import get_db
        app_obj.dependency_overrides[get_db] = lambda: db
        with patch("asc_api.services.incident_service.get_incident",
                   new_callable=AsyncMock, return_value=inc):
            c = TestClient(app_obj, raise_server_exceptions=False)
            r = c.get(f"/incidents/{inc.id}/piil-binding")
        assert r.json()["items"][0]["target"] == "incident:my-inc:triaged"

    def test_endpoint_accepts_limit_param(self):
        inc = _make_incident()
        app_obj = _make_endpoint_app()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([]))
        from asc_api.db.session import get_db
        app_obj.dependency_overrides[get_db] = lambda: db
        with patch("asc_api.services.incident_service.get_incident",
                   new_callable=AsyncMock, return_value=inc):
            c = TestClient(app_obj, raise_server_exceptions=False)
            r = c.get(f"/incidents/{inc.id}/piil-binding?limit=10")
        assert r.status_code == 200

    def test_unauthed_request_rejected(self):
        from asc_api.api.v1.endpoints.incidents import router
        from asc_api.db.session import get_db
        fresh_app = FastAPI()
        fresh_app.include_router(router)
        fresh_app.dependency_overrides[get_db] = lambda: AsyncMock()
        # No auth override â†’ get_analyst_or_admin enforces JWT
        c = TestClient(fresh_app, raise_server_exceptions=False)
        r = c.get("/incidents/some-id/piil-binding")
        assert r.status_code in (401, 403, 422)

    def test_multiple_items_returned(self):
        inc = _make_incident()
        entries = [_make_fe(action_id=inc.id) for _ in range(3)]
        app_obj = _make_endpoint_app()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars(entries))
        from asc_api.db.session import get_db
        app_obj.dependency_overrides[get_db] = lambda: db
        with patch("asc_api.services.incident_service.get_incident",
                   new_callable=AsyncMock, return_value=inc):
            c = TestClient(app_obj, raise_server_exceptions=False)
            r = c.get(f"/incidents/{inc.id}/piil-binding")
        assert r.json()["count"] == 3
        assert len(r.json()["items"]) == 3

    def test_item_has_signature_ed25519(self):
        inc = _make_incident()
        fe = _make_fe(action_id=inc.id)
        app_obj = _make_endpoint_app()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([fe]))
        from asc_api.db.session import get_db
        app_obj.dependency_overrides[get_db] = lambda: db
        with patch("asc_api.services.incident_service.get_incident",
                   new_callable=AsyncMock, return_value=inc):
            c = TestClient(app_obj, raise_server_exceptions=False)
            r = c.get(f"/incidents/{inc.id}/piil-binding")
        assert "signature_ed25519" in r.json()["items"][0]

    def test_item_has_signed_at(self):
        inc = _make_incident()
        fe = _make_fe(action_id=inc.id)
        app_obj = _make_endpoint_app()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([fe]))
        from asc_api.db.session import get_db
        app_obj.dependency_overrides[get_db] = lambda: db
        with patch("asc_api.services.incident_service.get_incident",
                   new_callable=AsyncMock, return_value=inc):
            c = TestClient(app_obj, raise_server_exceptions=False)
            r = c.get(f"/incidents/{inc.id}/piil-binding")
        assert "signed_at" in r.json()["items"][0]

    def test_item_action_id_matches_incident(self):
        inc = _make_incident(id="specific-inc")
        fe = _make_fe(action_id="specific-inc")
        app_obj = _make_endpoint_app()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([fe]))
        from asc_api.db.session import get_db
        app_obj.dependency_overrides[get_db] = lambda: db
        with patch("asc_api.services.incident_service.get_incident",
                   new_callable=AsyncMock, return_value=inc):
            c = TestClient(app_obj, raise_server_exceptions=False)
            r = c.get(f"/incidents/{inc.id}/piil-binding")
        assert r.json()["items"][0]["action_id"] == "specific-inc"

    def test_item_has_last_verified_at(self):
        inc = _make_incident()
        fe = _make_fe(action_id=inc.id, last_verified_at=None)
        app_obj = _make_endpoint_app()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([fe]))
        from asc_api.db.session import get_db
        app_obj.dependency_overrides[get_db] = lambda: db
        with patch("asc_api.services.incident_service.get_incident",
                   new_callable=AsyncMock, return_value=inc):
            c = TestClient(app_obj, raise_server_exceptions=False)
            r = c.get(f"/incidents/{inc.id}/piil-binding")
        assert "last_verified_at" in r.json()["items"][0]


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TestSoarEventsEndpoint
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestSoarEventsEndpoint:

    def test_returns_404_when_incident_not_found(self):
        client = TestClient(_make_endpoint_app(), raise_server_exceptions=False)
        with patch("asc_api.services.incident_service.get_incident",
                   new_callable=AsyncMock, return_value=None):
            r = client.get("/incidents/missing/soar-events")
        assert r.status_code == 404

    def test_returns_200_with_empty_list(self):
        inc = _make_incident()
        app_obj = _make_endpoint_app()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([]))
        from asc_api.db.session import get_db
        app_obj.dependency_overrides[get_db] = lambda: db
        with patch("asc_api.services.incident_service.get_incident",
                   new_callable=AsyncMock, return_value=inc):
            c = TestClient(app_obj, raise_server_exceptions=False)
            r = c.get(f"/incidents/{inc.id}/soar-events")
        assert r.status_code == 200

    def test_response_has_incident_id(self):
        inc = _make_incident(id="soar-inc-id")
        app_obj = _make_endpoint_app()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([]))
        from asc_api.db.session import get_db
        app_obj.dependency_overrides[get_db] = lambda: db
        with patch("asc_api.services.incident_service.get_incident",
                   new_callable=AsyncMock, return_value=inc):
            c = TestClient(app_obj, raise_server_exceptions=False)
            r = c.get(f"/incidents/{inc.id}/soar-events")
        assert r.json()["incident_id"] == "soar-inc-id"

    def test_response_has_items_list(self):
        inc = _make_incident()
        app_obj = _make_endpoint_app()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([]))
        from asc_api.db.session import get_db
        app_obj.dependency_overrides[get_db] = lambda: db
        with patch("asc_api.services.incident_service.get_incident",
                   new_callable=AsyncMock, return_value=inc):
            c = TestClient(app_obj, raise_server_exceptions=False)
            r = c.get(f"/incidents/{inc.id}/soar-events")
        assert isinstance(r.json()["items"], list)

    def test_response_has_count_field(self):
        inc = _make_incident()
        app_obj = _make_endpoint_app()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([]))
        from asc_api.db.session import get_db
        app_obj.dependency_overrides[get_db] = lambda: db
        with patch("asc_api.services.incident_service.get_incident",
                   new_callable=AsyncMock, return_value=inc):
            c = TestClient(app_obj, raise_server_exceptions=False)
            r = c.get(f"/incidents/{inc.id}/soar-events")
        assert "count" in r.json()

    def test_count_matches_items_length(self):
        inc = _make_incident()
        entries = [_make_tl_entry(incident_id=inc.id) for _ in range(2)]
        app_obj = _make_endpoint_app()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars(entries))
        from asc_api.db.session import get_db
        app_obj.dependency_overrides[get_db] = lambda: db
        with patch("asc_api.services.incident_service.get_incident",
                   new_callable=AsyncMock, return_value=inc):
            c = TestClient(app_obj, raise_server_exceptions=False)
            r = c.get(f"/incidents/{inc.id}/soar-events")
        body = r.json()
        assert body["count"] == len(body["items"])

    def test_item_has_id(self):
        inc = _make_incident()
        tl = _make_tl_entry(id="tl-xyz", incident_id=inc.id)
        app_obj = _make_endpoint_app()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([tl]))
        from asc_api.db.session import get_db
        app_obj.dependency_overrides[get_db] = lambda: db
        with patch("asc_api.services.incident_service.get_incident",
                   new_callable=AsyncMock, return_value=inc):
            c = TestClient(app_obj, raise_server_exceptions=False)
            r = c.get(f"/incidents/{inc.id}/soar-events")
        assert r.json()["items"][0]["id"] == "tl-xyz"

    def test_item_has_event_type(self):
        inc = _make_incident()
        tl = _make_tl_entry(event_type="soar_triggered", incident_id=inc.id)
        app_obj = _make_endpoint_app()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([tl]))
        from asc_api.db.session import get_db
        app_obj.dependency_overrides[get_db] = lambda: db
        with patch("asc_api.services.incident_service.get_incident",
                   new_callable=AsyncMock, return_value=inc):
            c = TestClient(app_obj, raise_server_exceptions=False)
            r = c.get(f"/incidents/{inc.id}/soar-events")
        assert r.json()["items"][0]["event_type"] == "soar_triggered"

    def test_item_has_actor(self):
        inc = _make_incident()
        tl = _make_tl_entry(actor="system:soar", incident_id=inc.id)
        app_obj = _make_endpoint_app()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([tl]))
        from asc_api.db.session import get_db
        app_obj.dependency_overrides[get_db] = lambda: db
        with patch("asc_api.services.incident_service.get_incident",
                   new_callable=AsyncMock, return_value=inc):
            c = TestClient(app_obj, raise_server_exceptions=False)
            r = c.get(f"/incidents/{inc.id}/soar-events")
        assert r.json()["items"][0]["actor"] == "system:soar"

    def test_item_has_detail(self):
        inc = _make_incident()
        tl = _make_tl_entry(detail={"trigger_name": "alpha"}, incident_id=inc.id)
        app_obj = _make_endpoint_app()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([tl]))
        from asc_api.db.session import get_db
        app_obj.dependency_overrides[get_db] = lambda: db
        with patch("asc_api.services.incident_service.get_incident",
                   new_callable=AsyncMock, return_value=inc):
            c = TestClient(app_obj, raise_server_exceptions=False)
            r = c.get(f"/incidents/{inc.id}/soar-events")
        assert r.json()["items"][0]["detail"]["trigger_name"] == "alpha"

    def test_item_has_created_at(self):
        inc = _make_incident()
        tl = _make_tl_entry(incident_id=inc.id)
        app_obj = _make_endpoint_app()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([tl]))
        from asc_api.db.session import get_db
        app_obj.dependency_overrides[get_db] = lambda: db
        with patch("asc_api.services.incident_service.get_incident",
                   new_callable=AsyncMock, return_value=inc):
            c = TestClient(app_obj, raise_server_exceptions=False)
            r = c.get(f"/incidents/{inc.id}/soar-events")
        assert "created_at" in r.json()["items"][0]

    def test_item_has_incident_id(self):
        inc = _make_incident(id="my-inc-soar")
        tl = _make_tl_entry(incident_id="my-inc-soar")
        app_obj = _make_endpoint_app()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([tl]))
        from asc_api.db.session import get_db
        app_obj.dependency_overrides[get_db] = lambda: db
        with patch("asc_api.services.incident_service.get_incident",
                   new_callable=AsyncMock, return_value=inc):
            c = TestClient(app_obj, raise_server_exceptions=False)
            r = c.get(f"/incidents/{inc.id}/soar-events")
        assert r.json()["items"][0]["incident_id"] == "my-inc-soar"

    def test_endpoint_accepts_limit_param(self):
        inc = _make_incident()
        app_obj = _make_endpoint_app()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([]))
        from asc_api.db.session import get_db
        app_obj.dependency_overrides[get_db] = lambda: db
        with patch("asc_api.services.incident_service.get_incident",
                   new_callable=AsyncMock, return_value=inc):
            c = TestClient(app_obj, raise_server_exceptions=False)
            r = c.get(f"/incidents/{inc.id}/soar-events?limit=20")
        assert r.status_code == 200

    def test_unauthed_request_rejected(self):
        from asc_api.api.v1.endpoints.incidents import router
        from asc_api.db.session import get_db
        fresh_app = FastAPI()
        fresh_app.include_router(router)
        fresh_app.dependency_overrides[get_db] = lambda: AsyncMock()
        c = TestClient(fresh_app, raise_server_exceptions=False)
        r = c.get("/incidents/some/soar-events")
        assert r.status_code in (401, 403, 422)

    def test_multiple_soar_events(self):
        inc = _make_incident()
        entries = [_make_tl_entry(incident_id=inc.id) for _ in range(4)]
        app_obj = _make_endpoint_app()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars(entries))
        from asc_api.db.session import get_db
        app_obj.dependency_overrides[get_db] = lambda: db
        with patch("asc_api.services.incident_service.get_incident",
                   new_callable=AsyncMock, return_value=inc):
            c = TestClient(app_obj, raise_server_exceptions=False)
            r = c.get(f"/incidents/{inc.id}/soar-events")
        assert r.json()["count"] == 4

    def test_detail_none_returns_empty_dict(self):
        inc = _make_incident()
        tl = _make_tl_entry(incident_id=inc.id, detail=None)
        app_obj = _make_endpoint_app()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([tl]))
        from asc_api.db.session import get_db
        app_obj.dependency_overrides[get_db] = lambda: db
        with patch("asc_api.services.incident_service.get_incident",
                   new_callable=AsyncMock, return_value=inc):
            c = TestClient(app_obj, raise_server_exceptions=False)
            r = c.get(f"/incidents/{inc.id}/soar-events")
        assert r.json()["items"][0]["detail"] == {}

    def test_items_list_is_list_type(self):
        inc = _make_incident()
        app_obj = _make_endpoint_app()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([]))
        from asc_api.db.session import get_db
        app_obj.dependency_overrides[get_db] = lambda: db
        with patch("asc_api.services.incident_service.get_incident",
                   new_callable=AsyncMock, return_value=inc):
            c = TestClient(app_obj, raise_server_exceptions=False)
            r = c.get(f"/incidents/{inc.id}/soar-events")
        assert isinstance(r.json().get("items"), list)

    def test_empty_count_is_zero(self):
        inc = _make_incident()
        app_obj = _make_endpoint_app()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([]))
        from asc_api.db.session import get_db
        app_obj.dependency_overrides[get_db] = lambda: db
        with patch("asc_api.services.incident_service.get_incident",
                   new_callable=AsyncMock, return_value=inc):
            c = TestClient(app_obj, raise_server_exceptions=False)
            r = c.get(f"/incidents/{inc.id}/soar-events")
        assert r.json()["count"] == 0

    def test_incident_id_in_response_matches_request(self):
        inc = _make_incident(id="request-id-match")
        app_obj = _make_endpoint_app()
        db = AsyncMock()
        db.execute = AsyncMock(return_value=_mock_scalars([]))
        from asc_api.db.session import get_db
        app_obj.dependency_overrides[get_db] = lambda: db
        with patch("asc_api.services.incident_service.get_incident",
                   new_callable=AsyncMock, return_value=inc):
            c = TestClient(app_obj, raise_server_exceptions=False)
            r = c.get(f"/incidents/request-id-match/soar-events")
        assert r.json()["incident_id"] == "request-id-match"


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TestSerializerFe
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestSerializerFe:

    def _call(self, **kw):
        from asc_api.api.v1.endpoints.incidents import _fe
        return _fe(_make_fe(**kw))

    def test_returns_dict(self):
        result = self._call()
        assert isinstance(result, dict)

    def test_has_id(self):
        result = self._call(id="fe-id-test")
        assert result["id"] == "fe-id-test"

    def test_has_action_id(self):
        result = self._call(action_id="inc-123")
        assert result["action_id"] == "inc-123"

    def test_has_action_type(self):
        result = self._call(action_type="piil_soar_binding")
        assert result["action_type"] == "piil_soar_binding"

    def test_has_target(self):
        result = self._call(target="incident:abc:closed")
        assert result["target"] == "incident:abc:closed"

    def test_has_hash_sha3_512(self):
        result = self._call(hash_sha3_512="x" * 128)
        assert result["hash_sha3_512"] == "x" * 128

    def test_has_signature_ed25519(self):
        result = self._call(signature_ed25519="PIIL-SIG")
        assert result["signature_ed25519"] == "PIIL-SIG"

    def test_has_canonical_data(self):
        result = self._call(canonical_data={"key": "value"})
        assert result["canonical_data"] == {"key": "value"}

    def test_has_signed_by_email(self):
        result = self._call(signed_by_email="admin@premos.com")
        assert result["signed_by_email"] == "admin@premos.com"

    def test_has_verified(self):
        result = self._call(verified=True)
        assert result["verified"] is True

    def test_has_signed_at(self):
        result = self._call()
        assert "signed_at" in result

    def test_has_last_verified_at_none(self):
        result = self._call(last_verified_at=None)
        assert result["last_verified_at"] is None


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TestIncidentsModuleIntegration
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestIncidentsModuleIntegration:

    def test_module_imports_forensic_entry(self):
        import inspect
        import asc_api.api.v1.endpoints.incidents as m
        src = inspect.getsource(m)
        assert "ForensicEntry" in src

    def test_module_imports_select(self):
        import inspect
        import asc_api.api.v1.endpoints.incidents as m
        src = inspect.getsource(m)
        assert "from sqlalchemy import select" in src

    def test_module_imports_incident_timeline(self):
        import inspect
        import asc_api.api.v1.endpoints.incidents as m
        src = inspect.getsource(m)
        assert "IncidentTimeline" in src

    def test_fe_serializer_exists(self):
        from asc_api.api.v1.endpoints.incidents import _fe
        assert callable(_fe)

    def test_piil_binding_route_in_router(self):
        from asc_api.api.v1.endpoints.incidents import router
        paths = [r.path for r in router.routes]
        assert any("piil-binding" in p for p in paths)

    def test_soar_events_route_in_router(self):
        from asc_api.api.v1.endpoints.incidents import router
        paths = [r.path for r in router.routes]
        assert any("soar-events" in p for p in paths)

    def test_docstring_mentions_piil_binding(self):
        import inspect
        import asc_api.api.v1.endpoints.incidents as m
        src = inspect.getsource(m)
        assert "piil-binding" in src.lower()

    def test_docstring_mentions_soar_events(self):
        import inspect
        import asc_api.api.v1.endpoints.incidents as m
        src = inspect.getsource(m)
        assert "soar-events" in src.lower()

    def test_router_prefix_is_incidents(self):
        from asc_api.api.v1.endpoints.incidents import router
        assert router.prefix == "/incidents"

    def test_piil_binding_route_is_get(self):
        from asc_api.api.v1.endpoints.incidents import router
        for r in router.routes:
            if "piil-binding" in r.path:
                assert "GET" in r.methods
                break

    def test_soar_events_route_is_get(self):
        from asc_api.api.v1.endpoints.incidents import router
        for r in router.routes:
            if "soar-events" in r.path:
                assert "GET" in r.methods
                break

    def test_total_routes_increased_to_sixteen(self):
        from asc_api.api.v1.endpoints.incidents import router
        # Was 14 endpoints, now 16 with piil-binding and soar-events
        assert len(router.routes) >= 16


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TestCeleryAppAndConfig
# (Source-inspection approach â€” celery not installed in test env)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestCeleryAppAndConfig:

    def test_celery_app_file_has_five_plus_includes(self):
        assert _celery_app_src().count("app.tasks.") >= 5

    def test_sla_escalation_in_include_list(self):
        assert "app.tasks.sla_escalation" in _celery_app_src()

    def test_beat_schedule_has_five_entries_in_source(self):
        src = _celery_app_src()
        # five known schedule keys
        for key in ["proactive-escalation", "pcdi-critical-findings",
                    "soar-scheduled-reports", "correlation-sweep", "sla-breach-escalation"]:
            assert key in src

    def test_sla_interval_var_in_celery_module(self):
        assert "_SLA_INTERVAL" in _celery_app_src()

    def test_config_has_sla_escalation_field(self):
        from asc_api.core.config import Settings
        assert hasattr(Settings(), "SLA_ESCALATION_CHECK_INTERVAL_SECONDS")

    def test_config_sla_default_greater_than_escalation_check(self):
        from asc_api.core.config import Settings
        s = Settings()
        assert s.SLA_ESCALATION_CHECK_INTERVAL_SECONDS > s.ESCALATION_CHECK_INTERVAL_SECONDS

    def test_sla_interval_is_positive(self):
        from asc_api.core.config import Settings
        assert Settings().SLA_ESCALATION_CHECK_INTERVAL_SECONDS > 0

    def test_beat_schedule_proactive_escalation_in_source(self):
        assert "proactive-escalation" in _celery_app_src()

    def test_beat_schedule_correlation_sweep_in_source(self):
        assert "correlation-sweep" in _celery_app_src()

    def test_sla_task_name_contains_sla_in_source(self):
        assert "sla" in _celery_app_src().lower()
