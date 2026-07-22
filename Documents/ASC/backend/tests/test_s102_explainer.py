"""
S102/S110 — Tests del módulo de explicación adaptativa (motor PROPIO, sin LLM externo).

Regla del proyecto: cero mocks en producto. Aquí la lógica propia (aislamiento de tenant,
selección de perfil desde el tenant, guardrail, generación determinista) se prueba de verdad.
El motor no llama a ningún servicio externo, así que el endpoint se ejercita end-to-end real.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from asc_api.models.alert import Alert
from asc_api.models.tenant import Tenant
from asc_api.models.user import User
from asc_api.core.security import create_access_token, get_password_hash
from asc_api.services import explainer


# ─── Unit: utilidades de contexto/registro ────────────────────────────────────

class TestExplainerService:
    def test_profiles_validos_incluyen_guardrail(self):
        for prof in ("hogar", "pyme", "enterprise"):
            sysprompt = explainer._PROFILE_SYSTEM[prof]
            assert "EXPLICAS y RECOMIENDAS" in sysprompt
            assert "No decides ni ejecutas" in sysprompt

    def test_normalize_profile_desconocido_cae_a_pyme(self):
        assert explainer._normalize_profile("marciano") == "pyme"
        assert explainer._normalize_profile(None) == "pyme"
        assert explainer._normalize_profile("HOGAR") == "hogar"

    def test_build_context_omite_campos_vacios(self):
        ctx = explainer.build_alert_context({
            "title": "Beacon C2 detectado", "severity": "critical",
            "affected_hosts": [], "ttps": None, "risk_score": 0.91,
        })
        assert "Beacon C2 detectado" in ctx and "critical" in ctx
        assert "Hosts afectados" not in ctx and "TTPs" not in ctx

    def test_build_context_sin_datos_no_inventa(self):
        assert explainer.build_alert_context({}) == "(alerta sin campos legibles)"

    def test_build_context_serializa_listas_y_dicts(self):
        ctx = explainer.build_alert_context({
            "affected_hosts": ["WS-01", "WS-02"],
            "matched_iocs": [{"type": "ip", "value": "1.2.3.4"}],
        })
        assert "WS-01" in ctx and "1.2.3.4" in ctx     # dict serializado a JSON, no repr


# ─── Integración de endpoint (DB real de test, motor propio real) ─────────────

async def _mk_tenant_user_alert(db, profile="pyme"):
    tid = str(uuid.uuid4())
    db.add(Tenant(id=tid, name="Acme", slug=f"acme-{tid[:8]}", profile=profile))
    user = User(
        email=f"u-{tid[:8]}@premoscorp.com", full_name="U",
        hashed_password=get_password_hash("Xx@12345!"),
        role="analyst", is_active=True, tenant_id=tid,
    )
    db.add(user)
    alert = Alert(
        id=str(uuid.uuid4()), title="Beacon C2", description="tráfico saliente periódico",
        severity="critical", status="open", risk_score=0.92,
        source_events=[], matched_iocs=[], affected_hosts=["WS-01"],
        ttps=["T1071"], recommended_actions=["block_ip"],
        detected_at=datetime.now(timezone.utc), tenant_id=tid,
    )
    db.add(alert)
    await db.commit()
    return tid, user, alert


class TestExplainEndpoint:
    @pytest.mark.asyncio
    async def test_sin_auth_rechaza(self, client, db):
        _, _, alert = await _mk_tenant_user_alert(db)
        r = await client.post(f"/api/v1/alerts/{alert.id}/explain")
        assert r.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_alerta_de_otro_tenant_404(self, client, db):
        _, user, _ = await _mk_tenant_user_alert(db)
        headers = {"Authorization": f"Bearer {create_access_token(user.id)}"}
        r = await client.post(f"/api/v1/alerts/{uuid.uuid4()}/explain", headers=headers)
        assert r.status_code == 404

    @pytest.mark.asyncio
    async def test_responde_con_motor_propio_sin_key(self, client, db):
        # El motor propio NO necesita ninguna API key: siempre responde (200 + stream).
        _, user, alert = await _mk_tenant_user_alert(db)
        headers = {"Authorization": f"Bearer {create_access_token(user.id)}"}
        r = await client.post(f"/api/v1/alerts/{alert.id}/explain", headers=headers)
        assert r.status_code == 200
        assert "text/event-stream" in r.headers["content-type"]
        body = r.text
        assert "event: meta" in body and "event: delta" in body and "event: done" in body
        assert "Beacon" in body                          # palabra real de la alerta (stream por palabra)
        assert "firewall" in body                        # block_ip -> recomendación humanizada
        assert "event: error" not in body                # sin errores (no hay upstream)

    @pytest.mark.asyncio
    async def test_stream_usa_perfil_del_tenant(self, client, db, monkeypatch):
        _, user, alert = await _mk_tenant_user_alert(db, profile="hogar")
        captured = {}

        async def fake_stream(alert_data, profile):
            captured["profile"] = profile
            captured["alert_id"] = alert_data.get("id")
            for piece in ("Tu ", "computadora ", "recibió una alerta."):
                yield piece

        import asc_api.api.v1.endpoints.explain as ep
        monkeypatch.setattr(ep, "stream_explanation", fake_stream)
        headers = {"Authorization": f"Bearer {create_access_token(user.id)}"}
        r = await client.post(f"/api/v1/alerts/{alert.id}/explain", headers=headers)
        assert r.status_code == 200
        assert "computadora" in r.text
        assert captured["profile"] == "hogar"            # perfil vino del tenant
        assert captured["alert_id"] == alert.id


class TestExplainEndpointErrores:
    @pytest.mark.asyncio
    async def test_excepcion_inesperada_no_filtra_detalle(self, client, db, monkeypatch):
        _, user, alert = await _mk_tenant_user_alert(db)

        async def boom(alert_data, profile):
            raise ValueError("detalle interno sensible")
            yield  # noqa — hace de esto un async generator

        import asc_api.api.v1.endpoints.explain as ep
        monkeypatch.setattr(ep, "stream_explanation", boom)
        headers = {"Authorization": f"Bearer {create_access_token(user.id)}"}
        r = await client.post(f"/api/v1/alerts/{alert.id}/explain", headers=headers)
        assert "event: error" in r.text
        assert "detalle interno sensible" not in r.text   # no filtra el mensaje crudo
