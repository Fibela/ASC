"""
S102 — Tests del módulo de explicación adaptativa.

Distinción de mocks (regla del proyecto):
  - En PRODUCTO: cero mocks. Datos reales de Supabase.
  - En estos tests unitarios: el cliente Anthropic (servicio externo, red) SÍ
    se simula. Es la práctica correcta — no dependemos de red ni gastamos tokens.
    La lógica propia (aislamiento de tenant, selección de perfil, guardrail,
    manejo de 503) se prueba de verdad.
"""
from __future__ import annotations

import uuid
import pytest
import pytest_asyncio
from datetime import datetime, timezone

from asc_api.models.alert import Alert
from asc_api.models.tenant import Tenant
from asc_api.models.user import User
from asc_api.core.config import get_settings
from asc_api.core.security import create_access_token, get_password_hash
from asc_api.services import explainer


# ─── Unit: servicio puro (sin DB, sin red) ────────────────────────────────────

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
            "title": "Beacon C2 detectado",
            "severity": "critical",
            "affected_hosts": [],       # vacío -> omitido
            "ttps": None,               # None -> omitido
            "risk_score": 0.91,
        })
        assert "Beacon C2 detectado" in ctx
        assert "critical" in ctx
        assert "Hosts afectados" not in ctx
        assert "TTPs" not in ctx

    def test_build_context_sin_datos_no_inventa(self):
        ctx = explainer.build_alert_context({})
        assert ctx == "(alerta sin campos legibles)"

    @pytest.mark.asyncio
    async def test_stream_sin_api_key_lanza_disabled(self, monkeypatch):
        monkeypatch.setattr(get_settings(), "ANTHROPIC_API_KEY", "", raising=False)
        gen = explainer.stream_explanation({"id": "x", "title": "t"}, "pyme")
        with pytest.raises(explainer.ExplainerDisabled):
            await gen.__anext__()


# ─── Integración de endpoint (DB real de test + stream simulado) ──────────────

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
    async def test_sin_api_key_503(self, client, db, monkeypatch):
        _, user, alert = await _mk_tenant_user_alert(db)
        monkeypatch.setattr(get_settings(), "ANTHROPIC_API_KEY", "", raising=False)
        headers = {"Authorization": f"Bearer {create_access_token(user.id)}"}
        r = await client.post(f"/api/v1/alerts/{alert.id}/explain", headers=headers)
        assert r.status_code == 503

    @pytest.mark.asyncio
    async def test_stream_ok_usa_perfil_del_tenant(self, client, db, monkeypatch):
        _, user, alert = await _mk_tenant_user_alert(db, profile="hogar")
        monkeypatch.setattr(get_settings(), "ANTHROPIC_API_KEY", "sk-ant-test", raising=False)

        captured = {}

        async def fake_stream(alert_data, profile):
            captured["profile"] = profile
            captured["alert_id"] = alert_data.get("id")
            for piece in ("Tu ", "computadora ", "recibió una alerta."):
                yield piece

        # se parchea en el namespace del endpoint (donde se importó)
        import asc_api.api.v1.endpoints.explain as ep
        monkeypatch.setattr(ep, "stream_explanation", fake_stream)

        headers = {"Authorization": f"Bearer {create_access_token(user.id)}"}
        r = await client.post(f"/api/v1/alerts/{alert.id}/explain", headers=headers)
        assert r.status_code == 200
        assert "text/event-stream" in r.headers["content-type"]
        body = r.text
        assert "event: meta" in body
        assert "event: delta" in body
        assert "event: done" in body
        assert "computadora" in body
        assert captured["profile"] == "hogar"     # perfil vino del tenant, no de un default
        assert captured["alert_id"] == alert.id
