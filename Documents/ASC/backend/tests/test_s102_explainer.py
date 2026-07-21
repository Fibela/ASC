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
import httpx
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
        monkeypatch.setattr("asc_api.api.v1.endpoints.explain.settings.ANTHROPIC_API_KEY", "sk-ant-test")

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


# ─── Unit: ruta real de streaming SSE (httpx simulado, sin red) ────────────────
#
# El test previo (TestExplainEndpoint) parchea stream_explanation ENTERO, así que
# el parser SSE real y _payload nunca se ejecutaban. Aquí los ejercitamos de
# verdad con un cliente httpx falso: cero red, cero tokens, cobertura honesta del
# código que sí se despliega.

class _FakeResp:
    def __init__(self, status_code=200, lines=None, body=b""):
        self.status_code = status_code
        self._lines = lines or []
        self._body = body
        self.request = httpx.Request("POST", explainer._ANTHROPIC_URL)

    async def aiter_lines(self):
        for ln in self._lines:
            yield ln

    async def aread(self):
        return self._body


class _FakeStreamCtx:
    def __init__(self, resp):
        self._resp = resp

    async def __aenter__(self):
        return self._resp

    async def __aexit__(self, *exc):
        return False


class _FakeClient:
    def __init__(self, resp):
        self._resp = resp

    def stream(self, *a, **k):
        return _FakeStreamCtx(self._resp)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


def _patch_httpx(monkeypatch, resp):
    monkeypatch.setattr(get_settings(), "ANTHROPIC_API_KEY", "sk-ant-test", raising=False)
    monkeypatch.setattr(explainer.httpx, "AsyncClient", lambda *a, **k: _FakeClient(resp))


class TestExplainerStreamingReal:
    def test_build_context_serializa_listas_y_dicts(self):
        ctx = explainer.build_alert_context({
            "affected_hosts": ["WS-01", "WS-02"],
            "matched_iocs": [{"type": "ip", "value": "1.2.3.4"}],
        })
        assert "WS-01" in ctx and "WS-02" in ctx
        assert "1.2.3.4" in ctx          # dict serializado, no repr de Python
        assert "'" not in ctx.split("IOCs")[-1]  # json usa comillas dobles

    def test_payload_estructura_y_stream_activo(self):
        p = explainer._payload("enterprise", "ctx de prueba")
        assert p["model"] == get_settings().ANTHROPIC_MODEL
        assert p["max_tokens"] == get_settings().EXPLAINER_MAX_TOKENS
        assert p["stream"] is True
        assert "analista SOC" in p["system"]          # perfil enterprise
        assert "ctx de prueba" in p["messages"][0]["content"]

    @pytest.mark.asyncio
    async def test_stream_parsea_deltas_y_tolera_ruido(self, monkeypatch):
        lines = [
            'event: ping',                                                   # no 'data:' -> skip
            'data: {"type":"content_block_delta","delta":{"text":"Hola"}}',
            'data: ',                                                        # vacío -> skip
            'data: {"type":"message_start"}',                               # no delta -> skip
            'data: no-es-json{',                                            # JSONDecodeError -> skip
            'data: {"type":"content_block_delta","delta":{"text":" mundo"}}',
            'data: [DONE]',                                                 # terminador -> skip
        ]
        _patch_httpx(monkeypatch, _FakeResp(200, lines))
        pieces = [p async for p in explainer.stream_explanation({"id": "a1"}, "hogar")]
        assert pieces == ["Hola", " mundo"]

    @pytest.mark.asyncio
    async def test_stream_status_no_200_propaga_httpstatuserror(self, monkeypatch):
        _patch_httpx(monkeypatch, _FakeResp(500, lines=[], body=b'{"error":"boom"}'))
        with pytest.raises(httpx.HTTPStatusError):
            async for _ in explainer.stream_explanation({"id": "a2"}, "pyme"):
                pass


# ─── Integración: ramas de error honesto del endpoint (contrato "reporta, no simula") ──

class TestExplainEndpointErrores:
    async def _prep(self, client, db, monkeypatch, failing_stream):
        _, user, alert = await _mk_tenant_user_alert(db)
        monkeypatch.setattr("asc_api.api.v1.endpoints.explain.settings.ANTHROPIC_API_KEY", "sk-ant-test")
        import asc_api.api.v1.endpoints.explain as ep
        monkeypatch.setattr(ep, "stream_explanation", failing_stream)
        headers = {"Authorization": f"Bearer {create_access_token(user.id)}"}
        return await client.post(f"/api/v1/alerts/{alert.id}/explain", headers=headers)

    @pytest.mark.asyncio
    async def test_upstream_httpstatuserror_emite_evento_error(self, client, db, monkeypatch):
        async def boom(alert_data, profile):
            req = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
            raise httpx.HTTPStatusError("upstream", request=req, response=httpx.Response(502, request=req))
            yield  # noqa — hace de esto un async generator
        r = await self._prep(client, db, monkeypatch, boom)
        assert r.status_code == 200
        assert "event: error" in r.text
        assert "upstream" in r.text.lower()

    @pytest.mark.asyncio
    async def test_timeout_emite_evento_error(self, client, db, monkeypatch):
        async def boom(alert_data, profile):
            raise httpx.TimeoutException("lento")
            yield
        r = await self._prep(client, db, monkeypatch, boom)
        assert "event: error" in r.text
        assert "tiempo" in r.text.lower()

    @pytest.mark.asyncio
    async def test_excepcion_inesperada_no_filtra_detalle(self, client, db, monkeypatch):
        async def boom(alert_data, profile):
            raise ValueError("detalle interno sensible")
            yield
        r = await self._prep(client, db, monkeypatch, boom)
        assert "event: error" in r.text
        assert "detalle interno sensible" not in r.text   # no se filtra el mensaje crudo
