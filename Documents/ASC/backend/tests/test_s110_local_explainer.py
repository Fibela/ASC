"""
S110 — Motor de explicación PROPIO (determinista, sin LLM externo).

Prueba: 3 secciones, registros distintos por perfil, mapeo MITRE, omisión de campos
ausentes (nada inventado), guardrail (recomienda, nunca 'ejecutamos'), y streaming.
"""
from __future__ import annotations

import pytest

from asc_api.services.local_explainer import (
    build_explanation,
    stream_local_explanation,
)

_ALERT = {
    "id": "a1",
    "title": "Beacon C2 detectado",
    "severity": "critical",
    "risk_score": 0.92,
    "affected_hosts": ["WS-01"],
    "ttps": ["T1071"],
    "matched_iocs": [{"x": 1}],
    "recommended_actions": ["block_ip", "isolate_endpoint"],
}


class TestBuildExplanation:
    def test_tres_secciones(self):
        txt = build_explanation(_ALERT, "pyme")
        assert "**Qué ocurrió:**" in txt
        assert "**Por qué importa:**" in txt
        assert "**Qué se recomienda considerar:**" in txt

    def test_registros_distintos(self):
        hogar = build_explanation(_ALERT, "hogar")
        ent = build_explanation(_ALERT, "enterprise")
        assert hogar != ent
        assert "palabras simples" in hogar or "llamando a casa" in hogar   # analogía hogar
        assert "T1071" in ent                                               # tecnicismo enterprise
        assert "T1071" not in hogar                                         # hogar SIN el código

    def test_perfil_invalido_cae_a_pyme(self):
        assert build_explanation(_ALERT, "marciano") == build_explanation(_ALERT, "pyme")

    def test_ttp_desconocido_usa_generico_con_codigo(self):
        a = {**_ALERT, "ttps": ["T9999"]}
        txt = build_explanation(a, "enterprise")
        assert "T9999" in txt and "MITRE" in txt

    def test_omite_campos_ausentes_no_inventa(self):
        minimal = {"title": "Alerta X", "severity": "low"}
        txt = build_explanation(minimal, "pyme")
        assert "Alerta X" in txt
        assert "Equipo" not in txt          # sin hosts -> sin línea de equipos
        assert "indicador" not in txt        # sin IOCs -> sin línea de IOCs
        # sin acciones -> usa la recomendación por defecto, no inventa acciones
        assert "recomienda" in txt.lower()

    def test_guardrail_recomienda_no_ejecuta(self):
        txt = build_explanation(_ALERT, "pyme").lower()
        assert "recomien" in txt                       # tono de recomendación
        for verbo in ("bloqueamos", "aislamos", "ejecutamos", "neutralizamos", "hemos bloqueado"):
            assert verbo not in txt                    # NUNCA afirma haber actuado

    def test_acciones_humanizadas(self):
        txt = build_explanation(_ALERT, "pyme")
        assert "firewall" in txt.lower()               # block_ip -> firewall
        assert "aislar el equipo" in txt.lower()       # isolate_endpoint


class TestStreaming:
    @pytest.mark.asyncio
    async def test_stream_reensambla_al_texto_completo(self):
        full = build_explanation(_ALERT, "pyme")
        pieces = [p async for p in stream_local_explanation(_ALERT, "pyme")]
        assert "".join(pieces) == full
        assert len(pieces) > 5                          # emitió en varios trozos
