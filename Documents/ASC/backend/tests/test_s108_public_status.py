"""S108.3 — página de estado PÚBLICA (sin auth) + badge helper."""
from __future__ import annotations

import pytest

from asc_api.api.v1.endpoints.health import _status_badge


class TestBadge:
    def test_estados_conocidos(self):
        assert _status_badge("operational")[0] == "Operativo"
        assert _status_badge("degraded")[0] == "Degradado"
        assert _status_badge("down")[0] == "Caído"
        assert _status_badge("unknown")[0] == "Sin datos"
        assert _status_badge("cualquier-otro")[0] == "Sin datos"   # fallback


class TestPublicStatusPage:
    @pytest.mark.asyncio
    async def test_publico_sin_auth_devuelve_html(self, client):
        r = await client.get("/api/v1/health/status")
        assert r.status_code == 200                      # SIN token
        assert "text/html" in r.headers["content-type"]
        body = r.text
        assert "PremosCorp" in body and "Estado del servicio" in body
        assert "Base de datos" in body and "Monitoreo" in body

    @pytest.mark.asyncio
    async def test_no_filtra_nombres_de_job(self, client):
        # la página pública no debe listar los job_ids de cron (anti-inteligencia)
        r = await client.get("/api/v1/health/status")
        assert "cron-escalation" not in r.text and "watchdog-supabase" not in r.text
