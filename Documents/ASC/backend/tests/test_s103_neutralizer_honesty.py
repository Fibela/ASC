"""
S103 — Honestidad del neutralizador.

Regla dura verificada: una simulación NUNCA reporta success=True. El estado
es un tri-valor honesto (executed / simulated / failed) para que UI, reportes
y el analista jamás vean un "aislé el equipo" que no ocurrió.
"""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, patch

from asc_api.services import neutralizer as N
from asc_api.services.specter_bridge import SprecterBridgeResult, DispatchMode


AGENT_ONLY = ["isolate_endpoint", "kill_process", "quarantine_file", "remove_persistence"]


class TestNeutralizationResult:
    def test_status_deriva_de_success_y_simulated(self):
        assert N.NeutralizationResult(True, "x").status == "executed"
        assert N.NeutralizationResult(False, "x", simulated=True).status == "simulated"
        assert N.NeutralizationResult(False, "x").status == "failed"

    def test_details_llevan_flags_honestos(self):
        r = N.NeutralizationResult(False, "x", simulated=True)
        assert r.details["simulated"] is True
        assert r.details["status"] == "simulated"


class TestSimulacionesNoMienten:
    @pytest.mark.asyncio
    async def test_acciones_agent_only_son_simuladas_no_exitosas(self):
        cases = {
            "isolate_endpoint": {"host": "WS-07"},
            "kill_process": {"host": "WS-07", "process_name": "evil.exe"},
            "quarantine_file": {"host": "WS-07", "file_path": "/tmp/x"},
            "remove_persistence": {"host": "WS-07", "persistence_type": "run_key", "target": "x"},
        }
        for action, params in cases.items():
            r = await N.execute_action(action, params)
            assert r.success is False, f"{action} reportó éxito de una simulación"
            assert r.simulated is True
            assert r.status == "simulated"
            assert r.details.get("requires") == "specter_agent"
            assert "[SIMULATION]" in r.message and "NOT executed" in r.message

    @pytest.mark.asyncio
    async def test_block_ip_sin_adaptador_es_simulado(self):
        # En entorno de test no hay firewall configurado → simulación honesta.
        r = await N.block_ip("1.2.3.4")
        assert r.success is False
        assert r.simulated is True
        assert r.details.get("requires") == "firewall_adapter"

    @pytest.mark.asyncio
    async def test_disable_account_sin_adaptador_es_simulado(self):
        r = await N.disable_account("evil", "CORP")
        assert r.success is False
        assert r.simulated is True
        assert r.details.get("requires") == "identity_adapter"


class TestAdaptadorRealSiEjecuta:
    @pytest.mark.asyncio
    async def test_block_ip_con_adaptador_es_executed(self):
        fake_fw = AsyncMock()
        fake_fw.block_ip = AsyncMock(return_value={"success": True, "message": "blocked"})
        with patch("asc_api.adapters.get_firewall_adapter", return_value=fake_fw):
            r = await N.block_ip("1.2.3.4")
        assert r.success is True
        assert r.simulated is False
        assert r.status == "executed"

    @pytest.mark.asyncio
    async def test_adaptador_que_falla_es_failed_no_simulado(self):
        fake_fw = AsyncMock()
        fake_fw.block_ip = AsyncMock(side_effect=RuntimeError("PAN-OS 500"))
        with patch("asc_api.adapters.get_firewall_adapter", return_value=fake_fw):
            r = await N.block_ip("1.2.3.4")
        assert r.success is False
        assert r.simulated is False       # fue un intento REAL que falló
        assert r.status == "failed"


class TestBridgeResultSimulated:
    def test_simulated_deriva_de_dispatch_mode(self):
        sim = SprecterBridgeResult(success=False, message="x", dispatch_mode=DispatchMode.SIMULATION)
        assert sim.simulated is True and sim.status == "simulated"
        real = SprecterBridgeResult(success=True, message="x", dispatch_mode=DispatchMode.SPECTER)
        assert real.simulated is False and real.status == "executed"

    def test_simulated_explicito_gana(self):
        r = SprecterBridgeResult(success=False, message="x",
                                 dispatch_mode=DispatchMode.SPECTER, simulated=True)
        assert r.simulated is True
