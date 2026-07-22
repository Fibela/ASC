"""
S105.1 — Aislamiento multi-tenant de Threat Intel (modelo de 2 CAPAS).

Prueba la frontera real, no la documentación:
  CAPA 0 GLOBAL  (tenant_id=NULL) → visible a todos los tenants.
  CAPA 2 PRIVADA (tenant_id=<uuid>) → SOLO el tenant dueño; nunca cruza.

La CAPA 1 SHARED (sharing_group_id) es roadmap; ver docs/roadmap/threat-intel-3-capas.md.
"""
from __future__ import annotations

import pytest

from asc_api.services import threat_intel as ti


TA = "tenant-aaaaaaaa"
TB = "tenant-bbbbbbbb"


async def _mk(db, value, tenant_id, itype="ip"):
    return await ti.create_indicator(
        db, indicator_type=itype, value=value, tenant_id=tenant_id
    )


class TestTwoLayerVisibility:
    @pytest.mark.asyncio
    async def test_private_de_A_invisible_para_B(self, db):
        ind = await _mk(db, "10.0.0.1", TA)
        assert await ti.get_indicator(db, ind.id, tenant_id=TA) is not None   # dueño ve
        assert await ti.get_indicator(db, ind.id, tenant_id=TB) is None       # otro NO ve (IDOR cerrado)
        assert await ti.get_indicator(db, ind.id, tenant_id=None) is None     # scope global NO ve privados

    @pytest.mark.asyncio
    async def test_global_visible_para_todos(self, db):
        ind = await _mk(db, "10.0.0.2", None)                                 # CAPA 0
        assert await ti.get_indicator(db, ind.id, tenant_id=TA) is not None
        assert await ti.get_indicator(db, ind.id, tenant_id=TB) is not None
        assert await ti.get_indicator(db, ind.id, tenant_id=None) is not None

    @pytest.mark.asyncio
    async def test_list_devuelve_global_mas_propio_no_ajeno(self, db):
        await _mk(db, "1.1.1.1", None)   # global
        await _mk(db, "2.2.2.2", TA)     # privado A
        await _mk(db, "3.3.3.3", TB)     # privado B
        rows_a, total_a = await ti.list_indicators(db, tenant_id=TA)
        vals_a = {r.value for r in rows_a}
        assert "1.1.1.1" in vals_a and "2.2.2.2" in vals_a
        assert "3.3.3.3" not in vals_a          # NO ve el privado de B
        assert total_a == 2

    @pytest.mark.asyncio
    async def test_enrich_no_filtra_privado_ajeno(self, db):
        await _mk(db, "9.9.9.9", TA, itype="ip")
        await _mk(db, "7.7.7.7", None, itype="ip")
        # B enriquece: NO debe hacer match con el privado de A, sí con el global
        m_priv = await ti.enrich(db, "9.9.9.9", "ip", tenant_id=TB)
        m_glob = await ti.enrich(db, "7.7.7.7", "ip", tenant_id=TB)
        assert m_priv == []
        assert len(m_glob) == 1

    @pytest.mark.asyncio
    async def test_update_ajeno_rechazado(self, db):
        ind = await _mk(db, "5.5.5.5", TA)
        # B intenta actualizar el privado de A → None (no visible = no editable)
        assert await ti.update_indicator(db, ind.id, {"severity": "critical"}, tenant_id=TB) is None
        # A sí puede
        upd = await ti.update_indicator(db, ind.id, {"severity": "critical"}, tenant_id=TA)
        assert upd is not None and upd.severity == "critical"

    @pytest.mark.asyncio
    async def test_delete_ajeno_rechazado(self, db):
        ind = await _mk(db, "6.6.6.6", TA)
        assert await ti.delete_indicator(db, ind.id, tenant_id=TB) is False
        assert await ti.delete_indicator(db, ind.id, tenant_id=TA) is True

    @pytest.mark.asyncio
    async def test_stats_scopeados(self, db):
        await _mk(db, "1.0.0.1", None)   # global
        await _mk(db, "1.0.0.2", TA)     # privado A
        await _mk(db, "1.0.0.3", TB)     # privado B
        st_a = await ti.get_stats(db, tenant_id=TA)
        assert st_a["total"] == 2        # global + propio, no el de B

    @pytest.mark.asyncio
    async def test_bulk_import_no_colisiona_entre_tenants(self, db):
        # mismo (type,value) importado por A y por B → dos registros privados distintos
        await ti.bulk_import(db, [{"indicator_type": "ip", "value": "4.4.4.4"}], tenant_id=TA)
        r = await ti.bulk_import(db, [{"indicator_type": "ip", "value": "4.4.4.4"}], tenant_id=TB)
        assert r["created"] == 1 and r["updated"] == 0   # no vio el de A → creó el suyo
        rows_a, _ = await ti.list_indicators(db, tenant_id=TA)
        rows_b, _ = await ti.list_indicators(db, tenant_id=TB)
        assert "4.4.4.4" in {x.value for x in rows_a}
        assert "4.4.4.4" in {x.value for x in rows_b}
