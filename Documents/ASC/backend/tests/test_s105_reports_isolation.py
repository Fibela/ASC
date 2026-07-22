"""
S105.2 — Aislamiento multi-tenant de reportes (ejecutivos + PDF/HTML).

Prueba la frontera real:
  - KPIs se agregan SOLO sobre datos del tenant (no mezcla números entre clientes).
  - get/list de reportes ejecutivos scopeados (un tenant no ve reportes de otro).
  - _build_report_data (PDF/HTML) scopea alertas por tenant.

Modelo: NULL = reporte/dato global (single-tenant legacy). tenant_id = privado.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from asc_api.services import reporting_service as rs
from asc_api.models.incident import Incident
from asc_api.models.executive_report import ExecutiveReport
from asc_api.models.alert import Alert
from asc_api.api.v1.endpoints.reports import _build_report_data

TA = "tenant-aaaa"
TB = "tenant-bbbb"
NOW = datetime.now(timezone.utc)
START = NOW - timedelta(days=1)
END = NOW + timedelta(days=1)


def _report(tenant_id, rtype="weekly"):
    return ExecutiveReport(
        report_type=rtype, title="R", generated_by="sys",
        period_start=START, period_end=END,
        hash_sha3_512="0" * 128, signature_ed25519="sig",
        tenant_id=tenant_id,
    )


class TestReportTenantIsolation:
    @pytest.mark.asyncio
    async def test_incident_kpis_no_mezclan_tenants(self, db):
        db.add(Incident(title="A", created_by="s", tenant_id=TA, detected_at=NOW))
        db.add(Incident(title="B", created_by="s", tenant_id=TB, detected_at=NOW))
        db.add(Incident(title="G", created_by="s", tenant_id=None, detected_at=NOW))
        await db.commit()
        kpis_a = await rs._incident_kpis(db, START, END, TA)
        kpis_b = await rs._incident_kpis(db, START, END, TB)
        assert kpis_a["total"] == 1     # solo el de A, NO el de B ni el global
        assert kpis_b["total"] == 1

    @pytest.mark.asyncio
    async def test_get_report_ajeno_invisible(self, db):
        ra = _report(TA)
        db.add(ra)
        await db.commit()
        assert await rs.get_report(db, ra.id, tenant_id=TA) is not None
        assert await rs.get_report(db, ra.id, tenant_id=TB) is None   # IDOR cerrado

    @pytest.mark.asyncio
    async def test_list_reports_scopeado(self, db):
        db.add(_report(TA)); db.add(_report(TB)); db.add(_report(None))
        await db.commit()
        rows_a = await rs.list_reports(db, tenant_id=TA)
        tids = {r.tenant_id for r in rows_a}
        assert TB not in tids            # no ve los de B
        assert tids <= {TA, None}        # solo propio + global

    @pytest.mark.asyncio
    async def test_summary_scopeado(self, db):
        db.add(_report(TA)); db.add(_report(TB)); db.add(_report(TB))
        await db.commit()
        summ_a = await rs.get_reporting_summary(db, tenant_id=TA)
        assert summ_a["total_reports"] == 1      # solo el de A

    @pytest.mark.asyncio
    async def test_pdf_data_scopea_alertas(self, db):
        db.add(Alert(id="al-a", title="A", description="d", severity="high", status="open",
                     risk_score=0.5, tenant_id=TA, detected_at=NOW))
        db.add(Alert(id="al-b", title="B", description="d", severity="high", status="open",
                     risk_score=0.5, tenant_id=TB, detected_at=NOW))
        await db.commit()
        data_a = await _build_report_data(db, 24, "sys", tenant_id=TA)
        titles = {a["title"] for a in data_a["alerts"]}
        assert "A" in titles and "B" not in titles
        assert data_a["summary"]["total_alerts"] == 1
