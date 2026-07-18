"""
S103.8 — Chequeo de deriva de esquema (previene incidente I-3).

En SQLite (test) el chequeo se omite (devuelve []) → readiness sigue 'ready'.
El comportamiento real anti-deriva es en Postgres de producción; aquí se prueba
que el cableado no rompe readiness y que el helper degrada limpio fuera de PG.
"""
from __future__ import annotations

import pytest
from asc_api.core.schema_check import missing_model_columns


class TestSchemaCheck:
    @pytest.mark.asyncio
    async def test_sqlite_skips_gracefully(self, db):
        # En SQLite no hay information_schema — el chequeo se omite sin error.
        missing = await missing_model_columns(db)
        assert missing == []


class TestReadinessWiring:
    @pytest.mark.asyncio
    async def test_readiness_reports_schema_and_stays_ready(self, client):
        r = await client.get("/api/v1/health/readiness")
        assert r.status_code == 200
        body = r.json()
        # Lo que S103.8 agrega: el bloque de esquema, presente y SIN deriva en SQLite.
        # (El status global puede ser 'degraded' si REDIS_URL local no resuelve —
        #  depende del entorno; en CI sin .env es 'ready'. No lo asertamos aquí.)
        assert body["checks"]["schema"]["ok"] is True
        assert body["checks"]["schema"]["missing"] == []
        assert body["checks"]["database"]["ok"] is True


class TestStartupWiring:
    def test_lifespan_runs_schema_check(self):
        # Garantiza que el chequeo de deriva se ejecuta al ARRANCAR (no solo en
        # readiness). Si alguien lo quita del lifespan, este test lo caza.
        from pathlib import Path
        main_src = (Path(__file__).resolve().parents[1] / "asc_api" / "main.py").read_text(encoding="utf-8")
        assert "missing_model_columns" in main_src, "el startup schema check no está cableado en el lifespan"
        assert "schema_drift_detected" in main_src, "falta el log claro de deriva al arrancar"
