"""
S108-Ops.1 — /health/platform: monitoreo de plataforma por frescura de latidos.

Prueba el lector que FALTABA (el feature estaba inconcluso): resumen público sin
fuga de cadencia, detalle por-job con auth, y degradación honesta si la tabla no
existe (migración pendiente).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text

from asc_api.api.v1.endpoints.health import _overall_platform_status


async def _mk_table(db):
    await db.execute(text(
        "CREATE TABLE IF NOT EXISTS platform_heartbeats ("
        "id VARCHAR(64) PRIMARY KEY, last_seen_at TIMESTAMP NOT NULL, "
        "last_status VARCHAR(16) NOT NULL DEFAULT 'ok', "
        "consecutive_failures INTEGER NOT NULL DEFAULT 0, detail TEXT)"
    ))
    await db.commit()


async def _beat(db, job, when, status="ok"):
    await db.execute(
        text("INSERT INTO platform_heartbeats (id,last_seen_at,last_status,consecutive_failures) "
             "VALUES (:id,:ts,:st,0)"),
        {"id": job, "ts": when.isoformat(), "st": status},
    )
    await db.commit()


class TestOverallHelper:
    def test_unknown_sin_datos(self):
        assert _overall_platform_status(None) == "unknown"
        assert _overall_platform_status([]) == "unknown"

    def test_operational_todo_fresco_ok(self):
        assert _overall_platform_status([{"stale": False, "last_status": "ok"}]) == "operational"

    def test_degraded_por_rancio_o_error(self):
        assert _overall_platform_status([{"stale": True, "last_status": "ok"}]) == "degraded"
        assert _overall_platform_status([{"stale": False, "last_status": "error"}]) == "degraded"


class TestPlatformEndpoint:
    @pytest.mark.asyncio
    async def test_unknown_sin_tabla(self, client):
        # SQLite de test no tiene la tabla → degradación honesta, no 500
        r = await client.get("/api/v1/health/platform")
        assert r.status_code == 200
        assert r.json()["status"] == "unknown"

    @pytest.mark.asyncio
    async def test_operational_con_latido_fresco(self, client, db):
        await _mk_table(db)
        await _beat(db, "watchdog-supabase", datetime.now(timezone.utc))
        r = await client.get("/api/v1/health/platform")
        assert r.json()["status"] == "operational"
        assert r.json()["jobs_total"] == 1 and r.json()["jobs_stale"] == 0

    @pytest.mark.asyncio
    async def test_degraded_con_latido_rancio(self, client, db):
        await _mk_table(db)
        await _beat(db, "watchdog-supabase", datetime.now(timezone.utc) - timedelta(minutes=30))
        r = await client.get("/api/v1/health/platform")
        assert r.json()["status"] == "degraded"
        assert r.json()["jobs_stale"] == 1

    @pytest.mark.asyncio
    async def test_publico_no_filtra_detalle_por_job(self, client, db):
        await _mk_table(db)
        await _beat(db, "cron-escalation", datetime.now(timezone.utc))
        r = await client.get("/api/v1/health/platform")
        assert "jobs" not in r.json()               # sin lista por-job
        assert "cron-escalation" not in r.text       # sin nombres de job (anti-inteligencia)

    @pytest.mark.asyncio
    async def test_detalle_requiere_auth(self, client):
        r = await client.get("/api/v1/health/platform/detail")
        assert r.status_code in (401, 403)
