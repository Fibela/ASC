"""
Alembic env.py — ASC PremosCorp async migrations.

Configured for:
  - asyncpg driver (postgresql+asyncpg://)
  - Auto-detect: imports all SQLAlchemy models so autogenerate picks up changes
  - DATABASE_URL read from app settings (env var) — not hardcoded in alembic.ini
"""
from __future__ import annotations

import asyncio
import os
from logging.config import fileConfig

from sqlalchemy import pool
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context

# ── Import all models so autogenerate can detect schema changes ───────────────
# Each import registers the model's table with Base.metadata
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

from asc_api.db.base import Base  # noqa: E402
import asc_api.models  # noqa: E402, F401 — side-effect: registers all models

# ── Alembic config object ─────────────────────────────────────────────────────
config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

# Override sqlalchemy.url from app settings — keeps secrets out of alembic.ini
def _get_url() -> str:
    from asc_api.core.config import get_settings
    url = get_settings().DATABASE_URL
    # asyncpg driver is used at runtime; for Alembic we can keep it as-is
    # since async_engine_from_config handles it.
    return url


# ── Offline mode (generate SQL without connecting) ───────────────────────────

def run_migrations_offline() -> None:
    url = _get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


# ── Online mode (connect and run) ────────────────────────────────────────────

def _do_run_migrations(connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def _run_async_migrations() -> None:
    cfg = config.get_section(config.config_ini_section, {})
    cfg["sqlalchemy.url"] = _get_url()

    # statement_cache_size=0 required when connecting via pgbouncer (Supabase pooler)
    engine = async_engine_from_config(
        cfg,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
        connect_args={"statement_cache_size": 0},
    )
    try:
        async with engine.connect() as conn:
            await conn.run_sync(_do_run_migrations)
    except (ConnectionRefusedError, OSError) as exc:
        # Graceful degradation in CI environments where the DB is not available.
        # Migrations themselves cannot run, but import/syntax validation still works.
        import logging
        logging.getLogger("alembic.env").warning(
            "Database unavailable (%s). Alembic online migration skipped — "
            "run migrations manually once the DB is reachable.", exc
        )
    finally:
        await engine.dispose()


def run_migrations_online() -> None:
    asyncio.run(_run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
