"""
Chequeo de deriva de esquema (S103.8) — columnas de los modelos ORM vs DB real.

Motivación: incidente I-3 (2026-07-17). La migración `tokens_valid_after` se aplicó
DESPUÉS del deploy; el modelo `User` referenciaba la columna, la DB no la tenía, y
toda query de usuario tiró 500 (portal caído: asc_unreachable). `/health/readiness`
solo hacía `SELECT 1`, que pasa igual → reportaba `database: ok` con el app caído.

Este chequeo compara las columnas mapeadas en `Base.metadata` contra
`information_schema.columns` y devuelve las faltantes. Cableado en readiness, habría
cazado I-3 antes de que el portal cayera. Solo Postgres (producción); en SQLite de
test se omite (devuelve []).
"""
from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from asc_api.db.base import Base


async def missing_model_columns(db: AsyncSession) -> list[str]:
    """
    Devuelve ["tabla.columna", ...] mapeadas por el ORM pero AUSENTES en la DB.

    Solo considera tablas que existen en la DB (una tabla entera ausente es otro
    problema y no se reporta aquí para no ensuciar la señal). Vacío = sin deriva.
    """
    bind = db.get_bind()
    if bind.dialect.name != "postgresql":
        # Introspección vía information_schema es específica de Postgres.
        # En el SQLite de los tests no aplica — se omite (no es deriva real).
        return []

    rows = (
        await db.execute(
            text(
                "SELECT table_name, column_name FROM information_schema.columns "
                "WHERE table_schema = 'public'"
            )
        )
    ).all()

    actual: dict[str, set[str]] = {}
    for table_name, column_name in rows:
        actual.setdefault(table_name, set()).add(column_name)

    missing: list[str] = []
    for table_name, table in Base.metadata.tables.items():
        if table_name not in actual:
            continue  # tabla ausente = otro problema; no reportamos sus columnas
        present = actual[table_name]
        for col in table.columns:
            if col.name not in present:
                missing.append(f"{table_name}.{col.name}")
    return sorted(missing)
