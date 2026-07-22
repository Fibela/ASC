"""platform_heartbeats — continuous production monitoring

Revision ID: a7u90v8y2t15
Revises: z6t89u7x1s14
Create Date: 2026-07-22

Tabla de latidos usada por:
  - Vercel Cron endpoints (escriben cada vez que corren)
  - Supabase Edge Function watchdog (escribe desde infraestructura AWS independiente)

El endpoint GET /api/v1/health/platform lee esta tabla y reporta
cuáles jobs están frescos y cuáles llevan demasiado tiempo sin reportar.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "a7u90v8y2t15"
down_revision = "e37196d70ecb"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "platform_heartbeats",
        sa.Column("id", sa.String(64), primary_key=True,
                  comment="Job identifier — e.g. 'cron-heartbeat', 'watchdog-supabase'"),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_status", sa.String(16), nullable=False, server_default="ok",
                  comment="'ok' | 'error' | 'unreachable'"),
        sa.Column("consecutive_failures", sa.Integer, nullable=False, server_default="0"),
        sa.Column("detail", sa.Text, nullable=True,
                  comment="Error message or extra context on last run"),
    )


def downgrade() -> None:
    op.drop_table("platform_heartbeats")
