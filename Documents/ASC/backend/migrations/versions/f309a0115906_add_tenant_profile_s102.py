"""add_tenant_profile_s102

Revision ID: f309a0115906
Revises: c9d12f0e5b67
Create Date: 2026-07-15

S102 — Módulo de explicación adaptativa.
Añade `profile` al tenant: define el registro de audiencia con el que
el explainer (claude-fable-5) traduce cada alerta. Valores: hogar | pyme |
enterprise. Se fija en onboarding; el admin puede cambiarlo.

ID generado con uuid4 (hex real de 12 chars — los IDs escritos a mano
quedaron prohibidos tras la auditoría S101).
"""
from alembic import op
import sqlalchemy as sa

revision = "f309a0115906"
down_revision = "c9d12f0e5b67"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "tenants",
        sa.Column(
            "profile",
            sa.String(20),
            nullable=False,
            server_default="pyme",
        ),
    )
    # Guardia de dominio a nivel DB — no confiar solo en la app.
    op.create_check_constraint(
        "profile_valid",
        "tenants",
        "profile IN ('hogar', 'pyme', 'enterprise')",
    )


def downgrade() -> None:
    op.drop_constraint("profile_valid", "tenants", type_="check")
    op.drop_column("tenants", "profile")
