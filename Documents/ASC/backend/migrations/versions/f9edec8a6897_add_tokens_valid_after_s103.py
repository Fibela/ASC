"""add_tokens_valid_after_s103

Revision ID: f9edec8a6897
Revises: f309a0115906
Create Date: 2026-07-16

S103.3 — Invalidación de sesión por epoch. `users.tokens_valid_after` marca el
instante tras el cual un cambio de contraseña (o logout-all) invalida TODOS los
tokens previos (access + refresh de cualquier dispositivo). NULL = sin corte.

ID hex real (uuid4) sobre head f309a0115906.
"""
from alembic import op
import sqlalchemy as sa

revision = "f9edec8a6897"
down_revision = "f309a0115906"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("tokens_valid_after", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("users", "tokens_valid_after")
