"""add_onboarding_p53

P53 — Onboarding Flow.

Adds email verification and onboarding step tracking to the users table.
All columns use server defaults that preserve existing user functionality:
  - email_verified defaults to TRUE so legacy users are auto-verified.
  - onboarding_step defaults to 'completed' so legacy users are unaffected.
  - Token fields are nullable — only set during the onboarding registration flow.

Revision ID: r8l01o0q3k05
Revises: p6j79m8o1i93
Create Date: 2026-06-14
"""
from alembic import op
import sqlalchemy as sa

revision = "r8l01o0q3k05"
down_revision = "p6j79m8o1i93"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Email verification: TRUE default ensures no existing user is locked out.
    op.add_column(
        "users",
        sa.Column("email_verified", sa.Boolean(), nullable=False, server_default="true"),
    )
    # SHA-256 hash of the one-time verification token (never the raw token).
    op.add_column(
        "users",
        sa.Column("email_verification_token", sa.String(64), nullable=True),
    )
    op.create_index("ix_users_email_verification_token", "users", ["email_verification_token"])
    # Expiry timestamp for the verification token.
    op.add_column(
        "users",
        sa.Column("email_verification_expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    # Wizard step tracker: pending_email → pending_setup → completed.
    # Default 'completed' keeps legacy users unaffected.
    op.add_column(
        "users",
        sa.Column("onboarding_step", sa.String(50), nullable=False, server_default="completed"),
    )


def downgrade() -> None:
    op.drop_column("users", "onboarding_step")
    op.drop_column("users", "email_verification_expires_at")
    op.drop_index("ix_users_email_verification_token", table_name="users")
    op.drop_column("users", "email_verification_token")
    op.drop_column("users", "email_verified")
