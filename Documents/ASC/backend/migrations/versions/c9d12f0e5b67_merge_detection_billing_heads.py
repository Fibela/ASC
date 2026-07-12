"""merge detection_billing and main migration heads

Revision ID: c9d12f0e5b67
Revises: a8c01v9x3y26, b3c4d5e6f7a8
Create Date: 2026-07-11 00:00:00.000000

Merges the detection_rules/billing_plans branch (b3c4d5e6f7a8, branched from
z6t89u7x1s14) back into the main chain (a8c01v9x3y26) to resolve the two-head
situation and restore a single Alembic head.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "c9d12f0e5b67"
down_revision: Union[str, Sequence[str], None] = ("a8c01v9x3y26", "b3c4d5e6f7a8")
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
