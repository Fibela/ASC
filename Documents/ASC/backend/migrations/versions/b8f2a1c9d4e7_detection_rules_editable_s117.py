"""S117.4 — detection rules: editable conditions + seed DET-005..014

Adds `conditions` (JSON) and `match_type` columns to detection_rules so rules are
data-driven (editable without code), then seeds 10 new MITRE-mapped rules covering
execution, credential access, persistence, defense evasion and C2.

The seed is imported from asc_api.services.detection_rules.SEED_RULES so the DB
catalogue, the runtime evaluator and the unit tests all share ONE source of truth
(prevents catalogue-vs-engine drift).

Revision ID: b8f2a1c9d4e7
Revises: a7u90v8y2t15
Create Date: 2026-07-23
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import sqlalchemy as sa
from alembic import op

from asc_api.services.detection_rules import SEED_RULES

revision = "b8f2a1c9d4e7"
down_revision = "a7u90v8y2t15"
branch_labels = None
depends_on = None

_NOW = datetime(2026, 7, 23, tzinfo=timezone.utc)
_NEW_RULE_IDS = [r["rule_id"] for r in SEED_RULES]


def upgrade() -> None:
    op.add_column(
        "detection_rules",
        sa.Column("conditions", sa.JSON(), nullable=False, server_default="[]"),
    )
    op.add_column(
        "detection_rules",
        sa.Column("match_type", sa.String(10), nullable=False, server_default="all"),
    )

    rules_tbl = sa.table(
        "detection_rules",
        sa.column("id", sa.String),
        sa.column("rule_id", sa.String),
        sa.column("name", sa.String),
        sa.column("mitre_ttp", sa.String),
        sa.column("severity", sa.String),
        sa.column("description", sa.Text),
        sa.column("tags", sa.JSON),
        sa.column("risk_score_default", sa.Float),
        sa.column("is_active", sa.Boolean),
        sa.column("conditions", sa.JSON),
        sa.column("match_type", sa.String),
        sa.column("created_at", sa.DateTime),
        sa.column("updated_at", sa.DateTime),
    )
    op.bulk_insert(
        rules_tbl,
        [
            {
                "id": str(uuid.uuid4()),
                "rule_id": r["rule_id"],
                "name": r["name"],
                "mitre_ttp": r["mitre_ttp"],
                "severity": r["severity"],
                "description": r["description"],
                "tags": r["tags"],
                "risk_score_default": r["risk_score"],
                "is_active": True,
                "conditions": r["conditions"],
                "match_type": r["match_type"],
                "created_at": _NOW,
                "updated_at": _NOW,
            }
            for r in SEED_RULES
        ],
    )


def downgrade() -> None:
    ids = ", ".join(f"'{rid}'" for rid in _NEW_RULE_IDS)
    op.execute(f"DELETE FROM detection_rules WHERE rule_id IN ({ids})")  # noqa: S608 — ids are literals
    op.drop_column("detection_rules", "match_type")
    op.drop_column("detection_rules", "conditions")
