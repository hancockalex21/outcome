"""add verification score factors

Revision ID: 20260914_0011
Revises: 20260914_0010
Create Date: 2026-09-14 00:00:06
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260914_0011"
down_revision: str | None = "20260914_0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("verification_results") as batch_op:
        batch_op.add_column(
            sa.Column("evidence_score_version", sa.String(length=128), nullable=True)
        )
        batch_op.add_column(sa.Column("score_factors", sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column("evidence_ids_used", sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column("evidence_ids_excluded", sa.JSON(), nullable=True))
        batch_op.alter_column("score_factors", nullable=False)
        batch_op.alter_column("evidence_ids_used", nullable=False)
        batch_op.alter_column("evidence_ids_excluded", nullable=False)


def downgrade() -> None:
    with op.batch_alter_table("verification_results") as batch_op:
        batch_op.drop_column("evidence_ids_excluded")
        batch_op.drop_column("evidence_ids_used")
        batch_op.drop_column("score_factors")
        batch_op.drop_column("evidence_score_version")
