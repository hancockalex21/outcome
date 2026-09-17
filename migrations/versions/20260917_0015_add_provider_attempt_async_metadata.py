"""add provider attempt async metadata

Revision ID: 20260917_0015
Revises: 20260915_0014
Create Date: 2026-09-17 00:00:01
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260917_0015"
down_revision: str | None = "20260915_0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("provider_attempts") as batch_op:
        batch_op.add_column(sa.Column("capability", sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column("attempt_number", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("planned_order", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("started_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("latency_ms", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("timeout_ms", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("deadline_exceeded", sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column("health_effect", sa.String(length=128), nullable=True))
        batch_op.add_column(
            sa.Column(
                "attempt_metadata",
                sa.JSON(),
                nullable=False,
                server_default=sa.text("'{}'"),
            )
        )
        batch_op.alter_column("attempt_metadata", server_default=None)


def downgrade() -> None:
    with op.batch_alter_table("provider_attempts") as batch_op:
        batch_op.drop_column("attempt_metadata")
        batch_op.drop_column("health_effect")
        batch_op.drop_column("deadline_exceeded")
        batch_op.drop_column("timeout_ms")
        batch_op.drop_column("latency_ms")
        batch_op.drop_column("completed_at")
        batch_op.drop_column("started_at")
        batch_op.drop_column("planned_order")
        batch_op.drop_column("attempt_number")
        batch_op.drop_column("capability")
