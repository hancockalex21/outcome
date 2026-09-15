"""add policy hash metadata

Revision ID: 20260915_0013
Revises: 20260915_0012
Create Date: 2026-09-15 00:00:01
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260915_0013"
down_revision: str | None = "20260915_0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("policies") as batch_op:
        batch_op.add_column(sa.Column("policy_hash", sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column("effective_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("published_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_policies_account_version", "policies", ["account_id", "version"])


def downgrade() -> None:
    op.drop_index("ix_policies_account_version", table_name="policies")
    with op.batch_alter_table("policies") as batch_op:
        batch_op.drop_column("published_at")
        batch_op.drop_column("effective_at")
        batch_op.drop_column("policy_hash")
