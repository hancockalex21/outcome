"""add verification orchestration metadata

Revision ID: 20260915_0012
Revises: 20260914_0011
Create Date: 2026-09-15 00:00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260915_0012"
down_revision: str | None = "20260914_0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("verification_requests") as batch_op:
        batch_op.add_column(sa.Column("idempotency_key", sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column("request_fingerprint", sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column("lifecycle_state", sa.String(length=64), nullable=True))
        batch_op.add_column(
            sa.Column("request_config_version", sa.String(length=128), nullable=True)
        )
        batch_op.add_column(sa.Column("lifecycle_metadata", sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("failed_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.alter_column("lifecycle_state", nullable=False)
        batch_op.alter_column("lifecycle_metadata", nullable=False)
        batch_op.create_unique_constraint(
            "uq_verification_requests_idempotency",
            ["account_id", "idempotency_key"],
        )
    op.create_index(
        "ix_verification_requests_idempotency",
        "verification_requests",
        ["account_id", "idempotency_key"],
    )


def downgrade() -> None:
    op.drop_index("ix_verification_requests_idempotency", table_name="verification_requests")
    with op.batch_alter_table("verification_requests") as batch_op:
        batch_op.drop_constraint("uq_verification_requests_idempotency", type_="unique")
        batch_op.drop_column("failed_at")
        batch_op.drop_column("completed_at")
        batch_op.drop_column("lifecycle_metadata")
        batch_op.drop_column("request_config_version")
        batch_op.drop_column("lifecycle_state")
        batch_op.drop_column("request_fingerprint")
        batch_op.drop_column("idempotency_key")
