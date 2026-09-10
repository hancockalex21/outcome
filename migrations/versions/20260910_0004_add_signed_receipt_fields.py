"""add signed receipt fields

Revision ID: 20260910_0004
Revises: 20260910_0003
Create Date: 2026-09-10 00:00:03
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260910_0004"
down_revision: str | None = "20260910_0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("receipts") as batch_op:
        batch_op.add_column(
            sa.Column(
                "authorization_request_id",
                sa.Uuid(as_uuid=True),
                sa.ForeignKey(
                    "authorization_requests.id",
                    name="fk_receipts_authorization_request_id",
                    ondelete="SET NULL",
                ),
                nullable=True,
            )
        )
        batch_op.add_column(sa.Column("canonical_payload", sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column("action_hash", sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column("signature", sa.String(length=512), nullable=True))
        batch_op.add_column(sa.Column("signing_key_id", sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column("issued_at", sa.DateTime(timezone=True), nullable=True))

        batch_op.alter_column("canonical_payload", nullable=False)
        batch_op.alter_column("action_hash", nullable=False)
        batch_op.alter_column("signature", nullable=False)
        batch_op.alter_column("signing_key_id", nullable=False)
        batch_op.alter_column("issued_at", nullable=False)


def downgrade() -> None:
    with op.batch_alter_table("receipts") as batch_op:
        batch_op.drop_column("issued_at")
        batch_op.drop_column("signing_key_id")
        batch_op.drop_column("signature")
        batch_op.drop_column("action_hash")
        batch_op.drop_column("canonical_payload")
        batch_op.drop_column("authorization_request_id")
