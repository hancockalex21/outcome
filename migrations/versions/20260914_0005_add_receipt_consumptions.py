"""add receipt consumptions

Revision ID: 20260914_0005
Revises: 20260910_0004
Create Date: 2026-09-14 00:00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260914_0005"
down_revision: str | None = "20260910_0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "receipt_consumptions",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column(
            "account_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("accounts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("consumption_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("receipt_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("authorization_request_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("action_hash", sa.String(length=128), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("execution_request_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "account_id",
            "receipt_id",
            name="uq_receipt_consumptions_receipt",
        ),
        sa.UniqueConstraint(
            "account_id",
            "execution_request_id",
            name="uq_receipt_consumptions_execution_request",
        ),
    )
    op.create_index(
        "ix_receipt_consumptions_account_created_at",
        "receipt_consumptions",
        ["account_id", "created_at"],
    )
    op.create_index(
        "ix_receipt_consumptions_receipt_id",
        "receipt_consumptions",
        ["receipt_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_receipt_consumptions_receipt_id", table_name="receipt_consumptions")
    op.drop_index(
        "ix_receipt_consumptions_account_created_at",
        table_name="receipt_consumptions",
    )
    op.drop_table("receipt_consumptions")
