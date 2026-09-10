"""add double entry ledger fields

Revision ID: 20260910_0003
Revises: 20260910_0002
Create Date: 2026-09-10 00:00:02
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260910_0003"
down_revision: str | None = "20260910_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "credit_ledger_transactions",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column(
            "account_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("accounts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("transaction_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("idempotency_key", sa.String(length=255), nullable=False),
        sa.Column("transaction_type", sa.String(length=64), nullable=False),
        sa.Column("amount_micro_usd", sa.Integer(), nullable=False),
        sa.Column("currency", sa.String(length=3), nullable=False),
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
            "idempotency_key",
            name="uq_credit_ledger_transactions_idempotency",
        ),
    )
    op.create_index(
        "ix_credit_ledger_transactions_account_created_at",
        "credit_ledger_transactions",
        ["account_id", "created_at"],
    )
    op.create_index(
        "ix_credit_ledger_transactions_transaction_id",
        "credit_ledger_transactions",
        ["transaction_id"],
        unique=True,
    )
    op.add_column(
        "credit_ledger_entries",
        sa.Column("transaction_id", sa.Uuid(as_uuid=True), nullable=True),
    )
    op.add_column(
        "credit_ledger_entries",
        sa.Column("ledger_account", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "credit_ledger_entries",
        sa.Column("direction", sa.String(length=16), nullable=True),
    )
    op.add_column(
        "credit_ledger_entries",
        sa.Column("amount_micro_usd", sa.Integer(), nullable=True),
    )

    op.alter_column("credit_ledger_entries", "transaction_id", nullable=False)
    op.alter_column("credit_ledger_entries", "ledger_account", nullable=False)
    op.alter_column("credit_ledger_entries", "direction", nullable=False)
    op.alter_column("credit_ledger_entries", "amount_micro_usd", nullable=False)
    op.create_index(
        "ix_credit_ledger_entries_transaction_id",
        "credit_ledger_entries",
        ["transaction_id"],
    )

def downgrade() -> None:
    op.drop_index("ix_credit_ledger_entries_transaction_id", table_name="credit_ledger_entries")
    op.drop_column("credit_ledger_entries", "amount_micro_usd")
    op.drop_column("credit_ledger_entries", "direction")
    op.drop_column("credit_ledger_entries", "ledger_account")
    op.drop_column("credit_ledger_entries", "transaction_id")
    op.drop_index(
        "ix_credit_ledger_transactions_transaction_id",
        table_name="credit_ledger_transactions",
    )
    op.drop_index(
        "ix_credit_ledger_transactions_account_created_at",
        table_name="credit_ledger_transactions",
    )
    op.drop_table("credit_ledger_transactions")
