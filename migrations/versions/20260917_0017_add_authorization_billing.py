"""add authorization billing records

Revision ID: 20260917_0017
Revises: 20260917_0016
Create Date: 2026-09-17 00:00:03
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260917_0017"
down_revision: str | None = "20260917_0016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "authorization_billings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("billing_id", sa.Uuid(), nullable=False),
        sa.Column("authorization_request_id", sa.Uuid(), nullable=False),
        sa.Column("pricing_version", sa.String(length=128), nullable=False),
        sa.Column("quote_fingerprint", sa.String(length=128), nullable=False),
        sa.Column("max_reserved_spend_micro_usd", sa.Integer(), nullable=False),
        sa.Column("reservation_id", sa.Uuid(), nullable=True),
        sa.Column("reservation_state", sa.String(length=64), nullable=True),
        sa.Column("actual_charge_micro_usd", sa.Integer(), nullable=True),
        sa.Column("settlement_ledger_transaction_id", sa.Uuid(), nullable=True),
        sa.Column("billing_state", sa.String(length=64), nullable=False),
        sa.Column("reserved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("settled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reason_code", sa.String(length=128), nullable=True),
        sa.Column("execution_mode", sa.String(length=64), nullable=False),
        sa.Column("billing_metadata", sa.JSON(), nullable=False),
        sa.Column("account_id", sa.Uuid(), nullable=False),
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
        sa.ForeignKeyConstraint(["account_id"], ["accounts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["authorization_request_id"],
            ["authorization_requests.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "account_id",
            "authorization_request_id",
            name="uq_authorization_billings_account_authorization",
        ),
        sa.UniqueConstraint(
            "settlement_ledger_transaction_id",
            name="uq_authorization_billings_settlement_ledger",
        ),
    )
    op.create_index(
        "ix_authorization_billings_account_created_at",
        "authorization_billings",
        ["account_id", "created_at"],
    )
    op.create_index(
        "ix_authorization_billings_billing_id",
        "authorization_billings",
        ["billing_id"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ix_authorization_billings_billing_id", table_name="authorization_billings")
    op.drop_index(
        "ix_authorization_billings_account_created_at",
        table_name="authorization_billings",
    )
    op.drop_table("authorization_billings")
