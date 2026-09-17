"""add account funding records

Revision ID: 20260917_0016
Revises: 20260917_0015
Create Date: 2026-09-17 00:00:02
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260917_0016"
down_revision: str | None = "20260917_0015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "account_fundings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("funding_id", sa.Uuid(), nullable=False),
        sa.Column("amount_micro_usd", sa.Integer(), nullable=False),
        sa.Column("currency", sa.String(length=3), nullable=False),
        sa.Column("gateway", sa.String(length=64), nullable=False),
        sa.Column("external_payment_id", sa.String(length=255), nullable=True),
        sa.Column("external_customer_id", sa.String(length=255), nullable=True),
        sa.Column("idempotency_key", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=64), nullable=False),
        sa.Column("succeeded_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ledger_transaction_id", sa.Uuid(), nullable=True),
        sa.Column("succeeded_event_id", sa.String(length=255), nullable=True),
        sa.Column("reason_code", sa.String(length=128), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
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
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("funding_id"),
        sa.UniqueConstraint(
            "account_id",
            "idempotency_key",
            name="uq_account_fundings_account_idempotency",
        ),
        sa.UniqueConstraint(
            "gateway",
            "external_payment_id",
            name="uq_account_fundings_external_payment",
        ),
        sa.UniqueConstraint(
            "ledger_transaction_id",
            name="uq_account_fundings_ledger_transaction",
        ),
    )
    op.create_index(
        "ix_account_fundings_account_created_at",
        "account_fundings",
        ["account_id", "created_at"],
    )
    op.create_index(
        "ix_account_fundings_external_payment",
        "account_fundings",
        ["gateway", "external_payment_id"],
    )
    op.create_table(
        "payment_webhook_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("gateway", sa.String(length=64), nullable=False),
        sa.Column("external_event_id", sa.String(length=255), nullable=False),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("processing_status", sa.String(length=64), nullable=False),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("funding_id", sa.Uuid(), nullable=True),
        sa.Column("external_payment_id", sa.String(length=255), nullable=True),
        sa.Column("reason_code", sa.String(length=128), nullable=True),
        sa.Column("safe_payload", sa.JSON(), nullable=False),
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
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "gateway",
            "external_event_id",
            name="uq_payment_webhook_events_gateway_event",
        ),
    )
    op.create_index(
        "ix_payment_webhook_events_received",
        "payment_webhook_events",
        ["gateway", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_payment_webhook_events_received", table_name="payment_webhook_events")
    op.drop_table("payment_webhook_events")
    op.drop_index("ix_account_fundings_external_payment", table_name="account_fundings")
    op.drop_index("ix_account_fundings_account_created_at", table_name="account_fundings")
    op.drop_table("account_fundings")
