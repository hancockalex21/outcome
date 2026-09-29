"""add controlled beta registration records and promotional credit classification

Revision ID: 20260929_0018
Revises: 20260917_0017
Create Date: 2026-09-29 00:00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260929_0018"
down_revision: str | None = "20260917_0017"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "beta_registration_capacity",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("registrations_used", sa.Integer(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.bulk_insert(
        sa.table(
            "beta_registration_capacity",
            sa.column("id", sa.Integer()),
            sa.column("registrations_used", sa.Integer()),
        ),
        [{"id": 1, "registrations_used": 0}],
    )
    op.create_table(
        "beta_registrations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("idempotency_key_hash", sa.String(length=128), nullable=False),
        sa.Column("request_fingerprint", sa.String(length=128), nullable=False),
        sa.Column("agent_id", sa.Uuid(), nullable=False),
        sa.Column("credential_id", sa.Uuid(), nullable=False),
        sa.Column("policy_id", sa.Uuid(), nullable=False),
        sa.Column("promotional_ledger_transaction_id", sa.Uuid(), nullable=False),
        sa.Column("promotional_credit_micro_usd", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=64), nullable=False),
        sa.Column("account_id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["account_id"], ["accounts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["credential_id"], ["agent_credentials.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["policy_id"], ["policies.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["promotional_ledger_transaction_id"],
            ["credit_ledger_transactions.transaction_id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("account_id", name="uq_beta_registrations_account"),
        sa.UniqueConstraint("credential_id", name="uq_beta_registrations_credential"),
        sa.UniqueConstraint("idempotency_key_hash", name="uq_beta_registrations_idempotency_hash"),
        sa.UniqueConstraint("policy_id", name="uq_beta_registrations_policy"),
        sa.UniqueConstraint(
            "promotional_ledger_transaction_id",
            name="uq_beta_registrations_promotional_ledger",
        ),
    )
    op.create_index(
        "ix_beta_registrations_account_created_at",
        "beta_registrations",
        ["account_id", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_beta_registrations_account_created_at", table_name="beta_registrations")
    op.drop_table("beta_registrations")
    op.drop_table("beta_registration_capacity")
