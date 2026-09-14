"""add customer provider credentials

Revision ID: 20260914_0007
Revises: 20260914_0006
Create Date: 2026-09-14 00:00:02
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260914_0007"
down_revision: str | None = "20260914_0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "customer_provider_credentials",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column(
            "account_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("accounts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("secret_ref", sa.String(length=255), nullable=False),
        sa.Column(
            "provider_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("providers.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("credential_type", sa.String(length=128), nullable=False),
        sa.Column("lifecycle_state", sa.String(length=64), nullable=False),
        sa.Column("version", sa.String(length=128), nullable=False),
        sa.Column("external_secret_locator", sa.String(length=512), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
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
            "provider_id",
            "secret_ref",
            name="uq_customer_provider_credentials_scope",
        ),
    )
    op.create_index(
        "ix_customer_provider_credentials_account_created_at",
        "customer_provider_credentials",
        ["account_id", "created_at"],
    )
    op.create_index(
        "ix_customer_provider_credentials_secret_ref",
        "customer_provider_credentials",
        ["secret_ref"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_customer_provider_credentials_secret_ref",
        table_name="customer_provider_credentials",
    )
    op.drop_index(
        "ix_customer_provider_credentials_account_created_at",
        table_name="customer_provider_credentials",
    )
    op.drop_table("customer_provider_credentials")
