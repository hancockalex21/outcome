"""add provider rights fields

Revision ID: 20260914_0006
Revises: 20260914_0005
Create Date: 2026-09-14 00:00:01
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260914_0006"
down_revision: str | None = "20260914_0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("provider_rights") as batch_op:
        batch_op.add_column(sa.Column("provider_alias", sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column("capability", sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column("billing_mode", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("enabled", sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column("rights_status", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("permitted_regions", sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column("permitted_data_use", sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column("permitted_execution_modes", sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column("customer_secret_required", sa.Boolean(), nullable=True))
        batch_op.add_column(
            sa.Column("outcome_managed_credential_allowed", sa.Boolean(), nullable=True)
        )
        batch_op.add_column(
            sa.Column("customer_managed_credential_allowed", sa.Boolean(), nullable=True)
        )
        batch_op.add_column(sa.Column("evidence_retention_allowed", sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column("caching_allowed", sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column("commercial_usage_allowed", sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column("automated_agent_usage_allowed", sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column("rights_version", sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column("effective_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("reason_code", sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column("tenant_restrictions", sa.JSON(), nullable=True))

        batch_op.alter_column("provider_alias", nullable=False)
        batch_op.alter_column("capability", nullable=False)
        batch_op.alter_column("billing_mode", nullable=False)
        batch_op.alter_column("enabled", nullable=False)
        batch_op.alter_column("rights_status", nullable=False)
        batch_op.alter_column("permitted_regions", nullable=False)
        batch_op.alter_column("permitted_data_use", nullable=False)
        batch_op.alter_column("permitted_execution_modes", nullable=False)
        batch_op.alter_column("customer_secret_required", nullable=False)
        batch_op.alter_column("outcome_managed_credential_allowed", nullable=False)
        batch_op.alter_column("customer_managed_credential_allowed", nullable=False)
        batch_op.alter_column("evidence_retention_allowed", nullable=False)
        batch_op.alter_column("caching_allowed", nullable=False)
        batch_op.alter_column("commercial_usage_allowed", nullable=False)
        batch_op.alter_column("automated_agent_usage_allowed", nullable=False)
        batch_op.alter_column("rights_version", nullable=False)
        batch_op.alter_column("effective_at", nullable=False)
        batch_op.alter_column("reason_code", nullable=False)
        batch_op.alter_column("tenant_restrictions", nullable=False)

    op.create_index(
        "ix_provider_rights_provider_capability",
        "provider_rights",
        ["provider_id", "capability"],
    )


def downgrade() -> None:
    op.drop_index("ix_provider_rights_provider_capability", table_name="provider_rights")
    with op.batch_alter_table("provider_rights") as batch_op:
        batch_op.drop_column("tenant_restrictions")
        batch_op.drop_column("reason_code")
        batch_op.drop_column("expires_at")
        batch_op.drop_column("effective_at")
        batch_op.drop_column("rights_version")
        batch_op.drop_column("automated_agent_usage_allowed")
        batch_op.drop_column("commercial_usage_allowed")
        batch_op.drop_column("caching_allowed")
        batch_op.drop_column("evidence_retention_allowed")
        batch_op.drop_column("customer_managed_credential_allowed")
        batch_op.drop_column("outcome_managed_credential_allowed")
        batch_op.drop_column("customer_secret_required")
        batch_op.drop_column("permitted_execution_modes")
        batch_op.drop_column("permitted_data_use")
        batch_op.drop_column("permitted_regions")
        batch_op.drop_column("rights_status")
        batch_op.drop_column("enabled")
        batch_op.drop_column("billing_mode")
        batch_op.drop_column("capability")
        batch_op.drop_column("provider_alias")
