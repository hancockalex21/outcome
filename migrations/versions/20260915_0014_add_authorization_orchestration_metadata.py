"""add authorization orchestration metadata

Revision ID: 20260915_0014
Revises: 20260915_0013
Create Date: 2026-09-15 00:00:02
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260915_0014"
down_revision: str | None = "20260915_0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("authorization_requests") as batch_op:
        batch_op.add_column(sa.Column("action_schema_version", sa.String(128), nullable=True))
        batch_op.add_column(sa.Column("policy_id", sa.Uuid(as_uuid=True), nullable=True))
        batch_op.add_column(sa.Column("policy_version", sa.String(128), nullable=True))
        batch_op.add_column(
            sa.Column("authorization_expires_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch_op.add_column(sa.Column("idempotency_key", sa.String(255), nullable=True))
        batch_op.add_column(sa.Column("request_fingerprint", sa.String(128), nullable=True))
        batch_op.add_column(
            sa.Column(
                "lifecycle_state",
                sa.String(64),
                nullable=False,
                server_default="RECEIVED",
            )
        )
        batch_op.add_column(sa.Column("request_config_version", sa.String(128), nullable=True))
        batch_op.add_column(
            sa.Column(
                "lifecycle_metadata",
                sa.JSON(),
                nullable=False,
                server_default=sa.text("'{}'"),
            )
        )
        batch_op.add_column(sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("failed_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.create_foreign_key(
            "fk_authorization_requests_policy_id",
            "policies",
            ["policy_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch_op.create_unique_constraint(
            "uq_authorization_requests_account_idempotency",
            ["account_id", "idempotency_key"],
        )
        batch_op.alter_column("lifecycle_state", server_default=None)
        batch_op.alter_column("lifecycle_metadata", server_default=None)
    op.create_index(
        "ix_authorization_requests_idempotency",
        "authorization_requests",
        ["account_id", "idempotency_key"],
    )

    with op.batch_alter_table("authorization_results") as batch_op:
        batch_op.add_column(sa.Column("policy_id", sa.Uuid(as_uuid=True), nullable=True))
        batch_op.add_column(sa.Column("policy_version", sa.String(128), nullable=True))
        batch_op.add_column(sa.Column("policy_hash", sa.String(128), nullable=True))
        batch_op.add_column(sa.Column("action_hash", sa.String(128), nullable=True))
        batch_op.add_column(sa.Column("action_schema_version", sa.String(128), nullable=True))
        batch_op.add_column(
            sa.Column("verification_result_id", sa.Uuid(as_uuid=True), nullable=True)
        )
        batch_op.add_column(
            sa.Column("verification_request_id", sa.Uuid(as_uuid=True), nullable=True)
        )
        batch_op.add_column(sa.Column("receipt_id", sa.Uuid(as_uuid=True), nullable=True))
        batch_op.add_column(
            sa.Column("authorization_expires_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch_op.add_column(
            sa.Column("provenance", sa.JSON(), nullable=False, server_default=sa.text("'{}'"))
        )
        batch_op.create_foreign_key(
            "fk_authorization_results_policy_id",
            "policies",
            ["policy_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch_op.create_foreign_key(
            "fk_authorization_results_verification_result_id",
            "verification_results",
            ["verification_result_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch_op.create_foreign_key(
            "fk_authorization_results_verification_request_id",
            "verification_requests",
            ["verification_request_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch_op.create_unique_constraint(
            "uq_authorization_results_account_request",
            ["account_id", "authorization_request_id"],
        )
        batch_op.alter_column("provenance", server_default=None)


def downgrade() -> None:
    with op.batch_alter_table("authorization_results") as batch_op:
        batch_op.drop_constraint("uq_authorization_results_account_request", type_="unique")
        batch_op.drop_constraint(
            "fk_authorization_results_verification_request_id",
            type_="foreignkey",
        )
        batch_op.drop_constraint(
            "fk_authorization_results_verification_result_id",
            type_="foreignkey",
        )
        batch_op.drop_constraint("fk_authorization_results_policy_id", type_="foreignkey")
        batch_op.drop_column("provenance")
        batch_op.drop_column("authorization_expires_at")
        batch_op.drop_column("receipt_id")
        batch_op.drop_column("verification_request_id")
        batch_op.drop_column("verification_result_id")
        batch_op.drop_column("action_schema_version")
        batch_op.drop_column("action_hash")
        batch_op.drop_column("policy_hash")
        batch_op.drop_column("policy_version")
        batch_op.drop_column("policy_id")

    op.drop_index("ix_authorization_requests_idempotency", table_name="authorization_requests")
    with op.batch_alter_table("authorization_requests") as batch_op:
        batch_op.drop_constraint(
            "uq_authorization_requests_account_idempotency",
            type_="unique",
        )
        batch_op.drop_constraint("fk_authorization_requests_policy_id", type_="foreignkey")
        batch_op.drop_column("failed_at")
        batch_op.drop_column("completed_at")
        batch_op.drop_column("lifecycle_metadata")
        batch_op.drop_column("request_config_version")
        batch_op.drop_column("lifecycle_state")
        batch_op.drop_column("request_fingerprint")
        batch_op.drop_column("idempotency_key")
        batch_op.drop_column("authorization_expires_at")
        batch_op.drop_column("policy_version")
        batch_op.drop_column("policy_id")
        batch_op.drop_column("action_schema_version")
