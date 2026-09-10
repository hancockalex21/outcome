"""create control plane tables

Revision ID: 20260910_0001
Revises:
Create Date: 2026-09-10 00:00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260910_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def timestamps() -> list[sa.Column[object]]:
    return [
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
    ]


def account_id_column() -> sa.Column[object]:
    return sa.Column(
        "account_id",
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("accounts.id", ondelete="CASCADE"),
        nullable=False,
    )


def create_account_created_index(table_name: str) -> None:
    op.create_index(f"ix_{table_name}_account_created_at", table_name, ["account_id", "created_at"])


def upgrade() -> None:
    op.create_table(
        "accounts",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("display_name", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=64), nullable=False),
        *timestamps(),
    )
    op.create_index("ix_accounts_created_at", "accounts", ["created_at"])

    op.create_table(
        "providers",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        account_id_column(),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("health", sa.String(length=64), nullable=False),
        sa.Column("config", sa.JSON(), nullable=False),
        *timestamps(),
    )
    create_account_created_index("providers")
    op.create_index("ix_providers_health", "providers", ["health"])

    op.create_table(
        "agent_credentials",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        account_id_column(),
        sa.Column("agent_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("key_fingerprint", sa.String(length=128), nullable=False),
        sa.Column("key_ciphertext_ref", sa.String(length=512), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
        *timestamps(),
        sa.UniqueConstraint(
            "account_id",
            "key_fingerprint",
            name="uq_agent_credentials_fingerprint",
        ),
    )
    create_account_created_index("agent_credentials")

    op.create_table(
        "policies",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        account_id_column(),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("body", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=64), nullable=False),
        *timestamps(),
    )
    create_account_created_index("policies")

    op.create_table(
        "provider_rights",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        account_id_column(),
        sa.Column(
            "provider_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("providers.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("right_name", sa.String(length=255), nullable=False),
        sa.Column("constraints", sa.JSON(), nullable=False),
        *timestamps(),
        sa.UniqueConstraint(
            "account_id",
            "provider_id",
            "right_name",
            name="uq_provider_rights_name",
        ),
    )
    create_account_created_index("provider_rights")

    op.create_table(
        "verification_requests",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        account_id_column(),
        sa.Column("request_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("agent_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("mode", sa.String(length=64), nullable=False),
        sa.Column("requested_assurance", sa.String(length=64), nullable=False),
        sa.Column("claim_hash", sa.String(length=128), nullable=False),
        sa.Column("subject_hash", sa.String(length=128), nullable=False),
        *timestamps(),
        sa.UniqueConstraint("request_id", name="uq_verification_requests_request_id"),
    )
    create_account_created_index("verification_requests")
    op.create_index("ix_verification_requests_request_id", "verification_requests", ["request_id"])

    op.create_table(
        "authorization_requests",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        account_id_column(),
        sa.Column("request_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("agent_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("action_name", sa.String(length=255), nullable=False),
        sa.Column("action_target_hash", sa.String(length=128), nullable=False),
        sa.Column("material_hash", sa.String(length=128), nullable=False),
        sa.Column("ephemeral_hash", sa.String(length=128), nullable=False),
        sa.Column("requested_assurance", sa.String(length=64), nullable=False),
        *timestamps(),
        sa.UniqueConstraint("request_id", name="uq_authorization_requests_request_id"),
    )
    create_account_created_index("authorization_requests")
    op.create_index(
        "ix_authorization_requests_request_id",
        "authorization_requests",
        ["request_id"],
    )

    op.create_table(
        "evidence_items",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        account_id_column(),
        sa.Column(
            "verification_request_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("verification_requests.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("evidence_type", sa.String(length=128), nullable=False),
        sa.Column("evidence_hash", sa.String(length=128), nullable=False),
        sa.Column("evidence_ref", sa.String(length=512), nullable=True),
        *timestamps(),
    )
    create_account_created_index("evidence_items")

    op.create_table(
        "provider_attempts",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        account_id_column(),
        sa.Column(
            "provider_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("providers.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "verification_request_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("verification_requests.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column(
            "authorization_request_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("authorization_requests.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("provider_health", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=64), nullable=False),
        sa.Column("error_code", sa.String(length=128), nullable=True),
        *timestamps(),
    )
    create_account_created_index("provider_attempts")
    op.create_index(
        "ix_provider_attempts_provider_health",
        "provider_attempts",
        ["provider_id", "provider_health"],
    )

    op.create_table(
        "verification_results",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        account_id_column(),
        sa.Column("request_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column(
            "verification_request_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("verification_requests.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", sa.String(length=64), nullable=False),
        sa.Column("evidence_score_basis_points", sa.Integer(), nullable=True),
        sa.Column("assurance", sa.String(length=64), nullable=False),
        sa.Column("reason_codes", sa.JSON(), nullable=False),
        *timestamps(),
    )
    create_account_created_index("verification_results")
    op.create_index("ix_verification_results_request_id", "verification_results", ["request_id"])

    op.create_table(
        "authorization_results",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        account_id_column(),
        sa.Column("request_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column(
            "authorization_request_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("authorization_requests.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("decision", sa.String(length=64), nullable=False),
        sa.Column("evidence_score_basis_points", sa.Integer(), nullable=True),
        sa.Column("assurance", sa.String(length=64), nullable=False),
        sa.Column("reason_codes", sa.JSON(), nullable=False),
        *timestamps(),
    )
    create_account_created_index("authorization_results")
    op.create_index("ix_authorization_results_request_id", "authorization_results", ["request_id"])

    op.create_table(
        "receipts",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        account_id_column(),
        sa.Column("receipt_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column(
            "verification_result_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("verification_results.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "authorization_result_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("authorization_results.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("receipt_hash", sa.String(length=128), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        *timestamps(),
        sa.UniqueConstraint("receipt_id", name="uq_receipts_receipt_id"),
    )
    create_account_created_index("receipts")
    op.create_index("ix_receipts_receipt_id", "receipts", ["receipt_id"])

    op.create_table(
        "credit_ledger_entries",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        account_id_column(),
        sa.Column("amount_minor", sa.Integer(), nullable=False),
        sa.Column("currency", sa.String(length=3), nullable=False),
        sa.Column("entry_type", sa.String(length=64), nullable=False),
        sa.Column("reference_id", sa.Uuid(as_uuid=True), nullable=True),
        *timestamps(),
    )
    create_account_created_index("credit_ledger_entries")

    op.create_table(
        "credit_reservations",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        account_id_column(),
        sa.Column("amount_minor", sa.Integer(), nullable=False),
        sa.Column("currency", sa.String(length=3), nullable=False),
        sa.Column("status", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        *timestamps(),
    )
    create_account_created_index("credit_reservations")

    op.create_table(
        "audit_events",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        account_id_column(),
        sa.Column("request_id", sa.Uuid(as_uuid=True), nullable=True),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("actor_hash", sa.String(length=128), nullable=True),
        sa.Column("payload", sa.JSON(), nullable=False),
        *timestamps(),
    )
    create_account_created_index("audit_events")
    op.create_index("ix_audit_events_request_id", "audit_events", ["request_id"])

    op.create_table(
        "benchmark_cases",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        account_id_column(),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("input_hash", sa.String(length=128), nullable=False),
        sa.Column("expected_outcome", sa.JSON(), nullable=False),
        *timestamps(),
    )
    create_account_created_index("benchmark_cases")

    op.create_table(
        "provider_metrics",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        account_id_column(),
        sa.Column(
            "provider_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("providers.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("provider_health", sa.String(length=64), nullable=False),
        sa.Column("metric_name", sa.String(length=128), nullable=False),
        sa.Column("metric_value", sa.Integer(), nullable=False),
        sa.Column("dimensions", sa.JSON(), nullable=False),
        *timestamps(),
    )
    create_account_created_index("provider_metrics")
    op.create_index(
        "ix_provider_metrics_provider_health",
        "provider_metrics",
        ["provider_id", "provider_health"],
    )


def downgrade() -> None:
    op.drop_table("provider_metrics")
    op.drop_table("benchmark_cases")
    op.drop_table("audit_events")
    op.drop_table("credit_reservations")
    op.drop_table("credit_ledger_entries")
    op.drop_table("receipts")
    op.drop_table("authorization_results")
    op.drop_table("verification_results")
    op.drop_table("provider_attempts")
    op.drop_table("evidence_items")
    op.drop_table("authorization_requests")
    op.drop_table("verification_requests")
    op.drop_table("provider_rights")
    op.drop_table("policies")
    op.drop_table("agent_credentials")
    op.drop_table("providers")
    op.drop_table("accounts")
