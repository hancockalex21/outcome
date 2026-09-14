from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON, Uuid

from outcome.db.metadata import Base


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class AccountScopedMixin(TimestampMixin):
    account_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("accounts.id", ondelete="CASCADE"),
        nullable=False,
    )


class Account(TimestampMixin, Base):
    __tablename__ = "accounts"
    __table_args__ = (Index("ix_accounts_created_at", "created_at"),)

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(64), nullable=False)


class AgentCredential(AccountScopedMixin, Base):
    __tablename__ = "agent_credentials"
    __table_args__ = (
        Index("ix_agent_credentials_account_created_at", "account_id", "created_at"),
        Index("ix_agent_credentials_key_prefix", "key_prefix", unique=True),
        UniqueConstraint("account_id", "key_fingerprint", name="uq_agent_credentials_fingerprint"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    agent_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    key_fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    key_ciphertext_ref: Mapped[str | None] = mapped_column(String(512), nullable=True)
    key_prefix: Mapped[str] = mapped_column(String(32), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    scopes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    metadata_json: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Policy(AccountScopedMixin, Base):
    __tablename__ = "policies"
    __table_args__ = (Index("ix_policies_account_created_at", "account_id", "created_at"),)

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    body: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(String(64), nullable=False)


class ProviderRight(AccountScopedMixin, Base):
    __tablename__ = "provider_rights"
    __table_args__ = (
        Index("ix_provider_rights_account_created_at", "account_id", "created_at"),
        Index("ix_provider_rights_provider_capability", "provider_id", "capability"),
        UniqueConstraint("account_id", "provider_id", "right_name", name="uq_provider_rights_name"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    provider_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("providers.id", ondelete="CASCADE"),
        nullable=False,
    )
    right_name: Mapped[str] = mapped_column(String(255), nullable=False)
    provider_alias: Mapped[str] = mapped_column(String(255), nullable=False)
    capability: Mapped[str] = mapped_column(String(128), nullable=False)
    billing_mode: Mapped[str] = mapped_column(String(64), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    rights_status: Mapped[str] = mapped_column(String(64), nullable=False)
    permitted_regions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    permitted_data_use: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    permitted_execution_modes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    customer_secret_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    outcome_managed_credential_allowed: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )
    customer_managed_credential_allowed: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )
    evidence_retention_allowed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    caching_allowed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    commercial_usage_allowed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    automated_agent_usage_allowed: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )
    rights_version: Mapped[str] = mapped_column(String(128), nullable=False)
    effective_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reason_code: Mapped[str] = mapped_column(String(128), nullable=False)
    tenant_restrictions: Mapped[dict[str, object]] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )
    constraints: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)


class Provider(AccountScopedMixin, Base):
    __tablename__ = "providers"
    __table_args__ = (
        Index("ix_providers_account_created_at", "account_id", "created_at"),
        Index("ix_providers_health", "health"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    health: Mapped[str] = mapped_column(String(64), nullable=False)
    config: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)


class CustomerProviderCredential(AccountScopedMixin, Base):
    __tablename__ = "customer_provider_credentials"
    __table_args__ = (
        Index(
            "ix_customer_provider_credentials_account_created_at",
            "account_id",
            "created_at",
        ),
        Index(
            "ix_customer_provider_credentials_secret_ref",
            "secret_ref",
            unique=True,
        ),
        UniqueConstraint(
            "account_id",
            "provider_id",
            "secret_ref",
            name="uq_customer_provider_credentials_scope",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    secret_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    provider_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("providers.id", ondelete="CASCADE"),
        nullable=False,
    )
    credential_type: Mapped[str] = mapped_column(String(128), nullable=False)
    lifecycle_state: Mapped[str] = mapped_column(String(64), nullable=False)
    version: Mapped[str] = mapped_column(String(128), nullable=False)
    external_secret_locator: Mapped[str | None] = mapped_column(String(512), nullable=True)
    metadata_json: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class VerificationRequest(AccountScopedMixin, Base):
    __tablename__ = "verification_requests"
    __table_args__ = (
        Index("ix_verification_requests_account_created_at", "account_id", "created_at"),
        Index("ix_verification_requests_request_id", "request_id"),
        UniqueConstraint("request_id", name="uq_verification_requests_request_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    request_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    agent_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    mode: Mapped[str] = mapped_column(String(64), nullable=False)
    requested_assurance: Mapped[str] = mapped_column(String(64), nullable=False)
    claim_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    subject_hash: Mapped[str] = mapped_column(String(128), nullable=False)


class AuthorizationRequest(AccountScopedMixin, Base):
    __tablename__ = "authorization_requests"
    __table_args__ = (
        Index("ix_authorization_requests_account_created_at", "account_id", "created_at"),
        Index("ix_authorization_requests_request_id", "request_id"),
        UniqueConstraint("request_id", name="uq_authorization_requests_request_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    request_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    agent_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    action_name: Mapped[str] = mapped_column(String(255), nullable=False)
    action_target_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    material_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    ephemeral_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    requested_assurance: Mapped[str] = mapped_column(String(64), nullable=False)


class EvidenceItem(AccountScopedMixin, Base):
    __tablename__ = "evidence_items"
    __table_args__ = (Index("ix_evidence_items_account_created_at", "account_id", "created_at"),)

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    verification_request_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("verification_requests.id", ondelete="CASCADE"),
        nullable=False,
    )
    evidence_type: Mapped[str] = mapped_column(String(128), nullable=False)
    evidence_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    evidence_ref: Mapped[str | None] = mapped_column(String(512), nullable=True)
    provider_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True)
    provider_alias: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_uri: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    source_class: Mapped[str] = mapped_column(String(64), nullable=False)
    content_type: Mapped[str] = mapped_column(String(128), nullable=False)
    normalized_text: Mapped[str] = mapped_column(String(4096), nullable=False)
    extraction_method: Mapped[str] = mapped_column(String(128), nullable=False)
    extraction_version: Mapped[str] = mapped_column(String(128), nullable=False)
    extraction_quality: Mapped[str] = mapped_column(String(64), nullable=False)
    authority_metadata: Mapped[dict[str, object]] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )
    lineage_metadata: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    size_metadata: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    safety_flags: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    truncated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class EvidenceLineage(AccountScopedMixin, Base):
    __tablename__ = "evidence_lineages"
    __table_args__ = (
        Index("ix_evidence_lineages_account_created_at", "account_id", "created_at"),
        Index("ix_evidence_lineages_request", "account_id", "verification_request_id"),
        UniqueConstraint(
            "account_id",
            "evidence_id",
            "lineage_version",
            name="uq_evidence_lineages_version",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    evidence_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("evidence_items.id", ondelete="CASCADE"),
        nullable=False,
    )
    verification_request_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("verification_requests.id", ondelete="CASCADE"),
        nullable=False,
    )
    provider_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True)
    source_reference: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    source_class: Mapped[str] = mapped_column(String(64), nullable=False)
    lineage_type: Mapped[str] = mapped_column(String(64), nullable=False)
    publisher_identity: Mapped[str | None] = mapped_column(String(255), nullable=True)
    canonical_source_identity: Mapped[str | None] = mapped_column(String(255), nullable=True)
    origin_reference: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    origin_identity_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    lineage_version: Mapped[str] = mapped_column(String(128), nullable=False)
    lineage_metadata: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)


class EvidenceLineageRelationship(AccountScopedMixin, Base):
    __tablename__ = "evidence_lineage_relationships"
    __table_args__ = (
        Index(
            "ix_evidence_lineage_relationships_account_created_at",
            "account_id",
            "created_at",
        ),
        Index(
            "ix_evidence_lineage_relationships_request",
            "account_id",
            "verification_request_id",
        ),
        UniqueConstraint(
            "account_id",
            "parent_evidence_id",
            "child_evidence_id",
            "relationship_type",
            "lineage_version",
            name="uq_evidence_lineage_relationships_edge",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    verification_request_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("verification_requests.id", ondelete="CASCADE"),
        nullable=False,
    )
    parent_evidence_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("evidence_items.id", ondelete="CASCADE"),
        nullable=False,
    )
    child_evidence_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("evidence_items.id", ondelete="CASCADE"),
        nullable=False,
    )
    relationship_type: Mapped[str] = mapped_column(String(64), nullable=False)
    lineage_version: Mapped[str] = mapped_column(String(128), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(128), nullable=False)


class ProviderAttempt(AccountScopedMixin, Base):
    __tablename__ = "provider_attempts"
    __table_args__ = (
        Index("ix_provider_attempts_account_created_at", "account_id", "created_at"),
        Index("ix_provider_attempts_provider_health", "provider_id", "provider_health"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    provider_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("providers.id", ondelete="CASCADE"),
        nullable=False,
    )
    verification_request_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("verification_requests.id", ondelete="CASCADE"),
        nullable=True,
    )
    authorization_request_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("authorization_requests.id", ondelete="CASCADE"),
        nullable=True,
    )
    provider_health: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(64), nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(128), nullable=True)


class VerificationResult(AccountScopedMixin, Base):
    __tablename__ = "verification_results"
    __table_args__ = (
        Index("ix_verification_results_account_created_at", "account_id", "created_at"),
        Index("ix_verification_results_request_id", "request_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    request_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    verification_request_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("verification_requests.id", ondelete="CASCADE"),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_score_basis_points: Mapped[int | None] = mapped_column(Integer, nullable=True)
    assurance: Mapped[str] = mapped_column(String(64), nullable=False)
    reason_codes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)


class AuthorizationResult(AccountScopedMixin, Base):
    __tablename__ = "authorization_results"
    __table_args__ = (
        Index("ix_authorization_results_account_created_at", "account_id", "created_at"),
        Index("ix_authorization_results_request_id", "request_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    request_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    authorization_request_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("authorization_requests.id", ondelete="CASCADE"),
        nullable=False,
    )
    decision: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_score_basis_points: Mapped[int | None] = mapped_column(Integer, nullable=True)
    assurance: Mapped[str] = mapped_column(String(64), nullable=False)
    reason_codes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)


class Receipt(AccountScopedMixin, Base):
    __tablename__ = "receipts"
    __table_args__ = (
        Index("ix_receipts_account_created_at", "account_id", "created_at"),
        Index("ix_receipts_receipt_id", "receipt_id"),
        UniqueConstraint("receipt_id", name="uq_receipts_receipt_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    receipt_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    verification_result_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("verification_results.id", ondelete="SET NULL"),
        nullable=True,
    )
    authorization_result_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("authorization_results.id", ondelete="SET NULL"),
        nullable=True,
    )
    authorization_request_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey(
            "authorization_requests.id",
            name="fk_receipts_authorization_request_id",
            ondelete="SET NULL",
        ),
        nullable=True,
    )
    receipt_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    canonical_payload: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    action_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    signature: Mapped[str] = mapped_column(String(512), nullable=False)
    signing_key_id: Mapped[str] = mapped_column(String(128), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ReceiptConsumption(AccountScopedMixin, Base):
    __tablename__ = "receipt_consumptions"
    __table_args__ = (
        Index("ix_receipt_consumptions_account_created_at", "account_id", "created_at"),
        Index("ix_receipt_consumptions_receipt_id", "receipt_id"),
        UniqueConstraint("account_id", "receipt_id", name="uq_receipt_consumptions_receipt"),
        UniqueConstraint(
            "account_id",
            "execution_request_id",
            name="uq_receipt_consumptions_execution_request",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    consumption_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    receipt_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    authorization_request_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    action_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    consumed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    execution_request_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)


class CreditLedgerEntry(AccountScopedMixin, Base):
    __tablename__ = "credit_ledger_entries"
    __table_args__ = (
        Index("ix_credit_ledger_entries_account_created_at", "account_id", "created_at"),
        Index("ix_credit_ledger_entries_transaction_id", "transaction_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    amount_minor: Mapped[int] = mapped_column(Integer, nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    entry_type: Mapped[str] = mapped_column(String(64), nullable=False)
    reference_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True)
    transaction_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    ledger_account: Mapped[str] = mapped_column(String(128), nullable=False)
    direction: Mapped[str] = mapped_column(String(16), nullable=False)
    amount_micro_usd: Mapped[int] = mapped_column(Integer, nullable=False)


class CreditLedgerTransaction(AccountScopedMixin, Base):
    __tablename__ = "credit_ledger_transactions"
    __table_args__ = (
        Index("ix_credit_ledger_transactions_account_created_at", "account_id", "created_at"),
        Index("ix_credit_ledger_transactions_transaction_id", "transaction_id", unique=True),
        UniqueConstraint(
            "account_id",
            "idempotency_key",
            name="uq_credit_ledger_transactions_idempotency",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    transaction_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    transaction_type: Mapped[str] = mapped_column(String(64), nullable=False)
    amount_micro_usd: Mapped[int] = mapped_column(Integer, nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)


class CreditReservation(AccountScopedMixin, Base):
    __tablename__ = "credit_reservations"
    __table_args__ = (
        Index("ix_credit_reservations_account_created_at", "account_id", "created_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    amount_minor: Mapped[int] = mapped_column(Integer, nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    status: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AuditEvent(AccountScopedMixin, Base):
    """Append-only at the application layer; updates and deletes must not be exposed."""

    __tablename__ = "audit_events"
    __table_args__ = (
        Index("ix_audit_events_account_created_at", "account_id", "created_at"),
        Index("ix_audit_events_request_id", "request_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    request_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    actor_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    payload: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)


class BenchmarkCase(AccountScopedMixin, Base):
    __tablename__ = "benchmark_cases"
    __table_args__ = (Index("ix_benchmark_cases_account_created_at", "account_id", "created_at"),)

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    input_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    expected_outcome: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)


class ProviderMetric(AccountScopedMixin, Base):
    __tablename__ = "provider_metrics"
    __table_args__ = (
        Index("ix_provider_metrics_account_created_at", "account_id", "created_at"),
        Index("ix_provider_metrics_provider_health", "provider_id", "provider_health"),
        Index("ix_provider_metrics_provider_capability", "provider_id", "capability"),
        UniqueConstraint(
            "account_id",
            "provider_id",
            "capability",
            name="uq_provider_metrics_capability",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    provider_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("providers.id", ondelete="CASCADE"),
        nullable=False,
    )
    provider_health: Mapped[str] = mapped_column(String(64), nullable=False)
    metric_name: Mapped[str] = mapped_column(String(128), nullable=False)
    metric_value: Mapped[int] = mapped_column(Integer, nullable=False)
    dimensions: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    capability: Mapped[str] = mapped_column(String(128), nullable=False)
    metrics_version: Mapped[str] = mapped_column(String(128), nullable=False)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    request_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    success_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failure_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    timeout_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    rate_limited_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    system_failure_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    consecutive_failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    latency_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    latency_total_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    latency_max_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    current_health: Mapped[str] = mapped_column(String(64), nullable=False)
    circuit_state: Mapped[str] = mapped_column(String(64), nullable=False)
    circuit_opened_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    circuit_retry_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    manually_disabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


__all__ = [
    "Account",
    "AgentCredential",
    "AuditEvent",
    "AuthorizationRequest",
    "AuthorizationResult",
    "BenchmarkCase",
    "CreditLedgerEntry",
    "CreditLedgerTransaction",
    "CreditReservation",
    "CustomerProviderCredential",
    "EvidenceItem",
    "EvidenceLineage",
    "EvidenceLineageRelationship",
    "Policy",
    "Provider",
    "ProviderAttempt",
    "ProviderMetric",
    "ProviderRight",
    "Receipt",
    "ReceiptConsumption",
    "VerificationRequest",
    "VerificationResult",
]
