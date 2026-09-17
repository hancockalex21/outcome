from __future__ import annotations

import importlib

import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations

from outcome.db import models  # noqa: F401
from outcome.db.metadata import metadata

EXPECTED_TABLES = {
    "accounts",
    "agent_credentials",
    "policies",
    "provider_rights",
    "providers",
    "customer_provider_credentials",
    "verification_requests",
    "authorization_requests",
    "evidence_items",
    "evidence_lineages",
    "evidence_lineage_relationships",
    "provider_attempts",
    "verification_results",
    "authorization_results",
    "receipts",
    "receipt_consumptions",
    "credit_ledger_entries",
    "credit_ledger_transactions",
    "credit_reservations",
    "account_fundings",
    "payment_webhook_events",
    "audit_events",
    "benchmark_cases",
    "provider_metrics",
}

EXPECTED_INDEXES = {
    "ix_agent_credentials_account_created_at",
    "ix_agent_credentials_key_prefix",
    "ix_policies_account_created_at",
    "ix_policies_account_version",
    "ix_provider_rights_account_created_at",
    "ix_provider_rights_provider_capability",
    "ix_customer_provider_credentials_account_created_at",
    "ix_customer_provider_credentials_secret_ref",
    "ix_providers_account_created_at",
    "ix_providers_health",
    "ix_verification_requests_account_created_at",
    "ix_verification_requests_idempotency",
    "ix_verification_requests_request_id",
    "ix_authorization_requests_account_created_at",
    "ix_authorization_requests_idempotency",
    "ix_authorization_requests_request_id",
    "ix_evidence_items_account_created_at",
    "ix_evidence_lineages_account_created_at",
    "ix_evidence_lineages_request",
    "ix_evidence_lineage_relationships_account_created_at",
    "ix_evidence_lineage_relationships_request",
    "ix_provider_attempts_account_created_at",
    "ix_provider_attempts_provider_health",
    "ix_verification_results_account_created_at",
    "ix_verification_results_request_id",
    "ix_authorization_results_account_created_at",
    "ix_authorization_results_request_id",
    "ix_receipts_account_created_at",
    "ix_receipts_receipt_id",
    "ix_receipt_consumptions_account_created_at",
    "ix_receipt_consumptions_receipt_id",
    "ix_credit_ledger_entries_account_created_at",
    "ix_credit_reservations_account_created_at",
    "ix_credit_ledger_entries_transaction_id",
    "ix_credit_ledger_transactions_account_created_at",
    "ix_credit_ledger_transactions_transaction_id",
    "ix_account_fundings_account_created_at",
    "ix_account_fundings_external_payment",
    "ix_payment_webhook_events_received",
    "ix_audit_events_account_created_at",
    "ix_audit_events_request_id",
    "ix_benchmark_cases_account_created_at",
    "ix_provider_metrics_account_created_at",
    "ix_provider_metrics_provider_health",
    "ix_provider_metrics_provider_capability",
}


def test_model_metadata_contains_control_plane_tables() -> None:
    assert EXPECTED_TABLES <= set(metadata.tables)

    account_scoped_tables = EXPECTED_TABLES - {"accounts", "payment_webhook_events"}
    for table_name in account_scoped_tables:
        table = metadata.tables[table_name]
        assert "account_id" in table.columns
        assert any(
            fk.column.table.name == "accounts"
            for fk in table.columns["account_id"].foreign_keys
        )

    for table_name in EXPECTED_TABLES:
        table = metadata.tables[table_name]
        assert "created_at" in table.columns
        assert "updated_at" in table.columns


def test_agent_credentials_do_not_store_plaintext_api_keys() -> None:
    columns = set(metadata.tables["agent_credentials"].columns.keys())

    assert "api_key" not in columns
    assert "plaintext_api_key" not in columns
    assert "key_fingerprint" in columns
    assert "key_prefix" in columns
    assert "key_hash" in columns
    assert "key_ciphertext_ref" in columns


def test_ledger_money_columns_are_integer_microdollars() -> None:
    entries = metadata.tables["credit_ledger_entries"]
    transactions = metadata.tables["credit_ledger_transactions"]

    assert isinstance(entries.columns["amount_micro_usd"].type, sa.Integer)
    assert isinstance(transactions.columns["amount_micro_usd"].type, sa.Integer)
    assert not any(
        isinstance(column.type, sa.Float)
        for table in metadata.tables.values()
        for column in table.columns
    )


def test_control_plane_migration_upgrades_and_downgrades() -> None:
    base_migration = importlib.import_module(
        "migrations.versions.20260910_0001_create_control_plane_tables"
    )
    api_key_migration = importlib.import_module(
        "migrations.versions.20260910_0002_add_agent_api_key_fields"
    )
    ledger_migration = importlib.import_module(
        "migrations.versions.20260910_0003_add_double_entry_ledger_fields"
    )
    receipt_migration = importlib.import_module(
        "migrations.versions.20260910_0004_add_signed_receipt_fields"
    )
    consumption_migration = importlib.import_module(
        "migrations.versions.20260914_0005_add_receipt_consumptions"
    )
    provider_rights_migration = importlib.import_module(
        "migrations.versions.20260914_0006_add_provider_rights_fields"
    )
    customer_credentials_migration = importlib.import_module(
        "migrations.versions.20260914_0007_add_customer_provider_credentials"
    )
    inert_evidence_migration = importlib.import_module(
        "migrations.versions.20260914_0008_add_inert_evidence_fields"
    )
    evidence_lineage_migration = importlib.import_module(
        "migrations.versions.20260914_0009_add_evidence_lineage"
    )
    provider_health_migration = importlib.import_module(
        "migrations.versions.20260914_0010_add_provider_health_metrics"
    )
    verification_score_migration = importlib.import_module(
        "migrations.versions.20260914_0011_add_verification_score_factors"
    )
    verification_orchestration_migration = importlib.import_module(
        "migrations.versions.20260915_0012_add_verification_orchestration_metadata"
    )
    policy_hash_migration = importlib.import_module(
        "migrations.versions.20260915_0013_add_policy_hash_metadata"
    )
    authorization_orchestration_migration = importlib.import_module(
        "migrations.versions.20260915_0014_add_authorization_orchestration_metadata"
    )
    provider_attempt_async_migration = importlib.import_module(
        "migrations.versions.20260917_0015_add_provider_attempt_async_metadata"
    )
    account_funding_migration = importlib.import_module(
        "migrations.versions.20260917_0016_add_account_funding"
    )
    engine = sa.create_engine("sqlite:///:memory:")

    with engine.begin() as connection:
        context = MigrationContext.configure(connection)
        operations = Operations(context)
        base_migration.op = operations
        api_key_migration.op = operations
        ledger_migration.op = operations
        receipt_migration.op = operations
        consumption_migration.op = operations
        provider_rights_migration.op = operations
        customer_credentials_migration.op = operations
        inert_evidence_migration.op = operations
        evidence_lineage_migration.op = operations
        provider_health_migration.op = operations
        verification_score_migration.op = operations
        verification_orchestration_migration.op = operations
        policy_hash_migration.op = operations
        authorization_orchestration_migration.op = operations
        provider_attempt_async_migration.op = operations
        account_funding_migration.op = operations

        base_migration.upgrade()
        api_key_migration.upgrade()
        ledger_migration.upgrade()
        receipt_migration.upgrade()
        consumption_migration.upgrade()
        provider_rights_migration.upgrade()
        customer_credentials_migration.upgrade()
        inert_evidence_migration.upgrade()
        evidence_lineage_migration.upgrade()
        provider_health_migration.upgrade()
        verification_score_migration.upgrade()
        verification_orchestration_migration.upgrade()
        policy_hash_migration.upgrade()
        authorization_orchestration_migration.upgrade()
        provider_attempt_async_migration.upgrade()
        account_funding_migration.upgrade()

        inspector = sa.inspect(connection)
        assert EXPECTED_TABLES <= set(inspector.get_table_names())
        assert EXPECTED_INDEXES <= {
            index["name"]
            for table_name in EXPECTED_TABLES
            for index in inspector.get_indexes(table_name)
        }

        account_funding_migration.downgrade()
        provider_attempt_async_migration.downgrade()
        authorization_orchestration_migration.downgrade()
        policy_hash_migration.downgrade()
        verification_orchestration_migration.downgrade()
        verification_score_migration.downgrade()
        provider_health_migration.downgrade()
        evidence_lineage_migration.downgrade()
        inert_evidence_migration.downgrade()
        customer_credentials_migration.downgrade()
        provider_rights_migration.downgrade()
        consumption_migration.downgrade()
        receipt_migration.downgrade()
        ledger_migration.downgrade()
        api_key_migration.downgrade()
        base_migration.downgrade()

        inspector = sa.inspect(connection)
        assert set(inspector.get_table_names()) == set()
