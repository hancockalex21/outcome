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
    "verification_requests",
    "authorization_requests",
    "evidence_items",
    "provider_attempts",
    "verification_results",
    "authorization_results",
    "receipts",
    "credit_ledger_entries",
    "credit_reservations",
    "audit_events",
    "benchmark_cases",
    "provider_metrics",
}

EXPECTED_INDEXES = {
    "ix_agent_credentials_account_created_at",
    "ix_agent_credentials_key_prefix",
    "ix_policies_account_created_at",
    "ix_provider_rights_account_created_at",
    "ix_providers_account_created_at",
    "ix_providers_health",
    "ix_verification_requests_account_created_at",
    "ix_verification_requests_request_id",
    "ix_authorization_requests_account_created_at",
    "ix_authorization_requests_request_id",
    "ix_evidence_items_account_created_at",
    "ix_provider_attempts_account_created_at",
    "ix_provider_attempts_provider_health",
    "ix_verification_results_account_created_at",
    "ix_verification_results_request_id",
    "ix_authorization_results_account_created_at",
    "ix_authorization_results_request_id",
    "ix_receipts_account_created_at",
    "ix_receipts_receipt_id",
    "ix_credit_ledger_entries_account_created_at",
    "ix_credit_reservations_account_created_at",
    "ix_audit_events_account_created_at",
    "ix_audit_events_request_id",
    "ix_benchmark_cases_account_created_at",
    "ix_provider_metrics_account_created_at",
    "ix_provider_metrics_provider_health",
}


def test_model_metadata_contains_control_plane_tables() -> None:
    assert EXPECTED_TABLES <= set(metadata.tables)

    for table_name in EXPECTED_TABLES - {"accounts"}:
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


def test_control_plane_migration_upgrades_and_downgrades() -> None:
    base_migration = importlib.import_module(
        "migrations.versions.20260910_0001_create_control_plane_tables"
    )
    api_key_migration = importlib.import_module(
        "migrations.versions.20260910_0002_add_agent_api_key_fields"
    )
    engine = sa.create_engine("sqlite:///:memory:")

    with engine.begin() as connection:
        context = MigrationContext.configure(connection)
        operations = Operations(context)
        base_migration.op = operations
        api_key_migration.op = operations

        base_migration.upgrade()
        api_key_migration.upgrade()

        inspector = sa.inspect(connection)
        assert EXPECTED_TABLES <= set(inspector.get_table_names())
        assert EXPECTED_INDEXES <= {
            index["name"]
            for table_name in EXPECTED_TABLES
            for index in inspector.get_indexes(table_name)
        }

        api_key_migration.downgrade()
        base_migration.downgrade()

        inspector = sa.inspect(connection)
        assert set(inspector.get_table_names()) == set()
