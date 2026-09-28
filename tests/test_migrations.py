from __future__ import annotations

import os
import subprocess
import sys
from uuid import uuid4

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import make_url

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
    "authorization_billings",
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
    "ix_authorization_billings_account_created_at",
    "ix_authorization_billings_billing_id",
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
    admin_url_value = os.environ.get("OUTCOME_POSTGRES_ADMIN_URL")
    if not admin_url_value:
        pytest.skip("OUTCOME_POSTGRES_ADMIN_URL is not configured")

    database_name = f"outcome_migration_{uuid4().hex}"
    admin_url = make_url(admin_url_value).set(drivername="postgresql+psycopg")
    test_sync_url = admin_url.set(database=database_name)
    test_async_url = test_sync_url.set(drivername="postgresql+asyncpg")
    admin_engine = sa.create_engine(admin_url, isolation_level="AUTOCOMMIT")
    database_created = False
    try:
        with admin_engine.connect() as connection:
            connection.exec_driver_sql(f'CREATE DATABASE "{database_name}"')
        database_created = True

        migration_environment = os.environ.copy()
        migration_environment["OUTCOME_DATABASE_URL"] = test_async_url.render_as_string(
            hide_password=False
        )
        _run_alembic("upgrade", "head", environment=migration_environment)

        test_engine = sa.create_engine(test_sync_url)
        try:
            with test_engine.connect() as connection:
                inspector = sa.inspect(connection)
                assert EXPECTED_TABLES <= set(inspector.get_table_names())
                assert EXPECTED_INDEXES <= {
                    index["name"]
                    for table_name in EXPECTED_TABLES
                    for index in inspector.get_indexes(table_name)
                }

            _run_alembic("downgrade", "base", environment=migration_environment)
            with test_engine.connect() as connection:
                assert set(sa.inspect(connection).get_table_names()) == {"alembic_version"}
                assert connection.exec_driver_sql(
                    "SELECT version_num FROM alembic_version"
                ).all() == []
        finally:
            test_engine.dispose()
    finally:
        if database_created:
            with admin_engine.connect() as connection:
                connection.exec_driver_sql(
                    f'DROP DATABASE IF EXISTS "{database_name}" WITH (FORCE)'
                )
        admin_engine.dispose()


def _run_alembic(*arguments: str, environment: dict[str, str]) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "alembic", *arguments],
        env=environment,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
