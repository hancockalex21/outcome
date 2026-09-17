from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Float, create_engine, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from outcome.audit import AuditEventType, AuditService
from outcome.db.metadata import metadata
from outcome.db.models import Account, CreditLedgerEntry
from outcome.ledger import (
    IdempotencyConflict,
    LedgerAccount,
    LedgerDirection,
    LedgerService,
    LedgerTransaction,
    LedgerTransactionType,
    TenantLedgerAccessDenied,
)
from tests.test_api_keys import build_session


def account_id_from(session: Session) -> UUID:
    account_id = session.scalar(select(Account.id))
    assert account_id is not None
    return account_id


def create_second_account(session: Session) -> UUID:
    account_id = uuid4()
    session.add(Account(id=account_id, display_name="Other", status="active"))
    session.commit()
    return account_id


def assert_balanced(transaction: LedgerTransaction) -> None:
    debits = sum(
        entry.amount_micro_usd
        for entry in transaction.entries
        if entry.direction == LedgerDirection.DEBIT.value
    )
    credits = sum(
        entry.amount_micro_usd
        for entry in transaction.entries
        if entry.direction == LedgerDirection.CREDIT.value
    )

    assert debits == credits


def ledger_accounts(transaction: LedgerTransaction) -> set[str]:
    return {entry.ledger_account for entry in transaction.entries}


def test_funding_transaction_balances() -> None:
    session = build_session()
    account_id = account_id_from(session)

    transaction = LedgerService(session).fund_account(
        account_id=account_id,
        amount_micro_usd=5_000_000,
        idempotency_key="fund-1",
        correlation_id=uuid4(),
    )
    session.commit()

    assert_balanced(transaction)
    assert transaction.transaction_type is LedgerTransactionType.ACCOUNT_FUNDING
    assert ledger_accounts(transaction) == {
        LedgerAccount.CASH_FUNDING_CLEARING.value,
        LedgerAccount.CUSTOMER_PREPAID_LIABILITY.value,
    }


def test_settlement_debit_transaction_balances() -> None:
    session = build_session()
    account_id = account_id_from(session)
    service = LedgerService(session)
    service.fund_account(
        account_id=account_id,
        amount_micro_usd=5_000_000,
        idempotency_key="fund-1",
        correlation_id=uuid4(),
    )

    transaction = service.settle_reservation(
        account_id=account_id,
        amount_micro_usd=2_000_000,
        idempotency_key="settle-1",
        correlation_id=uuid4(),
    )
    session.commit()

    assert_balanced(transaction)
    assert ledger_accounts(transaction) == {
        LedgerAccount.CUSTOMER_PREPAID_LIABILITY.value,
        LedgerAccount.VERIFICATION_REVENUE.value,
    }


def test_refund_balances() -> None:
    session = build_session()
    account_id = account_id_from(session)

    transaction = LedgerService(session).refund_account(
        account_id=account_id,
        amount_micro_usd=1_000_000,
        idempotency_key="refund-1",
        correlation_id=uuid4(),
    )
    session.commit()

    assert_balanced(transaction)
    assert ledger_accounts(transaction) == {
        LedgerAccount.CUSTOMER_PREPAID_LIABILITY.value,
        LedgerAccount.CASH_FUNDING_CLEARING.value,
    }


def test_service_credit_balances() -> None:
    session = build_session()
    account_id = account_id_from(session)

    transaction = LedgerService(session).grant_service_credit(
        account_id=account_id,
        amount_micro_usd=750_000,
        idempotency_key="credit-1",
        correlation_id=uuid4(),
    )
    session.commit()

    assert_balanced(transaction)
    assert ledger_accounts(transaction) == {
        LedgerAccount.SERVICE_CREDIT_REFUND_LIABILITY.value,
        LedgerAccount.CUSTOMER_PREPAID_LIABILITY.value,
    }


def test_adjustment_balances() -> None:
    session = build_session()
    account_id = account_id_from(session)

    transaction = LedgerService(session).adjust_account(
        account_id=account_id,
        amount_micro_usd=-250_000,
        idempotency_key="adjust-1",
        correlation_id=uuid4(),
    )
    session.commit()

    assert_balanced(transaction)
    assert ledger_accounts(transaction) == {
        LedgerAccount.MANUAL_ADJUSTMENT_CLEARING.value,
        LedgerAccount.CUSTOMER_PREPAID_LIABILITY.value,
    }


def test_ledger_derived_account_balance() -> None:
    session = build_session()
    account_id = account_id_from(session)
    service = LedgerService(session)

    service.fund_account(
        account_id=account_id,
        amount_micro_usd=10_000_000,
        idempotency_key="fund-1",
        correlation_id=uuid4(),
    )
    service.settle_reservation(
        account_id=account_id,
        amount_micro_usd=3_000_000,
        idempotency_key="settle-1",
        correlation_id=uuid4(),
    )
    service.grant_service_credit(
        account_id=account_id,
        amount_micro_usd=500_000,
        idempotency_key="credit-1",
        correlation_id=uuid4(),
    )
    session.commit()

    assert service.balance_micro_usd(account_id=account_id) == 7_500_000
    assert "balance" not in set(metadata.tables["accounts"].columns.keys())


def test_duplicate_idempotency_returns_same_logical_transaction() -> None:
    session = build_session()
    account_id = account_id_from(session)
    service = LedgerService(session)

    first = service.fund_account(
        account_id=account_id,
        amount_micro_usd=1_000_000,
        idempotency_key="same-key",
        correlation_id=uuid4(),
    )
    session.commit()
    second = service.fund_account(
        account_id=account_id,
        amount_micro_usd=1_000_000,
        idempotency_key="same-key",
        correlation_id=uuid4(),
    )

    assert second.transaction_id == first.transaction_id
    assert session.scalar(select(func.count()).select_from(CreditLedgerEntry)) == 2


def test_conflicting_idempotency_reuse_fails() -> None:
    session = build_session()
    account_id = account_id_from(session)
    service = LedgerService(session)

    service.fund_account(
        account_id=account_id,
        amount_micro_usd=1_000_000,
        idempotency_key="same-key",
        correlation_id=uuid4(),
    )
    session.commit()

    with pytest.raises(IdempotencyConflict):
        service.fund_account(
            account_id=account_id,
            amount_micro_usd=2_000_000,
            idempotency_key="same-key",
            correlation_id=uuid4(),
        )


def test_concurrent_same_idempotency_attempts_cannot_double_post() -> None:
    with TemporaryDirectory() as directory:
        database_path = Path(directory) / "ledger.sqlite"
        engine = create_engine(
            f"sqlite:///{database_path}",
            connect_args={"check_same_thread": False},
        )
        metadata.create_all(engine)
        session_factory = sessionmaker(bind=engine)
        account_id = uuid4()
        with session_factory.begin() as session:
            session.add(Account(id=account_id, display_name="Concurrent", status="active"))

        def post_once() -> str:
            session = session_factory()
            try:
                LedgerService(session).fund_account(
                    account_id=account_id,
                    amount_micro_usd=1_000_000,
                    idempotency_key="concurrent-key",
                    correlation_id=uuid4(),
                )
                session.commit()
                return "posted"
            except IntegrityError:
                session.rollback()
                return "duplicate"
            finally:
                session.close()

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _: post_once(), range(2)))

        with session_factory() as session:
            assert sorted(results) == ["posted", "posted"]
            assert session.scalar(select(func.count()).select_from(CreditLedgerEntry)) == 2


def test_cross_tenant_access_denied() -> None:
    session = build_session()
    account_id = account_id_from(session)
    other_account_id = create_second_account(session)
    transaction = LedgerService(session).fund_account(
        account_id=account_id,
        amount_micro_usd=1_000_000,
        idempotency_key="fund-1",
        correlation_id=uuid4(),
    )
    session.commit()

    with pytest.raises(TenantLedgerAccessDenied):
        LedgerService(session).transaction_for_account(
            account_id=other_account_id,
            transaction_id=transaction.transaction_id,
        )


def test_historical_entries_cannot_be_mutated_through_service() -> None:
    session = build_session()
    account_id = account_id_from(session)
    service = LedgerService(session)
    transaction = service.fund_account(
        account_id=account_id,
        amount_micro_usd=1_000_000,
        idempotency_key="fund-1",
        correlation_id=uuid4(),
    )
    session.commit()

    assert not hasattr(service, "update_entry")
    assert not hasattr(service, "delete_entry")

    first_entry = session.get(CreditLedgerEntry, transaction.entries[0].id)
    assert first_entry is not None
    assert first_entry.amount_micro_usd == 1_000_000


def test_no_floats_used_for_persisted_monetary_values() -> None:
    money_columns = [
        metadata.tables["credit_ledger_entries"].columns["amount_micro_usd"],
        metadata.tables["credit_ledger_transactions"].columns["amount_micro_usd"],
    ]

    assert all(not isinstance(column.type, Float) for column in money_columns)


def test_audit_event_emitted_without_sensitive_values() -> None:
    session = build_session()
    account_id = account_id_from(session)
    correlation_id = uuid4()

    LedgerService(session, AuditService(session)).fund_account(
        account_id=account_id,
        amount_micro_usd=1_000_000,
        idempotency_key="fund-1",
        correlation_id=correlation_id,
    )
    session.commit()

    events = AuditService(session).timeline_for_correlation(
        account_id=account_id,
        correlation_id=correlation_id,
    )

    assert [event.event_type for event in events] == [
        AuditEventType.LEDGER_TRANSACTION_CREATED,
        AuditEventType.ACCOUNT_FUNDED,
    ]
    assert "idempotency_key" not in repr([event.payload for event in events])
    assert "payment_secret" not in repr([event.payload for event in events])
