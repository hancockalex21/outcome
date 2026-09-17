from __future__ import annotations

import asyncio
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import UUID, uuid4

import asyncpg
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import Session, sessionmaker

from outcome.audit import AuditService
from outcome.db.metadata import metadata
from outcome.db.models import (
    Account,
    AccountFunding,
    AuditEvent,
    CreditLedgerTransaction,
    PaymentWebhookEvent,
)
from outcome.ledger import LedgerService, LedgerTransactionType
from outcome.payments import (
    CrossTenantFundingAccess,
    FakeStripePaymentGateway,
    FundingError,
    FundingIdempotencyConflict,
    FundingReasonCode,
    FundingRequest,
    FundingService,
    FundingStatus,
    PaymentEventProcessingStatus,
    StaticStripeWebhookVerifier,
    StripeWebhookEvent,
    StripeWebhookPaymentObject,
    StripeWebhookService,
    micro_usd_to_stripe_cents,
    normalize_currency,
    stripe_cents_to_micro_usd,
)
from tests.test_api_keys import build_session

ACCOUNT_ID = UUID("11111111-1111-4111-8111-111111111111")
OTHER_ACCOUNT_ID = UUID("22222222-2222-4222-8222-222222222222")
NOW = datetime(2026, 9, 17, 12, 0, 0, tzinfo=UTC)


def setup_session() -> Session:
    session = build_session()
    account = session.scalar(select(Account))
    assert account is not None
    account.id = ACCOUNT_ID
    session.commit()
    return session


def funding_request(
    *,
    amount: object = 1_000_000,
    currency: str = "usd",
    key: str = "fund-key",
) -> FundingRequest:
    return FundingRequest(
        account_id=ACCOUNT_ID,
        amount_micro_usd=amount,  # type: ignore[arg-type]
        currency=currency,
        idempotency_key=key,
        return_reference="safe-return-ref",
    )


def create_funding(session: Session, *, amount: int = 1_000_000) -> tuple[FundingService, object]:
    gateway = FakeStripePaymentGateway()
    service = FundingService(session, gateway=gateway, clock=lambda: NOW)
    result = service.create_funding(
        funding_request(amount=amount),
        correlation_id=uuid4(),
    )
    session.commit()
    return service, result


def success_event(
    *,
    event_id: str = "evt_success",
    payment_id: str,
    amount_minor: int = 100,
    currency: str = "usd",
    funding_id: UUID | None = None,
    event_type: str = "payment_intent.succeeded",
) -> StripeWebhookEvent:
    metadata = {"funding_id": str(funding_id)} if funding_id is not None else {}
    return StripeWebhookEvent(
        external_event_id=event_id,
        event_type=event_type,
        payment=StripeWebhookPaymentObject(
            external_payment_id=payment_id,
            amount_minor=amount_minor,
            currency=currency,
            status="succeeded",
            metadata=metadata,
        ),
    )


def webhook_service(session: Session, event: StripeWebhookEvent) -> StripeWebhookService:
    return StripeWebhookService(
        session,
        verifier=StaticStripeWebhookVerifier(event),
        audit_service=AuditService(session),
        clock=lambda: NOW,
    )


def test_money_conversion_rules_are_exact() -> None:
    assert micro_usd_to_stripe_cents(10_000) == 1
    assert stripe_cents_to_micro_usd(1) == 10_000
    assert normalize_currency("usd") == "USD"
    with pytest.raises(FundingError):
        micro_usd_to_stripe_cents(10_001)
    with pytest.raises(FundingError):
        micro_usd_to_stripe_cents(1.2)
    with pytest.raises(FundingError):
        normalize_currency("eur")


@pytest.mark.parametrize("amount", [0, -10_000, 90_000, 100_000_010_000])
def test_invalid_funding_amount_rejected(amount: int) -> None:
    session = setup_session()
    service = FundingService(session, gateway=FakeStripePaymentGateway())

    with pytest.raises(FundingError):
        service.create_funding(funding_request(amount=amount), correlation_id=uuid4())


def test_valid_funding_creates_one_gateway_object_with_safe_metadata() -> None:
    session = setup_session()
    gateway = FakeStripePaymentGateway()
    service = FundingService(session, gateway=gateway)

    result = service.create_funding(funding_request(), correlation_id=uuid4())

    assert result.status is FundingStatus.PENDING
    assert result.external_payment_id is not None
    assert len(gateway.created) == 1
    amount_minor, currency, idempotency_key, metadata = gateway.created[0]
    assert amount_minor == 100
    assert currency == "usd"
    assert idempotency_key == f"funding:{ACCOUNT_ID}:fund-key"
    assert set(metadata) == {"funding_id", "account_ref"}


def test_funding_idempotency_reuses_same_operation_and_conflict_fails() -> None:
    session = setup_session()
    gateway = FakeStripePaymentGateway()
    service = FundingService(session, gateway=gateway)

    first = service.create_funding(funding_request(), correlation_id=uuid4())
    second = service.create_funding(funding_request(), correlation_id=uuid4())

    assert second.idempotent_replay is True
    assert second.funding_id == first.funding_id
    assert len(gateway.created) == 1
    with pytest.raises(FundingIdempotencyConflict):
        service.create_funding(funding_request(amount=2_000_000), correlation_id=uuid4())


def test_gateway_failure_does_not_credit_ledger_or_leak_secret() -> None:
    session = setup_session()
    gateway = FakeStripePaymentGateway()
    gateway.fail = True
    service = FundingService(session, gateway=gateway)

    with pytest.raises(FundingError):
        service.create_funding(funding_request(), correlation_id=uuid4())

    assert LedgerService(session).balance_micro_usd(account_id=ACCOUNT_ID) == 0
    assert "secret" not in repr(session.scalars(select(AuditEvent)).all()).lower()


def test_valid_success_webhook_credits_ledger_once() -> None:
    session = setup_session()
    _, funding = create_funding(session)
    assert funding.external_payment_id is not None

    result = webhook_service(
        session,
        success_event(
            payment_id=funding.external_payment_id,
            funding_id=funding.funding_id,
        ),
    ).process(payload=b"{}", signature_header="valid")

    assert result.status is PaymentEventProcessingStatus.PROCESSED
    assert result.ledger_transaction_id is not None
    assert LedgerService(session).balance_micro_usd(account_id=ACCOUNT_ID) == 1_000_000
    ledgers = session.scalars(select(CreditLedgerTransaction)).all()
    assert len(ledgers) == 1
    assert ledgers[0].transaction_type == LedgerTransactionType.ACCOUNT_FUNDING.value
    row = session.scalar(select(AccountFunding))
    assert row is not None
    assert row.status == FundingStatus.SUCCEEDED.value
    assert row.ledger_transaction_id == result.ledger_transaction_id


def test_duplicate_event_and_distinct_success_event_do_not_double_credit() -> None:
    session = setup_session()
    _, funding = create_funding(session)
    assert funding.external_payment_id is not None
    event = success_event(payment_id=funding.external_payment_id, funding_id=funding.funding_id)
    service = webhook_service(session, event)

    first = service.process(payload=b"{}", signature_header="valid")
    duplicate = service.process(payload=b"{}", signature_header="valid")
    second_event = webhook_service(
        session,
        success_event(
            event_id="evt_success_2",
            payment_id=funding.external_payment_id,
            funding_id=funding.funding_id,
        ),
    ).process(payload=b"{}", signature_header="valid")

    assert first.ledger_transaction_id == duplicate.ledger_transaction_id
    assert second_event.ledger_transaction_id == first.ledger_transaction_id
    assert LedgerService(session).balance_micro_usd(account_id=ACCOUNT_ID) == 1_000_000
    assert len(session.scalars(select(CreditLedgerTransaction)).all()) == 1


def test_invalid_signature_and_unsupported_event_have_no_financial_effect() -> None:
    session = setup_session()
    _, funding = create_funding(session)
    assert funding.external_payment_id is not None

    invalid = webhook_service(
        session,
        success_event(payment_id=funding.external_payment_id, funding_id=funding.funding_id),
    ).process(payload=b"{}", signature_header="bad")
    unsupported = webhook_service(
        session,
        success_event(
            event_id="evt_refund",
            payment_id=funding.external_payment_id,
            funding_id=funding.funding_id,
            event_type="charge.refunded",
        ),
    ).process(payload=b"{}", signature_header="valid")

    assert invalid.reason_code is FundingReasonCode.INVALID_WEBHOOK_SIGNATURE
    assert unsupported.reason_code is FundingReasonCode.UNSUPPORTED_EVENT
    assert LedgerService(session).balance_micro_usd(account_id=ACCOUNT_ID) == 0
    assert invalid.event_id is None
    assert len(session.scalars(select(AccountFunding)).all()) == 1


def test_invalid_signature_does_not_create_webhook_inbox_record() -> None:
    session = setup_session()
    _, funding = create_funding(session)
    assert funding.external_payment_id is not None

    result = webhook_service(
        session,
        success_event(payment_id=funding.external_payment_id, funding_id=funding.funding_id),
    ).process(payload=b'{"attacker_event":"evt_fake"}', signature_header="bad")

    assert result.reason_code is FundingReasonCode.INVALID_WEBHOOK_SIGNATURE
    assert session.execute(select(AccountFunding)).all()
    assert session.execute(select(PaymentWebhookEvent)).all() == []


@pytest.mark.parametrize(
    ("event", "reason"),
    [
        (
            success_event(payment_id="pi_unknown", funding_id=uuid4()),
            FundingReasonCode.UNKNOWN_FUNDING,
        ),
        (
            success_event(payment_id="placeholder", amount_minor=101),
            FundingReasonCode.AMOUNT_MISMATCH,
        ),
        (
            success_event(payment_id="placeholder", currency="eur"),
            FundingReasonCode.CURRENCY_MISMATCH,
        ),
        (
            success_event(payment_id="placeholder", funding_id=OTHER_ACCOUNT_ID),
            FundingReasonCode.ACCOUNT_MISMATCH,
        ),
    ],
)
def test_webhook_mismatches_do_not_credit(
    event: StripeWebhookEvent,
    reason: FundingReasonCode,
) -> None:
    session = setup_session()
    _, funding = create_funding(session)
    assert funding.external_payment_id is not None
    if event.payment.external_payment_id == "placeholder":
        event = success_event(
            event_id=event.external_event_id,
            payment_id=funding.external_payment_id,
            amount_minor=event.payment.amount_minor,
            currency=event.payment.currency,
            funding_id=UUID(str(event.payment.metadata["funding_id"]))
            if "funding_id" in event.payment.metadata
            else funding.funding_id,
        )

    result = webhook_service(session, event).process(payload=b"{}", signature_header="valid")

    assert result.reason_code is reason
    assert LedgerService(session).balance_micro_usd(account_id=ACCOUNT_ID) == 0


def test_failed_then_success_allowed_success_then_failed_does_not_regress() -> None:
    session = setup_session()
    _, funding = create_funding(session)
    assert funding.external_payment_id is not None
    failed = success_event(
        event_id="evt_failed",
        payment_id=funding.external_payment_id,
        funding_id=funding.funding_id,
        event_type="payment_intent.payment_failed",
    )
    succeeded = success_event(payment_id=funding.external_payment_id, funding_id=funding.funding_id)

    failed_result = webhook_service(session, failed).process(
        payload=b"{}",
        signature_header="valid",
    )
    success_result = webhook_service(session, succeeded).process(
        payload=b"{}",
        signature_header="valid",
    )
    late_failed = webhook_service(
        session,
        success_event(
            event_id="evt_failed_late",
            payment_id=funding.external_payment_id,
            funding_id=funding.funding_id,
            event_type="payment_intent.payment_failed",
        ),
    ).process(payload=b"{}", signature_header="valid")
    row = session.scalar(select(AccountFunding))

    assert failed_result.reason_code is FundingReasonCode.FUNDING_FAILED
    assert success_result.reason_code is FundingReasonCode.FUNDING_SUCCEEDED
    assert late_failed.reason_code is FundingReasonCode.WEBHOOK_PROCESSED
    assert row is not None
    assert row.status == FundingStatus.SUCCEEDED.value
    assert LedgerService(session).balance_micro_usd(account_id=ACCOUNT_ID) == 1_000_000


def test_cross_tenant_funding_lookup_denied_and_metadata_cannot_redirect() -> None:
    session = setup_session()
    service, funding = create_funding(session)
    assert funding.funding_id is not None
    with pytest.raises(CrossTenantFundingAccess):
        service.get_funding(account_id=OTHER_ACCOUNT_ID, funding_id=funding.funding_id)

    result = webhook_service(
        session,
        success_event(
            payment_id=funding.external_payment_id or "",
            funding_id=OTHER_ACCOUNT_ID,
        ),
    ).process(payload=b"{}", signature_header="valid")

    assert result.reason_code is FundingReasonCode.ACCOUNT_MISMATCH
    assert LedgerService(session).balance_micro_usd(account_id=ACCOUNT_ID) == 0


def test_external_payment_id_cannot_bind_to_two_accounts() -> None:
    session = setup_session()
    _, funding = create_funding(session)
    assert funding.external_payment_id is not None
    session.add(Account(id=OTHER_ACCOUNT_ID, display_name="Other", status="active"))
    session.add(
        AccountFunding(
            id=uuid4(),
            funding_id=uuid4(),
            account_id=OTHER_ACCOUNT_ID,
            amount_micro_usd=1_000_000,
            currency="USD",
            gateway="stripe",
            external_payment_id=funding.external_payment_id,
            idempotency_key="other-key",
            status=FundingStatus.PENDING.value,
            metadata_json={},
        )
    )

    with pytest.raises(IntegrityError):
        session.flush()
    session.rollback()


def test_raw_webhook_and_signature_not_persisted_or_audited() -> None:
    session = setup_session()
    _, funding = create_funding(session)
    assert funding.external_payment_id is not None
    payload = b'{"card":"4242","secret":"whsec_test"}'

    webhook_service(
        session,
        success_event(payment_id=funding.external_payment_id, funding_id=funding.funding_id),
    ).process(payload=payload, signature_header="valid")

    persisted = repr(session.scalars(select(AuditEvent)).all()) + repr(
        session.scalars(select(AccountFunding)).all()
    )
    assert "4242" not in persisted
    assert "whsec" not in persisted
    assert "valid" not in persisted


def test_concurrent_duplicate_processing_cannot_double_credit() -> None:
    with TemporaryDirectory() as directory:
        db_path = Path(directory) / "funding.sqlite"
        engine = create_engine(
            f"sqlite:///{db_path}",
            connect_args={"check_same_thread": False},
        )
        metadata.create_all(engine)
        factory = sessionmaker(bind=engine)
        session = factory()
        session.add(Account(id=ACCOUNT_ID, display_name="Concurrent", status="active"))
        session.commit()
        _, funding = create_funding(session)
        payment_id = funding.external_payment_id
        funding_id = funding.funding_id
        assert payment_id is not None and funding_id is not None
        event = success_event(payment_id=payment_id, funding_id=funding_id)

        def worker() -> object:
            local = factory()
            try:
                return StripeWebhookService(
                    local,
                    verifier=StaticStripeWebhookVerifier(event),
                    audit_service=AuditService(local),
                ).process(payload=b"{}", signature_header="valid")
            finally:
                local.commit()
                local.close()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: worker(), range(2)))

        final = factory()
        assert len(results) == 2
        assert LedgerService(final).balance_micro_usd(account_id=ACCOUNT_ID) == 1_000_000
        assert len(final.scalars(select(CreditLedgerTransaction)).all()) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("same_event_id", [True, False])
async def test_postgres_concurrent_webhook_processing_exactly_once(
    same_event_id: bool,
) -> None:
    database_name = f"outcome_payments_concurrency_{uuid4().hex}"
    admin_url = os.environ.get(
        "OUTCOME_POSTGRES_ADMIN_URL",
        "postgresql://outcome@127.0.0.1:5432/outcome",
    )
    test_url = f"postgresql+asyncpg://outcome@127.0.0.1:5432/{database_name}"
    try:
        admin = await asyncpg.connect(admin_url)
    except OSError:
        pytest.skip("local Postgres is not available")
    try:
        await admin.execute(f'CREATE DATABASE "{database_name}"')
    finally:
        await admin.close()
    engine = create_async_engine(test_url)
    try:
        async with engine.begin() as connection:
            await connection.run_sync(metadata.create_all)

        async with engine.begin() as connection:
            def seed(sync_connection):
                factory = sessionmaker(bind=sync_connection)
                session = factory()
                session.add(Account(id=ACCOUNT_ID, display_name="Pg", status="active"))
                result = FundingService(
                    session,
                    gateway=FakeStripePaymentGateway(),
                ).create_funding(funding_request(), correlation_id=uuid4())
                return result.funding_id, result.external_payment_id

            funding_id, payment_id = await connection.run_sync(seed)
        assert funding_id is not None and payment_id is not None

        async def worker(index: int):
            event_id = "evt_same" if same_event_id else f"evt_distinct_{index}"
            event = success_event(
                event_id=event_id,
                payment_id=payment_id,
                funding_id=funding_id,
            )
            async with engine.begin() as connection:
                def process(sync_connection):
                    factory = sessionmaker(bind=sync_connection)
                    session = factory()
                    return StripeWebhookService(
                        session,
                        verifier=StaticStripeWebhookVerifier(event),
                        audit_service=AuditService(session),
                    ).process(payload=b"{}", signature_header="valid")

                return await connection.run_sync(process)

        results = await asyncio.gather(worker(1), worker(2))

        async with engine.begin() as connection:
            def inspect(sync_connection):
                factory = sessionmaker(bind=sync_connection)
                session = factory()
                funding = session.scalar(select(AccountFunding))
                ledgers = session.scalars(select(CreditLedgerTransaction)).all()
                entries = [
                    entry
                    for ledger in ledgers
                    for entry in LedgerService(session)
                    .transaction_for_account(
                        account_id=ACCOUNT_ID,
                        transaction_id=ledger.transaction_id,
                    )
                    .entries
                ]
                balance = LedgerService(session).balance_micro_usd(account_id=ACCOUNT_ID)
                return funding, ledgers, entries, balance

            funding, ledgers, entries, balance = await connection.run_sync(inspect)

        assert all(result.status is PaymentEventProcessingStatus.PROCESSED for result in results)
        assert funding.status == FundingStatus.SUCCEEDED.value
        assert len(ledgers) == 1
        assert len(entries) == 2
        assert sum(e.amount_micro_usd for e in entries if e.direction == "DEBIT") == 1_000_000
        assert sum(e.amount_micro_usd for e in entries if e.direction == "CREDIT") == 1_000_000
        assert balance == 1_000_000
    finally:
        await engine.dispose()
        admin = await asyncpg.connect(admin_url)
        try:
            await admin.execute(f'DROP DATABASE IF EXISTS "{database_name}" WITH (FORCE)')
        finally:
            await admin.close()


def test_ledger_failure_cannot_leave_false_succeeded_state() -> None:
    session = setup_session()
    _, funding = create_funding(session)
    assert funding.external_payment_id is not None
    LedgerService(session).settle_reservation(
        account_id=ACCOUNT_ID,
        amount_micro_usd=1_000_000,
        idempotency_key=f"stripe:funding:{funding.funding_id}",
        correlation_id=uuid4(),
    )

    result = webhook_service(
        session,
        success_event(payment_id=funding.external_payment_id, funding_id=funding.funding_id),
    ).process(payload=b"{}", signature_header="valid")
    row = session.scalar(select(AccountFunding))

    assert result.reason_code is FundingReasonCode.LEDGER_POSTING_FAILED
    assert row is not None
    assert row.status != FundingStatus.SUCCEEDED.value
