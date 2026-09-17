from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import asyncpg
import pytest
from redis import Redis
from redis.exceptions import RedisError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import Session, sessionmaker

from outcome.audit import AuditService
from outcome.authorization import AuthorizationLifecyclePhase, AuthorizationOrchestrator
from outcome.billing import (
    AuthorizationBillingService,
    BillingError,
    BillingLifecycleState,
    BillingReasonCode,
    actual_charge_micro_usd,
)
from outcome.db.metadata import metadata
from outcome.db.models import (
    Account,
    AuthorizationBilling,
    AuthorizationRequest,
    CreditLedgerTransaction,
)
from outcome.domain import PolicyDecision
from outcome.execution import ExecutionAuthorizationValidator
from outcome.ledger import LedgerService
from outcome.policies import PolicyEvaluationService
from outcome.pricing import (
    BillingMode,
    CapabilityName,
    CapabilityPricingConfig,
    InMemoryPricingConfigStore,
    PricingQuote,
    PricingService,
)
from outcome.receipts import ReceiptService
from outcome.reservations import ReservationInsufficientFunds, ReservationService
from tests.test_api_keys import build_session
from tests.test_authorization_orchestrator import (
    add_policy,
    add_verification_result,
    envelope,
)
from tests.test_receipt_service import signer, verifier

ACCOUNT_ID = UUID("11111111-1111-4111-8111-111111111111")
AUTHORIZATION_ID = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
NOW = datetime(2026, 9, 17, 12, 0, 0, tzinfo=UTC)
AUTHORIZATION_NOW = datetime(2026, 9, 15, 12, 0, 0, tzinfo=UTC)


@pytest.fixture()
def redis_client() -> Redis:
    client = Redis(host="127.0.0.1", port=6379, db=14)
    try:
        client.ping()
    except RedisError:
        pytest.skip("local Redis is not available")
    client.flushdb()
    yield client
    client.flushdb()


def setup_session() -> Session:
    session = build_session()
    account = session.scalar(select(Account))
    assert account is not None
    account.id = ACCOUNT_ID
    session.commit()
    return session


def pricing_service(session: Session, *, billing_mode: BillingMode = BillingMode.MANAGED):
    return PricingService(
        config_store=InMemoryPricingConfigStore(
            (
                CapabilityPricingConfig(
                    capability=CapabilityName.AUTHORIZE,
                    billing_mode=billing_mode,
                    pricing_config_version=f"pricing-{billing_mode.value.lower()}-v1",
                    minimum_price_micro_usd=1_000_000,
                    included_evidence_budget_micro_usd=0,
                    expected_compute_cost_micro_usd=500_000,
                    expected_managed_supplier_cost_micro_usd=(
                        500_000 if billing_mode is BillingMode.MANAGED else 0
                    ),
                    target_gross_margin_bps=0,
                    maximum_retry_budget_micro_usd=0,
                    maximum_total_cost_micro_usd=2_000_000,
                    enabled=True,
                ),
            )
        ),
        audit_service=AuditService(session),
    )


def billing_service(
    session: Session,
    redis_client: Redis,
    *,
    billing_mode: BillingMode = BillingMode.MANAGED,
) -> AuthorizationBillingService:
    audit = AuditService(session)
    ledger = LedgerService(session, audit)
    return AuthorizationBillingService(
        session,
        pricing_service=pricing_service(session, billing_mode=billing_mode),
        reservation_service=ReservationService(
            redis=redis_client,
            ledger_service=ledger,
            audit_service=audit,
        ),
        ledger_service=ledger,
        audit_service=audit,
        clock=lambda: NOW,
        reservation_ttl=timedelta(minutes=10),
    )


def fund(session: Session, amount: int = 5_000_000) -> None:
    LedgerService(session).fund_account(
        account_id=ACCOUNT_ID,
        amount_micro_usd=amount,
        idempotency_key=f"fund:{uuid4()}",
        correlation_id=uuid4(),
    )
    session.commit()


def material(ephemeral: str = "ignored") -> dict[str, object]:
    return {
        "capability": "authorize",
        "amount_micro_usd": 1_000_000,
        "destination": "merchant-a",
        "ephemeral": ephemeral,
    }


def quote_and_reserve(
    service: AuthorizationBillingService,
    *,
    authorization_id: UUID = AUTHORIZATION_ID,
    material_value: dict[str, object] | None = None,
):
    quote = service.quote(
        account_id=ACCOUNT_ID,
        authorization_request_id=authorization_id,
        capability=CapabilityName.AUTHORIZE,
        execution_mode=BillingMode.MANAGED,
        material=material_value or material(),
        correlation_id=uuid4(),
    )
    result = service.create_or_reserve(
        account_id=ACCOUNT_ID,
        authorization_request_id=authorization_id,
        quote=quote,
        correlation_id=uuid4(),
    )
    return quote, result


def add_authorization_request(session: Session, authorization_id: UUID) -> None:
    session.add(
        AuthorizationRequest(
            id=authorization_id,
            account_id=ACCOUNT_ID,
            request_id=uuid4(),
            agent_id=uuid4(),
            action_name="authorize",
            action_target_hash="a" * 64,
            material_hash="b" * 64,
            ephemeral_hash="c" * 64,
            requested_assurance="STANDARD",
            action_schema_version="action.schema.v1",
            authorization_expires_at=NOW + timedelta(minutes=5),
            idempotency_key=f"auth:{authorization_id}",
            request_fingerprint="d" * 64,
            lifecycle_state="IN_PROGRESS",
            request_config_version="test",
            lifecycle_metadata={},
        )
    )


def test_quote_fingerprint_stable_and_material_changes(redis_client: Redis) -> None:
    session = setup_session()
    fund(session)
    service = billing_service(session, redis_client)

    first = service.quote(
        account_id=ACCOUNT_ID,
        authorization_request_id=AUTHORIZATION_ID,
        capability=CapabilityName.AUTHORIZE,
        execution_mode=BillingMode.MANAGED,
        material=material("a"),
        correlation_id=uuid4(),
    )
    second = service.quote(
        account_id=ACCOUNT_ID,
        authorization_request_id=AUTHORIZATION_ID,
        capability=CapabilityName.AUTHORIZE,
        execution_mode=BillingMode.MANAGED,
        material=material("a"),
        correlation_id=uuid4(),
    )
    changed = service.quote(
        account_id=ACCOUNT_ID,
        authorization_request_id=AUTHORIZATION_ID,
        capability=CapabilityName.AUTHORIZE,
        execution_mode=BillingMode.MANAGED,
        material={**material("a"), "amount_micro_usd": 2_000_000},
        correlation_id=uuid4(),
    )
    ephemeral_changed = service.quote(
        account_id=ACCOUNT_ID,
        authorization_request_id=AUTHORIZATION_ID,
        capability=CapabilityName.AUTHORIZE,
        execution_mode=BillingMode.MANAGED,
        material=material("b"),
        correlation_id=uuid4(),
    )

    assert first.quote_fingerprint == second.quote_fingerprint
    assert first.quote_fingerprint == ephemeral_changed.quote_fingerprint
    assert first.quote_fingerprint != changed.quote_fingerprint
    assert first.max_reserved_spend_micro_usd >= first.quoted_price_micro_usd


def test_inconsistent_pricing_quote_fails_closed(redis_client: Redis) -> None:
    class InconsistentPricingService:
        def quote(self, **_: object) -> PricingQuote:
            return PricingQuote(
                quote_id=uuid4(),
                capability=CapabilityName.AUTHORIZE,
                billing_mode=BillingMode.MANAGED,
                pricing_config_version="bad-pricing-v1",
                quoted_price_micro_usd=1_000_000,
                maximum_reserved_spend_micro_usd=999_999,
                included_evidence_budget_micro_usd=0,
                maximum_retry_budget_micro_usd=0,
                expected_total_cost_micro_usd=500_000,
                estimated_gross_margin_bps=0,
            )

    session = setup_session()
    audit = AuditService(session)
    ledger = LedgerService(session, audit)
    service = AuthorizationBillingService(
        session,
        pricing_service=InconsistentPricingService(),  # type: ignore[arg-type]
        reservation_service=ReservationService(
            redis=redis_client,
            ledger_service=ledger,
            audit_service=audit,
        ),
        ledger_service=ledger,
        audit_service=audit,
    )

    with pytest.raises(BillingError) as error:
        service.quote(
            account_id=ACCOUNT_ID,
            authorization_request_id=AUTHORIZATION_ID,
            capability=CapabilityName.AUTHORIZE,
            execution_mode=BillingMode.MANAGED,
            material=material(),
            correlation_id=uuid4(),
        )

    assert error.value.reason is BillingReasonCode.PRICING_INVARIANT_VIOLATION


def test_reservation_ttl_configuration_bounds(redis_client: Redis) -> None:
    session = setup_session()
    audit = AuditService(session)
    ledger = LedgerService(session, audit)
    base_kwargs = {
        "pricing_service": pricing_service(session),
        "reservation_service": ReservationService(
            redis=redis_client,
            ledger_service=ledger,
            audit_service=audit,
        ),
        "ledger_service": ledger,
        "audit_service": audit,
    }

    AuthorizationBillingService(
        session,
        **base_kwargs,
        reservation_ttl=timedelta(seconds=360),
        maximum_billable_execution_window=timedelta(seconds=300),
        reservation_ttl_safety_margin=timedelta(seconds=60),
    )
    AuthorizationBillingService(
        session,
        **base_kwargs,
        reservation_ttl=timedelta(seconds=460),
        maximum_billable_execution_window=timedelta(seconds=400),
        reservation_ttl_safety_margin=timedelta(seconds=60),
    )
    with pytest.raises(ValueError, match=BillingReasonCode.RESERVATION_TTL_UNSAFE.value):
        AuthorizationBillingService(
            session,
            **base_kwargs,
            reservation_ttl=timedelta(seconds=359),
            maximum_billable_execution_window=timedelta(seconds=300),
            reservation_ttl_safety_margin=timedelta(seconds=60),
        )
    with pytest.raises(ValueError, match=BillingReasonCode.RESERVATION_TTL_UNSAFE.value):
        AuthorizationBillingService(
            session,
            **base_kwargs,
            reservation_ttl=timedelta(seconds=3_601),
            max_reservation_ttl=timedelta(seconds=3_600),
        )


def test_sufficient_funds_reserve_settle_and_release(redis_client: Redis) -> None:
    session = setup_session()
    fund(session)
    service = billing_service(session, redis_client)
    quote, reserved = quote_and_reserve(service)

    settled = service.settle(
        account_id=ACCOUNT_ID,
        authorization_request_id=AUTHORIZATION_ID,
        quote=quote,
        decision=PolicyDecision.ALLOW,
        system_failure=False,
        correlation_id=uuid4(),
    )
    row = session.scalar(select(AuthorizationBilling))

    assert reserved.state is BillingLifecycleState.RESERVED
    assert settled.settlement_ledger_transaction_id is not None
    assert row is not None
    assert row.billing_state == BillingLifecycleState.RELEASED.value
    assert LedgerService(session).balance_micro_usd(account_id=ACCOUNT_ID) == 4_000_000
    assert len(session.scalars(select(CreditLedgerTransaction)).all()) == 2


def test_insufficient_funds_fails_before_work(redis_client: Redis) -> None:
    session = setup_session()
    service = billing_service(session, redis_client)
    quote = service.quote(
        account_id=ACCOUNT_ID,
        authorization_request_id=AUTHORIZATION_ID,
        capability=CapabilityName.AUTHORIZE,
        execution_mode=BillingMode.MANAGED,
        material=material(),
        correlation_id=uuid4(),
    )

    with pytest.raises(BillingError) as error:
        service.create_or_reserve(
            account_id=ACCOUNT_ID,
            authorization_request_id=AUTHORIZATION_ID,
            quote=quote,
            correlation_id=uuid4(),
        )

    assert error.value.reason is BillingReasonCode.INSUFFICIENT_FUNDS


def test_redis_unavailable_fails_closed_before_work() -> None:
    session = setup_session()
    fund(session)
    unavailable = Redis(host="127.0.0.1", port=1, socket_connect_timeout=0.01)
    service = billing_service(session, unavailable)
    quote = service.quote(
        account_id=ACCOUNT_ID,
        authorization_request_id=AUTHORIZATION_ID,
        capability=CapabilityName.AUTHORIZE,
        execution_mode=BillingMode.MANAGED,
        material=material(),
        correlation_id=uuid4(),
    )

    with pytest.raises(BillingError) as error:
        service.create_or_reserve(
            account_id=ACCOUNT_ID,
            authorization_request_id=AUTHORIZATION_ID,
            quote=quote,
            correlation_id=uuid4(),
        )

    row = session.scalar(select(AuthorizationBilling))
    assert error.value.reason is BillingReasonCode.REDIS_UNAVAILABLE
    assert row is not None
    assert row.billing_state == BillingLifecycleState.FAILED.value


def test_outstanding_reservation_reduces_availability(redis_client: Redis) -> None:
    session = setup_session()
    fund(session, amount=1_500_000)
    service = billing_service(session, redis_client)
    quote_and_reserve(service, authorization_id=uuid4())

    with pytest.raises((BillingError, ReservationInsufficientFunds)):
        quote_and_reserve(service, authorization_id=uuid4())


@pytest.mark.parametrize(
    ("decision", "system_failure", "expected"),
    [
        (PolicyDecision.ALLOW, False, 1_000_000),
        (PolicyDecision.BLOCK, False, 1_000_000),
        (PolicyDecision.ESCALATE, False, 1_000_000),
        (PolicyDecision.RETRY_HIGHER_ASSURANCE, False, 1_000_000),
        (PolicyDecision.BLOCK, True, 0),
    ],
)
def test_v1_actual_charge_semantics(
    redis_client: Redis,
    decision: PolicyDecision,
    system_failure: bool,
    expected: int,
) -> None:
    session = setup_session()
    service = billing_service(session, redis_client)
    quote = service.quote(
        account_id=ACCOUNT_ID,
        authorization_request_id=AUTHORIZATION_ID,
        capability=CapabilityName.AUTHORIZE,
        execution_mode=BillingMode.MANAGED,
        material=material(),
        correlation_id=uuid4(),
    )

    assert actual_charge_micro_usd(
        quote=quote,
        decision=decision,
        system_failure=system_failure,
    ) == expected


@pytest.mark.parametrize(
    "decision",
    [
        PolicyDecision.BLOCK,
        PolicyDecision.ESCALATE,
        PolicyDecision.RETRY_HIGHER_ASSURANCE,
    ],
)
def test_non_allow_pre_work_zero_and_post_work_charge(
    redis_client: Redis,
    decision: PolicyDecision,
) -> None:
    session = setup_session()
    service = billing_service(session, redis_client)
    quote = service.quote(
        account_id=ACCOUNT_ID,
        authorization_request_id=AUTHORIZATION_ID,
        capability=CapabilityName.AUTHORIZE,
        execution_mode=BillingMode.MANAGED,
        material=material(),
        correlation_id=uuid4(),
    )

    assert (
        actual_charge_micro_usd(
            quote=quote,
            decision=decision,
            system_failure=False,
            billable_work_occurred=False,
        )
        == 0
    )
    assert (
        actual_charge_micro_usd(
            quote=quote,
            decision=decision,
            system_failure=False,
            billable_work_occurred=True,
        )
        == 1_000_000
    )


def test_duplicate_settlement_no_double_charge(redis_client: Redis) -> None:
    session = setup_session()
    fund(session)
    service = billing_service(session, redis_client)
    quote, _ = quote_and_reserve(service)

    first = service.settle(
        account_id=ACCOUNT_ID,
        authorization_request_id=AUTHORIZATION_ID,
        quote=quote,
        decision=PolicyDecision.ALLOW,
        system_failure=False,
        correlation_id=uuid4(),
    )
    second = service.settle(
        account_id=ACCOUNT_ID,
        authorization_request_id=AUTHORIZATION_ID,
        quote=quote,
        decision=PolicyDecision.ALLOW,
        system_failure=False,
        correlation_id=uuid4(),
    )

    assert first.settlement_ledger_transaction_id == second.settlement_ledger_transaction_id
    assert LedgerService(session).balance_micro_usd(account_id=ACCOUNT_ID) == 4_000_000


def test_release_failure_quarantines_and_retry_is_idempotent(redis_client: Redis) -> None:
    class ReleaseFailingReservationService(ReservationService):
        def release(self, *, reservation_id: UUID, account_id: UUID):
            raise ReservationUnavailable(ReservationError.REDIS_UNAVAILABLE)

    from outcome.reservations import ReservationError, ReservationUnavailable

    session = setup_session()
    fund(session)
    audit = AuditService(session)
    ledger = LedgerService(session, audit)
    failing_service = AuthorizationBillingService(
        session,
        pricing_service=pricing_service(session),
        reservation_service=ReleaseFailingReservationService(
            redis=redis_client,
            ledger_service=ledger,
            audit_service=audit,
        ),
        ledger_service=ledger,
        audit_service=audit,
        clock=lambda: NOW,
        reservation_ttl=timedelta(minutes=10),
    )
    quote, _ = quote_and_reserve(failing_service)

    with pytest.raises(BillingError) as error:
        failing_service.settle(
            account_id=ACCOUNT_ID,
            authorization_request_id=AUTHORIZATION_ID,
            quote=quote,
            decision=PolicyDecision.ALLOW,
            system_failure=False,
            correlation_id=uuid4(),
        )

    assert error.value.reason is BillingReasonCode.RESERVATION_RELEASE_FAILED
    assert len(session.scalars(select(CreditLedgerTransaction)).all()) == 2
    with pytest.raises(BillingError) as second_error:
        quote_and_reserve(failing_service, authorization_id=uuid4())
    assert second_error.value.reason is BillingReasonCode.REDIS_UNAVAILABLE
    recovered = billing_service(session, redis_client).settle(
        account_id=ACCOUNT_ID,
        authorization_request_id=AUTHORIZATION_ID,
        quote=quote,
        decision=PolicyDecision.ALLOW,
        system_failure=False,
        correlation_id=uuid4(),
    )
    assert recovered.settlement_ledger_transaction_id is not None
    assert len(session.scalars(select(CreditLedgerTransaction)).all()) == 2


def test_byok_quote_excludes_managed_supplier_cost(redis_client: Redis) -> None:
    session = setup_session()
    service = billing_service(session, redis_client, billing_mode=BillingMode.BYOK)
    quote = service.quote(
        account_id=ACCOUNT_ID,
        authorization_request_id=AUTHORIZATION_ID,
        capability=CapabilityName.AUTHORIZE,
        execution_mode=BillingMode.BYOK,
        material=material(),
        correlation_id=uuid4(),
    )

    assert quote.expected_total_cost_micro_usd == 500_000
    assert quote.quoted_price_micro_usd == 1_000_000


def test_authorization_allow_settles_billing_before_receipt(redis_client: Redis) -> None:
    session = setup_session()
    add_policy(session)
    verification_result_id = add_verification_result(session)
    fund(session)
    billing = billing_service(session, redis_client)
    audit = AuditService(session)
    receipt_service = ReceiptService(
        session,
        signer=signer(),
        verifier=verifier(),
        audit_service=audit,
    )
    orchestrator = AuthorizationOrchestrator(
        session,
        policy_service=PolicyEvaluationService(session, audit, clock=lambda: NOW),
        receipt_service=receipt_service,
        execution_validator=ExecutionAuthorizationValidator(
            receipt_verifier=verifier(),
            audit_service=audit,
        ),
        billing_service=billing,
        audit_service=audit,
        clock=lambda: AUTHORIZATION_NOW,
    )

    result = orchestrator.authorize(envelope(verification_result_id=verification_result_id))
    billing_result = billing.get_for_authorization(
        account_id=ACCOUNT_ID,
        authorization_request_id=result.authorization_request_id,
    )

    assert result.decision is PolicyDecision.ALLOW
    assert result.lifecycle_state is AuthorizationLifecyclePhase.COMPLETED
    assert result.receipt_id is not None
    assert result.signed_receipt is not None
    assert billing_result.state is BillingLifecycleState.RELEASED
    assert billing_result.settlement_ledger_transaction_id is not None
    assert result.provenance["billing"] == {
        "actual_charge_micro_usd": 1_000_000,
        "billing_id": str(billing_result.billing_id),
        "billing_state": BillingLifecycleState.RELEASED.value,
        "currency": "USD",
        "execution_mode": BillingMode.MANAGED.value,
        "max_reserved_spend_micro_usd": 1_000_000,
        "pricing_version": "pricing-managed-v1",
        "quote_fingerprint": billing_result.quote.quote_fingerprint,
        "reservation_id": str(billing_result.reservation_id),
        "settlement_ledger_transaction_id": str(
            billing_result.settlement_ledger_transaction_id
        ),
    }
    assert LedgerService(session).balance_micro_usd(account_id=ACCOUNT_ID) == 4_000_000


def test_authorization_without_funds_fails_closed_without_receipt(redis_client: Redis) -> None:
    session = setup_session()
    add_policy(session)
    verification_result_id = add_verification_result(session)
    billing = billing_service(session, redis_client)
    audit = AuditService(session)
    orchestrator = AuthorizationOrchestrator(
        session,
        policy_service=PolicyEvaluationService(session, audit, clock=lambda: NOW),
        receipt_service=ReceiptService(
            session,
            signer=signer(),
            verifier=verifier(),
            audit_service=audit,
        ),
        execution_validator=ExecutionAuthorizationValidator(
            receipt_verifier=verifier(),
            audit_service=audit,
        ),
        billing_service=billing,
        audit_service=audit,
        clock=lambda: AUTHORIZATION_NOW,
    )

    result = orchestrator.authorize(envelope(verification_result_id=verification_result_id))

    assert result.decision is PolicyDecision.BLOCK
    assert result.receipt_id is None
    assert "SYSTEM_FAILURE" in result.reason_codes


def test_receipt_failure_after_settlement_is_compensated(redis_client: Redis) -> None:
    class FailingReceiptService(ReceiptService):
        def issue_authorization_receipt(self, **_: object):
            raise RuntimeError("signing unavailable")

    session = setup_session()
    add_policy(session)
    verification_result_id = add_verification_result(session)
    fund(session)
    billing = billing_service(session, redis_client)
    audit = AuditService(session)
    orchestrator = AuthorizationOrchestrator(
        session,
        policy_service=PolicyEvaluationService(session, audit, clock=lambda: NOW),
        receipt_service=FailingReceiptService(
            session,
            signer=signer(),
            verifier=verifier(),
            audit_service=audit,
        ),
        execution_validator=ExecutionAuthorizationValidator(
            receipt_verifier=verifier(),
            audit_service=audit,
        ),
        billing_service=billing,
        audit_service=audit,
        clock=lambda: AUTHORIZATION_NOW,
    )

    result = orchestrator.authorize(envelope(verification_result_id=verification_result_id))
    billing_result = billing.get_for_authorization(
        account_id=ACCOUNT_ID,
        authorization_request_id=result.authorization_request_id,
    )

    assert result.decision is PolicyDecision.BLOCK
    assert result.receipt_id is None
    assert BillingReasonCode.SYSTEM_FAILURE_ZERO_CHARGE.value == billing_result.reason_code.value
    assert billing_result.actual_charge_micro_usd == 0
    assert LedgerService(session).balance_micro_usd(account_id=ACCOUNT_ID) == 5_000_000
    assert len(session.scalars(select(CreditLedgerTransaction)).all()) == 3


def test_completed_allow_replay_reuses_billing_receipt_and_ledger(redis_client: Redis) -> None:
    session = setup_session()
    add_policy(session)
    verification_result_id = add_verification_result(session)
    fund(session)
    billing = billing_service(session, redis_client)
    audit = AuditService(session)
    orchestrator = AuthorizationOrchestrator(
        session,
        policy_service=PolicyEvaluationService(session, audit, clock=lambda: NOW),
        receipt_service=ReceiptService(
            session,
            signer=signer(),
            verifier=verifier(),
            audit_service=audit,
        ),
        execution_validator=ExecutionAuthorizationValidator(
            receipt_verifier=verifier(),
            audit_service=audit,
        ),
        billing_service=billing,
        audit_service=audit,
        clock=lambda: AUTHORIZATION_NOW,
    )
    request = envelope(verification_result_id=verification_result_id)

    first = orchestrator.authorize(request)
    ledger_count = len(session.scalars(select(CreditLedgerTransaction)).all())
    billing_first = billing.get_for_authorization(
        account_id=ACCOUNT_ID,
        authorization_request_id=first.authorization_request_id,
    )
    second = orchestrator.authorize(request)
    billing_second = billing.get_for_authorization(
        account_id=ACCOUNT_ID,
        authorization_request_id=second.authorization_request_id,
    )

    assert second.idempotent_replay is True
    assert second.authorization_result_id == first.authorization_result_id
    assert second.receipt_id == first.receipt_id
    assert second.signed_receipt == first.signed_receipt
    assert billing_second.billing_id == billing_first.billing_id
    assert billing_second.quote.quote_fingerprint == billing_first.quote.quote_fingerprint
    assert (
        billing_second.settlement_ledger_transaction_id
        == billing_first.settlement_ledger_transaction_id
    )
    assert len(session.scalars(select(CreditLedgerTransaction)).all()) == ledger_count


@pytest.mark.asyncio
async def test_postgres_concurrent_settlement_same_billing_operation(redis_client: Redis) -> None:
    database_name = f"outcome_billing_settle_{uuid4().hex}"
    admin_url = os.environ.get(
        "OUTCOME_POSTGRES_ADMIN_URL",
        "postgresql://outcome@127.0.0.1:5432/outcome",
    )
    try:
        admin = await asyncpg.connect(admin_url)
    except OSError:
        pytest.skip("local Postgres is not available")
    try:
        await admin.execute(f'CREATE DATABASE "{database_name}"')
    finally:
        await admin.close()
    engine = create_async_engine(
        f"postgresql+asyncpg://outcome@127.0.0.1:5432/{database_name}"
    )
    try:
        async with engine.begin() as connection:
            await connection.run_sync(metadata.create_all)
            def seed(sync_connection):
                factory = sessionmaker(bind=sync_connection)
                session = factory()
                session.add(Account(id=ACCOUNT_ID, display_name="Billing", status="active"))
                add_authorization_request(session, AUTHORIZATION_ID)
                LedgerService(session).fund_account(
                    account_id=ACCOUNT_ID,
                    amount_micro_usd=5_000_000,
                    idempotency_key=f"fund:{uuid4()}",
                    correlation_id=uuid4(),
                )
                service = billing_service(session, redis_client)
                quote_and_reserve(service)
            await connection.run_sync(seed)

        async def worker():
            async with engine.begin() as connection:
                def settle(sync_connection):
                    factory = sessionmaker(bind=sync_connection)
                    session = factory()
                    service = billing_service(session, redis_client)
                    quote = service.get_for_authorization(
                        account_id=ACCOUNT_ID,
                        authorization_request_id=AUTHORIZATION_ID,
                    ).quote
                    return service.settle(
                        account_id=ACCOUNT_ID,
                        authorization_request_id=AUTHORIZATION_ID,
                        quote=quote,
                        decision=PolicyDecision.ALLOW,
                        system_failure=False,
                        correlation_id=uuid4(),
                    )
                return await connection.run_sync(settle)

        results = await asyncio.gather(worker(), worker())

        async with engine.begin() as connection:
            def inspect(sync_connection):
                factory = sessionmaker(bind=sync_connection)
                session = factory()
                return (
                    session.scalars(select(CreditLedgerTransaction)).all(),
                    LedgerService(session).balance_micro_usd(account_id=ACCOUNT_ID),
                    session.scalar(select(AuthorizationBilling)),
                )
            ledgers, balance, billing = await connection.run_sync(inspect)
        assert (
            results[0].settlement_ledger_transaction_id
            == results[1].settlement_ledger_transaction_id
        )
        assert len(ledgers) == 2
        assert balance == 4_000_000
        assert billing.billing_state == BillingLifecycleState.RELEASED.value
    finally:
        await engine.dispose()
        admin = await asyncpg.connect(admin_url)
        try:
            await admin.execute(f'DROP DATABASE IF EXISTS "{database_name}" WITH (FORCE)')
        finally:
            await admin.close()


@pytest.mark.asyncio
async def test_postgres_concurrent_reservations_share_one_balance(redis_client: Redis) -> None:
    database_name = f"outcome_billing_reserve_{uuid4().hex}"
    admin_url = os.environ.get(
        "OUTCOME_POSTGRES_ADMIN_URL",
        "postgresql://outcome@127.0.0.1:5432/outcome",
    )
    first_authorization_id = uuid4()
    second_authorization_id = uuid4()
    try:
        admin = await asyncpg.connect(admin_url)
    except OSError:
        pytest.skip("local Postgres is not available")
    try:
        await admin.execute(f'CREATE DATABASE "{database_name}"')
    finally:
        await admin.close()
    engine = create_async_engine(
        f"postgresql+asyncpg://outcome@127.0.0.1:5432/{database_name}"
    )
    try:
        async with engine.begin() as connection:
            await connection.run_sync(metadata.create_all)

            def seed(sync_connection):
                factory = sessionmaker(bind=sync_connection)
                session = factory()
                session.add(Account(id=ACCOUNT_ID, display_name="Billing", status="active"))
                add_authorization_request(session, first_authorization_id)
                add_authorization_request(session, second_authorization_id)
                LedgerService(session).fund_account(
                    account_id=ACCOUNT_ID,
                    amount_micro_usd=1_000_000,
                    idempotency_key=f"fund:{uuid4()}",
                    correlation_id=uuid4(),
                )

            await connection.run_sync(seed)

        async def worker(authorization_id: UUID):
            async with engine.begin() as connection:
                def reserve(sync_connection):
                    factory = sessionmaker(bind=sync_connection)
                    session = factory()
                    service = billing_service(session, redis_client)
                    try:
                        _quote, result = quote_and_reserve(
                            service,
                            authorization_id=authorization_id,
                        )
                        return result.state.value
                    except BillingError as error:
                        return error.reason.value

                return await connection.run_sync(reserve)

        outcomes = await asyncio.gather(
            worker(first_authorization_id),
            worker(second_authorization_id),
        )

        async with engine.begin() as connection:
            def inspect(sync_connection):
                factory = sessionmaker(bind=sync_connection)
                session = factory()
                service = billing_service(session, redis_client)
                report = service.reservation_service.reconcile(account_id=ACCOUNT_ID)
                return (
                    session.scalars(
                        select(AuthorizationBilling).order_by(
                            AuthorizationBilling.authorization_request_id
                        )
                    ).all(),
                    LedgerService(session).balance_micro_usd(account_id=ACCOUNT_ID),
                    report.active_reserved_micro_usd,
                )

            billings, balance, active_reserved = await connection.run_sync(inspect)

        assert set(outcomes) == {
            BillingLifecycleState.RESERVED.value,
            BillingReasonCode.INSUFFICIENT_FUNDS.value,
        }
        assert len(billings) == 2
        assert {billing.billing_state for billing in billings} == {
            BillingLifecycleState.RESERVED.value,
            BillingLifecycleState.FAILED.value,
        }
        assert balance == 1_000_000
        assert active_reserved <= balance
    finally:
        await engine.dispose()
        admin = await asyncpg.connect(admin_url)
        try:
            await admin.execute(f'DROP DATABASE IF EXISTS "{database_name}" WITH (FORCE)')
        finally:
            await admin.close()
