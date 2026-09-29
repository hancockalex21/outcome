from __future__ import annotations

import json
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from tempfile import TemporaryDirectory
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from outcome.actions import ACTION_SCHEMA_VERSION
from outcome.api.main import create_app
from outcome.auth import ApiKeyScope
from outcome.core.config import Settings
from outcome.db.metadata import metadata
from outcome.db.models import (
    Account,
    AccountFunding,
    AgentCredential,
    AuditEvent,
    BetaRegistration,
    BetaRegistrationCapacity,
    CreditLedgerEntry,
    CreditLedgerTransaction,
    Policy,
)
from outcome.domain import AssuranceLevel, PolicyDecision
from outcome.ledger import LedgerAccount, LedgerDirection, LedgerService, LedgerTransactionType
from outcome.onboarding import (
    BetaRegistrationConflict,
    BetaRegistrationCredentialAlreadyIssued,
    BetaRegistrationInput,
    BetaRegistrationService,
    collect_beta_metrics,
)
from outcome.policies import (
    CrossTenantPolicyAccess,
    PolicyEvaluationRequest,
    PolicyEvaluationService,
)

TOKEN = "beta-bootstrap-token-with-at-least-32-characters"


class FakePipeline:
    def __init__(self, redis: FakeRedis) -> None:
        self.redis = redis
        self.key = ""

    def __enter__(self) -> FakePipeline:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def incr(self, key: str) -> FakePipeline:
        self.key = key
        return self

    def expire(self, key: str, seconds: int) -> FakePipeline:
        assert key == self.key
        assert seconds > 0
        return self

    def execute(self) -> list[object]:
        self.redis.counts[self.key] = self.redis.counts.get(self.key, 0) + 1
        return [self.redis.counts[self.key], True]


class FakeRedis:
    def __init__(self) -> None:
        self.counts: dict[str, int] = {}

    def pipeline(self, *, transaction: bool) -> FakePipeline:
        assert transaction is True
        return FakePipeline(self)


class UnavailableRedis(FakeRedis):
    def pipeline(self, *, transaction: bool):
        from redis.exceptions import RedisError

        raise RedisError("unavailable")


@pytest.fixture()
def session_factory() -> Iterator[sessionmaker[Session]]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    metadata.create_all(engine)
    with Session(engine) as session:
        session.add(BetaRegistrationCapacity(id=1, registrations_used=0))
        session.commit()
    yield sessionmaker(bind=engine)
    engine.dispose()


def enabled_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "beta_registration_enabled": True,
        "beta_registration_database_url": "sqlite://",
        "beta_registration_bootstrap_token": TOKEN,
        "beta_registration_limit": 2,
        "beta_promotional_credit_micro_usd": 1_000_000,
        "public_mcp_endpoint": "https://mcp.example.test/mcp",
        "public_quickstart_url": "https://docs.example.test/quickstart",
    }
    values.update(overrides)
    return Settings(**values)


def service_register(factory: sessionmaker[Session], key: str = "registration-1"):
    with factory() as session, session.begin():
        return BetaRegistrationService(
            session,
            promotional_credit_micro_usd=1_000_000,
            registration_limit=2,
        ).register(
            BetaRegistrationInput(display_name="Example Developer", idempotency_key=key),
            correlation_id=uuid4(),
        )


async def request_registration(
    factory: sessionmaker[Session],
    *,
    token: str | None = TOKEN,
    key: str | None = "registration-1",
    display_name: str = "Example Developer",
    settings: Settings | None = None,
):
    app = create_app(
        settings=settings or enabled_settings(),
        beta_session_factory=factory,
        beta_redis=FakeRedis(),  # type: ignore[arg-type]
    )
    headers = {}
    if token is not None:
        headers["X-Outcome-Beta-Token"] = token
    if key is not None:
        headers["Idempotency-Key"] = key
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        return await client.post(
            "/v1/beta/register",
            headers=headers,
            json={"display_name": display_name},
        )


@pytest.mark.asyncio
async def test_endpoint_disabled_by_default(session_factory: sessionmaker[Session]) -> None:
    response = await request_registration(session_factory, settings=Settings())
    assert response.status_code == 404


@pytest.mark.asyncio
@pytest.mark.parametrize("token", [None, "invalid-token"])
async def test_missing_or_invalid_bootstrap_rejected(
    session_factory: sessionmaker[Session], token: str | None
) -> None:
    response = await request_registration(session_factory, token=token)
    assert response.status_code == 401
    with session_factory() as session:
        assert session.scalar(select(func.count()).select_from(Account)) == 0


@pytest.mark.asyncio
async def test_valid_registration_is_atomic_minimal_and_secret_safe(
    session_factory: sessionmaker[Session],
) -> None:
    response = await request_registration(session_factory)
    assert response.status_code == 201
    body = response.json()
    plaintext = body["agent_api_key"]
    assert plaintext.startswith("oc_agent_")
    assert body["credential_scopes"] == [ApiKeyScope.AUTHORIZE_WRITE.value]
    assert body["promotional_credit_classification"] == "PROMOTIONAL_NOT_REVENUE"
    assert body["mcp_endpoint"] == "https://mcp.example.test/mcp"

    with session_factory() as session:
        assert session.scalar(select(func.count()).select_from(Account)) == 1
        assert session.scalar(select(func.count()).select_from(AgentCredential)) == 1
        assert session.scalar(select(func.count()).select_from(Policy)) == 1
        assert session.scalar(select(func.count()).select_from(BetaRegistration)) == 1
        credential = session.scalar(select(AgentCredential))
        assert credential is not None
        assert credential.scopes == [ApiKeyScope.AUTHORIZE_WRITE.value]
        assert plaintext not in repr(credential.__dict__)
        registration = session.scalar(select(BetaRegistration))
        assert registration is not None
        assert registration.account_id == credential.account_id
        transactions = session.scalars(select(CreditLedgerTransaction)).all()
        assert len(transactions) == 1
        assert transactions[0].transaction_type == LedgerTransactionType.PROMOTIONAL_CREDIT.value
        entries = session.scalars(select(CreditLedgerEntry)).all()
        assert {(entry.ledger_account, entry.direction) for entry in entries} == {
            (LedgerAccount.PROMOTIONAL_CREDIT_EXPENSE.value, LedgerDirection.DEBIT.value),
            (LedgerAccount.CUSTOMER_PREPAID_LIABILITY.value, LedgerDirection.CREDIT.value),
        }
        assert (
            LedgerService(session).balance_micro_usd(account_id=registration.account_id)
            == 1_000_000
        )
        audit_text = repr(session.scalars(select(AuditEvent)).all())
        assert plaintext not in audit_text
        assert TOKEN not in audit_text


@pytest.mark.asyncio
async def test_http_retry_requires_credential_recovery_and_conflict_fails(
    session_factory: sessionmaker[Session],
) -> None:
    first = await request_registration(session_factory)
    retry = await request_registration(session_factory)
    conflict = await request_registration(session_factory, display_name="Different")
    assert first.status_code == 201
    assert retry.status_code == 409
    assert retry.json()["detail"] == "registration completed; credential recovery required"
    assert conflict.status_code == 409
    assert conflict.json()["detail"] == "idempotency conflict"
    with session_factory() as session:
        assert session.scalar(select(func.count()).select_from(Account)) == 1
        assert session.scalar(select(func.count()).select_from(CreditLedgerTransaction)) == 1


def test_starter_policy_allows_only_harmless_zero_value_action(
    session_factory: sessionmaker[Session],
) -> None:
    result = service_register(session_factory)
    with session_factory() as session:
        policy_service = PolicyEvaluationService(session)
        base = {
            "action_type": "controlled_beta_test",
            "capability": "authorize",
            "amount_micro_usd": 0,
            "destination": "synthetic-resource",
            "resource": "demo",
        }
        allowed = policy_service.evaluate(
            PolicyEvaluationRequest(
                account_id=result.account_id,
                policy_id=result.policy_id,
                policy_version=1,
                material_action=base,
                action_schema_version=ACTION_SCHEMA_VERSION,
                assurance_level=AssuranceLevel.STANDARD,
            ),
            correlation_id=uuid4(),
        )
        dangerous = policy_service.evaluate(
            PolicyEvaluationRequest(
                account_id=result.account_id,
                policy_id=result.policy_id,
                policy_version=1,
                material_action={**base, "action_type": "transfer", "amount_micro_usd": 1},
                action_schema_version=ACTION_SCHEMA_VERSION,
                assurance_level=AssuranceLevel.STANDARD,
            ),
            correlation_id=uuid4(),
        )
    assert allowed.decision is PolicyDecision.ALLOW
    assert dangerous.decision is PolicyDecision.BLOCK


def test_two_registrations_are_tenant_isolated(session_factory: sessionmaker[Session]) -> None:
    first = service_register(session_factory, "first")
    second = service_register(session_factory, "second")
    with session_factory() as session:
        with pytest.raises(CrossTenantPolicyAccess):
            PolicyEvaluationService(session).evaluate(
                PolicyEvaluationRequest(
                    account_id=first.account_id,
                    policy_id=second.policy_id,
                    policy_version=1,
                    material_action={
                        "action_type": "controlled_beta_test",
                        "capability": "authorize",
                        "amount_micro_usd": 0,
                        "destination": "synthetic-resource",
                    },
                    action_schema_version=ACTION_SCHEMA_VERSION,
                    assurance_level=AssuranceLevel.STANDARD,
                ),
                correlation_id=uuid4(),
            )


def test_retry_and_conflict_never_duplicate_economic_value(
    session_factory: sessionmaker[Session],
) -> None:
    service_register(session_factory)
    with pytest.raises(BetaRegistrationCredentialAlreadyIssued):
        service_register(session_factory)
    with session_factory() as session:
        with session.begin():
            with pytest.raises(BetaRegistrationConflict, match="idempotency key reused"):
                BetaRegistrationService(
                    session,
                    promotional_credit_micro_usd=1_000_000,
                    registration_limit=2,
                ).register(
                    BetaRegistrationInput(
                        display_name="Different", idempotency_key="registration-1"
                    ),
                    correlation_id=uuid4(),
                )
        assert session.scalar(select(func.count()).select_from(Account)) == 1
        assert session.scalar(select(func.count()).select_from(CreditLedgerTransaction)) == 1


def test_registration_limit_and_missing_capacity_fail_closed(
    session_factory: sessionmaker[Session],
) -> None:
    service_register(session_factory, "one")
    service_register(session_factory, "two")
    with pytest.raises(Exception, match="limit reached"):
        service_register(session_factory, "three")
    with session_factory() as session:
        session.query(BetaRegistrationCapacity).delete()
        session.commit()
    with pytest.raises(Exception, match="unavailable"):
        service_register(session_factory, "four")


@pytest.mark.asyncio
async def test_malformed_oversized_and_rate_limited_requests(
    session_factory: sessionmaker[Session],
) -> None:
    malformed = await request_registration(session_factory, display_name="")
    assert malformed.status_code == 422
    app = create_app(
        settings=enabled_settings(api_request_max_bytes=32, beta_registration_rate_limit=1),
        beta_session_factory=session_factory,
        beta_redis=FakeRedis(),  # type: ignore[arg-type]
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        oversized = await client.post(
            "/v1/beta/register",
            headers={"X-Outcome-Beta-Token": TOKEN, "Idempotency-Key": "large"},
            content=json.dumps({"display_name": "x" * 100}),
        )
        assert oversized.status_code == 413
        first = await client.post(
            "/v1/beta/register",
            headers={"X-Outcome-Beta-Token": "wrong", "Idempotency-Key": "one"},
            json={"display_name": "One"},
        )
        second = await client.post(
            "/v1/beta/register",
            headers={"X-Outcome-Beta-Token": "wrong", "Idempotency-Key": "two"},
            json={"display_name": "Two"},
        )
    assert first.status_code == 401
    assert second.status_code == 429


@pytest.mark.asyncio
async def test_unavailable_abuse_control_fails_closed(
    session_factory: sessionmaker[Session],
) -> None:
    app = create_app(
        settings=enabled_settings(),
        beta_session_factory=session_factory,
        beta_redis=UnavailableRedis(),  # type: ignore[arg-type]
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/v1/beta/register",
            headers={"X-Outcome-Beta-Token": TOKEN, "Idempotency-Key": "one"},
            json={"display_name": "One"},
        )
    assert response.status_code == 503


def test_failure_rolls_back_all_state(
    session_factory: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(*args: object, **kwargs: object) -> object:
        raise RuntimeError("promotional funding failed")

    monkeypatch.setattr("outcome.onboarding.service.LedgerService.grant_promotional_credit", fail)
    with pytest.raises(RuntimeError, match="promotional funding failed"):
        service_register(session_factory)
    with session_factory() as session:
        assert session.scalar(select(func.count()).select_from(Account)) == 0
        assert session.scalar(select(BetaRegistrationCapacity.registrations_used)) == 0


def test_operator_metrics_distinguish_promotional_and_paid_funding(
    session_factory: sessionmaker[Session],
) -> None:
    result = service_register(session_factory)
    with session_factory() as session:
        with session.begin():
            paid = LedgerService(session).fund_account(
                account_id=result.account_id,
                amount_micro_usd=2_000_000,
                idempotency_key="customer-payment",
                correlation_id=uuid4(),
            )
            session.add(
                AccountFunding(
                    id=uuid4(),
                    funding_id=uuid4(),
                    account_id=result.account_id,
                    amount_micro_usd=2_000_000,
                    currency="USD",
                    gateway="stripe",
                    external_payment_id="pi_paid",
                    external_customer_id="cus_paid",
                    idempotency_key="paid-funding",
                    status="SUCCEEDED",
                    ledger_transaction_id=paid.transaction_id,
                    metadata_json={"funding_config_version": "stripe-funding-v1"},
                )
            )
            LedgerService(session).fund_account(
                account_id=result.account_id,
                amount_micro_usd=3_000_000,
                idempotency_key="operator-fixture-not-payment",
                correlation_id=uuid4(),
            )
        metrics = collect_beta_metrics(session)
    assert metrics.registered_accounts == 1
    assert metrics.promotional_credit_issued_micro_usd == 1_000_000
    assert metrics.customer_paid_funding_micro_usd == 2_000_000
    assert metrics.authorization_usage_micro_usd == 0


def test_concurrent_duplicate_registration_cannot_double_fund() -> None:
    with TemporaryDirectory() as directory:
        database = f"sqlite:///{directory}/beta.db"
        engine = create_engine(database, connect_args={"check_same_thread": False})
        metadata.create_all(engine)
        factory = sessionmaker(bind=engine)
        with factory() as session:
            session.add(BetaRegistrationCapacity(id=1, registrations_used=0))
            session.commit()

        def attempt() -> str:
            try:
                service_register(factory, "concurrent-key")
                return "created"
            except (BetaRegistrationCredentialAlreadyIssued, IntegrityError) as exc:
                return type(exc).__name__

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(lambda _: attempt(), range(2)))
        with factory() as session:
            assert session.scalar(select(func.count()).select_from(Account)) == 1
            assert session.scalar(select(func.count()).select_from(CreditLedgerTransaction)) == 1
            assert session.scalar(select(func.count()).select_from(BetaRegistration)) == 1
        assert outcomes.count("created") == 1
        engine.dispose()
