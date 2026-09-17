from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from outcome.audit import AuditEventType, AuditService
from outcome.db.metadata import metadata
from outcome.db.models import Account, AuditEvent, Provider
from outcome.domain import ProviderHealth
from outcome.pricing import (
    BillingMode,
    CapabilityName,
    CapabilityPricingConfig,
    InMemoryPricingConfigStore,
    PricingQuoteRejected,
    PricingRejectionReason,
    PricingService,
)
from outcome.providers import (
    CircuitState,
    ProviderAttemptOutcome,
    ProviderHealthConfig,
    ProviderHealthReason,
    ProviderHealthRequest,
    ProviderHealthService,
    provider_eligibility,
)
from tests.test_provider_rights import (
    ACCOUNT_ID,
    PROVIDER_ID,
    add_right,
    authorize,
    setup_session,
)

NOW = datetime(2026, 9, 14, 12, 0, 0, tzinfo=UTC)


class FrozenClock:
    def __init__(self, now: datetime) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: int) -> None:
        self.now += timedelta(seconds=seconds)


def health_service(
    session,
    *,
    clock: FrozenClock | None = None,
    audit: bool = False,
    failure_threshold: int = 3,
    timeout_threshold: int = 2,
) -> ProviderHealthService:
    return ProviderHealthService(
        session,
        AuditService(session) if audit else None,
        config=ProviderHealthConfig(
            failure_threshold=failure_threshold,
            timeout_threshold=timeout_threshold,
            degraded_failure_threshold=1,
            cooldown_seconds=60,
        ),
        clock=clock or FrozenClock(NOW),
    )


def record(
    service: ProviderHealthService,
    outcome: ProviderAttemptOutcome,
    *,
    latency_ms: int | None = 10,
):
    return service.record_attempt(
        account_id=ACCOUNT_ID,
        provider_id=PROVIDER_ID,
        capability=CapabilityName.VERIFY,
        outcome=outcome,
        latency_ms=latency_ms,
        correlation_id=uuid4(),
    )


def evaluate(service: ProviderHealthService):
    return service.evaluate(
        ProviderHealthRequest(
            account_id=ACCOUNT_ID,
            provider_id=PROVIDER_ID,
            capability=CapabilityName.VERIFY,
        ),
        correlation_id=uuid4(),
    )


def test_provider_attempt_outcome_values_are_stable() -> None:
    assert [value.value for value in ProviderAttemptOutcome] == [
        "SUCCESS",
        "TIMEOUT",
        "PROVIDER_FAILURE",
        "RATE_LIMITED",
        "CIRCUIT_OPEN",
        "DISABLED",
        "CANCELLED_BY_DEADLINE",
        "SYSTEM_FAILURE",
    ]
    with pytest.raises(ValueError):
        ProviderAttemptOutcome("PROVIDER_TIMEOUT")


def pricing_config() -> CapabilityPricingConfig:
    return CapabilityPricingConfig(
        capability=CapabilityName.VERIFY,
        billing_mode=BillingMode.MANAGED,
        pricing_config_version="pricing-v1",
        minimum_price_micro_usd=1,
        included_evidence_budget_micro_usd=1,
        expected_compute_cost_micro_usd=1,
        expected_managed_supplier_cost_micro_usd=1,
        target_gross_margin_bps=1000,
        maximum_retry_budget_micro_usd=0,
        maximum_total_cost_micro_usd=100,
        enabled=True,
    )


def test_successful_attempts_keep_provider_healthy() -> None:
    session = setup_session()
    service = health_service(session)

    result = record(service, ProviderAttemptOutcome.SUCCESS)

    assert result.provider_health is ProviderHealth.HEALTHY
    assert result.circuit_state is CircuitState.CLOSED
    assert result.success_count == 1


def test_configured_failure_threshold_opens_circuit() -> None:
    session = setup_session()
    service = health_service(session, failure_threshold=2)

    record(service, ProviderAttemptOutcome.PROVIDER_FAILURE)
    result = record(service, ProviderAttemptOutcome.PROVIDER_FAILURE)

    assert result.provider_health is ProviderHealth.CIRCUIT_OPEN
    assert result.circuit_state is CircuitState.OPEN
    assert result.reason_code is ProviderHealthReason.CIRCUIT_COOLDOWN_ACTIVE
    assert result.retry_after == NOW + timedelta(seconds=60)


def test_timeout_threshold_opens_circuit() -> None:
    session = setup_session()
    service = health_service(session, timeout_threshold=2)

    record(service, ProviderAttemptOutcome.TIMEOUT)
    result = record(service, ProviderAttemptOutcome.TIMEOUT)

    assert result.provider_health is ProviderHealth.CIRCUIT_OPEN
    assert result.timeout_count == 2


def test_system_failures_do_not_damage_provider_health() -> None:
    session = setup_session()
    service = health_service(session, failure_threshold=1)

    result = record(service, ProviderAttemptOutcome.SYSTEM_FAILURE)

    assert result.provider_health is ProviderHealth.HEALTHY
    assert result.failure_count == 0
    assert result.consecutive_failures == 0
    assert result.request_count == 1


def test_deadline_cancellation_does_not_count_as_provider_failure() -> None:
    session = setup_session()
    service = health_service(session, failure_threshold=1, timeout_threshold=1)

    result = record(service, ProviderAttemptOutcome.CANCELLED_BY_DEADLINE)

    assert result.provider_health is ProviderHealth.HEALTHY
    assert result.failure_count == 0
    assert result.consecutive_failures == 0
    assert result.timeout_count == 1
    assert result.request_count == 1


def test_circuit_open_provider_blocked() -> None:
    session = setup_session()
    service = health_service(session, failure_threshold=1)
    record(service, ProviderAttemptOutcome.PROVIDER_FAILURE)

    result = evaluate(service)

    assert result.usable is False
    assert result.provider_health is ProviderHealth.CIRCUIT_OPEN


def test_cooldown_does_not_prematurely_recover_provider() -> None:
    session = setup_session()
    clock = FrozenClock(NOW)
    service = health_service(session, clock=clock, failure_threshold=1)
    record(service, ProviderAttemptOutcome.PROVIDER_FAILURE)
    clock.advance(59)

    result = evaluate(service)

    assert result.provider_health is ProviderHealth.CIRCUIT_OPEN
    assert result.circuit_state is CircuitState.OPEN


def test_successful_probe_recovers_provider() -> None:
    session = setup_session()
    clock = FrozenClock(NOW)
    service = health_service(session, clock=clock, failure_threshold=1)
    record(service, ProviderAttemptOutcome.PROVIDER_FAILURE)
    clock.advance(60)

    result = record(service, ProviderAttemptOutcome.SUCCESS)

    assert result.provider_health is ProviderHealth.HEALTHY
    assert result.circuit_state is CircuitState.CLOSED


def test_failed_probe_reopens_circuit() -> None:
    session = setup_session()
    clock = FrozenClock(NOW)
    service = health_service(session, clock=clock, failure_threshold=1)
    record(service, ProviderAttemptOutcome.PROVIDER_FAILURE)
    clock.advance(60)

    result = record(service, ProviderAttemptOutcome.PROVIDER_FAILURE)

    assert result.provider_health is ProviderHealth.CIRCUIT_OPEN
    assert result.circuit_state is CircuitState.OPEN
    assert result.retry_after == NOW + timedelta(seconds=120)


def test_manual_disabled_overrides_recovery() -> None:
    session = setup_session()
    clock = FrozenClock(NOW)
    service = health_service(session, clock=clock)
    service.manual_disable(
        account_id=ACCOUNT_ID,
        provider_id=PROVIDER_ID,
        capability=CapabilityName.VERIFY,
        correlation_id=uuid4(),
    )
    clock.advance(120)

    result = record(service, ProviderAttemptOutcome.SUCCESS)

    assert result.provider_health is ProviderHealth.DISABLED
    assert result.usable is False


def test_provider_rights_remain_independent_from_health() -> None:
    session = setup_session()
    add_right(session)
    service = health_service(session, failure_threshold=1)
    health = record(service, ProviderAttemptOutcome.PROVIDER_FAILURE)
    rights = authorize(session)

    assert rights.allowed is True
    assert health.provider_health is ProviderHealth.CIRCUIT_OPEN


def test_healthy_provider_with_insufficient_rights_remains_unusable() -> None:
    session = setup_session()
    service = health_service(session)
    health = evaluate(service)
    rights = authorize(session)

    result = provider_eligibility(rights=rights, health=health)

    assert result.allowed is False
    assert result.rights_allowed is False


def test_authorized_provider_with_open_circuit_remains_unusable() -> None:
    session = setup_session()
    add_right(session)
    service = health_service(session, failure_threshold=1)
    health = record(service, ProviderAttemptOutcome.PROVIDER_FAILURE)
    rights = authorize(session)

    result = provider_eligibility(rights=rights, health=health)

    assert result.allowed is False
    assert result.rights_allowed is True
    assert result.provider_health is ProviderHealth.CIRCUIT_OPEN


def test_pricing_provider_availability_respects_health() -> None:
    session = setup_session()
    add_right(session)
    service = health_service(session, failure_threshold=1)
    record(service, ProviderAttemptOutcome.PROVIDER_FAILURE)
    pricing = PricingService(
        config_store=InMemoryPricingConfigStore((pricing_config(),)),
        provider_health_service=service,
    )

    with pytest.raises(PricingQuoteRejected) as error:
        pricing.quote(
            account_id=ACCOUNT_ID,
            capability=CapabilityName.VERIFY,
            billing_mode=BillingMode.MANAGED,
            correlation_id=uuid4(),
            provider_health_request=ProviderHealthRequest(
                account_id=ACCOUNT_ID,
                provider_id=PROVIDER_ID,
                capability=CapabilityName.VERIFY,
            ),
        )

    assert error.value.reason is PricingRejectionReason.PROVIDER_HEALTH_UNSAFE


def test_concurrent_outcome_recording_preserves_counts(tmp_path: Path) -> None:
    db_path = tmp_path / "provider-health.sqlite"
    engine = create_engine(f"sqlite:///{db_path}")
    metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    with session_factory() as session:
        session.add(Account(id=ACCOUNT_ID, display_name="Test", status="active"))
        session.add(
            Provider(
                id=PROVIDER_ID,
                account_id=ACCOUNT_ID,
                name="Provider",
                health=ProviderHealth.HEALTHY.value,
                config={},
            )
        )
        health_service(session).evaluate(
            ProviderHealthRequest(
                account_id=ACCOUNT_ID,
                provider_id=PROVIDER_ID,
                capability=CapabilityName.VERIFY,
            ),
            correlation_id=uuid4(),
        )
        session.commit()

    def worker() -> None:
        with session_factory() as session:
            health_service(session).record_attempt(
                account_id=ACCOUNT_ID,
                provider_id=PROVIDER_ID,
                capability=CapabilityName.VERIFY,
                outcome=ProviderAttemptOutcome.SUCCESS,
                correlation_id=uuid4(),
            )
            session.commit()

    with ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(lambda _: worker(), range(12)))

    with session_factory() as session:
        result = evaluate(health_service(session))

    assert result.request_count == 12
    assert result.success_count == 12
    assert result.failure_count == 0


def test_audit_contains_safe_metadata_only() -> None:
    session = setup_session()
    service = health_service(session, audit=True, failure_threshold=1)
    record(service, ProviderAttemptOutcome.PROVIDER_FAILURE)
    evaluate(service)
    session.commit()

    events = session.scalars(select(AuditEvent)).all()
    assert any(
        event.event_type == AuditEventType.PROVIDER_CIRCUIT_OPENED.value
        for event in events
    )
    payload_repr = repr([event.payload for event in events])
    assert "raw provider response" not in payload_repr
    assert "api_key" not in payload_repr
    assert "CIRCUIT_OPEN" in payload_repr


def test_deterministic_clock_and_cooldown_behavior() -> None:
    session = setup_session()
    clock = FrozenClock(NOW)
    service = health_service(session, clock=clock, failure_threshold=1)

    opened = record(service, ProviderAttemptOutcome.PROVIDER_FAILURE)
    clock.advance(60)
    ready = evaluate(service)

    assert opened.retry_after == NOW + timedelta(seconds=60)
    assert ready.circuit_state is CircuitState.HALF_OPEN
