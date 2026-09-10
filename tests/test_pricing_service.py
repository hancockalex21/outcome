from __future__ import annotations

import ast
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import select

from outcome.audit import AuditEventType, AuditService
from outcome.db.models import Account
from outcome.pricing import (
    BillingMode,
    CapabilityName,
    CapabilityPricingConfig,
    InMemoryPricingConfigStore,
    PricingQuoteRejected,
    PricingRejectionReason,
    PricingService,
)
from tests.test_api_keys import build_session


def config(
    *,
    billing_mode: BillingMode = BillingMode.MANAGED,
    minimum_price_micro_usd: int = 1,
    expected_compute_cost_micro_usd: int = 1_000_000,
    expected_managed_supplier_cost_micro_usd: int = 2_000_000,
    target_gross_margin_bps: int = 2500,
    maximum_retry_budget_micro_usd: int = 500_000,
    maximum_total_cost_micro_usd: int = 10_000_000,
    enabled: bool = True,
) -> CapabilityPricingConfig:
    return CapabilityPricingConfig(
        capability=CapabilityName.VERIFY,
        billing_mode=billing_mode,
        pricing_config_version="pricing-v1",
        minimum_price_micro_usd=minimum_price_micro_usd,
        included_evidence_budget_micro_usd=750_000,
        expected_compute_cost_micro_usd=expected_compute_cost_micro_usd,
        expected_managed_supplier_cost_micro_usd=expected_managed_supplier_cost_micro_usd,
        target_gross_margin_bps=target_gross_margin_bps,
        maximum_retry_budget_micro_usd=maximum_retry_budget_micro_usd,
        maximum_total_cost_micro_usd=maximum_total_cost_micro_usd,
        enabled=enabled,
    )


def pricing_service(
    pricing_config: CapabilityPricingConfig,
    audit_service: AuditService | None = None,
) -> PricingService:
    return PricingService(
        config_store=InMemoryPricingConfigStore((pricing_config,)),
        audit_service=audit_service,
    )


def account_id() -> object:
    session = build_session()
    return session.scalar(select(Account.id))


def test_managed_quote_meets_configured_gross_margin_floor() -> None:
    quote = pricing_service(config()).quote(
        account_id=uuid4(),
        capability=CapabilityName.VERIFY,
        billing_mode=BillingMode.MANAGED,
        correlation_id=uuid4(),
    )

    assert quote.expected_total_cost_micro_usd == 3_500_000
    assert quote.quoted_price_micro_usd == 4_666_667
    assert quote.estimated_gross_margin_bps >= 2500


def test_byok_quote_excludes_supplier_cogs_but_includes_outcome_compute() -> None:
    quote = pricing_service(config(billing_mode=BillingMode.BYOK)).quote(
        account_id=uuid4(),
        capability=CapabilityName.VERIFY,
        billing_mode=BillingMode.BYOK,
        correlation_id=uuid4(),
    )

    assert quote.expected_total_cost_micro_usd == 1_500_000
    assert quote.quoted_price_micro_usd == 2_000_000
    assert quote.estimated_gross_margin_bps == 2500


def test_minimum_price_overrides_lower_calculated_price() -> None:
    quote = pricing_service(
        config(
            minimum_price_micro_usd=5_000_000,
            expected_compute_cost_micro_usd=100_000,
            expected_managed_supplier_cost_micro_usd=100_000,
            maximum_retry_budget_micro_usd=0,
        )
    ).quote(
        account_id=uuid4(),
        capability=CapabilityName.VERIFY,
        billing_mode=BillingMode.MANAGED,
        correlation_id=uuid4(),
    )

    assert quote.quoted_price_micro_usd == 5_000_000
    assert quote.estimated_gross_margin_bps > 2500


def test_retry_reserve_affects_required_price() -> None:
    no_retry = pricing_service(config(maximum_retry_budget_micro_usd=0)).quote(
        account_id=uuid4(),
        capability=CapabilityName.VERIFY,
        billing_mode=BillingMode.MANAGED,
        correlation_id=uuid4(),
    )
    with_retry = pricing_service(config(maximum_retry_budget_micro_usd=1_000_000)).quote(
        account_id=uuid4(),
        capability=CapabilityName.VERIFY,
        billing_mode=BillingMode.MANAGED,
        correlation_id=uuid4(),
    )

    assert with_retry.expected_total_cost_micro_usd > no_retry.expected_total_cost_micro_usd
    assert with_retry.quoted_price_micro_usd > no_retry.quoted_price_micro_usd


def test_impossible_or_unsafe_margin_rejects_quote() -> None:
    service = pricing_service(config(maximum_total_cost_micro_usd=1_000_000))

    with pytest.raises(PricingQuoteRejected) as error:
        service.quote(
            account_id=uuid4(),
            capability=CapabilityName.VERIFY,
            billing_mode=BillingMode.MANAGED,
            correlation_id=uuid4(),
        )

    assert error.value.reason is PricingRejectionReason.MARGIN_TARGET_UNACHIEVABLE


def test_disabled_capability_rejects_quote() -> None:
    service = pricing_service(config(enabled=False))

    with pytest.raises(PricingQuoteRejected) as error:
        service.quote(
            account_id=uuid4(),
            capability=CapabilityName.VERIFY,
            billing_mode=BillingMode.MANAGED,
            correlation_id=uuid4(),
        )

    assert error.value.reason is PricingRejectionReason.CAPABILITY_DISABLED


def test_deterministic_same_input_quote() -> None:
    service = pricing_service(config())

    first = service.quote(
        account_id=uuid4(),
        capability=CapabilityName.VERIFY,
        billing_mode=BillingMode.MANAGED,
        correlation_id=uuid4(),
    )
    second = service.quote(
        account_id=uuid4(),
        capability=CapabilityName.VERIFY,
        billing_mode=BillingMode.MANAGED,
        correlation_id=uuid4(),
    )

    assert first == second


def test_exact_integer_arithmetic_rounds_up() -> None:
    quote = pricing_service(
        config(
            expected_compute_cost_micro_usd=1,
            expected_managed_supplier_cost_micro_usd=0,
            maximum_retry_budget_micro_usd=0,
            target_gross_margin_bps=3333,
        )
    ).quote(
        account_id=uuid4(),
        capability=CapabilityName.VERIFY,
        billing_mode=BillingMode.MANAGED,
        correlation_id=uuid4(),
    )

    assert quote.quoted_price_micro_usd == 2


def test_no_floats_used_for_money() -> None:
    tree = ast.parse(Path("src/outcome/pricing/service.py").read_text())

    assert not any(
        isinstance(node, ast.Constant) and isinstance(node.value, float)
        for node in ast.walk(tree)
    )


def test_public_pricing_response_hides_internal_supplier_costs_and_margin() -> None:
    public = pricing_service(config()).public_pricing()[0]
    public_fields = public.__dict__

    assert public_fields["capability"] is CapabilityName.VERIFY
    assert public_fields["billing_mode"] is BillingMode.MANAGED
    assert public_fields["minimum_price_micro_usd"] == 1
    assert "expected_managed_supplier_cost_micro_usd" not in public_fields
    assert "expected_compute_cost_micro_usd" not in public_fields
    assert "target_gross_margin_bps" not in public_fields
    assert "maximum_total_cost_micro_usd" not in public_fields


def test_config_version_included_in_quote_and_audit_metadata() -> None:
    session = build_session()
    account = session.scalar(select(Account.id))
    assert account is not None
    correlation_id = uuid4()

    quote = pricing_service(config(), AuditService(session)).quote(
        account_id=account,
        capability=CapabilityName.VERIFY,
        billing_mode=BillingMode.MANAGED,
        correlation_id=correlation_id,
    )
    session.commit()

    events = AuditService(session).timeline_for_correlation(
        account_id=account,
        correlation_id=correlation_id,
    )

    assert quote.pricing_config_version == "pricing-v1"
    assert events[0].event_type is AuditEventType.PRICING_QUOTE_GENERATED
    assert events[0].payload["pricing_config_version"] == "pricing-v1"
    assert "expected_managed_supplier_cost_micro_usd" not in events[0].payload
    assert "target_gross_margin_bps" not in events[0].payload
