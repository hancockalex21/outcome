from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from outcome.audit import AuditService
from outcome.db.models import Account, AuditEvent, Provider, ProviderRight
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
    ProviderCredentialMode,
    ProviderDataUse,
    ProviderExecutionMode,
    ProviderRightsReason,
    ProviderRightsRequest,
    ProviderRightsService,
    ProviderRightsStatus,
)
from tests.test_api_keys import build_session

ACCOUNT_ID = UUID("11111111-1111-4111-8111-111111111111")
OTHER_ACCOUNT_ID = UUID("22222222-2222-4222-8222-222222222222")
PROVIDER_ID = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
NOW = datetime(2026, 9, 14, 12, 0, 0, tzinfo=UTC)


def setup_session(*, provider_health: ProviderHealth = ProviderHealth.HEALTHY) -> Session:
    session = build_session()
    account = session.scalar(select(Account))
    assert account is not None
    account.id = ACCOUNT_ID
    session.add(
        Provider(
            id=PROVIDER_ID,
            account_id=ACCOUNT_ID,
            name="Search Provider",
            health=provider_health.value,
            config={},
        )
    )
    session.commit()
    return session


def add_right(
    session: Session,
    *,
    account_id: UUID = ACCOUNT_ID,
    provider_id: UUID = PROVIDER_ID,
    provider_alias: str = "search-provider",
    capability: CapabilityName = CapabilityName.VERIFY,
    billing_mode: BillingMode = BillingMode.MANAGED,
    enabled: bool = True,
    rights_status: ProviderRightsStatus = ProviderRightsStatus.AUTHORIZED,
    permitted_regions: list[str] | None = None,
    permitted_data_use: list[str] | None = None,
    permitted_execution_modes: list[str] | None = None,
    customer_secret_required: bool = False,
    outcome_managed_credential_allowed: bool = True,
    customer_managed_credential_allowed: bool = True,
    evidence_retention_allowed: bool = True,
    caching_allowed: bool = True,
    commercial_usage_allowed: bool = True,
    automated_agent_usage_allowed: bool = True,
    rights_version: str = "rights-v1",
    effective_at: datetime = NOW - timedelta(days=1),
    expires_at: datetime | None = NOW + timedelta(days=1),
    reason_code: str = "RIGHTS_ACTIVE",
    tenant_restrictions: dict[str, object] | None = None,
) -> ProviderRight:
    right = ProviderRight(
        id=uuid4(),
        account_id=account_id,
        provider_id=provider_id,
        right_name=f"{provider_alias}:{capability.value}:{billing_mode.value}:{rights_version}",
        provider_alias=provider_alias,
        capability=capability.value,
        billing_mode=billing_mode.value,
        enabled=enabled,
        rights_status=rights_status.value,
        permitted_regions=permitted_regions or ["US", "CA"],
        permitted_data_use=permitted_data_use or [ProviderDataUse.CLAIM_VERIFICATION.value],
        permitted_execution_modes=permitted_execution_modes or [ProviderExecutionMode.INLINE.value],
        customer_secret_required=customer_secret_required,
        outcome_managed_credential_allowed=outcome_managed_credential_allowed,
        customer_managed_credential_allowed=customer_managed_credential_allowed,
        evidence_retention_allowed=evidence_retention_allowed,
        caching_allowed=caching_allowed,
        commercial_usage_allowed=commercial_usage_allowed,
        automated_agent_usage_allowed=automated_agent_usage_allowed,
        rights_version=rights_version,
        effective_at=effective_at,
        expires_at=expires_at,
        reason_code=reason_code,
        tenant_restrictions=tenant_restrictions or {},
        constraints={},
    )
    session.add(right)
    session.commit()
    return right


def rights_request(
    *,
    account_id: UUID = ACCOUNT_ID,
    provider_id: UUID = PROVIDER_ID,
    capability: CapabilityName = CapabilityName.VERIFY,
    billing_mode: BillingMode = BillingMode.MANAGED,
    requested_region: str = "US",
    credential_mode: ProviderCredentialMode = ProviderCredentialMode.OUTCOME_MANAGED,
    evidence_retention_requested: bool = False,
    caching_requested: bool = False,
) -> ProviderRightsRequest:
    return ProviderRightsRequest(
        account_id=account_id,
        provider_id=provider_id,
        provider_alias="search-provider",
        capability=capability,
        billing_mode=billing_mode,
        requested_region=requested_region,
        requested_data_use=ProviderDataUse.CLAIM_VERIFICATION,
        requested_execution_mode=ProviderExecutionMode.INLINE,
        credential_mode=credential_mode,
        evidence_retention_requested=evidence_retention_requested,
        caching_requested=caching_requested,
        automated_agent=True,
        commercial_use=True,
        evaluated_at=NOW,
    )


def authorize(session: Session, request: ProviderRightsRequest | None = None) -> object:
    return ProviderRightsService(session).authorize(
        request or rights_request(),
        correlation_id=uuid4(),
    )


def test_explicitly_authorized_provider_allowed() -> None:
    session = setup_session()
    add_right(session)

    result = authorize(session)

    assert result.allowed is True
    assert result.rights_status is ProviderRightsStatus.AUTHORIZED
    assert result.reason_code is ProviderRightsReason.ALLOWED


def test_missing_rights_denied() -> None:
    session = setup_session()

    result = authorize(session)

    assert result.allowed is False
    assert result.rights_status is ProviderRightsStatus.UNKNOWN
    assert result.reason_code is ProviderRightsReason.MISSING_RIGHTS


def test_unknown_status_denied() -> None:
    session = setup_session()
    add_right(session, rights_status=ProviderRightsStatus.UNKNOWN)

    result = authorize(session)

    assert result.allowed is False
    assert result.reason_code is ProviderRightsReason.RIGHTS_UNKNOWN


def test_expired_rights_denied() -> None:
    session = setup_session()
    add_right(session, expires_at=NOW - timedelta(seconds=1))

    result = authorize(session)

    assert result.allowed is False
    assert result.rights_status is ProviderRightsStatus.EXPIRED


def test_disabled_rights_denied() -> None:
    session = setup_session()
    add_right(session, enabled=False)

    result = authorize(session)

    assert result.allowed is False
    assert result.rights_status is ProviderRightsStatus.DISABLED


def test_unsupported_capability_denied() -> None:
    session = setup_session()
    add_right(session, capability=CapabilityName.AUTHORIZE)

    result = authorize(session)

    assert result.allowed is False
    assert result.reason_code is ProviderRightsReason.MISSING_RIGHTS


def test_unsupported_region_denied() -> None:
    session = setup_session()
    add_right(session, permitted_regions=["CA"])

    result = authorize(session)

    assert result.allowed is False
    assert result.reason_code is ProviderRightsReason.UNSUPPORTED_REGION


def test_managed_denied_when_only_byok_allowed() -> None:
    session = setup_session()
    add_right(session, billing_mode=BillingMode.BYOK)

    result = authorize(session)

    assert result.allowed is False
    assert result.reason_code is ProviderRightsReason.UNSUPPORTED_BILLING_MODE


def test_byok_denied_when_customer_credentials_not_allowed() -> None:
    session = setup_session()
    add_right(
        session,
        billing_mode=BillingMode.BYOK,
        customer_managed_credential_allowed=False,
        outcome_managed_credential_allowed=False,
    )

    result = authorize(
        session,
        rights_request(
            billing_mode=BillingMode.BYOK,
            credential_mode=ProviderCredentialMode.CUSTOMER_MANAGED,
        ),
    )

    assert result.allowed is False
    assert result.reason_code is ProviderRightsReason.CUSTOMER_CREDENTIAL_USE_NOT_ALLOWED


def test_managed_credential_denied_when_managed_access_not_allowed() -> None:
    session = setup_session()
    add_right(session, outcome_managed_credential_allowed=False)

    result = authorize(session)

    assert result.allowed is False
    assert result.reason_code is ProviderRightsReason.MANAGED_ACCESS_NOT_ALLOWED


def test_retention_and_caching_request_denied_when_prohibited() -> None:
    session = setup_session()
    add_right(session, evidence_retention_allowed=False, caching_allowed=False)

    retention = authorize(session, rights_request(evidence_retention_requested=True))
    caching = authorize(session, rights_request(caching_requested=True))

    assert retention.reason_code is ProviderRightsReason.RETENTION_NOT_ALLOWED
    assert caching.reason_code is ProviderRightsReason.CACHING_NOT_ALLOWED


def test_automated_agent_usage_denied_where_not_permitted() -> None:
    session = setup_session()
    add_right(session, automated_agent_usage_allowed=False)

    result = authorize(session)

    assert result.allowed is False
    assert result.reason_code is ProviderRightsReason.AUTOMATED_AGENT_USE_NOT_ALLOWED


def test_tenant_restriction_can_narrow_provider_rights() -> None:
    session = setup_session()
    add_right(
        session,
        permitted_regions=["US", "CA"],
        tenant_restrictions={"permitted_regions": ["US"]},
    )

    result = authorize(session, rights_request(requested_region="CA"))

    assert result.allowed is False
    assert result.reason_code is ProviderRightsReason.TENANT_REGION_RESTRICTED


def test_tenant_restriction_cannot_broaden_provider_rights() -> None:
    session = setup_session()
    add_right(
        session,
        permitted_regions=["US"],
        tenant_restrictions={"permitted_regions": ["US", "CA"]},
    )

    result = authorize(session, rights_request(requested_region="CA"))

    assert result.allowed is False
    assert result.reason_code is ProviderRightsReason.UNSUPPORTED_REGION


def test_rights_version_returned() -> None:
    session = setup_session()
    add_right(session, rights_version="contract-2026-09")

    result = authorize(session)

    assert result.rights_version == "contract-2026-09"


def test_pricing_availability_respects_provider_rights() -> None:
    session = setup_session()
    add_right(session, rights_status=ProviderRightsStatus.UNKNOWN)
    service = PricingService(
        config_store=InMemoryPricingConfigStore(
            (
                CapabilityPricingConfig(
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
                ),
            )
        ),
        provider_rights_service=ProviderRightsService(session),
    )

    with pytest.raises(PricingQuoteRejected) as error:
        service.quote(
            account_id=ACCOUNT_ID,
            capability=CapabilityName.VERIFY,
            billing_mode=BillingMode.MANAGED,
            correlation_id=uuid4(),
            provider_rights_request=rights_request(),
        )

    assert error.value.reason is PricingRejectionReason.SUPPLIER_RIGHTS_UNAVAILABLE


def test_provider_health_remains_separate_from_rights() -> None:
    session = setup_session(provider_health=ProviderHealth.CIRCUIT_OPEN)
    add_right(session)

    result = authorize(session)

    assert result.allowed is True
    assert session.get(Provider, PROVIDER_ID).health == ProviderHealth.CIRCUIT_OPEN.value


def test_audit_contains_safe_metadata_only() -> None:
    session = setup_session()
    add_right(session)
    correlation_id = uuid4()

    ProviderRightsService(session, AuditService(session)).authorize(
        rights_request(),
        correlation_id=correlation_id,
    )
    session.commit()

    events = session.scalars(select(AuditEvent)).all()
    assert events
    for event in events:
        payload_repr = repr(event.payload)
        assert "contract text" not in payload_repr
        assert "api_key" not in payload_repr
        assert "supplier pricing" not in payload_repr
        assert "rights-v1" in payload_repr


def test_cross_tenant_behavior_fails_closed() -> None:
    session = setup_session()
    add_right(session)

    result = authorize(session, rights_request(account_id=OTHER_ACCOUNT_ID))

    assert result.allowed is False
    assert result.reason_code is ProviderRightsReason.MISSING_RIGHTS
