from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol
from uuid import UUID

from outcome.audit import AuditEventType, AuditService
from outcome.domain import AssuranceLevel, VerificationMode

if TYPE_CHECKING:
    from outcome.providers import (
        ProviderHealthRequest,
        ProviderHealthResult,
        ProviderRightsAuthorizationResult,
        ProviderRightsRequest,
    )

BASIS_POINTS = 10_000


class BillingMode(StrEnum):
    BYOK = "BYOK"
    MANAGED = "MANAGED"


class CapabilityName(StrEnum):
    VERIFY = "verify"
    AUTHORIZE = "authorize"


class PricingRejectionReason(StrEnum):
    CAPABILITY_DISABLED = "CAPABILITY_DISABLED"
    MARGIN_TARGET_UNACHIEVABLE = "MARGIN_TARGET_UNACHIEVABLE"
    PROVIDER_HEALTH_UNSAFE = "PROVIDER_HEALTH_UNSAFE"
    SUPPLIER_RIGHTS_UNAVAILABLE = "SUPPLIER_RIGHTS_UNAVAILABLE"
    CONFIG_NOT_FOUND = "CONFIG_NOT_FOUND"


class PricingQuoteRejected(ValueError):
    def __init__(self, reason: PricingRejectionReason) -> None:
        super().__init__(reason.value)
        self.reason = reason


class ProviderRightsAuthorizer(Protocol):
    def authorize(
        self,
        request: ProviderRightsRequest,
        *,
        correlation_id: UUID,
    ) -> ProviderRightsAuthorizationResult:
        raise NotImplementedError


class ProviderHealthEvaluator(Protocol):
    def evaluate(
        self,
        request: ProviderHealthRequest,
        *,
        correlation_id: UUID,
    ) -> ProviderHealthResult:
        raise NotImplementedError


@dataclass(frozen=True)
class CapabilityPricingConfig:
    capability: CapabilityName
    billing_mode: BillingMode
    pricing_config_version: str
    minimum_price_micro_usd: int
    included_evidence_budget_micro_usd: int
    expected_compute_cost_micro_usd: int
    expected_managed_supplier_cost_micro_usd: int
    target_gross_margin_bps: int
    maximum_retry_budget_micro_usd: int
    maximum_total_cost_micro_usd: int
    enabled: bool
    operational_cost_allocation_micro_usd: int = 0
    supported_modes: tuple[VerificationMode, ...] = (VerificationMode.INLINE,)
    supported_assurance: tuple[AssuranceLevel, ...] = (AssuranceLevel.STANDARD,)
    supplier_rights_available: bool = True
    provider_health_safe: bool = True

    def __post_init__(self) -> None:
        money_fields = (
            self.minimum_price_micro_usd,
            self.included_evidence_budget_micro_usd,
            self.expected_compute_cost_micro_usd,
            self.expected_managed_supplier_cost_micro_usd,
            self.maximum_retry_budget_micro_usd,
            self.maximum_total_cost_micro_usd,
            self.operational_cost_allocation_micro_usd,
        )
        if any(not isinstance(value, int) or value < 0 for value in money_fields):
            raise ValueError("pricing money fields must be non-negative integer microdollars")
        if not 0 <= self.target_gross_margin_bps < BASIS_POINTS:
            raise ValueError("target_gross_margin_bps must be between 0 and 9999")
        if not self.pricing_config_version:
            raise ValueError("pricing_config_version is required")

    def next_version(self, *, pricing_config_version: str) -> CapabilityPricingConfig:
        if pricing_config_version == self.pricing_config_version:
            raise ValueError("new pricing config version must differ from current version")
        return CapabilityPricingConfig(
            capability=self.capability,
            billing_mode=self.billing_mode,
            pricing_config_version=pricing_config_version,
            minimum_price_micro_usd=self.minimum_price_micro_usd,
            included_evidence_budget_micro_usd=self.included_evidence_budget_micro_usd,
            expected_compute_cost_micro_usd=self.expected_compute_cost_micro_usd,
            expected_managed_supplier_cost_micro_usd=self.expected_managed_supplier_cost_micro_usd,
            target_gross_margin_bps=self.target_gross_margin_bps,
            maximum_retry_budget_micro_usd=self.maximum_retry_budget_micro_usd,
            maximum_total_cost_micro_usd=self.maximum_total_cost_micro_usd,
            enabled=self.enabled,
            operational_cost_allocation_micro_usd=self.operational_cost_allocation_micro_usd,
            supported_modes=self.supported_modes,
            supported_assurance=self.supported_assurance,
            supplier_rights_available=self.supplier_rights_available,
            provider_health_safe=self.provider_health_safe,
        )


@dataclass(frozen=True)
class PricingQuote:
    quote_id: UUID
    capability: CapabilityName
    billing_mode: BillingMode
    pricing_config_version: str
    quoted_price_micro_usd: int
    maximum_reserved_spend_micro_usd: int
    included_evidence_budget_micro_usd: int
    maximum_retry_budget_micro_usd: int
    expected_total_cost_micro_usd: int
    estimated_gross_margin_bps: int


@dataclass(frozen=True)
class PublicPricingCapability:
    capability: CapabilityName
    billing_mode: BillingMode
    minimum_price_micro_usd: int
    included_evidence_budget_micro_usd: int
    supported_modes: tuple[VerificationMode, ...]
    supported_assurance: tuple[AssuranceLevel, ...]
    enabled: bool
    pricing_config_version: str


class InMemoryPricingConfigStore:
    def __init__(self, configs: tuple[CapabilityPricingConfig, ...]) -> None:
        self._configs = {
            (config.capability, config.billing_mode): config
            for config in configs
        }

    def get(
        self,
        *,
        capability: CapabilityName,
        billing_mode: BillingMode,
    ) -> CapabilityPricingConfig | None:
        return self._configs.get((capability, billing_mode))

    def public_capabilities(self) -> tuple[PublicPricingCapability, ...]:
        return tuple(
            PublicPricingCapability(
                capability=config.capability,
                billing_mode=config.billing_mode,
                minimum_price_micro_usd=config.minimum_price_micro_usd,
                included_evidence_budget_micro_usd=config.included_evidence_budget_micro_usd,
                supported_modes=config.supported_modes,
                supported_assurance=config.supported_assurance,
                enabled=config.enabled
                and config.supplier_rights_available
                and config.provider_health_safe,
                pricing_config_version=config.pricing_config_version,
            )
            for config in sorted(
                self._configs.values(),
                key=lambda item: (item.capability.value, item.billing_mode.value),
            )
        )


class PricingService:
    def __init__(
        self,
        *,
        config_store: InMemoryPricingConfigStore,
        audit_service: AuditService | None = None,
        provider_rights_service: ProviderRightsAuthorizer | None = None,
        provider_health_service: ProviderHealthEvaluator | None = None,
    ) -> None:
        self.config_store = config_store
        self.audit_service = audit_service
        self.provider_rights_service = provider_rights_service
        self.provider_health_service = provider_health_service

    def quote(
        self,
        *,
        account_id: UUID,
        capability: CapabilityName,
        billing_mode: BillingMode,
        correlation_id: UUID,
        provider_rights_request: ProviderRightsRequest | None = None,
        provider_health_request: ProviderHealthRequest | None = None,
    ) -> PricingQuote:
        config = self.config_store.get(capability=capability, billing_mode=billing_mode)
        if config is None:
            self._audit_rejection(
                account_id=account_id,
                capability=capability,
                billing_mode=billing_mode,
                correlation_id=correlation_id,
                version=None,
                reason=PricingRejectionReason.CONFIG_NOT_FOUND,
            )
            raise PricingQuoteRejected(PricingRejectionReason.CONFIG_NOT_FOUND)

        rejection = self._configuration_rejection(config)
        if rejection is not None:
            self._audit_rejection(
                account_id=account_id,
                capability=capability,
                billing_mode=billing_mode,
                correlation_id=correlation_id,
                version=config.pricing_config_version,
                reason=rejection,
            )
            raise PricingQuoteRejected(rejection)

        if self.provider_rights_service is not None and provider_rights_request is not None:
            rights = self.provider_rights_service.authorize(
                provider_rights_request,
                correlation_id=correlation_id,
            )
            if not rights.allowed:
                self._audit_rejection(
                    account_id=account_id,
                    capability=capability,
                    billing_mode=billing_mode,
                    correlation_id=correlation_id,
                    version=config.pricing_config_version,
                    reason=PricingRejectionReason.SUPPLIER_RIGHTS_UNAVAILABLE,
                )
                raise PricingQuoteRejected(PricingRejectionReason.SUPPLIER_RIGHTS_UNAVAILABLE)

        if self.provider_health_service is not None and provider_health_request is not None:
            health = self.provider_health_service.evaluate(
                provider_health_request,
                correlation_id=correlation_id,
            )
            if not health.usable:
                self._audit_rejection(
                    account_id=account_id,
                    capability=capability,
                    billing_mode=billing_mode,
                    correlation_id=correlation_id,
                    version=config.pricing_config_version,
                    reason=PricingRejectionReason.PROVIDER_HEALTH_UNSAFE,
                )
                raise PricingQuoteRejected(PricingRejectionReason.PROVIDER_HEALTH_UNSAFE)

        expected_total_cost = expected_total_cost_micro_usd(config)
        if expected_total_cost > config.maximum_total_cost_micro_usd:
            self._audit_rejection(
                account_id=account_id,
                capability=capability,
                billing_mode=billing_mode,
                correlation_id=correlation_id,
                version=config.pricing_config_version,
                reason=PricingRejectionReason.MARGIN_TARGET_UNACHIEVABLE,
            )
            raise PricingQuoteRejected(PricingRejectionReason.MARGIN_TARGET_UNACHIEVABLE)

        margin_price = margin_protected_price_micro_usd(
            expected_total_cost_micro_usd=expected_total_cost,
            target_gross_margin_bps=config.target_gross_margin_bps,
        )
        quoted_price = max(config.minimum_price_micro_usd, margin_price)
        estimated_margin = estimated_gross_margin_bps(
            quoted_price_micro_usd=quoted_price,
            expected_total_cost_micro_usd=expected_total_cost,
        )
        if estimated_margin < config.target_gross_margin_bps:
            self._audit_rejection(
                account_id=account_id,
                capability=capability,
                billing_mode=billing_mode,
                correlation_id=correlation_id,
                version=config.pricing_config_version,
                reason=PricingRejectionReason.MARGIN_TARGET_UNACHIEVABLE,
            )
            raise PricingQuoteRejected(PricingRejectionReason.MARGIN_TARGET_UNACHIEVABLE)

        quote = PricingQuote(
            quote_id=deterministic_quote_id(config=config),
            capability=capability,
            billing_mode=billing_mode,
            pricing_config_version=config.pricing_config_version,
            quoted_price_micro_usd=quoted_price,
            maximum_reserved_spend_micro_usd=expected_total_cost,
            included_evidence_budget_micro_usd=config.included_evidence_budget_micro_usd,
            maximum_retry_budget_micro_usd=config.maximum_retry_budget_micro_usd,
            expected_total_cost_micro_usd=expected_total_cost,
            estimated_gross_margin_bps=estimated_margin,
        )
        self._audit_quote(account_id=account_id, correlation_id=correlation_id, quote=quote)
        return quote

    def public_pricing(self) -> tuple[PublicPricingCapability, ...]:
        return self.config_store.public_capabilities()

    def _configuration_rejection(
        self,
        config: CapabilityPricingConfig,
    ) -> PricingRejectionReason | None:
        if not config.enabled:
            return PricingRejectionReason.CAPABILITY_DISABLED
        if not config.supplier_rights_available:
            return PricingRejectionReason.SUPPLIER_RIGHTS_UNAVAILABLE
        if not config.provider_health_safe:
            return PricingRejectionReason.PROVIDER_HEALTH_UNSAFE
        return None

    def _audit_quote(self, *, account_id: UUID, correlation_id: UUID, quote: PricingQuote) -> None:
        if self.audit_service is None:
            return
        self.audit_service.append_event(
            account_id=account_id,
            event_type=AuditEventType.PRICING_QUOTE_GENERATED,
            correlation_id=correlation_id,
            payload={
                "capability": quote.capability.value,
                "billing_mode": quote.billing_mode.value,
                "pricing_config_version": quote.pricing_config_version,
                "quoted_price_micro_usd": quote.quoted_price_micro_usd,
                "maximum_reserved_micro_usd": quote.maximum_reserved_spend_micro_usd,
                "reason_codes": ["PRICING_QUOTE_GENERATED"],
            },
        )

    def _audit_rejection(
        self,
        *,
        account_id: UUID,
        capability: CapabilityName,
        billing_mode: BillingMode,
        correlation_id: UUID,
        version: str | None,
        reason: PricingRejectionReason,
    ) -> None:
        if self.audit_service is None:
            return
        event_type = (
            AuditEventType.CAPABILITY_UNAVAILABLE
            if reason
            in {
                PricingRejectionReason.CAPABILITY_DISABLED,
                PricingRejectionReason.PROVIDER_HEALTH_UNSAFE,
                PricingRejectionReason.SUPPLIER_RIGHTS_UNAVAILABLE,
            }
            else AuditEventType.PRICING_QUOTE_REJECTED
        )
        payload: dict[str, object] = {
            "capability": capability.value,
            "billing_mode": billing_mode.value,
            "reason_codes": [reason.value],
        }
        if version is not None:
            payload["pricing_config_version"] = version
        self.audit_service.append_event(
            account_id=account_id,
            event_type=event_type,
            correlation_id=correlation_id,
            payload=payload,
        )


def expected_total_cost_micro_usd(config: CapabilityPricingConfig) -> int:
    supplier_cost = (
        config.expected_managed_supplier_cost_micro_usd
        if config.billing_mode is BillingMode.MANAGED
        else 0
    )
    return (
        config.expected_compute_cost_micro_usd
        + supplier_cost
        + config.maximum_retry_budget_micro_usd
        + config.operational_cost_allocation_micro_usd
    )


def margin_protected_price_micro_usd(
    *,
    expected_total_cost_micro_usd: int,
    target_gross_margin_bps: int,
) -> int:
    denominator = BASIS_POINTS - target_gross_margin_bps
    if denominator <= 0:
        raise PricingQuoteRejected(PricingRejectionReason.MARGIN_TARGET_UNACHIEVABLE)
    return ceil_div(expected_total_cost_micro_usd * BASIS_POINTS, denominator)


def estimated_gross_margin_bps(
    *,
    quoted_price_micro_usd: int,
    expected_total_cost_micro_usd: int,
) -> int:
    if quoted_price_micro_usd <= 0:
        raise PricingQuoteRejected(PricingRejectionReason.MARGIN_TARGET_UNACHIEVABLE)
    gross_profit = quoted_price_micro_usd - expected_total_cost_micro_usd
    return (gross_profit * BASIS_POINTS) // quoted_price_micro_usd


def deterministic_quote_id(*, config: CapabilityPricingConfig) -> UUID:
    source = "|".join(
        (
            config.capability.value,
            config.billing_mode.value,
            config.pricing_config_version,
            str(config.minimum_price_micro_usd),
            str(config.included_evidence_budget_micro_usd),
            str(config.expected_compute_cost_micro_usd),
            str(config.expected_managed_supplier_cost_micro_usd),
            str(config.target_gross_margin_bps),
            str(config.maximum_retry_budget_micro_usd),
            str(config.maximum_total_cost_micro_usd),
            str(config.operational_cost_allocation_micro_usd),
            str(config.enabled),
            str(config.supplier_rights_available),
            str(config.provider_health_safe),
        )
    )
    return uuid4_from_sha256(source)


def uuid4_from_sha256(source: str) -> UUID:
    import hashlib

    digest = bytearray(hashlib.sha256(source.encode("utf-8")).digest()[:16])
    digest[6] = (digest[6] & 0x0F) | 0x40
    digest[8] = (digest[8] & 0x3F) | 0x80
    return UUID(bytes=bytes(digest))


def ceil_div(numerator: int, denominator: int) -> int:
    return -(-numerator // denominator)
