from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from outcome.audit import AuditEventType, AuditService
from outcome.db.models import Provider, ProviderRight
from outcome.pricing.service import BillingMode, CapabilityName


class ProviderRightsStatus(StrEnum):
    AUTHORIZED = "AUTHORIZED"
    RESTRICTED = "RESTRICTED"
    EXPIRED = "EXPIRED"
    DISABLED = "DISABLED"
    UNKNOWN = "UNKNOWN"


class ProviderCredentialMode(StrEnum):
    OUTCOME_MANAGED = "OUTCOME_MANAGED"
    CUSTOMER_MANAGED = "CUSTOMER_MANAGED"


class ProviderDataUse(StrEnum):
    CLAIM_VERIFICATION = "CLAIM_VERIFICATION"
    AUTHORIZATION_CONTEXT = "AUTHORIZATION_CONTEXT"
    EVIDENCE_RETRIEVAL = "EVIDENCE_RETRIEVAL"


class ProviderExecutionMode(StrEnum):
    INLINE = "INLINE"
    ASYNC = "ASYNC"
    BATCH = "BATCH"


class ProviderRightsReason(StrEnum):
    ALLOWED = "ALLOWED"
    MISSING_RIGHTS = "MISSING_RIGHTS"
    RIGHTS_UNKNOWN = "RIGHTS_UNKNOWN"
    RIGHTS_EXPIRED = "RIGHTS_EXPIRED"
    PROVIDER_DISABLED = "PROVIDER_DISABLED"
    RIGHTS_DISABLED = "RIGHTS_DISABLED"
    UNSUPPORTED_CAPABILITY = "UNSUPPORTED_CAPABILITY"
    UNSUPPORTED_REGION = "UNSUPPORTED_REGION"
    UNSUPPORTED_BILLING_MODE = "UNSUPPORTED_BILLING_MODE"
    MANAGED_ACCESS_NOT_ALLOWED = "MANAGED_ACCESS_NOT_ALLOWED"
    CUSTOMER_CREDENTIAL_USE_NOT_ALLOWED = "CUSTOMER_CREDENTIAL_USE_NOT_ALLOWED"
    RETENTION_NOT_ALLOWED = "RETENTION_NOT_ALLOWED"
    CACHING_NOT_ALLOWED = "CACHING_NOT_ALLOWED"
    COMMERCIAL_USE_NOT_ALLOWED = "COMMERCIAL_USE_NOT_ALLOWED"
    AUTOMATED_AGENT_USE_NOT_ALLOWED = "AUTOMATED_AGENT_USE_NOT_ALLOWED"
    UNSUPPORTED_DATA_USE = "UNSUPPORTED_DATA_USE"
    UNSUPPORTED_EXECUTION_MODE = "UNSUPPORTED_EXECUTION_MODE"
    TENANT_PROVIDER_DISABLED = "TENANT_PROVIDER_DISABLED"
    TENANT_REGION_RESTRICTED = "TENANT_REGION_RESTRICTED"
    TENANT_REQUIRES_BYOK = "TENANT_REQUIRES_BYOK"


@dataclass(frozen=True)
class ProviderRightsRequest:
    account_id: UUID
    capability: CapabilityName
    billing_mode: BillingMode
    provider_id: UUID | None = None
    provider_alias: str | None = None
    requested_region: str | None = None
    requested_data_use: ProviderDataUse = ProviderDataUse.CLAIM_VERIFICATION
    requested_execution_mode: ProviderExecutionMode = ProviderExecutionMode.INLINE
    credential_mode: ProviderCredentialMode = ProviderCredentialMode.OUTCOME_MANAGED
    evidence_retention_requested: bool = False
    caching_requested: bool = False
    automated_agent: bool = True
    commercial_use: bool = True
    evaluated_at: datetime | None = None


@dataclass(frozen=True)
class ProviderRightsAuthorizationResult:
    allowed: bool
    rights_status: ProviderRightsStatus
    provider_id: UUID | None
    provider_alias: str | None
    capability: CapabilityName
    billing_mode: BillingMode
    rights_version: str | None
    reason_code: ProviderRightsReason


class ProviderRightsService:
    def __init__(self, session: Session, audit_service: AuditService | None = None) -> None:
        self.session = session
        self.audit_service = audit_service

    def authorize(
        self,
        request: ProviderRightsRequest,
        *,
        correlation_id: UUID,
    ) -> ProviderRightsAuthorizationResult:
        now = _aware_utc(request.evaluated_at)
        right = self._find_right(request=request, now=now)
        if right is None:
            result = ProviderRightsAuthorizationResult(
                allowed=False,
                rights_status=ProviderRightsStatus.UNKNOWN,
                provider_id=request.provider_id,
                provider_alias=request.provider_alias,
                capability=request.capability,
                billing_mode=request.billing_mode,
                rights_version=None,
                reason_code=ProviderRightsReason.MISSING_RIGHTS,
            )
            self._audit(result=result, account_id=request.account_id, correlation_id=correlation_id)
            return result

        result = self._evaluate(right=right, request=request, now=now)
        self._audit(result=result, account_id=request.account_id, correlation_id=correlation_id)
        return result

    def _find_right(
        self,
        *,
        request: ProviderRightsRequest,
        now: datetime,
    ) -> ProviderRight | None:
        base_statement = select(ProviderRight).where(
            ProviderRight.account_id == request.account_id,
            ProviderRight.capability == request.capability.value,
            ProviderRight.effective_at <= now,
        )
        if request.provider_id is not None:
            base_statement = base_statement.where(ProviderRight.provider_id == request.provider_id)
        elif request.provider_alias is not None:
            base_statement = base_statement.where(
                ProviderRight.provider_alias == request.provider_alias
            )
        else:
            return None
        exact_statement = base_statement.where(
            ProviderRight.billing_mode == request.billing_mode.value
        )
        exact = self.session.scalars(
            exact_statement.order_by(
                ProviderRight.effective_at.desc(),
                ProviderRight.created_at.desc(),
            )
        ).first()
        if exact is not None:
            return exact
        return self.session.scalars(
            base_statement.order_by(
                ProviderRight.effective_at.desc(),
                ProviderRight.created_at.desc(),
            )
        ).first()

    def _evaluate(
        self,
        *,
        right: ProviderRight,
        request: ProviderRightsRequest,
        now: datetime,
    ) -> ProviderRightsAuthorizationResult:
        provider = self.session.get(Provider, right.provider_id)
        reason = self._denial_reason(right=right, request=request, provider=provider, now=now)
        status = _rights_status(right)
        if reason is ProviderRightsReason.ALLOWED:
            return ProviderRightsAuthorizationResult(
                allowed=True,
                rights_status=status,
                provider_id=right.provider_id,
                provider_alias=right.provider_alias,
                capability=request.capability,
                billing_mode=request.billing_mode,
                rights_version=right.rights_version,
                reason_code=ProviderRightsReason.ALLOWED,
            )
        if reason is ProviderRightsReason.RIGHTS_EXPIRED:
            status = ProviderRightsStatus.EXPIRED
        elif reason in {
            ProviderRightsReason.PROVIDER_DISABLED,
            ProviderRightsReason.RIGHTS_DISABLED,
            ProviderRightsReason.TENANT_PROVIDER_DISABLED,
        }:
            status = ProviderRightsStatus.DISABLED
        elif status is ProviderRightsStatus.AUTHORIZED:
            status = ProviderRightsStatus.RESTRICTED
        return ProviderRightsAuthorizationResult(
            allowed=False,
            rights_status=status,
            provider_id=right.provider_id,
            provider_alias=right.provider_alias,
            capability=request.capability,
            billing_mode=request.billing_mode,
            rights_version=right.rights_version,
            reason_code=reason,
        )

    def _denial_reason(
        self,
        *,
        right: ProviderRight,
        request: ProviderRightsRequest,
        provider: Provider | None,
        now: datetime,
    ) -> ProviderRightsReason:
        status = _rights_status(right)
        if status is ProviderRightsStatus.UNKNOWN:
            return ProviderRightsReason.RIGHTS_UNKNOWN
        if status is ProviderRightsStatus.EXPIRED:
            return ProviderRightsReason.RIGHTS_EXPIRED
        if status is ProviderRightsStatus.DISABLED or not right.enabled:
            return ProviderRightsReason.RIGHTS_DISABLED
        if right.expires_at is not None and _db_timestamp_utc(right.expires_at) <= now:
            return ProviderRightsReason.RIGHTS_EXPIRED
        if provider is None:
            return ProviderRightsReason.PROVIDER_DISABLED
        if right.capability != request.capability.value:
            return ProviderRightsReason.UNSUPPORTED_CAPABILITY
        if right.billing_mode != request.billing_mode.value:
            return ProviderRightsReason.UNSUPPORTED_BILLING_MODE
        if request.requested_region not in set(right.permitted_regions):
            return ProviderRightsReason.UNSUPPORTED_REGION
        if request.requested_data_use.value not in set(right.permitted_data_use):
            return ProviderRightsReason.UNSUPPORTED_DATA_USE
        if request.requested_execution_mode.value not in set(right.permitted_execution_modes):
            return ProviderRightsReason.UNSUPPORTED_EXECUTION_MODE
        if (
            request.credential_mode is ProviderCredentialMode.OUTCOME_MANAGED
            and not right.outcome_managed_credential_allowed
        ):
            return ProviderRightsReason.MANAGED_ACCESS_NOT_ALLOWED
        if (
            request.credential_mode is ProviderCredentialMode.CUSTOMER_MANAGED
            and not right.customer_managed_credential_allowed
        ):
            return ProviderRightsReason.CUSTOMER_CREDENTIAL_USE_NOT_ALLOWED
        if request.evidence_retention_requested and not right.evidence_retention_allowed:
            return ProviderRightsReason.RETENTION_NOT_ALLOWED
        if request.caching_requested and not right.caching_allowed:
            return ProviderRightsReason.CACHING_NOT_ALLOWED
        if request.commercial_use and not right.commercial_usage_allowed:
            return ProviderRightsReason.COMMERCIAL_USE_NOT_ALLOWED
        if request.automated_agent and not right.automated_agent_usage_allowed:
            return ProviderRightsReason.AUTOMATED_AGENT_USE_NOT_ALLOWED
        return _tenant_restriction_reason(right=right, request=request)

    def _audit(
        self,
        *,
        result: ProviderRightsAuthorizationResult,
        account_id: UUID,
        correlation_id: UUID,
    ) -> None:
        if self.audit_service is None:
            return
        event_type = AuditEventType.PROVIDER_RIGHTS_EVALUATED
        if result.allowed:
            event_type = AuditEventType.PROVIDER_USE_ALLOWED
        elif result.rights_status is ProviderRightsStatus.EXPIRED:
            event_type = AuditEventType.PROVIDER_RIGHTS_EXPIRED
        elif result.rights_status is ProviderRightsStatus.UNKNOWN:
            event_type = AuditEventType.PROVIDER_RIGHTS_UNKNOWN
        else:
            event_type = AuditEventType.PROVIDER_USE_DENIED
        self.audit_service.append_event(
            account_id=account_id,
            event_type=event_type,
            correlation_id=correlation_id,
            payload={
                "provider_id": result.provider_id,
                "provider_alias": result.provider_alias,
                "capability": result.capability.value,
                "billing_mode": result.billing_mode.value,
                "rights_status": result.rights_status.value,
                "rights_version": result.rights_version,
                "reason_codes": [result.reason_code.value],
            },
        )


def _tenant_restriction_reason(
    *,
    right: ProviderRight,
    request: ProviderRightsRequest,
) -> ProviderRightsReason:
    restrictions = right.tenant_restrictions
    if restrictions.get("disabled") is True:
        return ProviderRightsReason.TENANT_PROVIDER_DISABLED
    tenant_regions = restrictions.get("permitted_regions")
    if isinstance(tenant_regions, list) and request.requested_region not in set(tenant_regions):
        return ProviderRightsReason.TENANT_REGION_RESTRICTED
    if restrictions.get("requires_byok") is True and request.billing_mode is not BillingMode.BYOK:
        return ProviderRightsReason.TENANT_REQUIRES_BYOK
    return ProviderRightsReason.ALLOWED


def _rights_status(right: ProviderRight) -> ProviderRightsStatus:
    try:
        return ProviderRightsStatus(right.rights_status)
    except ValueError:
        return ProviderRightsStatus.UNKNOWN


def _aware_utc(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(UTC)
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("provider rights timestamps must be timezone-aware")
    return value.astimezone(UTC)


def _db_timestamp_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
