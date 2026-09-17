from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import cast
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from outcome.actions import canonical_material_json
from outcome.audit import AuditEventType, AuditService
from outcome.db.models import AuthorizationBilling
from outcome.domain import PolicyDecision
from outcome.ledger import IdempotencyConflict, LedgerService
from outcome.pricing import BillingMode, CapabilityName, PricingQuote, PricingService
from outcome.reservations import (
    ReservationConflict,
    ReservationInsufficientFunds,
    ReservationService,
    ReservationState,
    ReservationUnavailable,
)

BILLING_VERSION = "authorization-billing-v1"
DEFAULT_RESERVATION_TTL_SECONDS = 900
DEFAULT_MAXIMUM_BILLABLE_EXECUTION_WINDOW_SECONDS = 300
DEFAULT_RESERVATION_TTL_SAFETY_MARGIN_SECONDS = 60
DEFAULT_MAX_RESERVATION_TTL_SECONDS = 3600


class BillingLifecycleState(StrEnum):
    QUOTED = "QUOTED"
    RESERVED = "RESERVED"
    IN_PROGRESS = "IN_PROGRESS"
    SETTLED = "SETTLED"
    RELEASED = "RELEASED"
    FAILED = "FAILED"
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"


class BillingReasonCode(StrEnum):
    BILLING_QUOTED = "BILLING_QUOTED"
    BILLING_RESERVED = "BILLING_RESERVED"
    BILLING_IN_PROGRESS = "BILLING_IN_PROGRESS"
    BILLING_SETTLED = "BILLING_SETTLED"
    BILLING_RELEASED = "BILLING_RELEASED"
    INSUFFICIENT_FUNDS = "INSUFFICIENT_FUNDS"
    REDIS_UNAVAILABLE = "REDIS_UNAVAILABLE"
    RESERVATION_STATE_AMBIGUOUS = "RESERVATION_STATE_AMBIGUOUS"
    RESERVATION_RELEASE_FAILED = "RESERVATION_RELEASE_FAILED"
    SETTLEMENT_STATE_AMBIGUOUS = "SETTLEMENT_STATE_AMBIGUOUS"
    CHARGE_EXCEEDS_RESERVE = "CHARGE_EXCEEDS_RESERVE"
    LEDGER_SETTLEMENT_FAILED = "LEDGER_SETTLEMENT_FAILED"
    PRICING_INVARIANT_VIOLATION = "PRICING_INVARIANT_VIOLATION"
    RESERVATION_TTL_UNSAFE = "RESERVATION_TTL_UNSAFE"
    SYSTEM_FAILURE_ZERO_CHARGE = "SYSTEM_FAILURE_ZERO_CHARGE"
    ZERO_CHARGE = "ZERO_CHARGE"


class BillingError(RuntimeError):
    def __init__(self, reason: BillingReasonCode) -> None:
        super().__init__(reason.value)
        self.reason = reason


class CrossTenantBillingAccess(PermissionError):
    pass


@dataclass(frozen=True)
class BillingQuote:
    quote_id: UUID
    pricing_version: str
    capability: CapabilityName
    execution_mode: BillingMode
    quoted_price_micro_usd: int
    max_reserved_spend_micro_usd: int
    expected_total_cost_micro_usd: int
    currency: str
    quote_fingerprint: str


@dataclass(frozen=True)
class BillingResult:
    billing_id: UUID
    account_id: UUID
    authorization_request_id: UUID
    state: BillingLifecycleState
    quote: BillingQuote
    reservation_id: UUID | None
    actual_charge_micro_usd: int | None
    settlement_ledger_transaction_id: UUID | None
    reason_code: BillingReasonCode


class AuthorizationBillingService:
    def __init__(
        self,
        session: Session,
        *,
        pricing_service: PricingService,
        reservation_service: ReservationService,
        ledger_service: LedgerService,
        audit_service: AuditService | None = None,
        clock: Callable[[], datetime] | None = None,
        reservation_ttl: timedelta = timedelta(seconds=DEFAULT_RESERVATION_TTL_SECONDS),
        maximum_billable_execution_window: timedelta = timedelta(
            seconds=DEFAULT_MAXIMUM_BILLABLE_EXECUTION_WINDOW_SECONDS,
        ),
        reservation_ttl_safety_margin: timedelta = timedelta(
            seconds=DEFAULT_RESERVATION_TTL_SAFETY_MARGIN_SECONDS,
        ),
        max_reservation_ttl: timedelta = timedelta(seconds=DEFAULT_MAX_RESERVATION_TTL_SECONDS),
    ) -> None:
        self.session = session
        self.pricing_service = pricing_service
        self.reservation_service = reservation_service
        self.ledger_service = ledger_service
        self.audit_service = audit_service or AuditService(session)
        self.clock = clock or (lambda: datetime.now(UTC))
        self.reservation_ttl = reservation_ttl
        self.maximum_billable_execution_window = maximum_billable_execution_window
        self.reservation_ttl_safety_margin = reservation_ttl_safety_margin
        self.max_reservation_ttl = max_reservation_ttl
        self._validate_ttl_configuration()

    def quote(
        self,
        *,
        account_id: UUID,
        authorization_request_id: UUID,
        capability: CapabilityName,
        execution_mode: BillingMode,
        material: Mapping[str, object],
        correlation_id: UUID,
    ) -> BillingQuote:
        pricing_quote = self.pricing_service.quote(
            account_id=account_id,
            capability=capability,
            billing_mode=execution_mode,
            correlation_id=correlation_id,
        )
        if pricing_quote.quoted_price_micro_usd < 0:
            raise BillingError(BillingReasonCode.PRICING_INVARIANT_VIOLATION)
        if pricing_quote.quoted_price_micro_usd > pricing_quote.maximum_reserved_spend_micro_usd:
            raise BillingError(BillingReasonCode.PRICING_INVARIANT_VIOLATION)
        quote = BillingQuote(
            quote_id=pricing_quote.quote_id,
            pricing_version=pricing_quote.pricing_config_version,
            capability=capability,
            execution_mode=execution_mode,
            quoted_price_micro_usd=pricing_quote.quoted_price_micro_usd,
            max_reserved_spend_micro_usd=pricing_quote.maximum_reserved_spend_micro_usd,
            expected_total_cost_micro_usd=pricing_quote.expected_total_cost_micro_usd,
            currency="USD",
            quote_fingerprint=quote_fingerprint(
                account_id=account_id,
                authorization_request_id=authorization_request_id,
                quote=pricing_quote,
                max_reserved_spend_micro_usd=pricing_quote.maximum_reserved_spend_micro_usd,
                material=material,
            ),
        )
        return quote

    def create_or_reserve(
        self,
        *,
        account_id: UUID,
        authorization_request_id: UUID,
        quote: BillingQuote,
        correlation_id: UUID,
    ) -> BillingResult:
        row = self._get_for_authorization(
            account_id=account_id,
            authorization_request_id=authorization_request_id,
        )
        if row is None:
            row = AuthorizationBilling(
                id=uuid4(),
                billing_id=uuid4(),
                account_id=account_id,
                authorization_request_id=authorization_request_id,
                pricing_version=quote.pricing_version,
                quote_fingerprint=quote.quote_fingerprint,
                max_reserved_spend_micro_usd=quote.max_reserved_spend_micro_usd,
                billing_state=BillingLifecycleState.QUOTED.value,
                execution_mode=quote.execution_mode.value,
                billing_metadata=_quote_metadata(quote),
            )
            self.session.add(row)
            try:
                self.session.flush()
            except IntegrityError:
                self.session.rollback()
                row = self._get_for_authorization(
                    account_id=account_id,
                    authorization_request_id=authorization_request_id,
                )
                if row is None:
                    raise
            self._audit(row, AuditEventType.BILLING_QUOTED, correlation_id)
        self._assert_quote_match(row, quote)
        if row.reservation_id is not None:
            return self._result(row, quote, BillingReasonCode.BILLING_RESERVED)
        try:
            reservation = self.reservation_service.reserve(
                account_id=account_id,
                request_id=authorization_request_id,
                amount_micro_usd=quote.max_reserved_spend_micro_usd,
                ttl_seconds=int(self.reservation_ttl.total_seconds()),
            )
        except ReservationInsufficientFunds as exc:
            row.billing_state = BillingLifecycleState.FAILED.value
            row.reason_code = BillingReasonCode.INSUFFICIENT_FUNDS.value
            self.session.flush()
            self._audit(row, AuditEventType.BILLING_RESERVATION_FAILED, correlation_id)
            raise BillingError(BillingReasonCode.INSUFFICIENT_FUNDS) from exc
        except ReservationUnavailable as exc:
            row.billing_state = BillingLifecycleState.FAILED.value
            row.reason_code = BillingReasonCode.REDIS_UNAVAILABLE.value
            self.session.flush()
            self._audit(row, AuditEventType.BILLING_RESERVATION_FAILED, correlation_id)
            raise BillingError(BillingReasonCode.REDIS_UNAVAILABLE) from exc
        except ReservationConflict as exc:
            row.billing_state = BillingLifecycleState.RECONCILIATION_REQUIRED.value
            row.reason_code = BillingReasonCode.RESERVATION_STATE_AMBIGUOUS.value
            self.session.flush()
            self._audit(row, AuditEventType.BILLING_RECONCILIATION_REQUIRED, correlation_id)
            raise BillingError(BillingReasonCode.RESERVATION_STATE_AMBIGUOUS) from exc
        row.reservation_id = reservation.reservation_id
        row.reservation_state = reservation.state.value
        row.billing_state = BillingLifecycleState.RESERVED.value
        row.reserved_at = self.clock()
        row.reason_code = BillingReasonCode.BILLING_RESERVED.value
        self.session.flush()
        self._audit(row, AuditEventType.BILLING_RESERVED, correlation_id)
        return self._result(row, quote, BillingReasonCode.BILLING_RESERVED)

    def mark_in_progress(
        self,
        *,
        account_id: UUID,
        authorization_request_id: UUID,
        correlation_id: UUID,
    ) -> None:
        row = self._require_for_authorization(account_id, authorization_request_id)
        row.billing_state = BillingLifecycleState.IN_PROGRESS.value
        row.reason_code = BillingReasonCode.BILLING_IN_PROGRESS.value
        self.session.flush()
        self._audit(row, AuditEventType.BILLING_IN_PROGRESS, correlation_id)

    def settle(
        self,
        *,
        account_id: UUID,
        authorization_request_id: UUID,
        quote: BillingQuote,
        decision: PolicyDecision,
        system_failure: bool,
        billable_work_occurred: bool = True,
        correlation_id: UUID,
    ) -> BillingResult:
        row = self._require_for_authorization(account_id, authorization_request_id)
        self._assert_quote_match(row, quote)
        if row.billing_state in {
            BillingLifecycleState.SETTLED.value,
            BillingLifecycleState.RELEASED.value,
        }:
            return self._result(row, quote, BillingReasonCode.BILLING_SETTLED)
        if row.reservation_id is None:
            row.billing_state = BillingLifecycleState.RECONCILIATION_REQUIRED.value
            row.reason_code = BillingReasonCode.RESERVATION_STATE_AMBIGUOUS.value
            self.session.flush()
            self._audit(row, AuditEventType.BILLING_RECONCILIATION_REQUIRED, correlation_id)
            raise BillingError(BillingReasonCode.RESERVATION_STATE_AMBIGUOUS)
        actual_charge = actual_charge_micro_usd(
            quote=quote,
            decision=decision,
            system_failure=system_failure,
            billable_work_occurred=billable_work_occurred,
        )
        if actual_charge > row.max_reserved_spend_micro_usd:
            row.billing_state = BillingLifecycleState.RECONCILIATION_REQUIRED.value
            row.reason_code = BillingReasonCode.CHARGE_EXCEEDS_RESERVE.value
            self.session.flush()
            self._audit(row, AuditEventType.BILLING_RECONCILIATION_REQUIRED, correlation_id)
            raise BillingError(BillingReasonCode.CHARGE_EXCEEDS_RESERVE)
        if actual_charge == 0:
            row.actual_charge_micro_usd = 0
            row.billing_state = BillingLifecycleState.SETTLED.value
            row.settled_at = self.clock()
            row.reason_code = BillingReasonCode.ZERO_CHARGE.value
            self.session.flush()
            self._audit(row, AuditEventType.BILLING_SETTLED, correlation_id)
            self.release(
                account_id=account_id,
                authorization_request_id=authorization_request_id,
                correlation_id=correlation_id,
            )
            return self._result(row, quote, BillingReasonCode.ZERO_CHARGE)
        try:
            transaction = self.ledger_service.settle_reservation(
                account_id=account_id,
                amount_micro_usd=actual_charge,
                idempotency_key=f"authorization:billing:settle:{row.billing_id}",
                correlation_id=authorization_request_id,
            )
        except (IdempotencyConflict, ValueError) as exc:
            row.billing_state = BillingLifecycleState.RECONCILIATION_REQUIRED.value
            row.reason_code = BillingReasonCode.LEDGER_SETTLEMENT_FAILED.value
            self.session.flush()
            self._audit(row, AuditEventType.BILLING_RECONCILIATION_REQUIRED, correlation_id)
            raise BillingError(BillingReasonCode.LEDGER_SETTLEMENT_FAILED) from exc
        row.actual_charge_micro_usd = actual_charge
        row.settlement_ledger_transaction_id = transaction.transaction_id
        row.billing_state = BillingLifecycleState.SETTLED.value
        row.settled_at = self.clock()
        row.reason_code = BillingReasonCode.BILLING_SETTLED.value
        self.session.flush()
        self._audit(row, AuditEventType.BILLING_SETTLED, correlation_id)
        self.release(
            account_id=account_id,
            authorization_request_id=authorization_request_id,
            correlation_id=correlation_id,
        )
        return self._result(row, quote, BillingReasonCode.BILLING_SETTLED)

    def compensate_system_failure(
        self,
        *,
        account_id: UUID,
        authorization_request_id: UUID,
        correlation_id: UUID,
    ) -> BillingResult:
        row = self._require_for_authorization(account_id, authorization_request_id)
        quote = _quote_from_row(row)
        if not row.actual_charge_micro_usd or row.actual_charge_micro_usd <= 0:
            return self.settle(
                account_id=account_id,
                authorization_request_id=authorization_request_id,
                quote=quote,
                decision=PolicyDecision.BLOCK,
                system_failure=True,
                billable_work_occurred=False,
                correlation_id=correlation_id,
            )
        credit = self.ledger_service.grant_service_credit(
            account_id=account_id,
            amount_micro_usd=row.actual_charge_micro_usd,
            idempotency_key=f"authorization:billing:system-failure-credit:{row.billing_id}",
            correlation_id=row.billing_id,
        )
        metadata = dict(row.billing_metadata)
        metadata["system_failure_credit_ledger_transaction_id"] = str(credit.transaction_id)
        metadata["compensated_actual_charge_micro_usd"] = row.actual_charge_micro_usd
        row.billing_metadata = metadata
        row.actual_charge_micro_usd = 0
        row.billing_state = BillingLifecycleState.RELEASED.value
        row.reason_code = BillingReasonCode.SYSTEM_FAILURE_ZERO_CHARGE.value
        self.session.flush()
        self._audit(row, AuditEventType.BILLING_SETTLED, correlation_id)
        return self._result(row, quote, BillingReasonCode.SYSTEM_FAILURE_ZERO_CHARGE)

    def release(
        self,
        *,
        account_id: UUID,
        authorization_request_id: UUID,
        correlation_id: UUID,
    ) -> BillingResult:
        row = self._require_for_authorization(account_id, authorization_request_id)
        quote = _quote_from_row(row)
        if row.reservation_id is None:
            return self._result(row, quote, BillingReasonCode.BILLING_RELEASED)
        try:
            released = self.reservation_service.release(
                reservation_id=row.reservation_id,
                account_id=account_id,
            )
        except ReservationUnavailable as exc:
            row.billing_state = BillingLifecycleState.RECONCILIATION_REQUIRED.value
            row.reason_code = BillingReasonCode.RESERVATION_RELEASE_FAILED.value
            self.session.flush()
            self._audit(row, AuditEventType.BILLING_RECONCILIATION_REQUIRED, correlation_id)
            try:
                self.reservation_service.reconcile(account_id=account_id)
            except ReservationUnavailable:
                pass
            raise BillingError(BillingReasonCode.RESERVATION_RELEASE_FAILED) from exc
        row.reservation_state = (
            released.state.value if released is not None else ReservationState.RELEASED.value
        )
        row.billing_state = BillingLifecycleState.RELEASED.value
        row.released_at = self.clock()
        row.reason_code = BillingReasonCode.BILLING_RELEASED.value
        self.session.flush()
        self._audit(row, AuditEventType.BILLING_RELEASED, correlation_id)
        return self._result(row, quote, BillingReasonCode.BILLING_RELEASED)

    def get_for_authorization(
        self,
        *,
        account_id: UUID,
        authorization_request_id: UUID,
    ) -> BillingResult:
        row = self._require_for_authorization(account_id, authorization_request_id)
        reason = BillingReasonCode(row.reason_code or BillingReasonCode.BILLING_QUOTED.value)
        return self._result(row, _quote_from_row(row), reason)

    def _get_for_authorization(
        self,
        account_id: UUID,
        authorization_request_id: UUID,
    ) -> AuthorizationBilling | None:
        return self.session.scalar(
            select(AuthorizationBilling)
            .where(AuthorizationBilling.account_id == account_id)
            .where(AuthorizationBilling.authorization_request_id == authorization_request_id)
            .with_for_update()
        )

    def _require_for_authorization(
        self,
        account_id: UUID,
        authorization_request_id: UUID,
    ) -> AuthorizationBilling:
        row = self._get_for_authorization(account_id, authorization_request_id)
        if row is None:
            raise CrossTenantBillingAccess("billing record not found for account")
        return row

    def _assert_quote_match(self, row: AuthorizationBilling, quote: BillingQuote) -> None:
        if row.quote_fingerprint != quote.quote_fingerprint:
            raise BillingError(BillingReasonCode.RESERVATION_STATE_AMBIGUOUS)

    def _result(
        self,
        row: AuthorizationBilling,
        quote: BillingQuote,
        reason: BillingReasonCode,
    ) -> BillingResult:
        return BillingResult(
            billing_id=row.billing_id,
            account_id=row.account_id,
            authorization_request_id=row.authorization_request_id,
            state=BillingLifecycleState(row.billing_state),
            quote=quote,
            reservation_id=row.reservation_id,
            actual_charge_micro_usd=row.actual_charge_micro_usd,
            settlement_ledger_transaction_id=row.settlement_ledger_transaction_id,
            reason_code=reason,
        )

    def _audit(
        self,
        row: AuthorizationBilling,
        event_type: AuditEventType,
        correlation_id: UUID,
    ) -> None:
        self.audit_service.append_event(
            account_id=row.account_id,
            event_type=event_type,
            correlation_id=correlation_id,
            request_id=row.authorization_request_id,
            payload={
                "billing_id": row.billing_id,
                "authorization_request_id": row.authorization_request_id,
                "pricing_config_version": row.pricing_version,
                "maximum_reserved_micro_usd": row.max_reserved_spend_micro_usd,
                "actual_charge_micro_usd": row.actual_charge_micro_usd,
                "ledger_transaction_id": row.settlement_ledger_transaction_id,
                "billing_state": row.billing_state,
                "execution_mode": row.execution_mode,
                "reason_codes": [row.reason_code or event_type.value.upper()],
            },
        )

    def _validate_ttl_configuration(self) -> None:
        reservation_seconds = int(self.reservation_ttl.total_seconds())
        execution_seconds = int(self.maximum_billable_execution_window.total_seconds())
        margin_seconds = int(self.reservation_ttl_safety_margin.total_seconds())
        max_seconds = int(self.max_reservation_ttl.total_seconds())
        if min(reservation_seconds, execution_seconds, margin_seconds, max_seconds) <= 0:
            raise ValueError(BillingReasonCode.RESERVATION_TTL_UNSAFE.value)
        if reservation_seconds > max_seconds:
            raise ValueError(BillingReasonCode.RESERVATION_TTL_UNSAFE.value)
        if reservation_seconds < execution_seconds + margin_seconds:
            raise ValueError(BillingReasonCode.RESERVATION_TTL_UNSAFE.value)


def actual_charge_micro_usd(
    *,
    quote: BillingQuote,
    decision: PolicyDecision,
    system_failure: bool,
    billable_work_occurred: bool = True,
) -> int:
    if system_failure:
        return 0
    if not billable_work_occurred and decision is not PolicyDecision.ALLOW:
        return 0
    if decision in {
        PolicyDecision.ALLOW,
        PolicyDecision.BLOCK,
        PolicyDecision.ESCALATE,
        PolicyDecision.RETRY_HIGHER_ASSURANCE,
    }:
        return quote.quoted_price_micro_usd
    return 0


def quote_fingerprint(
    *,
    account_id: UUID,
    authorization_request_id: UUID,
    quote: PricingQuote,
    max_reserved_spend_micro_usd: int,
    material: Mapping[str, object],
) -> str:
    material_without_ephemeral = {
        key: value
        for key, value in material.items()
        if key not in {"client_timestamp", "correlation_id", "ephemeral", "nonce", "trace_id"}
    }
    canonical = canonical_material_json(
        material={
            "account_id": str(account_id),
            "authorization_request_id": str(authorization_request_id),
            "billing_version": BILLING_VERSION,
            "capability": quote.capability.value,
            "execution_mode": quote.billing_mode.value,
            "expected_total_cost_micro_usd": quote.expected_total_cost_micro_usd,
            "material": material_without_ephemeral,
            "max_reserved_spend_micro_usd": max_reserved_spend_micro_usd,
            "pricing_version": quote.pricing_config_version,
            "quoted_price_micro_usd": quote.quoted_price_micro_usd,
        },
        action_schema_version=BILLING_VERSION,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _quote_metadata(quote: BillingQuote) -> dict[str, object]:
    return {
        "billing_version": BILLING_VERSION,
        "capability": quote.capability.value,
        "currency": quote.currency,
        "expected_total_cost_micro_usd": quote.expected_total_cost_micro_usd,
        "quote_id": str(quote.quote_id),
        "quoted_price_micro_usd": quote.quoted_price_micro_usd,
    }


def _quote_from_row(row: AuthorizationBilling) -> BillingQuote:
    metadata = cast(dict[str, str | int], row.billing_metadata)
    return BillingQuote(
        quote_id=UUID(str(metadata["quote_id"])),
        pricing_version=row.pricing_version,
        capability=CapabilityName(str(metadata["capability"])),
        execution_mode=BillingMode(row.execution_mode),
        quoted_price_micro_usd=int(metadata["quoted_price_micro_usd"]),
        max_reserved_spend_micro_usd=row.max_reserved_spend_micro_usd,
        expected_total_cost_micro_usd=int(metadata["expected_total_cost_micro_usd"]),
        currency=str(metadata["currency"]),
        quote_fingerprint=row.quote_fingerprint,
    )


__all__ = [
    "AuthorizationBillingService",
    "BillingError",
    "BillingLifecycleState",
    "BillingQuote",
    "BillingReasonCode",
    "BillingResult",
    "CrossTenantBillingAccess",
    "actual_charge_micro_usd",
    "quote_fingerprint",
]
