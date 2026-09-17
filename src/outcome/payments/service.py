from __future__ import annotations

import hmac
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from outcome.audit import AuditEventType, AuditService
from outcome.db.models import AccountFunding, PaymentWebhookEvent
from outcome.ledger import IdempotencyConflict, LedgerService

MICRO_USD_PER_CENT = 10_000
SUPPORTED_FUNDING_CURRENCY = "USD"
PAYMENT_GATEWAY_STRIPE = "stripe"
FUNDING_CONFIG_VERSION = "stripe-funding-v1"
MIN_FUNDING_MICRO_USD = 100_000
MAX_FUNDING_MICRO_USD = 100_000_000_000


class FundingStatus(StrEnum):
    CREATED = "CREATED"
    PENDING = "PENDING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class PaymentEventProcessingStatus(StrEnum):
    RECEIVED = "RECEIVED"
    PROCESSED = "PROCESSED"
    IGNORED = "IGNORED"
    REJECTED = "REJECTED"
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"


class FundingReasonCode(StrEnum):
    INVALID_AMOUNT = "INVALID_AMOUNT"
    UNSUPPORTED_CURRENCY = "UNSUPPORTED_CURRENCY"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    GATEWAY_FAILURE = "GATEWAY_FAILURE"
    INVALID_WEBHOOK_SIGNATURE = "INVALID_WEBHOOK_SIGNATURE"
    UNSUPPORTED_EVENT = "UNSUPPORTED_EVENT"
    UNKNOWN_FUNDING = "UNKNOWN_FUNDING"
    PAYMENT_ID_MISMATCH = "PAYMENT_ID_MISMATCH"
    AMOUNT_MISMATCH = "AMOUNT_MISMATCH"
    CURRENCY_MISMATCH = "CURRENCY_MISMATCH"
    ACCOUNT_MISMATCH = "ACCOUNT_MISMATCH"
    INVALID_STATE_TRANSITION = "INVALID_STATE_TRANSITION"
    LEDGER_POSTING_FAILED = "LEDGER_POSTING_FAILED"
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"
    SYSTEM_FAILURE = "SYSTEM_FAILURE"
    FUNDING_CREATED = "FUNDING_CREATED"
    FUNDING_SUCCEEDED = "FUNDING_SUCCEEDED"
    FUNDING_FAILED = "FUNDING_FAILED"
    FUNDING_CANCELLED = "FUNDING_CANCELLED"
    WEBHOOK_PROCESSED = "WEBHOOK_PROCESSED"


class FundingError(ValueError):
    def __init__(self, reason: FundingReasonCode) -> None:
        super().__init__(reason.value)
        self.reason = reason


class FundingIdempotencyConflict(FundingError):
    pass


class CrossTenantFundingAccess(PermissionError):
    pass


@dataclass(frozen=True)
class FundingRequest:
    account_id: UUID
    amount_micro_usd: int
    currency: str
    idempotency_key: str
    return_reference: str | None = None


@dataclass(frozen=True)
class GatewayPaymentIntent:
    external_payment_id: str
    external_customer_id: str | None
    amount_minor: int
    currency: str
    status: str


class PaymentGateway:
    gateway_name = PAYMENT_GATEWAY_STRIPE

    def create_payment_intent(
        self,
        *,
        amount_minor: int,
        currency: str,
        idempotency_key: str,
        metadata: Mapping[str, str],
    ) -> GatewayPaymentIntent:
        raise NotImplementedError


@dataclass(frozen=True)
class StripeWebhookPaymentObject:
    external_payment_id: str
    amount_minor: int
    currency: str
    status: str
    metadata: Mapping[str, str]
    external_customer_id: str | None = None


@dataclass(frozen=True)
class StripeWebhookEvent:
    external_event_id: str
    event_type: str
    payment: StripeWebhookPaymentObject


class StripeWebhookVerifier:
    def verify(self, *, payload: bytes, signature_header: str) -> StripeWebhookEvent:
        raise NotImplementedError


class FakeStripePaymentGateway(PaymentGateway):
    def __init__(self) -> None:
        self.created: list[tuple[int, str, str, Mapping[str, str]]] = []
        self.fail = False

    def create_payment_intent(
        self,
        *,
        amount_minor: int,
        currency: str,
        idempotency_key: str,
        metadata: Mapping[str, str],
    ) -> GatewayPaymentIntent:
        if self.fail:
            raise RuntimeError("stripe gateway unavailable")
        self.created.append((amount_minor, currency, idempotency_key, dict(metadata)))
        return GatewayPaymentIntent(
            external_payment_id=f"pi_{idempotency_key[-24:]}",
            external_customer_id=None,
            amount_minor=amount_minor,
            currency=currency,
            status="requires_payment_method",
        )


class StaticStripeWebhookVerifier(StripeWebhookVerifier):
    def __init__(self, event: StripeWebhookEvent, *, expected_signature: str = "valid") -> None:
        self.event = event
        self.expected_signature = expected_signature

    def verify(self, *, payload: bytes, signature_header: str) -> StripeWebhookEvent:
        if not payload or not hmac.compare_digest(signature_header, self.expected_signature):
            raise FundingError(FundingReasonCode.INVALID_WEBHOOK_SIGNATURE)
        return self.event


@dataclass(frozen=True)
class FundingResult:
    funding_id: UUID | None
    account_id: UUID
    amount_micro_usd: int
    currency: str
    status: FundingStatus
    external_payment_id: str | None
    ledger_transaction_id: UUID | None
    idempotent_replay: bool
    reason_code: FundingReasonCode


class FundingService:
    def __init__(
        self,
        session: Session,
        *,
        gateway: PaymentGateway,
        audit_service: AuditService | None = None,
        clock: Callable[[], datetime] | None = None,
        min_funding_micro_usd: int = MIN_FUNDING_MICRO_USD,
        max_funding_micro_usd: int = MAX_FUNDING_MICRO_USD,
    ) -> None:
        self.session = session
        self.gateway = gateway
        self.audit_service = audit_service or AuditService(session)
        self.clock = clock or (lambda: datetime.now(UTC))
        self.min_funding_micro_usd = min_funding_micro_usd
        self.max_funding_micro_usd = max_funding_micro_usd

    def create_funding(self, request: FundingRequest, *, correlation_id: UUID) -> FundingResult:
        amount_minor = micro_usd_to_stripe_cents(request.amount_micro_usd)
        currency = normalize_currency(request.currency)
        if request.amount_micro_usd < self.min_funding_micro_usd:
            raise FundingError(FundingReasonCode.INVALID_AMOUNT)
        if request.amount_micro_usd > self.max_funding_micro_usd:
            raise FundingError(FundingReasonCode.INVALID_AMOUNT)
        if not request.idempotency_key:
            raise FundingError(FundingReasonCode.IDEMPOTENCY_CONFLICT)
        existing = self._funding_for_idempotency(request.account_id, request.idempotency_key)
        if existing is not None:
            if (
                existing.amount_micro_usd != request.amount_micro_usd
                or existing.currency != currency
            ):
                raise FundingIdempotencyConflict(FundingReasonCode.IDEMPOTENCY_CONFLICT)
            return self._result(existing, FundingReasonCode.FUNDING_CREATED, True)

        funding_id = uuid4()
        row = AccountFunding(
            id=uuid4(),
            funding_id=funding_id,
            account_id=request.account_id,
            amount_micro_usd=request.amount_micro_usd,
            currency=currency,
            gateway=self.gateway.gateway_name,
            external_payment_id=None,
            external_customer_id=None,
            idempotency_key=request.idempotency_key,
            status=FundingStatus.CREATED.value,
            metadata_json={
                "funding_config_version": FUNDING_CONFIG_VERSION,
                "return_reference": request.return_reference,
            },
        )
        self.session.add(row)
        self.session.flush()
        self._audit(
            row,
            AuditEventType.FUNDING_CREATED,
            correlation_id,
            FundingReasonCode.FUNDING_CREATED,
        )
        try:
            intent = self.gateway.create_payment_intent(
                amount_minor=amount_minor,
                currency=currency.lower(),
                idempotency_key=f"funding:{request.account_id}:{request.idempotency_key}",
                metadata={
                    "funding_id": str(funding_id),
                    "account_ref": str(request.account_id),
                },
            )
        except Exception as exc:
            row.status = FundingStatus.FAILED.value
            row.reason_code = FundingReasonCode.GATEWAY_FAILURE.value
            self.session.flush()
            self._audit(
                row,
                AuditEventType.FUNDING_FAILED,
                correlation_id,
                FundingReasonCode.GATEWAY_FAILURE,
            )
            raise FundingError(FundingReasonCode.GATEWAY_FAILURE) from exc
        row.external_payment_id = intent.external_payment_id
        row.external_customer_id = intent.external_customer_id
        row.status = FundingStatus.PENDING.value
        self.session.flush()
        self._audit(
            row,
            AuditEventType.FUNDING_GATEWAY_OBJECT_CREATED,
            correlation_id,
            FundingReasonCode.FUNDING_CREATED,
        )
        return self._result(row, FundingReasonCode.FUNDING_CREATED, False)

    def get_funding(self, *, account_id: UUID, funding_id: UUID) -> FundingResult:
        row = self.session.scalar(
            select(AccountFunding).where(AccountFunding.funding_id == funding_id)
        )
        if row is None or row.account_id != account_id:
            raise CrossTenantFundingAccess("funding belongs to a different account")
        reason = FundingReasonCode(row.reason_code or FundingReasonCode.FUNDING_CREATED)
        return self._result(row, reason, False)

    def _funding_for_idempotency(
        self,
        account_id: UUID,
        idempotency_key: str,
    ) -> AccountFunding | None:
        return self.session.scalar(
            select(AccountFunding).where(
                AccountFunding.account_id == account_id,
                AccountFunding.idempotency_key == idempotency_key,
            )
        )

    def _result(
        self,
        row: AccountFunding,
        reason: FundingReasonCode,
        replay: bool,
    ) -> FundingResult:
        return FundingResult(
            funding_id=row.funding_id,
            account_id=row.account_id,
            amount_micro_usd=row.amount_micro_usd,
            currency=row.currency,
            status=FundingStatus(row.status),
            external_payment_id=row.external_payment_id,
            ledger_transaction_id=row.ledger_transaction_id,
            idempotent_replay=replay,
            reason_code=reason,
        )

    def _audit(
        self,
        row: AccountFunding,
        event_type: AuditEventType,
        correlation_id: UUID,
        reason: FundingReasonCode,
    ) -> None:
        self.audit_service.append_event(
            account_id=row.account_id,
            event_type=event_type,
            correlation_id=correlation_id,
            request_id=row.funding_id,
            payload={
                "funding_id": row.funding_id,
                "external_payment_id": row.external_payment_id,
                "cost_amount_minor": row.amount_micro_usd,
                "currency": row.currency,
                "ledger_transaction_id": row.ledger_transaction_id,
                "reason_codes": [reason.value],
            },
        )


@dataclass(frozen=True)
class WebhookProcessingResult:
    event_id: UUID | None
    funding_id: UUID | None
    status: PaymentEventProcessingStatus
    reason_code: FundingReasonCode
    ledger_transaction_id: UUID | None = None


class StripeWebhookService:
    SUPPORTED_SUCCESS_EVENTS = {"payment_intent.succeeded"}
    SUPPORTED_FAILURE_EVENTS = {"payment_intent.payment_failed", "payment_intent.canceled"}
    IGNORED_EVENTS = {
        "charge.refunded",
        "charge.dispute.created",
        "payment_intent.processing",
    }

    def __init__(
        self,
        session: Session,
        *,
        verifier: StripeWebhookVerifier,
        ledger_service: LedgerService | None = None,
        audit_service: AuditService | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.session = session
        self.verifier = verifier
        self.audit_service = audit_service or AuditService(session)
        self.ledger_service = ledger_service or LedgerService(session, self.audit_service)
        self.clock = clock or (lambda: datetime.now(UTC))

    def process(self, *, payload: bytes, signature_header: str) -> WebhookProcessingResult:
        try:
            event = self.verifier.verify(payload=payload, signature_header=signature_header)
        except FundingError:
            return WebhookProcessingResult(
                event_id=None,
                funding_id=None,
                status=PaymentEventProcessingStatus.REJECTED,
                reason_code=FundingReasonCode.INVALID_WEBHOOK_SIGNATURE,
            )
        inbox = self._create_or_get_event(event)
        if inbox.processing_status == PaymentEventProcessingStatus.PROCESSED.value:
            return WebhookProcessingResult(
                event_id=inbox.id,
                funding_id=inbox.funding_id,
                status=PaymentEventProcessingStatus.PROCESSED,
                reason_code=FundingReasonCode.WEBHOOK_PROCESSED,
                ledger_transaction_id=self._ledger_id_for_funding(inbox.funding_id),
            )
        if event.event_type in self.IGNORED_EVENTS or (
            event.event_type
            not in self.SUPPORTED_SUCCESS_EVENTS | self.SUPPORTED_FAILURE_EVENTS
        ):
            return self._mark_event(
                inbox,
                PaymentEventProcessingStatus.IGNORED,
                FundingReasonCode.UNSUPPORTED_EVENT,
            )
        funding = self._funding_for_payment(event.payment.external_payment_id)
        if funding is None:
            return self._mark_event(
                inbox,
                PaymentEventProcessingStatus.RECONCILIATION_REQUIRED,
                FundingReasonCode.UNKNOWN_FUNDING,
                external_payment_id=event.payment.external_payment_id,
            )
        inbox.funding_id = funding.funding_id
        inbox.external_payment_id = event.payment.external_payment_id
        if event.payment.metadata.get("funding_id") not in {None, str(funding.funding_id)}:
            return self._reconcile(funding, inbox, FundingReasonCode.ACCOUNT_MISMATCH)
        if funding.external_payment_id != event.payment.external_payment_id:
            return self._reconcile(funding, inbox, FundingReasonCode.PAYMENT_ID_MISMATCH)
        try:
            amount_micro = stripe_cents_to_micro_usd(event.payment.amount_minor)
        except FundingError:
            return self._reconcile(funding, inbox, FundingReasonCode.AMOUNT_MISMATCH)
        if amount_micro != funding.amount_micro_usd:
            return self._reconcile(funding, inbox, FundingReasonCode.AMOUNT_MISMATCH)
        try:
            event_currency = normalize_currency(event.payment.currency)
        except FundingError:
            return self._reconcile(funding, inbox, FundingReasonCode.CURRENCY_MISMATCH)
        if event_currency != funding.currency:
            return self._reconcile(funding, inbox, FundingReasonCode.CURRENCY_MISMATCH)
        if event.event_type in self.SUPPORTED_FAILURE_EVENTS:
            return self._process_failure(funding, inbox, event)
        return self._process_success(funding, inbox, event)

    def _create_or_get_event(self, event: StripeWebhookEvent) -> PaymentWebhookEvent:
        existing = self.session.scalar(
            select(PaymentWebhookEvent).where(
                PaymentWebhookEvent.gateway == PAYMENT_GATEWAY_STRIPE,
                PaymentWebhookEvent.external_event_id == event.external_event_id,
            )
        )
        if existing is not None:
            return existing
        row = PaymentWebhookEvent(
            id=uuid4(),
            gateway=PAYMENT_GATEWAY_STRIPE,
            external_event_id=event.external_event_id,
            event_type=event.event_type,
            processing_status=PaymentEventProcessingStatus.RECEIVED.value,
            external_payment_id=event.payment.external_payment_id,
            safe_payload={
                "event_type": event.event_type,
                "external_payment_id": event.payment.external_payment_id,
                "amount_minor": event.payment.amount_minor,
                "currency": event.payment.currency,
            },
        )
        try:
            with self.session.begin_nested():
                self.session.add(row)
                self.session.flush()
        except IntegrityError:
            existing = self.session.scalar(
                select(PaymentWebhookEvent).where(
                    PaymentWebhookEvent.gateway == PAYMENT_GATEWAY_STRIPE,
                    PaymentWebhookEvent.external_event_id == event.external_event_id,
                )
            )
            if existing is None:
                raise
            return existing
        return row

    def _funding_for_payment(self, external_payment_id: str) -> AccountFunding | None:
        return self.session.scalar(
            select(AccountFunding)
            .where(
                AccountFunding.gateway == PAYMENT_GATEWAY_STRIPE,
                AccountFunding.external_payment_id == external_payment_id,
            )
            .with_for_update()
        )

    def _process_success(
        self,
        funding: AccountFunding,
        inbox: PaymentWebhookEvent,
        event: StripeWebhookEvent,
    ) -> WebhookProcessingResult:
        if funding.status == FundingStatus.SUCCEEDED.value:
            return self._mark_event(
                inbox,
                PaymentEventProcessingStatus.PROCESSED,
                FundingReasonCode.WEBHOOK_PROCESSED,
                funding=funding,
            )
        success_allowed_states = {
            FundingStatus.CREATED.value,
            FundingStatus.PENDING.value,
            FundingStatus.FAILED.value,
        }
        if funding.status not in success_allowed_states:
            return self._reconcile(funding, inbox, FundingReasonCode.INVALID_STATE_TRANSITION)
        try:
            ledger = self.ledger_service.fund_account(
                account_id=funding.account_id,
                amount_micro_usd=funding.amount_micro_usd,
                idempotency_key=f"stripe:funding:{funding.funding_id}",
                correlation_id=funding.funding_id,
            )
        except (IdempotencyConflict, ValueError):
            return self._reconcile(funding, inbox, FundingReasonCode.LEDGER_POSTING_FAILED)
        funding.status = FundingStatus.SUCCEEDED.value
        funding.succeeded_at = self.clock()
        funding.ledger_transaction_id = ledger.transaction_id
        funding.succeeded_event_id = event.external_event_id
        funding.reason_code = FundingReasonCode.FUNDING_SUCCEEDED.value
        return self._mark_event(
            inbox,
            PaymentEventProcessingStatus.PROCESSED,
            FundingReasonCode.FUNDING_SUCCEEDED,
            funding=funding,
        )

    def _process_failure(
        self,
        funding: AccountFunding,
        inbox: PaymentWebhookEvent,
        event: StripeWebhookEvent,
    ) -> WebhookProcessingResult:
        if funding.status == FundingStatus.SUCCEEDED.value:
            return self._mark_event(
                inbox,
                PaymentEventProcessingStatus.PROCESSED,
                FundingReasonCode.WEBHOOK_PROCESSED,
                funding=funding,
            )
        funding.status = (
            FundingStatus.CANCELLED.value
            if event.event_type == "payment_intent.canceled"
            else FundingStatus.FAILED.value
        )
        funding.reason_code = (
            FundingReasonCode.FUNDING_CANCELLED.value
            if event.event_type == "payment_intent.canceled"
            else FundingReasonCode.FUNDING_FAILED.value
        )
        return self._mark_event(
            inbox,
            PaymentEventProcessingStatus.PROCESSED,
            FundingReasonCode(funding.reason_code),
            funding=funding,
        )

    def _reconcile(
        self,
        funding: AccountFunding,
        inbox: PaymentWebhookEvent,
        reason: FundingReasonCode,
    ) -> WebhookProcessingResult:
        funding.reason_code = FundingReasonCode.RECONCILIATION_REQUIRED.value
        return self._mark_event(
            inbox,
            PaymentEventProcessingStatus.RECONCILIATION_REQUIRED,
            reason,
            funding=funding,
        )

    def _mark_event(
        self,
        inbox: PaymentWebhookEvent,
        status: PaymentEventProcessingStatus,
        reason: FundingReasonCode,
        *,
        funding: AccountFunding | None = None,
        external_payment_id: str | None = None,
    ) -> WebhookProcessingResult:
        inbox.processing_status = status.value
        inbox.processed_at = self.clock()
        inbox.reason_code = reason.value
        if funding is not None:
            inbox.funding_id = funding.funding_id
            inbox.external_payment_id = funding.external_payment_id
        elif external_payment_id is not None:
            inbox.external_payment_id = external_payment_id
        self.session.flush()
        if funding is not None:
            event_type = (
                AuditEventType.FUNDING_SUCCEEDED
                if reason is FundingReasonCode.FUNDING_SUCCEEDED
                else AuditEventType.FUNDING_FAILED
                if reason in {FundingReasonCode.FUNDING_FAILED, FundingReasonCode.FUNDING_CANCELLED}
                else AuditEventType.FUNDING_RECONCILIATION_REQUIRED
                if status is PaymentEventProcessingStatus.RECONCILIATION_REQUIRED
                else AuditEventType.PAYMENT_WEBHOOK_VERIFIED
            )
            self._audit_funding(funding, event_type, reason, inbox.external_event_id)
        return WebhookProcessingResult(
            event_id=inbox.id,
            funding_id=inbox.funding_id,
            status=status,
            reason_code=reason,
            ledger_transaction_id=funding.ledger_transaction_id if funding else None,
        )

    def _ledger_id_for_funding(self, funding_id: UUID | None) -> UUID | None:
        if funding_id is None:
            return None
        funding = self.session.scalar(
            select(AccountFunding).where(AccountFunding.funding_id == funding_id)
        )
        return funding.ledger_transaction_id if funding else None

    def _audit_funding(
        self,
        funding: AccountFunding,
        event_type: AuditEventType,
        reason: FundingReasonCode,
        external_event_id: str,
    ) -> None:
        self.audit_service.append_event(
            account_id=funding.account_id,
            event_type=event_type,
            correlation_id=funding.funding_id,
            request_id=funding.funding_id,
            payload={
                "funding_id": funding.funding_id,
                "payment_event_id": external_event_id,
                "external_payment_id": funding.external_payment_id,
                "cost_amount_minor": funding.amount_micro_usd,
                "currency": funding.currency,
                "ledger_transaction_id": funding.ledger_transaction_id,
                "reason_codes": [reason.value],
            },
        )


def normalize_currency(currency: str) -> str:
    normalized = currency.upper()
    if normalized != SUPPORTED_FUNDING_CURRENCY:
        raise FundingError(FundingReasonCode.UNSUPPORTED_CURRENCY)
    return normalized


def micro_usd_to_stripe_cents(amount_micro_usd: object) -> int:
    if not isinstance(amount_micro_usd, int) or isinstance(amount_micro_usd, bool):
        raise FundingError(FundingReasonCode.INVALID_AMOUNT)
    if amount_micro_usd <= 0:
        raise FundingError(FundingReasonCode.INVALID_AMOUNT)
    if amount_micro_usd % MICRO_USD_PER_CENT != 0:
        raise FundingError(FundingReasonCode.INVALID_AMOUNT)
    return amount_micro_usd // MICRO_USD_PER_CENT


def stripe_cents_to_micro_usd(amount_minor: object) -> int:
    if not isinstance(amount_minor, int) or isinstance(amount_minor, bool) or amount_minor <= 0:
        raise FundingError(FundingReasonCode.INVALID_AMOUNT)
    return amount_minor * MICRO_USD_PER_CENT


__all__ = [
    "CrossTenantFundingAccess",
    "FakeStripePaymentGateway",
    "FundingError",
    "FundingIdempotencyConflict",
    "FundingReasonCode",
    "FundingRequest",
    "FundingResult",
    "FundingService",
    "FundingStatus",
    "GatewayPaymentIntent",
    "PaymentEventProcessingStatus",
    "PaymentGateway",
    "StaticStripeWebhookVerifier",
    "StripeWebhookEvent",
    "StripeWebhookPaymentObject",
    "StripeWebhookService",
    "StripeWebhookVerifier",
    "WebhookProcessingResult",
    "micro_usd_to_stripe_cents",
    "normalize_currency",
    "stripe_cents_to_micro_usd",
]
