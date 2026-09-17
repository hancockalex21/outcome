from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from outcome.audit import AuditEventType, AuditService
from outcome.db.models import CreditLedgerEntry, CreditLedgerTransaction

MICRO_USD_CURRENCY = "USD"


class LedgerDirection(StrEnum):
    DEBIT = "DEBIT"
    CREDIT = "CREDIT"


class LedgerAccount(StrEnum):
    CUSTOMER_PREPAID_LIABILITY = "customer_prepaid_liability"
    CASH_FUNDING_CLEARING = "cash_funding_clearing"
    VERIFICATION_REVENUE = "verification_revenue"
    SERVICE_CREDIT_REFUND_LIABILITY = "service_credit_refund_liability"
    MANUAL_ADJUSTMENT_CLEARING = "manual_adjustment_clearing"
    RESERVATION_RELEASE_CLEARING = "reservation_release_clearing"


class LedgerTransactionType(StrEnum):
    ACCOUNT_FUNDING = "account_funding"
    RESERVATION_SETTLEMENT = "reservation_settlement"
    SERVICE_CREDIT = "service_credit"
    REFUND = "refund"
    MANUAL_ADJUSTMENT = "manual_adjustment"
    RESERVATION_RELEASE = "reservation_release"


class IdempotencyConflict(ValueError):
    pass


class TenantLedgerAccessDenied(PermissionError):
    pass


@dataclass(frozen=True)
class LedgerTransaction:
    transaction_id: UUID
    account_id: UUID
    idempotency_key: str
    transaction_type: LedgerTransactionType
    entries: tuple[CreditLedgerEntry, ...]


@dataclass(frozen=True)
class LedgerPosting:
    ledger_account: LedgerAccount
    direction: LedgerDirection
    amount_micro_usd: int


class LedgerService:
    def __init__(self, session: Session, audit_service: AuditService | None = None) -> None:
        self.session = session
        self.audit_service = audit_service or AuditService(session)

    def fund_account(
        self,
        *,
        account_id: UUID,
        amount_micro_usd: int,
        idempotency_key: str,
        correlation_id: UUID,
    ) -> LedgerTransaction:
        return self._post_transaction(
            account_id=account_id,
            amount_micro_usd=amount_micro_usd,
            idempotency_key=idempotency_key,
            correlation_id=correlation_id,
            transaction_type=LedgerTransactionType.ACCOUNT_FUNDING,
            postings=(
                LedgerPosting(
                    LedgerAccount.CASH_FUNDING_CLEARING,
                    LedgerDirection.DEBIT,
                    amount_micro_usd,
                ),
                LedgerPosting(
                    LedgerAccount.CUSTOMER_PREPAID_LIABILITY,
                    LedgerDirection.CREDIT,
                    amount_micro_usd,
                ),
            ),
            audit_event_type=AuditEventType.ACCOUNT_FUNDED,
        )

    def settle_reservation(
        self,
        *,
        account_id: UUID,
        amount_micro_usd: int,
        idempotency_key: str,
        correlation_id: UUID,
    ) -> LedgerTransaction:
        return self._post_transaction(
            account_id=account_id,
            amount_micro_usd=amount_micro_usd,
            idempotency_key=idempotency_key,
            correlation_id=correlation_id,
            transaction_type=LedgerTransactionType.RESERVATION_SETTLEMENT,
            postings=(
                LedgerPosting(
                    LedgerAccount.CUSTOMER_PREPAID_LIABILITY,
                    LedgerDirection.DEBIT,
                    amount_micro_usd,
                ),
                LedgerPosting(
                    LedgerAccount.VERIFICATION_REVENUE,
                    LedgerDirection.CREDIT,
                    amount_micro_usd,
                ),
            ),
            audit_event_type=AuditEventType.CREDIT_SETTLED,
        )

    def grant_service_credit(
        self,
        *,
        account_id: UUID,
        amount_micro_usd: int,
        idempotency_key: str,
        correlation_id: UUID,
    ) -> LedgerTransaction:
        return self._post_transaction(
            account_id=account_id,
            amount_micro_usd=amount_micro_usd,
            idempotency_key=idempotency_key,
            correlation_id=correlation_id,
            transaction_type=LedgerTransactionType.SERVICE_CREDIT,
            postings=(
                LedgerPosting(
                    LedgerAccount.SERVICE_CREDIT_REFUND_LIABILITY,
                    LedgerDirection.DEBIT,
                    amount_micro_usd,
                ),
                LedgerPosting(
                    LedgerAccount.CUSTOMER_PREPAID_LIABILITY,
                    LedgerDirection.CREDIT,
                    amount_micro_usd,
                ),
            ),
            audit_event_type=AuditEventType.CREDIT_REFUND_ADJUSTMENT_CREATED,
        )

    def refund_account(
        self,
        *,
        account_id: UUID,
        amount_micro_usd: int,
        idempotency_key: str,
        correlation_id: UUID,
    ) -> LedgerTransaction:
        return self._post_transaction(
            account_id=account_id,
            amount_micro_usd=amount_micro_usd,
            idempotency_key=idempotency_key,
            correlation_id=correlation_id,
            transaction_type=LedgerTransactionType.REFUND,
            postings=(
                LedgerPosting(
                    LedgerAccount.CUSTOMER_PREPAID_LIABILITY,
                    LedgerDirection.DEBIT,
                    amount_micro_usd,
                ),
                LedgerPosting(
                    LedgerAccount.CASH_FUNDING_CLEARING,
                    LedgerDirection.CREDIT,
                    amount_micro_usd,
                ),
            ),
            audit_event_type=AuditEventType.CREDIT_REFUND_ADJUSTMENT_CREATED,
        )

    def adjust_account(
        self,
        *,
        account_id: UUID,
        amount_micro_usd: int,
        idempotency_key: str,
        correlation_id: UUID,
    ) -> LedgerTransaction:
        direction = LedgerDirection.CREDIT if amount_micro_usd > 0 else LedgerDirection.DEBIT
        offset_direction = LedgerDirection.DEBIT if amount_micro_usd > 0 else LedgerDirection.CREDIT
        absolute_amount = abs(amount_micro_usd)
        return self._post_transaction(
            account_id=account_id,
            amount_micro_usd=absolute_amount,
            idempotency_key=idempotency_key,
            correlation_id=correlation_id,
            transaction_type=LedgerTransactionType.MANUAL_ADJUSTMENT,
            postings=(
                LedgerPosting(
                    LedgerAccount.MANUAL_ADJUSTMENT_CLEARING,
                    offset_direction,
                    absolute_amount,
                ),
                LedgerPosting(
                    LedgerAccount.CUSTOMER_PREPAID_LIABILITY,
                    direction,
                    absolute_amount,
                ),
            ),
            audit_event_type=AuditEventType.CREDIT_REFUND_ADJUSTMENT_CREATED,
        )

    def release_reservation(
        self,
        *,
        account_id: UUID,
        amount_micro_usd: int,
        idempotency_key: str,
        correlation_id: UUID,
    ) -> LedgerTransaction:
        return self._post_transaction(
            account_id=account_id,
            amount_micro_usd=amount_micro_usd,
            idempotency_key=idempotency_key,
            correlation_id=correlation_id,
            transaction_type=LedgerTransactionType.RESERVATION_RELEASE,
            postings=(
                LedgerPosting(
                    LedgerAccount.RESERVATION_RELEASE_CLEARING,
                    LedgerDirection.DEBIT,
                    amount_micro_usd,
                ),
                LedgerPosting(
                    LedgerAccount.CUSTOMER_PREPAID_LIABILITY,
                    LedgerDirection.CREDIT,
                    amount_micro_usd,
                ),
            ),
            audit_event_type=AuditEventType.CREDIT_RELEASED,
        )

    def balance_micro_usd(self, *, account_id: UUID) -> int:
        entries = self._entries_for_account(account_id=account_id)
        balance = 0
        for entry in entries:
            if entry.ledger_account != LedgerAccount.CUSTOMER_PREPAID_LIABILITY.value:
                continue
            if entry.direction == LedgerDirection.CREDIT.value:
                balance += entry.amount_micro_usd
            else:
                balance -= entry.amount_micro_usd
        return balance

    def transaction_for_account(
        self,
        *,
        account_id: UUID,
        transaction_id: UUID,
    ) -> LedgerTransaction:
        entries = self._entries_for_transaction(transaction_id=transaction_id)
        if not entries:
            raise TenantLedgerAccessDenied("ledger transaction not found for account")
        if any(entry.account_id != account_id for entry in entries):
            raise TenantLedgerAccessDenied("ledger transaction belongs to a different account")
        return self._transaction_from_entries(entries)

    def _post_transaction(
        self,
        *,
        account_id: UUID,
        amount_micro_usd: int,
        idempotency_key: str,
        correlation_id: UUID,
        transaction_type: LedgerTransactionType,
        postings: tuple[LedgerPosting, ...],
        audit_event_type: AuditEventType,
    ) -> LedgerTransaction:
        if amount_micro_usd <= 0:
            raise ValueError("amount_micro_usd must be positive")
        if not idempotency_key:
            raise ValueError("idempotency_key is required")
        self._assert_balanced(postings)

        existing = self._entries_for_idempotency(
            account_id=account_id,
            idempotency_key=idempotency_key,
        )
        if existing:
            transaction = self._transaction_from_entries(existing)
            if (
                transaction.transaction_type != transaction_type
                or self._transaction_amount(transaction.entries) != amount_micro_usd
            ):
                raise IdempotencyConflict(
                    "idempotency key reused with conflicting parameters"
                ) from None
            return transaction

        transaction_id = uuid4()
        try:
            with self.session.begin_nested():
                transaction_record = CreditLedgerTransaction(
                    id=uuid4(),
                    account_id=account_id,
                    transaction_id=transaction_id,
                    idempotency_key=idempotency_key,
                    transaction_type=transaction_type.value,
                    amount_micro_usd=amount_micro_usd,
                    currency=MICRO_USD_CURRENCY,
                )
                self.session.add(transaction_record)
                self.session.flush()
                entries = tuple(
                    CreditLedgerEntry(
                        id=uuid4(),
                        account_id=account_id,
                        transaction_id=transaction_id,
                        ledger_account=posting.ledger_account.value,
                        direction=posting.direction.value,
                        amount_micro_usd=posting.amount_micro_usd,
                        amount_minor=posting.amount_micro_usd,
                        currency=MICRO_USD_CURRENCY,
                        entry_type=transaction_type.value,
                        reference_id=correlation_id,
                    )
                    for posting in postings
                )
                self.session.add_all(entries)
                self.session.flush()
        except IntegrityError:
            existing_after_race = self._entries_for_idempotency(
                account_id=account_id,
                idempotency_key=idempotency_key,
            )
            if not existing_after_race:
                raise
            transaction = self._transaction_from_entries(existing_after_race)
            if (
                transaction.transaction_type != transaction_type
                or self._transaction_amount(transaction.entries) != amount_micro_usd
            ):
                raise IdempotencyConflict(
                    "idempotency key reused with conflicting parameters"
                ) from None
            return transaction
        self.audit_service.append_event(
            account_id=account_id,
            event_type=AuditEventType.LEDGER_TRANSACTION_CREATED,
            correlation_id=correlation_id,
            payload={
                "ledger_transaction_id": transaction_id,
                "transaction_type": transaction_type.value,
                "cost_amount_minor": amount_micro_usd,
                "currency": MICRO_USD_CURRENCY,
                "reason_codes": [audit_event_type.value.upper()],
            },
        )
        if audit_event_type is not AuditEventType.LEDGER_TRANSACTION_CREATED:
            self.audit_service.append_event(
                account_id=account_id,
                event_type=audit_event_type,
                correlation_id=correlation_id,
                payload={
                    "ledger_transaction_id": transaction_id,
                    "transaction_type": transaction_type.value,
                    "cost_amount_minor": amount_micro_usd,
                    "currency": MICRO_USD_CURRENCY,
                    "reason_codes": [audit_event_type.value.upper()],
                },
            )
        return LedgerTransaction(
            transaction_id=transaction_id,
            account_id=account_id,
            idempotency_key=idempotency_key,
            transaction_type=transaction_type,
            entries=entries,
        )

    def _entries_for_account(self, *, account_id: UUID) -> tuple[CreditLedgerEntry, ...]:
        return tuple(
            self.session.scalars(
                select(CreditLedgerEntry)
                .where(CreditLedgerEntry.account_id == account_id)
                .order_by(CreditLedgerEntry.created_at, CreditLedgerEntry.id)
            ).all()
        )

    def _entries_for_idempotency(
        self,
        *,
        account_id: UUID,
        idempotency_key: str,
    ) -> tuple[CreditLedgerEntry, ...]:
        transaction = self.session.scalar(
            select(CreditLedgerTransaction)
            .where(CreditLedgerTransaction.account_id == account_id)
            .where(CreditLedgerTransaction.idempotency_key == idempotency_key)
        )
        if transaction is None:
            return ()
        return tuple(
            self.session.scalars(
                select(CreditLedgerEntry)
                .where(CreditLedgerEntry.account_id == account_id)
                .where(CreditLedgerEntry.transaction_id == transaction.transaction_id)
                .order_by(CreditLedgerEntry.created_at, CreditLedgerEntry.id)
            ).all()
        )

    def _entries_for_transaction(self, *, transaction_id: UUID) -> tuple[CreditLedgerEntry, ...]:
        return tuple(
            self.session.scalars(
                select(CreditLedgerEntry)
                .where(CreditLedgerEntry.transaction_id == transaction_id)
                .order_by(CreditLedgerEntry.created_at, CreditLedgerEntry.id)
            ).all()
        )

    def _transaction_from_entries(
        self,
        entries: tuple[CreditLedgerEntry, ...],
    ) -> LedgerTransaction:
        first = entries[0]
        if any(entry.transaction_id != first.transaction_id for entry in entries):
            raise ValueError("entries span multiple transactions")
        self._assert_entry_balance(entries)
        return LedgerTransaction(
            transaction_id=first.transaction_id,
            account_id=first.account_id,
            idempotency_key=self._transaction_record(first.transaction_id).idempotency_key,
            transaction_type=LedgerTransactionType(first.entry_type),
            entries=entries,
        )

    def _transaction_record(self, transaction_id: UUID) -> CreditLedgerTransaction:
        record = self.session.scalar(
            select(CreditLedgerTransaction).where(
                CreditLedgerTransaction.transaction_id == transaction_id
            )
        )
        if record is None:
            raise ValueError("ledger transaction header is missing")
        return record

    def _assert_balanced(self, postings: tuple[LedgerPosting, ...]) -> None:
        debits = sum(
            posting.amount_micro_usd
            for posting in postings
            if posting.direction is LedgerDirection.DEBIT
        )
        credits = sum(
            posting.amount_micro_usd
            for posting in postings
            if posting.direction is LedgerDirection.CREDIT
        )
        if debits != credits:
            raise ValueError("ledger transaction must balance")

    def _assert_entry_balance(self, entries: tuple[CreditLedgerEntry, ...]) -> None:
        debits = sum(
            entry.amount_micro_usd
            for entry in entries
            if entry.direction == LedgerDirection.DEBIT.value
        )
        credits = sum(
            entry.amount_micro_usd
            for entry in entries
            if entry.direction == LedgerDirection.CREDIT.value
        )
        if debits != credits:
            raise ValueError("persisted ledger transaction is unbalanced")

    def _transaction_amount(self, entries: tuple[CreditLedgerEntry, ...]) -> int:
        return max(entry.amount_micro_usd for entry in entries)
