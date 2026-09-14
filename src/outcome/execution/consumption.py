from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC
from enum import StrEnum
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from outcome.audit import AuditEventType, AuditService
from outcome.db.models import ReceiptConsumption
from outcome.execution.service import (
    ExecutionAuthorizationRequest,
    ExecutionAuthorizationResult,
    ExecutionAuthorizationStatus,
    ExecutionAuthorizationValidator,
)


class ReceiptConsumptionStatus(StrEnum):
    CONSUMED = "CONSUMED"
    ALREADY_CONSUMED = "ALREADY_CONSUMED"
    IDEMPOTENT_REPLAY = "IDEMPOTENT_REPLAY"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    NOT_AUTHORIZED = "NOT_AUTHORIZED"
    SYSTEM_FAILURE = "SYSTEM_FAILURE"


@dataclass(frozen=True)
class ReceiptConsumptionResult:
    status: ReceiptConsumptionStatus
    consumption_id: UUID | None = None
    receipt_id: UUID | None = None
    account_id: UUID | None = None
    authorization_request_id: UUID | None = None
    action_hash: str | None = None
    execution_request_id: UUID | None = None
    validation_status: ExecutionAuthorizationStatus | None = None
    reason_code: str | None = None


class ReceiptConsumptionService:
    def __init__(
        self,
        session: Session,
        *,
        validator: ExecutionAuthorizationValidator,
        audit_service: AuditService | None = None,
    ) -> None:
        self.session = session
        self.validator = validator
        self.audit_service = audit_service or AuditService(session)

    def consume(
        self,
        *,
        authorization_request: ExecutionAuthorizationRequest,
        execution_request_id: UUID,
        correlation_id: UUID,
    ) -> ReceiptConsumptionResult:
        validation = self.validator.validate(
            authorization_request,
            correlation_id=correlation_id,
        )
        if validation.status is not ExecutionAuthorizationStatus.AUTHORIZED:
            result = ReceiptConsumptionResult(
                status=ReceiptConsumptionStatus.NOT_AUTHORIZED,
                receipt_id=validation.receipt_id,
                account_id=authorization_request.authenticated_account_id,
                authorization_request_id=validation.authorization_request_id,
                action_hash=validation.action_hash,
                execution_request_id=execution_request_id,
                validation_status=validation.status,
                reason_code=validation.status.value,
            )
            self._audit(
                result=result,
                event_type=AuditEventType.RECEIPT_CONSUMPTION_CONFLICT,
                correlation_id=correlation_id,
            )
            return result

        try:
            existing_for_execution = self._get_by_execution_request(
                account_id=authorization_request.authenticated_account_id,
                execution_request_id=execution_request_id,
            )
            if existing_for_execution is not None:
                result = self._result_from_existing(
                    existing_for_execution,
                    validation=validation,
                    execution_request_id=execution_request_id,
                )
                event_type = (
                    AuditEventType.RECEIPT_IDEMPOTENT_EXECUTION_REPLAY
                    if result.status is ReceiptConsumptionStatus.IDEMPOTENT_REPLAY
                    else AuditEventType.RECEIPT_CONSUMPTION_CONFLICT
                )
                self._audit(result=result, event_type=event_type, correlation_id=correlation_id)
                return result

            existing_for_receipt = self._get_by_receipt(
                account_id=authorization_request.authenticated_account_id,
                receipt_id=validation.receipt_id,
            )
            if existing_for_receipt is not None:
                result = self._already_consumed_result(
                    existing_for_receipt,
                    execution_request_id=execution_request_id,
                )
                self._audit(
                    result=result,
                    event_type=AuditEventType.RECEIPT_REPLAY_DETECTED,
                    correlation_id=correlation_id,
                )
                return result

            consumption = ReceiptConsumption(
                id=uuid4(),
                account_id=authorization_request.authenticated_account_id,
                consumption_id=uuid4(),
                receipt_id=_required_uuid(validation.receipt_id, "receipt_id"),
                authorization_request_id=_required_uuid(
                    validation.authorization_request_id,
                    "authorization_request_id",
                ),
                action_hash=_required_string(validation.action_hash, "action_hash"),
                consumed_at=authorization_request.current_timestamp.astimezone(UTC),
                execution_request_id=execution_request_id,
            )
            self.session.add(consumption)
            self.session.flush()
        except IntegrityError:
            self.session.rollback()
            result = self._resolve_integrity_race(
                authorization_request=authorization_request,
                validation=validation,
                execution_request_id=execution_request_id,
            )
            self._audit_integrity_result(result=result, correlation_id=correlation_id)
            return result
        except SQLAlchemyError:
            self.session.rollback()
            result = ReceiptConsumptionResult(
                status=ReceiptConsumptionStatus.SYSTEM_FAILURE,
                receipt_id=validation.receipt_id,
                account_id=authorization_request.authenticated_account_id,
                authorization_request_id=validation.authorization_request_id,
                action_hash=validation.action_hash,
                execution_request_id=execution_request_id,
                validation_status=validation.status,
                reason_code=ReceiptConsumptionStatus.SYSTEM_FAILURE.value,
            )
            self._audit(
                result=result,
                event_type=AuditEventType.RECEIPT_CONSUMPTION_SYSTEM_FAILURE,
                correlation_id=correlation_id,
            )
            return result

        result = ReceiptConsumptionResult(
            status=ReceiptConsumptionStatus.CONSUMED,
            consumption_id=consumption.consumption_id,
            receipt_id=consumption.receipt_id,
            account_id=consumption.account_id,
            authorization_request_id=consumption.authorization_request_id,
            action_hash=consumption.action_hash,
            execution_request_id=consumption.execution_request_id,
            validation_status=validation.status,
            reason_code=ReceiptConsumptionStatus.CONSUMED.value,
        )
        self._audit(
            result=result,
            event_type=AuditEventType.RECEIPT_CONSUMPTION_SUCCEEDED,
            correlation_id=correlation_id,
        )
        return result

    def _get_by_execution_request(
        self,
        *,
        account_id: UUID,
        execution_request_id: UUID,
    ) -> ReceiptConsumption | None:
        return self.session.scalar(
            select(ReceiptConsumption).where(
                ReceiptConsumption.account_id == account_id,
                ReceiptConsumption.execution_request_id == execution_request_id,
            )
        )

    def _get_by_receipt(
        self,
        *,
        account_id: UUID,
        receipt_id: UUID | None,
    ) -> ReceiptConsumption | None:
        if receipt_id is None:
            return None
        return self.session.scalar(
            select(ReceiptConsumption).where(
                ReceiptConsumption.account_id == account_id,
                ReceiptConsumption.receipt_id == receipt_id,
            )
        )

    def _result_from_existing(
        self,
        existing: ReceiptConsumption,
        *,
        validation: ExecutionAuthorizationResult,
        execution_request_id: UUID,
    ) -> ReceiptConsumptionResult:
        same_logical_context = (
            existing.receipt_id == validation.receipt_id
            and existing.authorization_request_id == validation.authorization_request_id
            and existing.action_hash == validation.action_hash
        )
        status = (
            ReceiptConsumptionStatus.IDEMPOTENT_REPLAY
            if same_logical_context
            else ReceiptConsumptionStatus.IDEMPOTENCY_CONFLICT
        )
        return ReceiptConsumptionResult(
            status=status,
            consumption_id=existing.consumption_id,
            receipt_id=existing.receipt_id,
            account_id=existing.account_id,
            authorization_request_id=existing.authorization_request_id,
            action_hash=existing.action_hash,
            execution_request_id=execution_request_id,
            validation_status=validation.status,
            reason_code=status.value,
        )

    def _already_consumed_result(
        self,
        existing: ReceiptConsumption,
        *,
        execution_request_id: UUID,
    ) -> ReceiptConsumptionResult:
        return ReceiptConsumptionResult(
            status=ReceiptConsumptionStatus.ALREADY_CONSUMED,
            consumption_id=existing.consumption_id,
            receipt_id=existing.receipt_id,
            account_id=existing.account_id,
            authorization_request_id=existing.authorization_request_id,
            action_hash=existing.action_hash,
            execution_request_id=execution_request_id,
            reason_code=ReceiptConsumptionStatus.ALREADY_CONSUMED.value,
        )

    def _resolve_integrity_race(
        self,
        *,
        authorization_request: ExecutionAuthorizationRequest,
        validation: ExecutionAuthorizationResult,
        execution_request_id: UUID,
    ) -> ReceiptConsumptionResult:
        existing_for_execution = self._get_by_execution_request(
            account_id=authorization_request.authenticated_account_id,
            execution_request_id=execution_request_id,
        )
        if existing_for_execution is not None:
            return self._result_from_existing(
                existing_for_execution,
                validation=validation,
                execution_request_id=execution_request_id,
            )
        existing_for_receipt = self._get_by_receipt(
            account_id=authorization_request.authenticated_account_id,
            receipt_id=validation.receipt_id,
        )
        if existing_for_receipt is not None:
            return self._already_consumed_result(
                existing_for_receipt,
                execution_request_id=execution_request_id,
            )
        return ReceiptConsumptionResult(
            status=ReceiptConsumptionStatus.SYSTEM_FAILURE,
            receipt_id=validation.receipt_id,
            account_id=authorization_request.authenticated_account_id,
            authorization_request_id=validation.authorization_request_id,
            action_hash=validation.action_hash,
            execution_request_id=execution_request_id,
            validation_status=validation.status,
            reason_code=ReceiptConsumptionStatus.SYSTEM_FAILURE.value,
        )

    def _audit_integrity_result(
        self,
        *,
        result: ReceiptConsumptionResult,
        correlation_id: UUID,
    ) -> None:
        event_type = {
            ReceiptConsumptionStatus.IDEMPOTENT_REPLAY: (
                AuditEventType.RECEIPT_IDEMPOTENT_EXECUTION_REPLAY
            ),
            ReceiptConsumptionStatus.ALREADY_CONSUMED: AuditEventType.RECEIPT_REPLAY_DETECTED,
            ReceiptConsumptionStatus.IDEMPOTENCY_CONFLICT: (
                AuditEventType.RECEIPT_CONSUMPTION_CONFLICT
            ),
        }.get(result.status, AuditEventType.RECEIPT_CONSUMPTION_SYSTEM_FAILURE)
        self._audit(result=result, event_type=event_type, correlation_id=correlation_id)

    def _audit(
        self,
        *,
        result: ReceiptConsumptionResult,
        event_type: AuditEventType,
        correlation_id: UUID,
    ) -> None:
        try:
            self.audit_service.append_event(
                account_id=_required_uuid(result.account_id, "account_id"),
                event_type=event_type,
                correlation_id=correlation_id,
                request_id=result.authorization_request_id,
                payload={
                    "receipt_id": result.receipt_id,
                    "authorization_request_id": result.authorization_request_id,
                    "action_hash": result.action_hash,
                    "execution_request_id": result.execution_request_id,
                    "consumption_id": result.consumption_id,
                    "reason_codes": [result.reason_code or result.status.value],
                },
            )
        except SQLAlchemyError:
            if event_type is not AuditEventType.RECEIPT_CONSUMPTION_SYSTEM_FAILURE:
                raise


def _required_uuid(value: UUID | None, field_name: str) -> UUID:
    if value is None:
        raise ValueError(f"{field_name} is required")
    return value


def _required_string(value: str | None, field_name: str) -> str:
    if not value:
        raise ValueError(f"{field_name} is required")
    return value
