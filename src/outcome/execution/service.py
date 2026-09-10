from __future__ import annotations

import hmac
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from uuid import UUID

from outcome.actions import ActionBindingContext, CanonicalizationError, action_hash
from outcome.audit import AuditEventType, AuditService
from outcome.domain import PolicyDecision, VerificationStatus
from outcome.receipts import ReceiptVerificationStatus, ReceiptVerifier, SignedReceipt


class ExecutionAuthorizationStatus(StrEnum):
    AUTHORIZED = "AUTHORIZED"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    EXPIRED_RECEIPT = "EXPIRED_RECEIPT"
    UNKNOWN_SIGNING_KEY = "UNKNOWN_SIGNING_KEY"
    MALFORMED_RECEIPT = "MALFORMED_RECEIPT"
    ACCOUNT_MISMATCH = "ACCOUNT_MISMATCH"
    ACTION_MISMATCH = "ACTION_MISMATCH"
    SCHEMA_MISMATCH = "SCHEMA_MISMATCH"
    DECISION_NOT_ALLOWED = "DECISION_NOT_ALLOWED"


@dataclass(frozen=True)
class ExecutionAuthorizationRequest:
    signed_receipt: SignedReceipt
    proposed_material: Mapping[str, object]
    proposed_action_schema_version: str
    authenticated_account_id: UUID
    current_timestamp: datetime
    ephemeral: Mapping[str, object] | None = None
    supplied_action_hash: str | None = None


@dataclass(frozen=True)
class ExecutionAuthorizationResult:
    status: ExecutionAuthorizationStatus
    executable: bool
    receipt_id: UUID | None = None
    authorization_request_id: UUID | None = None
    action_hash: str | None = None
    policy_decision: PolicyDecision | None = None
    verification_status: VerificationStatus | None = None
    reason_code: str | None = None


class ExecutionAuthorizationValidator:
    def __init__(
        self,
        *,
        receipt_verifier: ReceiptVerifier,
        audit_service: AuditService | None = None,
    ) -> None:
        self.receipt_verifier = receipt_verifier
        self.audit_service = audit_service

    def validate(
        self,
        request: ExecutionAuthorizationRequest,
        *,
        correlation_id: UUID,
    ) -> ExecutionAuthorizationResult:
        payload = request.signed_receipt.payload
        receipt_result = self.receipt_verifier.verify(
            request.signed_receipt,
            now=request.current_timestamp,
        )
        if receipt_result.status is not ReceiptVerificationStatus.SIGNATURE_VALID:
            result = _receipt_failure_result(request.signed_receipt, receipt_result.status)
            self._audit(request=request, correlation_id=correlation_id, result=result)
            return result

        if not hmac.compare_digest(
            str(payload.account_id),
            str(request.authenticated_account_id),
        ):
            result = _result(
                status=ExecutionAuthorizationStatus.ACCOUNT_MISMATCH,
                signed_receipt=request.signed_receipt,
            )
            self._audit(request=request, correlation_id=correlation_id, result=result)
            return result

        if not hmac.compare_digest(
            payload.action_schema_version,
            request.proposed_action_schema_version,
        ):
            result = _result(
                status=ExecutionAuthorizationStatus.SCHEMA_MISMATCH,
                signed_receipt=request.signed_receipt,
            )
            self._audit(request=request, correlation_id=correlation_id, result=result)
            return result

        try:
            recomputed_action_hash = action_hash(
                material=request.proposed_material,
                binding_context=ActionBindingContext(
                    account_id=payload.account_id,
                    policy_version=payload.policy_version,
                    action_schema_version=payload.action_schema_version,
                    authorization_expires_at=payload.expires_at,
                ),
            )
        except CanonicalizationError:
            result = _result(
                status=ExecutionAuthorizationStatus.ACTION_MISMATCH,
                signed_receipt=request.signed_receipt,
            )
            self._audit(request=request, correlation_id=correlation_id, result=result)
            return result

        if not hmac.compare_digest(recomputed_action_hash, payload.action_hash):
            result = _result(
                status=ExecutionAuthorizationStatus.ACTION_MISMATCH,
                signed_receipt=request.signed_receipt,
                action_hash=payload.action_hash,
            )
            self._audit(request=request, correlation_id=correlation_id, result=result)
            return result

        if payload.policy_decision is not PolicyDecision.ALLOW:
            result = _result(
                status=ExecutionAuthorizationStatus.DECISION_NOT_ALLOWED,
                signed_receipt=request.signed_receipt,
                action_hash=payload.action_hash,
            )
            self._audit(request=request, correlation_id=correlation_id, result=result)
            return result

        result = _result(
            status=ExecutionAuthorizationStatus.AUTHORIZED,
            signed_receipt=request.signed_receipt,
            action_hash=payload.action_hash,
            executable=True,
        )
        self._audit(request=request, correlation_id=correlation_id, result=result)
        return result

    def _audit(
        self,
        *,
        request: ExecutionAuthorizationRequest,
        correlation_id: UUID,
        result: ExecutionAuthorizationResult,
    ) -> None:
        if self.audit_service is None:
            return
        event_type = (
            AuditEventType.EXECUTION_AUTHORIZATION_VALIDATED
            if result.status is ExecutionAuthorizationStatus.AUTHORIZED
            else AuditEventType.EXECUTION_AUTHORIZATION_REJECTED
        )
        self.audit_service.append_event(
            account_id=request.authenticated_account_id,
            event_type=event_type,
            correlation_id=correlation_id,
            request_id=result.authorization_request_id,
            payload={
                "receipt_id": result.receipt_id,
                "authorization_request_id": result.authorization_request_id,
                "action_hash": result.action_hash,
                "policy_decision": result.policy_decision,
                "reason_codes": [result.status.value],
            },
        )


def _receipt_failure_result(
    signed_receipt: SignedReceipt,
    receipt_status: ReceiptVerificationStatus,
) -> ExecutionAuthorizationResult:
    status = {
        ReceiptVerificationStatus.SIGNATURE_INVALID: (
            ExecutionAuthorizationStatus.INVALID_SIGNATURE
        ),
        ReceiptVerificationStatus.RECEIPT_EXPIRED: ExecutionAuthorizationStatus.EXPIRED_RECEIPT,
        ReceiptVerificationStatus.UNKNOWN_SIGNING_KEY: (
            ExecutionAuthorizationStatus.UNKNOWN_SIGNING_KEY
        ),
        ReceiptVerificationStatus.RECEIPT_MALFORMED: (
            ExecutionAuthorizationStatus.MALFORMED_RECEIPT
        ),
    }[receipt_status]
    return _result(status=status, signed_receipt=signed_receipt)


def _result(
    *,
    status: ExecutionAuthorizationStatus,
    signed_receipt: SignedReceipt,
    action_hash: str | None = None,
    executable: bool = False,
) -> ExecutionAuthorizationResult:
    payload = signed_receipt.payload
    return ExecutionAuthorizationResult(
        status=status,
        executable=executable,
        receipt_id=payload.receipt_id,
        authorization_request_id=payload.authorization_request_id,
        action_hash=action_hash or payload.action_hash,
        policy_decision=payload.policy_decision,
        verification_status=payload.verification_status,
        reason_code=status.value,
    )
