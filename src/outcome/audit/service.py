from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from outcome.db.models import AuditEvent


class AuditEventType(StrEnum):
    ACCOUNT_FUNDED = "account_funded"
    REQUEST_ACCEPTED = "request_accepted"
    POLICY_SELECTED = "policy_selected"
    PROVIDER_ATTEMPTED = "provider_attempted"
    EVIDENCE_NORMALIZATION_ACCEPTED = "evidence_normalization_accepted"
    EVIDENCE_NORMALIZATION_REJECTED = "evidence_normalization_rejected"
    EVIDENCE_TRUNCATED = "evidence_truncated"
    EVIDENCE_UNSAFE_SOURCE_REJECTED = "evidence_unsafe_source_rejected"
    EVIDENCE_EXTRACTION_FAILED = "evidence_extraction_failed"
    EVIDENCE_ACCEPTED = "evidence_accepted"
    EVIDENCE_REJECTED = "evidence_rejected"
    SCORE_COMPUTED = "score_computed"
    DECISION_MADE = "decision_made"
    CREDIT_RESERVED = "credit_reserved"
    CREDIT_SETTLED = "credit_settled"
    CREDIT_RELEASED = "credit_released"
    CREDIT_REFUND_ADJUSTMENT_CREATED = "credit_refund_adjustment_created"
    LEDGER_TRANSACTION_CREATED = "ledger_transaction_created"
    CAPABILITY_UNAVAILABLE = "capability_unavailable"
    PRICING_QUOTE_GENERATED = "pricing_quote_generated"
    PRICING_QUOTE_REJECTED = "pricing_quote_rejected"
    PROVIDER_RIGHTS_EVALUATED = "provider_rights_evaluated"
    PROVIDER_USE_ALLOWED = "provider_use_allowed"
    PROVIDER_USE_DENIED = "provider_use_denied"
    PROVIDER_RIGHTS_EXPIRED = "provider_rights_expired"
    PROVIDER_RIGHTS_UNKNOWN = "provider_rights_unknown"
    SECRET_REFERENCE_SELECTED = "secret_reference_selected"
    SECRET_RESOLUTION_ATTEMPTED = "secret_resolution_attempted"
    SECRET_RESOLUTION_DENIED = "secret_resolution_denied"
    SECRET_RESOLUTION_SUCCEEDED = "secret_resolution_succeeded"
    SECRET_CREDENTIAL_INACTIVE = "secret_credential_inactive"
    RECONCILIATION_MISMATCH = "reconciliation_mismatch"
    RESERVATION_EXPIRED = "reservation_expired"
    RESERVATION_SETTLED = "reservation_settled"
    SPEND_QUARANTINED = "spend_quarantined"
    RECEIPT_ISSUED = "receipt_issued"
    RECEIPT_VERIFICATION_SUCCEEDED = "receipt_verification_succeeded"
    RECEIPT_VERIFICATION_FAILED = "receipt_verification_failed"
    EXPIRED_RECEIPT_PRESENTED = "expired_receipt_presented"
    UNKNOWN_SIGNING_KEY = "unknown_signing_key"
    EXECUTION_AUTHORIZATION_VALIDATED = "execution_authorization_validated"
    EXECUTION_AUTHORIZATION_REJECTED = "execution_authorization_rejected"
    RECEIPT_CONSUMPTION_SUCCEEDED = "receipt_consumption_succeeded"
    RECEIPT_REPLAY_DETECTED = "receipt_replay_detected"
    RECEIPT_IDEMPOTENT_EXECUTION_REPLAY = "receipt_idempotent_execution_replay"
    RECEIPT_CONSUMPTION_CONFLICT = "receipt_consumption_conflict"
    RECEIPT_CONSUMPTION_SYSTEM_FAILURE = "receipt_consumption_system_failure"
    ESCALATION = "escalation"
    TIMEOUT = "timeout"
    PROVIDER_FAILURE = "provider_failure"
    SYSTEM_FAILURE = "system_failure"


class AuditPayloadRejected(ValueError):
    pass


class CrossTenantAuditAccess(PermissionError):
    pass


@dataclass(frozen=True)
class AuditTimelineEvent:
    id: UUID
    account_id: UUID
    request_id: UUID | None
    correlation_id: UUID
    event_type: AuditEventType
    payload: dict[str, object]
    created_at: datetime


ALLOWED_PAYLOAD_FIELDS = frozenset(
    {
        "account_id",
        "agent_credential_id",
        "agent_key_prefix",
        "request_id",
        "correlation_id",
        "event_type",
        "provider_alias",
        "provider_health",
        "provider_id",
        "secret_ref",
        "credential_type",
        "credential_state",
        "credential_version",
        "secret_resolution_status",
        "rights_status",
        "rights_version",
        "region",
        "verification_status",
        "policy_decision",
        "evidence_ref",
        "evidence_id",
        "evidence_hash",
        "evidence_type",
        "source_class",
        "extraction_quality",
        "content_hash",
        "byte_count",
        "character_count",
        "truncated",
        "cost_amount_minor",
        "currency",
        "latency_ms",
        "reason_codes",
        "receipt_id",
        "consumption_id",
        "execution_request_id",
        "billing_reservation_id",
        "available_micro_usd",
        "billing_mode",
        "capability",
        "provider_attempt_id",
        "verification_result_id",
        "authorization_result_id",
        "authorization_request_id",
        "action_hash",
        "score_basis_points",
        "timeout_ms",
        "error_code",
        "ledger_account",
        "ledger_transaction_id",
        "maximum_reserved_micro_usd",
        "pricing_config_version",
        "quoted_price_micro_usd",
        "receipt_version",
        "receipt_verification_status",
        "reservation_id",
        "reservation_state",
        "signing_key_id",
        "timestamp",
        "transaction_type",
    }
)

SENSITIVE_PAYLOAD_FIELDS = frozenset(
    {
        "api_key",
        "authorization",
        "authorization_header",
        "byok_credentials",
        "cookie",
        "cookies",
        "decrypted_provider_secret",
        "external_response",
        "html",
        "plaintext_api_key",
        "raw_byok_credentials",
        "raw_evidence",
        "raw_html",
        "response_body",
        "stripe_secret",
        "stripe_signature",
    }
)


class AuditService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def append_event(
        self,
        *,
        account_id: UUID,
        event_type: AuditEventType,
        correlation_id: UUID,
        request_id: UUID | None = None,
        payload: dict[str, object] | None = None,
    ) -> AuditTimelineEvent:
        normalized_payload = self._normalize_payload(
            account_id=account_id,
            event_type=event_type,
            correlation_id=correlation_id,
            request_id=request_id,
            payload=payload or {},
        )
        event = AuditEvent(
            id=uuid4(),
            account_id=account_id,
            request_id=request_id,
            event_type=event_type.value,
            actor_hash=self._actor_hash(normalized_payload),
            payload=normalized_payload,
        )
        self.session.add(event)
        self.session.flush()
        return self._to_timeline_event(event)

    def timeline_for_correlation(
        self,
        *,
        account_id: UUID,
        correlation_id: UUID,
    ) -> tuple[AuditTimelineEvent, ...]:
        events = self.session.scalars(
            select(AuditEvent).where(AuditEvent.account_id == account_id)
        ).all()
        timeline = tuple(
            self._to_timeline_event(event)
            for event in sorted(
                events,
                key=lambda event: (
                    str(event.payload.get("timestamp", "")),
                    event.created_at,
                    str(event.id),
                ),
            )
            if event.payload.get("correlation_id") == str(correlation_id)
        )
        if timeline:
            return timeline

        any_tenant_events = self.session.scalars(select(AuditEvent)).all()
        if any(
            event.account_id != account_id
            and event.payload.get("correlation_id") == str(correlation_id)
            for event in any_tenant_events
        ):
            raise CrossTenantAuditAccess("correlation_id belongs to a different account")

        return ()

    def _normalize_payload(
        self,
        *,
        account_id: UUID,
        event_type: AuditEventType,
        correlation_id: UUID,
        request_id: UUID | None,
        payload: dict[str, object],
    ) -> dict[str, object]:
        rejected_fields = {
            field for field in payload if field.lower() in SENSITIVE_PAYLOAD_FIELDS
        }
        rejected_fields |= set(payload) - ALLOWED_PAYLOAD_FIELDS
        if rejected_fields:
            fields = ", ".join(sorted(rejected_fields))
            raise AuditPayloadRejected(f"audit payload contains disallowed fields: {fields}")

        normalized = {
            key: self._normalize_value(value)
            for key, value in payload.items()
            if value is not None
        }
        normalized["account_id"] = str(account_id)
        normalized["correlation_id"] = str(correlation_id)
        normalized["event_type"] = event_type.value
        normalized["timestamp"] = datetime.now(UTC).isoformat()
        if request_id is not None:
            normalized["request_id"] = str(request_id)

        return normalized

    def _to_timeline_event(self, event: AuditEvent) -> AuditTimelineEvent:
        correlation_id_value = event.payload["correlation_id"]
        return AuditTimelineEvent(
            id=event.id,
            account_id=event.account_id,
            request_id=event.request_id,
            correlation_id=UUID(str(correlation_id_value)),
            event_type=AuditEventType(event.event_type),
            payload=dict(event.payload),
            created_at=event.created_at,
        )

    def _actor_hash(self, payload: dict[str, object]) -> str | None:
        agent_credential_id = payload.get("agent_credential_id")
        if agent_credential_id is None:
            return None
        return str(agent_credential_id)

    def _normalize_value(self, value: object) -> object:
        if isinstance(value, UUID):
            return str(value)
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, StrEnum):
            return value.value
        if isinstance(value, list):
            return [self._normalize_value(item) for item in value]
        if isinstance(value, dict):
            return {
                str(key): self._normalize_value(nested_value)
                for key, nested_value in value.items()
            }
        return value
