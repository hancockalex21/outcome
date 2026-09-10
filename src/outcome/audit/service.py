from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from outcome.db.models import AuditEvent


class AuditEventType(StrEnum):
    REQUEST_ACCEPTED = "request_accepted"
    POLICY_SELECTED = "policy_selected"
    PROVIDER_ATTEMPTED = "provider_attempted"
    EVIDENCE_ACCEPTED = "evidence_accepted"
    EVIDENCE_REJECTED = "evidence_rejected"
    SCORE_COMPUTED = "score_computed"
    DECISION_MADE = "decision_made"
    CREDIT_RESERVED = "credit_reserved"
    CREDIT_SETTLED = "credit_settled"
    CREDIT_RELEASED = "credit_released"
    RECEIPT_ISSUED = "receipt_issued"
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
        "verification_status",
        "policy_decision",
        "evidence_ref",
        "evidence_hash",
        "evidence_type",
        "cost_amount_minor",
        "currency",
        "latency_ms",
        "reason_codes",
        "receipt_id",
        "billing_reservation_id",
        "provider_attempt_id",
        "verification_result_id",
        "authorization_result_id",
        "score_basis_points",
        "timeout_ms",
        "error_code",
        "timestamp",
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
