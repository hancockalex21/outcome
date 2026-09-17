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
    POLICY_EVALUATION_STARTED = "policy_evaluation_started"
    POLICY_RULE_MATCHED = "policy_rule_matched"
    POLICY_DECISION_PRODUCED = "policy_decision_produced"
    POLICY_BLOCKED_ACTION = "policy_blocked_action"
    POLICY_HIGHER_ASSURANCE_REQUIRED = "policy_higher_assurance_required"
    POLICY_ESCALATION_REQUIRED = "policy_escalation_required"
    POLICY_INVALID_OR_DISABLED = "policy_invalid_or_disabled"
    PROVIDER_ATTEMPTED = "provider_attempted"
    EVIDENCE_NORMALIZATION_ACCEPTED = "evidence_normalization_accepted"
    EVIDENCE_NORMALIZATION_REJECTED = "evidence_normalization_rejected"
    EVIDENCE_TRUNCATED = "evidence_truncated"
    EVIDENCE_UNSAFE_SOURCE_REJECTED = "evidence_unsafe_source_rejected"
    EVIDENCE_EXTRACTION_FAILED = "evidence_extraction_failed"
    EVIDENCE_LINEAGE_RECORDED = "evidence_lineage_recorded"
    EVIDENCE_LINEAGE_RELATIONSHIP_REJECTED = "evidence_lineage_relationship_rejected"
    EVIDENCE_INDEPENDENCE_EVALUATED = "evidence_independence_evaluated"
    EVIDENCE_SHARED_ORIGIN_DETECTED = "evidence_shared_origin_detected"
    EVIDENCE_UNKNOWN_LINEAGE_ENCOUNTERED = "evidence_unknown_lineage_encountered"
    EVIDENCE_ACCEPTED = "evidence_accepted"
    EVIDENCE_REJECTED = "evidence_rejected"
    SCORE_COMPUTED = "score_computed"
    EVIDENCE_EXCLUDED_FROM_SCORING = "evidence_excluded_from_scoring"
    VERIFICATION_STATUS_DERIVED = "verification_status_derived"
    DECISION_MADE = "decision_made"
    CREDIT_RESERVED = "credit_reserved"
    CREDIT_SETTLED = "credit_settled"
    CREDIT_RELEASED = "credit_released"
    CREDIT_REFUND_ADJUSTMENT_CREATED = "credit_refund_adjustment_created"
    LEDGER_TRANSACTION_CREATED = "ledger_transaction_created"
    FUNDING_CREATED = "funding_created"
    FUNDING_GATEWAY_OBJECT_CREATED = "funding_gateway_object_created"
    PAYMENT_WEBHOOK_RECEIVED = "payment_webhook_received"
    PAYMENT_WEBHOOK_VERIFIED = "payment_webhook_verified"
    PAYMENT_WEBHOOK_REJECTED = "payment_webhook_rejected"
    FUNDING_SUCCEEDED = "funding_succeeded"
    FUNDING_FAILED = "funding_failed"
    FUNDING_RECONCILIATION_REQUIRED = "funding_reconciliation_required"
    BILLING_QUOTED = "billing_quoted"
    BILLING_RESERVED = "billing_reserved"
    BILLING_RESERVATION_FAILED = "billing_reservation_failed"
    BILLING_IN_PROGRESS = "billing_in_progress"
    BILLING_SETTLED = "billing_settled"
    BILLING_RELEASED = "billing_released"
    BILLING_RECONCILIATION_REQUIRED = "billing_reconciliation_required"
    CAPABILITY_UNAVAILABLE = "capability_unavailable"
    PRICING_QUOTE_GENERATED = "pricing_quote_generated"
    PRICING_QUOTE_REJECTED = "pricing_quote_rejected"
    PROVIDER_RIGHTS_EVALUATED = "provider_rights_evaluated"
    PROVIDER_USE_ALLOWED = "provider_use_allowed"
    PROVIDER_USE_DENIED = "provider_use_denied"
    PROVIDER_RIGHTS_EXPIRED = "provider_rights_expired"
    PROVIDER_RIGHTS_UNKNOWN = "provider_rights_unknown"
    PROVIDER_HEALTH_EVALUATED = "provider_health_evaluated"
    PROVIDER_DEGRADED = "provider_degraded"
    PROVIDER_CIRCUIT_OPENED = "provider_circuit_opened"
    PROVIDER_CIRCUIT_PROBE_ATTEMPTED = "provider_circuit_probe_attempted"
    PROVIDER_CIRCUIT_RECOVERED = "provider_circuit_recovered"
    PROVIDER_MANUALLY_DISABLED = "provider_manually_disabled"
    PROVIDER_USE_BLOCKED_BY_HEALTH = "provider_use_blocked_by_health"
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
    VERIFICATION_RECEIVED = "verification_received"
    VERIFICATION_PROVIDER_ELIGIBILITY_EVALUATED = (
        "verification_provider_eligibility_evaluated"
    )
    VERIFICATION_PROVIDER_ATTEMPT_STARTED = "verification_provider_attempt_started"
    VERIFICATION_PROVIDER_ATTEMPT_COMPLETED = "verification_provider_attempt_completed"
    VERIFICATION_LINEAGE_COMPLETED = "verification_lineage_completed"
    VERIFICATION_EVIDENCE_ASSESSMENT_COMPLETED = (
        "verification_evidence_assessment_completed"
    )
    VERIFICATION_COMPLETED = "verification_completed"
    VERIFICATION_FAILED = "verification_failed"
    VERIFICATION_IDEMPOTENT_REPLAY = "verification_idempotent_replay"
    VERIFICATION_IDEMPOTENCY_CONFLICT = "verification_idempotency_conflict"
    VERIFICATION_COLLECTION_PLANNED = "verification_collection_planned"
    VERIFICATION_COLLECTION_COMPLETED = "verification_collection_completed"
    VERIFICATION_COLLECTION_DEADLINE_REACHED = "verification_collection_deadline_reached"
    PROVIDER_ATTEMPT_STARTED = "provider_attempt_started"
    PROVIDER_ATTEMPT_SUCCEEDED = "provider_attempt_succeeded"
    PROVIDER_ATTEMPT_TIMED_OUT = "provider_attempt_timed_out"
    PROVIDER_ATTEMPT_FAILED = "provider_attempt_failed"
    PROVIDER_ATTEMPT_RATE_LIMITED = "provider_attempt_rate_limited"
    PROVIDER_EXECUTION_PREPARED = "provider_execution_prepared"
    PROVIDER_EXECUTION_STARTED = "provider_execution_started"
    PROVIDER_SECRET_REFERENCE_VALIDATED = "provider_secret_reference_validated"
    PROVIDER_EXECUTION_SUCCEEDED = "provider_execution_succeeded"
    PROVIDER_EXECUTION_FAILED = "provider_execution_failed"
    PROVIDER_EXECUTION_REJECTED = "provider_execution_rejected"
    AUTHORIZATION_RECEIVED = "authorization_received"
    AUTHORIZATION_VALIDATED = "authorization_validated"
    AUTHORIZATION_VERIFICATION_COMPLETED = "authorization_verification_completed"
    AUTHORIZATION_POLICY_EVALUATED = "authorization_policy_evaluated"
    AUTHORIZATION_DECISION_PRODUCED = "authorization_decision_produced"
    AUTHORIZATION_RECEIPT_ISSUED = "authorization_receipt_issued"
    AUTHORIZATION_COMPLETED = "authorization_completed"
    AUTHORIZATION_FAILED = "authorization_failed"
    AUTHORIZATION_IDEMPOTENT_REPLAY = "authorization_idempotent_replay"
    AUTHORIZATION_IDEMPOTENCY_CONFLICT = "authorization_idempotency_conflict"
    MCP_TOOL_INVOKED = "mcp_tool_invoked"
    MCP_TOOL_COMPLETED = "mcp_tool_completed"
    MCP_TOOL_REJECTED = "mcp_tool_rejected"


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
        "request_fingerprint",
        "idempotency_key",
        "correlation_id",
        "event_type",
        "lifecycle_state",
        "request_config_version",
        "policy_id",
        "policy_version",
        "policy_hash",
        "matched_rule_ids",
        "assurance_level",
        "required_assurance",
        "escalation_strategy",
        "provider_alias",
        "provider_health",
        "provider_id",
        "circuit_state",
        "retry_after",
        "next_probe_at",
        "metrics_version",
        "window_start",
        "window_end",
        "request_count",
        "success_count",
        "failure_count",
        "timeout_count",
        "consecutive_failures",
        "rate_limited_count",
        "system_failure_count",
        "manually_disabled",
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
        "left_evidence_id",
        "right_evidence_id",
        "parent_evidence_id",
        "child_evidence_id",
        "source_class",
        "lineage_type",
        "lineage_version",
        "relationship_type",
        "independence_result",
        "shared_origin",
        "source_identity_hash",
        "origin_reference",
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
        "funding_id",
        "billing_id",
        "payment_event_id",
        "external_payment_id",
        "billing_reservation_id",
        "available_micro_usd",
        "billing_mode",
        "execution_mode",
        "capability",
        "credential_ref_hash",
        "provider_attempt_id",
        "provider_outcome",
        "planned_provider_ids",
        "planned_order",
        "attempt_number",
        "timeout_ms",
        "deadline_exceeded",
        "health_effect",
        "execution_plan_version",
        "transport_version",
        "max_providers",
        "max_concurrency",
        "overall_deadline_ms",
        "verification_result_id",
        "verification_request_id",
        "authorization_result_id",
        "authorization_request_id",
        "action_hash",
        "material_hash",
        "authorization_lifetime_seconds",
        "score_basis_points",
        "evidence_score_version",
        "evidence_count",
        "independent_evidence_count",
        "source_authority_component",
        "extraction_quality_component",
        "independence_component",
        "corroboration_component",
        "contradiction_component",
        "freshness_component",
        "coverage_component",
        "final_score",
        "evidence_ids_used",
        "evidence_ids_excluded",
        "providers_contributed",
        "providers_failed",
        "lineage_versions",
        "error_code",
        "ledger_account",
        "ledger_transaction_id",
        "maximum_reserved_micro_usd",
        "actual_charge_micro_usd",
        "billing_state",
        "pricing_config_version",
        "quoted_price_micro_usd",
        "receipt_version",
        "receipt_verification_status",
        "reservation_id",
        "reservation_state",
        "signing_key_id",
        "timestamp",
        "transaction_type",
        "duration_ms",
        "mcp_tool_name",
        "mcp_tool_version",
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
