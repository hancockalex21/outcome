from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from outcome.actions.material import (
    ACTION_SCHEMA_VERSION,
    CanonicalizationError,
    material_action_hash,
)
from outcome.audit import AuditEventType, AuditService
from outcome.db.models import Policy, VerificationResult
from outcome.domain import AssuranceLevel, EscalationStrategy, PolicyDecision, VerificationStatus

POLICY_SCHEMA_VERSION = "policy.v1"
POLICY_STATUS_PUBLISHED = "PUBLISHED"


class PolicyValidationError(ValueError):
    pass


class PolicyEvaluationError(ValueError):
    pass


class PublishedPolicyImmutable(PolicyValidationError):
    pass


class CrossTenantPolicyAccess(PermissionError):
    pass


class PolicyRuleEffect(StrEnum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    ESCALATE = "ESCALATE"


class PolicyEvaluationReason(StrEnum):
    POLICY_ALLOWED = "POLICY_ALLOWED"
    POLICY_DISABLED = "POLICY_DISABLED"
    NO_MATCHING_ALLOW_RULE = "NO_MATCHING_ALLOW_RULE"
    EXPLICIT_BLOCK_RULE = "EXPLICIT_BLOCK_RULE"
    UNKNOWN_CAPABILITY = "UNKNOWN_CAPABILITY"
    UNSUPPORTED_ACTION_SCHEMA = "UNSUPPORTED_ACTION_SCHEMA"
    VERIFICATION_REQUIRED = "VERIFICATION_REQUIRED"
    VERIFICATION_CONTRADICTED = "VERIFICATION_CONTRADICTED"
    VERIFICATION_INCONCLUSIVE = "VERIFICATION_INCONCLUSIVE"
    PROVIDER_FAILURE = "PROVIDER_FAILURE"
    SYSTEM_FAILURE = "SYSTEM_FAILURE"
    ASSURANCE_INSUFFICIENT = "ASSURANCE_INSUFFICIENT"
    ACTION_LIMIT_EXCEEDED = "ACTION_LIMIT_EXCEEDED"
    DESTINATION_NOT_ALLOWED = "DESTINATION_NOT_ALLOWED"
    TIME_CONSTRAINT_VIOLATION = "TIME_CONSTRAINT_VIOLATION"
    INVALID_POLICY = "INVALID_POLICY"


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    effect: PolicyRuleEffect
    action_types: tuple[str, ...] = ()
    capabilities: tuple[str, ...] = ()
    required_verification_status: VerificationStatus | None = None
    minimum_evidence_score: int | None = None
    required_assurance: AssuranceLevel | None = None
    max_amount_micro_usd: int | None = None
    allowed_destinations: tuple[str, ...] = ()
    blocked_destinations: tuple[str, ...] = ()
    expires_at: datetime | None = None
    escalation_strategy: EscalationStrategy | None = None
    inconclusive_decision: PolicyDecision = PolicyDecision.RETRY_HIGHER_ASSURANCE
    provider_failure_decision: PolicyDecision = PolicyDecision.ESCALATE
    limit_exceeded_decision: PolicyDecision = PolicyDecision.BLOCK


@dataclass(frozen=True)
class DeterministicPolicy:
    policy_id: UUID
    account_id: UUID
    name: str
    version: int
    enabled: bool
    action_schema_version: str
    rules: tuple[PolicyRule, ...]
    policy_schema_version: str = POLICY_SCHEMA_VERSION
    effective_at: datetime | None = None


@dataclass(frozen=True)
class PolicyVerificationReference:
    verification_result_id: UUID
    verification_request_id: UUID
    status: VerificationStatus
    evidence_score_basis_points: int | None
    evidence_score_version: str | None


@dataclass(frozen=True)
class PolicyEvaluationRequest:
    account_id: UUID
    policy_id: UUID
    policy_version: int
    material_action: Mapping[str, object]
    action_schema_version: str
    assurance_level: AssuranceLevel
    verification: PolicyVerificationReference | None = None
    request_context: Mapping[str, object] | None = None
    evaluated_at: datetime | None = None
    ephemeral: Mapping[str, object] | None = None


@dataclass(frozen=True)
class PolicyEvaluationResult:
    decision: PolicyDecision
    policy_id: UUID
    policy_version: int
    policy_hash: str
    matched_rule_ids: tuple[str, ...]
    reason_codes: tuple[PolicyEvaluationReason, ...]
    required_assurance: AssuranceLevel | None
    escalation_strategy: EscalationStrategy | None
    action_hash: str
    verification_result_id: UUID | None
    verification_request_id: UUID | None
    verification_status: VerificationStatus | None
    evidence_score_basis_points: int | None
    evidence_score_version: str | None
    evaluated_at: datetime


class PolicyEvaluationService:
    def __init__(
        self,
        session: Session,
        audit_service: AuditService | None = None,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.session = session
        self.audit_service = audit_service or AuditService(session)
        self.clock = clock or (lambda: datetime.now(UTC))

    def publish(self, policy: DeterministicPolicy) -> Policy:
        validate_policy(policy)
        policy_hash = canonical_policy_hash(policy)
        existing = self.session.get(Policy, policy.policy_id)
        if existing is not None:
            if existing.account_id != policy.account_id:
                raise CrossTenantPolicyAccess("policy belongs to a different account")
            if existing.policy_hash != policy_hash or existing.version != policy.version:
                raise PublishedPolicyImmutable("published policy versions are immutable")
            return existing
        now = _aware_utc(self.clock())
        row = Policy(
            id=policy.policy_id,
            account_id=policy.account_id,
            name=policy.name,
            version=policy.version,
            body=policy_to_json(policy),
            status=POLICY_STATUS_PUBLISHED if policy.enabled else "DISABLED",
            policy_hash=policy_hash,
            effective_at=policy.effective_at or now,
            published_at=now,
        )
        self.session.add(row)
        self.session.flush()
        return row

    def evaluate(
        self,
        request: PolicyEvaluationRequest,
        *,
        correlation_id: UUID,
    ) -> PolicyEvaluationResult:
        evaluated_at = _aware_utc(request.evaluated_at or self.clock())
        action_hash = self._material_hash(request)
        policy_row = self._load_policy(request)
        self._audit(
            account_id=request.account_id,
            event_type=AuditEventType.POLICY_EVALUATION_STARTED,
            correlation_id=correlation_id,
            policy_id=request.policy_id,
            policy_version=request.policy_version,
            policy_hash=policy_row.policy_hash,
            action_hash=action_hash,
            decision=None,
            reason_codes=[],
        )
        policy = policy_from_model(policy_row)
        result = self._evaluate_policy(
            policy=policy,
            policy_hash=policy_row.policy_hash or canonical_policy_hash(policy),
            request=request,
            action_hash=action_hash,
            evaluated_at=evaluated_at,
        )
        self._audit_result(request.account_id, result, correlation_id)
        return result

    def _evaluate_policy(
        self,
        *,
        policy: DeterministicPolicy,
        policy_hash: str,
        request: PolicyEvaluationRequest,
        action_hash: str,
        evaluated_at: datetime,
    ) -> PolicyEvaluationResult:
        if not policy.enabled:
            return _result(
                request=request,
                policy_hash=policy_hash,
                action_hash=action_hash,
                evaluated_at=evaluated_at,
                decision=PolicyDecision.BLOCK,
                reasons=(PolicyEvaluationReason.POLICY_DISABLED,),
            )
        if request.action_schema_version != policy.action_schema_version:
            return _result(
                request=request,
                policy_hash=policy_hash,
                action_hash=action_hash,
                evaluated_at=evaluated_at,
                decision=PolicyDecision.BLOCK,
                reasons=(PolicyEvaluationReason.UNSUPPORTED_ACTION_SCHEMA,),
            )
        if (
            request.verification is not None
            and request.verification.status is VerificationStatus.SYSTEM_FAILURE
        ):
            return _result(
                request=request,
                policy_hash=policy_hash,
                action_hash=action_hash,
                evaluated_at=evaluated_at,
                decision=PolicyDecision.BLOCK,
                reasons=(PolicyEvaluationReason.SYSTEM_FAILURE,),
            )

        matching_rules = [rule for rule in policy.rules if _rule_matches_action(rule, request)]
        explicit_blocks = [rule for rule in matching_rules if rule.effect is PolicyRuleEffect.BLOCK]
        if explicit_blocks:
            return _result_for_rule(
                request,
                policy_hash,
                action_hash,
                evaluated_at,
                explicit_blocks[0],
                PolicyDecision.BLOCK,
                PolicyEvaluationReason.EXPLICIT_BLOCK_RULE,
            )

        allow_rules = [rule for rule in matching_rules if rule.effect is PolicyRuleEffect.ALLOW]
        if not allow_rules:
            reason = (
                PolicyEvaluationReason.UNKNOWN_CAPABILITY
                if _action_capability(request) is None
                else PolicyEvaluationReason.NO_MATCHING_ALLOW_RULE
            )
            return _result(
                request=request,
                policy_hash=policy_hash,
                action_hash=action_hash,
                evaluated_at=evaluated_at,
                decision=PolicyDecision.BLOCK,
                reasons=(reason,),
            )

        rule = allow_rules[0]
        verification_result = self._verification_decision(request, rule)
        if verification_result is not None:
            decision, reason = verification_result
            return _result_for_rule(
                request,
                policy_hash,
                action_hash,
                evaluated_at,
                rule,
                decision,
                reason,
            )
        if rule.expires_at is not None and _aware_utc(rule.expires_at) <= evaluated_at:
            return _result_for_rule(
                request,
                policy_hash,
                action_hash,
                evaluated_at,
                rule,
                PolicyDecision.BLOCK,
                PolicyEvaluationReason.TIME_CONSTRAINT_VIOLATION,
            )
        if _assurance_rank(request.assurance_level) < _assurance_rank(
            rule.required_assurance or AssuranceLevel.LOW
        ):
            return _result_for_rule(
                request,
                policy_hash,
                action_hash,
                evaluated_at,
                rule,
                PolicyDecision.RETRY_HIGHER_ASSURANCE,
                PolicyEvaluationReason.ASSURANCE_INSUFFICIENT,
            )
        limit_result = _limit_decision(request, rule)
        if limit_result is not None:
            return _result_for_rule(
                request,
                policy_hash,
                action_hash,
                evaluated_at,
                rule,
                limit_result,
                PolicyEvaluationReason.ACTION_LIMIT_EXCEEDED,
            )
        if not _destination_allowed(request, rule):
            return _result_for_rule(
                request,
                policy_hash,
                action_hash,
                evaluated_at,
                rule,
                PolicyDecision.BLOCK,
                PolicyEvaluationReason.DESTINATION_NOT_ALLOWED,
            )
        return _result_for_rule(
            request,
            policy_hash,
            action_hash,
            evaluated_at,
            rule,
            PolicyDecision.ALLOW,
            PolicyEvaluationReason.POLICY_ALLOWED,
        )

    def _verification_decision(
        self,
        request: PolicyEvaluationRequest,
        rule: PolicyRule,
    ) -> tuple[PolicyDecision, PolicyEvaluationReason] | None:
        if (
            rule.required_verification_status is None
            and rule.minimum_evidence_score is None
        ):
            return None
        if request.verification is None:
            return PolicyDecision.BLOCK, PolicyEvaluationReason.VERIFICATION_REQUIRED
        verification = request.verification
        if verification.status is VerificationStatus.SYSTEM_FAILURE:
            return PolicyDecision.BLOCK, PolicyEvaluationReason.SYSTEM_FAILURE
        if verification.status is VerificationStatus.PROVIDER_FAILED:
            return rule.provider_failure_decision, PolicyEvaluationReason.PROVIDER_FAILURE
        if verification.status is VerificationStatus.CONTRADICTED:
            return PolicyDecision.BLOCK, PolicyEvaluationReason.VERIFICATION_CONTRADICTED
        if verification.status is VerificationStatus.INCONCLUSIVE:
            return rule.inconclusive_decision, PolicyEvaluationReason.VERIFICATION_INCONCLUSIVE
        if (
            rule.required_verification_status is not None
            and verification.status is not rule.required_verification_status
        ):
            return PolicyDecision.BLOCK, PolicyEvaluationReason.VERIFICATION_REQUIRED
        if (
            rule.minimum_evidence_score is not None
            and (verification.evidence_score_basis_points or 0) < rule.minimum_evidence_score
        ):
            return (
                PolicyDecision.RETRY_HIGHER_ASSURANCE,
                PolicyEvaluationReason.VERIFICATION_INCONCLUSIVE,
            )
        return None

    def _load_policy(self, request: PolicyEvaluationRequest) -> Policy:
        policy = self.session.scalar(
            select(Policy).where(
                Policy.account_id == request.account_id,
                Policy.id == request.policy_id,
                Policy.version == request.policy_version,
            )
        )
        if policy is not None:
            return policy
        cross_tenant = self.session.get(Policy, request.policy_id)
        if cross_tenant is not None and cross_tenant.account_id != request.account_id:
            raise CrossTenantPolicyAccess("policy belongs to a different account")
        raise PolicyEvaluationError("policy not found")

    def _material_hash(self, request: PolicyEvaluationRequest) -> str:
        if request.action_schema_version != ACTION_SCHEMA_VERSION:
            return hashlib.sha256(request.action_schema_version.encode("utf-8")).hexdigest()
        try:
            return material_action_hash(
                material=request.material_action,
                action_schema_version=request.action_schema_version,
            )
        except CanonicalizationError as exc:
            raise PolicyEvaluationError("invalid material action") from exc

    def _audit_result(
        self,
        account_id: UUID,
        result: PolicyEvaluationResult,
        correlation_id: UUID,
    ) -> None:
        event_type = AuditEventType.POLICY_DECISION_PRODUCED
        if any(
            reason
            in {
                PolicyEvaluationReason.POLICY_DISABLED,
                PolicyEvaluationReason.INVALID_POLICY,
                PolicyEvaluationReason.UNSUPPORTED_ACTION_SCHEMA,
            }
            for reason in result.reason_codes
        ):
            event_type = AuditEventType.POLICY_INVALID_OR_DISABLED
        elif result.decision is PolicyDecision.BLOCK:
            event_type = AuditEventType.POLICY_BLOCKED_ACTION
        elif result.decision is PolicyDecision.RETRY_HIGHER_ASSURANCE:
            event_type = AuditEventType.POLICY_HIGHER_ASSURANCE_REQUIRED
        elif result.decision is PolicyDecision.ESCALATE:
            event_type = AuditEventType.POLICY_ESCALATION_REQUIRED
        if result.matched_rule_ids:
            self._audit(
                account_id=account_id,
                event_type=AuditEventType.POLICY_RULE_MATCHED,
                correlation_id=correlation_id,
                policy_id=result.policy_id,
                policy_version=result.policy_version,
                policy_hash=result.policy_hash,
                action_hash=result.action_hash,
                decision=result.decision,
                reason_codes=[reason.value for reason in result.reason_codes],
                matched_rule_ids=list(result.matched_rule_ids),
                verification=result,
            )
        self._audit(
            account_id=account_id,
            event_type=event_type,
            correlation_id=correlation_id,
            policy_id=result.policy_id,
            policy_version=result.policy_version,
            policy_hash=result.policy_hash,
            action_hash=result.action_hash,
            decision=result.decision,
            reason_codes=[reason.value for reason in result.reason_codes],
            matched_rule_ids=list(result.matched_rule_ids),
            verification=result,
        )

    def _audit(
        self,
        *,
        account_id: UUID,
        event_type: AuditEventType,
        correlation_id: UUID,
        policy_id: UUID,
        policy_version: int,
        policy_hash: str | None,
        action_hash: str,
        decision: PolicyDecision | None,
        reason_codes: list[str],
        matched_rule_ids: list[str] | None = None,
        verification: PolicyEvaluationResult | None = None,
    ) -> None:
        payload: dict[str, object] = {
            "policy_id": policy_id,
            "policy_version": policy_version,
            "policy_hash": policy_hash,
            "action_hash": action_hash,
            "reason_codes": reason_codes,
        }
        if decision is not None:
            payload["policy_decision"] = decision
        if matched_rule_ids is not None:
            payload["matched_rule_ids"] = matched_rule_ids
        if verification is not None:
            payload["required_assurance"] = verification.required_assurance
            payload["escalation_strategy"] = verification.escalation_strategy
            payload["verification_result_id"] = verification.verification_result_id
            payload["verification_request_id"] = verification.verification_request_id
            payload["verification_status"] = verification.verification_status
            payload["score_basis_points"] = verification.evidence_score_basis_points
            payload["evidence_score_version"] = verification.evidence_score_version
        self.audit_service.append_event(
            account_id=account_id,
            event_type=event_type,
            correlation_id=correlation_id,
            payload=payload,
        )


def validate_policy(policy: DeterministicPolicy) -> None:
    if policy.policy_schema_version != POLICY_SCHEMA_VERSION:
        raise PolicyValidationError("unsupported policy schema version")
    if policy.action_schema_version != ACTION_SCHEMA_VERSION:
        raise PolicyValidationError("unsupported action schema version")
    seen: set[str] = set()
    for rule in policy.rules:
        if not rule.rule_id:
            raise PolicyValidationError("rule_id is required")
        if rule.rule_id in seen:
            raise PolicyValidationError("duplicate rule_id")
        seen.add(rule.rule_id)
        if rule.minimum_evidence_score is not None:
            _validate_score(rule.minimum_evidence_score)
        if rule.max_amount_micro_usd is not None:
            _validate_safe_int(rule.max_amount_micro_usd)
        if rule.expires_at is not None:
            _aware_utc(rule.expires_at)


def canonical_policy_hash(policy: DeterministicPolicy) -> str:
    validate_policy(policy)
    try:
        canonical = material_action_hash(
            material=policy_to_json(policy),
            action_schema_version=POLICY_SCHEMA_VERSION,
        )
    except CanonicalizationError as exc:
        raise PolicyValidationError("policy contains unsafe canonical values") from exc
    return canonical


def policy_to_json(policy: DeterministicPolicy) -> dict[str, object]:
    return {
        "action_schema_version": policy.action_schema_version,
        "enabled": policy.enabled,
        "policy_schema_version": policy.policy_schema_version,
        "rules": [
            {
                "allowed_destinations": list(rule.allowed_destinations),
                "blocked_destinations": list(rule.blocked_destinations),
                "capabilities": list(rule.capabilities),
                "action_types": list(rule.action_types),
                "effect": rule.effect.value,
                "escalation_strategy": (
                    rule.escalation_strategy.value if rule.escalation_strategy else None
                ),
                "expires_at": _timestamp(rule.expires_at),
                "inconclusive_decision": rule.inconclusive_decision.value,
                "limit_exceeded_decision": rule.limit_exceeded_decision.value,
                "max_amount_micro_usd": rule.max_amount_micro_usd,
                "minimum_evidence_score": rule.minimum_evidence_score,
                "provider_failure_decision": rule.provider_failure_decision.value,
                "required_assurance": (
                    rule.required_assurance.value if rule.required_assurance else None
                ),
                "required_verification_status": (
                    rule.required_verification_status.value
                    if rule.required_verification_status
                    else None
                ),
                "rule_id": rule.rule_id,
            }
            for rule in policy.rules
        ],
        "version": policy.version,
    }


def policy_from_model(policy: Policy) -> DeterministicPolicy:
    body = policy.body
    rules_value = body.get("rules")
    if not isinstance(rules_value, list):
        raise PolicyEvaluationError("invalid policy body")
    return DeterministicPolicy(
        policy_id=policy.id,
        account_id=policy.account_id,
        name=policy.name,
        version=policy.version,
        enabled=policy.status == POLICY_STATUS_PUBLISHED and body.get("enabled") is True,
        action_schema_version=_string(body.get("action_schema_version")),
        policy_schema_version=_string(body.get("policy_schema_version")),
        rules=tuple(_rule_from_json(rule) for rule in rules_value if isinstance(rule, dict)),
        effective_at=policy.effective_at,
    )


def verification_reference_from_model(result: VerificationResult) -> PolicyVerificationReference:
    return PolicyVerificationReference(
        verification_result_id=result.id,
        verification_request_id=result.verification_request_id,
        status=VerificationStatus(result.status),
        evidence_score_basis_points=result.evidence_score_basis_points,
        evidence_score_version=result.evidence_score_version,
    )


def _rule_from_json(value: Mapping[str, object]) -> PolicyRule:
    return PolicyRule(
        rule_id=_string(value.get("rule_id")),
        effect=PolicyRuleEffect(_string(value.get("effect"))),
        action_types=_strings(value.get("action_types")),
        capabilities=_strings(value.get("capabilities")),
        required_verification_status=_optional_enum(
            VerificationStatus,
            value.get("required_verification_status"),
        ),
        minimum_evidence_score=_optional_int(value.get("minimum_evidence_score")),
        required_assurance=_optional_enum(AssuranceLevel, value.get("required_assurance")),
        max_amount_micro_usd=_optional_int(value.get("max_amount_micro_usd")),
        allowed_destinations=_strings(value.get("allowed_destinations")),
        blocked_destinations=_strings(value.get("blocked_destinations")),
        expires_at=_optional_datetime(value.get("expires_at")),
        escalation_strategy=_optional_enum(EscalationStrategy, value.get("escalation_strategy")),
        inconclusive_decision=PolicyDecision(_string(value.get("inconclusive_decision"))),
        provider_failure_decision=PolicyDecision(_string(value.get("provider_failure_decision"))),
        limit_exceeded_decision=PolicyDecision(_string(value.get("limit_exceeded_decision"))),
    )


def _rule_matches_action(rule: PolicyRule, request: PolicyEvaluationRequest) -> bool:
    action_type = _action_type(request)
    capability = _action_capability(request)
    action_match = not rule.action_types or action_type in set(rule.action_types)
    capability_match = not rule.capabilities or capability in set(rule.capabilities)
    return action_match and capability_match


def _action_type(request: PolicyEvaluationRequest) -> str | None:
    value = request.material_action.get("action_type")
    return value if isinstance(value, str) else None


def _action_capability(request: PolicyEvaluationRequest) -> str | None:
    value = request.material_action.get("capability")
    return value if isinstance(value, str) else None


def _limit_decision(
    request: PolicyEvaluationRequest,
    rule: PolicyRule,
) -> PolicyDecision | None:
    if rule.max_amount_micro_usd is None:
        return None
    value = request.material_action.get("amount_micro_usd")
    if not isinstance(value, int):
        return PolicyDecision.BLOCK
    _validate_safe_int(value)
    if value > rule.max_amount_micro_usd:
        return rule.limit_exceeded_decision
    return None


def _destination_allowed(request: PolicyEvaluationRequest, rule: PolicyRule) -> bool:
    value = request.material_action.get("destination")
    destination = value if isinstance(value, str) else None
    if destination is None:
        return not rule.allowed_destinations and not rule.blocked_destinations
    if destination in set(rule.blocked_destinations):
        return False
    return not rule.allowed_destinations or destination in set(rule.allowed_destinations)


def _result_for_rule(
    request: PolicyEvaluationRequest,
    policy_hash: str,
    action_hash: str,
    evaluated_at: datetime,
    rule: PolicyRule,
    decision: PolicyDecision,
    reason: PolicyEvaluationReason,
) -> PolicyEvaluationResult:
    return _result(
        request=request,
        policy_hash=policy_hash,
        action_hash=action_hash,
        evaluated_at=evaluated_at,
        decision=decision,
        reasons=(reason,),
        matched_rule_ids=(rule.rule_id,),
        required_assurance=rule.required_assurance,
        escalation_strategy=rule.escalation_strategy,
    )


def _result(
    *,
    request: PolicyEvaluationRequest,
    policy_hash: str,
    action_hash: str,
    evaluated_at: datetime,
    decision: PolicyDecision,
    reasons: tuple[PolicyEvaluationReason, ...],
    matched_rule_ids: tuple[str, ...] = (),
    required_assurance: AssuranceLevel | None = None,
    escalation_strategy: EscalationStrategy | None = None,
) -> PolicyEvaluationResult:
    return PolicyEvaluationResult(
        decision=decision,
        policy_id=request.policy_id,
        policy_version=request.policy_version,
        policy_hash=policy_hash,
        matched_rule_ids=matched_rule_ids,
        reason_codes=reasons,
        required_assurance=required_assurance,
        escalation_strategy=escalation_strategy,
        action_hash=action_hash,
        verification_result_id=(
            request.verification.verification_result_id if request.verification else None
        ),
        verification_request_id=(
            request.verification.verification_request_id if request.verification else None
        ),
        verification_status=request.verification.status if request.verification else None,
        evidence_score_basis_points=(
            request.verification.evidence_score_basis_points if request.verification else None
        ),
        evidence_score_version=(
            request.verification.evidence_score_version if request.verification else None
        ),
        evaluated_at=evaluated_at,
    )


def _assurance_rank(value: AssuranceLevel) -> int:
    return {
        AssuranceLevel.LOW: 1,
        AssuranceLevel.STANDARD: 2,
        AssuranceLevel.HIGH: 3,
    }[value]


def _validate_score(value: int) -> None:
    if not isinstance(value, int):
        raise PolicyValidationError("score must be an integer")
    if not 0 <= value <= 10_000:
        raise PolicyValidationError("score must be between 0 and 10000")


def _validate_safe_int(value: int) -> None:
    if not isinstance(value, int):
        raise PolicyValidationError("policy numeric values must be integers")
    if not -(2**53 - 1) <= value <= 2**53 - 1:
        raise PolicyValidationError("integer is outside safe canonical range")


def _timestamp(value: datetime | None) -> str | None:
    if value is None:
        return None
    return _aware_utc(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise PolicyValidationError("policy timestamps must be timezone-aware")
    return value.astimezone(UTC)


def _string(value: object) -> str:
    if not isinstance(value, str):
        raise PolicyEvaluationError("expected string policy value")
    return value


def _strings(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        raise PolicyEvaluationError("expected string list policy value")
    return tuple(_string(item) for item in value)


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int):
        raise PolicyEvaluationError("expected integer policy value")
    _validate_safe_int(value)
    return value


def _optional_datetime(value: object) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.endswith("Z"):
        raise PolicyEvaluationError("expected canonical UTC timestamp")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _optional_enum[EnumT: StrEnum](enum_type: type[EnumT], value: object) -> EnumT | None:
    if value is None:
        return None
    return enum_type(_string(value))


__all__ = [
    "POLICY_SCHEMA_VERSION",
    "POLICY_STATUS_PUBLISHED",
    "CrossTenantPolicyAccess",
    "DeterministicPolicy",
    "PolicyEvaluationError",
    "PolicyEvaluationReason",
    "PolicyEvaluationRequest",
    "PolicyEvaluationResult",
    "PolicyEvaluationService",
    "PolicyRule",
    "PolicyRuleEffect",
    "PolicyValidationError",
    "PolicyVerificationReference",
    "PublishedPolicyImmutable",
    "canonical_policy_hash",
    "policy_from_model",
    "policy_to_json",
    "validate_policy",
    "verification_reference_from_model",
]
