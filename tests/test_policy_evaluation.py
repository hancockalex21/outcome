from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select

from outcome.actions.material import ACTION_SCHEMA_VERSION
from outcome.audit import AuditService
from outcome.db.models import Account, AuditEvent, Policy, VerificationRequest, VerificationResult
from outcome.domain import AssuranceLevel, PolicyDecision, VerificationStatus
from outcome.policies import (
    CrossTenantPolicyAccess,
    DeterministicPolicy,
    PolicyEvaluationReason,
    PolicyEvaluationRequest,
    PolicyEvaluationService,
    PolicyRule,
    PolicyRuleEffect,
    PolicyValidationError,
    PolicyVerificationReference,
    PublishedPolicyImmutable,
    canonical_policy_hash,
    policy_from_model,
    validate_policy,
    verification_reference_from_model,
)
from tests.test_api_keys import build_session

ACCOUNT_ID = UUID("11111111-1111-4111-8111-111111111111")
OTHER_ACCOUNT_ID = UUID("22222222-2222-4222-8222-222222222222")
POLICY_ID = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
NOW = datetime(2026, 9, 15, 12, 0, 0, tzinfo=UTC)


def policy(
    *,
    enabled: bool = True,
    rules: tuple[PolicyRule, ...] | None = None,
    policy_id: UUID = POLICY_ID,
) -> DeterministicPolicy:
    return DeterministicPolicy(
        policy_id=policy_id,
        account_id=ACCOUNT_ID,
        name="tenant-policy",
        version=1,
        enabled=enabled,
        action_schema_version=ACTION_SCHEMA_VERSION,
        rules=rules
        if rules is not None
        else (
            PolicyRule(
                rule_id="allow-purchase",
                effect=PolicyRuleEffect.ALLOW,
                action_types=("purchase",),
                capabilities=("authorize",),
                required_verification_status=VerificationStatus.VERIFIED,
                minimum_evidence_score=7_000,
                required_assurance=AssuranceLevel.STANDARD,
                max_amount_micro_usd=10_000_000,
                allowed_destinations=("merchant-a",),
                inconclusive_decision=PolicyDecision.RETRY_HIGHER_ASSURANCE,
                provider_failure_decision=PolicyDecision.ESCALATE,
                limit_exceeded_decision=PolicyDecision.BLOCK,
            ),
        ),
        effective_at=NOW,
    )


def material(
    *,
    action_type: str = "purchase",
    capability: str = "authorize",
    amount: int = 5_000_000,
    destination: str = "merchant-a",
) -> dict[str, object]:
    return {
        "action_type": action_type,
        "capability": capability,
        "amount_micro_usd": amount,
        "destination": destination,
        "resource": "order-123",
    }


def setup() -> tuple:
    session = build_session()
    account = session.scalar(select(Account))
    assert account is not None
    account.id = ACCOUNT_ID
    service = PolicyEvaluationService(session, AuditService(session), clock=lambda: NOW)
    service.publish(policy())
    session.commit()
    return session, service


def setup_with_rule(rule: PolicyRule) -> tuple:
    session = build_session()
    account = session.scalar(select(Account))
    assert account is not None
    account.id = ACCOUNT_ID
    service = PolicyEvaluationService(session, AuditService(session), clock=lambda: NOW)
    service.publish(policy(rules=(rule,)))
    session.commit()
    return session, service


def policy_request(
    *,
    verification_ref: PolicyVerificationReference | None,
    assurance: AssuranceLevel = AssuranceLevel.STANDARD,
) -> PolicyEvaluationRequest:
    return PolicyEvaluationRequest(
        account_id=ACCOUNT_ID,
        policy_id=POLICY_ID,
        policy_version=1,
        material_action=material(),
        action_schema_version=ACTION_SCHEMA_VERSION,
        assurance_level=assurance,
        verification=verification_ref,
        evaluated_at=NOW,
    )


def verification(
    status: VerificationStatus = VerificationStatus.VERIFIED,
    score: int | None = 8_000,
) -> PolicyVerificationReference:
    return PolicyVerificationReference(
        verification_result_id=uuid4(),
        verification_request_id=uuid4(),
        status=status,
        evidence_score_basis_points=score,
        evidence_score_version="evidence-score-v1",
    )


def request(
    *,
    material_action: dict[str, object] | None = None,
    assurance: AssuranceLevel = AssuranceLevel.STANDARD,
    verification_ref: PolicyVerificationReference | None = None,
    action_schema_version: str = ACTION_SCHEMA_VERSION,
    ephemeral: dict[str, object] | None = None,
    account_id: UUID = ACCOUNT_ID,
) -> PolicyEvaluationRequest:
    return PolicyEvaluationRequest(
        account_id=account_id,
        policy_id=POLICY_ID,
        policy_version=1,
        material_action=material_action or material(),
        action_schema_version=action_schema_version,
        assurance_level=assurance,
        verification=verification_ref if verification_ref is not None else verification(),
        evaluated_at=NOW,
        ephemeral=ephemeral,
    )


def evaluate(service: PolicyEvaluationService, req: PolicyEvaluationRequest):
    return service.evaluate(req, correlation_id=uuid4())


def test_explicit_allow_produces_allow() -> None:
    _session, service = setup()

    result = evaluate(service, request())

    assert result.decision is PolicyDecision.ALLOW
    assert result.reason_codes == (PolicyEvaluationReason.POLICY_ALLOWED,)
    assert result.matched_rule_ids == ("allow-purchase",)


def test_explicit_block_dominates_allow() -> None:
    session = build_session()
    account = session.scalar(select(Account))
    assert account is not None
    account.id = ACCOUNT_ID
    service = PolicyEvaluationService(session, clock=lambda: NOW)
    service.publish(
        policy(
            rules=(
                PolicyRule(
                    rule_id="block-merchant",
                    effect=PolicyRuleEffect.BLOCK,
                    action_types=("purchase",),
                    capabilities=("authorize",),
                    blocked_destinations=("merchant-a",),
                ),
                policy().rules[0],
            )
        )
    )

    result = evaluate(service, request())

    assert result.decision is PolicyDecision.BLOCK
    assert result.reason_codes == (PolicyEvaluationReason.EXPLICIT_BLOCK_RULE,)


def test_system_failure_precedes_explicit_block() -> None:
    session = build_session()
    account = session.scalar(select(Account))
    assert account is not None
    account.id = ACCOUNT_ID
    service = PolicyEvaluationService(session, clock=lambda: NOW)
    service.publish(
        policy(
            rules=(
                PolicyRule(
                    rule_id="block-merchant",
                    effect=PolicyRuleEffect.BLOCK,
                    action_types=("purchase",),
                    capabilities=("authorize",),
                    blocked_destinations=("merchant-a",),
                ),
                policy().rules[0],
            )
        )
    )

    result = evaluate(
        service,
        request(verification_ref=verification(VerificationStatus.SYSTEM_FAILURE)),
    )

    assert result.decision is PolicyDecision.BLOCK
    assert result.reason_codes == (PolicyEvaluationReason.SYSTEM_FAILURE,)


def test_no_matching_allow_defaults_block_and_unknown_capability_blocks() -> None:
    _session, service = setup()

    no_match = evaluate(service, request(material_action=material(action_type="refund")))
    unknown = evaluate(service, request(material_action={"action_type": "purchase"}))

    assert no_match.decision is PolicyDecision.BLOCK
    assert no_match.reason_codes == (PolicyEvaluationReason.NO_MATCHING_ALLOW_RULE,)
    assert unknown.decision is PolicyDecision.BLOCK
    assert unknown.reason_codes == (PolicyEvaluationReason.UNKNOWN_CAPABILITY,)


def test_disabled_policy_cannot_allow() -> None:
    session = build_session()
    account = session.scalar(select(Account))
    assert account is not None
    account.id = ACCOUNT_ID
    service = PolicyEvaluationService(session, clock=lambda: NOW)
    service.publish(policy(enabled=False))

    result = evaluate(service, request())

    assert result.decision is PolicyDecision.BLOCK
    assert result.reason_codes == (PolicyEvaluationReason.POLICY_DISABLED,)


def test_unsupported_action_schema_fails_closed() -> None:
    _session, service = setup()

    result = evaluate(service, request(action_schema_version="action.material.v999"))

    assert result.decision is PolicyDecision.BLOCK
    assert result.reason_codes == (PolicyEvaluationReason.UNSUPPORTED_ACTION_SCHEMA,)


def test_verification_status_requirements() -> None:
    _session, service = setup()

    verified = evaluate(
        service,
        request(verification_ref=verification(VerificationStatus.VERIFIED)),
    )
    contradicted = evaluate(
        service,
        request(verification_ref=verification(VerificationStatus.CONTRADICTED)),
    )
    inconclusive = evaluate(
        service,
        request(verification_ref=verification(VerificationStatus.INCONCLUSIVE)),
    )

    assert verified.decision is PolicyDecision.ALLOW
    assert contradicted.decision is PolicyDecision.BLOCK
    assert contradicted.reason_codes == (PolicyEvaluationReason.VERIFICATION_CONTRADICTED,)
    assert inconclusive.decision is PolicyDecision.RETRY_HIGHER_ASSURANCE
    assert inconclusive.reason_codes == (PolicyEvaluationReason.VERIFICATION_INCONCLUSIVE,)


def test_provider_failure_escalates_and_system_failure_blocks() -> None:
    _session, service = setup()

    provider = evaluate(
        service,
        request(verification_ref=verification(VerificationStatus.PROVIDER_FAILED)),
    )
    system = evaluate(
        service,
        request(verification_ref=verification(VerificationStatus.SYSTEM_FAILURE)),
    )

    assert provider.decision is PolicyDecision.ESCALATE
    assert provider.reason_codes == (PolicyEvaluationReason.PROVIDER_FAILURE,)
    assert system.decision is PolicyDecision.BLOCK
    assert system.reason_codes == (PolicyEvaluationReason.SYSTEM_FAILURE,)


def test_score_only_policy_requires_verification_and_enforces_score() -> None:
    session, service = setup_with_rule(
        PolicyRule(
            rule_id="score-only",
            effect=PolicyRuleEffect.ALLOW,
            action_types=("purchase",),
            capabilities=("authorize",),
            minimum_evidence_score=9_000,
        )
    )

    missing = evaluate(service, policy_request(verification_ref=None))
    insufficient = evaluate(service, policy_request(verification_ref=verification(score=5_000)))
    no_score = evaluate(service, policy_request(verification_ref=verification(score=None)))
    sufficient = evaluate(service, policy_request(verification_ref=verification(score=9_500)))

    assert missing.decision is PolicyDecision.BLOCK
    assert missing.reason_codes == (PolicyEvaluationReason.VERIFICATION_REQUIRED,)
    assert insufficient.decision is PolicyDecision.RETRY_HIGHER_ASSURANCE
    assert insufficient.reason_codes == (PolicyEvaluationReason.VERIFICATION_INCONCLUSIVE,)
    assert no_score.decision is PolicyDecision.RETRY_HIGHER_ASSURANCE
    assert no_score.reason_codes == (PolicyEvaluationReason.VERIFICATION_INCONCLUSIVE,)
    assert sufficient.decision is PolicyDecision.ALLOW

    stored = session.get(Policy, POLICY_ID)
    assert stored is not None
    restored = policy_from_model(stored)
    assert restored.rules[0].required_verification_status is None
    assert restored.rules[0].minimum_evidence_score == 9_000
    validate_policy(restored)


@pytest.mark.parametrize(
    ("status", "decision", "reason"),
    [
        (
            VerificationStatus.SYSTEM_FAILURE,
            PolicyDecision.BLOCK,
            PolicyEvaluationReason.SYSTEM_FAILURE,
        ),
        (
            VerificationStatus.CONTRADICTED,
            PolicyDecision.BLOCK,
            PolicyEvaluationReason.VERIFICATION_CONTRADICTED,
        ),
        (
            VerificationStatus.INCONCLUSIVE,
            PolicyDecision.RETRY_HIGHER_ASSURANCE,
            PolicyEvaluationReason.VERIFICATION_INCONCLUSIVE,
        ),
        (
            VerificationStatus.PROVIDER_FAILED,
            PolicyDecision.ESCALATE,
            PolicyEvaluationReason.PROVIDER_FAILURE,
        ),
    ],
)
def test_score_only_policy_preserves_verification_failure_semantics(
    status: VerificationStatus,
    decision: PolicyDecision,
    reason: PolicyEvaluationReason,
) -> None:
    _session, service = setup_with_rule(
        PolicyRule(
            rule_id="score-only",
            effect=PolicyRuleEffect.ALLOW,
            action_types=("purchase",),
            capabilities=("authorize",),
            minimum_evidence_score=9_000,
        )
    )

    result = evaluate(
        service,
        policy_request(verification_ref=verification(status=status, score=9_500)),
    )

    assert result.decision is decision
    assert result.reason_codes == (reason,)


def test_status_only_and_unconstrained_verification_behavior_is_preserved() -> None:
    _status_session, status_service = setup_with_rule(
        PolicyRule(
            rule_id="status-only",
            effect=PolicyRuleEffect.ALLOW,
            action_types=("purchase",),
            capabilities=("authorize",),
            required_verification_status=VerificationStatus.VERIFIED,
        )
    )
    missing = evaluate(status_service, policy_request(verification_ref=None))
    verified = evaluate(
        status_service,
        policy_request(verification_ref=verification(VerificationStatus.VERIFIED)),
    )
    assert missing.decision is PolicyDecision.BLOCK
    assert verified.decision is PolicyDecision.ALLOW

    _optional_session, optional_service = setup_with_rule(
        PolicyRule(
            rule_id="verification-optional",
            effect=PolicyRuleEffect.ALLOW,
            action_types=("purchase",),
            capabilities=("authorize",),
        )
    )
    optional = evaluate(optional_service, policy_request(verification_ref=None))
    assert optional.decision is PolicyDecision.ALLOW


def test_required_assurance_is_independent_of_verification_constraints() -> None:
    _session, service = setup_with_rule(
        PolicyRule(
            rule_id="assurance-only",
            effect=PolicyRuleEffect.ALLOW,
            action_types=("purchase",),
            capabilities=("authorize",),
            required_assurance=AssuranceLevel.HIGH,
        )
    )

    result = evaluate(
        service,
        policy_request(verification_ref=None, assurance=AssuranceLevel.STANDARD),
    )

    assert result.decision is PolicyDecision.RETRY_HIGHER_ASSURANCE
    assert result.reason_codes == (PolicyEvaluationReason.ASSURANCE_INSUFFICIENT,)


def test_insufficient_assurance_retries() -> None:
    _session, service = setup()

    result = evaluate(service, request(assurance=AssuranceLevel.LOW))

    assert result.decision is PolicyDecision.RETRY_HIGHER_ASSURANCE
    assert result.decision.value == "RETRY_HIGHER_ASSURANCE"
    assert result.reason_codes == (PolicyEvaluationReason.ASSURANCE_INSUFFICIENT,)
    assert result.required_assurance is AssuranceLevel.STANDARD


def test_action_limit_and_destination_constraints() -> None:
    _session, service = setup()

    too_large = evaluate(service, request(material_action=material(amount=20_000_000)))
    bad_destination = evaluate(
        service,
        request(material_action=material(destination="merchant-b")),
    )

    assert too_large.decision is PolicyDecision.BLOCK
    assert too_large.reason_codes == (PolicyEvaluationReason.ACTION_LIMIT_EXCEEDED,)
    assert bad_destination.decision is PolicyDecision.BLOCK
    assert bad_destination.reason_codes == (PolicyEvaluationReason.DESTINATION_NOT_ALLOWED,)


@pytest.mark.parametrize(
    ("destination_present", "destination"),
    [(False, None), (True, None), (True, 123), (True, ["merchant-a"])],
)
def test_allowed_destination_constraint_rejects_missing_or_invalid_destination(
    destination_present: bool,
    destination: object,
) -> None:
    _session, service = setup()
    action = material()
    action.pop("destination")
    if destination_present:
        action["destination"] = destination

    result = evaluate(service, request(material_action=action))

    assert result.decision is PolicyDecision.BLOCK
    assert result.reason_codes == (PolicyEvaluationReason.DESTINATION_NOT_ALLOWED,)


@pytest.mark.parametrize(
    ("destination_present", "destination"),
    [(False, None), (True, None), (True, 123), (True, ["merchant-a"])],
)
def test_blocked_destination_constraint_rejects_missing_or_invalid_destination(
    destination_present: bool,
    destination: object,
) -> None:
    session = build_session()
    account = session.scalar(select(Account))
    assert account is not None
    account.id = ACCOUNT_ID
    service = PolicyEvaluationService(session, clock=lambda: NOW)
    service.publish(
        policy(
            rules=(
                PolicyRule(
                    rule_id="allow-unblocked-purchase",
                    effect=PolicyRuleEffect.ALLOW,
                    action_types=("purchase",),
                    capabilities=("authorize",),
                    blocked_destinations=("merchant-b",),
                ),
            )
        )
    )
    action = material()
    action.pop("destination")
    if destination_present:
        action["destination"] = destination

    result = evaluate(service, request(material_action=action))

    assert result.decision is PolicyDecision.BLOCK
    assert result.reason_codes == (PolicyEvaluationReason.DESTINATION_NOT_ALLOWED,)


def test_destination_remains_optional_without_destination_constraints() -> None:
    session = build_session()
    account = session.scalar(select(Account))
    assert account is not None
    account.id = ACCOUNT_ID
    service = PolicyEvaluationService(session, clock=lambda: NOW)
    service.publish(
        policy(
            rules=(
                PolicyRule(
                    rule_id="allow-purchase-without-destination-constraint",
                    effect=PolicyRuleEffect.ALLOW,
                    action_types=("purchase",),
                    capabilities=("authorize",),
                ),
            )
        )
    )
    action = material()
    action.pop("destination")

    result = evaluate(service, request(material_action=action))

    assert result.decision is PolicyDecision.ALLOW
    assert result.reason_codes == (PolicyEvaluationReason.POLICY_ALLOWED,)


def test_both_destination_constraints_preserve_valid_string_semantics() -> None:
    session = build_session()
    account = session.scalar(select(Account))
    assert account is not None
    account.id = ACCOUNT_ID
    service = PolicyEvaluationService(session, clock=lambda: NOW)
    service.publish(
        policy(
            rules=(
                PolicyRule(
                    rule_id="allow-selected-unblocked-destination",
                    effect=PolicyRuleEffect.ALLOW,
                    action_types=("purchase",),
                    capabilities=("authorize",),
                    allowed_destinations=("merchant-a", "merchant-b"),
                    blocked_destinations=("merchant-b",),
                ),
            )
        )
    )

    allowed = evaluate(service, request(material_action=material(destination="merchant-a")))
    blocked = evaluate(service, request(material_action=material(destination="merchant-b")))
    disallowed = evaluate(service, request(material_action=material(destination="merchant-c")))

    assert allowed.decision is PolicyDecision.ALLOW
    assert blocked.decision is PolicyDecision.BLOCK
    assert disallowed.decision is PolicyDecision.BLOCK
    assert blocked.reason_codes == (PolicyEvaluationReason.DESTINATION_NOT_ALLOWED,)
    assert disallowed.reason_codes == (PolicyEvaluationReason.DESTINATION_NOT_ALLOWED,)


def test_material_change_can_alter_decision_but_ephemeral_does_not() -> None:
    _session, service = setup()

    allowed = evaluate(service, request(ephemeral={"nonce": str(uuid4())}))
    same = evaluate(service, request(ephemeral={"nonce": str(uuid4())}))
    changed = evaluate(service, request(material_action=material(destination="merchant-b")))

    assert same.decision is allowed.decision
    assert same.action_hash == allowed.action_hash
    assert changed.decision is PolicyDecision.BLOCK
    assert changed.action_hash != allowed.action_hash


def test_same_inputs_are_deterministic_and_policy_hash_is_stable() -> None:
    _session, service = setup()
    req = request()

    first = evaluate(service, req)
    second = evaluate(service, req)

    assert first == second
    assert canonical_policy_hash(policy()) == canonical_policy_hash(policy())


def test_material_policy_change_changes_hash_and_published_version_is_immutable() -> None:
    session, service = setup()
    changed = policy(
        rules=(
            PolicyRule(
                rule_id="allow-purchase",
                effect=PolicyRuleEffect.ALLOW,
                action_types=("purchase",),
                capabilities=("authorize",),
                max_amount_micro_usd=1,
            ),
        )
    )

    assert canonical_policy_hash(policy()) != canonical_policy_hash(changed)
    with pytest.raises(PublishedPolicyImmutable):
        service.publish(changed)
    session.rollback()


def test_cross_tenant_policy_denied() -> None:
    session, service = setup()
    session.add(Account(id=OTHER_ACCOUNT_ID, display_name="Other", status="active"))
    session.commit()

    with pytest.raises(CrossTenantPolicyAccess):
        evaluate(service, request(account_id=OTHER_ACCOUNT_ID))


def test_malformed_policy_duplicate_rules_and_unsafe_numbers_rejected() -> None:
    duplicate = policy(rules=(policy().rules[0], policy().rules[0]))
    unsafe = policy(
        rules=(
            PolicyRule(
                rule_id="unsafe",
                effect=PolicyRuleEffect.ALLOW,
                max_amount_micro_usd=9_007_199_254_740_992,
            ),
        )
    )

    with pytest.raises(PolicyValidationError):
        validate_policy(duplicate)
    with pytest.raises(PolicyValidationError):
        validate_policy(unsafe)
    with pytest.raises(PolicyValidationError):
        validate_policy(
            policy(
                rules=(
                    PolicyRule(
                        rule_id="float",
                        effect=PolicyRuleEffect.ALLOW,
                        max_amount_micro_usd=1.5,  # type: ignore[arg-type]
                    ),
                )
            )
        )


def test_audit_contains_safe_metadata_and_verification_provenance() -> None:
    session, service = setup()
    verification_request_id = uuid4()
    verification_result_id = uuid4()
    session.add(
        VerificationRequest(
            id=verification_request_id,
            account_id=ACCOUNT_ID,
            request_id=uuid4(),
            agent_id=uuid4(),
            mode="INLINE",
            requested_assurance="STANDARD",
            claim_hash="claim",
            subject_hash="subject",
        )
    )
    session.add(
        VerificationResult(
            id=verification_result_id,
            account_id=ACCOUNT_ID,
            request_id=uuid4(),
            verification_request_id=verification_request_id,
            status=VerificationStatus.VERIFIED.value,
            evidence_score_basis_points=8_500,
            evidence_score_version="evidence-score-v1",
            score_factors={},
            evidence_ids_used=[],
            evidence_ids_excluded=[],
            assurance="STANDARD",
            reason_codes=["VERIFICATION_STATUS_VERIFIED"],
        )
    )
    session.commit()
    model = session.get(VerificationResult, verification_result_id)
    assert model is not None

    result = evaluate(
        service,
        request(verification_ref=verification_reference_from_model(model)),
    )
    events = session.scalars(select(AuditEvent)).all()

    assert result.verification_result_id == verification_result_id
    assert result.verification_request_id == verification_request_id
    payload_repr = repr([event.payload for event in events])
    assert "raw evidence" not in payload_repr
    assert "api_key" not in payload_repr
    assert str(verification_result_id) in payload_repr
    assert "merchant-a" not in payload_repr
