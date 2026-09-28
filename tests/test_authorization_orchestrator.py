from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from outcome.actions import ACTION_SCHEMA_VERSION, material_action_hash
from outcome.audit import AuditService
from outcome.authorization import (
    AuthenticatedAuthorizationContext,
    AuthorizationIdempotencyConflict,
    AuthorizationLifecyclePhase,
    AuthorizationMaterial,
    AuthorizationOrchestrationError,
    AuthorizationOrchestrationReason,
    AuthorizationOrchestrationResult,
    AuthorizationOrchestrator,
    AuthorizationRequestEnvelope,
    CrossTenantAuthorizationAccess,
    authorization_request_fingerprint,
)
from outcome.db.metadata import metadata
from outcome.db.models import (
    Account,
    AuditEvent,
    AuthorizationRequest,
    AuthorizationResult,
    Receipt,
    VerificationRequest,
    VerificationResult,
)
from outcome.domain import AssuranceLevel, PolicyDecision, VerificationMode, VerificationStatus
from outcome.execution import (
    ExecutionAuthorizationRequest,
    ExecutionAuthorizationStatus,
    ExecutionAuthorizationValidator,
    ReceiptConsumptionService,
    ReceiptConsumptionStatus,
)
from outcome.policies import (
    DeterministicPolicy,
    PolicyEvaluationReason,
    PolicyEvaluationRequest,
    PolicyEvaluationResult,
    PolicyEvaluationService,
    PolicyRule,
    PolicyRuleEffect,
)
from outcome.pricing import CapabilityName
from outcome.receipts import NonAllowReceiptProhibited, ReceiptService
from outcome.verification import (
    AuthenticatedVerificationContext,
    VerificationLifecyclePhase,
    VerificationMaterial,
    VerificationOrchestrationResult,
    VerificationRequestEnvelope,
)
from tests.test_receipt_service import signer, verifier

ACCOUNT_ID = UUID("11111111-1111-4111-8111-111111111111")
OTHER_ACCOUNT_ID = UUID("22222222-2222-4222-8222-222222222222")
AGENT_ID = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
POLICY_ID = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
NOW = datetime(2026, 9, 15, 12, 0, 0, tzinfo=UTC)
EXPIRES_AT = NOW + timedelta(minutes=5)


def material_action(
    *,
    amount: int = 5_000_000,
    destination: str = "merchant-a",
) -> dict[str, object]:
    return {
        "action_type": "purchase",
        "capability": "authorize",
        "amount_micro_usd": amount,
        "currency": "USD",
        "destination": destination,
        "merchant": "merchant-a",
        "sku": "sku-123",
        "quantity": 1,
    }


def policy(
    *,
    policy_id: UUID = POLICY_ID,
    required_assurance: AssuranceLevel = AssuranceLevel.STANDARD,
    inconclusive_decision: PolicyDecision = PolicyDecision.RETRY_HIGHER_ASSURANCE,
) -> DeterministicPolicy:
    return DeterministicPolicy(
        policy_id=policy_id,
        account_id=ACCOUNT_ID,
        name="authorization-policy",
        version=1,
        enabled=True,
        action_schema_version=ACTION_SCHEMA_VERSION,
        rules=(
            PolicyRule(
                rule_id="allow-purchase",
                effect=PolicyRuleEffect.ALLOW,
                action_types=("purchase",),
                capabilities=("authorize",),
                required_verification_status=VerificationStatus.VERIFIED,
                minimum_evidence_score=7_000,
                required_assurance=required_assurance,
                max_amount_micro_usd=10_000_000,
                allowed_destinations=("merchant-a",),
                inconclusive_decision=inconclusive_decision,
                provider_failure_decision=PolicyDecision.ESCALATE,
            ),
        ),
        effective_at=NOW,
    )


def build_session() -> Session:
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    session.add(Account(id=ACCOUNT_ID, display_name="Authorization", status="active"))
    session.commit()
    return session


def add_policy(session: Session, value: DeterministicPolicy | None = None) -> None:
    PolicyEvaluationService(session, AuditService(session), clock=lambda: NOW).publish(
        value or policy()
    )
    session.commit()


def add_verification_result(
    session: Session,
    *,
    status: VerificationStatus = VerificationStatus.VERIFIED,
    score: int | None = 8_500,
    account_id: UUID = ACCOUNT_ID,
) -> UUID:
    verification_request_id = uuid4()
    verification_result_id = uuid4()
    session.add(
        VerificationRequest(
            id=verification_request_id,
            account_id=account_id,
            request_id=uuid4(),
            agent_id=AGENT_ID,
            mode=VerificationMode.INLINE.value,
            requested_assurance=AssuranceLevel.STANDARD.value,
            claim_hash="claim",
            subject_hash="subject",
        )
    )
    session.add(
        VerificationResult(
            id=verification_result_id,
            account_id=account_id,
            request_id=uuid4(),
            verification_request_id=verification_request_id,
            status=status.value,
            evidence_score_basis_points=score,
            evidence_score_version="evidence-score-v1",
            score_factors={},
            evidence_ids_used=[],
            evidence_ids_excluded=[],
            assurance=AssuranceLevel.STANDARD.value,
            reason_codes=[status.value],
        )
    )
    session.commit()
    return verification_result_id


def envelope(
    *,
    idempotency_key: str = "authorize-key",
    action: dict[str, object] | None = None,
    assurance: AssuranceLevel = AssuranceLevel.STANDARD,
    verification_result_id: UUID | None = None,
    expires_at: datetime = EXPIRES_AT,
    policy_id: UUID = POLICY_ID,
    action_schema_version: str = ACTION_SCHEMA_VERSION,
    ephemeral: dict[str, object] | None = None,
) -> AuthorizationRequestEnvelope:
    return AuthorizationRequestEnvelope(
        authenticated=AuthenticatedAuthorizationContext(
            account_id=ACCOUNT_ID,
            agent_id=AGENT_ID,
        ),
        material=AuthorizationMaterial(
            policy_id=policy_id,
            policy_version=1,
            material_action=action or material_action(),
            action_schema_version=action_schema_version,
            assurance_level=assurance,
            authorization_expires_at=expires_at,
            verification_required=True,
            verification_result_id=verification_result_id,
        ),
        idempotency_key=idempotency_key,
        correlation_id=uuid4(),
        ephemeral=ephemeral,
    )


def service(session: Session) -> AuthorizationOrchestrator:
    audit = AuditService(session)
    receipt_service = ReceiptService(
        session,
        signer=signer(),
        verifier=verifier(),
        audit_service=audit,
    )
    return AuthorizationOrchestrator(
        session,
        policy_service=PolicyEvaluationService(session, audit, clock=lambda: NOW),
        receipt_service=receipt_service,
        execution_validator=ExecutionAuthorizationValidator(
            receipt_verifier=verifier(),
            audit_service=audit,
        ),
        audit_service=audit,
        clock=lambda: NOW,
    )


def authorize(
    session: Session,
    *,
    request: AuthorizationRequestEnvelope | None = None,
    verification_status: VerificationStatus = VerificationStatus.VERIFIED,
    verification_score: int | None = 8_500,
) -> AuthorizationOrchestrationResult:
    verification_result_id = add_verification_result(
        session,
        status=verification_status,
        score=verification_score,
    )
    if request is not None and request.material.verification_result_id is None:
        request = replace(
            request,
            material=replace(
                request.material,
                verification_result_id=verification_result_id,
            ),
        )
    return service(session).authorize(
        request or envelope(verification_result_id=verification_result_id)
    )


def test_complete_internal_allow_authorization_issues_one_receipt() -> None:
    session = build_session()
    add_policy(session)

    result = authorize(session)
    receipts = session.scalars(select(Receipt)).all()

    assert result.decision is PolicyDecision.ALLOW
    assert result.lifecycle_state is AuthorizationLifecyclePhase.COMPLETED
    assert result.receipt_id is not None
    assert result.signed_receipt is not None
    assert len(receipts) == 1
    assert receipts[0].receipt_id == result.receipt_id
    assert receipts[0].action_hash == result.action_hash
    assert result.provenance["policy_hash"] == result.policy_hash


def test_destination_constrained_authorization_without_destination_issues_no_receipt() -> None:
    session = build_session()
    add_policy(session)
    action = material_action()
    action.pop("destination")

    result = authorize(session, request=envelope(action=action))

    assert result.decision is PolicyDecision.BLOCK
    assert PolicyEvaluationReason.DESTINATION_NOT_ALLOWED.value in result.reason_codes
    assert result.receipt_id is None
    assert result.signed_receipt is None
    assert len(session.scalars(select(Receipt)).all()) == 0


@pytest.mark.parametrize(
    ("score", "decision"),
    [
        (None, PolicyDecision.BLOCK),
        (5_000, PolicyDecision.RETRY_HIGHER_ASSURANCE),
    ],
)
def test_score_only_policy_missing_or_insufficient_verification_issues_no_receipt(
    score: int | None,
    decision: PolicyDecision,
) -> None:
    session = build_session()
    add_policy(
        session,
        DeterministicPolicy(
            policy_id=POLICY_ID,
            account_id=ACCOUNT_ID,
            name="score-only-policy",
            version=1,
            enabled=True,
            action_schema_version=ACTION_SCHEMA_VERSION,
            rules=(
                PolicyRule(
                    rule_id="score-only",
                    effect=PolicyRuleEffect.ALLOW,
                    action_types=("purchase",),
                    capabilities=("authorize",),
                    minimum_evidence_score=9_000,
                ),
            ),
            effective_at=NOW,
        ),
    )
    if score is None:
        request = envelope()
        request = replace(
            request,
            material=replace(
                request.material,
                verification_required=False,
                verification_result_id=None,
            ),
        )
    else:
        verification_result_id = add_verification_result(session, score=score)
        request = envelope(verification_result_id=verification_result_id)

    result = service(session).authorize(request)

    assert result.decision is decision
    assert result.receipt_id is None
    assert result.signed_receipt is None
    assert len(session.scalars(select(Receipt)).all()) == 0


def test_emitted_receipt_self_verifies_and_passes_execution_validator() -> None:
    session = build_session()
    add_policy(session)
    result = authorize(session)
    assert result.signed_receipt is not None

    receipt_check = verifier().verify(result.signed_receipt, now=NOW)
    execution = ExecutionAuthorizationValidator(receipt_verifier=verifier()).validate(
        ExecutionAuthorizationRequest(
            signed_receipt=result.signed_receipt,
            proposed_material=material_action(),
            proposed_action_schema_version=ACTION_SCHEMA_VERSION,
            authenticated_account_id=ACCOUNT_ID,
            current_timestamp=NOW,
        ),
        correlation_id=uuid4(),
    )

    assert receipt_check.status.name == "SIGNATURE_VALID"
    assert execution.status is ExecutionAuthorizationStatus.AUTHORIZED


def test_execution_rejects_changed_material_account_and_expired_receipt() -> None:
    session = build_session()
    add_policy(session)
    result = authorize(session)
    assert result.signed_receipt is not None
    validator = ExecutionAuthorizationValidator(receipt_verifier=verifier())

    changed_material = validator.validate(
        ExecutionAuthorizationRequest(
            signed_receipt=result.signed_receipt,
            proposed_material=material_action(amount=5_000_001),
            proposed_action_schema_version=ACTION_SCHEMA_VERSION,
            authenticated_account_id=ACCOUNT_ID,
            current_timestamp=NOW,
        ),
        correlation_id=uuid4(),
    )
    changed_account = validator.validate(
        ExecutionAuthorizationRequest(
            signed_receipt=result.signed_receipt,
            proposed_material=material_action(),
            proposed_action_schema_version=ACTION_SCHEMA_VERSION,
            authenticated_account_id=OTHER_ACCOUNT_ID,
            current_timestamp=NOW,
        ),
        correlation_id=uuid4(),
    )
    expired = validator.validate(
        ExecutionAuthorizationRequest(
            signed_receipt=result.signed_receipt,
            proposed_material=material_action(),
            proposed_action_schema_version=ACTION_SCHEMA_VERSION,
            authenticated_account_id=ACCOUNT_ID,
            current_timestamp=EXPIRES_AT + timedelta(microseconds=1),
        ),
        correlation_id=uuid4(),
    )

    assert changed_material.status is ExecutionAuthorizationStatus.ACTION_MISMATCH
    assert changed_account.status is ExecutionAuthorizationStatus.ACCOUNT_MISMATCH
    assert expired.status is ExecutionAuthorizationStatus.EXPIRED_RECEIPT


def test_emitted_receipt_can_be_consumed_once() -> None:
    session = build_session()
    add_policy(session)
    result = authorize(session)
    assert result.signed_receipt is not None
    audit = AuditService(session)
    consumption = ReceiptConsumptionService(
        session,
        validator=ExecutionAuthorizationValidator(
            receipt_verifier=verifier(),
            audit_service=audit,
        ),
        audit_service=audit,
    )
    request = ExecutionAuthorizationRequest(
        signed_receipt=result.signed_receipt,
        proposed_material=material_action(),
        proposed_action_schema_version=ACTION_SCHEMA_VERSION,
        authenticated_account_id=ACCOUNT_ID,
        current_timestamp=NOW,
    )

    first = consumption.consume(
        authorization_request=request,
        execution_request_id=uuid4(),
        correlation_id=uuid4(),
    )
    second = consumption.consume(
        authorization_request=request,
        execution_request_id=uuid4(),
        correlation_id=uuid4(),
    )

    assert first.status is ReceiptConsumptionStatus.CONSUMED
    assert second.status is ReceiptConsumptionStatus.ALREADY_CONSUMED


@pytest.mark.parametrize(
    ("status", "decision"),
    [
        (VerificationStatus.INCONCLUSIVE, PolicyDecision.RETRY_HIGHER_ASSURANCE),
        (VerificationStatus.PROVIDER_FAILED, PolicyDecision.ESCALATE),
        (VerificationStatus.CONTRADICTED, PolicyDecision.BLOCK),
        (VerificationStatus.SYSTEM_FAILURE, PolicyDecision.BLOCK),
    ],
)
def test_non_allow_decisions_never_issue_receipts(
    status: VerificationStatus,
    decision: PolicyDecision,
) -> None:
    session = build_session()
    add_policy(session)

    result = authorize(session, verification_status=status)

    assert result.decision is decision
    assert result.receipt_id is None
    assert result.signed_receipt is None
    assert len(session.scalars(select(Receipt)).all()) == 0


def test_insufficient_assurance_returns_retry_higher_assurance_value() -> None:
    session = build_session()
    add_policy(session, policy(required_assurance=AssuranceLevel.HIGH))

    result = authorize(session, request=envelope(assurance=AssuranceLevel.STANDARD))

    assert result.decision is PolicyDecision.RETRY_HIGHER_ASSURANCE
    assert result.decision.value == "RETRY_HIGHER_ASSURANCE"
    assert AuthorizationOrchestrationReason.HIGHER_ASSURANCE_REQUIRED.value in result.reason_codes
    assert result.receipt_id is None


def test_receipt_service_rejects_non_allow_receipt_issuance() -> None:
    session = build_session()
    receipt_service = ReceiptService(
        session,
        signer=signer(),
        verifier=verifier(),
        audit_service=AuditService(session),
    )

    with pytest.raises(NonAllowReceiptProhibited):
        receipt_service.issue_authorization_receipt(
            account_id=ACCOUNT_ID,
            authorization_request_id=uuid4(),
            action_hash="a" * 64,
            action_schema_version=ACTION_SCHEMA_VERSION,
            policy_version="1",
            policy_decision=PolicyDecision.BLOCK,
            expires_at=EXPIRES_AT,
            issued_at=NOW,
            correlation_id=uuid4(),
        )


def test_missing_policy_and_unsupported_schema_fail_closed() -> None:
    session = build_session()

    missing = authorize(session)

    assert missing.decision is PolicyDecision.BLOCK
    assert AuthorizationOrchestrationReason.SYSTEM_FAILURE.value in missing.reason_codes
    with pytest.raises(AuthorizationOrchestrationError):
        service(session).authorize(envelope(action_schema_version="action.material.v999"))


@pytest.mark.parametrize(
    "expires_at",
    [NOW, NOW + timedelta(minutes=6), datetime(2026, 9, 15, 12, 1, 0)],
)
def test_invalid_expiration_rejected(expires_at: datetime) -> None:
    session = build_session()
    add_policy(session)

    with pytest.raises(AuthorizationOrchestrationError):
        service(session).authorize(envelope(expires_at=expires_at))


def test_action_binding_mismatch_fails_closed() -> None:
    session = build_session()
    add_policy(session)
    verification_result_id = add_verification_result(session)

    class MismatchingPolicyService(PolicyEvaluationService):
        def evaluate(
            self,
            request: PolicyEvaluationRequest,
            *,
            correlation_id: UUID,
        ) -> PolicyEvaluationResult:
            result = super().evaluate(request, correlation_id=correlation_id)
            return replace(result, action_hash="f" * 64)

    audit = AuditService(session)
    orchestrator = AuthorizationOrchestrator(
        session,
        policy_service=MismatchingPolicyService(session, audit, clock=lambda: NOW),
        receipt_service=ReceiptService(
            session,
            signer=signer(),
            verifier=verifier(),
            audit_service=audit,
        ),
        execution_validator=ExecutionAuthorizationValidator(receipt_verifier=verifier()),
        audit_service=audit,
        clock=lambda: NOW,
    )

    result = orchestrator.authorize(envelope(verification_result_id=verification_result_id))

    assert result.decision is PolicyDecision.BLOCK
    assert AuthorizationOrchestrationReason.ACTION_BINDING_MISMATCH.value in result.reason_codes
    assert result.receipt_id is None


def test_idempotent_replay_returns_same_result_and_receipt() -> None:
    session = build_session()
    add_policy(session)
    first_verification = add_verification_result(session)
    request = envelope(verification_result_id=first_verification)

    first = service(session).authorize(request)
    second = service(session).authorize(
        replace(request, correlation_id=uuid4(), ephemeral={"trace_id": str(uuid4())})
    )

    assert second.idempotent_replay is True
    assert second.authorization_result_id == first.authorization_result_id
    assert second.receipt_id == first.receipt_id
    assert len(session.scalars(select(Receipt)).all()) == 1


def test_idempotency_conflict_rejected() -> None:
    session = build_session()
    add_policy(session)
    verification_result_id = add_verification_result(session)
    first = envelope(verification_result_id=verification_result_id)
    service(session).authorize(first)

    with pytest.raises(AuthorizationIdempotencyConflict):
        service(session).authorize(
            envelope(
                idempotency_key=first.idempotency_key,
                action=material_action(amount=6_000_000),
                verification_result_id=verification_result_id,
            )
        )


def test_fingerprint_ignores_ephemeral_and_changes_on_material() -> None:
    verification_result_id = uuid4()
    first = envelope(
        verification_result_id=verification_result_id,
        ephemeral={"nonce": "one"},
    )
    second = replace(first, ephemeral={"nonce": "two"}, correlation_id=uuid4())
    changed = envelope(
        verification_result_id=verification_result_id,
        action=material_action(amount=9_000_000),
    )

    assert authorization_request_fingerprint(first.material) == (
        authorization_request_fingerprint(second.material)
    )
    assert authorization_request_fingerprint(first.material) != (
        authorization_request_fingerprint(changed.material)
    )


def test_concurrent_identical_authorization_does_not_duplicate_receipts() -> None:
    with TemporaryDirectory() as tempdir:
        database_path = Path(tempdir) / "authorization.db"
        engine = create_engine(
            f"sqlite:///{database_path}",
            connect_args={"check_same_thread": False},
        )
        metadata.create_all(engine)
        session_factory = sessionmaker(bind=engine)
        setup = session_factory()
        setup.add(Account(id=ACCOUNT_ID, display_name="Concurrent", status="active"))
        add_policy(setup)
        verification_result_id = add_verification_result(setup)
        setup.close()

        def run_once() -> PolicyDecision:
            thread_session = session_factory()
            try:
                result = service(thread_session).authorize(
                    envelope(verification_result_id=verification_result_id)
                )
                thread_session.commit()
                return result.decision
            except AuthorizationOrchestrationError:
                thread_session.rollback()
                return PolicyDecision.BLOCK
            finally:
                thread_session.close()

        with ThreadPoolExecutor(max_workers=8) as executor:
            decisions = list(executor.map(lambda _: run_once(), range(8)))

        check = session_factory()
        try:
            assert PolicyDecision.ALLOW in decisions
            assert len(check.scalars(select(AuthorizationRequest)).all()) == 1
            assert len(check.scalars(select(AuthorizationResult)).all()) == 1
            assert len(check.scalars(select(Receipt)).all()) == 1
        finally:
            check.close()


def test_retry_after_receipt_issuance_crash_does_not_create_second_receipt() -> None:
    session = build_session()
    add_policy(session)
    verification_result_id = add_verification_result(session)
    request = envelope(verification_result_id=verification_result_id)
    fingerprint = authorization_request_fingerprint(request.material)
    material_hash = material_action_hash(
        material=request.material.material_action,
        action_schema_version=request.material.action_schema_version,
    )
    stored = AuthorizationRequest(
        id=uuid4(),
        account_id=ACCOUNT_ID,
        request_id=uuid4(),
        agent_id=AGENT_ID,
        action_name="purchase",
        action_target_hash=material_hash,
        material_hash=material_hash,
        ephemeral_hash="e" * 64,
        requested_assurance=AssuranceLevel.STANDARD.value,
        action_schema_version=ACTION_SCHEMA_VERSION,
        policy_id=POLICY_ID,
        policy_version="1",
        authorization_expires_at=EXPIRES_AT,
        idempotency_key=request.idempotency_key,
        request_fingerprint=fingerprint,
        lifecycle_state=AuthorizationLifecyclePhase.RECEIPT_ISSUANCE.value,
        request_config_version=request.material.request_config_version,
        lifecycle_metadata={},
    )
    session.add(stored)
    session.flush()
    receipt_service = ReceiptService(
        session,
        signer=signer(),
        verifier=verifier(),
        audit_service=AuditService(session),
    )
    receipt_service.issue_authorization_receipt(
        account_id=ACCOUNT_ID,
        authorization_request_id=stored.id,
        action_hash="a" * 64,
        action_schema_version=ACTION_SCHEMA_VERSION,
        policy_version="1",
        policy_decision=PolicyDecision.ALLOW,
        expires_at=EXPIRES_AT,
        issued_at=NOW,
        correlation_id=uuid4(),
    )
    session.commit()

    with pytest.raises(AuthorizationOrchestrationError):
        service(session).authorize(request)

    assert len(session.scalars(select(Receipt)).all()) == 1
    assert len(session.scalars(select(AuthorizationResult)).all()) == 0


def test_cross_tenant_verification_rejected() -> None:
    session = build_session()
    add_policy(session)
    session.add(Account(id=OTHER_ACCOUNT_ID, display_name="Other", status="active"))
    other_result = add_verification_result(
        session,
        account_id=OTHER_ACCOUNT_ID,
    )

    with pytest.raises(CrossTenantAuthorizationAccess):
        service(session).authorize(envelope(verification_result_id=other_result))


def test_audit_reconstructs_lifecycle_without_raw_action_or_secrets() -> None:
    session = build_session()
    add_policy(session)

    result = authorize(session)
    events = session.scalars(select(AuditEvent)).all()
    payload_repr = repr([event.payload for event in events])

    assert result.policy_hash is not None
    assert result.verification_result_id is not None
    assert result.evidence_score_version == "evidence-score-v1"
    assert result.action_hash is not None
    assert "merchant-a" not in payload_repr
    assert "raw_evidence" not in payload_repr
    assert "api_key" not in payload_repr
    assert "signature" not in payload_repr


def test_verification_request_can_be_orchestrated_when_required() -> None:
    session = build_session()
    no_score_policy = DeterministicPolicy(
        policy_id=POLICY_ID,
        account_id=ACCOUNT_ID,
        name="authorization-policy-without-score",
        version=1,
        enabled=True,
        action_schema_version=ACTION_SCHEMA_VERSION,
        rules=(
            PolicyRule(
                rule_id="allow-purchase",
                effect=PolicyRuleEffect.ALLOW,
                action_types=("purchase",),
                capabilities=("authorize",),
                required_verification_status=VerificationStatus.VERIFIED,
                required_assurance=AssuranceLevel.STANDARD,
            ),
        ),
        effective_at=NOW,
    )
    add_policy(session, no_score_policy)
    verification_request = VerificationRequestEnvelope(
        authenticated=AuthenticatedVerificationContext(
            account_id=ACCOUNT_ID,
            agent_id=AGENT_ID,
        ),
        material=VerificationMaterial(
            capability=CapabilityName.VERIFY,
            mode=VerificationMode.INLINE,
            assurance=AssuranceLevel.STANDARD,
            claim={"merchant": "merchant-a"},
            subject={"transaction": "txn-1"},
            provider_ids=(),
        ),
        idempotency_key="verify-from-authorize",
        correlation_id=uuid4(),
    )
    authorization_request = envelope(verification_result_id=None)
    authorization_request = replace(
        authorization_request,
        material=replace(
            authorization_request.material,
            verification_request=verification_request,
        ),
    )

    class FakeVerificationOrchestrator:
        calls = 0

        async def verify_async(
            self,
            request: VerificationRequestEnvelope,
            *,
            providers: tuple[object, ...],
        ) -> VerificationOrchestrationResult:
            self.calls += 1
            return VerificationOrchestrationResult(
                verification_request_id=uuid4(),
                account_id=request.authenticated.account_id,
                status=VerificationStatus.VERIFIED,
                lifecycle_state=VerificationLifecyclePhase.COMPLETED,
                evidence_score=None,
                verification_result_id=uuid4(),
                request_fingerprint="verification-fingerprint",
                idempotent_replay=False,
                reason_codes=("VERIFIED",),
                evidence_ids_used=(),
                evidence_ids_excluded=(),
                providers_contributed=(),
                providers_failed=(),
                scoring_version="evidence-score-v1",
                lineage_versions=(),
            )

    audit = AuditService(session)
    fake_verification = FakeVerificationOrchestrator()
    result = AuthorizationOrchestrator(
        session,
        policy_service=PolicyEvaluationService(session, audit, clock=lambda: NOW),
        verification_orchestrator=fake_verification,  # type: ignore[arg-type]
        receipt_service=ReceiptService(
            session,
            signer=signer(),
            verifier=verifier(),
            audit_service=audit,
        ),
        execution_validator=ExecutionAuthorizationValidator(receipt_verifier=verifier()),
        audit_service=audit,
        clock=lambda: NOW,
    ).authorize(authorization_request)

    assert result.decision is PolicyDecision.ALLOW
    assert result.receipt_id is not None
    assert fake_verification.calls == 1


@pytest.mark.asyncio
async def test_authorize_async_can_run_inside_existing_event_loop() -> None:
    session = build_session()
    add_policy(session)
    verification_result_id = add_verification_result(session)

    result = await service(session).authorize_async(
        envelope(
            idempotency_key="async-authorize",
            verification_result_id=verification_result_id,
        )
    )

    assert result.decision is PolicyDecision.ALLOW
    assert result.receipt_id is not None
