from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import NAMESPACE_URL, UUID, uuid5

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from outcome.audit import AuditService
from outcome.benchmarks.metrics import BenchmarkReport, compute_report
from outcome.benchmarks.schema import (
    BenchmarkCase,
    BenchmarkCaseKind,
    BenchmarkDataset,
    BenchmarkLabel,
    BenchmarkResult,
    FixtureProvider,
    MatchClassification,
    load_dataset,
)
from outcome.db.metadata import metadata
from outcome.db.models import (
    Account,
    EvidenceItem,
    EvidenceLineage,
    Provider,
    ProviderAttempt,
    ProviderRight,
)
from outcome.domain import (
    AssuranceLevel,
    EscalationStrategy,
    PolicyDecision,
    ProviderHealth,
    VerificationStatus,
)
from outcome.evidence import (
    EVIDENCE_SCORE_VERSION,
    EvidenceScore,
)
from outcome.policies import (
    DeterministicPolicy,
    PolicyEvaluationRequest,
    PolicyEvaluationService,
    PolicyRule,
    PolicyRuleEffect,
    PolicyVerificationReference,
)
from outcome.pricing import BillingMode, CapabilityName
from outcome.providers import (
    ProviderCredentialMode,
    ProviderDataUse,
    ProviderExecutionMode,
    ProviderHealthConfig,
    ProviderHealthService,
)
from outcome.verification import (
    AuthenticatedVerificationContext,
    EvidenceProviderRequest,
    ProviderCollectionConfig,
    ProviderEvidencePayload,
    ProviderEvidenceResult,
    ProviderPlan,
    VerificationMaterial,
    VerificationOrchestrator,
    VerificationRequestEnvelope,
)

BENCHMARK_CODE_VERSION = "offline-evaluation-v1"
BENCHMARK_ACCOUNT_ID = UUID("10000000-0000-4000-8000-000000000001")
BENCHMARK_AGENT_ID = UUID("10000000-0000-4000-8000-000000000002")
BENCHMARK_POLICY_ID = UUID("10000000-0000-4000-8000-000000000003")
BENCHMARK_NOW = datetime(2026, 9, 18, 12, 0, 0, tzinfo=UTC)


@dataclass
class FixtureEvidenceProvider:
    fixture: FixtureProvider
    calls: int = 0

    def collect(self, request: EvidenceProviderRequest) -> ProviderEvidenceResult:
        self.calls += 1
        return ProviderEvidenceResult(
            provider_id=self.fixture.provider_id,
            provider_alias=self.fixture.provider_alias,
            capability=request.capability,
            attempt_outcome=self.fixture.outcome,
            latency_ms=self.fixture.latency_ms,
            evidence=tuple(
                ProviderEvidencePayload(
                    source_uri=evidence.source_uri,
                    source_class=evidence.source_class,
                    content_type=evidence.content_type,
                    body=evidence.body,
                    observed_at=evidence.observed_at,
                    stance=evidence.stance,
                    lineage_type=evidence.lineage_type,
                    parent_evidence_ids=(),
                    origin_reference=evidence.origin_reference,
                    publisher_identity=evidence.publisher_identity,
                    canonical_source_identity=evidence.canonical_source_identity,
                    coverage_basis_points=evidence.coverage_basis_points,
                    authority_metadata=evidence.authority_metadata,
                    lineage_metadata=evidence.lineage_metadata,
                )
                for evidence in self.fixture.evidence
            ),
        )


def run_benchmark_dataset(path: Path) -> BenchmarkReport:
    dataset = load_dataset(path)
    results = run_dataset(dataset)
    return compute_report(results)


def run_dataset(dataset: BenchmarkDataset) -> tuple[BenchmarkResult, ...]:
    verification_results = tuple(_run_verification_case(case) for case in dataset.cases)
    authorization_results = tuple(
        _run_authorization_case(case, dataset_version=dataset.dataset_version)
        for case in dataset.authorization_cases
    )
    return verification_results + authorization_results


def _run_verification_case(case: BenchmarkCase) -> BenchmarkResult:
    session = _session()
    _seed_account(session)
    providers: list[ProviderPlan] = []
    for fixture in case.providers:
        _seed_provider(session, fixture)
        providers.append(
            ProviderPlan(
                provider_id=fixture.provider_id,
                provider_alias=fixture.provider_alias,
                billing_mode=BillingMode.MANAGED,
                requested_region="US",
                credential_mode=ProviderCredentialMode.OUTCOME_MANAGED,
                adapter=FixtureEvidenceProvider(fixture),
            )
        )
    orchestrator = VerificationOrchestrator(
        session,
        audit_service=AuditService(session),
        provider_health_service=ProviderHealthService(
            session,
            AuditService(session),
            config=ProviderHealthConfig(failure_threshold=2, timeout_threshold=2),
            clock=lambda: BENCHMARK_NOW,
        ),
        collection_config=ProviderCollectionConfig(
            max_providers=8,
            max_concurrency=4,
            per_provider_timeout=timedelta(seconds=1),
            overall_deadline=timedelta(seconds=2),
        ),
        clock=lambda: BENCHMARK_NOW,
    )
    result = orchestrator.verify(
        VerificationRequestEnvelope(
            authenticated=AuthenticatedVerificationContext(
                account_id=BENCHMARK_ACCOUNT_ID,
                agent_id=BENCHMARK_AGENT_ID,
            ),
            material=VerificationMaterial(
                capability=case.capability,
                mode=case.mode,
                assurance=case.assurance,
                claim=case.claim,
                subject=case.subject,
                provider_ids=tuple(provider.provider_id for provider in case.providers),
            ),
            idempotency_key=f"benchmark:{case.benchmark_case_id}",
            correlation_id=_uuid(case.benchmark_case_id, "correlation"),
            ephemeral={"benchmark_case_id": case.benchmark_case_id},
        ),
        providers=tuple(providers),
    )
    session.commit()
    score = result.evidence_score
    evidence_items = session.scalars(
        select(EvidenceItem).where(
            EvidenceItem.account_id == BENCHMARK_ACCOUNT_ID,
            EvidenceItem.verification_request_id == result.verification_request_id,
        )
    ).all()
    attempts = session.scalars(
        select(ProviderAttempt).where(
            ProviderAttempt.account_id == BENCHMARK_ACCOUNT_ID,
            ProviderAttempt.verification_request_id == result.verification_request_id,
        )
    ).all()
    lineages = session.scalars(
        select(EvidenceLineage).where(
            EvidenceLineage.account_id == BENCHMARK_ACCOUNT_ID,
            EvidenceLineage.verification_request_id == result.verification_request_id,
        )
    ).all()
    expected_status = _expected_status(case.truth_label)
    if result.status in {VerificationStatus.PROVIDER_FAILED, VerificationStatus.SYSTEM_FAILURE}:
        classification = MatchClassification.OPERATIONAL_FAILURE
    elif result.status is expected_status:
        classification = MatchClassification.MATCH
    else:
        classification = MatchClassification.MISMATCH
    return BenchmarkResult(
        case_id=case.benchmark_case_id,
        case_kind=BenchmarkCaseKind.VERIFICATION,
        dataset_version=case.dataset_version,
        code_version=BENCHMARK_CODE_VERSION,
        scoring_version=result.scoring_version,
        verification_status=result.status,
        evidence_score=score.final_score if score else None,
        score_components=_score_components(score),
        reason_codes=tuple(sorted(result.reason_codes)),
        evidence_count=score.evidence_count if score else 0,
        independent_evidence_count=score.independent_evidence_count if score else 0,
        source_classes=tuple(sorted({item.source_class for item in evidence_items})),
        extraction_qualities=tuple(sorted({item.extraction_quality for item in evidence_items})),
        lineage_types=tuple(sorted({lineage.lineage_type for lineage in lineages})),
        provider_outcomes=tuple(sorted(attempt.status for attempt in attempts)),
        operational_failure_category=(
            result.status
            if result.status
            in {
                VerificationStatus.PROVIDER_FAILED,
                VerificationStatus.SYSTEM_FAILURE,
            }
            else None
        ),
        expected_label=case.truth_label,
        match_classification=classification,
    )


def _run_authorization_case(case: object, *, dataset_version: str) -> BenchmarkResult:
    # The authorization benchmark intentionally exercises deterministic policy evaluation only.
    # It does not create receipts, reservations, ledger entries, or Stripe/payment effects.
    from outcome.benchmarks.schema import AuthorizationBenchmarkCase

    typed = (
        case
        if isinstance(case, AuthorizationBenchmarkCase)
        else AuthorizationBenchmarkCase.model_validate(case)
    )
    session = _session()
    _seed_account(session)
    service = PolicyEvaluationService(session, AuditService(session), clock=lambda: BENCHMARK_NOW)
    policy = _authorization_policy()
    service.publish(policy)
    verification = None
    if typed.verification_status is not None:
        verification = PolicyVerificationReference(
            verification_result_id=_uuid(typed.benchmark_case_id, "verification-result"),
            verification_request_id=_uuid(typed.benchmark_case_id, "verification-request"),
            status=typed.verification_status,
            evidence_score_basis_points=typed.evidence_score_basis_points,
            evidence_score_version=EVIDENCE_SCORE_VERSION,
        )
    result = service.evaluate(
        PolicyEvaluationRequest(
            account_id=BENCHMARK_ACCOUNT_ID,
            policy_id=policy.policy_id,
            policy_version=policy.version,
            material_action=typed.material_action,
            action_schema_version="action.material.v1",
            assurance_level=typed.assurance,
            verification=verification,
            evaluated_at=BENCHMARK_NOW,
        ),
        correlation_id=_uuid(typed.benchmark_case_id, "policy-correlation"),
    )
    return BenchmarkResult(
        case_id=typed.benchmark_case_id,
        case_kind=BenchmarkCaseKind.AUTHORIZATION,
        dataset_version=dataset_version,
        code_version=BENCHMARK_CODE_VERSION,
        scoring_version=None,
        policy_decision=result.decision,
        reason_codes=tuple(reason.value for reason in result.reason_codes),
        expected_policy_decision=typed.expected_decision,
        match_classification=(
            MatchClassification.MATCH
            if result.decision is typed.expected_decision
            else MatchClassification.MISMATCH
        ),
    )


def _seed_account(session: Session) -> None:
    session.add(
        Account(
            id=BENCHMARK_ACCOUNT_ID,
            display_name="Benchmark Account",
            status="ACTIVE",
        )
    )
    session.flush()


def _seed_provider(session: Session, fixture: FixtureProvider) -> None:
    session.add(
        Provider(
            id=fixture.provider_id,
            account_id=BENCHMARK_ACCOUNT_ID,
            name=fixture.provider_alias,
            health=(
                ProviderHealth.HEALTHY.value
                if fixture.healthy
                else ProviderHealth.CIRCUIT_OPEN.value
            ),
            config={},
        )
    )
    if fixture.enabled_rights:
        session.add(
            ProviderRight(
                id=_uuid(str(fixture.provider_id), "right"),
                account_id=BENCHMARK_ACCOUNT_ID,
                provider_id=fixture.provider_id,
                right_name=f"benchmark-{fixture.provider_alias}",
                provider_alias=fixture.provider_alias,
                capability=CapabilityName.VERIFY.value,
                billing_mode=BillingMode.MANAGED.value,
                enabled=True,
                rights_status="AUTHORIZED",
                permitted_regions=["US"],
                permitted_data_use=[ProviderDataUse.CLAIM_VERIFICATION.value],
                permitted_execution_modes=[ProviderExecutionMode.INLINE.value],
                customer_secret_required=False,
                outcome_managed_credential_allowed=True,
                customer_managed_credential_allowed=False,
                evidence_retention_allowed=False,
                caching_allowed=False,
                commercial_usage_allowed=True,
                automated_agent_usage_allowed=True,
                rights_version="benchmark-rights-v1",
                effective_at=BENCHMARK_NOW - timedelta(days=1),
                expires_at=BENCHMARK_NOW + timedelta(days=1),
                reason_code="ALLOWED",
                tenant_restrictions={},
                constraints={},
            )
        )
    session.flush()


def _authorization_policy() -> DeterministicPolicy:
    return DeterministicPolicy(
        policy_id=BENCHMARK_POLICY_ID,
        account_id=BENCHMARK_ACCOUNT_ID,
        name="Benchmark policy",
        version=1,
        enabled=True,
        action_schema_version="action.material.v1",
        rules=(
            PolicyRule(
                rule_id="block-wire",
                effect=PolicyRuleEffect.BLOCK,
                action_types=("wire-transfer",),
                blocked_destinations=("blocked-destination",),
            ),
            PolicyRule(
                rule_id="allow-purchase",
                effect=PolicyRuleEffect.ALLOW,
                action_types=("payment",),
                capabilities=("authorize",),
                required_verification_status=VerificationStatus.VERIFIED,
                minimum_evidence_score=7_000,
                required_assurance=AssuranceLevel.STANDARD,
                max_amount_micro_usd=1_000_000,
                allowed_destinations=("merchant-ok", "ops-queue"),
                inconclusive_decision=PolicyDecision.RETRY_HIGHER_ASSURANCE,
                provider_failure_decision=PolicyDecision.ESCALATE,
                limit_exceeded_decision=PolicyDecision.BLOCK,
                escalation_strategy=EscalationStrategy.WEBHOOK,
            ),
            PolicyRule(
                rule_id="expired-window",
                effect=PolicyRuleEffect.ALLOW,
                action_types=("expired-payment",),
                capabilities=("authorize",),
                expires_at=BENCHMARK_NOW - timedelta(seconds=1),
            ),
        ),
    )


def _expected_status(label: BenchmarkLabel) -> VerificationStatus:
    return {
        BenchmarkLabel.SUPPORTED: VerificationStatus.VERIFIED,
        BenchmarkLabel.CONTRADICTED: VerificationStatus.CONTRADICTED,
        BenchmarkLabel.INSUFFICIENT_EVIDENCE: VerificationStatus.INCONCLUSIVE,
    }[label]


def _score_components(score: EvidenceScore | None) -> dict[str, int]:
    if score is None:
        return {}
    return {
        "source_authority": score.source_authority_component,
        "extraction_quality": score.extraction_quality_component,
        "independence": score.independence_component,
        "corroboration": score.corroboration_component,
        "contradiction": score.contradiction_component,
        "freshness": score.freshness_component,
        "coverage": score.coverage_component,
    }


def _session() -> Session:
    engine = create_engine(
        "sqlite://",
        future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    metadata.create_all(engine)
    factory = sessionmaker(bind=engine, future=True)
    return factory()


def _uuid(case_id: str, purpose: str) -> UUID:
    return uuid5(NAMESPACE_URL, f"outcome-benchmark:{case_id}:{purpose}")


__all__ = [
    "BENCHMARK_CODE_VERSION",
    "run_benchmark_dataset",
    "run_dataset",
]
