from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from outcome.audit import AuditService
from outcome.db.metadata import metadata
from outcome.db.models import Account, AuditEvent, EvidenceItem, Provider, VerificationResult
from outcome.domain import AssuranceLevel, ProviderHealth, VerificationMode, VerificationStatus
from outcome.evidence import EvidenceStance, SourceClass
from outcome.pricing import BillingMode, CapabilityName
from outcome.providers import (
    ProviderAttemptOutcome,
    ProviderCredentialMode,
    ProviderHealthConfig,
    ProviderHealthRequest,
    ProviderHealthService,
)
from outcome.verification import (
    AuthenticatedVerificationContext,
    EvidenceProviderRequest,
    ProviderEvidencePayload,
    ProviderEvidenceResult,
    ProviderPlan,
    VerificationIdempotencyConflict,
    VerificationMaterial,
    VerificationOrchestrator,
    VerificationRequestEnvelope,
    verification_request_fingerprint,
)
from tests.test_provider_rights import ACCOUNT_ID, PROVIDER_ID, add_right, setup_session

AGENT_ID = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
NOW = datetime(2026, 9, 15, 12, 0, 0, tzinfo=UTC)


@dataclass
class FakeProvider:
    result: ProviderEvidenceResult
    calls: int = 0

    def collect(self, request: EvidenceProviderRequest) -> ProviderEvidenceResult:
        self.calls += 1
        assert request.account_id == ACCOUNT_ID
        return self.result


@dataclass
class FailingProvider:
    calls: int = 0

    def collect(self, request: EvidenceProviderRequest) -> ProviderEvidenceResult:
        self.calls += 1
        raise RuntimeError("worker crashed with no secrets")


class SharedCountingProvider:
    def __init__(self, result: ProviderEvidenceResult) -> None:
        self.result = result
        self.calls = 0
        self.lock = Lock()

    def collect(self, request: EvidenceProviderRequest) -> ProviderEvidenceResult:
        with self.lock:
            self.calls += 1
        return self.result


def payload(
    *,
    body: str = "supported",
    source_class: SourceClass = SourceClass.AUTHORITATIVE_REGISTRY,
    stance: EvidenceStance = EvidenceStance.SUPPORTS,
    source_uri: str = "https://registry.example/item",
    content_type: str = "text/plain",
) -> ProviderEvidencePayload:
    return ProviderEvidencePayload(
        source_uri=source_uri,
        source_class=source_class,
        content_type=content_type,
        body=body,
        observed_at=NOW,
        stance=stance,
        canonical_source_identity=source_uri,
    )


def provider_result(
    *,
    provider_id: UUID = PROVIDER_ID,
    outcome: ProviderAttemptOutcome = ProviderAttemptOutcome.SUCCESS,
    evidence: tuple[ProviderEvidencePayload, ...] | None = None,
) -> ProviderEvidenceResult:
    return ProviderEvidenceResult(
        provider_id=provider_id,
        provider_alias="provider",
        capability=CapabilityName.VERIFY,
        attempt_outcome=outcome,
        latency_ms=10,
        evidence=evidence if evidence is not None else (payload(),),
    )


def material(*, claim_amount: int = 10, provider_ids: tuple[UUID, ...] = (PROVIDER_ID,)):
    return VerificationMaterial(
        capability=CapabilityName.VERIFY,
        mode=VerificationMode.INLINE,
        assurance=AssuranceLevel.STANDARD,
        claim={"merchant": "merchant", "amount": claim_amount},
        subject={"entity": "merchant"},
        provider_ids=provider_ids,
    )


def envelope(*, idempotency_key: str = "verify-key", claim_amount: int = 10):
    return VerificationRequestEnvelope(
        authenticated=AuthenticatedVerificationContext(
            account_id=ACCOUNT_ID,
            agent_id=AGENT_ID,
        ),
        material=material(claim_amount=claim_amount),
        idempotency_key=idempotency_key,
        correlation_id=uuid4(),
        ephemeral={"trace_id": str(uuid4())},
    )


def plan(adapter, *, provider_id: UUID = PROVIDER_ID) -> ProviderPlan:
    return ProviderPlan(
        provider_id=provider_id,
        provider_alias="provider",
        billing_mode=BillingMode.MANAGED,
        requested_region="US",
        credential_mode=ProviderCredentialMode.OUTCOME_MANAGED,
        adapter=adapter,
    )


def orchestrator(session: Session) -> VerificationOrchestrator:
    return VerificationOrchestrator(
        session,
        scoring_service=None,
        provider_health_service=ProviderHealthService(
            session,
            AuditService(session),
            config=ProviderHealthConfig(failure_threshold=2, timeout_threshold=2),
            clock=lambda: NOW,
        ),
        clock=lambda: NOW,
    )


def add_active_right(session: Session, *, provider_id: UUID = PROVIDER_ID) -> None:
    add_right(session, provider_id=provider_id, expires_at=NOW.replace(day=16))


def test_successful_end_to_end_internal_verification() -> None:
    session = setup_session()
    add_active_right(session)
    adapter = FakeProvider(provider_result())

    result = orchestrator(session).verify(envelope(), providers=(plan(adapter),))

    assert result.status is VerificationStatus.VERIFIED
    assert result.evidence_score is not None
    assert result.providers_contributed == (PROVIDER_ID,)
    assert adapter.calls == 1


def test_provider_rights_checked_before_provider_attempt() -> None:
    session = setup_session()
    adapter = FakeProvider(provider_result())

    result = orchestrator(session).verify(envelope(), providers=(plan(adapter),))

    assert adapter.calls == 0
    assert result.status is VerificationStatus.PROVIDER_FAILED


def test_unhealthy_provider_not_attempted() -> None:
    session = setup_session(provider_health=ProviderHealth.CIRCUIT_OPEN)
    add_active_right(session)
    ProviderHealthService(
        session,
        AuditService(session),
        config=ProviderHealthConfig(failure_threshold=1),
        clock=lambda: NOW,
    ).record_attempt(
        account_id=ACCOUNT_ID,
        provider_id=PROVIDER_ID,
        capability=CapabilityName.VERIFY,
        outcome=ProviderAttemptOutcome.PROVIDER_FAILURE,
        correlation_id=uuid4(),
    )
    adapter = FakeProvider(provider_result())

    result = orchestrator(session).verify(envelope(), providers=(plan(adapter),))

    assert adapter.calls == 0
    assert result.status is VerificationStatus.PROVIDER_FAILED


def test_provider_output_passes_through_normalizer_and_lineage_before_scoring() -> None:
    session = setup_session()
    add_active_right(session)
    adapter = FakeProvider(
        provider_result(
            evidence=(
                payload(
                    body="<html><script>bad()</script><body>Visible</body></html>",
                    source_uri="https://html.example",
                    content_type="text/html",
                ),
            )
        )
    )

    result = orchestrator(session).verify(envelope(), providers=(plan(adapter),))
    persisted = session.scalar(select(EvidenceItem))

    assert result.status is VerificationStatus.INCONCLUSIVE
    assert persisted is not None
    assert persisted.normalized_text == "Visible"
    assert result.lineage_versions == ("evidence-lineage-v1",)


def test_rejected_evidence_never_reaches_scoring() -> None:
    session = setup_session()
    add_active_right(session)
    adapter = FakeProvider(
        provider_result(
            evidence=(payload(body="x" * 20_000, source_uri="https://large.example"),)
        )
    )

    result = orchestrator(session).verify(envelope(), providers=(plan(adapter),))

    assert result.status is VerificationStatus.PROVIDER_FAILED
    assert result.evidence_score is not None
    assert result.evidence_score.evidence_count == 0


def test_contradictory_and_weak_evidence_statuses() -> None:
    session = setup_session()
    add_active_right(session)
    contradiction = FakeProvider(
        provider_result(evidence=(payload(stance=EvidenceStance.CONTRADICTS),))
    )
    weak = FakeProvider(
        provider_result(
            evidence=(
                payload(
                    body="maybe",
                    source_class=SourceClass.UNKNOWN,
                    source_uri="https://unknown.example",
                ),
            ),
        )
    )

    contradicted = orchestrator(session).verify(
        envelope(idempotency_key="contradict"),
        providers=(plan(contradiction),),
    )
    weak_result = orchestrator(session).verify(
        envelope(idempotency_key="weak"),
        providers=(plan(weak),),
    )

    assert contradicted.status is VerificationStatus.CONTRADICTED
    assert weak_result.status is VerificationStatus.INCONCLUSIVE
    assert weak_result.status is not VerificationStatus.PROVIDER_FAILED


def test_provider_timeout_with_no_usable_evidence_produces_provider_failed() -> None:
    session = setup_session()
    add_active_right(session)
    adapter = FakeProvider(
        provider_result(outcome=ProviderAttemptOutcome.PROVIDER_TIMEOUT, evidence=())
    )

    result = orchestrator(session).verify(envelope(), providers=(plan(adapter),))

    assert result.status is VerificationStatus.PROVIDER_FAILED


def test_internal_system_failure_produces_system_failure_without_damaging_health() -> None:
    session = setup_session()
    add_active_right(session)
    adapter = FailingProvider()

    result = orchestrator(session).verify(envelope(), providers=(plan(adapter),))
    health = ProviderHealthService(session).evaluate(
        request=ProviderHealthRequest(
            account_id=ACCOUNT_ID,
            provider_id=PROVIDER_ID,
            capability=CapabilityName.VERIFY,
        ),
        correlation_id=uuid4(),
    )

    assert result.status is VerificationStatus.SYSTEM_FAILURE
    assert health.failure_count == 0


def test_partial_provider_failure_does_not_poison_sufficient_evidence() -> None:
    session = setup_session()
    add_active_right(session)
    second_provider_id = uuid4()
    session.add(
        Provider(
            id=second_provider_id,
            account_id=ACCOUNT_ID,
            name="Second",
            health=ProviderHealth.HEALTHY.value,
            config={},
        )
    )
    add_active_right(session, provider_id=second_provider_id)
    failed = FakeProvider(
        provider_result(outcome=ProviderAttemptOutcome.PROVIDER_TIMEOUT, evidence=())
    )
    good = FakeProvider(provider_result(provider_id=second_provider_id))

    result = orchestrator(session).verify(
        VerificationRequestEnvelope(
            authenticated=AuthenticatedVerificationContext(ACCOUNT_ID, AGENT_ID),
            material=material(provider_ids=(PROVIDER_ID, second_provider_id)),
            idempotency_key="partial",
            correlation_id=uuid4(),
        ),
        providers=(plan(failed), plan(good, provider_id=second_provider_id)),
    )

    assert result.status is VerificationStatus.VERIFIED
    assert PROVIDER_ID in result.providers_failed
    assert second_provider_id in result.providers_contributed


def test_attempt_updates_health_for_provider_attributable_failure() -> None:
    session = setup_session()
    add_active_right(session)
    adapter = FakeProvider(
        provider_result(outcome=ProviderAttemptOutcome.PROVIDER_FAILURE, evidence=())
    )

    orchestrator(session).verify(envelope(), providers=(plan(adapter),))
    health = ProviderHealthService(session).evaluate(
        ProviderHealthRequest(
            account_id=ACCOUNT_ID,
            provider_id=PROVIDER_ID,
            capability=CapabilityName.VERIFY,
        ),
        correlation_id=uuid4(),
    )

    assert health.failure_count == 1


def test_idempotent_replay_does_not_execute_provider_twice() -> None:
    session = setup_session()
    add_active_right(session)
    adapter = FakeProvider(provider_result())
    service = orchestrator(session)

    first = service.verify(envelope(), providers=(plan(adapter),))
    second = service.verify(envelope(), providers=(plan(adapter),))

    assert first.status is VerificationStatus.VERIFIED
    assert second.idempotent_replay is True
    assert second.verification_result_id == first.verification_result_id
    assert adapter.calls == 1


def test_conflicting_request_under_same_idempotency_key_rejected() -> None:
    session = setup_session()
    add_active_right(session)
    service = orchestrator(session)
    service.verify(
        envelope(idempotency_key="same", claim_amount=10),
        providers=(plan(FakeProvider(provider_result())),),
    )

    with pytest.raises(VerificationIdempotencyConflict):
        service.verify(
            envelope(idempotency_key="same", claim_amount=11),
            providers=(plan(FakeProvider(provider_result())),),
        )


def test_request_fingerprint_ignores_ephemeral_fields_and_changes_on_material_change() -> None:
    first = envelope(claim_amount=10)
    second = VerificationRequestEnvelope(
        authenticated=first.authenticated,
        material=first.material,
        idempotency_key=first.idempotency_key,
        correlation_id=uuid4(),
        ephemeral={"nonce": str(uuid4())},
    )
    changed = envelope(claim_amount=11)

    assert verification_request_fingerprint(first.material) == verification_request_fingerprint(
        second.material
    )
    assert verification_request_fingerprint(first.material) != verification_request_fingerprint(
        changed.material
    )


def test_cross_tenant_provider_access_rejected_without_attempt() -> None:
    session = setup_session()
    add_active_right(session)
    session.add(
        Account(
            id=UUID("22222222-2222-4222-8222-222222222222"),
            display_name="Other",
            status="active",
        )
    )
    session.commit()
    adapter = FakeProvider(provider_result())

    result = orchestrator(session).verify(
        VerificationRequestEnvelope(
            authenticated=AuthenticatedVerificationContext(
                UUID("22222222-2222-4222-8222-222222222222"),
                uuid4(),
            ),
            material=material(),
            idempotency_key="tenant",
            correlation_id=uuid4(),
        ),
        providers=(plan(adapter),),
    )

    assert result.status is VerificationStatus.PROVIDER_FAILED
    assert adapter.calls == 0


def test_final_provenance_and_audit_are_safe() -> None:
    session = setup_session()
    add_active_right(session)
    raw = "raw secret provider body"
    result = orchestrator(session).verify(
        envelope(),
        providers=(plan(FakeProvider(provider_result(evidence=(payload(body=raw),)))),),
    )
    session.commit()

    persisted = session.scalar(select(VerificationResult))
    events = session.scalars(select(AuditEvent)).all()
    assert persisted is not None
    assert result.scoring_version == "evidence-score-v1"
    assert result.evidence_ids_used
    assert result.providers_contributed == (PROVIDER_ID,)
    assert raw not in repr([event.payload for event in events])
    assert raw not in repr(persisted.score_factors)


def test_process_interruption_does_not_mutate_completed_result() -> None:
    session = setup_session()
    add_active_right(session)
    service = orchestrator(session)
    first = service.verify(
        envelope(idempotency_key="done"),
        providers=(plan(FakeProvider(provider_result())),),
    )
    stored = session.scalar(select(VerificationResult))
    assert stored is not None
    original_score = stored.evidence_score_basis_points

    replay = service.verify(
        envelope(idempotency_key="done"),
        providers=(plan(FakeProvider(provider_result(evidence=(payload(body="changed"),)))),),
    )

    assert replay.idempotent_replay is True
    replayed = session.get(VerificationResult, first.verification_result_id)
    assert replayed is not None
    assert replayed.evidence_score_basis_points == original_score


def test_concurrent_identical_requests_do_not_duplicate_completed_workflows(tmp_path: Path) -> None:
    db_path = tmp_path / "verification.sqlite"
    engine = create_engine(f"sqlite:///{db_path}")
    metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    adapter = SharedCountingProvider(provider_result())
    with session_factory() as session:
        session.add(Account(id=ACCOUNT_ID, display_name="Test", status="active"))
        session.add(
            Provider(
                id=PROVIDER_ID,
                account_id=ACCOUNT_ID,
                name="Provider",
                health=ProviderHealth.HEALTHY.value,
                config={},
            )
        )
        session.commit()
        add_active_right(session)

    def worker() -> VerificationStatus:
        with session_factory() as session:
            result = orchestrator(session).verify(
                envelope(idempotency_key="concurrent"),
                providers=(plan(adapter),),
            )
            session.commit()
            return result.status

    with ThreadPoolExecutor(max_workers=4) as executor:
        statuses = list(executor.map(lambda _: worker(), range(8)))

    with session_factory() as session:
        results = session.scalars(select(VerificationResult)).all()

    assert statuses
    assert len(results) == 1
    assert adapter.calls == 1
