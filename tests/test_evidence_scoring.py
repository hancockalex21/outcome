from __future__ import annotations

from dataclasses import fields
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from outcome.audit import AuditService
from outcome.db.models import (
    Account,
    AuditEvent,
    EvidenceItem,
    VerificationRequest,
    VerificationResult,
)
from outcome.domain import VerificationStatus
from outcome.evidence import (
    CrossTenantEvidenceScoringAccess,
    EvidenceLineageInput,
    EvidenceLineageService,
    EvidenceLineageType,
    EvidenceScore,
    EvidenceScoringConfig,
    EvidenceScoringReason,
    EvidenceScoringService,
    EvidenceStance,
    EvidenceStanceInput,
    InertEvidence,
    SourceClass,
)
from tests.test_evidence_normalizer import (
    ACCOUNT_ID,
    OBSERVED_AT,
    OTHER_ACCOUNT_ID,
    PROVIDER_ID,
    REQUEST_ID,
    build_evidence_session,
    evidence_input,
    normalize,
)

NOW = datetime(2026, 9, 14, 13, 0, 0, tzinfo=UTC)


def make_evidence(
    session: Session,
    *,
    body: str = "claim supported",
    source_uri: str = "https://source.example/item",
    source_class: SourceClass = SourceClass.REPUTABLE_SECONDARY,
    observed_at: datetime = OBSERVED_AT,
) -> InertEvidence:
    inert = normalize(
        session,
        evidence_input(
            body=body,
            source_uri=source_uri,
            source_class=source_class,
        ).__class__(
            account_id=ACCOUNT_ID,
            verification_request_id=REQUEST_ID,
            provider_id=PROVIDER_ID,
            provider_alias="provider",
            source_uri=source_uri,
            source_class=source_class,
            content_type="text/plain",
            body=body,
            observed_at=observed_at,
            authority_metadata={"publisher": source_uri},
            lineage_metadata={},
        ),
    )
    return cast(InertEvidence, inert)


def record_lineage(
    session: Session,
    evidence: InertEvidence,
    *,
    lineage_type: EvidenceLineageType = EvidenceLineageType.ORIGINAL,
    parent_evidence_ids: tuple[object, ...] = (),
    origin_reference: str | None = None,
    canonical_source_identity: str | None = None,
) -> None:
    EvidenceLineageService(session).record_lineage(
        EvidenceLineageInput(
            evidence_id=evidence.evidence_id,
            account_id=evidence.account_id,
            verification_request_id=evidence.verification_request_id,
            provider_id=evidence.provider_id,
            source_reference=evidence.source_uri,
            source_class=evidence.source_class,
            parent_evidence_ids=cast(tuple, parent_evidence_ids),
            origin_reference=origin_reference,
            lineage_type=lineage_type,
            canonical_source_identity=canonical_source_identity,
            observed_at=evidence.observed_at,
            lineage_version="lineage-v1",
        ),
        correlation_id=uuid4(),
    )


def score(
    session: Session,
    evidence: tuple[InertEvidence, ...],
    stances: tuple[EvidenceStanceInput, ...],
    *,
    config: EvidenceScoringConfig | None = None,
    override: VerificationStatus | None = None,
) -> EvidenceScore:
    return EvidenceScoringService(
        session,
        AuditService(session),
        config=config,
        clock=lambda: NOW,
    ).score(
        account_id=ACCOUNT_ID,
        verification_request_id=REQUEST_ID,
        evidence_ids=tuple(item.evidence_id for item in evidence),
        stances=stances,
        correlation_id=uuid4(),
        operational_status_override=override,
    )


def stance(evidence: InertEvidence, value: EvidenceStance) -> EvidenceStanceInput:
    return EvidenceStanceInput(evidence_id=evidence.evidence_id, stance=value)


def test_authoritative_supporting_evidence_scores_strongly() -> None:
    session = build_evidence_session()
    item = make_evidence(session, source_class=SourceClass.AUTHORITATIVE_REGISTRY)
    record_lineage(session, item, canonical_source_identity="registry")

    result = score(session, (item,), (stance(item, EvidenceStance.SUPPORTS),))

    assert result.final_score >= 7_000
    assert result.verification_status is VerificationStatus.VERIFIED
    assert EvidenceScoringReason.AUTHORITATIVE_SOURCE_PRESENT.value in result.reason_codes


def test_multiple_independent_supporting_sources_increase_corroboration() -> None:
    session = build_evidence_session()
    first = make_evidence(session, body="a", source_uri="https://a.example")
    second = make_evidence(session, body="b", source_uri="https://b.example")
    record_lineage(session, first, canonical_source_identity="a")
    record_lineage(session, second, canonical_source_identity="b")

    single = score(session, (first,), (stance(first, EvidenceStance.SUPPORTS),))
    multiple = score(
        session,
        (first, second),
        (stance(first, EvidenceStance.SUPPORTS), stance(second, EvidenceStance.SUPPORTS)),
    )

    assert multiple.independent_evidence_count == 2
    assert multiple.corroboration_component > single.corroboration_component
    assert EvidenceScoringReason.MULTIPLE_INDEPENDENT_SOURCES.value in multiple.reason_codes


def test_syndicated_copies_do_not_multiply_independent_credit() -> None:
    session = build_evidence_session()
    first = make_evidence(session, body="wire a", source_uri="https://a.example")
    second = make_evidence(session, body="wire b", source_uri="https://b.example")
    record_lineage(
        session,
        first,
        lineage_type=EvidenceLineageType.SYNDICATED,
        origin_reference="urn:wire:story",
    )
    record_lineage(
        session,
        second,
        lineage_type=EvidenceLineageType.SYNDICATED,
        origin_reference="urn:wire:story",
    )

    result = score(
        session,
        (first, second),
        (stance(first, EvidenceStance.SUPPORTS), stance(second, EvidenceStance.SUPPORTS)),
    )

    assert result.independent_evidence_count == 1
    assert EvidenceScoringReason.DEPENDENT_EVIDENCE_DISCOUNTED.value in result.reason_codes


def test_mirror_or_derivative_evidence_is_discounted() -> None:
    session = build_evidence_session()
    parent = make_evidence(session, body="primary", source_uri="https://primary.example")
    child = make_evidence(session, body="mirror", source_uri="https://mirror.example")
    record_lineage(session, parent, canonical_source_identity="primary")
    record_lineage(
        session,
        child,
        lineage_type=EvidenceLineageType.MIRROR,
        parent_evidence_ids=(parent.evidence_id,),
    )

    result = score(
        session,
        (parent, child),
        (stance(parent, EvidenceStance.SUPPORTS), stance(child, EvidenceStance.SUPPORTS)),
    )

    assert result.independent_evidence_count == 1
    assert EvidenceScoringReason.DEPENDENT_EVIDENCE_DISCOUNTED.value in result.reason_codes


def test_unknown_lineage_is_treated_conservatively() -> None:
    session = build_evidence_session()
    first = make_evidence(session, body="one", source_uri="https://one.example")
    second = make_evidence(session, body="two", source_uri="https://two.example")
    record_lineage(session, first, lineage_type=EvidenceLineageType.UNKNOWN)
    record_lineage(session, second)

    result = score(
        session,
        (first, second),
        (stance(first, EvidenceStance.SUPPORTS), stance(second, EvidenceStance.SUPPORTS)),
    )

    assert result.independent_evidence_count == 1
    assert EvidenceScoringReason.UNKNOWN_LINEAGE_DISCOUNTED.value in result.reason_codes


def test_poor_extraction_quality_lowers_evidence_strength() -> None:
    session = build_evidence_session()
    clean = make_evidence(session, body="support", source_uri="https://clean.example")
    partial = make_evidence(session, body="x" * 5000, source_uri="https://partial.example")
    record_lineage(session, clean, canonical_source_identity="clean")
    record_lineage(session, partial, canonical_source_identity="partial")

    clean_score = score(session, (clean,), (stance(clean, EvidenceStance.SUPPORTS),))
    partial_score = score(session, (partial,), (stance(partial, EvidenceStance.SUPPORTS),))

    assert partial_score.extraction_quality_component < clean_score.extraction_quality_component
    assert partial_score.final_score < clean_score.final_score


def test_contradictory_evidence_lowers_score() -> None:
    session = build_evidence_session()
    support = make_evidence(session, body="yes", source_uri="https://yes.example")
    contradiction = make_evidence(
        session,
        body="no",
        source_uri="https://no.example",
        source_class=SourceClass.AUTHORITATIVE_REGISTRY,
    )
    record_lineage(session, support, canonical_source_identity="yes")
    record_lineage(session, contradiction, canonical_source_identity="no")

    supporting = score(session, (support,), (stance(support, EvidenceStance.SUPPORTS),))
    mixed = score(
        session,
        (support, contradiction),
        (
            stance(support, EvidenceStance.SUPPORTS),
            stance(contradiction, EvidenceStance.CONTRADICTS),
        ),
    )

    assert mixed.final_score < supporting.final_score
    assert EvidenceScoringReason.CONTRADICTORY_EVIDENCE_PRESENT.value in mixed.reason_codes


def test_strong_contradiction_can_produce_contradicted() -> None:
    session = build_evidence_session()
    item = make_evidence(
        session,
        body="no",
        source_uri="https://registry.example/no",
        source_class=SourceClass.AUTHORITATIVE_REGISTRY,
    )
    record_lineage(session, item, canonical_source_identity="registry")

    result = score(session, (item,), (stance(item, EvidenceStance.CONTRADICTS),))

    assert result.verification_status is VerificationStatus.CONTRADICTED


def test_weak_evidence_produces_inconclusive() -> None:
    session = build_evidence_session()
    item = make_evidence(
        session,
        body="maybe",
        source_uri="https://unknown.example",
        source_class=SourceClass.UNKNOWN,
    )
    record_lineage(session, item, lineage_type=EvidenceLineageType.UNKNOWN)

    result = score(session, (item,), (stance(item, EvidenceStance.SUPPORTS),))

    assert result.verification_status is VerificationStatus.INCONCLUSIVE


def test_inconclusive_is_not_provider_failure() -> None:
    session = build_evidence_session()
    item = make_evidence(session, source_class=SourceClass.UNKNOWN)
    record_lineage(session, item, lineage_type=EvidenceLineageType.UNKNOWN)

    result = score(session, (item,), (stance(item, EvidenceStance.SUPPORTS),))

    assert result.verification_status is VerificationStatus.INCONCLUSIVE
    assert result.verification_status is not VerificationStatus.PROVIDER_FAILED


def test_provider_and_system_failure_overrides_are_operational() -> None:
    session = build_evidence_session()
    item = make_evidence(session, source_class=SourceClass.AUTHORITATIVE_REGISTRY)
    record_lineage(session, item, canonical_source_identity="registry")

    provider = score(
        session,
        (item,),
        (stance(item, EvidenceStance.SUPPORTS),),
        override=VerificationStatus.PROVIDER_FAILED,
    )
    system = score(
        session,
        (item,),
        (stance(item, EvidenceStance.SUPPORTS),),
        override=VerificationStatus.SYSTEM_FAILURE,
    )

    assert provider.verification_status is VerificationStatus.PROVIDER_FAILED
    assert system.verification_status is VerificationStatus.SYSTEM_FAILURE


def test_same_inputs_and_config_are_deterministic_and_versioned() -> None:
    session = build_evidence_session()
    item = make_evidence(session, source_class=SourceClass.AUTHORITATIVE_REGISTRY)
    record_lineage(session, item, canonical_source_identity="registry")
    config = EvidenceScoringConfig(evidence_score_version="score-test-v1")

    first = score(session, (item,), (stance(item, EvidenceStance.SUPPORTS),), config=config)
    second = score(session, (item,), (stance(item, EvidenceStance.SUPPORTS),), config=config)

    assert first.final_score == second.final_score
    assert first.evidence_score_version == "score-test-v1"


def test_cross_tenant_evidence_rejected() -> None:
    session = build_evidence_session()
    session.add(Account(id=OTHER_ACCOUNT_ID, display_name="Other", status="active"))
    other_request_id = uuid4()
    session.add(
        VerificationRequest(
            id=other_request_id,
            account_id=OTHER_ACCOUNT_ID,
            request_id=uuid4(),
            agent_id=uuid4(),
            mode="INLINE",
            requested_assurance="STANDARD",
            claim_hash="claim",
            subject_hash="subject",
        )
    )
    session.commit()
    item = make_evidence(session, source_class=SourceClass.REPUTABLE_SECONDARY)
    persisted = session.get(EvidenceItem, item.evidence_id)
    assert persisted is not None
    persisted.account_id = OTHER_ACCOUNT_ID
    persisted.verification_request_id = other_request_id
    session.commit()

    with pytest.raises(CrossTenantEvidenceScoringAccess):
        score(session, (item,), (stance(item, EvidenceStance.SUPPORTS),))


def test_raw_evidence_text_not_in_audit_or_result_reasoning() -> None:
    session = build_evidence_session()
    secret_text = "raw secret evidence body"
    item = make_evidence(session, body=secret_text, source_class=SourceClass.AUTHORITATIVE_REGISTRY)
    record_lineage(session, item, canonical_source_identity="registry")

    result = score(session, (item,), (stance(item, EvidenceStance.SUPPORTS),))
    session.commit()

    events = session.scalars(select(AuditEvent)).all()
    persisted = session.scalar(select(VerificationResult))
    assert persisted is not None
    assert secret_text not in repr([event.payload for event in events])
    assert secret_text not in repr(result.reason_codes)
    assert secret_text not in repr(persisted.score_factors)


def test_no_floating_point_confidence_field_exists() -> None:
    names = {field.name for field in fields(EvidenceScore)}

    assert "confidence" not in names
    assert "probability" not in names
    assert "final_score" in names


def test_stale_and_limited_coverage_reason_codes() -> None:
    session = build_evidence_session()
    old = make_evidence(
        session,
        body="old",
        source_uri="https://old.example",
        source_class=SourceClass.PRIMARY,
        observed_at=NOW - timedelta(days=30),
    )
    record_lineage(session, old, canonical_source_identity="old")

    result = score(
        session,
        (old,),
        (
            EvidenceStanceInput(
                evidence_id=old.evidence_id,
                stance=EvidenceStance.SUPPORTS,
                coverage_basis_points=5_000,
            ),
        ),
        config=EvidenceScoringConfig(max_age_seconds=60),
    )

    assert EvidenceScoringReason.STALE_EVIDENCE.value in result.reason_codes
    assert EvidenceScoringReason.LIMITED_COVERAGE.value in result.reason_codes
