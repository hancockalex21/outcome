from __future__ import annotations

from typing import cast
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from outcome.audit import AuditEventType, AuditService
from outcome.db.models import Account, AuditEvent, VerificationRequest
from outcome.evidence import (
    CrossTenantLineageAccess,
    EvidenceIndependenceRelationship,
    EvidenceLineageCycleRejected,
    EvidenceLineageInput,
    EvidenceLineageService,
    EvidenceLineageType,
    EvidenceNormalizationInput,
    EvidenceNormalizer,
    ExtractionQuality,
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


def _make_evidence(
    session: Session,
    *,
    body: str,
    source_uri: str,
    source_class: SourceClass = SourceClass.UNKNOWN,
    content_type: str = "text/plain",
) -> InertEvidence:
    inert = normalize(
        session,
        evidence_input(
            body=body,
            source_uri=source_uri,
            source_class=source_class,
            content_type=content_type,
        ),
    )
    return cast(InertEvidence, inert)


def _record(
    service: EvidenceLineageService,
    evidence: InertEvidence,
    *,
    lineage_type: EvidenceLineageType = EvidenceLineageType.ORIGINAL,
    parent_evidence_ids: tuple[UUID, ...] = (),
    origin_reference: str | None = None,
    publisher_identity: str | None = None,
    canonical_source_identity: str | None = None,
    source_class: SourceClass | None = None,
    lineage_version: str = "lineage-v1",
) -> None:
    service.record_lineage(
        EvidenceLineageInput(
            evidence_id=evidence.evidence_id,
            account_id=evidence.account_id,
            verification_request_id=evidence.verification_request_id,
            provider_id=evidence.provider_id,
            source_reference=evidence.source_uri,
            source_class=source_class or evidence.source_class,
            parent_evidence_ids=parent_evidence_ids,
            origin_reference=origin_reference,
            lineage_type=lineage_type,
            publisher_identity=publisher_identity,
            canonical_source_identity=canonical_source_identity,
            observed_at=evidence.observed_at,
            lineage_version=lineage_version,
        ),
        correlation_id=uuid4(),
    )


def _classify(
    service: EvidenceLineageService,
    left: InertEvidence,
    right: InertEvidence,
) -> EvidenceIndependenceRelationship:
    return service.classify_independence(
        account_id=ACCOUNT_ID,
        left_evidence_id=left.evidence_id,
        right_evidence_id=right.evidence_id,
        correlation_id=uuid4(),
    ).relationship


def test_unrelated_original_sources_are_independent() -> None:
    session = build_evidence_session()
    service = EvidenceLineageService(session)
    left = _make_evidence(session, body="alpha", source_uri="https://alpha.example/a")
    right = _make_evidence(session, body="beta", source_uri="https://beta.example/b")

    _record(service, left, canonical_source_identity="Alpha Publisher")
    _record(service, right, canonical_source_identity="Beta Publisher")

    assert _classify(service, left, right) is EvidenceIndependenceRelationship.INDEPENDENT


def test_direct_parent_child_is_directly_dependent() -> None:
    session = build_evidence_session()
    service = EvidenceLineageService(session)
    parent = _make_evidence(session, body="original", source_uri="https://source.example/a")
    child = _make_evidence(session, body="copy", source_uri="https://copy.example/a")

    _record(service, parent, canonical_source_identity="source.example")
    _record(
        service,
        child,
        lineage_type=EvidenceLineageType.DIRECT_DERIVATION,
        parent_evidence_ids=(parent.evidence_id,),
        canonical_source_identity="copy.example",
    )

    assert _classify(service, parent, child) is EvidenceIndependenceRelationship.DIRECTLY_DEPENDENT


def test_same_upstream_origin_is_likely_dependent() -> None:
    session = build_evidence_session()
    service = EvidenceLineageService(session)
    left = _make_evidence(session, body="wire one", source_uri="https://one.example/story")
    right = _make_evidence(session, body="wire two", source_uri="https://two.example/story")

    _record(service, left, origin_reference="urn:wire:story-123")
    _record(service, right, origin_reference="urn:wire:story-123")

    assert _classify(service, left, right) is EvidenceIndependenceRelationship.LIKELY_DEPENDENT


@pytest.mark.parametrize(
    "lineage_type",
    [
        EvidenceLineageType.SYNDICATED,
        EvidenceLineageType.MIRROR,
        EvidenceLineageType.MODEL_SUMMARY,
    ],
)
def test_copied_lineage_types_are_not_independent(
    lineage_type: EvidenceLineageType,
) -> None:
    session = build_evidence_session()
    service = EvidenceLineageService(session)
    left = _make_evidence(session, body=f"{lineage_type} left", source_uri="https://a.example")
    right = _make_evidence(session, body=f"{lineage_type} right", source_uri="https://b.example")

    _record(service, left, lineage_type=lineage_type, origin_reference="urn:origin:shared")
    _record(service, right, lineage_type=lineage_type, origin_reference="urn:origin:shared")

    assert _classify(service, left, right) is EvidenceIndependenceRelationship.LIKELY_DEPENDENT


def test_same_canonical_source_does_not_count_as_independence() -> None:
    session = build_evidence_session()
    service = EvidenceLineageService(session)
    left = _make_evidence(session, body="page one", source_uri="https://publisher.example/a")
    right = _make_evidence(session, body="page two", source_uri="https://publisher.example/b")

    _record(service, left, canonical_source_identity="Publisher Example")
    _record(service, right, canonical_source_identity="publisher example")

    assert _classify(service, left, right) is EvidenceIndependenceRelationship.LIKELY_DEPENDENT


def test_different_domains_with_same_syndicated_origin_are_dependent() -> None:
    session = build_evidence_session()
    service = EvidenceLineageService(session)
    left = _make_evidence(session, body="press release one", source_uri="https://site-a.example")
    right = _make_evidence(session, body="press release two", source_uri="https://site-b.example")

    _record(service, left, lineage_type=EvidenceLineageType.SYNDICATED, origin_reference="urn:pr:9")
    _record(
        service,
        right,
        lineage_type=EvidenceLineageType.SYNDICATED,
        origin_reference="urn:pr:9",
    )

    assert _classify(service, left, right) is EvidenceIndependenceRelationship.LIKELY_DEPENDENT


def test_unknown_lineage_does_not_automatically_count_as_independent() -> None:
    session = build_evidence_session()
    service = EvidenceLineageService(session)
    left = _make_evidence(session, body="unknown one", source_uri="https://one.example")
    right = _make_evidence(session, body="unknown two", source_uri="https://two.example")

    _record(service, left, lineage_type=EvidenceLineageType.UNKNOWN)
    _record(service, right)

    result = service.classify_independence(
        account_id=ACCOUNT_ID,
        left_evidence_id=left.evidence_id,
        right_evidence_id=right.evidence_id,
        correlation_id=uuid4(),
    )

    assert result.relationship is EvidenceIndependenceRelationship.UNKNOWN
    assert result.reason_code == "UNKNOWN_LINEAGE"


def test_source_class_and_extraction_quality_remain_separate_from_lineage() -> None:
    session = build_evidence_session()
    service = EvidenceLineageService(session)
    authoritative = _make_evidence(
        session,
        body='{"verified":true}',
        content_type="application/json",
        source_uri="https://registry.example/item",
        source_class=SourceClass.AUTHORITATIVE_REGISTRY,
    )
    derivative = _make_evidence(
        session,
        body="summary",
        source_uri="https://summary.example/item",
        source_class=SourceClass.REPUTABLE_SECONDARY,
    )

    _record(service, authoritative, source_class=SourceClass.AUTHORITATIVE_REGISTRY)
    _record(
        service,
        derivative,
        lineage_type=EvidenceLineageType.DIRECT_DERIVATION,
        parent_evidence_ids=(authoritative.evidence_id,),
        source_class=SourceClass.REPUTABLE_SECONDARY,
    )

    assert authoritative.source_class is SourceClass.AUTHORITATIVE_REGISTRY
    assert authoritative.extraction_quality is ExtractionQuality.EXACT_STRUCTURED
    assert _classify(service, authoritative, derivative) is (
        EvidenceIndependenceRelationship.DIRECTLY_DEPENDENT
    )


def test_graph_reconstruction_is_deterministic_and_includes_shared_origin() -> None:
    session = build_evidence_session()
    service = EvidenceLineageService(session)
    first = _make_evidence(session, body="first", source_uri="https://a.example")
    second = _make_evidence(session, body="second", source_uri="https://b.example")
    child = _make_evidence(session, body="child", source_uri="https://c.example")

    _record(service, second, origin_reference="urn:shared")
    _record(service, first, origin_reference="urn:shared")
    _record(
        service,
        child,
        lineage_type=EvidenceLineageType.AGGREGATED,
        parent_evidence_ids=(first.evidence_id, second.evidence_id),
    )

    graph = service.graph_for_request(account_id=ACCOUNT_ID, verification_request_id=REQUEST_ID)
    graph_again = service.graph_for_request(
        account_id=ACCOUNT_ID,
        verification_request_id=REQUEST_ID,
    )

    assert graph == graph_again
    assert [node.evidence_id for node in graph.nodes] == sorted(
        [first.evidence_id, second.evidence_id, child.evidence_id],
        key=str,
    )
    assert any(edge.relationship_type.value == "shared_origin" for edge in graph.edges)


def test_cycle_is_rejected() -> None:
    session = build_evidence_session()
    service = EvidenceLineageService(session)
    parent = _make_evidence(session, body="parent", source_uri="https://parent.example")
    child = _make_evidence(session, body="child", source_uri="https://child.example")

    _record(service, parent)
    _record(
        service,
        child,
        lineage_type=EvidenceLineageType.DIRECT_DERIVATION,
        parent_evidence_ids=(parent.evidence_id,),
    )

    with pytest.raises(EvidenceLineageCycleRejected):
        _record(
            service,
            parent,
            lineage_type=EvidenceLineageType.DIRECT_DERIVATION,
            parent_evidence_ids=(child.evidence_id,),
            lineage_version="lineage-v2",
        )


def test_cross_tenant_relationship_rejected() -> None:
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
    own = _make_evidence(session, body="own", source_uri="https://own.example")
    other = EvidenceNormalizer(session, AuditService(session)).normalize(
        EvidenceNormalizationInput(
            account_id=OTHER_ACCOUNT_ID,
            verification_request_id=other_request_id,
            provider_id=PROVIDER_ID,
            provider_alias="provider",
            source_uri="https://other.example",
            source_class=SourceClass.UNKNOWN,
            content_type="text/plain",
            body="other",
            observed_at=OBSERVED_AT,
            authority_metadata={},
            lineage_metadata={},
        ),
        correlation_id=uuid4(),
    )
    service = EvidenceLineageService(session)

    with pytest.raises(CrossTenantLineageAccess):
        _record(
            service,
            own,
            lineage_type=EvidenceLineageType.DIRECT_DERIVATION,
            parent_evidence_ids=(other.evidence_id,),
        )


def test_lineage_service_is_append_only_at_service_boundary() -> None:
    methods = {
        name
        for name in dir(EvidenceLineageService)
        if not name.startswith("_") and callable(getattr(EvidenceLineageService, name))
    }

    assert methods == {"classify_independence", "graph_for_request", "record_lineage"}


def test_raw_evidence_not_emitted_to_audit() -> None:
    session = build_evidence_session()
    service = EvidenceLineageService(session)
    secret_text = "sensitive raw evidence body"
    first = _make_evidence(session, body=secret_text, source_uri="https://first.example")
    second = _make_evidence(session, body="second", source_uri="https://second.example")

    _record(service, first, origin_reference="urn:safe-origin")
    _record(service, second, origin_reference="urn:safe-origin")
    service.classify_independence(
        account_id=ACCOUNT_ID,
        left_evidence_id=first.evidence_id,
        right_evidence_id=second.evidence_id,
        correlation_id=uuid4(),
    )
    session.commit()

    lineage_events = session.scalars(
        select(AuditEvent).where(
            AuditEvent.event_type.in_(
                [
                    AuditEventType.EVIDENCE_LINEAGE_RECORDED.value,
                    AuditEventType.EVIDENCE_INDEPENDENCE_EVALUATED.value,
                    AuditEventType.EVIDENCE_SHARED_ORIGIN_DETECTED.value,
                ]
            )
        )
    ).all()
    assert lineage_events
    assert secret_text not in repr([event.payload for event in lineage_events])
