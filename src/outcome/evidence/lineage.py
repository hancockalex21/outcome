from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from urllib.parse import urlparse
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from outcome.audit import AuditEventType, AuditService
from outcome.db.models import (
    EvidenceItem,
    EvidenceLineage,
    EvidenceLineageRelationship,
)
from outcome.evidence.normalizer import SourceClass

LINEAGE_VERSION = "evidence-lineage-v1"


class EvidenceLineageType(StrEnum):
    ORIGINAL = "ORIGINAL"
    DIRECT_DERIVATION = "DIRECT_DERIVATION"
    SYNDICATED = "SYNDICATED"
    MIRROR = "MIRROR"
    AGGREGATED = "AGGREGATED"
    MODEL_SUMMARY = "MODEL_SUMMARY"
    UNKNOWN = "UNKNOWN"


class EvidenceRelationshipType(StrEnum):
    DERIVES_FROM = "derives_from"
    SYNDICATED_FROM = "syndicated_from"
    MIRRORS = "mirrors"
    SUMMARIZES = "summarizes"
    AGGREGATES = "aggregates"
    SHARED_ORIGIN = "shared_origin"


class EvidenceIndependenceRelationship(StrEnum):
    INDEPENDENT = "INDEPENDENT"
    LIKELY_DEPENDENT = "LIKELY_DEPENDENT"
    DIRECTLY_DEPENDENT = "DIRECTLY_DEPENDENT"
    UNKNOWN = "UNKNOWN"


class EvidenceLineageError(ValueError):
    pass


class EvidenceLineageRejected(EvidenceLineageError):
    pass


class EvidenceLineageCycleRejected(EvidenceLineageRejected):
    pass


class CrossTenantLineageAccess(PermissionError):
    pass


@dataclass(frozen=True)
class EvidenceLineageInput:
    evidence_id: UUID
    account_id: UUID
    verification_request_id: UUID
    provider_id: UUID | None
    source_reference: str | None
    source_class: SourceClass
    parent_evidence_ids: tuple[UUID, ...] = ()
    origin_reference: str | None = None
    lineage_type: EvidenceLineageType = EvidenceLineageType.UNKNOWN
    publisher_identity: str | None = None
    canonical_source_identity: str | None = None
    observed_at: datetime | None = None
    lineage_version: str = LINEAGE_VERSION
    lineage_metadata: dict[str, object] | None = None


@dataclass(frozen=True)
class EvidenceLineageRecord:
    evidence_id: UUID
    account_id: UUID
    verification_request_id: UUID
    provider_id: UUID | None
    source_reference: str | None
    source_class: SourceClass
    parent_evidence_ids: tuple[UUID, ...]
    origin_reference: str | None
    lineage_type: EvidenceLineageType
    publisher_identity: str | None
    canonical_source_identity: str | None
    observed_at: datetime
    lineage_version: str


@dataclass(frozen=True)
class EvidenceIndependenceResult:
    relationship: EvidenceIndependenceRelationship
    reason_code: str
    shared_origin: str | None
    lineage_version: str


@dataclass(frozen=True)
class EvidenceGraphNode:
    evidence_id: UUID
    lineage_type: EvidenceLineageType
    source_class: SourceClass
    publisher_identity: str | None
    canonical_source_identity: str | None
    origin_reference: str | None
    lineage_version: str


@dataclass(frozen=True)
class EvidenceGraphEdge:
    parent_evidence_id: UUID
    child_evidence_id: UUID
    relationship_type: EvidenceRelationshipType
    lineage_version: str


@dataclass(frozen=True)
class EvidenceLineageGraph:
    nodes: tuple[EvidenceGraphNode, ...]
    edges: tuple[EvidenceGraphEdge, ...]


class EvidenceLineageService:
    def __init__(self, session: Session, audit_service: AuditService | None = None) -> None:
        self.session = session
        self.audit_service = audit_service or AuditService(session)

    def record_lineage(
        self,
        lineage_input: EvidenceLineageInput,
        *,
        correlation_id: UUID,
    ) -> EvidenceLineageRecord:
        evidence = self._require_evidence(
            account_id=lineage_input.account_id,
            verification_request_id=lineage_input.verification_request_id,
            evidence_id=lineage_input.evidence_id,
        )
        parent_ids = tuple(dict.fromkeys(lineage_input.parent_evidence_ids))
        if lineage_input.evidence_id in parent_ids:
            self._audit_rejected(lineage_input, correlation_id, "LINEAGE_SELF_CYCLE")
            raise EvidenceLineageCycleRejected("evidence cannot derive from itself")
        for parent_id in parent_ids:
            self._require_evidence(
                account_id=lineage_input.account_id,
                verification_request_id=lineage_input.verification_request_id,
                evidence_id=parent_id,
            )
            if self._would_create_cycle(
                account_id=lineage_input.account_id,
                child_id=lineage_input.evidence_id,
                new_parent_id=parent_id,
            ):
                self._audit_rejected(lineage_input, correlation_id, "LINEAGE_CYCLE")
                raise EvidenceLineageCycleRejected("lineage relationship would create a cycle")

        observed_at = _aware_utc(lineage_input.observed_at or evidence.observed_at)
        canonical_identity = normalize_source_identity(
            source_reference=lineage_input.source_reference,
            publisher_identity=lineage_input.publisher_identity,
            canonical_source_identity=lineage_input.canonical_source_identity,
        )
        origin_identity = normalize_source_identity(
            source_reference=lineage_input.origin_reference,
            publisher_identity=None,
            canonical_source_identity=lineage_input.origin_reference,
        )
        origin_hash = _identity_hash(origin_identity or canonical_identity)
        lineage = EvidenceLineage(
            id=uuid4(),
            account_id=lineage_input.account_id,
            evidence_id=lineage_input.evidence_id,
            verification_request_id=lineage_input.verification_request_id,
            provider_id=lineage_input.provider_id,
            source_reference=lineage_input.source_reference,
            source_class=lineage_input.source_class.value,
            lineage_type=lineage_input.lineage_type.value,
            publisher_identity=_normalize_freeform_identity(lineage_input.publisher_identity),
            canonical_source_identity=canonical_identity,
            origin_reference=lineage_input.origin_reference,
            origin_identity_hash=origin_hash,
            observed_at=observed_at,
            lineage_version=lineage_input.lineage_version,
            lineage_metadata=lineage_input.lineage_metadata or {},
        )
        self.session.add(lineage)
        for parent_id in parent_ids:
            self.session.add(
                EvidenceLineageRelationship(
                    id=uuid4(),
                    account_id=lineage_input.account_id,
                    verification_request_id=lineage_input.verification_request_id,
                    parent_evidence_id=parent_id,
                    child_evidence_id=lineage_input.evidence_id,
                    relationship_type=_relationship_for_lineage_type(
                        lineage_input.lineage_type
                    ).value,
                    lineage_version=lineage_input.lineage_version,
                    reason_code="EXPLICIT_LINEAGE_PARENT",
                )
            )
        self.session.flush()
        self.audit_service.append_event(
            account_id=lineage_input.account_id,
            event_type=AuditEventType.EVIDENCE_LINEAGE_RECORDED,
            correlation_id=correlation_id,
            request_id=lineage_input.verification_request_id,
            payload={
                "evidence_id": lineage_input.evidence_id,
                "provider_id": lineage_input.provider_id,
                "source_class": lineage_input.source_class,
                "lineage_type": lineage_input.lineage_type,
                "lineage_version": lineage_input.lineage_version,
                "source_identity_hash": origin_hash or _identity_hash(canonical_identity),
                "reason_codes": ["LINEAGE_RECORDED"],
            },
        )
        return EvidenceLineageRecord(
            evidence_id=lineage_input.evidence_id,
            account_id=lineage_input.account_id,
            verification_request_id=lineage_input.verification_request_id,
            provider_id=lineage_input.provider_id,
            source_reference=lineage_input.source_reference,
            source_class=lineage_input.source_class,
            parent_evidence_ids=parent_ids,
            origin_reference=lineage_input.origin_reference,
            lineage_type=lineage_input.lineage_type,
            publisher_identity=_normalize_freeform_identity(lineage_input.publisher_identity),
            canonical_source_identity=canonical_identity,
            observed_at=observed_at,
            lineage_version=lineage_input.lineage_version,
        )

    def classify_independence(
        self,
        *,
        account_id: UUID,
        left_evidence_id: UUID,
        right_evidence_id: UUID,
        correlation_id: UUID,
    ) -> EvidenceIndependenceResult:
        left = self._latest_lineage(account_id=account_id, evidence_id=left_evidence_id)
        right = self._latest_lineage(account_id=account_id, evidence_id=right_evidence_id)
        if left is None or right is None:
            self._ensure_not_cross_tenant(account_id, left_evidence_id)
            self._ensure_not_cross_tenant(account_id, right_evidence_id)
            result = EvidenceIndependenceResult(
                relationship=EvidenceIndependenceRelationship.UNKNOWN,
                reason_code="UNKNOWN_LINEAGE",
                shared_origin=None,
                lineage_version=LINEAGE_VERSION,
            )
            self._audit_independence(
                account_id,
                left_evidence_id,
                right_evidence_id,
                result,
                correlation_id,
            )
            self.audit_service.append_event(
                account_id=account_id,
                event_type=AuditEventType.EVIDENCE_UNKNOWN_LINEAGE_ENCOUNTERED,
                correlation_id=correlation_id,
                payload={
                    "left_evidence_id": left_evidence_id,
                    "right_evidence_id": right_evidence_id,
                    "independence_result": result.relationship,
                    "reason_codes": [result.reason_code],
                },
            )
            return result

        result = self._classify_from_lineage(left, right)
        self._audit_independence(
            account_id,
            left_evidence_id,
            right_evidence_id,
            result,
            correlation_id,
        )
        if result.shared_origin is not None:
            self.audit_service.append_event(
                account_id=account_id,
                event_type=AuditEventType.EVIDENCE_SHARED_ORIGIN_DETECTED,
                correlation_id=correlation_id,
                request_id=left.verification_request_id,
                payload={
                    "left_evidence_id": left_evidence_id,
                    "right_evidence_id": right_evidence_id,
                    "shared_origin": result.shared_origin,
                    "independence_result": result.relationship,
                    "reason_codes": [result.reason_code],
                },
            )
        return result

    def graph_for_request(
        self,
        *,
        account_id: UUID,
        verification_request_id: UUID,
    ) -> EvidenceLineageGraph:
        lineages = tuple(
            self.session.scalars(
                select(EvidenceLineage)
                .where(
                    EvidenceLineage.account_id == account_id,
                    EvidenceLineage.verification_request_id == verification_request_id,
                )
                .order_by(
                    EvidenceLineage.observed_at,
                    EvidenceLineage.evidence_id,
                    EvidenceLineage.lineage_version,
                )
            )
        )
        edges = [
            EvidenceGraphEdge(
                parent_evidence_id=edge.parent_evidence_id,
                child_evidence_id=edge.child_evidence_id,
                relationship_type=EvidenceRelationshipType(edge.relationship_type),
                lineage_version=edge.lineage_version,
            )
            for edge in self.session.scalars(
                select(EvidenceLineageRelationship)
                .where(
                    EvidenceLineageRelationship.account_id == account_id,
                    EvidenceLineageRelationship.verification_request_id
                    == verification_request_id,
                )
                .order_by(
                    EvidenceLineageRelationship.parent_evidence_id,
                    EvidenceLineageRelationship.child_evidence_id,
                    EvidenceLineageRelationship.relationship_type,
                    EvidenceLineageRelationship.lineage_version,
                )
            )
        ]
        edges.extend(_shared_origin_edges(lineages))
        return EvidenceLineageGraph(
            nodes=tuple(_node_from_lineage(lineage) for lineage in lineages),
            edges=tuple(
                sorted(
                    edges,
                    key=lambda edge: (
                        str(edge.parent_evidence_id),
                        str(edge.child_evidence_id),
                        edge.relationship_type.value,
                        edge.lineage_version,
                    ),
                )
            ),
        )

    def _classify_from_lineage(
        self,
        left: EvidenceLineage,
        right: EvidenceLineage,
    ) -> EvidenceIndependenceResult:
        lineage_version = max(left.lineage_version, right.lineage_version)
        direct_relationship = self._relationship_between(left, right)
        if direct_relationship is not None:
            return EvidenceIndependenceResult(
                relationship=EvidenceIndependenceRelationship.DIRECTLY_DEPENDENT,
                reason_code="DIRECT_PARENT_CHILD",
                shared_origin=_shared_origin(left, right),
                lineage_version=lineage_version,
            )
        if (
            left.lineage_type == EvidenceLineageType.UNKNOWN.value
            or right.lineage_type == EvidenceLineageType.UNKNOWN.value
        ):
            return EvidenceIndependenceResult(
                relationship=EvidenceIndependenceRelationship.UNKNOWN,
                reason_code="UNKNOWN_LINEAGE",
                shared_origin=_shared_origin(left, right),
                lineage_version=lineage_version,
            )
        if _same_origin_hash(left, right):
            return EvidenceIndependenceResult(
                relationship=EvidenceIndependenceRelationship.LIKELY_DEPENDENT,
                reason_code="SAME_UPSTREAM_ORIGIN",
                shared_origin=_shared_origin(left, right),
                lineage_version=lineage_version,
            )
        if (
            left.canonical_source_identity is not None
            and left.canonical_source_identity == right.canonical_source_identity
        ):
            return EvidenceIndependenceResult(
                relationship=EvidenceIndependenceRelationship.LIKELY_DEPENDENT,
                reason_code="SAME_CANONICAL_SOURCE",
                shared_origin=left.canonical_source_identity,
                lineage_version=lineage_version,
            )
        if (
            left.lineage_type == EvidenceLineageType.ORIGINAL.value
            and right.lineage_type == EvidenceLineageType.ORIGINAL.value
        ):
            return EvidenceIndependenceResult(
                relationship=EvidenceIndependenceRelationship.INDEPENDENT,
                reason_code="UNRELATED_ORIGINAL_SOURCES",
                shared_origin=None,
                lineage_version=lineage_version,
            )
        return EvidenceIndependenceResult(
            relationship=EvidenceIndependenceRelationship.UNKNOWN,
            reason_code="INSUFFICIENT_LINEAGE",
            shared_origin=None,
            lineage_version=lineage_version,
        )

    def _relationship_between(
        self,
        left: EvidenceLineage,
        right: EvidenceLineage,
    ) -> EvidenceLineageRelationship | None:
        return self.session.scalar(
            select(EvidenceLineageRelationship).where(
                EvidenceLineageRelationship.account_id == left.account_id,
                EvidenceLineageRelationship.verification_request_id
                == left.verification_request_id,
                (
                    (
                        EvidenceLineageRelationship.parent_evidence_id == left.evidence_id
                    )
                    & (
                        EvidenceLineageRelationship.child_evidence_id
                        == right.evidence_id
                    )
                )
                | (
                    (
                        EvidenceLineageRelationship.parent_evidence_id == right.evidence_id
                    )
                    & (
                        EvidenceLineageRelationship.child_evidence_id
                        == left.evidence_id
                    )
                ),
            )
        )

    def _latest_lineage(self, *, account_id: UUID, evidence_id: UUID) -> EvidenceLineage | None:
        return self.session.scalar(
            select(EvidenceLineage)
            .where(
                EvidenceLineage.account_id == account_id,
                EvidenceLineage.evidence_id == evidence_id,
            )
            .order_by(EvidenceLineage.created_at.desc(), EvidenceLineage.lineage_version.desc())
        )

    def _require_evidence(
        self,
        *,
        account_id: UUID,
        verification_request_id: UUID,
        evidence_id: UUID,
    ) -> EvidenceItem:
        item = self.session.scalar(
            select(EvidenceItem).where(
                EvidenceItem.account_id == account_id,
                EvidenceItem.verification_request_id == verification_request_id,
                EvidenceItem.id == evidence_id,
            )
        )
        if item is not None:
            return item
        self._ensure_not_cross_tenant(account_id, evidence_id)
        raise EvidenceLineageRejected("evidence does not exist in this verification request")

    def _ensure_not_cross_tenant(self, account_id: UUID, evidence_id: UUID) -> None:
        cross_tenant = self.session.scalar(
            select(EvidenceItem).where(EvidenceItem.id == evidence_id)
        )
        if cross_tenant is not None and cross_tenant.account_id != account_id:
            raise CrossTenantLineageAccess("evidence belongs to a different account")

    def _would_create_cycle(
        self,
        *,
        account_id: UUID,
        child_id: UUID,
        new_parent_id: UUID,
    ) -> bool:
        descendants = {child_id}
        stack = [child_id]
        while stack:
            current = stack.pop()
            children = self.session.scalars(
                select(EvidenceLineageRelationship.child_evidence_id).where(
                    EvidenceLineageRelationship.account_id == account_id,
                    EvidenceLineageRelationship.parent_evidence_id == current,
                )
            ).all()
            for descendant in children:
                if descendant == new_parent_id:
                    return True
                if descendant not in descendants:
                    descendants.add(descendant)
                    stack.append(descendant)
        return False

    def _audit_rejected(
        self,
        lineage_input: EvidenceLineageInput,
        correlation_id: UUID,
        reason_code: str,
    ) -> None:
        self.audit_service.append_event(
            account_id=lineage_input.account_id,
            event_type=AuditEventType.EVIDENCE_LINEAGE_RELATIONSHIP_REJECTED,
            correlation_id=correlation_id,
            request_id=lineage_input.verification_request_id,
            payload={
                "evidence_id": lineage_input.evidence_id,
                "lineage_type": lineage_input.lineage_type,
                "lineage_version": lineage_input.lineage_version,
                "reason_codes": [reason_code],
            },
        )

    def _audit_independence(
        self,
        account_id: UUID,
        left_evidence_id: UUID,
        right_evidence_id: UUID,
        result: EvidenceIndependenceResult,
        correlation_id: UUID,
    ) -> None:
        self.audit_service.append_event(
            account_id=account_id,
            event_type=AuditEventType.EVIDENCE_INDEPENDENCE_EVALUATED,
            correlation_id=correlation_id,
            payload={
                "left_evidence_id": left_evidence_id,
                "right_evidence_id": right_evidence_id,
                "independence_result": result.relationship,
                "shared_origin": result.shared_origin,
                "lineage_version": result.lineage_version,
                "reason_codes": [result.reason_code],
            },
        )


def normalize_source_identity(
    *,
    source_reference: str | None,
    publisher_identity: str | None = None,
    canonical_source_identity: str | None = None,
) -> str | None:
    if canonical_source_identity:
        return _normalize_freeform_identity(canonical_source_identity)
    if publisher_identity:
        return _normalize_freeform_identity(publisher_identity)
    if not source_reference:
        return None
    parsed = urlparse(source_reference)
    if parsed.scheme in {"http", "https"} and parsed.hostname:
        hostname = parsed.hostname.lower()
        if hostname.startswith("www."):
            hostname = hostname[4:]
        return hostname
    if parsed.scheme in {"urn", "provider", "evidence"}:
        return _normalize_freeform_identity(source_reference)
    return _normalize_freeform_identity(source_reference)


def _normalize_freeform_identity(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = re.sub(r"\s+", " ", value.strip().lower())
    return normalized or None


def _identity_hash(value: str | None) -> str | None:
    if value is None:
        return None
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise EvidenceLineageRejected("lineage timestamps must be timezone-aware")
    return value.astimezone(UTC)


def _relationship_for_lineage_type(
    lineage_type: EvidenceLineageType,
) -> EvidenceRelationshipType:
    match lineage_type:
        case EvidenceLineageType.SYNDICATED:
            return EvidenceRelationshipType.SYNDICATED_FROM
        case EvidenceLineageType.MIRROR:
            return EvidenceRelationshipType.MIRRORS
        case EvidenceLineageType.AGGREGATED:
            return EvidenceRelationshipType.AGGREGATES
        case EvidenceLineageType.MODEL_SUMMARY:
            return EvidenceRelationshipType.SUMMARIZES
        case _:
            return EvidenceRelationshipType.DERIVES_FROM


def _node_from_lineage(lineage: EvidenceLineage) -> EvidenceGraphNode:
    return EvidenceGraphNode(
        evidence_id=lineage.evidence_id,
        lineage_type=EvidenceLineageType(lineage.lineage_type),
        source_class=SourceClass(lineage.source_class),
        publisher_identity=lineage.publisher_identity,
        canonical_source_identity=lineage.canonical_source_identity,
        origin_reference=lineage.origin_reference,
        lineage_version=lineage.lineage_version,
    )


def _same_origin_hash(left: EvidenceLineage, right: EvidenceLineage) -> bool:
    return (
        left.origin_identity_hash is not None
        and left.origin_identity_hash == right.origin_identity_hash
    )


def _shared_origin(left: EvidenceLineage, right: EvidenceLineage) -> str | None:
    if _same_origin_hash(left, right):
        return left.origin_reference or left.origin_identity_hash
    if (
        left.canonical_source_identity is not None
        and left.canonical_source_identity == right.canonical_source_identity
    ):
        return left.canonical_source_identity
    return None


def _shared_origin_edges(lineages: tuple[EvidenceLineage, ...]) -> list[EvidenceGraphEdge]:
    edges: list[EvidenceGraphEdge] = []
    for left_index, left in enumerate(lineages):
        for right in lineages[left_index + 1 :]:
            if _shared_origin(left, right) is None:
                continue
            parent_id, child_id = sorted((left.evidence_id, right.evidence_id), key=str)
            edges.append(
                EvidenceGraphEdge(
                    parent_evidence_id=parent_id,
                    child_evidence_id=child_id,
                    relationship_type=EvidenceRelationshipType.SHARED_ORIGIN,
                    lineage_version=max(left.lineage_version, right.lineage_version),
                )
            )
    return edges


__all__ = [
    "CrossTenantLineageAccess",
    "EvidenceGraphEdge",
    "EvidenceGraphNode",
    "EvidenceIndependenceRelationship",
    "EvidenceIndependenceResult",
    "EvidenceLineageCycleRejected",
    "EvidenceLineageError",
    "EvidenceLineageGraph",
    "EvidenceLineageInput",
    "EvidenceLineageRecord",
    "EvidenceLineageRejected",
    "EvidenceLineageService",
    "EvidenceLineageType",
    "EvidenceRelationshipType",
    "LINEAGE_VERSION",
    "normalize_source_identity",
]
