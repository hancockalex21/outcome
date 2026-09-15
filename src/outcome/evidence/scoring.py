from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from outcome.audit import AuditEventType, AuditService
from outcome.db.models import EvidenceItem, VerificationRequest, VerificationResult
from outcome.domain import AssuranceLevel, VerificationStatus
from outcome.evidence.lineage import (
    EvidenceIndependenceRelationship,
    EvidenceLineageService,
)
from outcome.evidence.normalizer import ExtractionQuality, SourceClass

EVIDENCE_SCORE_VERSION = "evidence-score-v1"
SCORE_MAX = 10_000


class EvidenceStance(StrEnum):
    SUPPORTS = "SUPPORTS"
    CONTRADICTS = "CONTRADICTS"
    NEUTRAL = "NEUTRAL"
    UNKNOWN = "UNKNOWN"


class EvidenceScoringReason(StrEnum):
    AUTHORITATIVE_SOURCE_PRESENT = "AUTHORITATIVE_SOURCE_PRESENT"
    MULTIPLE_INDEPENDENT_SOURCES = "MULTIPLE_INDEPENDENT_SOURCES"
    DEPENDENT_EVIDENCE_DISCOUNTED = "DEPENDENT_EVIDENCE_DISCOUNTED"
    UNKNOWN_LINEAGE_DISCOUNTED = "UNKNOWN_LINEAGE_DISCOUNTED"
    LOW_EXTRACTION_QUALITY = "LOW_EXTRACTION_QUALITY"
    CONTRADICTORY_EVIDENCE_PRESENT = "CONTRADICTORY_EVIDENCE_PRESENT"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    STALE_EVIDENCE = "STALE_EVIDENCE"
    LIMITED_COVERAGE = "LIMITED_COVERAGE"
    PROVIDER_FAILURE_OVERRIDE = "PROVIDER_FAILURE_OVERRIDE"
    SYSTEM_FAILURE_OVERRIDE = "SYSTEM_FAILURE_OVERRIDE"
    VERIFICATION_STATUS_VERIFIED = "VERIFICATION_STATUS_VERIFIED"
    VERIFICATION_STATUS_CONTRADICTED = "VERIFICATION_STATUS_CONTRADICTED"
    VERIFICATION_STATUS_INCONCLUSIVE = "VERIFICATION_STATUS_INCONCLUSIVE"


class EvidenceExclusionReason(StrEnum):
    CROSS_TENANT = "CROSS_TENANT"
    WRONG_VERIFICATION_REQUEST = "WRONG_VERIFICATION_REQUEST"
    EXTRACTION_FAILED = "EXTRACTION_FAILED"
    EXPLICITLY_UNUSABLE = "EXPLICITLY_UNUSABLE"
    MISSING_EVIDENCE = "MISSING_EVIDENCE"


class EvidenceScoringError(ValueError):
    pass


class CrossTenantEvidenceScoringAccess(PermissionError):
    pass


@dataclass(frozen=True)
class EvidenceStanceInput:
    evidence_id: UUID
    stance: EvidenceStance
    coverage_basis_points: int = SCORE_MAX


@dataclass(frozen=True)
class EvidenceScoringConfig:
    evidence_score_version: str = EVIDENCE_SCORE_VERSION
    verified_threshold: int = 7_000
    contradicted_threshold: int = 7_000
    contradiction_block_threshold: int = 4_000
    max_age_seconds: int | None = None
    authority_weights: dict[SourceClass, int] | None = None
    extraction_quality_weights: dict[ExtractionQuality, int] | None = None
    component_weights: dict[str, int] | None = None

    def authority_weight(self, source_class: SourceClass) -> int:
        return (self.authority_weights or _AUTHORITY_WEIGHTS)[source_class]

    def extraction_weight(self, quality: ExtractionQuality) -> int:
        return (self.extraction_quality_weights or _EXTRACTION_WEIGHTS)[quality]

    def component_weight(self, component: str) -> int:
        return (self.component_weights or _COMPONENT_WEIGHTS)[component]


@dataclass(frozen=True)
class EvidenceScore:
    verification_request_id: UUID
    account_id: UUID
    evidence_score_version: str
    evidence_count: int
    independent_evidence_count: int
    source_authority_component: int
    extraction_quality_component: int
    independence_component: int
    corroboration_component: int
    contradiction_component: int
    freshness_component: int
    coverage_component: int
    final_score: int
    verification_status: VerificationStatus
    reason_codes: tuple[str, ...]
    evidence_ids_used: tuple[UUID, ...]
    evidence_ids_excluded: tuple[UUID, ...]
    computed_at: datetime


@dataclass(frozen=True)
class _EligibleEvidence:
    item: EvidenceItem
    stance: EvidenceStance
    coverage_basis_points: int
    authority_score: int
    extraction_score: int

    @property
    def strength(self) -> int:
        return (self.authority_score + self.extraction_score) // 2


_AUTHORITY_WEIGHTS = {
    SourceClass.AUTHORITATIVE_REGISTRY: 9_000,
    SourceClass.PRIMARY: 8_500,
    SourceClass.REPUTABLE_SECONDARY: 6_500,
    SourceClass.DERIVATIVE: 3_000,
    SourceClass.UNKNOWN: 1_500,
}

_EXTRACTION_WEIGHTS = {
    ExtractionQuality.EXACT_STRUCTURED: 9_000,
    ExtractionQuality.DIRECT_TEXT: 8_000,
    ExtractionQuality.NORMALIZED_TEXT: 6_500,
    ExtractionQuality.PARTIAL: 3_500,
    ExtractionQuality.LOW_CONFIDENCE: 1_500,
    ExtractionQuality.FAILED: 0,
}

_COMPONENT_WEIGHTS = {
    "source_authority": 2_000,
    "extraction_quality": 1_500,
    "independence": 2_000,
    "corroboration": 2_000,
    "contradiction": 2_000,
    "freshness": 300,
    "coverage": 200,
}


class EvidenceScoringService:
    def __init__(
        self,
        session: Session,
        audit_service: AuditService | None = None,
        *,
        lineage_service: EvidenceLineageService | None = None,
        config: EvidenceScoringConfig | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.session = session
        self.audit_service = audit_service or AuditService(session)
        self.lineage_service = lineage_service or EvidenceLineageService(
            session,
            self.audit_service,
        )
        self.config = config or EvidenceScoringConfig()
        self.clock = clock or (lambda: datetime.now(UTC))

    def score(
        self,
        *,
        account_id: UUID,
        verification_request_id: UUID,
        evidence_ids: tuple[UUID, ...],
        stances: tuple[EvidenceStanceInput, ...],
        correlation_id: UUID,
        operational_status_override: VerificationStatus | None = None,
    ) -> EvidenceScore:
        computed_at = _aware_utc(self.clock())
        request = self._require_request(account_id, verification_request_id)
        stance_by_id = {stance.evidence_id: stance for stance in stances}
        eligible: list[_EligibleEvidence] = []
        excluded: list[UUID] = []
        reason_codes: set[str] = set()

        for evidence_id in tuple(dict.fromkeys(evidence_ids)):
            item = self._load_evidence(
                account_id=account_id,
                verification_request_id=verification_request_id,
                evidence_id=evidence_id,
            )
            if item is None:
                excluded.append(evidence_id)
                reason_codes.add(EvidenceExclusionReason.MISSING_EVIDENCE.value)
                self._audit_exclusion(
                    account_id,
                    verification_request_id,
                    evidence_id,
                    EvidenceExclusionReason.MISSING_EVIDENCE,
                    correlation_id,
                )
                continue
            exclusion = self._exclusion_reason(item)
            if exclusion is not None:
                excluded.append(evidence_id)
                reason_codes.add(exclusion.value)
                self._audit_exclusion(
                    account_id,
                    verification_request_id,
                    evidence_id,
                    exclusion,
                    correlation_id,
                )
                continue
            stance = stance_by_id.get(evidence_id)
            eligible.append(
                _EligibleEvidence(
                    item=item,
                    stance=stance.stance if stance is not None else EvidenceStance.UNKNOWN,
                    coverage_basis_points=(
                        _bounded_score(stance.coverage_basis_points)
                        if stance is not None
                        else 0
                    ),
                    authority_score=self.config.authority_weight(SourceClass(item.source_class)),
                    extraction_score=self.config.extraction_weight(
                        ExtractionQuality(item.extraction_quality)
                    ),
                )
            )

        supporting = [item for item in eligible if item.stance is EvidenceStance.SUPPORTS]
        contradicting = [item for item in eligible if item.stance is EvidenceStance.CONTRADICTS]
        active = supporting + contradicting
        independent_ids, dependency_reasons = self._independent_representatives(
            account_id=account_id,
            evidence=active,
            correlation_id=correlation_id,
        )
        reason_codes.update(dependency_reasons)
        authority_component = _average([item.authority_score for item in active])
        extraction_component = _average([item.extraction_score for item in active])
        independent_count = len(
            [item for item in supporting if item.item.id in independent_ids]
        )
        independence_component = min(SCORE_MAX, independent_count * 3_500)
        dependent_support_count = max(0, len(supporting) - independent_count)
        corroboration_component = min(
            SCORE_MAX,
            (4_500 if independent_count else 0)
            + max(0, independent_count - 1) * 2_500
            + dependent_support_count * 500,
        )
        contradiction_strength = _average([item.strength for item in contradicting])
        contradiction_component = max(0, SCORE_MAX - contradiction_strength)
        freshness_component = self._freshness_component(active, computed_at, reason_codes)
        coverage_component = _average([item.coverage_basis_points for item in active])
        if coverage_component < 7_000 and active:
            reason_codes.add(EvidenceScoringReason.LIMITED_COVERAGE.value)

        final_score = self._final_score(
            source_authority_component=authority_component,
            extraction_quality_component=extraction_component,
            independence_component=independence_component,
            corroboration_component=corroboration_component,
            contradiction_component=contradiction_component,
            freshness_component=freshness_component,
            coverage_component=coverage_component,
        )
        if any(item.authority_score >= 8_500 for item in active):
            reason_codes.add(EvidenceScoringReason.AUTHORITATIVE_SOURCE_PRESENT.value)
        if independent_count > 1:
            reason_codes.add(EvidenceScoringReason.MULTIPLE_INDEPENDENT_SOURCES.value)
        if any(item.extraction_score < 4_000 for item in active):
            reason_codes.add(EvidenceScoringReason.LOW_EXTRACTION_QUALITY.value)
        if contradicting:
            reason_codes.add(EvidenceScoringReason.CONTRADICTORY_EVIDENCE_PRESENT.value)
        if not active:
            reason_codes.add(EvidenceScoringReason.INSUFFICIENT_EVIDENCE.value)

        status = self._status(
            final_score=final_score,
            support_count=len(supporting),
            contradiction_strength=contradiction_strength,
            operational_status_override=operational_status_override,
            reason_codes=reason_codes,
        )
        score = EvidenceScore(
            verification_request_id=verification_request_id,
            account_id=account_id,
            evidence_score_version=self.config.evidence_score_version,
            evidence_count=len(eligible),
            independent_evidence_count=independent_count,
            source_authority_component=authority_component,
            extraction_quality_component=extraction_component,
            independence_component=independence_component,
            corroboration_component=corroboration_component,
            contradiction_component=contradiction_component,
            freshness_component=freshness_component,
            coverage_component=coverage_component,
            final_score=final_score,
            verification_status=status,
            reason_codes=tuple(sorted(reason_codes)),
            evidence_ids_used=tuple(item.item.id for item in eligible),
            evidence_ids_excluded=tuple(excluded),
            computed_at=computed_at,
        )
        self._persist_result(score=score, request=request)
        self._audit_score(score=score, correlation_id=correlation_id)
        return score

    def _independent_representatives(
        self,
        *,
        account_id: UUID,
        evidence: list[_EligibleEvidence],
        correlation_id: UUID,
    ) -> tuple[set[UUID], set[str]]:
        representatives: list[_EligibleEvidence] = []
        reason_codes: set[str] = set()
        for item in evidence:
            if not representatives:
                representatives.append(item)
                continue
            relationships = [
                self.lineage_service.classify_independence(
                    account_id=account_id,
                    left_evidence_id=item.item.id,
                    right_evidence_id=representative.item.id,
                    correlation_id=correlation_id,
                ).relationship
                for representative in representatives
            ]
            if all(
                relationship is EvidenceIndependenceRelationship.INDEPENDENT
                for relationship in relationships
            ):
                representatives.append(item)
            elif any(
                relationship is EvidenceIndependenceRelationship.UNKNOWN
                for relationship in relationships
            ):
                reason_codes.add(EvidenceScoringReason.UNKNOWN_LINEAGE_DISCOUNTED.value)
            else:
                reason_codes.add(EvidenceScoringReason.DEPENDENT_EVIDENCE_DISCOUNTED.value)
        return {item.item.id for item in representatives}, reason_codes

    def _freshness_component(
        self,
        evidence: list[_EligibleEvidence],
        computed_at: datetime,
        reason_codes: set[str],
    ) -> int:
        if self.config.max_age_seconds is None or not evidence:
            return SCORE_MAX
        max_age = timedelta(seconds=self.config.max_age_seconds)
        fresh_count = sum(
            1
            for item in evidence
            if computed_at - _db_timestamp_utc(item.item.observed_at) <= max_age
        )
        component = (fresh_count * SCORE_MAX) // len(evidence)
        if component < SCORE_MAX:
            reason_codes.add(EvidenceScoringReason.STALE_EVIDENCE.value)
        return component

    def _status(
        self,
        *,
        final_score: int,
        support_count: int,
        contradiction_strength: int,
        operational_status_override: VerificationStatus | None,
        reason_codes: set[str],
    ) -> VerificationStatus:
        if operational_status_override is VerificationStatus.PROVIDER_FAILED:
            reason_codes.add(EvidenceScoringReason.PROVIDER_FAILURE_OVERRIDE.value)
            return VerificationStatus.PROVIDER_FAILED
        if operational_status_override is VerificationStatus.SYSTEM_FAILURE:
            reason_codes.add(EvidenceScoringReason.SYSTEM_FAILURE_OVERRIDE.value)
            return VerificationStatus.SYSTEM_FAILURE
        if contradiction_strength >= self.config.contradicted_threshold:
            reason_codes.add(EvidenceScoringReason.VERIFICATION_STATUS_CONTRADICTED.value)
            return VerificationStatus.CONTRADICTED
        if (
            support_count > 0
            and final_score >= self.config.verified_threshold
            and contradiction_strength < self.config.contradiction_block_threshold
        ):
            reason_codes.add(EvidenceScoringReason.VERIFICATION_STATUS_VERIFIED.value)
            return VerificationStatus.VERIFIED
        reason_codes.add(EvidenceScoringReason.VERIFICATION_STATUS_INCONCLUSIVE.value)
        return VerificationStatus.INCONCLUSIVE

    def _final_score(
        self,
        *,
        source_authority_component: int,
        extraction_quality_component: int,
        independence_component: int,
        corroboration_component: int,
        contradiction_component: int,
        freshness_component: int,
        coverage_component: int,
    ) -> int:
        weighted = (
            source_authority_component * self.config.component_weight("source_authority")
            + extraction_quality_component * self.config.component_weight("extraction_quality")
            + independence_component * self.config.component_weight("independence")
            + corroboration_component * self.config.component_weight("corroboration")
            + contradiction_component * self.config.component_weight("contradiction")
            + freshness_component * self.config.component_weight("freshness")
            + coverage_component * self.config.component_weight("coverage")
        )
        return _bounded_score(weighted // SCORE_MAX)

    def _require_request(
        self,
        account_id: UUID,
        verification_request_id: UUID,
    ) -> VerificationRequest:
        request = self.session.scalar(
            select(VerificationRequest).where(
                VerificationRequest.account_id == account_id,
                VerificationRequest.id == verification_request_id,
            )
        )
        if request is None:
            raise EvidenceScoringError("verification request not found")
        return request

    def _load_evidence(
        self,
        *,
        account_id: UUID,
        verification_request_id: UUID,
        evidence_id: UUID,
    ) -> EvidenceItem | None:
        item = self.session.scalar(select(EvidenceItem).where(EvidenceItem.id == evidence_id))
        if item is None:
            return None
        if item.account_id != account_id:
            raise CrossTenantEvidenceScoringAccess("evidence belongs to a different account")
        if item.verification_request_id != verification_request_id:
            raise EvidenceScoringError("evidence belongs to a different verification request")
        return item

    def _exclusion_reason(self, item: EvidenceItem) -> EvidenceExclusionReason | None:
        if ExtractionQuality(item.extraction_quality) is ExtractionQuality.FAILED:
            return EvidenceExclusionReason.EXTRACTION_FAILED
        if item.authority_metadata.get("scoring_usable") is False:
            return EvidenceExclusionReason.EXPLICITLY_UNUSABLE
        if "SCORING_UNUSABLE" in item.safety_flags:
            return EvidenceExclusionReason.EXPLICITLY_UNUSABLE
        return None

    def _persist_result(self, *, score: EvidenceScore, request: VerificationRequest) -> None:
        self.session.add(
            VerificationResult(
                id=uuid4(),
                account_id=score.account_id,
                request_id=request.request_id,
                verification_request_id=score.verification_request_id,
                status=score.verification_status.value,
                evidence_score_basis_points=score.final_score,
                evidence_score_version=score.evidence_score_version,
                score_factors={
                    "source_authority_component": score.source_authority_component,
                    "extraction_quality_component": score.extraction_quality_component,
                    "independence_component": score.independence_component,
                    "corroboration_component": score.corroboration_component,
                    "contradiction_component": score.contradiction_component,
                    "freshness_component": score.freshness_component,
                    "coverage_component": score.coverage_component,
                    "computed_at": score.computed_at.isoformat(),
                },
                evidence_ids_used=[str(evidence_id) for evidence_id in score.evidence_ids_used],
                evidence_ids_excluded=[
                    str(evidence_id) for evidence_id in score.evidence_ids_excluded
                ],
                assurance=AssuranceLevel.STANDARD.value,
                reason_codes=list(score.reason_codes),
            )
        )
        self.session.flush()

    def _audit_score(self, *, score: EvidenceScore, correlation_id: UUID) -> None:
        payload: dict[str, object] = {
            "verification_status": score.verification_status.value,
            "evidence_score_version": score.evidence_score_version,
            "evidence_count": score.evidence_count,
            "independent_evidence_count": score.independent_evidence_count,
            "source_authority_component": score.source_authority_component,
            "extraction_quality_component": score.extraction_quality_component,
            "independence_component": score.independence_component,
            "corroboration_component": score.corroboration_component,
            "contradiction_component": score.contradiction_component,
            "freshness_component": score.freshness_component,
            "coverage_component": score.coverage_component,
            "final_score": score.final_score,
            "evidence_ids_used": list(score.evidence_ids_used),
            "evidence_ids_excluded": list(score.evidence_ids_excluded),
            "reason_codes": list(score.reason_codes),
        }
        self.audit_service.append_event(
            account_id=score.account_id,
            event_type=AuditEventType.SCORE_COMPUTED,
            correlation_id=correlation_id,
            request_id=score.verification_request_id,
            payload=payload,
        )
        self.audit_service.append_event(
            account_id=score.account_id,
            event_type=AuditEventType.VERIFICATION_STATUS_DERIVED,
            correlation_id=correlation_id,
            request_id=score.verification_request_id,
            payload=payload,
        )

    def _audit_exclusion(
        self,
        account_id: UUID,
        verification_request_id: UUID,
        evidence_id: UUID,
        reason: EvidenceExclusionReason,
        correlation_id: UUID,
    ) -> None:
        self.audit_service.append_event(
            account_id=account_id,
            event_type=AuditEventType.EVIDENCE_EXCLUDED_FROM_SCORING,
            correlation_id=correlation_id,
            request_id=verification_request_id,
            payload={
                "evidence_id": evidence_id,
                "reason_codes": [reason.value],
            },
        )


def _average(values: list[int]) -> int:
    if not values:
        return 0
    return sum(values) // len(values)


def _bounded_score(value: int) -> int:
    return min(SCORE_MAX, max(0, value))


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise EvidenceScoringError("scoring timestamps must be timezone-aware")
    return value.astimezone(UTC)


def _db_timestamp_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


__all__ = [
    "EVIDENCE_SCORE_VERSION",
    "EvidenceExclusionReason",
    "EvidenceScore",
    "EvidenceScoringConfig",
    "EvidenceScoringError",
    "EvidenceScoringReason",
    "EvidenceScoringService",
    "EvidenceStance",
    "EvidenceStanceInput",
    "CrossTenantEvidenceScoringAccess",
]
