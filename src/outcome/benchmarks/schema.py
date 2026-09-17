from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from outcome.domain import AssuranceLevel, PolicyDecision, VerificationMode, VerificationStatus
from outcome.evidence import EvidenceLineageType, EvidenceStance, ExtractionQuality, SourceClass
from outcome.pricing import CapabilityName
from outcome.providers import ProviderAttemptOutcome

BENCHMARK_SCHEMA_VERSION = "benchmark-case-v1"
AUTHORIZATION_BENCHMARK_SCHEMA_VERSION = "authorization-benchmark-v1"
BENCHMARK_DATASET_VERSION = "benchmark-dataset-v1"
BENCHMARK_REPORT_VERSION = "benchmark-report-v1"

BoundedString = Annotated[str, Field(min_length=1, max_length=1024)]
LongString = Annotated[str, Field(min_length=1, max_length=4096)]
ScoreInt = Annotated[int, Field(ge=0, le=10_000)]


class BenchmarkLabel(StrEnum):
    SUPPORTED = "SUPPORTED"
    CONTRADICTED = "CONTRADICTED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class LabelSourceType(StrEnum):
    HUMAN_CURATED = "HUMAN_CURATED"
    AUTHORITATIVE_FIXTURE = "AUTHORITATIVE_FIXTURE"
    SYNTHETIC_ADVERSARIAL = "SYNTHETIC_ADVERSARIAL"


class MatchClassification(StrEnum):
    MATCH = "MATCH"
    MISMATCH = "MISMATCH"
    OPERATIONAL_FAILURE = "OPERATIONAL_FAILURE"


class BenchmarkCaseKind(StrEnum):
    VERIFICATION = "VERIFICATION"
    AUTHORIZATION = "AUTHORIZATION"


class LabelProvenance(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    source_type: LabelSourceType
    reference_id: BoundedString
    as_of: datetime
    labeling_method: BoundedString
    dataset_version: Literal["benchmark-dataset-v1"] = "benchmark-dataset-v1"

    @field_validator("as_of")
    @classmethod
    def require_aware_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("label provenance as_of must be timezone-aware")
        return value.astimezone(UTC)


class FixtureEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    source_uri: BoundedString | None = None
    source_class: SourceClass
    content_type: Literal["text/plain", "application/json", "text/html"]
    body: LongString
    observed_at: datetime
    stance: EvidenceStance
    lineage_type: EvidenceLineageType = EvidenceLineageType.ORIGINAL
    origin_reference: BoundedString | None = None
    publisher_identity: BoundedString | None = None
    canonical_source_identity: BoundedString | None = None
    coverage_basis_points: ScoreInt = 10_000
    authority_metadata: dict[str, Any] = Field(default_factory=dict)
    lineage_metadata: dict[str, Any] = Field(default_factory=dict)
    expected_extraction_quality: ExtractionQuality | None = None
    expected_source_class: SourceClass | None = None
    expected_independence: BoundedString | None = None

    @field_validator("observed_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("evidence observed_at must be timezone-aware")
        return value.astimezone(UTC)


class FixtureProvider(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    provider_id: UUID
    provider_alias: BoundedString
    outcome: ProviderAttemptOutcome = ProviderAttemptOutcome.SUCCESS
    evidence: tuple[FixtureEvidence, ...] = ()
    latency_ms: Annotated[int | None, Field(ge=0, le=60_000)] = 10
    enabled_rights: bool = True
    healthy: bool = True


class BenchmarkCase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    benchmark_case_id: BoundedString
    case_kind: BenchmarkCaseKind = BenchmarkCaseKind.VERIFICATION
    schema_version: Literal["benchmark-case-v1"] = "benchmark-case-v1"
    dataset_version: Literal["benchmark-dataset-v1"] = "benchmark-dataset-v1"
    category: BoundedString
    claim: dict[str, Any]
    subject: dict[str, Any] = Field(default_factory=dict)
    truth_label: BenchmarkLabel
    label_provenance: LabelProvenance
    providers: tuple[FixtureProvider, ...]
    temporal_as_of: datetime
    difficulty: BoundedString = "standard"
    tags: tuple[BoundedString, ...] = ()
    notes: BoundedString | None = None
    expected_operational_status: VerificationStatus | None = None
    expected_verification_status: VerificationStatus | None = None
    mode: VerificationMode = VerificationMode.INLINE
    assurance: AssuranceLevel = AssuranceLevel.STANDARD
    capability: CapabilityName = CapabilityName.VERIFY

    @field_validator("temporal_as_of")
    @classmethod
    def require_aware_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("temporal_as_of must be timezone-aware")
        return value.astimezone(UTC)


class AuthorizationBenchmarkCase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    benchmark_case_id: BoundedString
    schema_version: Literal["authorization-benchmark-v1"] = (
        "authorization-benchmark-v1"
    )
    dataset_version: Literal["benchmark-dataset-v1"] = "benchmark-dataset-v1"
    category: BoundedString
    material_action: dict[str, Any]
    verification_status: VerificationStatus | None = None
    evidence_score_basis_points: ScoreInt | None = None
    assurance: AssuranceLevel = AssuranceLevel.STANDARD
    expected_decision: PolicyDecision
    tags: tuple[BoundedString, ...] = ()
    notes: BoundedString | None = None


class BenchmarkDataset(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    dataset_version: Literal["benchmark-dataset-v1"] = "benchmark-dataset-v1"
    schema_version: Literal["benchmark-case-v1"] = "benchmark-case-v1"
    name: BoundedString
    description: BoundedString
    cases: tuple[BenchmarkCase, ...]
    authorization_cases: tuple[AuthorizationBenchmarkCase, ...] = ()

    @model_validator(mode="after")
    def reject_duplicate_case_ids(self) -> BenchmarkDataset:
        ids = [case.benchmark_case_id for case in self.cases]
        ids.extend(case.benchmark_case_id for case in self.authorization_cases)
        if len(ids) != len(set(ids)):
            raise ValueError("benchmark case IDs must be unique")
        return self


class BenchmarkResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str
    case_kind: BenchmarkCaseKind
    dataset_version: str
    code_version: str
    scoring_version: str | None = None
    verification_status: VerificationStatus | None = None
    policy_decision: PolicyDecision | None = None
    evidence_score: int | None = None
    score_components: dict[str, int] = Field(default_factory=dict)
    reason_codes: tuple[str, ...] = ()
    evidence_count: int = 0
    independent_evidence_count: int = 0
    source_classes: tuple[str, ...] = ()
    extraction_qualities: tuple[str, ...] = ()
    lineage_types: tuple[str, ...] = ()
    provider_outcomes: tuple[str, ...] = ()
    operational_failure_category: VerificationStatus | None = None
    expected_label: BenchmarkLabel | None = None
    expected_policy_decision: PolicyDecision | None = None
    match_classification: MatchClassification


def load_dataset(path: Path) -> BenchmarkDataset:
    return BenchmarkDataset.model_validate_json(path.read_text(encoding="utf-8"))


def result_to_stable_json(result: BenchmarkResult) -> dict[str, Any]:
    return result.model_dump(mode="json", exclude_none=True)
