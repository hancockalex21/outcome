from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from outcome.benchmarks.schema import (
    BENCHMARK_REPORT_VERSION,
    BenchmarkLabel,
    BenchmarkResult,
    MatchClassification,
    result_to_stable_json,
)
from outcome.domain import VerificationStatus


class RegressionChangeType(StrEnum):
    UNCHANGED = "UNCHANGED"
    CHANGED = "CHANGED"
    REGRESSION = "REGRESSION"
    IMPROVEMENT = "IMPROVEMENT"


@dataclass(frozen=True)
class ScoreBucket:
    lower: int
    upper: int

    @property
    def label(self) -> str:
        return f"{self.lower}-{self.upper}"


class BenchmarkReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    report_version: str = BENCHMARK_REPORT_VERSION
    dataset_version: str
    code_version: str
    total_cases: int
    evaluated_factual_cases: int
    exact_label_status_agreement: dict[str, Any]
    precision_recall: dict[str, dict[str, int | str]]
    confusion_matrix: dict[str, dict[str, int]]
    operational_failures: dict[str, int]
    score_buckets: dict[str, dict[str, Any]]
    score_distribution_by_label: dict[str, dict[str, int]]
    score_distribution_by_outcome: dict[str, dict[str, int]]
    component_analysis: dict[str, dict[str, Any]]
    source_class_analysis: dict[str, dict[str, Any]]
    extraction_quality_analysis: dict[str, dict[str, Any]]
    lineage_analysis: dict[str, dict[str, Any]]
    false_high_score_cases: tuple[str, ...]
    false_low_score_cases: tuple[str, ...]
    results: tuple[dict[str, Any], ...] = Field(default_factory=tuple)


def compute_report(results: tuple[BenchmarkResult, ...]) -> BenchmarkReport:
    dataset_version = results[0].dataset_version if results else "unknown"
    code_version = results[0].code_version if results else "unknown"
    factual = [result for result in results if result.expected_label is not None]
    factual_non_operational = [
        result
        for result in factual
        if result.verification_status
        not in {VerificationStatus.PROVIDER_FAILED, VerificationStatus.SYSTEM_FAILURE}
    ]
    matches = [
        result
        for result in factual_non_operational
        if result.match_classification is MatchClassification.MATCH
    ]
    confusion = _confusion_matrix(factual_non_operational)
    return BenchmarkReport(
        dataset_version=dataset_version,
        code_version=code_version,
        total_cases=len(results),
        evaluated_factual_cases=len(factual_non_operational),
        exact_label_status_agreement={
            "matched": len(matches),
            "total": len(factual_non_operational),
            "rate_basis_points": _safe_rate(len(matches), len(factual_non_operational)),
        },
        precision_recall=_precision_recall(confusion),
        confusion_matrix=confusion,
        operational_failures=dict(
            sorted(
                Counter(
                    result.verification_status.value
                    for result in factual
                    if result.verification_status
                    in {VerificationStatus.PROVIDER_FAILED, VerificationStatus.SYSTEM_FAILURE}
                ).items()
            )
        ),
        score_buckets=_score_buckets(factual),
        score_distribution_by_label=_score_distribution_by(
            factual,
            key=lambda result: result.expected_label.value if result.expected_label else "NONE",
        ),
        score_distribution_by_outcome=_score_distribution_by(
            factual,
            key=lambda result: result.verification_status.value
            if result.verification_status
            else "NONE",
        ),
        component_analysis=_component_analysis(factual),
        source_class_analysis=_categorical_analysis(
            factual,
            lambda result: result.source_classes,
        ),
        extraction_quality_analysis=_categorical_analysis(
            factual,
            lambda result: result.extraction_qualities,
        ),
        lineage_analysis=_categorical_analysis(
            factual,
            lambda result: result.lineage_types,
        ),
        false_high_score_cases=tuple(
            result.case_id
            for result in factual
            if (result.evidence_score or 0) >= 7_000
            and result.expected_label is not BenchmarkLabel.SUPPORTED
        ),
        false_low_score_cases=tuple(
            result.case_id
            for result in factual
            if (result.evidence_score or 0) < 4_000
            and result.expected_label is BenchmarkLabel.SUPPORTED
        ),
        results=tuple(result_to_stable_json(result) for result in results),
    )


def compare_with_golden(
    *,
    current: tuple[BenchmarkResult, ...],
    golden: tuple[BenchmarkResult, ...],
) -> dict[str, dict[str, str]]:
    current_by_id = {result.case_id: result for result in current}
    golden_by_id = {result.case_id: result for result in golden}
    comparison: dict[str, dict[str, str]] = {}
    for case_id in sorted(set(current_by_id) | set(golden_by_id)):
        current_result = current_by_id.get(case_id)
        golden_result = golden_by_id.get(case_id)
        if current_result is None or golden_result is None:
            comparison[case_id] = {
                "change_type": RegressionChangeType.CHANGED.value,
                "reason": "CASE_ADDED_OR_REMOVED",
            }
            continue
        if result_to_stable_json(current_result) == result_to_stable_json(golden_result):
            comparison[case_id] = {
                "change_type": RegressionChangeType.UNCHANGED.value,
                "reason": "SEMANTIC_OUTPUT_UNCHANGED",
            }
            continue
        comparison[case_id] = _classify_change(current_result, golden_result)
    return comparison


def _classify_change(
    current: BenchmarkResult,
    golden: BenchmarkResult,
) -> dict[str, str]:
    if (
        golden.match_classification is MatchClassification.MATCH
        and current.match_classification is not MatchClassification.MATCH
    ):
        return {
            "change_type": RegressionChangeType.REGRESSION.value,
            "reason": "MATCH_BECAME_MISMATCH",
        }
    if (
        golden.match_classification is not MatchClassification.MATCH
        and current.match_classification is MatchClassification.MATCH
    ):
        return {
            "change_type": RegressionChangeType.IMPROVEMENT.value,
            "reason": "MISMATCH_BECAME_MATCH",
        }
    if (
        current.expected_label is not BenchmarkLabel.SUPPORTED
        and (golden.evidence_score or 0) < 7_000
        and (current.evidence_score or 0) >= 7_000
    ):
        return {
            "change_type": RegressionChangeType.REGRESSION.value,
            "reason": "HIGH_SCORE_ON_NON_SUPPORTED_CASE",
        }
    return {
        "change_type": RegressionChangeType.CHANGED.value,
        "reason": "SEMANTIC_OUTPUT_CHANGED",
    }


def _expected_status(label: BenchmarkLabel) -> VerificationStatus:
    return {
        BenchmarkLabel.SUPPORTED: VerificationStatus.VERIFIED,
        BenchmarkLabel.CONTRADICTED: VerificationStatus.CONTRADICTED,
        BenchmarkLabel.INSUFFICIENT_EVIDENCE: VerificationStatus.INCONCLUSIVE,
    }[label]


def _confusion_matrix(results: list[BenchmarkResult]) -> dict[str, dict[str, int]]:
    matrix: dict[str, dict[str, int]] = {}
    labels = [label.value for label in BenchmarkLabel]
    statuses = [
        VerificationStatus.VERIFIED.value,
        VerificationStatus.CONTRADICTED.value,
        VerificationStatus.INCONCLUSIVE.value,
    ]
    for label in labels:
        matrix[label] = {status: 0 for status in statuses}
    for result in results:
        if result.expected_label is None or result.verification_status is None:
            continue
        matrix[result.expected_label.value][result.verification_status.value] += 1
    return matrix


def _precision_recall(
    matrix: dict[str, dict[str, int]],
) -> dict[str, dict[str, int | str]]:
    metrics: dict[str, dict[str, int | str]] = {}
    mappings = {
        BenchmarkLabel.SUPPORTED.value: VerificationStatus.VERIFIED.value,
        BenchmarkLabel.CONTRADICTED.value: VerificationStatus.CONTRADICTED.value,
        BenchmarkLabel.INSUFFICIENT_EVIDENCE.value: VerificationStatus.INCONCLUSIVE.value,
    }
    for label, status in mappings.items():
        true_positive = matrix[label][status]
        predicted_total = sum(row[status] for row in matrix.values())
        actual_total = sum(matrix[label].values())
        metrics[label] = {
            "predicted_status": status,
            "precision_basis_points": _safe_rate(true_positive, predicted_total),
            "recall_basis_points": _safe_rate(true_positive, actual_total),
            "true_positive": true_positive,
            "predicted_total": predicted_total,
            "actual_total": actual_total,
        }
    return metrics


def _score_buckets(results: list[BenchmarkResult]) -> dict[str, dict[str, Any]]:
    buckets = [ScoreBucket(start, min(start + 999, 10_000)) for start in range(0, 10_000, 1000)]
    buckets[-1] = ScoreBucket(9000, 10_000)
    output: dict[str, dict[str, Any]] = {}
    for bucket in buckets:
        contained = [
            result
            for result in results
            if result.evidence_score is not None
            and bucket.lower <= result.evidence_score <= bucket.upper
        ]
        output[bucket.label] = {
            "case_count": len(contained),
            "label_distribution": dict(
                sorted(
                    Counter(
                        result.expected_label.value
                        for result in contained
                        if result.expected_label is not None
                    ).items()
                )
            ),
            "verification_distribution": dict(
                sorted(
                    Counter(
                        result.verification_status.value
                        for result in contained
                        if result.verification_status is not None
                    ).items()
                )
            ),
            "disagreement_count": sum(
                1
                for result in contained
                if result.match_classification is not MatchClassification.MATCH
            ),
            "disagreement_rate_basis_points": _safe_rate(
                sum(
                    1
                    for result in contained
                    if result.match_classification is not MatchClassification.MATCH
                ),
                len(contained),
            ),
        }
    return output


def _score_distribution_by(
    results: list[BenchmarkResult],
    key: Any,
) -> dict[str, dict[str, int]]:
    grouped: dict[str, Counter[str]] = defaultdict(Counter)
    for result in results:
        bucket = _bucket_for_score(result.evidence_score)
        grouped[str(key(result))][bucket] += 1
    return {group: dict(sorted(counter.items())) for group, counter in sorted(grouped.items())}


def _component_analysis(results: list[BenchmarkResult]) -> dict[str, dict[str, Any]]:
    components: dict[str, list[int]] = defaultdict(list)
    for result in results:
        for name, value in result.score_components.items():
            components[name].append(value)
    return {
        name: {
            "count": len(values),
            "min": min(values),
            "max": max(values),
            "average": sum(values) // len(values),
        }
        for name, values in sorted(components.items())
        if values
    }


def _categorical_analysis(
    results: list[BenchmarkResult],
    values_for: Any,
) -> dict[str, dict[str, Any]]:
    grouped: dict[str, list[BenchmarkResult]] = defaultdict(list)
    for result in results:
        values = values_for(result) or ("NONE",)
        for value in values:
            grouped[str(value)].append(result)
    return {
        key: {
            "case_count": len(values),
            "matched": sum(
                1
                for result in values
                if result.match_classification is MatchClassification.MATCH
            ),
            "match_rate_basis_points": _safe_rate(
                sum(
                    1
                    for result in values
                    if result.match_classification is MatchClassification.MATCH
                ),
                len(values),
            ),
        }
        for key, values in sorted(grouped.items())
    }


def _bucket_for_score(score: int | None) -> str:
    if score is None:
        return "NONE"
    lower = (score // 1000) * 1000
    if lower >= 9000:
        return "9000-10000"
    return f"{lower}-{lower + 999}"


def _safe_rate(numerator: int, denominator: int) -> int:
    if denominator <= 0:
        return 0
    return (numerator * 10_000) // denominator


__all__ = [
    "BenchmarkReport",
    "RegressionChangeType",
    "compare_with_golden",
    "compute_report",
]
