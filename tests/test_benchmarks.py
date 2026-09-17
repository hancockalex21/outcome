from __future__ import annotations

import copy
import inspect
from pathlib import Path

import pytest
from pydantic import ValidationError

from outcome.benchmarks import BenchmarkDataset, BenchmarkLabel, compare_with_golden
from outcome.benchmarks.metrics import BenchmarkReport, RegressionChangeType, compute_report
from outcome.benchmarks.runner import run_benchmark_dataset
from outcome.benchmarks.schema import (
    BENCHMARK_DATASET_VERSION,
    BenchmarkCaseKind,
    BenchmarkResult,
    MatchClassification,
    load_dataset,
)
from outcome.domain import PolicyDecision, VerificationStatus

DATASET_PATH = Path("benchmarks/datasets/v1.json")
GOLDEN_PATH = Path("benchmarks/golden/v1/results.json")


def dataset() -> BenchmarkDataset:
    return load_dataset(DATASET_PATH)


def test_benchmark_schema_validation_and_required_provenance() -> None:
    raw = copy.deepcopy(dataset().model_dump(mode="json"))
    raw["cases"][0].pop("label_provenance")

    with pytest.raises(ValidationError):
        BenchmarkDataset.model_validate(raw)


def test_duplicate_case_ids_rejected() -> None:
    raw = copy.deepcopy(dataset().model_dump(mode="json"))
    raw["cases"][1]["benchmark_case_id"] = raw["cases"][0]["benchmark_case_id"]

    with pytest.raises(ValidationError):
        BenchmarkDataset.model_validate(raw)


def test_invalid_labels_rejected() -> None:
    raw = copy.deepcopy(dataset().model_dump(mode="json"))
    raw["cases"][0]["truth_label"] = "VERIFIED"

    with pytest.raises(ValidationError):
        BenchmarkDataset.model_validate(raw)


def test_temporal_fields_are_timezone_aware() -> None:
    raw = copy.deepcopy(dataset().model_dump(mode="json"))
    raw["cases"][0]["temporal_as_of"] = "2026-09-18T12:00:00"

    with pytest.raises(ValidationError):
        BenchmarkDataset.model_validate(raw)


def test_dataset_version_required_and_stable() -> None:
    loaded = dataset()

    assert loaded.dataset_version == BENCHMARK_DATASET_VERSION
    assert all(case.dataset_version == BENCHMARK_DATASET_VERSION for case in loaded.cases)


def test_runner_uses_production_verification_machinery() -> None:
    import outcome.benchmarks.runner as runner

    source = inspect.getsource(runner)

    assert "VerificationOrchestrator" in source
    assert "EvidenceScoringService" not in source


def test_benchmark_runner_core_cases_and_operational_failures() -> None:
    report = run_benchmark_dataset(DATASET_PATH)
    by_id = {result["case_id"]: result for result in report.results}

    assert by_id["verify-supported-registry"]["verification_status"] == "VERIFIED"
    assert by_id["verify-contradicted-primary"]["verification_status"] == "CONTRADICTED"
    assert by_id["verify-insufficient-unknown"]["verification_status"] == "INCONCLUSIVE"
    assert by_id["verify-provider-timeout"]["verification_status"] == "PROVIDER_FAILED"
    assert by_id["verify-system-failure"]["verification_status"] == "SYSTEM_FAILURE"
    assert by_id["verify-hostile-prompt-evidence"]["verification_status"] == "INCONCLUSIVE"
    assert "TIMEOUT" in by_id["verify-provider-timeout"]["provider_outcomes"]


def test_benchmark_lineage_and_duplicate_evidence_behavior() -> None:
    report = run_benchmark_dataset(DATASET_PATH)
    duplicate = next(
        result for result in report.results if result["case_id"] == "verify-syndicated-duplicates"
    )

    assert "SYNDICATED" in duplicate["lineage_types"]
    assert duplicate["independent_evidence_count"] <= 1


def test_ordering_cases_have_identical_semantic_outputs() -> None:
    report = run_benchmark_dataset(DATASET_PATH)
    by_id = {result["case_id"]: result for result in report.results}
    a = by_id["verify-ordering-a"]
    b = by_id["verify-ordering-b"]

    assert a["verification_status"] == b["verification_status"]
    assert a["evidence_score"] == b["evidence_score"]
    assert a["score_components"] == b["score_components"]
    assert a["reason_codes"] == b["reason_codes"]


def test_metrics_confusion_precision_recall_and_safe_division() -> None:
    report = compute_report(
        (
            _result(
                "a",
                BenchmarkLabel.SUPPORTED,
                VerificationStatus.VERIFIED,
                10_000,
                MatchClassification.MATCH,
            ),
            _result(
                "b",
                BenchmarkLabel.CONTRADICTED,
                VerificationStatus.INCONCLUSIVE,
                0,
                MatchClassification.MISMATCH,
            ),
        )
    )

    assert report.confusion_matrix["SUPPORTED"]["VERIFIED"] == 1
    assert report.confusion_matrix["CONTRADICTED"]["INCONCLUSIVE"] == 1
    assert report.precision_recall["INSUFFICIENT_EVIDENCE"]["recall_basis_points"] == 0


def test_score_bucket_boundaries_include_zero_and_ten_thousand() -> None:
    report = compute_report(
        (
            _result(
                "zero",
                BenchmarkLabel.INSUFFICIENT_EVIDENCE,
                VerificationStatus.INCONCLUSIVE,
                0,
                MatchClassification.MATCH,
            ),
            _result(
                "max",
                BenchmarkLabel.SUPPORTED,
                VerificationStatus.VERIFIED,
                10_000,
                MatchClassification.MATCH,
            ),
        )
    )

    assert report.score_buckets["0-999"]["case_count"] == 1
    assert report.score_buckets["9000-10000"]["case_count"] == 1


def test_component_source_extraction_and_lineage_segmentation() -> None:
    report = run_benchmark_dataset(DATASET_PATH)

    assert "source_authority" in report.component_analysis
    assert "AUTHORITATIVE_REGISTRY" in report.source_class_analysis
    assert "EXACT_STRUCTURED" in report.extraction_quality_analysis
    assert "SYNDICATED" in report.lineage_analysis


def test_authorization_policy_outcomes_and_no_billing_effects() -> None:
    import outcome.benchmarks.runner as runner

    report = run_benchmark_dataset(DATASET_PATH)
    decisions = {
        result["case_id"]: result["policy_decision"]
        for result in report.results
        if result["case_kind"] == "AUTHORIZATION"
    }

    assert decisions["auth-allow-verified"] == PolicyDecision.ALLOW.value
    assert decisions["auth-insufficient-assurance"] == (
        PolicyDecision.RETRY_HIGHER_ASSURANCE.value
    )
    assert decisions["auth-provider-failure-escalate"] == PolicyDecision.ESCALATE.value
    assert decisions["auth-system-failure-block"] == PolicyDecision.BLOCK.value
    assert "AuthorizationBillingService" not in inspect.getsource(runner)
    assert "LedgerService" not in inspect.getsource(runner)


def test_golden_comparator_and_expected_regression_detection() -> None:
    golden = _result(
        "case",
        BenchmarkLabel.INSUFFICIENT_EVIDENCE,
        VerificationStatus.INCONCLUSIVE,
        1_000,
        MatchClassification.MATCH,
    )
    current = _result(
        "case",
        BenchmarkLabel.INSUFFICIENT_EVIDENCE,
        VerificationStatus.VERIFIED,
        8_000,
        MatchClassification.MISMATCH,
    )

    comparison = compare_with_golden(current=(current,), golden=(golden,))

    assert comparison["case"]["change_type"] == RegressionChangeType.REGRESSION.value


def test_golden_artifact_matches_current_deterministic_run() -> None:
    current = run_benchmark_dataset(DATASET_PATH)
    golden_report = BenchmarkReport.model_validate_json(GOLDEN_PATH.read_text(encoding="utf-8"))

    assert current.dataset_version == BENCHMARK_DATASET_VERSION
    assert current.model_dump(mode="json") == golden_report.model_dump(mode="json")


def test_golden_snapshot_has_no_nondeterministic_fields() -> None:
    golden_text = GOLDEN_PATH.read_text(encoding="utf-8")

    assert "/Users/" not in golden_text
    assert "latency_ms" not in golden_text
    assert "computed_at" not in golden_text


def test_malformed_benchmark_artifact_rejected() -> None:
    with pytest.raises(ValidationError):
        BenchmarkDataset.model_validate({"dataset_version": BENCHMARK_DATASET_VERSION})


def _result(
    case_id: str,
    label: BenchmarkLabel,
    status: VerificationStatus,
    score: int,
    match: MatchClassification,
) -> BenchmarkResult:
    return BenchmarkResult(
        case_id=case_id,
        case_kind=BenchmarkCaseKind.VERIFICATION,
        dataset_version=BENCHMARK_DATASET_VERSION,
        code_version="test",
        scoring_version="test-score",
        verification_status=status,
        evidence_score=score,
        score_components={
            "source_authority": score,
            "extraction_quality": score,
            "independence": score,
            "corroboration": score,
            "contradiction": score,
            "freshness": score,
            "coverage": score,
        },
        source_classes=("UNKNOWN",),
        extraction_qualities=("DIRECT_TEXT",),
        lineage_types=("UNKNOWN",),
        expected_label=label,
        match_classification=match,
    )
