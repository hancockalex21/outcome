from __future__ import annotations

import argparse
import json
from pathlib import Path

from outcome.benchmarks.metrics import compare_with_golden
from outcome.benchmarks.runner import run_benchmark_dataset
from outcome.benchmarks.schema import BenchmarkResult

DEFAULT_DATASET = Path("benchmarks/datasets/v1.json")
DEFAULT_GOLDEN = Path("benchmarks/golden/v1/results.json")
DEFAULT_REPORT = Path("benchmarks/latest-report.json")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Outcome offline benchmark evaluation.")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--golden", type=Path, default=DEFAULT_GOLDEN)
    parser.add_argument("--output", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--update-golden", action="store_true")
    args = parser.parse_args()

    report = run_benchmark_dataset(args.dataset)
    report_json = report.model_dump(mode="json")
    args.output.write_text(
        json.dumps(report_json, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if args.update_golden:
        args.golden.write_text(
            json.dumps(report_json, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"updated golden benchmark: {args.golden}")
        return
    if args.golden.exists():
        golden_json = json.loads(args.golden.read_text(encoding="utf-8"))
        golden_results = tuple(
            BenchmarkResult.model_validate(result)
            for result in golden_json.get("results", [])
        )
        current_results = tuple(
            BenchmarkResult.model_validate(result)
            for result in report_json.get("results", [])
        )
        comparison = compare_with_golden(current=current_results, golden=golden_results)
        regressions = [
            case_id
            for case_id, change in comparison.items()
            if change["change_type"] == "REGRESSION"
        ]
        if regressions:
            raise SystemExit(f"benchmark regressions detected: {', '.join(regressions)}")
    print(
        f"benchmark complete: {report.total_cases} cases, "
        f"{report.exact_label_status_agreement['matched']}/"
        f"{report.exact_label_status_agreement['total']} factual matches"
    )


if __name__ == "__main__":
    main()
