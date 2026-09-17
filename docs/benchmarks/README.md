# Outcome Benchmark And Evaluation

This benchmark package is an offline regression and measurement framework. It is not
production request handling, and it is not evidence that Outcome is broadly accurate.

The checked-in `benchmark-dataset-v1` is synthetic and deterministic. It exists to
catch semantic regressions in verification, scoring, lineage, provider failure handling,
and deterministic policy behavior. Future real-world labeled datasets can use the same
schema, but no external datasets are downloaded or scraped here.

## What It Measures

- Verification status agreement against independent fixture labels.
- Evidence Score behavior by truth label and verification result.
- Component behavior for source authority, extraction quality, independence,
  corroboration, contradiction, freshness, and coverage.
- Segmentation by `SourceClass`, `ExtractionQuality`, and lineage type.
- Operational failure rates for provider and system failures.
- Deterministic policy/authorization decisions for bounded policy cases.
- Golden regression drift against `benchmarks/golden/v1/results.json`.

## What It Does Not Measure

- Production accuracy.
- Statistical significance.
- Probability calibration.
- Generalized reliability.
- Real provider quality.
- Real customer or production evidence.
- Live billing or payment effects.

Evidence Score remains an integer `0..10000` evidence-strength score. It is not a
probability, not a confidence percentage, and not a policy authorization probability.

## Truth Labels

Benchmark truth labels are independent of Outcome's Evidence Score:

- `SUPPORTED`
- `CONTRADICTED`
- `INSUFFICIENT_EVIDENCE`

Operational states such as `PROVIDER_FAILED` and `SYSTEM_FAILURE` are reported
separately from factual truth labels.

Every case includes label provenance with a source type, reference identifier,
labeling method, dataset version, and timezone-aware `as_of` timestamp. Synthetic
cases are explicitly labeled as synthetic.

## Current Production Evidence Score Configuration

The benchmark documents the current production defaults from
`outcome.evidence.scoring.EvidenceScoringConfig`. Prompt 29 does not tune these values.

Thresholds:

- `verified_threshold`: `7000`
- `contradicted_threshold`: `7000`
- `contradiction_block_threshold`: `4000`
- `max_age_seconds`: `None`

Authority weights:

- `AUTHORITATIVE_REGISTRY`: `9000`
- `PRIMARY`: `8500`
- `REPUTABLE_SECONDARY`: `6500`
- `DERIVATIVE`: `3000`
- `UNKNOWN`: `1500`

Extraction weights:

- `EXACT_STRUCTURED`: `9000`
- `DIRECT_TEXT`: `8000`
- `NORMALIZED_TEXT`: `6500`
- `PARTIAL`: `3500`
- `LOW_CONFIDENCE`: `1500`
- `FAILED`: `0`

Component weights:

- `source_authority`: `2000`
- `extraction_quality`: `1500`
- `independence`: `2000`
- `corroboration`: `2000`
- `contradiction`: `2000`
- `freshness`: `300`
- `coverage`: `200`

## Running

```sh
make benchmark
```

This writes `benchmarks/latest-report.json` and compares the current run with the
checked-in golden baseline. The generated latest report is intentionally ignored by
git.

To intentionally update the golden baseline:

```sh
make benchmark-update-golden
```

Golden updates must be reviewed. The process is:

1. Run `make benchmark`.
2. Inspect semantic differences.
3. Explain why the change is expected.
4. Run `make benchmark-update-golden`.
5. Commit code, dataset, and golden changes together.

## Adding Cases

Add cases to `benchmarks/datasets/v1.json`. Keep fixtures deterministic and safe:

- no customer data
- no secrets
- no payment details
- no production evidence
- no network dependency

Use the independent label provenance fields to explain where the label comes from.
Do not use Outcome's own score or status as the truth label.
