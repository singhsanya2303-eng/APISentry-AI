# Detection Evaluation Workflow

## Evidence classes

This project reports two different evidence classes and never mixes them:

1. **Synthetic-rule agreement** — agreement with deterministic expectations from the MW4 synthetic harness. It verifies orchestration, missing-signal handling and conservative rule behavior. It is not predictive accuracy.
2. **Labelled predictive metrics** — precision, recall, F1, false-positive rate and false-negative rate computed only from a dataset with authoritative labels supplied by an authorized evaluator.

The Batch 7 classifier bundle is frozen. Evaluation must not retrain, replace or retune it in this workflow.

## Current evidence status

- **Implemented in code:** the primary detection modules, MW4 orchestration and synthetic harness, advisory mitigation lifecycle, classifier services, persistence models, and the labelled-metrics evaluation CLI exist in the repository.
- **Locally verified:** the Task 12A safe backend suite result is **1494 passed, 29 warnings**, with the separately gated PostgreSQL persistence test excluded. Artifact-free development explicitly skips real-artifact classifier tests with visible reasons. These are local test results, not performance measurements or production evidence.
- **Experimental/research:** `research/` scripts and tests and the frozen Batch 7 classifier bundle are exploratory artifacts. The bundle is excluded from the contribution; when absent, classifier endpoints return explicit HTTP `503` and no substitute model is used. Required CI/test mode uses `--require-classifier-artifact` and fails collection when the bundle is missing.
- **Production readiness:** not established. Production request-time enforcement remains disabled/advisory-only, Gate E/WP9 are isolated default-disabled demonstrations, and PostgreSQL durability/deployment controls require separate verification and approval.

This document does not report real-world precision, recall, F1, false-positive rate or false-negative rate. No authoritative labelled production dataset is included, and this task did not invent evaluation metrics or performance results.

## Reproducible labelled evaluation

`scripts/evaluate_detection_metrics.py` accepts `.jsonl` or `.csv` input. Each row needs a label field and a prediction field. Rows missing either value are skipped and counted.

```powershell
python scripts/evaluate_detection_metrics.py `
  --input <labelled-predictions.jsonl> `
  --dataset-kind labelled `
  --label-field label `
  --pred-field predicted `
  --positive-class malicious `
  --category-field category `
  --output <evaluation-report.json>
```

JSONL example:

```json
{"request_ref":"r1","label":"malicious","predicted":"malicious","category":"credential_stuffing"}
{"request_ref":"r2","label":"benign","predicted":"benign","category":"normal"}
```

Use `--dataset-kind synthetic-rule-agreement` for the existing synthetic harness. In that mode the script intentionally omits binary predictive metrics and states that agreement is not accuracy. `--dataset-kind unknown` also withholds predictive metrics.

## Report interpretation

- `predictive_accuracy_supported` is `true` only for explicitly labelled data with both positive and negative labels represented and both fields present.
- `binary_metrics` contains counts: `tp`, `fp`, `tn`, `fn`, `precision`, `recall`, `f1`, `false_positive_rate`, `false_negative_rate`, `valid_rows`, `skipped_invalid_rows`, and a `supported` flag.
- `confusion_matrix` is descriptive for every dataset kind; it does not by itself establish accuracy.
- Decision margins and risk scores are not calibrated probabilities. Do not present them as probabilities.
- Thresholds used by advisory policies are operational configuration, not validated accuracy claims. Changing them requires a new labelled evaluation.

## Limits

No real labelled production dataset is included in this repository. Until an authorized labelled dataset is supplied, the project can report only synthetic-rule agreement, harness coverage, and structural detection checks — not real-world precision, recall, F1, FPR or FNR.
