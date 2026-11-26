# APISENTRY AI Evaluation Report
> **Historical snapshot:** This report records evidence from its original task/date and is preserved for context. It is not a statement of current repository state. Current safe backend suite evidence is **1494 passed, 29 warnings** (Task 12A), excluding the separately gated PostgreSQL persistence suite.

## Verdict
- **AI evaluation readiness: NO-GO (for production claims) / PARTIAL (framework baseline)**
- **Local demo AI behavior: CONDITIONAL PASS** (existing detectors/pipeline functional in isolated demo; no new model training or frozen artifact changes)

## Scope and Constraints
- Batch 7 frozen payload classifier artifacts **not modified**.
- No model training/replacement performed.
- No external dataset downloads performed without governance/approval.
- Evaluation must separate synthetic, public-dataset, and real-traffic results. No synthetic-rule agreement reported as real-world accuracy.

## Current AI/Detection Inventory (code-inspected)
| Component | Role | Status |
|---|---|---|
| MW1 Unified Risk Assessment | Sole overall risk-score owner (per program constraint) | Preserve; not refactored in this pass |
| Bot detection (MW2) | Bot behavior/risk signals | Existing implementation preserved |
| Payload classifier (Batch 7 frozen) | HTTP payload classification | Frozen artifacts preserved; no modification |
| BOLA/Brute-force/Rate anomaly/Behavior/Traffic trends | Supporting detectors | Existing routes/services present |
| Mitigation dry-run/decision engine | Advisory decisions | Existing; advisory default preserved |

## Batch 7 Preservation
- No Batch 7 artifact modifications made in this pass.
- Prior verified payload classifier bundle hash (from prior report): `2d694c932b9779d4971fa418aa35ecdf60cc266fe909b2ea40aa5392c5ae92dc`.
- This pass did not locate the bundle file by filename scan; no changes were made to any payload classifier artifact. Treat hash as previously reported, not re-computed here.

## Evaluation Framework (implemented baseline)
- Added `scripts/evaluate_detection_metrics.py` - reproducible metric calculator for labeled prediction outputs.
- Inputs: CSV/JSONL with `label` and `predicted` (and optional `category`, `score`, `confidence`).
- Outputs: precision, recall, F1, FPR, FNR, confusion matrix, per-category metrics, uncertainty/coverage notes.
- The script does **not** download datasets, train models, or modify artifacts. It computes metrics only from supplied local files.

## Metrics Definitions
- **Precision** = TP / (TP + FP)
- **Recall** = TP / (TP + FN)
- **F1** = 2PR / (P+R)
- **FPR** = FP / (FP + TN)
- **FNR** = FN / (FN + TP)
- Confusion matrix reported per class/category.
- Decision margins/confidence must not be described as calibrated probabilities unless calibrated.

## Evaluation Runs Executed This Pass
| Dataset | Type | Run | Result |
|---|---|---|---|
| None executed against production/real traffic | Real | Not run | Blocked - no approved real traffic dataset/pipeline |
| None executed against public dataset | Public | Not run | Blocked - no dataset downloaded/governed in this pass |
| None executed against synthetic benchmark | Synthetic | Not run | Harness added; no labeled synthetic benchmark artifact generated in this pass |

## Limitations
- No real-world accuracy claim is made.
- No synthetic-rule agreement treated as real-world model accuracy.
- Frozen Batch 7 model not retrained/evaluated on new data in this pass.
- Dataset licensing/provenance review required before any public dataset use.
- Model drift monitoring not connected to production telemetry.

## Recommended Next Steps
1. Curate approved labeled datasets with source/license/provenance documentation.
2. Run `scripts/evaluate_detection_metrics.py` on synthetic, public, and real labeled sets separately.
3. Add per-detector threshold analysis and calibration review (without calling margins probabilities).
4. Add drift baseline snapshots and periodic evaluation in CI/approved environment.
5. Preserve MW1 as sole overall risk-score owner; integrate detector outputs as signals only.