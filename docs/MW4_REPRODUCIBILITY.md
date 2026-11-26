# MW4 Reproducibility Guide

## Scope
Covers MW4-C P1 / MW4-D synthetic benchmark+evaluation harness, key non-PG regression checks, and evidence interpretation. No PostgreSQL required.

## Required existing environment
- Windows repo at `<PROJECT_ROOT>`
- Existing Python venv: `.venv\Scripts\python.exe`
- Existing Node/npm dependencies in `frontend/` (no installs/upgrades)
- No `.env`/secrets required for harness and most non-PG tests

## Test commands (non-PG)

```powershell
# P1 harness tests
.\.venv\Scripts\python.exe -m pytest -q backend/tests/test_mw4_p1_evaluation_harness.py backend/tests/test_mw4_p1_rbac_security_regression.py

# Full non-PG backend suite (explicit exclusion)
.\.venv\Scripts\python.exe -m pytest -q --ignore=backend/tests/test_mitigation_policy_lifecycle_persistence.py backend/tests

# Frontend
cd frontend
npx --no-install oxlint
node --test tests/mitigationAdminApi.test.js tests/mitigationAdminHelpers.test.js tests/mitigationRuntimeApi.test.js
npm run build
```

## Harness commands

```powershell
.\.venv\Scripts\python.exe backend/scripts/run_mw4_p1_harness.py --out <out-dir> --seed 1337 --n-per-category 20 --iterations 2 --warmup 1
```

## Expected outputs
- `synthetic_dataset.json` — dataset metadata, cases, `dataset_sha256`
- `benchmark_results.json` — in-process sequential timing stats, memory tracemalloc, errors
- `evaluation_results.json` — synthetic-rule agreement, MW2 coverage, missing-signal handling
- `harness_summary.json` — compact summary

## Hash / determinism verification
- P1 baseline dataset: `mw4-p1-synth-v1`, seed `1337`, n_per_category `20`, cases `180`, SHA256 `3c9f18292d25df1893d5e18465707648380b94784d82d8367ba67c40745ff1dc`.
- Same seed+params should produce same dataset hash.
- Benchmark timing values may vary by machine/load; error counts and structural outputs should be stable.

## Metric interpretation
- **Synthetic-rule agreement:** agreement with conservative synthetic expected labels only. **Not** real-world precision/recall/F1/FPR/FNR/generalization.
- **Benchmark timing:** in-process sequential MW4-A orchestration timing. **Not** API/browser/production latency/capacity.
- **Missing-signal handling:** verifies missing/error cases are not silently treated as clean benign.

## Troubleshooting
- If `KeyError` or import errors occur, confirm commands run from repo root and venv Python is used.
- If frontend tests fail due to missing node_modules, do **not** install deps without approval; report environment blocker.
- If PostgreSQL-gated test is collected, ensure `--ignore=backend/tests/test_mitigation_policy_lifecycle_persistence.py` is used.
- Do not start PostgreSQL or touch MW4-B preserved pgdata for reproducibility runs.