# APISentry MW4-C P1 — Local Demo Runbook (Safe, Loopback, Synthetic)

> This runbook is for an isolated local demonstration only. **Not production deployment. Not real enforcement. Not PostgreSQL verification.**

## Safety boundaries (mandatory)
- Loopback only (`127.0.0.1`/`localhost`). No LAN/public exposure.
- Gate E demo default OFF. Explicit confirmation required.
- Synthetic requests only. No real customer traffic.
- Temporary SQLite demo DB under system temp; demo-owned; disposed on disable.
- Kill switch available and effective.
- No PostgreSQL start/stop/connect/restore/migration/pg-gated tests.
- No secret/env values in commands or evidence.

## Prerequisites
- Python 3.11+ (project uses `.venv`), Node.js/npm for frontend.
- From repo root: `<PROJECT_ROOT>`
- Use existing `.venv`: `.venv\Scripts\python.exe`

## 1) Backend tests (non-PG)
```powershell
.\.venv\Scripts\python.exe -m pytest -q --ignore=backend/tests/test_mitigation_policy_lifecycle_persistence.py backend/tests
```
Record exit code, pass/fail/skip/warning counts. Exclusion is explicit: pg-gated persistence test.

## 2) Frontend checks
```powershell
cd frontend
npm run lint
node --test tests/mitigationAdminApi.test.js tests/mitigationAdminHelpers.test.js tests/mitigationRuntimeApi.test.js
npm run build
```

## 3) P1 synthetic benchmark/evaluation harness (bounded, reproducible)
```powershell
.\.venv\Scripts\python.exe backend/scripts/run_mw4_p1_harness.py --out <external-run-dir>\benchmarks --seed 1337 --n-per-category 20 --iterations 2 --warmup 1
```
Outputs: `synthetic_dataset.json`, `benchmark_results.json`, `evaluation_results.json`, `harness_summary.json`.
Interpretation: synthetic-rule agreement and in-process timing only; no production accuracy/capacity claims.

## 4) Gate E live local demo (isolated)
Preferred: run existing Gate E pytest and/or the isolated P0-B style TestClient script against temp sqlite.
```powershell
.\.venv\Scripts\python.exe -m pytest -q backend/tests/test_mitigation_demo_enforcement.py
```
For a live local process demo, bind only to 127.0.0.1, use isolated temp SQLite, enable demo auth only in isolated dev config if needed, and never expose externally. Capture status/enable/run/kill-switch/disable evidence.

## 5) Runtime analysis (advisory)
- Start backend on loopback; authenticate as analyst/admin.
- Call `GET /api/v1/security/mitigation/runtime-analyze?page=1&page_size=50&include_behavioral_risk=true`.
- Confirm response has `advisory_only=true`, `enforcement_executed=false`, MW1 assessment, MW2 envelope separate.

## 6) Shutdown / cleanup
- Kill backend/frontend processes.
- Disable Gate E demo (`POST /demo/disable`) if enabled.
- Do not delete preserved PG run dirs. Do not touch PostgreSQL.

## Known failure scenarios
- MW4-B PG ambiguity: do not start/repair/cleanup preserved pgdata.
- Missing auth: 401/503. Viewer role on protected routes: 403.
- Invalid demo confirmation/schema: 422.
- Kill switch active: run rejected (409).
- Detector/model unavailable: explicit error/missing status; no fabricated clean signal.