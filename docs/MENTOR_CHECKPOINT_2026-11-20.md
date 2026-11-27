# APISentry AI — Interim Mentor Checkpoint

**Review date:** 20 November 2026
**Document type:** Interim technical checkpoint (verification and documentation only)
**Scope of this checkpoint:** no application code, dataset, research report, model artifact, environment, or Git state was changed during preparation.

---

## 1. Project Title and Objective

**APISentry AI — Intelligent API Security Monitoring and Threat Detection System.**

The objective is a web-based platform that analyzes API traffic, identifies suspicious request patterns, and produces security insights through a React dashboard backed by a FastAPI service. The project is currently at an **interim, advisory-only** stage: backend analysis services and a persistence/audit foundation exist and are test-covered; runtime enforcement and production-validated machine learning are explicitly out of scope at this checkpoint.

Status labels used throughout this document:

| Label | Meaning |
|---|---|
| **Implemented** | Code and routes/models exist in the repository. |
| **Tested** | Current repository evidence from test execution in this checkpoint supports the behavior. |
| **Partially implemented** | Core logic exists but coverage, integration, or operational readiness is incomplete. |
| **Not integrated** | Exists in isolation (typically research artifacts) but is not wired into runtime decision paths. |
| **Unverified** | Not exercised or confirmed during this checkpoint. |
| **Deferred** | Explicitly postponed by a prior decision. |

---

## 2. Problem Statement and Motivation

APIs are exposed to object-level authorization abuse (BOLA/IDOR), brute-force attempts, rate anomalies, malicious payloads, and automated client activity. Manual review of request logs does not scale, and naive alerting produces high false-positive volumes.

APISentry AI addresses this by providing:

- modular traffic analysis endpoints for several known abuse classes;
- a deterministic, evidence-based bot-detection score;
- a deterministic advisory mitigation *recommendation* layer;
- persisted decisions and a hash-chained audit trail for accountability;
- a React dashboard for analyst review.

**Motivation constraint:** all detection and mitigation outputs are advisory. No blocking, throttling, banning, or active enforcement is enabled anywhere in the verified code paths.

---

## 3. Technology Stack

Evidence: `README.md`, `backend/requirements.txt`, `frontend/package.json`, `research/requirements.txt`.

**Backend**

- Python 3.13.7 (verified in `.venv`)
- FastAPI 0.162.0, Uvicorn (declared `>=0.28.0`)
- SQLAlchemy 2.1.6, Alembic 1.20.1, psycopg2-binary (declared)
- Pydantic v2, pydantic-settings, python-dotenv, bcrypt
- pytest 9.1.1, httpx (test client)
- NumPy, scikit-learn 1.9.1, PyTorch (declared)

**Frontend**

- React 19, Vite 8, Recharts 3, lucide-react
- Oxlint for linting

**Research**

- Separate `research/` Python package for canonical events, preprocessing, capture contracts, group-aware splits, and verification utilities.

**Environment note:** the system `python` on PATH does **not** have Alembic installed. All tests in this checkpoint were executed with `.venv\Scripts\python.exe`. No packages were installed.

---

## 4. System Architecture

Evidence: `backend/app/main.py`, `backend/app/api/v1/router.py`, `backend/app/core/config.py`.

- `create_app()` builds the FastAPI application, configures CORS (`Authorization`, `Content-Type`, `X-API-Key`, `X-Request-ID`), adds `RequestLoggingMiddleware`, mounts the v1 router at `/api/v1`, and exposes `/health`, `/`, `/docs`, `/redoc`.
- Application startup optionally calls `init_db()` only when `AUTO_CREATE_SCHEMA=True` **and** `ENVIRONMENT != "production"`; production configuration forces this off.
- `api_router` mounts public `auth` and `users` routers, then mounts nine analysis routers behind a shared `Depends(require_analyst_or_api_key)` dependency: BOLA, brute force, rate anomaly, behavior, bot detection, mitigation analysis, clustering, token classifier, and traffic trends. `/api/v1/health` is public.
- Optional demo-auth router is mounted at `/demo/auth` only when demo auth is explicitly configured.
- Tests override authentication dependencies and use an **in-memory SQLite** database (`backend/tests/conftest.py`); no PostgreSQL instance was contacted.

---

## 5. Implemented Backend Modules

Evidence: route files under `backend/app/api/v1/routes/`, services under `backend/app/services/`.

| Module | Status | Notes |
|---|---|---|
| BOLA/IDOR analysis | Implemented; Tested | Protected analysis route; frontend client present. |
| Brute-force analysis | Implemented; Tested | Protected analysis route; frontend client present. |
| Rate-anomaly analysis | Implemented; Tested | Protected analysis route; frontend client present. |
| Behavior analysis | Implemented; Tested | Protected analysis route; frontend client present. |
| Clustering analysis | Implemented; Tested | Protected analysis route; frontend client present. |
| Token classifier analysis | Implemented; Tested | Protected route; artifact-based prediction. |
| Traffic trends | Implemented; Tested | Protected analysis route; frontend client present. |
| Bot detection (`/api/v1/security/bot/analyze`) | Implemented; Tested | Deterministic advisory scoring; no frontend integration. |
| Mitigation analysis (`/api/v1/security/mitigation/analyze`) | Implemented; Tested | Advisory recommendation + persistence boundary; no frontend integration. |
| Health/root endpoints | Implemented; Tested | Public. |

All nine protected analysis routers are test-covered by the current backend suite (see §11).

---

## 6. Authentication and RBAC

Evidence: `backend/app/core/security.py`, `backend/app/models/user.py`, `backend/app/api/v1/routes/auth.py`, `backend/app/api/v1/routes/users.py`, `backend/app/api/v1/router.py`.

**Status: Implemented; Tested (authentication tests are excluded from global dependency overrides in `conftest.py`).**

- Password hashing via bcrypt (`hash_password`, `verify_password`).
- JWT bearer tokens: HS256, 60-minute access-token lifetime, decode/validation and revocation support (`create_access_token`, `decode_access_token`, `revoke_token`, `is_token_revoked`).
- API-key authentication (`require_api_key`) using the `X-API-Key` header.
- Roles: `admin`, `analyst`, `viewer` (`UserRole`).
- `RequireRole` dependency class and `require_analyst_or_api_key` combined dependency.
- Registration, login, `/me`, logout, and admin user-management routes exist.
- All analysis routers are mounted behind `require_analyst_or_api_key`; user-management routes are admin-restricted.

**Unverified:** live token expiry behavior in a deployed environment, password-reset/account-recovery flows (not observed in inspected code), and role behavior against a real PostgreSQL-backed user store.

---

## 7. Bot Detection Methodology

Evidence: `backend/app/services/bot_detection_service.py` (1,364 lines), `backend/app/api/v1/routes/bot_detection.py`.

**Status: Implemented; Tested; advisory only.**

- Reads existing traffic and behavior records rather than collecting new traffic.
- Groups events by client identity (`ClientGroupKey`), filters detector evidences, and computes scaled signal weights via `_scaled()` against configured thresholds in `BotScoringConfig`.
- Produces opaque, privacy-preserving request references (`_opaque_request_id`) and selects a representative actor for each group.
- Uses historical findings as supporting context; score and evidence are returned through `BotDetectionResponse`.
- It is **deterministic and evidence-based** — not a trained model.
- **No enforcement:** the service scores and explains; it does not block, throttle, or ban.
- Frontend integration: **Not integrated** — no bot-detection API client or UI module exists in the inspected frontend.

---

## 8. Mitigation Policy Methodology

Evidence: `backend/app/services/mitigation_policy_service.py` (595 lines), `backend/app/services/mitigation_integration_service.py` (379 lines), `backend/app/api/v1/routes/mitigation_analysis.py`.

**Status: Implemented; Tested; advisory only.**

- `evaluate_mitigation_decision()` and `finalize()` implement a pure, deterministic policy engine over summarized bot-detection evidence (`_EvidenceSignals`, `_summarize_signals`, `_explanation`).
- Policy versioning, route classes, idempotency keys, and dedupe keys are validated before evaluation (`_validate_policy_version`, `_validate_route_class`, `_validate_idempotency_key`, `build_dedupe_key`).
- `build_mitigation_context()` translates a bot-detection result into a request context; `_unavailable_outcomes()` records where detection evidence was insufficient.
- `evaluate_and_persist_bot_detection()` orchestrates detection → policy evaluation → persistence; failures roll back safely via `_rollback_safely` in the route.
- Outputs are **recommendations with reasons and evidence references**. No enforcement hook, blocking rule, or rate-limit action is present in the verified paths.
- Frontend integration: **Not integrated** — no mitigation API client or UI module exists in the inspected frontend.

---

## 9. Database and Audit Architecture

Evidence: `backend/app/models/mitigation.py`, `backend/app/models/traffic.py`, `backend/alembic/versions/*`, `backend/app/services/mitigation_audit_integration_service.py`.

**Status: Implemented; Tested (SQLite test fixtures); live PostgreSQL migration Unverified.**

**Models** (`app/models/mitigation.py`): `MitigationPolicy`, `MitigationPolicyState`, `MitigationPolicyActivationEvent`, `MitigationDecision`, `MitigationAuditEvent`, plus enums for policy mode, activation events/reason codes, decision type, scope type, attribution status, and audit event/entity types. Constraints include SHA-256 and uuid5 format checks, enum checks, and event hashing.

**Migrations** (`backend/alembic/versions/`):

- `0001_baseline_existing_schema` — baseline for existing schema.
- `0002_mitigation_policy_models` — policy and activation tables.
- `0003_mitigation_decision_audit` — decision and audit-event tables.

**Persistence and audit:**

- `MitigationDecision` records validated, deduplicated decisions with opaque evidence references.
- `MitigationAuditEvent` uses canonical-content SHA-256 digests (`_content_digest`), deterministic uuid5 event IDs (`_event_uuid`), and hash chaining for tamper evidence.
- `persist_decision_audit_events()` validates authentication context, resolves actors, and persists planned events with conflict detection (`MitigationAuditConflictError`, `MitigationAuditPersistenceFailure`).
- `alembic.ini` and migration tests assert no embedded DSN / database URL leakage in output.

**Unverified:** upgrades/downgrades against PostgreSQL, concurrent-write behavior, and long-term audit-chain verification outside tests. No migration was executed during this checkpoint.

---

## 10. Frontend Status

Evidence: `frontend/src/App.jsx`, `frontend/src/components/AnalysisPanel.jsx`, `frontend/src/services/api.js`, `frontend/src/services/tokenStorage.js`.

**Status: Partially implemented.**

- `api.js` uses `fetch` with `VITE_API_BASE_URL` (default `http://127.0.0.1:8000`), optional `X-API-Key`, bearer-token headers from local storage, and clears invalid sessions on HTTP 401.
- API clients exist for auth (`register`, `login`, `me`, `logout`), admin user listing, BOLA, brute force, rate anomaly, behavior, clustering, token classifier, and traffic trends, plus health.
- `App.jsx` exposes **seven** analysis modules through `AnalysisPanel`; no bot-detection or mitigation module is present in the module list.
- No frontend code references bot detection or mitigation endpoints.
- `node_modules` is present, but no dev server, build, lint, or browser verification was performed in this checkpoint.

**Not integrated:** bot detection and mitigation recommendation UI. **Unverified:** live browser rendering and end-to-end API calls from the UI.

---

## 11. Test Evidence

All commands below were executed during this checkpoint with no package installs, no PostgreSQL connection, no migrations, and no environment changes. `-B` suppresses bytecode writes and `-p no:cacheprovider` prevents pytest cache writes.

| Command (working directory) | Result |
|---|---|
| `& '..\.venv\Scripts\python.exe' -B -m pytest -p no:cacheprovider --collect-only -q tests` (`backend`) | **1029 tests collected in 1.59s; exit 0** |
| `& '..\.venv\Scripts\python.exe' -B -m pytest -p no:cacheprovider -q tests` (`backend`) | **1029 passed, 7 warnings in 83.72s; exit 0** |
| `& '..\.venv\Scripts\python.exe' -B -m pytest -p no:cacheprovider -q tests --ignore=tests/test_alembic_baseline.py --ignore=tests/test_mitigation_decision_audit_models.py --ignore=tests/test_mitigation_models.py` (`backend`) | **930 passed, 7 warnings in 73.96s; exit 0** |
| `& '..\.venv\Scripts\python.exe' -B -m pytest -p no:cacheprovider -q tests/test_alembic_baseline.py tests/test_mitigation_decision_audit_models.py tests/test_mitigation_models.py` (`backend`) | **99 passed in 8.50s; exit 0** |
| `& '.venv\Scripts\python.exe' -B -m pytest -p no:cacheprovider -q research/tests` (repository root) | **145 passed in 2.05s; exit 0** |

**Warnings (non-failing):** Starlette deprecation warnings for `httpx` test client and `HTTP_422_UNPROCESSABLE_ENTITY`; one scikit-learn `ConvergenceWarning` in the CSIC artifact round-trip test.

**Setup-dependent attempt (not a code failure):**

- Running `pytest -q tests` from `research/` produced 11 collection errors (`ModuleNotFoundError: No module named 'research'`, exit 2). The research package must be imported from the repository root; the root-level command above passes.

**Discrepancy — previously reported Alembic collection blocker is not reproducible.** An earlier handoff reported `ImportError: cannot import name 'command' from 'alembic' (unknown location)` during test collection. In this checkpoint, full collection and full execution both succeed with exit 0, and the three named test files pass directly (99 passed). The earlier failure is therefore treated as an invocation/environment artifact, not a current repository defect. It is **not** claimed to be permanently resolved; treat it as unresolved until it can be reproduced and root-caused.

**Tested scope caveat:** these results cover the Python backend and research suites. Frontend tests were not executed; no live server, browser, PostgreSQL, or migration run was performed.

---

## 12. ML Research Methodology and Results

All ML work is **research-only and Not integrated** into runtime detection, mitigation, authentication, routes, frontend, database enforcement, blocking, throttling, or banning.

### 12.1 CSIC 2010 — HTTP anomaly classifier

**Status: research baseline completed; predeclared acceptance FAILED; Not integrated.**

Evidence: `backend/models/csic_http_anomaly/v1/evaluation_report.json`, `evaluation_report.md`, `acceptance_criteria.json`, `backend/app/services/csic_training_service.py`, `backend/scripts/train_csic_http_classifier.py`, `backend/tests/test_csic_http_pipeline.py`.

- Dataset acquired and audited: **223,585 rows, 61,065 sessions**; SHA-256 `46f207d266909bfd46cb255d8a357828cba9ee49a93d8ea7becf0354c7446a0e`.
- Group-aware split by **cookie/session** with seed **42**, 70/15/15; **zero session overlap** across splits (train 42,745 / validation 9,160 / test 9,160 sessions).
- Trained research candidates: TF-IDF logistic regression, TF-IDF linear SVM, structured logistic regression, plus a deterministic keyword baseline.
- Selected model: `structured_logistic_regression`.
- Final held-out test: **session PR-AUC 0.3031224308481131**, session FPR **0.9098148148148149**, recall 0.7407, precision 0.3618, F1 0.4861, request PR-AUC 0.4380. Session confusion matrix: TN 487, FP 4,913, FN 975, TP 2,785.
- Keyword baseline session PR-AUC: **0.4730384186565084** (better than the selected model).
- Predeclared acceptance: **passed: false** — minimum PR-AUC (0.7), maximum FPR (0.2), and beat-baseline checks all FAIL; recall PASS; zero-overlap PASS.
- Artifact round-trip and research-only prediction are Tested via `test_csic_http_pipeline.py`.
- Declared limitations: session-level labels, no attack-category ground truth, keyword heuristics only in the baseline, controlled academic web traffic rather than APISentry traffic.

### 12.2 SR-BH 2020 — request-level multilabel dataset

**Status: audit completed; Phase 1 training deliberately HALTED; no model trained.**

- Raw source audited: `research/datasets/raw/data_capec_multilabel.csv` — **907,815 rows × 38 columns**.
- Only **12 usable CAPEC attack labels** were present, and those labels were concentrated on **17–19 July**. CAPEC-248 had a single positive example.
- No valid leakage-resistant three-way date-block split could be constructed with complete coverage of all 12 labels; any split would leave labels absent or concentrate them in one partition.
- Training was halted **before fitting**; there is no SR-BH model artifact and no SR-BH performance claim.
- This dataset must not be merged with other datasets or used to claim production accuracy.

### 12.3 WAMM — final normalized-overlap audit

**Status: read-only audit completed; final decision NO-GO.**

Evidence: `research/datasets/raw/WAMM-Dataset-Repository-main.zip` (SHA-256 `e75bf62186b301ebd29ff021e4a32f4574904802b535862a7346ce6391332599`); prior read-only audit and addendum. Publication resolved as Osama et al., *IEEE Access* vol. 14, pp. 61512–61527, 2026, DOI `10.1109/ACCESS.2026.3685450`.

Final normalized comparison against DS-Base:

| Dataset | Rows matching DS-Base | Share | Identical label strings |
|---|---:|---:|---:|
| v1 | 745,616 / 1,093,547 | 68.18% | 0 |
| v2 | 620,056 / 704,665 | 87.99% | 0 |

Additional verified findings:

- DS-Base contains **859,293 rows** (actual header `Full_request`, `class`) and **471,918 unique normalized requests**; v1 has **550,702 unique normalized requests**.
- **v2 is a subset of v1**: all 312,256 unique v2 requests appear in v1; v1 and v2 share the same 132,171 unique normal requests.
- Most label-string differences are formatting conversions, but **genuine semantic relabeling also occurs** (examples: `Fake the Source of Data` → `000 - Normal` in 481 rows; `SQL Injection` → `000 - Normal` in 167 rows).
- The three versions form **one overlapping dataset lineage, not independent corpora**.
- Combining versions across evaluation partitions would cause **substantial leakage**.
- WAMM has no timestamps or sessions and shows strong Host/User-Agent leakage.
- **Final decision: NO-GO** as shipped. No WAMM model was trained and no WAMM data was merged into any other experiment.

### 12.4 General ML limitation

None of CSIC 2010, SR-BH 2020, or WAMM establishes real-world production API attack-detection accuracy. No research dataset result should be presented as validation of the runtime detector.

---

## 13. CSIC, SR-BH and WAMM Dataset Decisions

| Dataset | Decision | Rationale |
|---|---|---|
| CSIC 2010 | **Preserve as a failed research baseline**; do not promote, retrain for runtime, or report as accuracy evidence. | Predeclared acceptance failed; very high FPR and PR-AUC below the keyword baseline. |
| SR-BH 2020 | **Phase 1 halted**; no model trained. | All 12 labels confined to three dates; no defensible leakage-resistant 3-way date-block split with complete class coverage. |
| WAMM | **NO-GO as shipped**. | v2 ⊂ v1; all versions overlap DS-Base; one dataset lineage; semantic relabeling; no temporal/session structure; leakage risk. |

**Cross-dataset rule:** do not merge CSIC, SR-BH, or WAMM experiments. Do not overwrite `backend/models/token_usage_classifier.joblib` or any existing CSIC artifact/report; future artifact writes must use no-overwrite guards, consistent with `write_json_guard` and `_write_text_guard`.

**Controlled collection:** `research/STAGE_7_HANDOFF.md` reports that no controlled traffic collection has been successfully completed, an earlier attempt failed, no backup/restore rehearsal has been performed, and no experimental detection results are established. Collection remains **NO-GO** until isolation, backup/restore, and cleanup procedures are proven and approved.

---

## 14. Known Limitations and Unresolved Risks

1. **No enforcement layer.** Detection and mitigation are advisory; blocking/throttling/banning is Deferred by design.
2. **Frontend gap.** Bot detection and mitigation are not exposed in the UI or API client.
3. **Absolute CSIC performance is poor.** Session PR-AUC ~0.303 with FPR ~0.910; keyword baseline outperforms the selected model.
4. **SR-BH split infeasibility.** Temporal label concentration prevents a defensible three-way evaluation.
5. **WAMM lineage/leakage.** Overlapping versions and semantic relabeling make shipped versions unsuitable for evaluation.
6. **No production-validated ML.** Runtime token classifier artifact exists but was not retrained or revalidated here.
7. **Operational unverified areas.** PostgreSQL migrations, live server startup, frontend build/browser behavior, concurrency, and audit-chain verification outside tests.
8. **Authentication details unverified in deployment.** Token expiry/revocation behavior against a real DB and any account-recovery flow were not exercised.
9. **Prior test-blocker discrepancy.** Reported Alembic import failure did not reproduce; root cause remains unconfirmed.
10. **Research collection gate.** No controlled collection, backup/restore rehearsal, or experimental detection results from that pipeline.

---

## 15. Current Completion Assessment

No completion percentage is asserted. Status by capability:

| Capability | Status |
|---|---|
| Architecture, stack, routing, CORS, middleware, health | Implemented; Tested |
| Auth, JWT, API key, RBAC, protected routers | Implemented; Tested (deployment behavior Unverified) |
| Analysis modules (BOLA, brute force, rate anomaly, behavior, clustering, token classifier, trends) | Implemented; Tested |
| Bot detection engine and API | Implemented; Tested; Not integrated with frontend |
| Mitigation policy, API, persistence, audit | Implemented; Tested; Not integrated with frontend |
| DB models and Alembic migration scripts | Implemented; Tested on SQLite; PostgreSQL Unverified |
| Frontend dashboard for seven existing modules | Partially implemented; browser behavior Unverified |
| Frontend bot detection / mitigation UI | Not integrated |
| CSIC research classifier | Completed baseline; acceptance FAILED; Not integrated |
| SR-BH model | Deferred / halted; no model trained |
| WAMM evaluation | Completed audit; NO-GO |
| Controlled collection and backup/restore | Deferred; NO-GO |
| Runtime enforcement / blocking | Deferred |

---

## 16. Next Development Milestones

Ordered as proposed milestones, not commitments:

1. Wire bot-detection and mitigation recommendation endpoints into the frontend API client and dashboard, with explicit advisory labeling.
2. Reproduce and root-cause the historically reported Alembic import error under the exact failing invocation, then document a canonical test command.
3. Verify a clean Alembic upgrade path against a disposable PostgreSQL instance (separate from any production data), with no DSN leakage.
4. Add live-server and browser-level smoke verification for health, login, RBAC, and one analysis module.
5. Maintain the research boundary: keep CSIC/SR-BH/WAMM artifacts separate, preserve no-overwrite guards, and do not merge datasets.
6. Resolve Stage 7 collection preconditions (isolation, backup/restore rehearsal, cleanup) and seek explicit approval before any controlled collection.
7. Consider an advisory-only model-validation plan using future, legitimately independent data; do not repurpose the three audited datasets for production accuracy claims.
8. Treat enforcement/blocking as a separate, later design decision with its own review and safeguards.

---

## 17. Suggested Mentor Demonstration Sequence

Suggested total: **5–7 minutes**. Items marked **Runnable now** were supported by test execution in this checkpoint; items marked **Requires setup or verification** were not executed as live demos.

1. **(0:00–0:45) Project introduction — Runnable now (static).** Show `README.md` and this checkpoint. State the advisory-only boundary.
2. **(0:45–1:30) Architecture — Runnable now (static).** Walk through `backend/app/main.py` and `backend/app/api/v1/router.py`: public auth/users, nine protected routers, CORS, middleware, `/health`.
3. **(1:30–2:15) Authentication — Runnable now via tests; live server Requires setup.** Show `require_analyst_or_api_key`, JWT/API-key support, roles, and the authentication test results in §11. A browser login demo requires a configured live backend/frontend.
4. **(2:15–3:00) Bot detection — Runnable now via tests; live UI Not integrated.** Show `BotScoringConfig`, evidence grouping, deterministic scoring, and `test_bot_detection_api.py`. Explicitly note there is no frontend module.
5. **(3:00–3:45) Mitigation recommendation — Runnable now via tests; live UI Not integrated.** Show `evaluate_mitigation_decision`, `evaluate_and_persist_bot_detection`, the `/api/v1/security/mitigation/analyze` route, and its tests. Emphasize: recommendation only, no enforcement.
6. **(3:45–4:30) Audit/persistence — Runnable now via tests; PostgreSQL Requires setup.** Show `MitigationDecision`, `MitigationAuditEvent`, SHA-256 digests, uuid5 IDs, hash chaining, and the three Alembic revisions. State that migrations were not executed here.
7. **(4:30–5:45) ML research findings — Runnable now (artifact inspection).** Show the CSIC evaluation report and its `passed: false`; summarize SR-BH halt and WAMM NO-GO with the normalized-overlap table. State explicitly that none establishes production accuracy.
8. **(5:45–6:30) Limitations and next steps — Runnable now (discussion).** Use §§14–16: frontend gap, no enforcement, unverified PostgreSQL/live UI, collection NO-GO.

**Not demonstrated as runnable:** live browser UI, PostgreSQL migration, any retraining, any controlled collection, any enforcement behavior.

---

## 18. Questions and Decisions Requiring Mentor Guidance

1. Should frontend integration of bot detection and mitigation be prioritized next, or should operational verification (PostgreSQL migration, live smoke tests) come first?
2. What is the acceptable advisory-only presentation standard for the UI so recommendations are never mistaken for enforcement?
3. Should the historically reported Alembic import error be treated as closed (not reproducible here) or formally root-caused before milestone work proceeds?
4. Is there approval to use a disposable PostgreSQL instance for migration verification, given this checkpoint's no-PostgreSQL constraint?
5. Should the failed CSIC baseline be retained as a documented negative result in the main README, or kept only in the research artifact path?
6. What independent, legitimately collected data source is acceptable for any future ML validation, given the NO-GO decisions on SR-BH and WAMM and the failed CSIC criteria?
7. At what gate may enforcement/blocking design begin, and what safeguards would be required before any such capability is enabled?

---

## Appendix A — Verification Performed for This Checkpoint

**Target file check:** `docs/MENTOR_CHECKPOINT_2026-11-20.md` was absent and `docs/` did not exist before creation. This document is the only file created.

**Files inspected (read or staged read-only):**

- Root: `README.md`, `.gitignore`, directory listings (`.env.local` was **not** read).
- Backend config/entry: `backend/requirements.txt`, `backend/app/main.py`, `backend/app/api/v1/router.py`, `backend/app/core/config.py`.
- Auth/RBAC: `backend/app/core/security.py`, `backend/app/api/v1/routes/auth.py`, `backend/app/api/v1/routes/users.py`, `backend/app/models/user.py`.
- Detection/mitigation: `backend/app/api/v1/routes/bot_detection.py`, `backend/app/services/bot_detection_service.py`, `backend/app/api/v1/routes/mitigation_analysis.py`, `backend/app/services/mitigation_policy_service.py`, `backend/app/services/mitigation_integration_service.py`, `backend/app/services/mitigation_audit_integration_service.py`.
- DB/migrations: `backend/app/models/mitigation.py`, `backend/app/models/traffic.py`, `backend/alembic/versions/0001_baseline_existing_schema.py`, `0002_mitigation_policy_models.py`, `0003_mitigation_decision_audit.py`, `backend/alembic/env.py`, `backend/alembic.ini`.
- Tests: `backend/tests/conftest.py` and the full `backend/tests/` suite (collection plus execution).
- ML: `backend/app/services/csic_training_service.py`, `backend/app/services/csic_http_feature_adapter.py`, `backend/scripts/train_csic_http_classifier.py`, `backend/train_token_classifier.py`, `backend/models/csic_http_anomaly/v1/evaluation_report.json`, `evaluation_report.md`, `acceptance_criteria.json`, `backend/models/token_usage_classifier.joblib` (existence/size only), `backend/tests/test_csic_http_pipeline.py`.
- Research: `research/README.md`, `research/data_manifest.yaml`, `research/STAGE_7_HANDOFF.md`, `research/requirements.txt`, the `research/tests/` suite, and raw dataset directory listings (CSIC 2010 archive, SR-BH CAPEC CSV, WAMM archive).
- Frontend: `frontend/package.json`, `frontend/src/App.jsx`, `frontend/src/components/AnalysisPanel.jsx`, `frontend/src/services/api.js`, `frontend/src/services/tokenStorage.js`, `frontend/src/main.jsx`, `vite.config.js` (existence), `frontend/node_modules` (existence only).

**Tests executed:** see §11 for exact commands and outcomes.

**Changes made:** only `docs/MENTOR_CHECKPOINT_2026-11-20.md`. No application code, dataset, existing research report, model artifact, environment, Git state, or secrets were modified. No packages were installed; no PostgreSQL connection or migration was performed; no enforcement/blocking was enabled.
