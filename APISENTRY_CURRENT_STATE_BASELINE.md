# APISENTRY_CURRENT_STATE_BASELINE
> **Historical snapshot:** This report records evidence from its original task/date and is preserved for context. It is not a statement of current repository state. Current safe backend suite evidence is **1494 passed, 29 warnings** (Task 12A), excluding the separately gated PostgreSQL persistence suite.

**Audit type:** Phase 0 strict read-only audit (no source/config modification)  
**Audit date:** 2026-11-24 (local workspace inspection)  
**Workspace:** `<PROJECT_ROOT>`  
**Auditor constraint:** Evidence from current files, git state, reports, tests, and code inspection only. No PostgreSQL connections, no DB start/stop, no enforcement activation, no Batch 7 modification, no dependency install, no secrets inspected.

---

## 1. Repository Identity and Preservation Status

| Item | Evidence | Status |
|---|---|---|
| Git repo | `git rev-parse --short HEAD` => `ce7c8f8`; branch `master` | Present |
| Dirty worktree | `git status --short` => **167 entries** (modified, untracked, deleted in status output); many pre-existing APISENTRY reports, backend/frontend/tests changes | **Preserved / not cleaned** |
| Recent commits | `git log --oneline -5` shows recent agent-host commits and `ce7c8f8 docs(research): finalize Stage 7 readiness and team handoff` | Historical baseline only |
| Secrets | No `.env` values inspected/exposed; `.env.example` only observed | Preserved |
| Batch 7 frozen artifacts | `research/models/http_payload_classifier/v1/model_bundle.joblib` SHA256 `2D694C932B9779D4971FA418AA35ECDF60CC266FE909B2EA40AA5392C5AE92DC`; `metadata.json` present; service pins same hash (`backend/app/services/http_payload_classifier_service.py:54`) | Preserved, hash matches |
| Isolated SQLite demo DB | `<LOCAL_TEMP>\opencode\apisentry_local_demo_20261123\apisentry_demo.sqlite3` previously verified/preserved (692224 bytes at preflight per checkpoint) | Preserved (not re-touched) |
| Protected PostgreSQL resources | Ports 5432/55446/55447 not to be touched; existing PG service observed on 5432 (PID 7560, preflight) | Not touched by audit |
| Disposable PG workdir (approved DB mission, separate) | `<LOCAL_TEMP>\opencode\apisentry_pg_0004_verify_20261124_20261124_102520` created; initdb succeeded; cluster startup unstable/unconfirmed; background start command unfinished at checkpoint | **Execution incomplete - do not assume ready** |
| One coding agent | This audit only; no parallel coding agent actions | Compliant |

**Preservation confirmation:** No reset/checkout/clean/stash/stage/commit/push/branch switch performed. No DB/container start/stop performed by this audit. No enforcement activated. No Batch 7 artifacts modified. No dependencies installed.

---

## 2. Completion Matrix (20 Major Modules)

Classification legend: **COMPLETED AND VERIFIED** = implemented and verified by current evidence; **IMPLEMENTED BUT NOT FULLY VERIFIED** = code exists with partial verification; **PARTIALLY IMPLEMENTED** = meaningful gaps/incomplete behavior; **NOT IMPLEMENTED** = missing; **BLOCKED** = external approval/infra/dependency required; **NOT STARTED** = no implementation; **UNKNOWN / NO CURRENT EVIDENCE** = cannot confirm.

| # | Module | Classification | Evidence (files/APIs/tests/reports) | Latest available test/verification evidence | Remaining acceptance criteria |
|---|---|---|---|---|---|
| 1 | **Backend app shell / startup / health / readiness** | IMPLEMENTED BUT NOT FULLY VERIFIED | `backend/app/main.py` (`create_app`, lifespan auto-create guard, `/health`, `/ready`, `/`, CORS, middleware wiring, exception handlers); `backend/app/api/v1/router.py` (`/api/v1/health`); `backend/app/core/config.py`; tests `backend/tests/test_health.py`, `test_lifespan.py`, `test_api_hardening.py` | Hardening tests 14 passed (checkpoint); full safe suite 1398 passed, 0 failed, 27 warnings (checkpoint). `/ready` 200 on isolated SQLite demo previously verified. | Production startup path without unsafe auto-create; PG readiness in approved env; deployment runbook validation. |
| 2 | **Authentication (register/login/logout/me, JWT, password hashing)** | IMPLEMENTED BUT NOT FULLY VERIFIED | `backend/app/api/v1/routes/auth.py` (`POST /register`, `POST /login`, `GET /me`, `POST /logout`); `backend/app/core/security.py` (JWT create/decode, bcrypt/PBKDF2 verify, revocation check, `require_jwt_auth`); `backend/app/models/user.py`, `backend/app/schemas/auth.py`; tests `test_jwt_authentication.py`, `test_persistent_auth.py`, `test_authentication.py`, `test_sec01_jwt_revocation.py` | SEC-01 7 passed previously; full safe suite 1398 passed. Browser login/logout previously verified in final browser acceptance. | Refresh-token/rotation design (not implemented); durable multi-worker revocation on approved PG; exhaustive browser E2E for all auth edge states. |
| 3 | **JWT revocation & persistent token invalidation** | PARTIALLY IMPLEMENTED | `backend/app/core/security.py` (hash-based revocation, in-memory fallback, DB lookup, fail-closed on DB lookup failure); `backend/app/models/revoked_token.py`; `backend/app/alembic/versions/0004_revoked_tokens.py`; `backend/app/api/v1/routes/auth.py` logout; `backend/tests/test_sec01_jwt_revocation.py`; reports `APISENTRY_SEC01_JWT_REVOCATION.md`, `APISENTRY_DATABASE_READINESS_REPORT.md` | SEC-01 tests pass in safe suite; restart behavior simulated in tests. 0004 **not applied** to approved PostgreSQL; no real multi-worker PG verification. | Apply/verify 0004 on disposable approved PG; verify restart/multi-worker/revocation durability; cleanup scheduling; fail-closed behavior in production persistent mode. |
| 4 | **RBAC / authorization / sensitive endpoint protection** | IMPLEMENTED BUT NOT FULLY VERIFIED | `backend/app/core/security.py` (`require_admin`, `require_analyst`, `require_viewer`, `require_jwt_auth`, `require_analyst_or_api_key`); `backend/app/api/v1/router.py` blankets analysis routers with `require_analyst_or_api_key`; route deps in `users.py`, `mitigation_policy_admin.py`, `mitigation_decision_audit.py`, `mitigation_dry_run.py`, `mitigation_demo.py`, `demo_auth.py`; tests `test_jwt_authentication.py`, `test_mitigation_admin_api.py`, `test_mw4_p1_rbac_security_regression.py` | RBAC checks pass in safe suite; browser acceptance showed Viewer/Analyst restrictions and 403s. | Full role-by-role browser/API matrix for every route; periodic authz regression in CI; review static API key management for analysis routes. |
| 5 | **User management (admin/viewer self, profile)** | IMPLEMENTED BUT NOT FULLY VERIFIED | `backend/app/api/v1/routes/users.py`; `backend/app/services/user_service.py`; `backend/app/schemas/auth.py`; frontend `AdminPanel` in `frontend/src/App.jsx`; tests `test_persistent_auth.py`, `test_jwt_authentication.py` (admin user flows) | Admin users list rendered in browser acceptance; full safe suite passes. | Full CRUD/role-change/disable E2E; error/loading/empty states; audit trail for admin actions. |
| 6 | **Traffic ingestion / storage / aggregation / query foundation** | IMPLEMENTED BUT NOT FULLY VERIFIED | `backend/app/models/traffic.py` (`APITrafficLog`); `backend/app/services/traffic_service.py`, `traffic_aggregation_service.py`; `backend/app/schemas/traffic.py`; tests `test_traffic_schema.py`, `test_traffic_query.py`, `test_traffic_aggregation.py`, `test_persistence.py`, `test_database_error_handling.py` | Included in 1398-pass safe suite. | Production ingestion pipeline validation, indexing/perf on PG, retention/archival policy. |
| 7 | **BOLA detection** | IMPLEMENTED BUT NOT FULLY VERIFIED | `backend/app/api/v1/routes/bola.py`; `backend/app/services/bola_analysis_service.py`; `backend/app/detection/bola_detector.py`; `backend/app/services/resource_extractor.py`; tests `test_bola_api.py`, `test_bola_analysis_service.py`, `test_bola_detector.py`, `test_resource_extractor.py` | API/service/detector tests pass in safe suite. No dedicated browser E2E for all states. | Realistic dataset evaluation, false-positive review, UI workflow E2E. |
| 8 | **Brute-force detection** | IMPLEMENTED BUT NOT FULLY VERIFIED | `backend/app/api/v1/routes/bruteforce.py`; `backend/app/services/bruteforce_analysis_service.py`; `backend/app/detection/bruteforce_detector.py`; tests `test_bruteforce_api.py`, `test_bruteforce_analysis_service.py`, `test_bruteforce_detector.py` | Tests pass in safe suite. | Threshold tuning/evaluation on governed datasets; browser E2E. |
| 9 | **Rate anomaly / traffic anomaly detection** | IMPLEMENTED BUT NOT FULLY VERIFIED | `backend/app/api/v1/routes/rate_anomaly.py`; `backend/app/services/rate_anomaly_analysis_service.py`; `backend/app/detection/rate_anomaly_detector.py`; tests `test_rate_anomaly_api.py`, `test_rate_anomaly_analysis_service.py`, `test_rate_anomaly_detector.py`, `test_traffic_trends_api.py`, `test_traffic_trend_analysis_service.py` | Tests pass in safe suite. | Real traffic calibration, drift monitoring, UI E2E. |
| 10 | **Behavior / user behavior features / advanced pattern analyzers** | IMPLEMENTED BUT NOT FULLY VERIFIED | `backend/app/api/v1/routes/behavior.py`; `backend/app/services/behavior_analysis_service.py`, `behavior_feature_vector_service.py`, `user_behavior_features_service.py`, `request_pattern_anomaly_service.py`, `request_path_anomaly_service.py`, `http_method_anomaly_service.py`, `geo_velocity_anomaly_service.py`, `historical_request_pattern_service.py`, `user_agent_anomaly_service.py`; tests `test_behavior_*`, `test_advanced_detection_*`, `test_request_pattern_*`, `test_user_behavior_features_service.py` | Many tests pass in safe suite. | Dataset-backed evaluation, explainability review, UI E2E. |
| 11 | **Bot detection (MW2) and mitigation analysis** | IMPLEMENTED BUT NOT FULLY VERIFIED | `backend/app/api/v1/routes/bot_detection.py`, `mitigation_analysis.py`; `backend/app/services/bot_detection_service.py`, `stacked_autoencoder_service.py`; `frontend/src/components/BotDetection.jsx`, `MitigationAnalysis.jsx`; tests `test_bot_detection_api.py`, `test_bot_detection_service.py`, `test_stacked_autoencoder_*`, `test_mitigation_analysis_api.py` | Targeted and safe-suite tests pass; browser smoke previously verified bot detection panel. | Governed evaluation datasets, false-positive/negative measurement, responsive/browser E2E. |
| 12 | **ML training/support services (non-frozen)** | PARTIALLY IMPLEMENTED | `backend/app/services/ml_training_service.py`, `csic_training_service.py`, `csic_http_feature_adapter.py`; tests `test_ml_training_service.py`, `test_csic_http_pipeline.py` | Present in safe suite (tests exist/pass as part of 1398). | Clear production training/eval governance, reproducible pipelines, no accidental frozen-artifact coupling. |
| 13 | **HTTP Payload Classifier (Batch 7 frozen)** | IMPLEMENTED BUT NOT FULLY VERIFIED | `backend/app/api/v1/routes/http_payload_classifier.py`; `backend/app/services/http_payload_classifier_service.py` (pinned SHA256 `2d694c9...`); `backend/app/schemas/http_payload_classifier.py`; artifacts `research/models/http_payload_classifier/v1/model_bundle.joblib`, `metadata.json`; frontend `HttpPayloadClassifier.jsx`; tests `test_http_payload_classifier_api.py`, `test_http_payload_classifier_service.py` | Hash verified in audit; metadata present; service hash pin matches; API/service tests pass in safe suite; browser predict previously verified. | Governed evaluation on approved datasets; adversarial/FP review; no frozen artifact changes. |
| 14 | **MW1 Unified Risk Assessment (sole overall risk owner)** | IMPLEMENTED BUT NOT FULLY VERIFIED | `backend/app/services/unified_risk_assessment_service.py`; `backend/app/schemas/unified_risk_assessment.py`; `backend/app/detection/risk_scorer.py`; tests `test_unified_risk_assessment_service.py`, `test_risk_scorer.py`; docs/reports cite MW1 owner constraint | Unit/service tests pass in safe suite. No refactor violating sole-owner constraint observed. | End-to-end calibration/evaluation; explicit integration contract verification across all consumers; production telemetry. |
| 15 | **MW4 runtime orchestration / runtime analysis API** | IMPLEMENTED BUT NOT FULLY VERIFIED | `backend/app/services/mw4_runtime_orchestration_service.py`, `mw4_p1_evaluation.py`; `backend/app/schemas/mw4_runtime.py`; `backend/app/api/v1/routes/mitigation_analysis.py` (MW4 runtime-analyze context) and/or MW4-related routes; docs `docs/MW4_*`, `docs/mw4_p1_*`; tests `test_mw4_runtime_analysis_api.py`, `test_mw4_p1_evaluation_harness.py`, `test_mw4_p1_rbac_security_regression.py`, `test_mw4d_rc_regressions.py` | MW4 tests present in suite; prior smoke showed `/api/v1/security/mitigation/runtime-analyze` 200. | Full E2E with governed data; browser/API contract verification; production limits documented. |
| 16 | **Mitigation policy lifecycle (MW3 Gate A/B) + persistence** | PARTIALLY IMPLEMENTED | `backend/app/services/mitigation_policy_lifecycle_service.py` (Gate A, MW3 markers); `mitigation_policy_lifecycle_persistence_service.py`; `mitigation_policy_persistence_service.py`; `mitigation_policy_service.py`; `backend/app/models/mitigation.py`; migrations `0002_mitigation_policy_models.py`, `0003_mitigation_decision_audit.py`; tests `test_mitigation_policy_lifecycle.py`, `test_mitigation_policy_lifecycle_persistence.py` (PG-gated, excluded), `test_mitigation_policy_service.py`, `test_mitigation_policy_persistence_service.py`, `test_mitigation_models.py` | Non-PG tests pass in safe suite; PG-gated persistence test **not run**. SEC-02 added hydration/reconciliation. Batch 7 frozen-file deviation noted in `APISENTRY_REMAINING_BLOCKERS.md` for lifecycle service hash. | Resolve/acknowledge Batch 7 freeze deviation; run PG-gated persistence; verify restart/multi-worker consistency on approved PG; no silent in-memory overwrite. |
| 17 | **Mitigation admin/audit/dry-run APIs (Gate C) & decision/audit persistence** | IMPLEMENTED BUT NOT FULLY VERIFIED | Routes `mitigation_policy_admin.py`, `mitigation_decision_audit.py`, `mitigation_dry_run.py`; services `mitigation_audit_*`, `mitigation_decision_persistence_service.py`, `mitigation_integration_service.py`; schemas `mitigation_admin.py`, `mitigation_audit.py`, `mitigation.py`; frontend `MitigationAdmin*` components; tests `test_mitigation_admin_api.py`, `test_mitigation_decision_audit_models.py`, `test_mitigation_decision_persistence_service.py`, `test_mitigation_audit_persistence_service.py`, `test_mitigation_audit_integration_service.py` | Admin API tests pass; browser acceptance saw policies/dry-run/decisions/audit tabs. Some states partial. | Exhaustive E2E for create/validate/activate/deactivate/retire/rollback; audit completeness; pagination/filter UI verification. |
| 18 | **Gate E local demo enforcement harness (isolated, default OFF)** | IMPLEMENTED BUT NOT FULLY VERIFIED | `backend/app/api/v1/routes/mitigation_demo.py`; `backend/app/services/mitigation_demo_service.py`; `backend/app/schemas/mitigation_demo.py`; frontend `MitigationDemoPanel.jsx`; docs `APISENTRY_DEMO_RUNBOOK.md`; tests `test_mitigation_demo_enforcement.py`; reports `APISENTRY_FINAL_BROWSER_ACCEPTANCE_REPORT.md`, `APISENTRY_SEC05_DEMO_STATUS.md` | Demo enable/disable/kill-switch/synthetic run verified in browser acceptance and API smoke; demo restored DISABLED/ADVISORY ONLY. | UI validation clarity fully polished; responsive/browser E2E across viewports; confirm no real enforcement in all deployment modes. |
| 19 | **Frontend dashboard, routing, role-aware UX** | IMPLEMENTED BUT NOT FULLY VERIFIED | `frontend/src/App.jsx`, `App.css`, `components/*` (AnalysisPanel, BotDetection, HttpPayloadClassifier, MitigationAnalysis, MitigationAdmin*, etc.), `services/api.js`, `tokenStorage.js`, `utils/mitigationAdminHelpers.js`; tests `frontend/tests/*.test.js` (25 files? count from prior: 25 passed); lint/build scripts in `frontend/package.json` | Frontend tests 25 passed, lint PASS (1 pre-existing warning), build PASS. Browser acceptance CONDITIONAL PASS; responsive 768x1024/390x844 UNVERIFIED. | Full responsive QA, accessibility pass, error/empty/loading states for all modules, analyst/viewer/admin E2E matrix. |
| 20 | **Security hardening, observability, and production readiness controls** | PARTIALLY IMPLEMENTED | `backend/app/utils/middleware.py` (request size, security headers, request logging); `backend/app/core/rate_limit.py`; `backend/app/core/security_events.py`; `backend/app/main.py` (validation/500 handlers); config in `backend/app/core/config.py`; tests `test_api_hardening.py`, `test_middleware.py`, `test_security_configuration.py`; reports `APISENTRY_SAFE_SECURITY_HARDENING_REPORT.md`, `APISENTRY_SECURITY_REPORT.md`, `APISENTRY_REMAINING_BLOCKERS.md` | Hardening 14 passed; safe suite 1398 passed. Browser/responsive/infra UNVERIFIED. | Distributed rate limit/revocation store; streaming/chunked body hardening beyond current ASGI guard; CSP tightening; centralized security logging/SIEM; penetration/load testing; production deployment signoff. |

---

## 3. Implemented vs. Verified Distinction

| Area | Implemented | Verified | Gap |
|---|---|---|---|
| Auth/JWT/RBAC core | Yes | Unit/API/browser smoke | No full browser matrix; no distributed multi-worker JWT revocation on PG |
| P0/P1 hardening (headers, size limit, auth rate limit, 422/500 redaction) | Yes | 14 hardening tests + 1398 safe suite | No distributed rate limit; no pentest; no browser resize; chunked/stream edge cases only unit-tested |
| DB migrations 0001-0004 | Files present | Alembic/file review; 0001-0003 historically in SQLite tests; 0004 file-only | 0004 not applied/verified on approved PG; PG-gated persistence not run |
| MW1/MW2/MW4 | Yes | Unit/service/API tests | No governed real-dataset evaluation; no production calibration |
| Batch 7 payload classifier | Yes, frozen | SHA256 match, metadata, API/service tests, prior browser smoke | No new governed evaluation; frozen artifacts must remain unchanged |
| Gate E demo | Yes | Browser acceptance + tests | UI validation polish, responsive QA, no real enforcement proof beyond config/tests |
| Frontend | Yes | 25 node tests, lint/build, conditional browser acceptance | Responsive/tablet/mobile UNVERIFIED; full state matrix incomplete |

---

## 4. Exact Pending Work

### P0 / Deployment-blocking
1. **Apply and verify Alembic 0004 on disposable approved PostgreSQL only** - verify schema/ORM, upgrade path, idempotency semantics, downgrade behavior/documentation, fail-closed behavior. Evidence: `0004_revoked_tokens.py`, `APISENTRY_DATABASE_READINESS_REPORT.md`.
2. **Verify durable JWT revocation on approved PG** - login/logout/reuse after restart, DB unavailable/fail-closed, missing table/store behavior, cleanup/expiry, multi-worker independent processes. Tests: `test_sec01_jwt_revocation.py`, new PG verification.
3. **Run PG-gated persistence tests** - `backend/tests/test_mitigation_policy_lifecycle_persistence.py` in approved disposable PG env with exact command/results.
4. **Multi-worker consistency** - two independent processes against same disposable PG for revocation and mitigation persistence where supported.
5. **Backup/restore drill on disposable PG** - logical backup, SHA256, restore to second disposable DB, integrity/row counts, app read after restore.

### P1 / Security & correctness hardening
6. **Distributed rate limiting/revocation shared store** - requires architecture/dependency approval (Redis/shared store). Current limiter is per-process (`backend/app/core/rate_limit.py`).
7. **Streaming/chunked request body hardening** - ASGI guard exists; validate edge cases under real deployment/proxy configs.
8. **CSP tightening for production** - `unsafe-inline` styles and broad connect-src noted in `APISENTRY_SECURITY_REPORT.md`.
9. **Resolve Batch 7 freeze deviation decision** - `APISENTRY_REMAINING_BLOCKERS.md` reports lifecycle service hash deviation due SEC-02 hydration. Requires explicit user decision: accept audited deviation or refactor hydration into non-frozen module.
10. **Centralized security event logging/SIEM integration** - `security_events.py` exists; no centralized alerting.

### P2 / Verification gaps
11. **Responsive browser QA** - 1366x768/768x1024/390x844 with screenshot-capable tooling; currently UNVERIFIED.
12. **Full role-based browser E2E matrix** - admin/analyst/viewer across all modules, error/empty/loading states, demo panel full workflow.
13. **AI evaluation on governed datasets** - synthetic/public/real labeled runs via `scripts/evaluate_detection_metrics.py`; no real-world accuracy claims.
14. **Load/performance/security testing** - approved environment only; current local microbench not production throughput.

### P3 / Product/ops
15. **Production deployment runbook validation** - env/secrets, CORS, PG, migrations, worker model, monitoring, backups.
16. **crAPI/external API validation** - no current crAPI evidence found in workspace (glob/search returned none). Treat as NOT STARTED/NO CURRENT EVIDENCE until governed setup exists.

---

## 5. Critical Dependency Graph

```text
Approved disposable PostgreSQL env
  -> Alembic 0001-0003 baseline/upgrade
    -> Alembic 0004 revoked_tokens
      -> Persistent JWT revocation verification
      -> PG-gated mitigation persistence tests
      -> Multi-worker revocation/persistence verification
      -> Backup/restore drill
        -> Database readiness verdict

MW1 unified risk (sole owner)
  -> MW4 runtime orchestration
  -> Mitigation decision context
  -> Dashboard risk displays
  (must not be bypassed by other detectors)

Gate A lifecycle service
  -> Gate B persistence
  -> Gate C admin/audit/dry-run APIs
  -> Gate D dashboard (frontend mitigation admin)
  -> Gate E isolated demo harness

Batch 7 frozen payload artifact/hash
  -> Payload classifier service/API/UI
  -> Any evaluation must preserve artifact

Security hardening baseline
  -> Auth rate limit / headers / request limits
  -> JWT revocation
  -> RBAC
  -> Safe demo mode
  -> Production readiness (blocked by distributed/PG/pentest)
```

---

## 6. Database and Migration Status

| Item | Status | Evidence |
|---|---|---|
| Alembic config | Present | `backend/alembic.ini`, `backend/alembic/env.py` (uses `settings.get_database_url()`) |
| Migration chain | 0001-0004 present | `backend/alembic/versions/0001_baseline_existing_schema.py` ... `0004_revoked_tokens.py` |
| 0001 | Baseline users/api_traffic_logs | File-reviewed |
| 0002 | Mitigation policy models | File-reviewed |
| 0003 | Mitigation decision/audit | File-reviewed |
| 0004 | `revoked_tokens` table/indexes, additive; downgrade drops table | File-reviewed; **NOT APPLIED** to approved PG |
| ORM models registered | Includes `RevokedToken`, mitigation models, `User`, `APITrafficLog` | `backend/app/models/__init__.py`, `db/base.py`, `db/init_db.py` |
| Local SQLite demo | Isolated, preserved, previously PASS (scoped) | `APISENTRY_DATABASE_READINESS_REPORT.md` |
| Approved PG 0004 verification | **BLOCKED/INCOMPLETE** | Disposable cluster at `<LOCAL_TEMP>\opencode\apisentry_pg_0004_verify_20261124_20261124_102520`, port 55448 intended; startup unstable; background pg_ctl start unfinished per checkpoint. No DB-changing commands should run until cluster identity/process/port are confirmed disposable. |
| PG-gated persistence test | Not run | `backend/tests/test_mitigation_policy_lifecycle_persistence.py` excluded from safe suite |

---

## 7. Actual Enforcement Status

| Control | Status | Evidence |
|---|---|---|
| Real production enforcement | **NOT ENABLED** | Reports and code indicate advisory-only defaults; Gate E is demo-only synthetic/loopback. |
| Gate E demo enforcement | Implemented, default OFF, isolated temp SQLite, loopback-only, synthetic-only, explicit confirmation, bounded, kill switch | `mitigation_demo_service.py`, `mitigation_demo.py`, `APISENTRY_DEMO_RUNBOOK.md`, browser acceptance |
| Advisory-only payload/mw1/mw4 outputs | Present | Classifier limitations in service/schema; MW1 "does not block/throttle/mitigate" in module docstring |
| Enforcement claims | Must remain constrained | No claim of real blocking in production; demo status must show `real_enforcement=false` |

---

## 8. AI Evaluation Status

| Item | Status | Evidence |
|---|---|---|
| Batch 7 payload classifier artifact | Frozen/preserved; SHA256 verified | `model_bundle.joblib`, `metadata.json`, service hash pin |
| MW1/MW2/MW4 evaluation harnesses/tests | Present | `mw4_p1_evaluation.py`, `test_mw4_p1_evaluation_harness.py`, unit tests |
| Reproducible metric script | Present | `scripts/evaluate_detection_metrics.py` |
| Synthetic/public/real labeled evaluation runs | **NOT EXECUTED in governed manner** | `APISENTRY_AI_EVALUATION_REPORT.md` |
| Real-world accuracy claims | **NOT SUPPORTED** | No governed dataset runs/evidence |
| crAPI validation | **NO CURRENT EVIDENCE / NOT STARTED** | No crAPI files/evidence found by workspace search |

---

## 9. crAPI Status

**UNKNOWN / NO CURRENT EVIDENCE.** Workspace search for `crapi/CRAPI` returned no project files/artifacts/reports. README/docs inspected did not provide crAPI execution evidence. Any crAPI claim requires governed environment, explicit approval, and captured evidence.

---

## 10. Security and Production Blockers

| Blocker | Severity | Evidence | Needed |
|---|---|---|---|
| 0004 not applied/verified on approved PG | High | DB readiness report, SEC-01, migration file | Disposable PG verification, then approved rollout |
| No durable multi-worker JWT revocation proof | High | SEC-01, security report | Multi-process PG test |
| PG-gated persistence test not run | High | test file excluded | Run in approved disposable PG |
| Distributed rate limit/revocation not implemented | Medium-High | `rate_limit.py`, security report | Shared store/architecture approval |
| Batch 7 lifecycle service freeze deviation unresolved | Medium | `APISENTRY_REMAINING_BLOCKERS.md` | Explicit user decision + audit/refactor |
| Browser responsive QA unverified | Medium | Final browser acceptance | Tooling/manual evidence |
| No pentest/load/production security validation | High for prod | Reports | Approved environment/testing |
| AI evaluation not governed/complete | Medium-High | AI evaluation report | Governed datasets/runs |
| crAPI not evidenced | Medium | no evidence | Governed crAPI setup/run |

---

## 11. Corrected Completion Estimate (Methodology)

**Methodology:** Weighted engineering-readiness estimate, not a line-count metric. Weights: Core backend/auth/RBAC 15%, Detection/ML/MW1-MW4 20%, Mitigation lifecycle/admin/demo 20%, DB/migrations/persistence 15%, Frontend/UX 10%, Security hardening 10%, Verification/eval/prod readiness 10%. Each area scored by implemented+verified evidence; blocked/unverified items discounted.

| Area | Weight | Score | Weighted | Rationale |
|---|---:|---:|---:|---|
| Core backend/auth/RBAC | 15% | 78% | 11.7% | Solid code/tests; distributed revocation and full E2E gaps |
| Detection/ML/MW1-MW4 | 20% | 72% | 14.4% | Implemented and unit-tested; governed evaluation missing |
| Mitigation lifecycle/admin/demo | 20% | 74% | 14.8% | Gate A-E code present; PG persistence/multi-worker/freeze-deviation unresolved |
| DB/migrations/persistence | 15% | 45% | 6.75% | 0001-0004 files present; 0004/PG/multi-worker/backup-restore unverified |
| Frontend/UX | 10% | 70% | 7.0% | Functional and tested; responsive/E2E gaps |
| Security hardening | 10% | 66% | 6.6% | P0/P1 improved; distributed/prod controls missing |
| Verification/eval/prod readiness | 10% | 35% | 3.5% | No governed AI eval, no pentest/load, no prod signoff |

**Corrected completion estimate: ~64.8% (engineering prototype, local-demo conditional; production readiness materially lower ~35-40%).** 

This estimate is **conservative and evidence-based**; it should not be treated as release readiness. "Verified" is limited to cited tests/reports and local demo evidence.

---

## 12. Recommended Next Implementation Phase

**Phase 1 (next): Database & Persistence Verification on approved disposable PostgreSQL** - complete the user-approved DB mission first, because it unblocks SEC-01 durability, mitigation persistence confidence, and deployment readiness. Strictly follow disposable-cluster identity checks before every DB-changing command; record evidence in `APISENTRY_DATABASE_PERSISTENCE_REPORT.md`.

**Phase 2:** Resolve Batch 7 freeze-deviation decision and security follow-ups that require design approval (distributed rate limit/revocation, CSP tightening, streaming limits under proxies).

**Phase 3:** Full browser/responsive role E2E and UI polish, with evidence capture.

**Phase 4:** Governed AI evaluation (synthetic/public/real separated), crAPI/governed external validation, load/pentest, production deployment hardening.

---

## Historical Milestone Reconciliation

| Milestone | Status in evidence | Reconciliation | Evidence |
|---|---|---|---|
| Gate A (MW3 lifecycle) | IMPLEMENTED BUT NOT FULLY VERIFIED | Code and tests present; hydration/SEC-02 changed lifecycle service causing Batch 7 freeze-deviation note - needs explicit disposition | `mitigation_policy_lifecycle_service.py`, `test_mitigation_policy_lifecycle.py`, `APISENTRY_REMAINING_BLOCKERS.md` |
| Gate B (persistence) | PARTIALLY IMPLEMENTED | Persistence services/migrations present; PG-gated persistence test excluded; no approved PG run | `mitigation_policy_lifecycle_persistence_service.py`, `test_mitigation_policy_lifecycle_persistence.py`, DB readiness report |
| Gate C (admin/audit/dry-run APIs) | IMPLEMENTED BUT NOT FULLY VERIFIED | Routes/tests/UI present; browser smoke saw tabs; exhaustive E2E incomplete | `mitigation_policy_admin.py`, `mitigation_decision_audit.py`, `mitigation_dry_run.py`, tests, browser report |
| Gate D (dashboard/admin UI) | IMPLEMENTED BUT NOT FULLY VERIFIED | Mitigation admin/dashboard components exist; UI loading/admin states had prior observations; responsive unverified | `frontend/src/components/MitigationAdmin*.jsx`, browser reports |
| Gate E (isolated demo enforcement) | IMPLEMENTED BUT NOT FULLY VERIFIED | Default OFF, synthetic/loopback, kill switch, disable restores advisory-only verified in browser acceptance | `mitigation_demo.py`, `mitigation_demo_service.py`, `APISENTRY_DEMO_RUNBOOK.md`, final browser report |
| MW1 (unified risk sole owner) | IMPLEMENTED BUT NOT FULLY VERIFIED | Code/tests present; constraint documented; no governed evaluation | `unified_risk_assessment_service.py`, `test_unified_risk_assessment_service.py` |
| MW2 (bot detection) | IMPLEMENTED BUT NOT FULLY VERIFIED | Bot detection service/API/UI/tests present | `bot_detection_service.py`, bot tests, BotDetection.jsx |
| MW3 (policy lifecycle) | PARTIALLY IMPLEMENTED | Overlaps Gate A/B; PG persistence and freeze-deviation unresolved | MW3 markers in lifecycle service, remaining blockers |
| MW4 (runtime orchestration/eval) | IMPLEMENTED BUT NOT FULLY VERIFIED | MW4 services/schemas/tests/docs present; smoke 200 previously | `mw4_runtime_orchestration_service.py`, MW4 docs/tests |
| Batch 7 freeze | **VERIFIED WITH CAVEAT** | Payload classifier bundle hash matches `2d694c9...`; metadata present; service pins hash. Caveat: `APISENTRY_REMAINING_BLOCKERS.md` reports `mitigation_policy_lifecycle_service.py` hash deviated from a Batch 7 frozen-hash expectation - requires explicit disposition. | artifact hash, metadata, remaining blockers |
| Safe P0/P1 Security Hardening | IMPLEMENTED BUT NOT FULLY VERIFIED | Current pass added headers, request size, rate limit, security events, 422/500 redaction, CORS wildcard rejection; 14 hardening + 1398 safe suite pass; browser/responsive/infra unverified | `APISENTRY_SAFE_SECURITY_HARDENING_REPORT.md` |
| Final Browser Acceptance | **CONDITIONAL PASS (historical, scoped)** | Admin/viewer/analyst/demo flows passed; responsive 768/390 UNVERIFIED; no code changes in that pass | `APISENTRY_FINAL_BROWSER_ACCEPTANCE_REPORT.md` |
| Database & Persistence Engineering approval/execution | **APPROVED, EXECUTION INCOMPLETE** | User explicitly approved disposable PG work. Preflight/initdb done for disposable workdir on 55448; cluster startup unstable; background pg_ctl start unfinished; no 0004/PG verification completed. | checkpoint, temp workdir `apisentry_pg_0004_verify_20261124_20261124_102520` |

### Report reconciliation (historical/superseded/contradictory)

| Report | Status | Notes |
|---|---|---|
| `APISENTRY_FINAL_COMPLETION_REPORT.md` | Historical / superseded | Earlier "CONDITIONALLY COMPLETE" snapshot; later hardening and DB mission changed state |
| `APISENTRY_MASTER_IMPROVEMENT_REPORT.md` | Historical baseline, partially superseded | Useful summary; numbers superseded by later safe hardening (1388->1398, 4 hardening tests->14) |
| `APISENTRY_SAFE_SECURITY_HARDENING_REPORT.md` | Latest hardening evidence | Most current for P0/P1 hardening pass |
| `APISENTRY_SECURITY_REPORT.md` | Historical / partially superseded | Pre-dates latest hardening details; still useful for gap inventory |
| `APISENTRY_FINAL_SECURITY_HARDENING_REPORT.md` | Historical | Earlier security hardening report; reconcile against SAFE report |
| `APISENTRY_FINAL_BROWSER_ACCEPTANCE_REPORT.md` | Historical evidence, still valid for scoped flows | Responsive unverified remains |
| `APISENTRY_DATABASE_READINESS_REPORT.md` | Historical, still accurate on 0004/PG blockers | DB mission approved but not completed |
| `APISENTRY_REMAINING_BLOCKERS.md` | Historical but important | Contains Batch 7 lifecycle-service hash deviation and other blockers; must be reconciled |
| `APISENTRY_FEATURE_VERIFICATION_MATRIX.md` | Historical | Useful matrix; some statuses updated by later passes |

---

## Highest-Priority Unresolved Items

1. **Complete disposable PostgreSQL 0004 verification** on the approved isolated cluster (confirm cluster identity first; background start was unfinished) - covers migration, JWT revocation durability, PG-gated persistence, restart/multi-worker, backup/restore.
2. **Resolve Batch 7 freeze deviation decision** for `mitigation_policy_lifecycle_service.py` (SEC-02 hydration) - explicit accept/refactor disposition with audit evidence.
3. **Distributed revocation/rate-limit strategy** for multi-worker production (architecture/dependency approval required).
4. **Responsive browser QA (768x1024, 390x844) and full role E2E matrix** - currently UNVERIFIED.
5. **Governed AI evaluation + crAPI/production validation** - no real-world accuracy claims; crAPI has no current evidence.

*This audit is read-only and based on files/evidence available in the current workspace. It is not exhaustive where external systems, protected databases, browser tooling, or governed datasets were unavailable; such areas are explicitly marked UNVERIFIED/BLOCKED/NO CURRENT EVIDENCE.*