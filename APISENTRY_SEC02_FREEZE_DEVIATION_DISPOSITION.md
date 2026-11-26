# APISENTRY SEC-02 Freeze-Deviation Disposition
> **Historical snapshot:** This report records evidence from its original task/date and is preserved for context. It is not a statement of current repository state. Current safe backend suite evidence is **1494 passed, 29 warnings** (Task 12A), excluding the separately gated PostgreSQL persistence suite.

**Date:** 2026-11-24  
**Task type:** Documentation and evidence reconciliation only  
**Decision:** **ACCEPT DEVIATION**

## 1. Decision and scope

**ACCEPT DEVIATION** is recorded for the SEC-02 mitigation lifecycle hydration change in `backend/app/services/mitigation_policy_lifecycle_service.py`.

This decision concerns the **Batch 7 freeze-boundary classification** only: the available evidence does not establish that this lifecycle service was part of the Batch 7 frozen artifact set. The SEC-02 hydration change is therefore accepted as a **separate, additive lifecycle change**, not as a modification of a frozen Batch 7 artifact.

This is **not** blanket production approval. It does not change the production-readiness assessment and does not authorize enforcement activation. The five previously listed verification gaps now have focused regression coverage as recorded in Section 6; that coverage does not convert this decision into production approval.

No tests were rerun during this documentation reconciliation. Reported test results below are taken from existing implementation, regression, and persistence-task evidence; they are identified as previously reported evidence and are not claims of test execution in this documentation task.

## 2. Correct Batch 7 freeze boundary

The frozen Batch 7 artifact set is the HTTP payload classifier artifact directory:

`research/models/http_payload_classifier/v1/`

The Phase 3 hardening report records the integrity hashes for the frozen artifacts in `research/models/http_payload_classifier/v1/PHASE3_HARDENING_REPORT.md`, including:

| File | SHA-256 recorded in Phase 3 integrity block |
|---|---|
| `model_bundle.joblib` | `2d694c932b9779d4971fa418aa35ecdf60cc266fe909b2ea40aa5392c5ae92dc` |
| `model.joblib` | `5e2bd9e4c24cca91b4eb4ac8979100e04a8e45b71c719b1e4e26784dbcbbcdaa` |
| `vectorizer.joblib` | `b236fcf062d1a9363d750296fc5ff55e6a9f93b3993fdf0d0f7bb96c88d6884d` |
| `scaler.joblib` | `90b20ce5dfed6268055a8a88a81d853df00bf7d5fdcb4716dc3a87326a5a4678` |
| `metadata.json` | `bc4843693a3222098f9dc69602a79256cb6f14fc5c673bcbc36104cd571a1aa0` |

The classifier service pins the bundle digest at `backend/app/services/http_payload_classifier_service.py:54` as `ARTIFACT_SHA256 = 2d694c932b9779d4971fa418aa35ecdf60cc266fe909b2ea40aa5392c5ae92dc`, and verifies loaded artifact bytes against it with `hmac.compare_digest` at line 197.

Independently recomputed during the earlier documentation audit:

- `research/models/http_payload_classifier/v1/model_bundle.joblib`
- SHA-256: `2d694c932b9779d4971fa418aa35ecdf60cc266fe909b2ea40aa5392c5ae92dc`

This matches the pinned and recorded classifier bundle hash.

Several earlier reports incorrectly used the classifier bundle hash `2d694c...` as if it were an expected lifecycle-service hash. That comparison was a category error: `2d694c...` identifies the batch-7 payload classifier bundle, not `backend/app/services/mitigation_policy_lifecycle_service.py`.

## 3. Lifecycle service disposition

Current verified lifecycle-service hash after the scoped SEC-02 implementation:

- `backend/app/services/mitigation_policy_lifecycle_service.py`
- SHA-256: `934a8c32fbf6c25c3742ec6f9765ac7936695ba9e2a1086c47c51d82faa3a6c8`

The earlier audit hash `660772a7930c9808dd2ba7380a8d085b5e7bddfa52213665f08903004ca3eb15` described the **pre-fix lifecycle-service state**. It is retained here only as historical context and is no longer the current hash after the scoped SEC-02 implementation recorded in Section 8.

The original accepted lifecycle-service source or hash **could not be recovered** from the available workspace evidence:

- The file is untracked in Git.
- It is absent from `HEAD`, so `git blame` reports no such path in `HEAD`.
- `git log --all -- backend/app/services/mitigation_policy_lifecycle_service.py` produced no recoverable historical version.
- No lifecycle-service hash manifest was found in the Batch 7 evidence.

Therefore:

- No definitive line-by-line comparison against an unavailable original is claimed.
- The available evidence does **not** establish that this service was a Batch 7 frozen artifact.
- The earlier classification of this file as a Batch 7 frozen file is superseded by this disposition.

## 4. Stale hash correction

### Correct hashes

| Item | Correct classification | SHA-256 |
|---|---|---|
| `research/models/http_payload_classifier/v1/model_bundle.joblib` | Batch 7 frozen payload classifier bundle | `2d694c932b9779d4971fa418aa35ecdf60cc266fe909b2ea40aa5392c5ae92dc` |
| `backend/app/services/mitigation_policy_lifecycle_service.py` | Current lifecycle-service hash after the scoped SEC-02 implementation | `934a8c32fbf6c25c3742ec6f9765ac7936695ba9e2a1086c47c51d82faa3a6c8` |

### Stale or incorrect lifecycle references

- `2d694c...` is **only** the classifier bundle hash in the available evidence. It is not a valid lifecycle-service hash expectation.
- `660772a7930c9808dd2ba7380a8d085b5e7bddfa52213665f08903004ca3eb15` was the **pre-fix lifecycle-service hash**. It is retained only as historical context and is superseded by the current hash `934a8c32fbf6c25c3742ec6f9765ac7936695ba9e2a1086c47c51d82faa3a6c8` recorded in Sections 3, 4, and 8.
- `5b9b9adfc2e95a74012b56515fba70e8b3df0da5073340a92d074b576f822770` was previously reported as the lifecycle-service hash. It is **stale/unverified** in the current workspace and cannot be reproduced from an available original artifact. It must not be presented as the current lifecycle hash.

Reports containing incorrect or stale lifecycle-hash references:

| Report | Original issue | Action taken |
|---|---|---|
| `APISENTRY_REMAINING_BLOCKERS.md` | Asserted `2d694c...` as expected lifecycle hash and `5b9b9adf...` as actual lifecycle hash | Corrected in place with historical annotation and disposition reference |
| `APISENTRY_FINAL_REGRESSION_REPORT.md` | Asserted `5b9b9adf...` as lifecycle hash and `2d694c...` as expected frozen lifecycle hash | Corrected in place with historical annotation and disposition reference |
| `APISENTRY_FINAL_SECURITY_HARDENING_REPORT.md` | Asserted `5b9b9adf...` as lifecycle hash and `2d694c...` as expected frozen lifecycle hash | Corrected in place with historical annotation and disposition reference |
| `APISENTRY_FINAL_INTEGRATION_REPAIR_REPORT.md` | Correctly identified the category error but recorded `5b9b9adf...` as the current lifecycle hash | Corrected in place; historical value marked stale/unverified |

Documents with stale status language but no incorrect lifecycle hash assertion were left unchanged to preserve historical meaning:

| Report | Why left unchanged |
|---|---|
| `APISENTRY_CURRENT_STATE_BASELINE.md` | Records Phase 0 status and historical “requires disposition” language; no incorrect lifecycle hash value is asserted. This note supersedes that status. |
| `APISENTRY_DATABASE_PERSISTENCE_REPORT.md` | Records that disposition remained open at the time of that report; no incorrect lifecycle hash value is asserted. |
| `APISENTRY_SEC02_MITIGATION_CONSISTENCY.md` | Technical SEC-02 report; no lifecycle hash assertion. |
| `research/models/http_payload_classifier/v1/PHASE3_HARDENING_REPORT.md` | Correctly records the classifier bundle hash; must not be rewritten. |

No source-code hash, classifier artifact, model file, or metadata was changed.

## 5. SEC-02 technical rationale

The accepted change adds best-effort, read-only hydration/reconciliation to the in-memory mitigation lifecycle registry.

Observed behaviour in `backend/app/services/mitigation_policy_lifecycle_service.py` after the scoped SEC-02 implementation:

- `hydrate_from_persistence(db)` loads all persisted policy snapshots and the persisted active policy version.
- Missing in-memory policy versions may be reconstructed from persisted snapshots.
- Reconstructed records use the **authoritative active pointer**: when no in-memory active pointer exists, the persisted active version may be adopted; when pointers differ, the persisted-only record is reconstructed non-ACTIVE so there is exactly one ACTIVE record and it agrees with the retained in-memory pointer.
- Existing in-memory policy records are not overwritten.
- If a persisted active version conflicts with an in-memory active version, the service reports `active_version_divergence`, preserves both the in-memory pointer and the persisted pointer, and does not silently override memory.
- Read-only hydration leaves persisted pointer rows unchanged.
- If the persisted active version is missing from the registry, the service reports `persisted_active_missing_from_registry`.
- Persistence read errors produce `persistence_read_failed` and a non-OK hydration report.
- Missing persistence schema is handled as a compatibility fallback with `persistence_store_unavailable`; this is **not** equivalent to durable or multi-worker consistency.
- Reconstructed records are intentionally lossy under the Gate B persistence mapping contract.
- `hydration_report()` exposes the last hydration result for observability.

Route-level handling is additive or fail-closed:

- Mitigation admin and demo routes reject with `503 mitigation_registry_inconsistent` when hydration is not OK.
- The mitigation dry-run route performs a fresh read-only hydration through `get_db`; a non-OK report raises the existing `503 mitigation_registry_inconsistent` contract with a `consistency_note`, produces no decision, and performs no writes.
- When the registry is consistent, the dry-run route remains advisory-only and writes no mitigation decisions or audit events.
- Enforcement status reports `registry_consistent` and `consistency_note` additively.
- Existing advisory-only semantics and no-enforcement default remain unchanged.

Why this is additive:

- No existing lifecycle public method signature was changed by the scoped hydration fix.
- The persistence helper `load_all_persisted_policies(db)` is read-only.
- The response-contract additions in `EnforcementStatusResponse` are nullable/additive.
- No auth/RBAC model, database schema, migration, or enforcement path was changed by the scoped implementation; the dry-run change is a read-only route-level guard using the existing 503 contract.

Why moving hydration elsewhere is not currently justified:

- The lifecycle registry owns private state (`_policies`, `_active_version`).
- Moving reconciliation to a non-frozen module would require exposing private lifecycle mutators or adding callback/orchestration hooks.
- That would introduce new contracts and regression risk without a demonstrated reduction in risk.
- The original accepted lifecycle-service version needed for a low-risk restore is unavailable.

## 6. Verification and residual gaps

### Previously reported evidence — not rerun in this documentation task

| Evidence source | Reported result |
|---|---|
| `APISENTRY_SEC02_MITIGATION_CONSISTENCY.md` | SEC-02 targeted tests: **2 passed** |
| `APISENTRY_DATABASE_PERSISTENCE_REPORT.md` | Disposable PostgreSQL lifecycle persistence tests: **12 passed** |
| `APISENTRY_DATABASE_PERSISTENCE_REPORT.md` | JWT revocation tests: **8 passed, 1 warning** |
| `APISENTRY_DATABASE_PERSISTENCE_REPORT.md` | Safe backend suite: **1,399 passed, 0 failed, 27 warnings**, excluding `backend/tests/test_mitigation_policy_lifecycle_persistence.py`, which was run separately against disposable PostgreSQL |

Historical reports also record earlier counts such as 56 targeted mitigation tests and 1,382 safe backend tests. Those are earlier snapshots and are not substituted for the later reported evidence above. The final scoped implementation evidence in the next subsection supersedes these historical counts for the completed SEC-02 scope; the historical reports themselves remain unchanged.

### Final scoped implementation evidence — reported, not rerun in this documentation reconciliation

A focused regression-test task first added `backend/tests/test_sec02_hydration_regressions.py` and reported 17 and 19 passed with earlier `-q` runs. A later scoped implementation expanded that file to 20 focused cases and reran verification. The exact commands and final reported results below were executed from the `backend/` working directory using the existing project `.venv` interpreter. They were **not rerun** during this documentation reconciliation.

| Command | Final reported result |
|---|---|
| `& "..\.venv\Scripts\python.exe" -m pytest tests/test_sec02_hydration_regressions.py -v` | **20 passed, 1 warning in 1.36s** |
| `& "..\.venv\Scripts\python.exe" -m pytest tests/test_sec02_mitigation_consistency.py tests/test_sec02_hydration_regressions.py -v` | **22 passed, 1 warning in 0.91s** |
| `& "..\.venv\Scripts\python.exe" -m pytest tests/test_mitigation_admin_api.py tests/test_mitigation_demo_enforcement.py tests/test_mitigation_decision_audit_models.py -v` | **96 passed, 1 warning in 9.02s** |
| `& "..\.venv\Scripts\python.exe" -m pytest tests -v --ignore=tests/test_mitigation_policy_lifecycle_persistence.py` | **1,419 passed, 27 warnings in 84.15s** |
| `& "..\.venv\Scripts\python.exe" -m pytest tests/test_mitigation_policy_lifecycle_persistence.py -v` | **12 passed, 0 warnings in 4.02s; exit code 0** |

The earlier `-q` snapshots remain historical snapshots; the table above records the completed scoped implementation state.

### Updated gap status — all five COVERED

| Previously documented gap | Updated status | Relevant tests in `backend/tests/test_sec02_hydration_regressions.py` |
|---|---|---|
| Conflicting persisted versus in-memory active versions | **COVERED** | `test_hydration_conflicting_active_versions_does_not_override_either_state`; `test_hydration_adopts_persisted_active_record_as_active`; `test_conflicting_active_versions_routes_fail_closed_and_report_status`; `test_dry_run_fails_closed_when_active_versions_diverge` |
| Hydration DB-read failure | **COVERED** | `test_hydration_read_failure_reports_error_and_keeps_session_usable`; `test_hydration_read_failure_on_failed_transaction_allows_session_rollback`; `test_sensitive_routes_fail_closed_on_hydration_read_failure` |
| Missing-schema compatibility fallback | **COVERED** | `test_missing_persistence_schema_uses_compatibility_fallback`; `test_missing_persistence_schema_route_contract` |
| Repeated hydration idempotency | **COVERED** | `test_repeated_hydration_is_idempotent_and_non_destructive` |
| Hydration-triggered route 503 behaviour | **COVERED** | `test_conflicting_active_versions_routes_fail_closed_and_report_status`; `test_sensitive_routes_fail_closed_on_hydration_read_failure` (10 parametrized admin/demo routes); `test_dry_run_fails_closed_when_active_versions_diverge` |

Consistent-registry dry-run behaviour is separately covered by `test_dry_run_remains_advisory_when_registry_is_consistent`, which asserts an advisory-only response and no decision or audit-event writes.

Qualifications retained from the regression-test task and scoped implementation:

- Focused coverage does **not** establish every possible database failure mode.
- Missing-schema handling remains a **compatibility fallback**, not a durability or multi-worker consistency guarantee.
- On a caller-side failed transaction, the **caller must explicitly roll back**. Hydration does not automatically repair the transaction; the regression test asserts usability only after caller rollback.
- **No production code defect was exposed or fixed by the earlier regression-test task.** That statement applies only to that earlier task; the later scoped implementation did change production files to resolve the previously open persisted-ACTIVE divergence and to add the dry-run 503 hydration guard, as recorded in Section 8.

### Previously open persisted-ACTIVE item — RESOLVED by later scoped implementation

The earlier review item described hydration reconstructing the persisted-active policy record with `state=ACTIVE` while retaining a different in-memory active pointer. The later scoped implementation resolved this by deriving reconstructed record state from the authoritative active pointer: during divergence, the in-memory pointer and its ACTIVE record are preserved, the persisted pointer remains unchanged, and the persisted-only record is reconstructed non-ACTIVE with explicit `active_version_divergence` reporting. This item is no longer open for the scoped SEC-02 implementation; direct service-level `evaluate_policy()` calls remain unguarded by design, while production route entry points are guarded.

## 7. Preservation

- Batch 7 classifier artifacts remain unchanged; the recorded bundle hash remains `2d694c932b9779d4971fa418aa35ecdf60cc266fe909b2ea40aa5392c5ae92dc`.
- No lifecycle code refactor is authorized or performed by this disposition. The implementation summarized in Section 8 is prior scoped-task evidence, not work performed by this documentation reconciliation.
- No Python, TypeScript, JavaScript, SQL, migration, model file, test, configuration, environment, or generated artifact was modified by this documentation reconciliation.
- No database, service, container, or enforcement process was started, stopped, connected to, or modified by this documentation reconciliation.
- No secrets or environment-variable values were inspected or exposed.
- No Git staging, commit, reset, checkout, clean, stash, branch switch, merge, or rebase was performed.
- Git status before this documentation reconciliation: **171** entries.
- Git status after this documentation reconciliation: **171** entries; entry-set comparison shows no differences. This disposition file is untracked, so editing its content does not change the Git status text.
- The only file whose content changed during this reconciliation is `APISENTRY_SEC02_FREEZE_DEVIATION_DISPOSITION.md`.
- All pre-existing modified, untracked, and ignored user work was preserved.

## 8. Final scoped implementation and verification record

### Implementation files recorded from the scoped task

| File | SHA-256 | Recorded change summary |
|---|---|---|
| `backend/app/services/mitigation_policy_lifecycle_service.py` | `934a8c32fbf6c25c3742ec6f9765ac7936695ba9e2a1086c47c51d82faa3a6c8` | Authoritative active-record reconstruction; preservation of in-memory and persisted pointers during divergence; explicit divergence reporting; non-destructive hydration of missing policy records. |
| `backend/app/api/v1/routes/mitigation_dry_run.py` | `fb953fc0ef55ae3d9812de1385560a7d0f025697d910db36e78ac112afd9ac67` | Fresh read-only hydration using `get_db`; `503 mitigation_registry_inconsistent` fail-closed guard with consistency note; no writes; advisory-only dry-run behaviour retained for a consistent registry. |
| `backend/tests/test_sec02_hydration_regressions.py` | `de58414a0a872a37f77cca83593dbea1be7d9669f086ec437ddb30104d44868b` | 20 focused cases covering divergence reconstruction/adoption, pointer preservation, read failures, missing-schema fallback, idempotency, admin/demo 503 behaviour, dry-run 503 guard, and consistent-registry advisory-only behaviour. |
| `backend/tests/test_mitigation_policy_lifecycle_persistence.py` | `8ff8d112fd341f1e5f81b9584df2f8026d051feb5e22ec915894fbfa79f6e1e4` | Gate B PostgreSQL lifecycle persistence suite used for the verification recorded below. |

The hashes above were verified by the prior scoped implementation and persistence tasks. They are recorded as evidence only; this documentation reconciliation did not modify these files.

### Implementation behaviour recorded

- **Authoritative active-record reconstruction:** reconstructed policy records derive ACTIVE/non-ACTIVE state from the authoritative active pointer. When no in-memory pointer exists, the persisted active version may be adopted; during divergence, the persisted-only record is reconstructed non-ACTIVE so exactly one ACTIVE record agrees with the pointer.
- **Both pointers preserved during divergence:** the in-memory pointer and its ACTIVE record are retained, and the persisted pointer rows are left unchanged by read-only hydration.
- **Explicit divergence reporting:** conflicting pointers produce `active_version_divergence`; a persisted active version missing from the registry produces `persisted_active_missing_from_registry`; both surface through `hydration_report()` and route consistency metadata.
- **Dry-run 503 fail-closed guard:** the production dry-run route hydrates from a fresh read-only session and rejects with `503 mitigation_registry_inconsistent` when hydration is not OK, without creating decisions or audit events.
- **Consistent-registry advisory-only behaviour:** when hydration is OK, dry-run remains advisory-only, returns a decision reference, and writes no mitigation decisions or audit events.

### Verification evidence recorded

Exact commands and final reported results are recorded in Section 6. Summary:

- Hydration regression tests: **20 passed, 1 warning in 1.36s**.
- Combined SEC-02 tests: **22 passed, 1 warning in 0.91s**.
- Mitigation admin/demo/audit tests: **96 passed, 1 warning in 9.02s**.
- Safe backend suite: **1,419 passed, 27 warnings in 84.15s**.
- Disposable PostgreSQL lifecycle persistence suite: **12 passed, 0 warnings in 4.02s; exit code 0**.

A focused early `-q` dry-run attempt that timed out was not used as evidence; the successful `-v` runs above are the recorded results.

### Disposable PostgreSQL verification scope

- PostgreSQL version: **17.10**.
- Listener: **`127.0.0.1:55444`**.
- System identifier: **`7711796626029006216`**, agreeing from `pg_controldata` and `pg_control_system()`.
- Cluster: freshly initialized, task-owned disposable data directory at `<LOCAL_TEMP>\opencode\sec02_gateb_20261124_231924_066eea6f\data`.
- Identity verification: listener address/port, postmaster PID, process command line, `-D` data directory, `postmaster.pid`, and both system-identifier sources agreed before database creation and before test execution.
- Cleanup: the verified disposable cluster was stopped cleanly after testing; the process, children, and listener were gone, and the data directory plus evidence were preserved.
- Protected database preservation: PostgreSQL port `5432` remained owned by the existing PostgreSQL process and was untouched; ports `55446` and `55447` were unused before and after. No existing or protected database was contacted or modified.
- Schema preparation qualification: the disposable database was initialized from **project ORM metadata** (`Base.metadata.create_all`). **No Alembic migration command was run.** This run does **not** validate the Alembic migration path and must not be described as migration-path validation.
- No production traffic or enforcement was exercised.

### Final status and remaining limitations

- SEC-02 hydration regression coverage is **completed**.
- Gate B PostgreSQL persistence verification is **completed** within the disposable database scope described above.
- There is **no outstanding blocker** for the scoped SEC-02 implementation and persistence verification.
- **Alembic migration-path validation remains separately unverified.**
- The missing-schema compatibility fallback is **not** a durable or multi-worker consistency guarantee.
- Direct service-level `evaluate_policy()` calls remain **unguarded by design**; production route entry points are guarded.
- This record is **not** production approval and does not authorize enforcement activation.

## 9. Final disposition

**ACCEPT DEVIATION.**

`backend/app/services/mitigation_policy_lifecycle_service.py` is not established as part of the Batch 7 frozen artifact set. The SEC-02 hydration change is accepted as a separate, additive lifecycle change.

The five previously documented verification gaps are now covered by focused regression tests as recorded in Section 6. The previously open persisted ACTIVE-record divergence item was resolved by the later scoped implementation recorded in Section 8, with the remaining limitations listed there. This decision must not be used to describe the platform as production-ready or approved for production enforcement.
