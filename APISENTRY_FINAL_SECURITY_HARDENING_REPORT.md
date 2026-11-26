# APISENTRY Final Security Hardening Report
> **Historical snapshot:** This report records evidence from its original task/date and is preserved for context. It is not a statement of current repository state. Current safe backend suite evidence is **1494 passed, 29 warnings** (Task 12A), excluding the separately gated PostgreSQL persistence suite.

## Verdict
**CONDITIONAL HARDENING PASS**

Core SEC-01/SEC-02/SEC-05 code fixes are implemented with regression tests and the full safe backend suite passes. However, an earlier Batch 7 deviation claim (lifecycle service modified) is superseded by `APISENTRY_SEC02_FREEZE_DEVIATION_DISPOSITION.md`; durable PostgreSQL revocation/multi-worker consistency remains approval-blocked, and browser E2E uncovered UI loading/sign-out issues with incomplete exhaustive coverage.

## Scope & Constraints Respected
- Dirty/untracked/staged/ignored worktree preserved; **no staging, commits, pushes, reset, checkout, or clean** performed.
- No dependency install/upgrade. No `.env`/secrets/passwords/API keys/JWT/connection strings read or exposed.
- No ports `5432`, `55446`, `55447` touched; no existing PostgreSQL DBs started/stopped/connected/migrated; no backups/evidence modified.
- Isolated demo used only temp SQLite: `<LOCAL_TEMP>\opencode\apisentry_local_demo_20261123\apisentry_demo.sqlite3`.
- Demo remained loopback-only, synthetic-only, bounded, default OFF. No real mitigation enforcement/production deploy/external or attack traffic.

## SEC-01 — JWT Revocation
- **Status**: Implemented (conditional). See `APISENTRY_SEC01_JWT_REVOCATION.md`.
- Hash-based revocation with in-memory expiry cleanup and optional DB-backed persistence/fallback (`revoked_tokens`).
- `decode_access_token` enforces revocation after signature/expiry; `require_jwt_auth`/logout pass DB.
- Additive migration `0004_revoked_tokens.py` created **file-only**; not applied to existing PG.
- Regression: `backend/tests/test_sec01_jwt_revocation.py` — 5 passed.

## SEC-02 — Mitigation Lifecycle Consistency
- **Status**: Implemented (conditional). See `APISENTRY_SEC02_MITIGATION_CONSISTENCY.md`.
- Read-only `hydrate_from_persistence` reconciliation added to lifecycle service; never overwrites existing in-memory records; reports divergence fail-closed.
- Admin/decision-audit/demo routes hydrate best-effort. `EnforcementStatusResponse` additively includes `registry_consistent`, `consistency_note`.
- Regression: `backend/tests/test_sec02_mitigation_consistency.py` — 2 passed.

## SEC-05 — Demo Status Semantics
- **Status**: Implemented. See `APISENTRY_SEC05_DEMO_STATUS.md`.
- Explicit `expired`, `status_reason`, `real_enforcement` semantics; disable returns clean advisory/off state; kill-switch/expired states explicit.
- Frontend `MitigationDemoPanel.jsx` displays explicit status/reason/badges.
- Regression: `backend/tests/test_mitigation_demo_enforcement.py` — 21 passed.

## Verification Evidence
- Full safe backend suite: `pytest backend/tests -q --ignore=backend/tests/test_mitigation_policy_lifecycle_persistence.py` => **1382 passed, 0 failed, 27 warnings**.
- Frontend tests: `node --test frontend/tests/*.test.js` => **25 passed**.
- Frontend lint: `npm run lint` => **PASS**.
- Frontend build: `npm run build` => **PASS** (chunk-size warning only).
- Browser E2E: role nav/RBAC visibility verified for Viewer/Analyst/Admin; console errors 0 in sampled flows; UI loading/sign-out issues observed. See `APISENTRY_ROLE_BASED_E2E_MATRIX.md`.

## Batch 7 Freeze — corrected 2026-11-24
- **Historical entry (superseded)**: This section previously recorded lifecycle-service SHA-256 `5b9b9adfc2e95a74012b56515fba70e8b3df0da5073340a92d074b576f822770` and expected frozen hash `2d694c932b9779d4971fa418aa35ecdf60cc266fe909b2ea40aa5392c5ae92dc`.
- **Correction**: `2d694c...` is the frozen payload classifier bundle hash, not a lifecycle-service hash. `5b9b9adf...` is stale/unverified. Current independently computed lifecycle-service SHA-256: `660772a7930c9808dd2ba7380a8d085b5e7bddfa52213665f08903004ca3eb15`.
- **Disposition**: **ACCEPT DEVIATION** — the lifecycle service is not established as a Batch 7 frozen artifact; SEC-02 hydration is a separate additive lifecycle change. See `APISENTRY_SEC02_FREEZE_DEVIATION_DISPOSITION.md`. Historical SEC-01/SEC-02/SEC-05 results above are preserved unchanged.

## Blocking / Residual Issues
See `APISENTRY_REMAINING_BLOCKERS.md`. Key blockers: Batch 7 hash deviation; PG migration approval for durable revocation; PG-gated persistence test excluded; User Admin/Mitigation Control UI stuck loading; UI sign-out reliability; incomplete exhaustive browser E2E.

## Files Added/Modified (high-signal)
- SEC-01: `backend/app/core/security.py`, `backend/app/api/v1/routes/auth.py`, `backend/app/models/revoked_token.py`, `backend/app/models/__init__.py`, `backend/app/db/init_db.py`, `backend/alembic/versions/0004_revoked_tokens.py`, `backend/tests/test_sec01_jwt_revocation.py`
- SEC-02: `backend/app/services/mitigation_policy_lifecycle_service.py`, `backend/app/services/mitigation_policy_lifecycle_persistence_service.py`, `backend/app/api/v1/routes/mitigation_decision_audit.py`, `backend/app/api/v1/routes/mitigation_policy_admin.py`, `backend/app/api/v1/routes/mitigation_demo.py`, `backend/app/schemas/mitigation_admin.py`, `backend/tests/test_sec02_mitigation_consistency.py`
- SEC-05: `backend/app/services/mitigation_demo_service.py`, `backend/app/schemas/mitigation_demo.py`, `frontend/src/components/MitigationDemoPanel.jsx`, `backend/tests/test_mitigation_demo_enforcement.py`
- Test/schema alignment for 0004: `backend/app/scripts/verify_baseline.py`, `backend/tests/test_alembic_baseline.py`, `backend/tests/test_mitigation_decision_audit_models.py`, `backend/tests/test_mitigation_models.py`, `backend/tests/test_verify_baseline.py`, `backend/tests/test_verify_exact_structure.py`
- Reports: `APISENTRY_FINAL_SECURITY_HARDENING_REPORT.md`, `APISENTRY_SEC01_JWT_REVOCATION.md`, `APISENTRY_SEC02_MITIGATION_CONSISTENCY.md`, `APISENTRY_SEC05_DEMO_STATUS.md`, `APISENTRY_ROLE_BASED_E2E_MATRIX.md`, `APISENTRY_FINAL_REGRESSION_REPORT.md`, `APISENTRY_REMAINING_BLOCKERS.md`