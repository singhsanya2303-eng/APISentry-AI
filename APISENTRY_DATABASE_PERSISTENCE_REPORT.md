# APISENTRY Database & Persistence Verification Report
> **Historical snapshot:** This report records evidence from its original task/date and is preserved for context. It is not a statement of current repository state. Current safe backend suite evidence is **1494 passed, 29 warnings** (Task 12A), excluding the separately gated PostgreSQL persistence suite.

**Date:** 2026-11-24  
**Scope:** Isolated disposable PostgreSQL migration 0004 and persistence verification only. No production/existing DB touched. No unrelated redesign.

## TASK RESULT
**CONDITIONAL PASS**

Core acceptance criteria verified on the confirmed disposable cluster: identity, migration 0004 apply/downgrade/reapply, schema/ORM consistency, PostgreSQL-backed JWT revocation persistence, restart simulation, separate worker/process revocation, fail-closed DB lookup failure, missing-schema safe fallback, mitigation PG-gated persistence tests, backup/restore with representative revocation records.  
Not fully PASS because: full distributed revocation across all production deployment modes is not a new capability added here (existing implementation is DB-backed when schema present; this was verified); backup/restore was validated for schema/revocation records and migration revision but not with live mitigation policy/decision rows in the restored dataset (gateb test cleans up; it passed separately). No protected resources touched.

## ENVIRONMENT IDENTITY
- **Disposable data directory:** `<LOCAL_TEMP>\opencode\apisentry_pg_0004_verify_20261124_20261124_102520\data`
- **Port:** `55448` (listening 127.0.0.1 only during run; no protected ports used)
- **PostgreSQL version:** `17.10` (`SHOW server_version`, psql/pg_controldata)
- **Cluster identity evidence:**
  - `postmaster.pid` PID `17472`, port `55448`, data dir matches disposable path.
  - `pg_controldata`: Database system identifier `7711597199840553416`, cluster state `in production` during checks, catalog 202406281, control version 1700.
  - `pg_control_system()` system_identifier `7711597199840553416`.
  - Listener process command line: `"C:/Program Files/PostgreSQL/17/bin/postgres.exe" -D "<LOCAL_TEMP>/opencode/apisentry_pg_0004_verify_20261124_20261124_102520/data"`.
  - `pg_isready -h 127.0.0.1 -p 55448 -U postgres` => accepting connections.
  - Protected port 5432 listener owned by PID 7560 remained untouched; ports 55446/55447 not used.
  - Identity verified before each DB-changing command in this session (PID/listener/command-line/datadir/port checks).
- **Initial migration revision:** none (fresh disposable DB `apisentry_verify`, no `alembic_version` table before migration).
- **Final migration revision:** `0004_revoked_tokens` (head) on verification DBs after downgrade/reapply cycle; restored DB also `0004_revoked_tokens`.

## MIGRATION
- **Migration 0004 results:** PASS.
  - Applied `0001_baseline_existing_schema` -> `0002_mitigation_policy_models` -> `0003_mitigation_decision_audit` on disposable DB. Then applied `0003 -> 0004_revoked_tokens` successfully.
  - Repeat `alembic upgrade 0004_revoked_tokens` on head: no-op (no migration run, exit 0, current remains head).
  - Downgrade `0004 -> 0003` succeeded; `revoked_tokens` table removed; version `0003_mitigation_decision_audit`. Upgrade back to `0004` succeeded; version/table restored.
- **Schema verification:**
  - `revoked_tokens` columns: `id integer NOT NULL`, `token_hash varchar(64) NOT NULL`, `expires_at timestamptz NOT NULL`, `revoked_at timestamptz NOT NULL`.
  - Indexes: `ix_revoked_tokens_expires_at` btree(expires_at), `ix_revoked_tokens_token_hash` unique btree(token_hash), `revoked_tokens_pkey` unique btree(id).
  - PK constraint present. ORM metadata agrees (SQLAlchemy inspect/model columns matched).
- **Failures:** None.

## JWT REVOCATION
- **Persistence:** PASS. Revoked token hash persisted in PostgreSQL `revoked_tokens` (row count/fields verified).
- **Restart test:** PASS (simulation). Cleared in-memory revocation maps; token remained rejected via DB lookup on fresh session/process context.
- **Separate-worker test:** PASS. Process A created token; Process B accepted before revocation; Process C revoked; Process D (separate process, fresh memory) rejected with `Authentication token has been revoked`.
- **Failure handling:** PASS. DB lookup failure (unavailable DB) returned fail-closed (`is_token_revoked` True, logged "failing closed"). Missing revocation schema followed documented safe fallback: not revoked before revocation, in-memory revocation effective after revoke attempt, warning logged; no durable/multi-worker guarantee in missing-schema mode (as documented).
- **Expired/invalid/role:** PASS (targeted). Expired token rejected as expired; malformed token rejected; role claim preserved through decode.
- **Disabled-account check:** Existing `require_jwt_auth`/user checks remain in code (not modified); covered by existing auth tests in safe suite.
- **Limitations:** Missing 0004 schema falls back to in-memory (compatibility), not durable/multi-worker. Distributed guarantee requires shared persistent store deployed (0004) on all workers; verified on disposable PG with separate processes.

## MITIGATION PERSISTENCE
- **Policy results:** PASS by PG-gated test suite. `backend/tests/test_mitigation_policy_lifecycle_persistence.py` - **12 passed** on disposable PG (`apisentry_gateb_verify`, port 55448, env vars set).
- **Decision/audit results:** Covered by PG-gated lifecycle persistence tests and existing safe-suite tests; no failures observed.
- **Transaction and idempotency results:** Covered by PG-gated persistence tests (12 passed). No real enforcement activated.
- **Advisory-only/kill-switch semantics:** Unchanged; no enforcement activated.

## BACKUP & RESTORE
- **Backup verification:** PASS.
  - `apisentry_verify.dump`: 45,612 bytes, SHA256 `1DEC54ED355B20875A9C943D3B2C070ECB03E58297A5335FA2EE71C759BE4640`.
  - `apisentry_revocation_verify.dump`: SHA256 `A9F208DF1CC15D6217312FB54857A2C144B7D4A65953EB75619479031F24B72A`.
- **Restore target:** Separate disposable DBs on same confirmed disposable cluster: `apisentry_restore_target` (from verify dump), `apisentry_restore_revocation` (from revocation dump). No restore over source/original.
- **Restored data checks:** PASS.
  - Both restored DBs: `alembic_version = 0004_revoked_tokens`.
  - `apisentry_restore_target` table counts matched source (all zero in that snapshot).
  - `apisentry_restore_revocation` `revoked_tokens` count = 5 (matched source); representative rows present with hashes/expiry/revoked_at.

## TEST RESULTS
- **Focused PostgreSQL persistence/migration tests:**
  - `.\.venv\Scripts\python.exe -m pytest backend/tests/test_mitigation_policy_lifecycle_persistence.py -q` (env: `DATABASE_URL=postgresql://postgres@127.0.0.1:55448/apisentry_gateb_verify`, `MW4B_PG_HOST=127.0.0.1`, `MW4B_PG_PORT=55448`, `MW4B_PG_DATABASE=apisentry_gateb_verify`) => **12 passed in 5.25s**, EXIT 0. Used confirmed disposable cluster.
- **JWT revocation tests:**
  - `.\.venv\Scripts\python.exe -m pytest backend/tests/test_sec01_jwt_revocation.py -q` => **8 passed, 1 warning in 1.40s**, EXIT 0 (includes added rollback-regression test).
  - Ad-hoc disposable-PG verification scripts (evidence dir): `verify_jwt_revocation_pg.py` => all checks true (`valid_before_revocation`, `rejected_after_revocation`, `persisted_in_postgres`, `survives_restart_sim`, `db_lookup_failure_fails_closed`, `missing_schema_safe_fallback_not_revoked_before`, `missing_schema_safe_fallback_revoked_after_in_memory`, `expired_rejected`, `invalid_rejected`, `role_claim_preserved`), EXIT 0. `verify_jwt_multiprocess.py` => separate process create/check/revoke/check-after all passed.
- **Relevant backend regression suite:**
  - `.\.venv\Scripts\python.exe -m pytest backend/tests -q --ignore=backend/tests/test_mitigation_policy_lifecycle_persistence.py` (with env DATABASE_URL/MW4B vars cleared, `ENVIRONMENT=test`, `AUTO_CREATE_SCHEMA=false`) => **1399 passed, 27 warnings, 0 failed in 134.99s (0:02:14)**, EXIT 0.
- **PostgreSQL-gated test evidence:** `test_mitigation_policy_lifecycle_persistence.py` actually executed against disposable PG 55448/`apisentry_gateb_verify` (12 passed). Ad-hoc JWT PG scripts executed against `apisentry_revocation_verify` on same disposable cluster.
- **Warnings/failures:** No failures. Warnings are pre-existing deprecations (Starlette/TestClient httpx2, 422 constant, sklearn convergence, existing route warnings).

## IMPLEMENTATION
- **Changed files and reasons:**
  - `backend/app/core/security.py` - **small safe fix**: added `db.rollback()` in `is_token_revoked` exception handler before fail-closed/missing-store fallback. Defect found during PG verification: missing-schema/DB-error lookup left SQLAlchemy session aborted, causing subsequent operations on same session to fail with `InFailedSqlTransaction`. Fix preserves existing behavior and fail-closed semantics.
  - `backend/tests/test_sec01_jwt_revocation.py` - added regression test `test_revocation_lookup_error_rolls_back_session` for the above defect.
- **Reused components:** Existing Alembic migrations 0001-0004, `RevokedToken` model, `security.py` revocation logic, mitigation lifecycle persistence service/tests, pg_dump/pg_restore/psql, existing venv.
- **Tests added:** `test_revocation_lookup_error_rolls_back_session` in `backend/tests/test_sec01_jwt_revocation.py`.
- **Not implemented:** No distributed revocation redesign, no Redis/shared store, no Batch 7 lifecycle hash refactor, no unrelated frontend/research/docs changes.

## PRESERVATION
- **Git status before/after:** Before DB mission (post-Phase-0 audit): 168 lines in `git status --short`. After: 168 lines. `Compare-Object` of saved before/after status files showed no differences. (Phase 0 baseline identified 167 dirty entries; the 168th is the Phase 0 baseline report created during audit - preserved.)
- **All 167 Phase 0 dirty entries preserved:** Yes - no entry removed/reverted/staged/committed.
- **Protected databases and ports untouched:** Yes. Existing PG on 5432 (PID 7560) untouched. Ports 55446/55447 untouched. No connection to existing APISentry PostgreSQL. Only disposable cluster `.../apisentry_pg_0004_verify_20261124_20261124_102520` on 127.0.0.1:55448 used.
- **Existing SQLite demo preserved:** Yes - `<LOCAL_TEMP>\opencode\apisentry_local_demo_20261123\apisentry_demo.sqlite3` not touched.
- **Batch 7 frozen artifacts untouched:** Yes - `research/models/http_payload_classifier/v1/model_bundle.joblib` and `metadata.json` not modified.
- **No enforcement activated:** Yes. No demo enable/real enforcement/network enforcement.

## REMAINING BLOCKERS
- **Distributed production revocation strategy beyond DB-backed single-schema deployment:** DB-backed revocation is verified across separate processes on same disposable PG; production multi-worker deployments still require all workers to share the same migrated PG and correct config. No Redis/shared-store fallback implemented (separate approval/design).
- **Backup/restore evidence for mitigation policy/decision rows in same restored snapshot:** PG-gated mitigation persistence tests passed, but backup/restore verification used schema/revocation representative rows; a dedicated mitigation-populated backup/restore snapshot can be added if required.
- **Batch 7 freeze-deviation disposition:** `mitigation_policy_lifecycle_service.py` hash deviation noted in Phase 0 remains an explicit decision item; not modified here.

## NEXT ACTION
**Resolve the Batch 7 freeze-deviation disposition for `backend/app/services/mitigation_policy_lifecycle_service.py`** (explicitly accept audited SEC-02 deviation with evidence, or refactor hydration into a non-frozen module and re-verify), before any further security-hardening or production-readiness claims that depend on Batch 7 freeze integrity.