# APISENTRY Final Regression Report
> **Historical snapshot:** This report records evidence from its original task/date and is preserved for context. It is not a statement of current repository state. Current safe backend suite evidence is **1494 passed, 29 warnings** (Task 12A), excluding the separately gated PostgreSQL persistence suite.

## Scope
Hardening pass after SEC-01/SEC-02/SEC-05 fixes, on dirty worktree. No staging/commits/pushes. No existing PostgreSQL DBs touched. Isolated demo DB only.

## Backend
| Suite | Command | Result |
|---|---|---|
| SEC-01 revocation tests | `pytest backend/tests/test_sec01_jwt_revocation.py -q` | **5 passed, 1 warning** |
| SEC-02 consistency tests | `pytest backend/tests/test_sec02_mitigation_consistency.py ...` (targeted set) | **56 passed** (targeted mitigation set including sec02) |
| SEC-05 demo tests | `pytest backend/tests/test_mitigation_demo_enforcement.py -q` | **21 passed, 1 warning** |
| Decision audit models | `pytest backend/tests/test_mitigation_decision_audit_models.py -q` | **67 passed** |
| Previously-failing 6 | `pytest backend/tests/test_alembic_baseline.py backend/tests/test_mitigation_models.py::test_fresh_sqlite_upgrade_to_head_creates_expected_schema backend/tests/test_mitigation_policy_lifecycle.py::test_gate_a_has_no_persistence_or_enforcement_surface -q` | **10 passed** |
| Full safe backend suite | `pytest backend/tests -q --ignore=backend/tests/test_mitigation_policy_lifecycle_persistence.py` | **1382 passed, 0 failed, 27 warnings** (65.81s) |

## Frontend
| Check | Command | Result |
|---|---|---|
| Tests | `node --test frontend/tests/*.test.js` | **25 passed, 0 failed** |
| Lint | `npm run lint` | **PASS** (oxlint, 0 errors reported) |
| Build | `npm run build` | **PASS** (chunk-size warning only) |

## Browser E2E (Isolated Demo)
- Role login/nav visibility: **PASS** for Viewer/Analyst/Admin disposable accounts.
- Console errors: **0** in sampled flows.
- User Administration / Mitigation Control: **UI loading issue observed** despite 200 APIs.
- Sign out UI: **reliability issue observed**.
- Exhaustive module/form/error/responsive coverage: **NOT COMPLETE**.

## Batch 7 Hash — corrected 2026-11-24
- **Historical entry (superseded)**: This section previously recorded lifecycle-service SHA-256 `5b9b9adfc2e95a74012b56515fba70e8b3df0da5073340a92d074b576f822770` and expected frozen hash `2d694c932b9779d4971fa418aa35ecdf60cc266fe909b2ea40aa5392c5ae92dc`.
- **Correction**: `2d694c...` is the frozen payload classifier bundle hash, not a lifecycle-service hash. `5b9b9adf...` is stale/unverified. Current independently computed lifecycle-service SHA-256: `660772a7930c9808dd2ba7380a8d085b5e7bddfa52213665f08903004ca3eb15`.
- **Disposition**: **ACCEPT DEVIATION** — the lifecycle service is not established as a Batch 7 frozen artifact; SEC-02 hydration is a separate additive lifecycle change. See `APISENTRY_SEC02_FREEZE_DEVIATION_DISPOSITION.md`. Historical test results above are preserved unchanged.

## Known Excluded / Blocked
- `backend/tests/test_mitigation_policy_lifecycle_persistence.py` — PG-gated; excluded under no-touch DB constraints.
- No PostgreSQL migration/application for `0004_revoked_tokens.py`.
