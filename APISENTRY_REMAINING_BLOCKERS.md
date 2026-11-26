# APISENTRY Remaining Blockers
> **Historical snapshot:** This report records evidence from its original task/date and is preserved for context. It is not a statement of current repository state. Current safe backend suite evidence is **1494 passed, 29 warnings** (Task 12A), excluding the separately gated PostgreSQL persistence suite.

## 1. Batch 7 Freeze Deviation (DISPOSITIONED — HISTORICAL ENTRY)
- **Historical assertion (superseded)**: This entry previously treated `2d694c932b9779d4971fa418aa35ecdf60cc266fe909b2ea40aa5392c5ae92dc` as the expected lifecycle-service hash and `5b9b9adfc2e95a74012b56515fba70e8b3df0da5073340a92d074b576f822770` as the actual hash.
- **Correction (2026-11-24)**: `2d694c...` is the SHA-256 of the frozen payload classifier bundle `research/models/http_payload_classifier/v1/model_bundle.joblib`, not a lifecycle-service hash. The `5b9b9adf...` lifecycle value is stale/unverified. Current independently computed lifecycle-service SHA-256: `660772a7930c9808dd2ba7380a8d085b5e7bddfa52213665f08903004ca3eb15`. The original accepted lifecycle-service source/hash could not be recovered from available workspace evidence.
- **Disposition**: **ACCEPT DEVIATION**. Available evidence does not establish `backend/app/services/mitigation_policy_lifecycle_service.py` as a Batch 7 frozen artifact; the SEC-02 hydration change is accepted as a separate, additive lifecycle change. See `APISENTRY_SEC02_FREEZE_DEVIATION_DISPOSITION.md`.
- **Residual**: SEC-02 test gaps remain visible residual verification work; this disposition is not production approval.

## 2. Durable PostgreSQL JWT Revocation (HIGH, requires approval)
- `0004_revoked_tokens.py` migration created but **not applied** to any existing PostgreSQL DB.
- True multi-worker/restart-consistent revocation across production workers requires approved shared DB migration/infrastructure.
- No 5432/55446/55447 or existing DBs were touched.

## 3. PostgreSQL-gated Persistence Test (MEDIUM, environment/approval)
- `backend/tests/test_mitigation_policy_lifecycle_persistence.py` excluded; requires approved PG environment.

## 4. User Administration / Mitigation Control UI Loading State (MEDIUM)
- Admin browser E2E observed "Loading users…" and "Loading mitigation administration…" despite backend APIs returning 200. Console errors 0. Likely frontend state/render/response handling issue; not fully diagnosed/fixed in this pass.
- Impacts role-based admin usability.

## 5. UI Sign-out Button Reliability (LOW/MEDIUM)
- Sign out button click was unreliable in browser automation; programmatic token clear+reload worked. May be UI clickability/overlay/focus issue.

## 6. Exhaustive Browser E2E Coverage Incomplete (MEDIUM)
- Not fully covered: all module flows (Threat Analysis, BOLA, Brute Force, Rate Anomaly, Token Classification, Traffic Trend, Behavioral Risk, Bot Mitigation), invalid forms/API error UI states, loading/empty states across all roles, responsive desktop/mobile, all unauthorized action attempts via UI, demo panel full workflow.
- Evidence is partial; matrix marks uncovered areas.

## 7. Verifier/Schema Expectations Updated for 0004 (LOW, process)
- `verify_baseline.py`, alembic/model tests updated to recognize `0004_revoked_tokens`. These are correct for the new additive migration but mean baseline verification now expects the new revision in fresh-upgrade contexts. Existing PG DBs not migrated will differ until approved.
