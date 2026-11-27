# APISENTRY SEC-02 — Mitigation Lifecycle Consistency Hardening
> **Historical snapshot:** This report records evidence from its original task/date and is preserved for context. It is not a statement of current repository state. Current safe backend suite evidence is **1494 passed, 29 warnings** (Task 12A), excluding the separately gated PostgreSQL persistence suite.

## Status
**Implemented (CONDITIONAL)** — read-only hydration/reconciliation added; full durability/multi-worker consistency depends on approved persistent deployment.

## Problem
In-memory lifecycle registry could diverge from persisted Gate B state after restart/worker isolation. `enforcement/status` could report in-memory state without reconciliation.

## Fix Applied
- `backend/app/services/mitigation_policy_lifecycle_service.py`
  - Added `hydrate_from_persistence(db)` (read-only, best-effort).
  - Loads persisted policies via `load_all_persisted_policies`; loads persisted active version.
  - **Never overwrites existing in-memory policy records**. Only fills missing registry entries and missing active pointer.
  - If persisted active conflicts with in-memory active, reports divergence and keeps in-memory state (fail-closed against silent override).
  - Reconstructed records are lossy by Gate B mapping contract; marked in hydration report. They are sufficient for status/restart continuity, not full Gate A history.
  - Added `hydration_report()` for observability.
- `backend/app/services/mitigation_policy_lifecycle_persistence_service.py`
  - Added `load_all_persisted_policies(db)` read-only helper.
- `backend/app/api/v1/routes/mitigation_decision_audit.py`
  - `/security/mitigation/enforcement/status` hydrates before reporting; additively returns `registry_consistent` and `consistency_note`.
- `backend/app/api/v1/routes/mitigation_policy_admin.py`
  - Admin lifecycle read/write endpoints hydrate best-effort before operating (read-only reconciliation).
- `backend/app/api/v1/routes/mitigation_demo.py`
  - Demo enable/run hydrate lifecycle from DB before evaluating.
- `backend/app/schemas/mitigation_admin.py`
  - `EnforcementStatusResponse` extended additively with `registry_consistent`, `consistency_note` (nullable).

## Safety / Contract Preservation
- Advisory-only defaults preserved. No real enforcement added.
- No authz/demo safety/API contract breaks; schema changes additive.
- Hydration is read-only; no writes during reconciliation.

## Tests
- Added `backend/tests/test_sec02_mitigation_consistency.py` — **2 passed**.
  - hydration restores active policy after restart (fresh in-memory service)
  - hydration reports divergence without overriding memory
- Existing mitigation tests passed in targeted/full safe runs (admin, decision audit models, demo, audit integration).

## Residual Risk / Blockers
- In-memory lifecycle remains process-local; **multi-worker consistency** still requires approved shared persistence/infrastructure strategy.
- Reconstructed records are lossy (approval metadata/state transitions may be incomplete) per existing Gate B contract.
- Full PostgreSQL durability/parity validation blocked by no-touch constraint on existing PG instances.
