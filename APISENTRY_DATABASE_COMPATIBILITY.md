# APISENTRY Database Compatibility
> **Historical snapshot:** This report records evidence from its original task/date and is preserved for context. It is not a statement of current repository state. Current safe backend suite evidence is **1494 passed, 29 warnings** (Task 12A), excluding the separately gated PostgreSQL persistence suite.

## Current demo posture
- **Verified on:** isolated disposable SQLite file `<LOCAL_TEMP>\opencode\apisentry_local_demo_20261123\apisentry_demo.sqlite3`.
- **Existing PostgreSQL:** preserved, untouched. Ports 5432/55446/55447 not touched. No migrations/writes against existing DBs.

## SQLite compatibility (observed)
| Area | Status | Notes |
|---|---|---|
| Engine/session | PASS | `backend/app/db/session.py` adds `check_same_thread=False` and disables `pool_pre_ping` for sqlite. |
| Schema creation | PASS (demo) | `AUTO_CREATE_SCHEMA=true` + `init_db()` created tables on fresh SQLite. |
| User/auth persistence | PASS | Register/login/me/logout/RBAC worked. |
| Bot/runtime analysis | PASS | Bot analyze and mitigation runtime-analyze returned 200. |
| Mitigation policy lifecycle | PASS (smoke) | Create/validate/activate/dry-run worked. |
| Decision/audit persistence | PARTIAL | Endpoints responsive; deep integrity/concurrency/restart not fully tested. |
| Gate E demo | PASS | Isolated temp SQLite by design; enable/run/kill-switch/disable worked. |
| Payload classifier | PASS | Metadata/predict worked; artifact read-only/frozen. |
| Alembic on SQLite | PARTIAL | Not fully executed this pass. |
| PostgreSQL parity | BLOCKED | Not validated; PG-specific behavior may differ. |

## Risks / limitations
- SQLite is not a verified substitute for approved PostgreSQL production behavior.
- Concurrency, locking, JSON/query semantics, migrations, and PG-specific constraints may differ.
- In-memory lifecycle registry can diverge from persisted state after restart.

## PostgreSQL validation plan (requires separate explicit approval)
1. Obtain approval for an isolated PostgreSQL target (not 5432/55446/55447, not existing prod DB).
2. Create disposable DB/schema on approved isolated instance; document backup/restore before writes.
3. Run Alembic upgrade on approved isolated DB only.
4. Run backend against approved isolated DB; verify auth, RBAC, mitigation lifecycle, audit/decision persistence, demo constraints.
5. Run PG-gated tests on approved target only.
6. Record evidence and clean up only with approval.