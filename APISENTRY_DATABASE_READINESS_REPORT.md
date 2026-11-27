# APISENTRY Database Readiness Report
> **Historical snapshot:** This report records evidence from its original task/date and is preserved for context. It is not a statement of current repository state. Current safe backend suite evidence is **1494 passed, 29 warnings** (Task 12A), excluding the separately gated PostgreSQL persistence suite.

## Verdict
- **Local demo DB (isolated SQLite): PASS (scoped)**
- **PostgreSQL production readiness: NO-GO**

## Scope / Constraints
- No PostgreSQL connections, no ports 5432/55446/55447 touched.
- No Alembic migrations applied to any existing PostgreSQL database.
- No database data deleted/overwritten/reset. Existing isolated demo SQLite preserved.
- Migration 0004 reviewed file-only.

## Current Migration Chain (file-reviewed)
| Revision | Down Revision | Purpose | Risk |
|---|---|---|---|
| `0001_baseline_existing_schema.py` | None | Baseline existing schema | Low if matches deployed schema |
| `0002_mitigation_policy_models.py` | 0001 | Mitigation policy persistence models | Medium - schema change |
| `0003_mitigation_decision_audit.py` | 0002 | Decision/audit persistence | Medium - schema change |
| `0004_revoked_tokens.py` | 0003 | `revoked_tokens` table + indexes for JWT revocation durability | Low-medium additive; requires deployment approval |

## 0004 Review
- Creates `revoked_tokens` (`id`, `token_hash` VARCHAR(64) unique indexed, `expires_at` timestamptz indexed, `revoked_at` timestamptz).
- Additive only; no existing table alteration. Downgrade drops indexes/table.
- App code handles missing store by in-memory fallback with warning (compatibility) but **durability/multi-worker guarantees unavailable** until applied.

## Local Demo Evidence
- Isolated demo SQLite preserved: `<LOCAL_TEMP>\opencode\apisentry_local_demo_20261123\apisentry_demo.sqlite3`.
- Backend restarted with same env vars (`DATABASE_URL=sqlite:///.../apisentry_demo.sqlite3`, `ENVIRONMENT=development`, `AUTO_CREATE_SCHEMA=true`).
- `/ready` returned `200 {"status":"ready","service":"APISentry AI","checks":{"database":"ok"}}`.
- Demo enable/disable/kill-switch flows verified in browser.

## Readiness Gaps
| Gap | Impact | Required Action |
|---|---|---|
| 0004 not applied to PostgreSQL | Revoked tokens not durable across restart/workers | Test on disposable PostgreSQL, backup, apply, verify |
| No disposable PostgreSQL migration test executed in this pass | Unknown runtime migration behavior on target PG | Run in isolated disposable PG container/instance |
| Multi-worker DB consistency not verified | Revocation/policy state may diverge | Verify with shared PostgreSQL + multiple workers |
| Backup/restore procedure not executed | Recovery confidence low | Perform backup/restore drill on disposable DB |
| Connection pooling/transaction tuning not load-tested | Performance/reliability unknown under load | Load test with production-like pool settings |
| PG-gated persistence test excluded | Persistence behavior on PG unverified | Run `backend/tests/test_mitigation_policy_lifecycle_persistence.py` in approved PG env |

## Safe Deployment Prerequisites (0004 / PG)
1. **Separate explicit approval** for disposable PostgreSQL test and any later production migration.
2. Take full backup/snapshot before migration; verify restore.
3. Run on isolated disposable PostgreSQL first: `alembic upgrade head` (or up to 0004) with same code revision.
4. Verify `revoked_tokens` table/indexes, app startup, login/logout/revoked-token reuse, multi-worker behavior.
5. Run PG-gated tests in approved environment.
6. Only after verification, schedule production migration window with rollback plan.
7. Do not touch ports 5432/55446/55447 or existing user PostgreSQL data without separate explicit approval.

## Rollback / Recovery Notes
- 0004 downgrade drops `revoked_tokens` table/indexes; revocation durability lost. Only use with understanding of security impact.
- Application has missing-store fallback (in-memory) but this is not durable/multi-worker safe.
- Backup before migration is mandatory. Validate restore procedure on disposable DB.

## Files Reviewed
- `backend/alembic/versions/0001_baseline_existing_schema.py`
- `backend/alembic/versions/0002_mitigation_policy_models.py`
- `backend/alembic/versions/0003_mitigation_decision_audit.py`
- `backend/alembic/versions/0004_revoked_tokens.py`
- `backend/app/core/security.py`
- `backend/app/db/session.py`
- `backend/app/main.py`