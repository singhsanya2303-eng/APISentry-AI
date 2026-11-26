# APISENTRY Deployment Runbook
> **Historical snapshot:** This report records evidence from its original task/date and is preserved for context. It is not a statement of current repository state. Current safe backend suite evidence is **1494 passed, 29 warnings** (Task 12A), excluding the separately gated PostgreSQL persistence suite.

## Status
**Not production-deployment-ready.** This runbook documents safe local demo operation and required production deployment controls. Use separate explicit approval for any PostgreSQL migration or production infrastructure action.

## 1. Preconditions
- Preserve existing modified/untracked files; do not reset/clean.
- Do not expose `.env`, secrets, keys, tokens, credentials.
- Batch 7 frozen payload classifier artifacts must remain unchanged.
- No Alembic migration applied to existing PostgreSQL without separate explicit approval.
- No destructive DB operations on ports 5432/55446/55447 or preserved backups.

## 2. Local Isolated Demo (SQLite)
### Environment
- `DATABASE_URL=sqlite:///.../apisentry_demo.sqlite3` (isolated temp path)
- `ENVIRONMENT=development`
- `AUTO_CREATE_SCHEMA=true` (dev/demo only; never production)

### Start backend
```powershell
$dbDir = Join-Path $env:TEMP 'opencode\apisentry_local_demo_20261123'
$env:DATABASE_URL = 'sqlite:///' + ((Join-Path $dbDir 'apisentry_demo.sqlite3').Replace('\','/'))
$env:ENVIRONMENT = 'development'
$env:AUTO_CREATE_SCHEMA = 'true'
cd <repo-root>
.\.venv\Scripts\python.exe -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
```

### Start frontend
```powershell
cd <repo-root>\frontend
npm run dev -- --host 127.0.0.1 --port 5174
```

### Health checks
- `GET /health` -> liveness, expects 200.
- `GET /ready` -> readiness with DB check, expects 200 when DB reachable; 503 otherwise.

## 3. Security Configuration Checklist
| Setting | Production Requirement |
|---|---|
| `ENVIRONMENT` | `production` |
| `JWT_SECRET_KEY` | Strong secret, >=256-bit encoded, not predictable/dev default |
| `AUTO_CREATE_SCHEMA` | Forced false in production by config validation |
| `CORS_ORIGINS` | Explicit trusted origins only; no wildcard |
| `API_KEY` | Strong secret if service-to-service API key auth used |
| `MAX_REQUEST_BODY_BYTES` | Set appropriate limit (default 1 MiB) |
| `AUTH_RATE_LIMIT_*` | Enable; tune for deployment; use distributed limiter for multi-worker |
| `SECURITY_HEADERS_ENABLED` | true |
| Demo auth | Disabled in production (`is_demo_auth_enabled` enforces) |

## 4. Database Migration Runbook (PostgreSQL)
### Pre-migration
1. Obtain separate explicit approval.
2. Full backup/snapshot; verify restore on disposable instance.
3. Confirm target DB, credentials, migration revision, maintenance window.
4. Test on isolated disposable PostgreSQL first (no production touch).

### Migration 0004 (revoked_tokens)
- File: `backend/alembic/versions/0004_revoked_tokens.py`
- Additive: creates `revoked_tokens` table, unique `token_hash` index, `expires_at` index.
- Apply: `alembic upgrade 0004_revoked_tokens` (or `head` after validation).
- Verify:
  - table/indexes exist
  - login/logout/revoked token reuse returns 401
  - restart durability
  - multi-worker consistency with shared DB
  - PG-gated tests in approved env

### Rollback
- `alembic downgrade 0003_mitigation_decision_audit` drops revoked_tokens table/indexes.
- Security impact: revocation durability lost; only do with approved incident plan.

## 5. Backup and Restore
- Before any migration: logical backup (`pg_dump`) or snapshot per infra policy.
- Restore drill on disposable DB: restore backup, run smoke queries, verify app connectivity.
- Retain backup until post-migration verification complete.
- Never delete/overwrite preserved user DB/backups.

## 6. Observability / Monitoring
- Structured request logging via `RequestLoggingMiddleware` (no request bodies/sensitive params masked).
- `/health` liveness, `/ready` readiness with DB check.
- Security headers on responses.
- Recommended production additions: centralized logs, metrics (Prometheus/OpenTelemetry), alerting on 401/403/429 spikes, DB health, error rates, latency SLOs.

## 7. Incident / Recovery
- **Auth compromise/revocation issue**: rotate JWT secret (invalidates all tokens), investigate revoked_tokens store, verify 0004 applied.
- **DB unavailable**: `/ready` returns 503; app may fail closed for revocation DB checks. Restore DB/connectivity.
- **Rate limit abuse**: tune limits, add WAF/distributed limiter, review logs.
- **Demo kill switch**: use demo kill switch endpoint (admin, local demo only) to force advisory-only.

## 8. Deployment Verification Checklist
- [ ] Lint/tests/build pass in CI.
- [ ] `/health` and `/ready` green.
- [ ] Security headers present.
- [ ] Auth login/logout/revocation verified.
- [ ] RBAC verified for viewer/analyst/admin.
- [ ] 0004 applied and verified on disposable PG before production.
- [ ] Backups verified.
- [ ] No secrets in logs/responses.
- [ ] Batch 7 frozen artifacts unchanged.
- [ ] Demo/real enforcement defaults safe (advisory only).

## 9. Known Production Blockers
- Migration 0004 not applied/verified on production PostgreSQL.
- No distributed revocation/rate-limit shared store.
- No external security audit/pentest.
- No production load/perf validation.
- Responsive viewport verification unverified in this pass.