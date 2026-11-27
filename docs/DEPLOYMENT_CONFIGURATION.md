# Deployment Configuration and Safe Operations

## Scope

This document describes behavior that is implemented in the repository. It does not authorize a production deployment. Production request-time enforcement remains disabled/advisory-only: `RequestEnforcementMiddleware` is not registered by `app.main.create_app()`. Gate E and WP9 are isolated, default-disabled non-production demonstrations. Owner-approval staging steps are tracked separately in `docs/STAGING_PREPARATION.md`, `docs/STAGING_DATABASE_CHECKLIST.md`, and `docs/DEMO_MODULE_MATRIX.md`.

## Advisory versus isolated enforcement

| Mode | Where it runs | Effect | Default |
|---|---|---|---|
| Advisory (`advisory_only`) | Normal API routes and dashboard analysis | Evaluates and persists decisions/audits; never blocks or throttles real traffic | On |
| Isolated enforcement demo | Loopback-only synthetic harness started through `/api/v1/security/mitigation/request-enforcement-demo/enable` | Exercises the real middleware against synthetic requests in an injected temporary SQLite database | Off |

Production startup logs `enforcement_mode=advisory_only` and `production_request_middleware_registered=false`. `/health` and `/ready` expose the same status.

## Environment validation

Copy `backend/.env.example` to `backend/.env` and replace placeholders locally. Never commit the resulting `.env`.

`app.core.config.Settings` validates:

- `ENVIRONMENT=production` requires a non-predictable JWT secret of at least 256 encoded bits and rejects ambiguous aliases such as `prod`.
- `DEBUG` is forced to `false` in production.
- `AUTO_CREATE_SCHEMA` is forced to `false` in production.
- Production requires an explicit `DATABASE_URL` with a PostgreSQL scheme, host, and database, or all five PostgreSQL target settings.
- Component-based DSNs built from `POSTGRES_*` settings are escaped with SQLAlchemy `URL.create()`, so reserved characters in managed-database passwords do not break engine creation.
- `CORS_ORIGINS` cannot contain `*`, must contain absolute `http(s)` origins, and production origins must be HTTPS except loopback. Development auto-adds HTTP origins on ports 5173 and 5174 for the default Vite port and earlier isolated demos.
- Production rejects placeholder database passwords and a placeholder non-empty `API_KEY` using the same marker check applied to `JWT_SECRET_KEY`.
- `APISENTRY_ENABLE_PUBLIC_REGISTRATION` defaults to `false`; production requires it to be explicitly set to `false` and never permits public registration.
- `MAX_REQUEST_BODY_BYTES` is between 1 KiB and 100 MiB.
- `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` is between 1 and 10080.
- Auth rate-limit request/window values are positive and bounded.
- Demo authentication is never enabled in production.
- `APISENTRY_ENABLE_DEMO_CONTROL_PLANE` defaults to `false`; demo control-plane routers are disabled by default and cannot be enabled when `ENVIRONMENT=production`.

`Settings.deployment_summary()` provides a non-secret snapshot for logs and health endpoints. It reports booleans and counts, never secret values or a DSN.

## Demo control-plane and classifier test mode

- `APISENTRY_ENABLE_DEMO_CONTROL_PLANE=false` is the safe default in `backend/.env.example`. Gate E (`/security/mitigation/demo`) and WP9 (`/security/mitigation/request-enforcement-demo`) routers are mounted only through per-app configuration for explicit non-production opt-in. Production cannot enable them.
- Gate E and WP9 use synthetic requests and isolated temporary SQLite state. They are not production enforcement and must not be exposed publicly.
- The frozen HTTP payload classifier bundle is excluded from the contribution. When it is absent, classifier endpoints return explicit HTTP `503` with `Payload classifier model is not available.` No fake production model is substituted.
- Ordinary artifact-free development intentionally skips real-artifact classifier tests and shows a visible skip reason. Required CI/test mode can be enabled with `pytest --require-classifier-artifact`; collection fails when the required bundle is absent.
- Production request-time enforcement remains disabled; normal API routes are advisory-only.

## Startup and shutdown

- FastAPI lifespan emits structured `app.startup` and `app.shutdown` events through `app.core.operational_logging`.
- Startup calls `init_db()` only when `AUTO_CREATE_SCHEMA=true` and the environment is not production.
- Startup performs one best-effort cleanup of expired JWT revocation rows through a short-lived session. Cleanup failures are logged and never prevent liveness; no background job or external service is started. Readiness separately reports whether the durable revocation table is queryable.
- Unhandled errors emit `app.unhandled_error` with path, method, request ID and error type only. Response bodies remain generic.
- `log_operation()` serializes JSON and passes fields through `redact_sensitive()`; passwords, tokens, API keys, cookies, authorization headers and DSNs are masked.

## Health and readiness

- `GET /health`: liveness plus environment and enforcement mode.
- `GET /ready`: database and durable-revocation-store checks; returns `503` with `status=not_ready` when either is unavailable and emits `app.readiness_failed`. The `revocation_store` check queries `revoked_tokens` explicitly, so a missing migration `0004` is visible before authenticated traffic is routed.
- Neither endpoint returns secrets.

The frontend consumes only these two endpoints plus the authenticated profile
endpoint. A cold start is displayed as a bounded `checking → waking → online |
not_ready | offline` state sequence: at most 11 attempts, backoff delays totaling
80 seconds, a 90-second deadline, and a 4-second per-request timeout. Polling is
cancelled on unmount, logout, or an unauthorized event. The UI never invents
backend data. Viewer accounts see a read-only status surface with no analysis
navigation; backend RBAC remains authoritative.

Query parameters are normalized before redaction for both structured logs and
persisted `api_traffic_logs.query_params`. Noncanonical credential-like names
such as `authToken`, `access-token`, and `session_id` are masked with the same
`***MASKED***` value as canonical names.

## Registration and first administrator provisioning

Public self-registration is disabled by default and impossible in production.
When explicitly enabled in a non-production environment, registration always
creates a viewer and ignores client-supplied role fields. Login, active-account
checks, and Admin/Analyst/Viewer RBAC are unchanged; password hashing and auth
rate limiting are unchanged.

No unauthenticated admin-creation endpoint exists. The owner-controlled method
is the out-of-band `backend/scripts/provision_admin.py` command, which uses
`app.services.user_service.create_user` with `role=UserRole.ADMIN.value`, followed
by login and the existing admin-only user-management endpoints for further
provisioning. Credentials are supplied at run time through
`APISENTRY_NEW_ADMIN_PASSWORD` or an interactive prompt; they are never printed
or stored in source/docs. The command requires `--confirm-production` when
`ENVIRONMENT=production`.

## Migration, backup and recovery

1. Use a disposable, identity-verified PostgreSQL cluster for all migration rehearsals. Record host, port, database and user before starting.
2. Take and verify a logical backup or snapshot before migration. Restore it on the disposable cluster and run smoke checks.
3. Apply reviewed Alembic revisions only on that disposable cluster first. Confirm revision, table/index presence, and application restart behavior.
4. Production migration requires separate explicit authorization and a maintenance window. Never apply schema changes to the protected original database from this project flow.
5. Rollback uses the documented Alembic downgrade for the target revision. Rehearse it on disposable infrastructure and confirm that revocation/rate-limit/runtime smoke checks still pass or that the accepted fallback is understood. Revision `0001` is deliberately not downgradeable; restore from a verified backup instead of dropping baseline tables.
6. Dispose of the temporary cluster after verification.

### Clean database versus existing baseline

- A clean, empty database can be initialized with `alembic -c backend/alembic.ini upgrade head`, reaching `0004_revoked_tokens`. The chain is `0001_baseline_existing_schema` → `0002_mitigation_policy_models` → `0003_mitigation_decision_audit` → `0004_revoked_tokens`.
- `0001` is not idempotent. On an existing populated schema, do **not** run `upgrade` first. Run the read-only baseline verifier, take a verified backup, obtain owner authorization, and only then stamp the matching revision.
- `alembic stamp 0001_baseline_existing_schema` is only correct when the verified schema contains the reviewed `users` and `api_traffic_logs` baseline and no later mitigation/revocation tables. If later tables already exist, stamping `0001` is incorrect; a separate owner-reviewed head-level baseline decision is required before any Alembic operation.
- Ad hoc `init_db()` DDL is not equivalent to Alembic and can diverge (for example, a non-unique `ix_users_email`). Do not use it as a substitute for a reviewed baseline, and do not stamp a database whose verifier reports index/definition drift.
- Alembic and the read-only verifier scripts use direct, short-lived `NullPool` connections; normal request paths use the pooled SQLAlchemy engine. Never run migrations through the request pool.

### Durable JWT revocation cleanup

- Migration `0004_revoked_tokens` is required for restart-durable and multi-worker revocation. Without it, non-production falls back to process-local memory and must not be described as durable; production fails closed instead of accepting a JWT whose logout was recorded only in one process.
- Only a SHA-256 token hash and expiry are stored. The raw JWT is never written to the table and is redacted from logs.
- Expired rows are ignored by authentication. A throttled cleanup deletes at most 500 expired rows per pass from the existing `ix_revoked_tokens_expires_at` index, runs at most every 300 seconds on logout, and runs once at startup. This needs no schema change, Redis, or background job.
- Cleanup failure rolls back and is logged; the current process-local revocation remains functional. A DB failure during the revocation **write** degrades durability for other workers; in production `revoke_token()` raises HTTP `503` so logout never falsely claims durable revocation. The client clears its local token regardless of that response.
- Production maintenance may use a separately approved `DELETE FROM revoked_tokens WHERE expires_at <= NOW();`; this project does not execute it.

### Database validation strategy and CI exclusions

The safe CI suite runs isolated SQLite fixtures only. It covers user creation/login, role persistence, policy CRUD, audit persistence, revocation persistence, hash-only storage, cleanup, application restart simulation, and connection-failure behavior. It also includes source-only migration-chain validation and exact-structure metadata tests that do not run DDL.

`backend/tests/test_mitigation_policy_lifecycle_persistence.py` is excluded because it requires a dedicated PostgreSQL instance at `127.0.0.1:55444`. `backend/tests/test_alembic_baseline.py` is excluded because it performs SQLite DDL. Neither exclusion weakens or deletes those tests; they remain available for explicitly authorized infrastructure. The following are **NOT VERIFIED** in this environment: real managed-PostgreSQL behavior, live migration upgrade/downgrade/stamp timing, lock behavior, concurrent request pooling under load, and multi-worker revocation on a shared database.

Auth rate limiting is an in-process module-level counter keyed by client IP and
scope. It is **not shared across workers** and depends on correct proxy trust
configuration. The default demo is explicitly one worker. A shared Redis- or
database-backed limiter and validated `TRUSTED_PROXIES` are an owner/provider
decision requiring new infrastructure; they were not added here.

## Rollback of application configuration

- Disable new configuration by restoring the previous reviewed `backend/.env` values.
- Keep `ENVIRONMENT=production`, `AUTO_CREATE_SCHEMA=false`, explicit `CORS_ORIGINS`, and strong secrets.
- Never "fix" an enforcement issue by registering request-time middleware in production. Use the isolated demo harness instead.
- Rotate secrets if they may have been exposed; rotation invalidates existing JWTs.

## ML loading and hosting compatibility

Default startup still defers the stacked-autoencoder/torch import until the traffic-trends analysis request actually needs it. Production request-time enforcement remains advisory-only.

Clean-environment dependency compatibility was verified in an isolated venv outside the repository using Python 3.13.7 and `backend/requirements.txt` with `joblib` and `anyio` declared explicitly (no new package family). Installation exited 0, `pip check` reported no broken requirements, and imports succeeded with `numpy 2.5.5`, `scikit-learn 1.9.1`, and `torch 2.15.0+cpu`.

Bounded CPU-only process profiling used a temporary working directory, separate child processes per operation, a 180-second wall-clock timeout, a 2,048 MB Windows job-object memory ceiling, in-memory SQLite, and small synthetic inputs only. No server, database connection, migration, full dataset, large training job, or research dataset was used. Measured results:

| Operation | Latency | RSS / peak RSS | Result |
|---|---:|---:|---|
| `import numpy` | 0.153 s | 28.5 MB / 28.5 MB (+9.9 MB) | success |
| `import sklearn.ensemble` | 2.063 s | 113.9 MB / 113.9 MB (+85.4 MB) | success |
| `import torch` | 2.590 s | 269.6 MB / 269.6 MB (+155.7 MB) | success |
| `import app.main` after those imports | 2.170 s | 327.0 MB / 327.0 MB (+57.4 MB) | success |
| App startup with in-memory SQLite | 0.068 s | 178.4 MB / 178.4 MB | success |
| `/health` | 0.063 s | 180.1 MB / 180.1 MB | HTTP 200 |
| `/ready` | 0.006 s | 180.2 MB / 180.2 MB | HTTP 200 |
| Deterministic risk request | 0.055 s | 181.0 MB / 181.0 MB | HTTP 200 |
| Token classifier request | 0.132 s | 182.0 MB / 182.0 MB | HTTP 200 |
| Clustering request | 0.134 s | 181.4 MB / 181.4 MB | HTTP 200 |
| HTTP payload classifier request | 0.352 s | 200.2 MB / 213.0 MB | HTTP 200; artifact hash verified |
| SAE traffic-trend request | 4.827 s | 414.1 MB / 414.1 MB | HTTP 200; 12 baseline and 2 target windows |
| Four concurrent risk requests | 0.097 s total | 182.1 MB / 182.2 MB | four HTTP 200 responses; max 0.096 s |

A 512 MB backend is **not safely established**: the bounded SAE request alone reached 414.1 MB RSS, importing the full stack in one process reached 327.0 MB, and these sampled values exclude Uvicorn worker overhead, production request buffers, authentication state, database-driver variability, fragmentation, and real concurrency. For a controlled demo, allocate at least 1 GB to one backend worker for deterministic analysis, token classification, and clustering. Keep SAE traffic trends and the HTTP payload classifier as explicit opt-ins; give them 1–2 GB additional headroom or run them in a separate worker/process. Keep CSIC, SR-BH/WAMM research artifacts, and offline training helpers out of the demo. Do not silently substitute model scores or change detection thresholds.

## Remaining deployment dependencies

Production frontend builds require an origin-only HTTPS `VITE_API_BASE_URL`
with no credentials, path, query, or fragment; the value is injected into the
public bundle and is therefore never a secret. Builds also reject secret-shaped
`VITE_*` keys before emitting assets.

Distributed revocation, shared rate limiting, centralized log shipment,
production load testing, India-latency measurement, provider payment-method
eligibility, and external security review remain external operational decisions.
This repository provides safe defaults and verification evidence, not a
production authorization.
