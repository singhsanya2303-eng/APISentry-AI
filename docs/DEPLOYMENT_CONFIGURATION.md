# Deployment Configuration and Safe Operations

## Scope

This document describes behavior that is implemented in the repository. It does not authorize a production deployment. Production request-time enforcement remains disabled/advisory-only: `RequestEnforcementMiddleware` is not registered by `app.main.create_app()`. Gate E and WP9 are isolated, default-disabled non-production demonstrations.

## Advisory versus isolated enforcement

| Mode | Where it runs | Effect | Default |
|---|---|---|---|
| Advisory (`advisory_only`) | Normal API routes and dashboard analysis | Evaluates and persists decisions/audits; never blocks or throttles real traffic | On |
| Isolated enforcement demo | Loopback-only synthetic harness started through `/api/v1/security/mitigation/request-enforcement-demo/enable` | Exercises the real middleware against synthetic requests in an injected temporary SQLite database | Off |

Production startup logs `enforcement_mode=advisory_only` and `production_request_middleware_registered=false`. `/health` and `/ready` expose the same status.

## Environment validation

Copy `backend/.env.example` to `backend/.env` and replace placeholders locally. Never commit the resulting `.env`.

`app.core.config.Settings` validates:

- `ENVIRONMENT=production` requires a non-predictable JWT secret of at least 256 encoded bits.
- `AUTO_CREATE_SCHEMA` is forced to `false` in production.
- `CORS_ORIGINS` cannot contain `*` and must contain absolute `http(s)` origins.
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
- Unhandled errors emit `app.unhandled_error` with path, method, request ID and error type only. Response bodies remain generic.
- `log_operation()` serializes JSON and passes fields through `redact_sensitive()`; passwords, tokens, API keys, cookies, authorization headers and DSNs are masked.

## Health and readiness

- `GET /health`: liveness plus environment and enforcement mode.
- `GET /ready`: database dependency check; returns `503` with `status=not_ready` when unavailable and emits `app.readiness_failed`.
- Neither endpoint returns secrets.

## Migration, backup and recovery

1. Use a disposable, identity-verified PostgreSQL cluster for all migration rehearsals. Record host, port, database and user before starting.
2. Take and verify a logical backup or snapshot before migration. Restore it on the disposable cluster and run smoke checks.
3. Apply reviewed Alembic revisions only on that disposable cluster first. Confirm revision, table/index presence, and application restart behavior.
4. Production migration requires separate explicit authorization and a maintenance window. Never apply schema changes to the protected original database from this project flow.
5. Rollback uses the documented Alembic downgrade for the target revision. Rehearse it on disposable infrastructure and confirm that revocation/rate-limit/runtime smoke checks still pass or that the accepted fallback is understood.
6. Dispose of the temporary cluster after verification.

## Rollback of application configuration

- Disable new configuration by restoring the previous reviewed `backend/.env` values.
- Keep `ENVIRONMENT=production`, `AUTO_CREATE_SCHEMA=false`, explicit `CORS_ORIGINS`, and strong secrets.
- Never "fix" an enforcement issue by registering request-time middleware in production. Use the isolated demo harness instead.
- Rotate secrets if they may have been exposed; rotation invalidates existing JWTs.

## Remaining deployment dependencies

Distributed revocation, shared rate limiting, centralized log shipment, production load testing and external security review remain external operational decisions. This repository provides safe defaults and verification evidence, not a production authorization.
