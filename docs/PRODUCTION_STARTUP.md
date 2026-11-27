# Production Startup Preparation

This document prepares repository-side configuration only. It does not deploy
the application, create provider accounts, contact a database, or authorize a
production release. Final staging approval remains with the repository owner.

## 1. Frontend build

Set `VITE_API_BASE_URL` to the deployed HTTPS backend URL in a temporary env
directory containing only a reviewed copy of `frontend/.env.staging.example`.
Production builds fail when this value is missing, non-HTTPS, or loopback. Do
not use `frontend/.env.local`, do not add backend secrets to any `VITE_*` name,
and do not use `--emptyOutDir`.

```powershell
$buildRoot = Join-Path $env:TEMP ('apisentry-frontend-build-' + [guid]::NewGuid().ToString('N'))
$envDir = Join-Path $buildRoot 'env'
$outDir = Join-Path $buildRoot 'site'
New-Item -ItemType Directory -Path $envDir -Force | Out-Null
Copy-Item frontend/.env.staging.example (Join-Path $envDir '.env')
# Edit only the temporary copy: VITE_API_BASE_URL=https://<deployed-backend-host>
$env:APISENTRY_VITE_ENV_DIR = $envDir
npm --prefix frontend run build -- --outDir $outDir
```

Publish `$outDir` only. Never publish or clean the legacy untracked
`frontend/dist`; it is from an older revision and may contain credential-shaped
material. Any old credential that was ever real must be rotated by the owner.

## 2. Backend startup

Run from the repository root with the application directory set to `backend`:

```powershell
python -m uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port 8000 --workers 1
```

Production-safe constraints:

- `--reload` is never used.
- Use one worker initially. Auth rate limiting, JWT revocation warm state, and
  token revocation fallback are process-local; multiple workers weaken those
  guarantees until a shared store is implemented.
- `RequestEnforcementMiddleware` is not registered. Enforcement stays
  advisory-only.
- Gate E and WP9 remain disabled. `APISENTRY_ENABLE_DEMO_CONTROL_PLANE` is
  forced off when `ENVIRONMENT=production`.
- No secret, DSN, or credential is embedded in the startup command or repository
  configuration.

## 3. Required environment variable names

Set these through the host's secret/configuration mechanism, not in source:

| Name | Production expectation |
|---|---|
| `ENVIRONMENT` | Exact value `production`; aliases such as `prod` are rejected |
| `DEBUG` | Forced to `false` by validation |
| `AUTO_CREATE_SCHEMA` | Forced to `false` by validation |
| `DATABASE_URL` | Explicit DSN, **or** all PostgreSQL fields below |
| `POSTGRES_SERVER`, `POSTGRES_PORT`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB` | All required when `DATABASE_URL` is absent |
| `JWT_SECRET_KEY` | Generated 43-char base64url or 64-hex secret; placeholders and predictable values rejected |
| `CORS_ORIGINS` | Explicit trusted origins, HTTPS except loopback; wildcard rejected |
| `APISENTRY_ENABLE_PUBLIC_REGISTRATION` | Must be explicitly set to `false` |
| `APISENTRY_ENABLE_DEMO_AUTH` | Must remain `false` |
| `APISENTRY_ENABLE_DEMO_CONTROL_PLANE` | Forced `false` |
| `API_KEY` | Only if server-to-server API-key authentication is used |
| `MAX_REQUEST_BODY_BYTES` | Review bounded default (1 MiB) |
| `AUTH_RATE_LIMIT_ENABLED`, `AUTH_RATE_LIMIT_REQUESTS`, `AUTH_RATE_LIMIT_WINDOW_SECONDS` | Enable and tune for deployment |
| `TRUSTED_PROXIES` | Set only for known proxy networks when behind a proxy |

`frontend` uses only `VITE_API_BASE_URL` in production builds.

## 4. Health checks

- Liveness: `GET /health`. Reports `enforcement.mode=advisory_only` and
  `production_request_middleware_registered=false`.
- Readiness: `GET /ready`. Performs a minimal database `SELECT 1` and a query
  against the `revoked_tokens` store. It returns HTTP `503` with
  `status=not_ready` when either check is unavailable, and reports both
  `checks.database` and `checks.revocation_store` without secret values.
- Neither endpoint returns secret values.

## 5. Database initialization expectations

- Production startup never calls `init_db()`. Schema changes require reviewed
  Alembic migrations applied by an owner-controlled process with explicit
  authorization.
- No real database migration was run in this preparation phase.
- With public registration disabled, provision the first administrator
  out-of-band with `backend/scripts/provision_admin.py` (or the equivalent
  trusted service/database path), not through an HTTP registration route.
  Existing admin-only user endpoints can then manage roles. See
  `docs/DEPLOYMENT_CONFIGURATION.md`.

## 6. Known hosting limitations

- Process-local rate limiting and revocation require one worker for current
  guarantees; a shared store is needed before horizontal scaling.
- Centralized log shipment, secret delivery/rotation, TLS termination, and
  provider-specific health-check configuration are hosting responsibilities.
- Passing repository tests does not establish production readiness or authorize
  deployment.
- See `docs/STAGING_PREPARATION.md`, `docs/STAGING_DATABASE_CHECKLIST.md`, and
  `docs/DEMO_MODULE_MATRIX.md` for the owner-approval staging checklist.
