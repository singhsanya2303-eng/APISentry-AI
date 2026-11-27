# Staging Preparation (Owner-Approved Infrastructure Only)

This document is repository-side preparation. It does **not** create a provider
account, database, server, DNS record, TLS certificate, deployment, or publish
an artifact. Every command below is a future step that requires explicit owner
approval. No real secret value is included here.

## 1. Required owner decisions before staging

- Approve a disposable staging provider, region, budget, and lifetime.
- Approve the HTTPS backend origin and HTTPS frontend origin.
- Approve secret injection and rotation for the backend only.
- Approve whether the staging app uses `ENVIRONMENT=production` for fail-closed
  parity (recommended) or `ENVIRONMENT=staging` with every production-equivalent
  gate set explicitly.
- Approve the database initialization/migration path in
  `docs/STAGING_DATABASE_CHECKLIST.md`.
- Approve the demo scope from `docs/DEMO_MODULE_MATRIX.md`.
- Approve the one-worker runtime assumption and health-check probes.
- Confirm that public registration remains disabled and that admin accounts are
  provisioned only through the owner-controlled script.

## 2. Exact environment naming and safe templates

Templates:

- Backend: `backend/.env.staging.example`
- Frontend: `frontend/.env.staging.example`

Backend variable names are case-sensitive. Use exactly:

| Purpose | Name | Safe rule |
|---|---|---|
| Environment | `ENVIRONMENT` | Exact `production` for production-grade validation; aliases such as `prod` are rejected. `staging` is allowed but does not automatically enable production gates. |
| Debug | `DEBUG` | `false` |
| JWT signing key | `JWT_SECRET_KEY` | CSPRNG-generated 43-char base64url or 64-hex chars; owner-injected; never committed |
| Service key | `API_KEY` | Generated service key or empty; frontend never receives it |
| Frontend origins | `CORS_ORIGINS` | Explicit HTTPS origin(s), comma-separated; wildcard rejected |
| Proxy allowlist | `TRUSTED_PROXIES` | Owner-approved proxy CIDRs only |
| Database DSN | `DATABASE_URL` | Owner-provided PostgreSQL DSN, or leave unset |
| DSN components | `POSTGRES_SERVER`, `POSTGRES_PORT`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB` | Use all five when `DATABASE_URL` is unset; credential values are owner-injected |
| Schema creation | `AUTO_CREATE_SCHEMA` | `false` |
| Registration | `APISENTRY_ENABLE_PUBLIC_REGISTRATION` | Explicit `false`; production forbids `true` |
| Demo auth | `APISENTRY_ENABLE_DEMO_AUTH` | `false` |
| Demo control plane | `APISENTRY_ENABLE_DEMO_CONTROL_PLANE` | `false` |
| Request limits | `MAX_REQUEST_BODY_BYTES`, `AUTH_RATE_LIMIT_ENABLED`, `AUTH_RATE_LIMIT_REQUESTS`, `AUTH_RATE_LIMIT_WINDOW_SECONDS`, `SECURITY_HEADERS_ENABLED` | Reviewed explicit values; defaults are in the template |

Placeholder rejection is enforced in production for `JWT_SECRET_KEY`, database
credentials, and a non-empty `API_KEY`. Secret values are redacted from
operational logs, and `deployment_summary()` exposes only non-secret booleans.

Frontend build-time variable:

| Purpose | Name | Safe rule |
|---|---|---|
| Backend origin | `VITE_API_BASE_URL` | Absolute, non-loopback HTTPS origin. Production builds fail when missing or unsafe. |
| Isolated build env | `APISENTRY_VITE_ENV_DIR` | Temporary directory containing only a reviewed copy of `frontend/.env.staging.example`; never point this at repository local env files |

No browser secret is required. Do not define `VITE_*` names containing
`SECRET`, `PASSWORD`, `API_KEY`, `DATABASE_URL`, `POSTGRES`, `JWT`,
`CREDENTIAL`, or `TOKEN`.

## 3. Backend startup (future, single worker)

Run from the repository root, with secrets injected by the host/secret manager:

```powershell
python -m uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port 8000 --workers 1
```

Rules:

- Start with **one worker**. Rate-limit buckets and the in-memory revocation
  fallback are process-local; multi-worker behavior with a shared database is
  NOT VERIFIED.
- Never use `--reload` outside local development.
- Production configuration forces `DEBUG=false` and `AUTO_CREATE_SCHEMA=false`.
- Gate E/WP9 demo routers remain unmounted; request-time enforcement middleware
  is not registered in production. Enforcement stays advisory-only.
- Terminate TLS at the provider; do not expose plaintext HTTP to browsers.
- Do not serve the legacy untracked `frontend/dist` directory.

## 4. Frontend build (future, unique external temp directory)

```powershell
$buildRoot = Join-Path $env:TEMP ('apisentry-staging-build-' + [guid]::NewGuid().ToString('N'))
$envDir = Join-Path $buildRoot 'env'
$outDir = Join-Path $buildRoot 'site'
New-Item -ItemType Directory -Path $envDir -Force | Out-Null
Copy-Item frontend/.env.staging.example (Join-Path $envDir '.env')
# Edit only the temporary copy: VITE_API_BASE_URL=https://<approved-backend-origin>
$env:APISENTRY_VITE_ENV_DIR = $envDir
npm --prefix frontend run build -- --outDir $outDir
```

Publish only `$outDir`, after owner approval. Do not use `--emptyOutDir`, do not
modify `frontend/dist`, and do not upload any artifact during preparation.

## 5. Health and readiness checks

| Endpoint | Meaning | Expected future probe use |
|---|---|---|
| `GET /health` | Liveness plus advisory-only enforcement status; no database check | Container/provider liveness |
| `GET /ready` | Database `SELECT 1` plus a `revoked_tokens` store query; returns HTTP 503 with `status=not_ready` when either check is unavailable | Readiness before routing traffic |
| `GET /api/v1/health` | Versioned liveness alias | Inventory only |

The frontend consumes `/health`, `/ready`, and the authenticated profile
endpoint only. A cold start is displayed as a bounded
`checking → waking → online | not_ready | offline` sequence: at most 11
attempts, 80 seconds of cumulative backoff, a 90-second deadline, and a
4-second per-request timeout. Polling is cancelled on unmount, logout, or an
unauthorized event. The UI does not invent backend data.

Production builds hide the registration entry point and the submit handler
re-checks the policy; the backend remains fail-closed. Accounts without
Admin/Analyst rights receive a read-only Viewer status surface with Overview
and Service Status navigation only. Backend authorization remains authoritative.

`apiRequest()` uses `AbortController`, a bounded timeout, caller abort support,
and at most one retry for idempotent GET requests on network errors or
502/503/504. Mutations are never retried, and an HTTP 401 clears the local
session. These are repository-side implementation facts, not evidence of a
deployed or database-verified staging environment.

## 6. Pre-deployment gate checklist (not executed)

- [ ] Owner-approved provider, budget, and teardown plan exist.
- [ ] `ENVIRONMENT`, secrets, and CORS values reviewed; no real values in git.
- [ ] HTTPS frontend origin exactly matches backend `CORS_ORIGINS`.
- [ ] `VITE_API_BASE_URL` is non-loopback HTTPS in the temporary build env.
- [ ] Built bundle contains no `127.0.0.1:8000` or `localhost:8000` fallback.
- [ ] Database checklist completed only after explicit authorization.
- [ ] One worker configured; no `--reload`; probes point to `/health` and `/ready`.
- [ ] Registration disabled; admin provisioned through owner-controlled path.
- [ ] Demo control plane and demo auth disabled.
- [ ] Staging data is disposable; no production data copied.
- [ ] Teardown/rotation ownership assigned.

See `docs/DEPLOYMENT_CONFIGURATION.md`, `docs/PRODUCTION_STARTUP.md`,
`docs/STAGING_DATABASE_CHECKLIST.md`, and `docs/DEMO_MODULE_MATRIX.md`.
