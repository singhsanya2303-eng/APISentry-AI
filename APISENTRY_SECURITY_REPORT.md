# APISENTRY Security Report
> **Historical snapshot:** This report records evidence from its original task/date and is preserved for context. It is not a statement of current repository state. Current safe backend suite evidence is **1494 passed, 29 warnings** (Task 12A), excluding the separately gated PostgreSQL persistence suite.

## Verdict
- **Local demo security (isolated SQLite demo): CONDITIONAL PASS**
- **Production security readiness: NO-GO** (migration 0004 unapplied, no distributed revocation/rate-limit verification, no external penetration test, environment/secrets/deployment hardening still required)

## Scope and Evidence Basis
- Code inspection and targeted hardening in this pass.
- Focused tests executed: `backend/tests/test_api_hardening.py`, `backend/tests/test_sec01_jwt_revocation.py`, `backend/tests/test_sec02_mitigation_consistency.py` => **13 passed**.
- Full safe backend suite: **1388 passed, 27 warnings**, 0 failed (`pytest backend/tests -q --ignore=backend/tests/test_mitigation_policy_lifecycle_persistence.py`).
- Browser smoke: demo enable validation, disable to DISABLED/ADVISORY ONLY, console/network clean.
- No secrets inspected/exposed. No PostgreSQL touched. No migration 0004 applied.

## Implemented / Verified Controls

### Authentication & Token Lifecycle
- JWT HS256 tokens with required `sub`/`exp`, signature validation, expiry enforcement (`backend/app/core/security.py`).
- Token revocation on logout: SHA-256 token hash stored in-memory with expiry cleanup; optional DB persistence to `revoked_tokens` when store available.
- Revocation check after signature/expiry; revoked token reuse returns 401 (`Authentication token has been revoked`).
- DB revocation lookup failure fails closed; missing revocation store (0004 unapplied) falls back to in-memory with warning - **no durable or multi-worker guarantee**.
- Inactive user accounts rejected.

### Access Control / RBAC
- Server-side RBAC dependencies: `require_admin`, `require_analyst`, `require_viewer`, `get_current_active_user`.
- Public registration forces `viewer` role; client-supplied role ignored (`backend/app/api/v1/routes/auth.py`).
- Admin-only routes protected (`/users` admin endpoints, mitigation policy admin mutation routes, demo enable/disable/kill/run).
- Analyst read/analysis routes protected; viewer denied where required.
- Prior browser acceptance verified Viewer/Analyst restrictions (403 for analyst policy create/demo enable).

### API Protection (this pass)
- **Security headers middleware** added (`backend/app/utils/middleware.py`): `X-Content-Type-Options=nosniff`, `X-Frame-Options=DENY`, `Referrer-Policy=no-referrer`, `Permissions-Policy`, `Cross-Origin-Resource-Policy=same-site`, CSP (docs-compatible for docs/openapi; stricter default otherwise), HSTS in production.
- **Request body size limit** middleware added: Content-Length checked against `MAX_REQUEST_BODY_BYTES` (default 1 MiB); oversized returns 413, invalid Content-Length returns 400.
- **Auth rate limiting** added for login/register (`backend/app/core/rate_limit.py`): in-process sliding window, configurable `AUTH_RATE_LIMIT_ENABLED/REQUESTS/WINDOW_SECONDS`, returns 429 with `Retry-After`. **Per-process only; not distributed.**
- CORS configured via settings; dev localhost origins appended only in non-production. Production should set explicit `CORS_ORIGINS`.
- Safe error handling: no raw stack traces/secret leakage in responses; generic auth errors.

### Input Validation
- Pydantic schema validation on auth/mitigation demo/policy endpoints.
- Demo enable requires explicit `ENABLE_LOCAL_DEMO`, bounded max_requests/max_duration, synthetic/loopback acknowledgements.
- Frontend demo enable now validates required fields before submit (no unnecessary API request).

### Security Testing
- New `backend/tests/test_api_hardening.py`: security headers, readiness shape, 413 oversized payload, 429 auth rate limit.
- Existing SEC-01 JWT revocation and SEC-02 mitigation consistency tests pass.
- Full safe backend suite passes (1388).

## Findings / Gaps
| ID | Severity | Finding | Status |
|---|---|---|---|
| SEC-G1 | High | Revocation durable store migration 0004 not applied in deployment; in-memory fallback not multi-worker/durable | Open - requires approved PostgreSQL migration |
| SEC-G2 | Medium | Auth rate limiting is per-process only; no shared distributed limiter | Open - Redis/shared store requires architecture/dependency approval |
| SEC-G3 | Medium | No refresh-token rotation/revocation chain implemented; access-token-only model | Open - design change, compatibility review needed |
| SEC-G4 | Medium | Request size limit uses Content-Length only; chunked/unknown-length bodies need streaming cap hardening | Open |
| SEC-G5 | Medium | CSP allows `'unsafe-inline'` styles and broad connect-src for compatibility; tighten for production | Open |
| SEC-G6 | Low | Account lockout/bruteforce protection beyond rate limit not fully implemented | Partial |
| SEC-G7 | Low | Security event logging/alerting not centralized to SIEM/monitoring | Partial |
| SEC-G8 | Info | `require_analyst_or_api_key` allows static API key for service-to-service analysis routes; key management is deployment responsibility | Known |

## Recommendations
1. Apply migration 0004 on isolated disposable PostgreSQL, verify, then approved production rollout.
2. Add distributed rate limiting/revocation shared store for multi-worker deployments.
3. Add streaming request body size enforcement and stricter CSP for production builds.
4. Add account lockout/captcha/escalating delay for repeated auth failures (with careful UX/testing).
5. Add refresh-token strategy only with explicit compatibility/security review.
6. Run external penetration test and dependency vulnerability scan in approved environment.

## Files Changed (this pass, security-relevant)
- `backend/app/core/config.py` - hardening settings.
- `backend/app/core/rate_limit.py` - in-process auth rate limiter.
- `backend/app/utils/middleware.py` - security headers and request size limit middleware.
- `backend/app/main.py` - middleware wiring, `/ready` endpoint.
- `backend/app/api/v1/routes/auth.py` - rate limit enforcement on register/login.
- `backend/tests/test_api_hardening.py` - hardening tests.
- `backend/tests/conftest.py` - rate limit reset for test isolation.