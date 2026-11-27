# APISENTRY Safe P0/P1 Security Hardening Report
> **Historical snapshot:** This report records evidence from its original task/date and is preserved for context. It is not a statement of current repository state. Current safe backend suite evidence is **1494 passed, 29 warnings** (Task 12A), excluding the separately gated PostgreSQL persistence suite.

## Verdict
- **Local isolated-demo hardening pass: CONDITIONAL PASS**
- **Production security readiness: NO-GO** (unchanged blockers: Alembic 0004 unapplied on PostgreSQL, no distributed revocation/rate-limit shared store, no external pentest/load validation, browser/viewport verification unavailable in this session)

## Scope / Constraints Honored
- Preserved existing modified/untracked files; no reset/checkout/clean/stash/commit/push.
- Preserved isolated SQLite demo DB: `<LOCAL_TEMP>\opencode\apisentry_local_demo_20261123\apisentry_demo.sqlite3` (not recreated/reset/overwritten/deleted).
- No dependencies installed; no env/package changes.
- No PostgreSQL connections; ports `5432/55446/55447` untouched; Alembic `0004` not applied.
- Batch 7 frozen artifacts not modified. Real enforcement not enabled.
- No servers restarted. Browser/viewport verification **UNVERIFIED** (browser tools unavailable by user instruction).

## Implemented Changes

### 1) Streaming/chunked request-body size enforcement (P0)
- **File:** `backend/app/utils/middleware.py`
- Replaced `RequestSizeLimitMiddleware` from BaseHTTPMiddleware/Content-Length-only to **ASGI middleware** that:
  - Early rejects invalid/negative Content-Length with **400**; best-effort drains body before responding.
  - Early rejects oversized declared Content-Length with **413**; best-effort drains body before responding.
  - Always counts actual streamed bytes (covers chunked/missing/misleading Content-Length) and rejects with **413**.
  - Drains remaining body on over-limit during streaming to avoid keep-alive corruption.
  - Replays buffered body (up to limit) to downstream app; memory bounded to allowed limit (+ current chunk).
  - Emits structured security events (`request.too_large`, `request.invalid_content_length`).
- **Config:** `backend/app/core/config.py` `MAX_REQUEST_BODY_BYTES` default 1 MiB.
- **Tests:** `test_request_size_limit_rejects_large_payload`, `test_request_size_limit_rejects_chunked_oversized_body`, `test_request_size_limit_rejects_invalid_content_length`, `test_request_size_limit_rejects_negative_content_length`, `test_request_size_limit_rejects_misleading_small_content_length`.

### 2) Production CSP hardening (P1)
- **File:** `backend/app/utils/middleware.py`
- Hardened CSP defaults:
  - Added `object-src 'none'; base-uri 'self'; form-action 'self'` to docs and API/default policies.
  - Docs CSP: keeps required `unsafe-inline`/https script/style for FastAPI docs compatibility; `connect-src 'self' https:`.
  - API/default CSP: production `connect-src 'self' https:`; non-production `connect-src 'self' http: https:` for local dev compatibility; retains `style-src 'self' 'unsafe-inline'` for compatibility (documented limitation), `script-src 'self'`.
  - HSTS set in production only (existing behavior preserved).
- **Test:** `test_security_headers_present_on_health`, `test_security_headers_include_hardened_csp`.
- **Browser/frontend runtime verification:** UNVERIFIED (no browser session).

### 3) Structured security-event logging with strict sensitive-data redaction (P0/P1)
- **New file:** `backend/app/core/security_events.py`
  - `redact_sensitive()` recursively redacts sensitive keys (`password`, `passwd`, `pwd`, `token`, `access_token`, `refresh_token`, `id_token`, `jwt`, `authorization`, `api_key`, `x-api-key`, `secret`, `client_secret`, `jwt_secret_key`, `cookie`, `set-cookie`, `session`, `csrf`, `credential(s)`, `private_key`, `database_url`, and key-name markers), truncates large strings/blobs (>512 chars), bounds depth (6) and collection size (50).
  - `log_security_event()` emits structured `apisentry.security.events` logger records with redacted fields and `security_event` extra.
- **Integrations:**
  - `backend/app/core/rate_limit.py`: `auth.rate_limited`.
  - `backend/app/utils/middleware.py`: `request.too_large`, `request.invalid_content_length`.
  - `backend/app/core/security.py`: `auth.api_key_not_configured`, `auth.api_key_rejected`, `auth.missing_credentials`, `auth.token_expired`, `auth.token_revoked`, `auth.token_invalid`, `auth.rbac_denied`, `auth.not_configured`.
  - `backend/app/api/v1/routes/auth.py`: `auth.login_failed` (bad password / invalid credentials; no password/token logging).
- **Tests:** `test_security_event_redaction_masks_sensitive_fields`, `test_validation_error_redacts_sensitive_input`.

### 4) Protected route RBAC/auth audit (P0)
- **Code-reviewed audit result:**
  - **Public by design:** `/`, `/health`, `/ready`, `/api/v1/health`, `/docs`, `/redoc`, `/api/v1/openapi.json`, `/api/v1/auth/register`, `/api/v1/auth/login`; dev-only conditional `/demo/auth/login` (rate-limited).
  - **JWT-authenticated:** `/api/v1/auth/logout` (`oauth2_bearer` + explicit credential check, revokes token), `/api/v1/auth/me` (`get_current_active_user`), `/api/v1/auth/status` (if present in router map - not present; see below), `/api/v1/auth/users/{user_id}` (`require_jwt_auth`) - intentionally minimal BOLA-target demo endpoint; returns only accessed user_id/accessed_by/status, requires valid JWT. Documented; not changed.
  - **Admin-only:** `/api/v1/users` list, `/api/v1/users/{id}` patch (`require_admin`); mitigation policy mutations (`require_admin`); mitigation demo enable/disable/kill-switch/run (`require_admin`).
  - **Analyst/Admin read:** mitigation policy reads (`require_analyst`), mitigation decision/audit/enforcement status (`require_analyst`), mitigation dry-run (`require_analyst`), mitigation demo status (`require_analyst` + loopback guard), users/{id} allows self-or-admin.
  - **Analysis routers:** `bola`, `bruteforce`, `rate_anomaly`, `behavior`, `bot_detection`, `mitigation_analysis`, `clustering`, `token_classifier`, `traffic_trends`, `http_payload_classifier` all mounted behind blanket `Depends(require_analyst_or_api_key)` in `backend/app/api/v1/router.py`.
  - **No unprotected sensitive route found** in audited API surface.
- **Hardening change:** `backend/app/api/v1/routes/demo_auth.py` now enforces auth rate limiting (`demo.login` scope) and accepts `Request`; endpoint remains dev-only/conditionally mounted by `settings.is_demo_auth_enabled`.

### 5) In-process authentication rate limiting improvements (P0)
- **File:** `backend/app/core/rate_limit.py`
- Improvements:
  - **Forwarded-IP spoofing resistance:** uses `extract_client_ip(request, TRUSTED_PROXIES)`; untrusted peers cannot spoof via `X-Forwarded-For`.
  - **Concurrency safety:** lock-protected bucket updates.
  - **Bounded memory:** `_MAX_BUCKETS=10_000` with deterministic oldest-bucket eviction after cleanup.
  - **Expiry cleanup:** periodic cleanup (`_CLEANUP_INTERVAL_SECONDS=60`) and stale bucket removal on access/threshold.
  - **Config-safe defaults:** invalid config falls back to safe defaults.
  - **Structured event:** rate-limit denial emits redacted `auth.rate_limited`.
- **Tests:** `test_auth_rate_limit_returns_429`, `test_auth_rate_limit_ignores_spoofed_xff_from_untrusted_peer`.

### 6) CORS, exception handling, security headers, sensitive response exposure (P0/P1)
- **CORS:** `backend/app/core/config.py` rejects `CORS_ORIGINS` wildcard `*` (incompatible with credentialed CORS). Existing explicit origins, credentials, explicit methods/headers allowlists preserved. Non-production convenience localhost:5174 origin preserved.
- **Exception handling:** `backend/app/main.py`
  - Added `RequestValidationError` handler that redacts sensitive `input`/`ctx` values and redacts by sensitive `loc` names; preserves 422 structure. Uses `jsonable_encoder` for safe serialization.
  - Added generic `Exception` handler returning safe `{"detail":"Internal server error"}` and server-side logging (no internal leak to client).
- **Security headers:** `nosniff`, `DENY`, `no-referrer`, restrictive `Permissions-Policy`, `Cross-Origin-Resource-Policy: same-site`, hardened CSP, HSTS in production.
- **Sensitive response exposure:** generic 500 sanitized; validation errors redact sensitive fields; auth errors remain generic; no secrets/stack traces returned.
- **Tests:** `test_unhandled_exception_handler_does_not_leak`, `test_validation_error_redacts_sensitive_input`, `test_cors_wildcard_rejected_by_settings_validation`, `test_security_headers_present_on_health`, `test_security_headers_include_hardened_csp`.

## Files Changed (this hardening pass)
- `backend/app/core/config.py` - CORS wildcard validation.
- `backend/app/core/rate_limit.py` - bounded/cleanup/trusted-IP-aware rate limiter + security event.
- `backend/app/core/security.py` - security-event logging for auth/RBAC failures.
- `backend/app/core/security_events.py` - **new** structured redacted security-event logger.
- `backend/app/utils/middleware.py` - ASGI streaming request size limit (CL + actual bytes, drain, replay), hardened CSP, security-event logging.
- `backend/app/main.py` - safe validation/500 exception handlers.
- `backend/app/api/v1/routes/auth.py` - login failure security events.
- `backend/app/api/v1/routes/demo_auth.py` - rate limit on dev-only demo login.
- `backend/tests/test_api_hardening.py` - focused regression tests for hardening fixes.
- `APISENTRY_SAFE_SECURITY_HARDENING_REPORT.md` - this report.

## Verification Evidence

### Focused hardening tests (API-level / unit / TestClient)
Command:
```powershell
$env:PYTHONPATH='backend'; .\.venv\Scripts\python -m pytest backend/tests/test_api_hardening.py -q
```
Result: **14 passed, 1 warning** (StarletteDeprecationWarning from testclient/httpx)

### Full safe backend suite
Command:
```powershell
.\.venv\Scripts\python -m pytest backend/tests -q --ignore=backend/tests/test_mitigation_policy_lifecycle_persistence.py
```
Result: **1398 passed, 0 failed, 27 warnings** (95.70s)

### Frontend tests
Command:
```powershell
node --test frontend/tests/*.test.js
```
Result: **25 passed, 0 failed**

### Frontend lint
Command:
```powershell
cd frontend; npm run lint
```
Result: **PASS** (1 pre-existing warning: `src/App.jsx:267:7 react/set-state-in-effect`)

### Frontend production build
Command:
```powershell
cd frontend; npm run build
```
Result: **PASS** (`✓ built in 1.52s`; pre-existing chunk-size warning)

## Classification of Work
- **Implemented:** streaming/chunked body-size enforcement with misleading-CL/negative-CL/oversized/chunked coverage and drain/replay; CSP hardening (`object-src`, `base-uri`, `form-action`, prod connect-src tightening); structured redacted security-event logging; RBAC route audit + demo_auth rate-limit; auth rate limiter hardening (concurrency/bounded memory/cleanup/spoof resistance); CORS wildcard rejection; safe 500/422 sensitive redaction; security header review.
- **Unit-tested:** redaction, settings CORS validation, size-limit logic (invalid/negative/misleading/chunked/oversized), rate-limit behavior/spoof resistance, validation/500 sanitization, security headers/CSP.
- **API-tested (TestClient/ASGI):** 413/400 body limit, 429 rate limit with spoofed XFF, 422 sensitive redaction, 500 no-leak, CSP/header presence, misleading-CL ASGI rejection.
- **Browser-unverified:** frontend runtime CSP behavior in real browser, responsive viewports, end-to-end browser UX after hardening. **Do not mark PASS.**
- **Infrastructure-blocked / unchanged:** PostgreSQL migration 0004 application/verification, durable multi-worker revocation, distributed rate limiting/shared store, external pentest/load/security infra validation, production deployment signoff.

## Limitations / Remaining Blockers
- **Rate limiting is still per-process/in-memory.** Multi-worker/distributed deployments require approved shared store (Redis/DB) - not added.
- **CSP still allows `'unsafe-inline'` in `style-src`** for compatibility; further tightening needs browser-verified frontend CSP rollout strategy. Docs CSP retains inline script/style required by FastAPI docs.
- **Validation error redaction is best-effort** (sensitive key/loc-based + recursive redaction). It reduces exposure but is not a full DLP system.
- **Request body limit ASGI middleware buffers up to limit (+current chunk) in memory** and replays it; keep `MAX_REQUEST_BODY_BYTES` conservative.
- **Early-reject drain is best-effort**; abnormal client/network behavior may still affect connections in edge cases.
- **Alembic 0004 not applied**; revoked-token durability/multi-worker consistency remains blocked pending separate explicit approval and isolated disposable PostgreSQL verification.
- **No browser/responsive verification** in this session by user instruction.
- **No PostgreSQL touched**; PG-gated lifecycle persistence test remains excluded by constraint.
- **`/api/v1/auth/users/{user_id}` remains an intentional JWT-protected BOLA-target demo endpoint** (minimal response, no sensitive data exposure beyond IDs already known to caller context); review if product scope changes.

## Security Notes
- No secrets, `.env` values, keys, tokens, or credentials exposed.
- No real enforcement enabled; demo safety defaults preserved.
- Batch 7 frozen payload classifier artifacts untouched.