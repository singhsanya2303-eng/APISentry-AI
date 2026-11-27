# Final Release Candidate Runbook

**Status: repository-side release candidate prepared; owner actions pending.**
This runbook records local implementation, review, verification, and handoff
state. It does **not** deploy, provision, migrate, publish, or expose the
application. No provider account, DNS record, secret, database, or GitHub
release was created or contacted.

## 1. Scope and authorization boundary

- Hosting target chosen by the owner: Cloudflare Pages (frontend Free tier),
  Render Free Web Service (backend, one worker), Neon Free PostgreSQL.
- Academic/portfolio use only. Public registration is disabled; all accounts
  are created by the owner out of band.
- Production request-time enforcement stays advisory-only. Gate E and WP9 stay
  default-disabled and cannot be mounted in production.
- SAE traffic trends, the HTTP payload classifier, CSIC, SR-BH/WAMM, offline
  training helpers, demo control-plane/auth, and experimental enforcement are
  excluded from the default demo.
- No new dependency family was added. `backend/requirements.txt` was changed to
  declare `joblib>=1.4.0,<2` and `anyio>=4.4.0,<5` explicitly; both were
  previously available only transitively through the existing ML/web stacks.
  `frontend/package.json` is unchanged.

## 2. Hardening implemented in this final pass

| Area | Change | Evidence |
|---|---|---|
| Production revocation | A missing/unusable `revoked_tokens` store now fails closed for authenticated requests; logout returns HTTP 503 rather than claiming durable revocation it could not persist. `/ready` adds a `revocation_store` check. | `backend/app/core/security.py`, `backend/app/main.py`, `backend/tests/test_production_revocation_fail_closed.py` |
| Query redaction | Keys are normalized and masked by sensitive markers before both structured logging and `api_traffic_logs` persistence. Noncanonical names such as `authToken`, `session_id`, and `creditCardNumber` are covered. | `backend/app/utils/middleware.py`, `backend/tests/test_middleware.py` |
| Browser configuration | Production builds require an origin-only HTTPS `VITE_API_BASE_URL`; credentials, path, query, and fragment are rejected. Secret-shaped `VITE_*` keys still abort the build. | `frontend/vite.config.js`, `frontend/tests/stagingBuildConfig.test.js` |
| Registration UI | Production hides the register entry point and re-checks in the submit handler; backend remains fail-closed. | `frontend/src/App.jsx`, `frontend/src/services/registrationPolicy.js` |
| Viewer role | Accounts without Admin/Analyst rights get a read-only status surface built only from `/health`, `/ready`, and the authenticated profile endpoint. Navigation contains only Overview and a rendered Service Status entry; no analysis navigation is shown. | `frontend/src/components/ViewerLanding.jsx`, `frontend/src/components/Sidebar.jsx`, `frontend/src/App.jsx` |
| Cold-start UX | Bounded readiness polling with `checking`, `waking`, `online`, `not_ready`, `offline`; cancellation on unmount, logout, and unauthorized events. | `frontend/src/services/backendStatus.js`, `frontend/src/services/api.js` |
| API client | `AbortController`, bounded timeout, caller abort, and at most one retry for idempotent GET requests on network errors or 502/503/504. Mutations are never retried. | `frontend/src/services/api.js`, `frontend/tests/apiRequest.test.js` |
| Manual refresh spinner | Every manual check clears its own spinner, including when superseded by a newer check. | `frontend/src/App.jsx`, `frontend/tests/frontendUxRegression.test.js` |

## 3. Verification evidence

All commands were run locally with no external network or database calls. The
Python environment was the clean isolated venv created earlier outside the
repository (`apisentry-prompt3-venv`; Python 3.13.7, `numpy 2.5.5`,
`scikit-learn 1.9.1`, `torch 2.15.0+cpu`).

| Check | Command | Result |
|---|---|---|
| Backend safe suite | `python -B -m pytest -p no:cacheprovider -q tests --ignore=tests/test_mitigation_policy_lifecycle_persistence.py --ignore=tests/test_alembic_baseline.py` (from `backend/`) | **1545 passed, 29 warnings in 122.78s**, exit 0 |
| Targeted revocation/redaction/readiness tests | `python -B -m pytest -p no:cacheprovider -q tests/test_production_revocation_fail_closed.py tests/test_sec01_jwt_revocation.py tests/test_jwt_revocation_cleanup.py tests/test_middleware.py tests/test_api_hardening.py tests/test_deployment_configuration.py` | **56 passed, 1 warning**, exit 0 |
| Frontend tests | `node --test tests/*.test.js` (from `frontend/`) | **52 pass, 0 fail**, exit 0 |
| Frontend lint | `npm run lint` (from `frontend/`) | exit 0 |
| Production build | `APISENTRY_VITE_ENV_DIR=<fresh-temp-env-dir> npm --prefix frontend run build -- --outDir <fresh-temp-out-dir>` | exit 0, 20 files, one chunk-size warning only |
| Bundle configuration check | Scan built assets for the injected API base and secret-shaped local env values | configured HTTPS origin present; no secret-shaped `VITE_*` value present |
| Python syntax check | In-memory `compile()` over 228 backend `.py` files (no bytecode written) | 0 syntax errors |
| Whitespace check | `git diff --check` | exit 0 (only pre-existing CRLF normalization notices) |
| Publication allowlist | `git ls-files` plus non-ignored untracked entries | no tracked `frontend/dist`, `.env`, `.env.local`, raw dataset, or research model artifact |

The two `127.0.0.1` strings in the built bundle are static sample data in the
mitigation dashboard, not the configured API base. Build output was written to
a unique directory outside the repository; `--emptyOutDir` was not used.

## 4. Preservation evidence

- Branch remains `feature/apisentry-security-hardening`; HEAD is unchanged at
  `ea06fb5cce8b48fc10a0e6b6df06516eb8eb4da9`.
- No file was staged, committed, pushed, merged, or published. No branch,
  remote, stash, or worktree state was altered. Final staged count: 0; working
  status entries: 94; non-ignored untracked entries: 64.
- All 40 baseline untracked files remain byte-identical (0 missing, 0
  mismatched), and 26 historical `APISENTRY_*.md` reports remain present.
- `frontend/dist` was not read, copied, cleaned, or built into. It remains a
  legacy artifact excluded from publication.
- Model hashes remain verified: token classifier
  `a961152d18e905a135bd1d5cd6c64a9c8e4a44a40c114682fec0cc47e3ddc116`;
  payload bundle
  `2d694c932b9779d4971fa418aa35ecdf60cc266fe909b2ea40aa5392c5ae92dc`.
- Contributor attribution is preserved: Prityush Pal, Ishika Bharti,
  Sanya Singh.

## 5. Documented limitations (not implemented here)

- Real Neon/PostgreSQL behavior, live migration upgrade/downgrade/stamp timing,
  lock behavior, concurrent pooling, and multi-worker revocation are
  **NOT VERIFIED**. `docs/STAGING_DATABASE_CHECKLIST.md` remains **NOT EXECUTED**.
- Auth rate limiting is per-process and not shared across workers. A shared
  store and validated `TRUSTED_PROXIES` require an owner/provider decision and
  new infrastructure; the supported demo topology remains one worker.
- A local secret-shaped `VITE_*` key exists in an ignored frontend env file. It
  was not modified or reproduced. The supported build path rejects it.
- 512 MB backend memory is not safely established. One worker with at least
  1 GB is the conservative demo allocation; optional ML modules need more
  headroom and are excluded from the minimum path.
- India latency and provider payment-method eligibility are unverified.
- Publication must exclude `frontend/dist`, local env files, raw research
  datasets, research model artifacts, caches, bytecode, profiling output, and
  non-demo research files.

## 6. Owner handoff (not executed)

1. Review `docs/OWNER_SETUP_CHECKLIST.md` and approve the exact provider plan.
2. Create provider accounts/resources and secrets in owner-controlled consoles.
3. Apply reviewed Alembic revisions on a disposable database first; use a
   direct/unpooled Neon URL for migrations and a pooled URL at runtime.
4. Build the frontend from a clean temporary env directory with the real HTTPS
   backend origin; publish only the allowlisted source set.
5. Start one backend worker; confirm `/health` and `/ready` both report ready.
6. Provision the first administrator with `backend/scripts/provision_admin.py`;
   keep public registration disabled.
7. Run `docs/DEMO_GUIDE.md` as the acceptance walkthrough.

## 7. Acceptance gates before any public release

- Owner has approved infrastructure, secrets, DNS, migration window, and the
  final artifact set.
- `/ready` reports `database=ok` and `revocation_store=ok` on the deployed
  backend.
- Registration is confirmed disabled in both UI and backend.
- Viewer, Analyst, and Admin role behavior matches `docs/DEMO_GUIDE.md`.
- No secret, raw dataset, legacy `frontend/dist`, or research-only artifact is
  present in the published repository or Pages output.

This runbook is evidence of a repository-side release candidate, not a deployed
application and not a production authorization.
