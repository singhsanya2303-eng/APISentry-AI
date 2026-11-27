# Owner Setup Checklist (Cloudflare Pages + Render Free + Neon Free)

**Status: NOT EXECUTED.** Every item below is an owner-controlled action. This
repository contains no account, secret, DSN, DNS record, deployment, or
published artifact. Do not paste real credentials into files, chat, shell
history, screenshots, or documentation.

Cost target: ₹0 within the providers' current free tiers. Eligibility, payment
method requirements, regional availability, and quotas must be confirmed by the
owner in the provider consoles.

## 1. Provider references (verify current terms before acting)

- Cloudflare Pages limits: https://developers.cloudflare.com/pages/platform/limits/
- Cloudflare build configuration: https://developers.cloudflare.com/pages/configuration/build-configuration/
- Cloudflare Free plan: https://www.cloudflare.com/plans/free/
- Render Free services: https://render.com/docs/free
- Render pricing: https://render.com/pricing.md
- Render environment variables: https://render.com/docs/configure-environment-variables
- Render regions: https://render.com/docs/regions
- Neon pricing: https://neon.com/pricing.md
- Neon scale-to-zero: https://neon.com/docs/introduction/scale-to-zero.md
- Neon connection modes: https://neon.com/docs/connect/choose-connection.md
- Neon SQLAlchemy guide: https://neon.com/docs/guides/sqlalchemy.md
- Neon backups: https://neon.com/docs/postgres/backup-restore/backups.md
- Neon regions: https://neon.com/docs/introduction/regions.md

## 2. Repository and artifact decision

- [ ] Choose a repository publication allowlist. Include reviewed source, tests,
      documentation, templates, and `backend/models/token_usage_classifier.joblib`.
- [ ] Exclude `frontend/dist`, `.env`, `.env.local`, raw research datasets,
      research model artifacts (including the failed CSIC baseline), caches,
      bytecode, profiling output, screenshots containing local UI state, and
      non-demo research files.
- [ ] Confirm the legacy `frontend/dist` is neither copied nor published. It is
      a preserved local artifact, not a build output for this release.
- [ ] Confirm contributor attribution: Prityush Pal, Ishika Bharti, Sanya Singh.

## 3. Neon Free PostgreSQL

- [ ] Create the owner-controlled Neon project, database, and role in a region
      acceptable to the owner. No database was created or contacted locally.
- [ ] Confirm the free-tier compute/connection limits and scale-to-zero behavior
      are acceptable for a demo that may go cold between uses.
- [ ] Record two distinct URLs in the owner secret manager only:
      a **direct/unpooled** URL for migrations and a **pooled** URL for runtime.
- [ ] Take and verify a logical backup before any schema operation.
- [ ] On a disposable database, apply reviewed revisions in order:
      `0001_baseline_existing_schema` → `0002_mitigation_policy_models` →
      `0003_mitigation_decision_audit` → `0004_revoked_tokens`.
- [ ] Do **not** blindly stamp or upgrade a populated legacy schema. `0001` is
      not idempotent; verify the baseline first. See
      `docs/STAGING_DATABASE_CHECKLIST.md` (still marked NOT EXECUTED).
- [ ] Verify migration `0004` exists: the deployed `/ready` must report
      `checks.revocation_store = "ok"`. Without it, production denies
      authenticated requests rather than falling back to process memory.

## 4. Render Free Web Service (backend)

- [ ] Create the service from the allowlisted source repository.
- [ ] Configure exactly **one** worker. The auth rate limiter is per-process and
      is not shared; multiple workers would multiply the effective limit.
- [ ] Set a conservative memory allocation (at least 1 GB). Keep optional SAE,
      HTTP payload classifier, CSIC, and training helpers out of the demo path.
- [ ] Add server-side environment variables in the Render console:
      - `ENVIRONMENT=production` (exact value; aliases are rejected)
      - `DEBUG=false`
      - `AUTO_CREATE_SCHEMA=false`
      - `APISENTRY_ENABLE_PUBLIC_REGISTRATION=false`
      - `APISENTRY_ENABLE_DEMO_AUTH=false`
      - `APISENTRY_ENABLE_DEMO_CONTROL_PLANE=false`
      - `JWT_SECRET_KEY` = locally generated strong secret (never committed)
      - `CORS_ORIGINS` = exact HTTPS Cloudflare Pages origin(s); no wildcards
      - `DATABASE_URL` = Neon **pooled** runtime URL, injected from secrets
      - `API_KEY` = generated or empty; never placed in any `VITE_*` variable
- [ ] Leave `TRUSTED_PROXIES` unset unless the owner has verified Render's proxy
      address behavior for the chosen plan. Document the decision.
- [ ] Confirm the start command uses one worker and does not enable demo routers
      or request-time enforcement.
- [ ] Confirm `/health` returns HTTP 200 and `/ready` returns HTTP 200 with both
      `database=ok` and `revocation_store=ok`.

## 5. Cloudflare Pages (frontend)

- [ ] Connect the allowlisted repository and configure the production build.
- [ ] Provide `VITE_API_BASE_URL` as the exact HTTPS Render origin (scheme, host,
      and port only; no path, query, fragment, or credentials).
- [ ] Do not define any secret-shaped `VITE_*` variable. The build config
      rejects them before emitting assets.
- [ ] Do not use `frontend/.env.local` or `--emptyOutDir` for the release build.
      Build output goes to the provider-managed directory, not the preserved
      legacy `frontend/dist` in the repository.
- [ ] Confirm the deployed bundle contains the intended backend origin and no
      backend secret.

## 6. Accounts and access

- [ ] Provision the first administrator only with the out-of-band script
      `backend/scripts/provision_admin.py` (requires `--confirm-production` in
      production). Supply the password at run time; never store it in the repo.
- [ ] Create any additional Admin/Analyst/Viewer accounts through the existing
      admin-only endpoints or the same provisioning path.
- [ ] Confirm the registration entry point is hidden in the production UI and
      that direct registration attempts are rejected by the backend.
- [ ] Confirm Viewer accounts see only Overview and Service Status and cannot
      run analysis, mitigation, policy, or user-administration actions.

## 7. Post-deploy acceptance and rollback

- [ ] Exercise the flows in `docs/DEMO_GUIDE.md` for Admin, Analyst, and Viewer.
- [ ] Verify logout revocation: a logged-out token must be rejected on reuse.
- [ ] Verify advisory-only status: production middleware registered = false.
- [ ] Verify cold-start messaging during Render wake-up: bounded `waking` state
      resolves to `online`, `not_ready`, or `offline` within the documented
      90-second window.
- [ ] Rollback plan: restore the previous reviewed configuration and secrets;
      do not enable production enforcement to "fix" an issue. Database rollback
      uses verified backups, not blind Alembic downgrade of revision `0001`.
- [ ] Record observed latency and cost from provider dashboards; both are
      unverified in this repository.

No item in this checklist has been performed by the repository work. Owner
approval is required before starting any of it.
