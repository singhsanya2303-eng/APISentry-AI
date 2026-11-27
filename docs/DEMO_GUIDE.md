# APISentry Demo Guide

This guide describes the **repository-supported** academic/portfolio demo. It
assumes the owner has completed and authorized the provider setup in
`docs/OWNER_SETUP_CHECKLIST.md`. It does not perform deployment, create data, or
change thresholds.

## 1. Demo boundaries

Default demo:

- One backend worker, advisory-only enforcement, no Gate E/WP9, no public
  registration.
- Deterministic risk scoring, BOLA, brute-force, rate anomaly, bot detection,
  clustering comparison, token usage classifier, and advisory mitigation
  composition.
- Viewer accounts are read-only; Admin and Analyst roles run analysis.

Explicitly outside the default demo:

- Stacked-autoencoder traffic trends, HTTP payload classifier, CSIC, SR-BH/WAMM,
  offline training, capture tooling, demo control plane/auth, and request-time
  enforcement experiments.
- Any claim of real-world detection effectiveness, production blocking, or
  multi-worker durability.

If a service or artifact is unavailable, show the explicit failure state. Do
not substitute a score, hide the error, or change a threshold to improve a demo.

## 2. Sign-in and account policy

- The production login screen has no "register" entry point. Accounts are
  created by the owner via `backend/scripts/provision_admin.py` and the existing
  admin-only user endpoints.
- Use the three role accounts prepared by the owner: Admin, Analyst, Viewer.
- The frontend stores only the bearer JWT locally. A 401 response clears the
  session and returns to login.

## 3. Cold-start / readiness walkthrough

After a Render free-tier wake-up, the status pill and banner move through:

| State | Meaning | UI behavior |
|---|---|---|
| `checking` | First probe in progress | "Checking API"; refresh disabled |
| `waking` | Health not answered yet, retries remaining | "Backend is waking up"; bounded backoff |
| `online` | `/health` and `/ready` both succeeded | "API Connected"; metrics usable |
| `not_ready` | Health answered but readiness failed | "Service not ready"; check dependency state |
| `offline` | Bounded window ended without success | "API Offline"; refresh available |

Bounds: at most 11 attempts, 80 seconds of cumulative backoff, 90-second total
deadline, 4-second request timeout. Cancellation occurs on unmount, logout, or
an unauthorized event. Manual refresh always clears its own spinner.

`/ready` includes two checks: `database` and `revocation_store`. A demo is not
ready unless both are `ok`.

## 4. Admin walkthrough

1. Sign in and confirm the status banner reaches `online`.
2. Open **Security Overview** and confirm health/readiness values come only
   from the backend endpoints.
3. Run the deterministic modules (risk, BOLA, brute-force, rate anomaly, bot
   detection) with small synthetic inputs. Confirm results are analysis, not
   enforcement.
4. Open **Mitigation Control** and confirm advisory composition reports
   `advisory_only=true` and no enforcement execution.
5. Open **User Administration** and confirm role changes require Admin.
6. Log out, then reuse the old token directly: it must be rejected. In
   production, a missing revocation store causes logout to fail visibly rather
   than claim success.

## 5. Analyst walkthrough

1. Sign in and confirm the same bounded readiness states.
2. Run the read-only analysis modules available to Analyst.
3. Confirm mitigation/policy administration is not available to Analyst.
4. Confirm an unsupported or unavailable module returns an explicit error, not
   a fabricated result.

## 6. Viewer walkthrough

1. Sign in with a Viewer account.
2. Confirm the page title is "Viewer Overview" and navigation contains only
   **Overview** and **Service Status**.
3. Confirm the read-only cards show: signed-in role, backend status, readiness
   state, and last checked time. Values come from `/health`, `/ready`, and the
   authenticated profile endpoint only.
4. Confirm the copy explicitly lists unavailable actions: analysis runs,
   mitigation changes, policy changes, and user administration.
5. Try a protected endpoint directly (for example via the browser's network
   tooling): the backend must reject it even if the UI were manipulated.

## 7. Optional modules (only with owner approval)

- Token usage classifier: use only the trusted, hash-verified local artifact.
  If it is absent, show `available=false` / HTTP 503.
- Clustering: supply at least 10 finite numeric feature vectors; invalid input
  returns 422.
- Traffic trends and payload classifier: keep off the minimum path. They have
  substantially higher memory cost and stricter artifact requirements.

## 8. Demo anti-patterns

- Do not present advisory decisions as blocked traffic.
- Do not claim SQLite tests validate PostgreSQL or multi-worker behavior.
- Do not publish screenshots containing local secrets, tokens, or DSNs.
- Do not build into or publish the legacy `frontend/dist` directory.
- Do not run public registration or demo auth endpoints in production.
- Do not treat a repository release candidate as a deployed application.
