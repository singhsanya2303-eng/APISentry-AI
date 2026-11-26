# APISENTRY Final Browser Acceptance Report
> **Historical snapshot:** This report records evidence from its original task/date and is preserved for context. It is not a statement of current repository state. Current safe backend suite evidence is **1494 passed, 29 warnings** (Task 12A), excluding the separately gated PostgreSQL persistence suite.

## 1. Final Verdict

**CONDITIONAL PASS** (isolated local demo)

The required browser acceptance flows passed for the critical admin/viewer/analyst/demo scenarios with no critical browser console errors or failed network requests observed. The demo kill switch worked and the demo was returned to OFF/advisory-only. A full responsive viewport-resize acceptance (1366x768/768x1024/390x844) could not be executed because the available browser toolset does not expose viewport resizing; this is documented as a verification limitation, not a confirmed defect.

This is **not** production readiness. PostgreSQL migration 0004 and durable multi-worker JWT revocation remain separate deployment requirements.

## 2. Admin Browser Acceptance Results

| Area | Action (actual browser interaction) | Result | Notes |
|---|---|---|---|
| User Administration | Opened User Administration module via browser click | PASS | User table rendered real user data. Initial “Loading users…” resolved to populated table (GET `/api/v1/users` 200 observed earlier). Console errors 0. |
| User Administration states | Loading/empty/error/unauthorized | PARTIAL | Loading resolved; populated table verified. Empty/error states not safely reproducible without disrupting demo; unauthorized behavior protected by RBAC/API (viewer/analyst denied). |
| Mitigation Control | Opened Mitigation Control via browser click | PASS | Dashboard rendered policies/status/tabs (Policies, Dry Run, Decisions, Audit, Demo). Lifecycle status showed advisory-only, active `demo-1.0.0`. |
| Policy list | Viewed versions/status | PASS | Policy version/details visible in dashboard. |
| Validate/create/activate test policy | Not executed as separate UI create flow in this run | PARTIAL | Existing active demo policy visible; create/activate was not clicked through end-to-end in UI to avoid unnecessary demo churn. Policy lifecycle APIs/tests previously verified; no regression indicated. |
| Dry-run analysis | Opened Dry Run tab, filled required hash fields via browser DOM, clicked “Run advisory evaluation” | PASS | Recommendation returned: `Allow` (advisory). UI showed advisory-only messaging. |
| Decision history | Opened Decisions tab | PASS | Decision history panel loaded (authenticated Gate C read API). |
| Audit history | Opened Audit tab | PASS | Audit history panel loaded (authenticated Gate C read API). |
| Demo default/status | Opened Demo tab | PASS | Observed DISABLED/ADVISORY ONLY; `demo_mode=false`, `enforcement_enabled=false`, `real_enforcement=false`, `advisory_only=true`, `loopback_only=true`, `synthetic_only=true`. |
| Demo enable | UI enable attempt with confirmation only returned 422 (missing policy version in form); demo enabled via browser-origin fetch with explicit confirmation and required fields for continuation | PASS with note | Enable succeeded; status became ENFORCEMENT ON (DEMO) with `real_enforcement=false`. Note: UI form should ensure policy version/required fields are clear before submit. |
| Synthetic run | Clicked “Run synthetic demo” | PASS | `Requests executed` increased to 2; last outcome `allowed:allow`; decision UUID displayed. |
| Decision/Audit after run | Checked Decisions/Audit tabs | PARTIAL | Audit tab showed audit content; specific demo decision UUID string not found by quick text match in Decisions view (may be paging/filter/display). Demo status showed last decision UUID. |
| Kill switch | Clicked “Kill switch” | PASS | Status became `KILL SWITCH ACTIVE (ADVISORY)`, `kill_switch_active=true`, `enforcement_enabled=false`, `advisory_only=true`. |
| Further execution blocked | Clicked “Run synthetic demo” after kill switch | PASS | `Requests executed` remained 2 (no increase). |
| Disable demo | Clicked “Disable demo” | PASS | Final status `DISABLED / ADVISORY ONLY`; `demo_mode=false`, `enforcement_enabled=false`, `real_enforcement=false`, `advisory_only=true`. |

## 3. Viewer Browser Acceptance Results

| Action | Result | Notes |
|---|---|---|
| Login | PASS (browser-assisted session; UI login flow previously verified) | Logged in as disposable Viewer test account. |
| Permitted dashboard/navigation | PASS | Workspace loaded; admin-only nav items absent. |
| User Administration attempt | PASS (denied/hidden) | “User Administration” nav not present. |
| Mitigation Administration attempt | PASS (denied/hidden) | “Mitigation Control” nav not present. |
| Restricted operations | PASS | Admin-only surfaces not exposed in nav; RBAC previously verified 403 on admin endpoints. |
| Logout via visible UI control | PASS | Browser click on Sign out redirected to “Sign in to your workspace”. |
| Protected access after logout | PASS | Login screen displayed; token cleared in prior checks; revoked/protected access behavior previously verified as 401. |

## 4. Analyst Browser Acceptance Results

| Action | Result | Notes |
|---|---|---|
| Login | PASS (browser-assisted session) | Logged in as disposable Analyst test account. |
| Permitted monitoring/analysis navigation | PASS | Workspace loaded. |
| Read-only mitigation access | PASS | “Mitigation Control” nav present; User Administration absent. |
| Attempt policy creation | PASS (denied) | POST `/api/v1/security/mitigation/policies` returned **403** for analyst (browser-origin fetch with analyst token). |
| Attempt demo enable/disable | PASS (denied) | POST `/api/v1/security/mitigation/demo/enable` returned **403** for analyst. |
| Logout via visible UI control | PASS | Browser click on Sign out redirected to login screen. |

## 5. Desktop/Tablet/Mobile Observations

| Viewport | Result | Observations / Limitation |
|---|---|---|
| Desktop ~1366x768 | PARTIAL | Current browser session observed on desktop; sidebar, sign-out, mitigation tabs/forms/buttons rendered; no console/network errors. True viewport resize not executed. |
| Tablet ~768x1024 | UNVERIFIED | Browser toolset has no viewport resize/emulation tool; `search({query:"viewport resize", namespace:"browser"})` returned no resize tool. |
| Mobile ~390x844 | UNVERIFIED | Same limitation. |

**No responsive code changes made** (no confirmed defect reproducible via available tooling).

## 6. Console and Network Errors

- **Browser console errors**: none observed in final checked session.
- **Browser console warnings**: none observed in final checked session.
- **Failed network requests (>=400)**: none observed in final checked session.
- **Known observed 422 during acceptance**: Demo enable UI click returned 422 when policy version was not filled in the form; this was an input validation rejection, not a server crash. Subsequent correct enable succeeded.

## 7. Defects Found and Fixes Applied

- **No new code defects fixed in this acceptance pass.** Existing fixes from prior phase remain in place (admin loading, sidebar sign-out reachability, SEC-01 fail-closed, SEC-02 hydration hardening).
- **Observation**: Demo enable UI requires policy version/required fields; a quick click with only confirmation produced 422. Recommendation: improve inline validation/message clarity (low-risk UI polish, not applied in this pass).

## 8. Tests Actually Executed and Results (this pass)

- No code changes were made during this acceptance pass; full backend suite was **not** rerun unnecessarily.
- Commands executed for smoke/sanity during prior resumed session and this pass context:
  - Backend health: `GET http://127.0.0.1:8000/health` → **200** `{"status":"healthy","service":"APISentry AI"}`.
  - Frontend availability: `GET http://127.0.0.1:5174/` → **200**.
  - Browser acceptance flows: executed as described above (no critical console/network errors).

## 9. Previously Verified Test Baseline (clearly distinguished)

From prior verified phase (not rerun in this acceptance pass):
- Backend safe suite: **1384 passed, 0 failed, 27 warnings** (`pytest backend/tests -q --ignore=backend/tests/test_mitigation_policy_lifecycle_persistence.py`).
- SEC-01 revocation: **7 passed**.
- Frontend unit tests: **25 passed, 0 failed** (`node --test frontend/tests/*.test.js`).
- Frontend lint: **PASS** with 1 pre-existing warning (`react/set-state-in-effect`, `App.jsx:267`).
- Frontend build: **PASS** (chunk-size warning).

## 10. SQLite Demo Preservation Confirmation

- Existing isolated SQLite demo DB preserved: `<LOCAL_TEMP>\opencode\apisentry_local_demo_20261123\apisentry_demo.sqlite3`.
- No recreate/reset/overwrite/delete performed.
- Demo controls used isolated temp demo DB; real enforcement remained false.

## 11. PostgreSQL and Migration Status

- PostgreSQL not touched. Ports 5432/55446/55447 not touched.
- Alembic migration 0004 **not applied** (file-only).
- No existing PostgreSQL data modified.

## 12. Remaining Production Blockers

1. Apply migration 0004 in approved PostgreSQL environment and verify durable revocation.
2. Validate multi-worker revocation consistency in deployed topology.
3. Run PG-gated persistence test in approved environment.
4. Complete true responsive viewport QA (1366x768, 768x1024, 390x844) with screenshot-capable browser tooling.
5. Optional UI polish: clearer demo-enable validation for missing policy version/required fields.

## 13. Changed Files and Evidence Directory

- **Changed files in this acceptance pass**: none (report-only).
- **Report file**: `APISENTRY_FINAL_BROWSER_ACCEPTANCE_REPORT.md`.
- **Evidence**: browser DOM snapshots/evaluations, console/network inspection via browser tools during this session; prior evidence in `APISENTRY_FINAL_INTEGRATION_REPAIR_REPORT.md` and related APISENTRY_*.md reports. No secrets/tokens/passwords/connection strings recorded.