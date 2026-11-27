# APISENTRY Role-Based E2E Matrix
> **Historical snapshot:** This report records evidence from its original task/date and is preserved for context. It is not a statement of current repository state. Current safe backend suite evidence is **1494 passed, 29 warnings** (Task 12A), excluding the separately gated PostgreSQL persistence suite.

## Environment
- Isolated local demo only: frontend `http://127.0.0.1:5174/`, backend `http://127.0.0.1:8000/`
- Isolated disposable SQLite: `<LOCAL_TEMP>\opencode\apisentry_local_demo_20261123\apisentry_demo.sqlite3`
- No existing PostgreSQL touched; no ports 5432/55446/55447 used.
- Disposable accounts created in isolated DB: `e2e_viewer_20261123` (viewer), `e2e_analyst_20261123` (analyst), `e2e_admin_20261123` (admin).
- Browser evidence: Chromium in-app browser via browser tools; screenshot capture unavailable (requires visible desktop window). Evidence based on DOM snapshots, `document.body.innerText`, console/network inspection.

## Matrix

| Area | Viewer | Analyst | Admin | Evidence | Result |
|---|---|---|---|---|---|
| Login | Pass | Pass | Pass | DOM showed "Security Workspace" after login; role labels Viewer/Analyst/Administrator observed | PASS |
| Role nav visibility | Pass (no User Administration, no Mitigation Control) | Pass (no User Administration, has Mitigation Control) | Pass (has User Administration & Mitigation Control) | DOM text checks after login | PASS |
| Dashboard/Overview load | Observed | Observed | Observed | Workspace/Overview text visible | PASS (smoke) |
| User Administration page | N/A (hidden) | N/A (hidden) | **Partial/Issue** | Admin page renders but shows "Loading users…" despite `/api/v1/users` returning 200 in network; console error count 0 | **ISSUE** |
| Mitigation Control page | N/A (hidden) | Not fully exercised | **Partial/Issue** | Page shows "Loading mitigation administration…" despite mitigation API 200 responses; console error count 0 | **ISSUE** |
| Bot Detection nav | Not fully exercised | Not fully exercised | Navigated, page rendered heading | DOM text contained "Bot Detection" | PARTIAL |
| HTTP Payload Classifier nav | Not fully exercised | Not fully exercised | Navigated | DOM contained payload text; Batch 7 hash not visibly asserted in UI text | PARTIAL |
| Threat Analysis / other modules | Not fully exercised | Not fully exercised | Not fully exercised | Time/budget constrained | NOT FULLY COVERED |
| Logout via UI button | **Issue** | **Issue** | **Issue** | Sign out button click unreliable in sampled flow (UnknownVizError/stale/no effect); logout via API token removal+reload worked | **ISSUE** |
| Unauthorized actions (API-level expectation) | Role nav hidden; API RBAC covered by backend tests | Role nav hidden; API RBAC covered by backend tests | N/A | Backend RBAC tests pass in full suite | PARTIAL (UI/API mix) |
| Invalid forms/API errors | Not exhaustively exercised in browser | Not exhaustively exercised | Not exhaustively exercised | Backend validation tests pass | NOT FULLY COVERED |
| Loading/empty states | Not fully covered | Not fully covered | User Admin/Mitigation Control stuck loading observed | DOM evidence | PARTIAL/ISSUE |
| Console errors | 0 observed in sampled flows | 0 observed | 0 observed | `browser.console` checks | PASS (sampled) |
| Responsive desktop/mobile | Not exercised | Not exercised | Not exercised | Browser viewport/responsive tooling not completed | NOT COVERED |

## Key Findings
- **RBAC nav visibility is correct** for the three disposable roles.
- **User Administration and Mitigation Control pages can remain stuck in "Loading…"** in the admin browser session even when backend APIs return 200. Console shows no errors; likely frontend state/rendering or response-shape handling issue. Needs investigation.
- **UI Sign out button was unreliable** in automation; programmatic logout (clear token + reload) works. Could be clickability/overlay issue.
- Full end-to-end coverage of all requested modules/forms/error states/responsive views was **not completed** within this session.

## Verdict
**PARTIAL** — core role-based login/nav visibility verified; significant UI loading/logout gaps remain.