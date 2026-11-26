# APISENTRY Feature Verification Matrix
> **Historical snapshot:** This report records evidence from its original task/date and is preserved for context. It is not a statement of current repository state. Current safe backend suite evidence is **1494 passed, 29 warnings** (Task 12A), excluding the separately gated PostgreSQL persistence suite.

**Legend:** PASS = verified working; PARTIAL = implemented but incompletely verified; FAIL = verified broken; BLOCKED = requires approval/external dependency; NOT TESTED = no verification performed.

| Feature | Status | Evidence / Notes |
|---|---|---|
| Backend startup (isolated SQLite demo) | PASS | uvicorn on 127.0.0.1:8000 with temp SQLite env override; `/health` 200. |
| Backend startup with default PostgreSQL config | BLOCKED | Default config targets localhost:5432; cannot touch 5432/existing DBs. |
| Frontend startup | PASS | Vite dev server 127.0.0.1:5174 HTTP 200. |
| CORS for 5174 dev frontend | PASS | Dev CORS fix in `backend/app/main.py`; browser login/register worked. |
| Registration (viewer) | PASS | API 201; browser UI registration landed in dashboard. |
| Login | PASS | Admin and viewer login verified in browser/API. |
| Logout | PASS | Browser logout returned to login; API logout + post-logout `/me` 401 previously verified. |
| JWT validation / revocation | PARTIAL | 29 auth tests passed; logout revocation smoke passed; full expiry/edge matrix not exhaustively rerun. |
| RBAC - viewer restrictions | PASS | Viewer 403 on `/api/v1/users` and policy create; viewer UI hides admin/analyst-only modules. |
| RBAC - admin/analyst access | PARTIAL | Admin smoke passed across mitigation/admin/user endpoints; analyst full UI workflow not exhaustively tested. |
| User management API/UI | PASS (smoke) | `/api/v1/users` 200 for admin; User Administration page rendered real user table. |
| Health endpoint | PASS | `/health` 200. |
| Bot detection API | PASS | `/api/v1/security/bot/analyze` 200. |
| Bot Detection UI | PASS | Browser run returned 4 clients/148 events with advisory output. |
| Behavior/anomaly/rate/bruteforce/BOLA APIs | PARTIAL | Routes wired; covered by backend suite indirectly/partially; not all individually browser-E2E'd. |
| Unified risk / MW4 runtime analyze | PASS | `/api/v1/security/mitigation/runtime-analyze` 200 (API smoke). |
| Bot Mitigation UI | PASS (smoke) | Page rendered, advisory-only banner and filters visible. |
| HTTP payload classifier metadata | PASS | Metadata 200; Batch 7 hash `2d694c932b9779d4971fa418aa35ecdf60cc266fe909b2ea40aa5392c5ae92dc`. |
| HTTP payload classifier predict | PASS | API 200 with `payloads`; browser predict returned ANOMALOUS + advisory margin. |
| Mitigation policy create/validate/activate | PASS | Admin API smoke 201/200/200; Policies tab showed active `demo-1.0.0`. |
| Policy deactivate/retire/rollback | PARTIAL | Implemented/wired; not all executed in this smoke. |
| Dry-run analysis | PASS | API dry-run 200; Dry Run tab rendered. |
| Decision history | PARTIAL | Endpoint present; tab rendered; full row/detail E2E not exhaustive. |
| Audit history | PARTIAL | Endpoint present; tab rendered; full row/detail E2E not exhaustive. |
| Gate E demo controls | PASS | API smoke: status/enable/run/kill-switch/disable 200 with safe guards. Demo tab showed safety boundary/default off. |
| Demo safety restrictions | PASS | Loopback-only, synthetic-only, explicit confirmation, bounded, kill switch observed. |
| Dashboard navigation | PASS (smoke) | Admin nav showed all expected modules; key pages rendered. |
| Error/loading/empty states | PARTIAL | Some loading states observed; not systematically validated across all components. |
| Responsive layout | NOT TESTED | No viewport/responsive E2E pass. |
| Frontend lint/build | PASS | `npm run lint` and `npm run build` passed. |
| Frontend node tests | PASS | 25/25 passed. |
| Targeted backend tests | PASS | 134 passed, 22 warnings. |
| Full safe backend suite | PASS | 1372 passed, 27 warnings, PG-gated excluded. |
| PostgreSQL compatibility/persistence | BLOCKED | No approved PG access; ports 5432/55446/55447 restricted. |
| SQLite demo compatibility | PARTIAL | Core flows passed; not production parity guarantee. |