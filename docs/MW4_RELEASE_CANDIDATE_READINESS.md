# MW4 Release Candidate Readiness (Local Demo RC)

- **Run:** MW4-D RC evidence `mw4d_rc_20261122T194206Z_d91c55` (this phase)
- **Baseline:** MW4-C P1 `mw4c_p1_20261122T192911Z_c7a24f` (CONDITIONAL PASS)
- **Date:** 2026-11-22
- **Verdict:** **CONDITIONAL GO — Local demo release candidate only**

## 1. Product scope
APISentry AI is a local FastAPI + React prototype for API traffic analysis, advisory bot/MW2 detection, MW1 unified risk assessment, MW4-A runtime orchestration, mitigation policy lifecycle (Gate A-C), and a default-off isolated synthetic Gate E demonstration. It is **not** production-certified.

## 2. Implemented capabilities (CONFIRMED)
- **MW1 Unified Risk Assessment:** sole 0–100 risk owner; bounded severity; contributions/reasons/signal statuses/coverage/uncertainty/provenance; missing/error/invalid signals explicit; no fabricated probability/confidence.
- **MW2 Advanced Advisory Detection:** separate advisory envelope; structured statuses/caps/provenance/uncertainty; no combined score; no enforcement decision.
- **MW4-A Runtime Orchestration:** `GET /api/v1/security/mitigation/runtime-analyze` composes MW2 then MW1 per result; advisory-only; `enforcement_executed=false`.
- **Mitigation lifecycle/admin:** Gate A lifecycle, Gate B persistence services, Gate C authenticated admin/read APIs, Gate D dashboard, Gate E isolated demo.
- **Gate E demo:** default OFF, loopback-only, synthetic-only, explicit confirmation, temp SQLite demo-owned, kill switch, disable disposes demo state, no PG/original DB.
- **Frontend:** runtime analyze client + MW1/MW2 advisory display; role-aware dashboard; demo controls; lint/build clean.

## 3. Verified integration paths (CONFIRMED / PARTIALLY VERIFIED)
| Path | Status | Evidence |
|---|---|---|
| MW4-A runtime endpoint auth/RBAC | CONFIRMED | `require_analyst_or_api_key`; viewer 403, missing auth 401/503; P1/MW4-D RBAC tests |
| MW2->MW1 orchestration | CONFIRMED | `orchestrate_mw4_runtime` code/tests; P1 harness 0 errors |
| Frontend runtime API wrapper | CONFIRMED | `frontend/src/services/api.js` `mitigationRuntimeAnalyze` -> `GET /api/v1/security/mitigation/runtime-analyze` |
| Gate E enable/run/kill-switch/disable (TestClient) | CONFIRMED | `test_mitigation_demo_enforcement.py`, P0-B 18/18 evidence |
| Gate E browser UI flow | NOT VERIFIED | No browser automation tooling; no live browser run |

## 4. Backend and frontend verification
- **Backend:** full non-PG suite expected green per P1 (1370 passed, 27 warnings) with pg-gated test excluded; MW4-D targeted regressions run (see final report).
- **Frontend:** 25 node tests pass (P1 baseline); lint/build pass.
- **Harness:** P1 reproducibility confirmed (same seed/hash `3c9f18292d25df1893d5e18465707648380b94784d82d8367ba67c40745ff1dc`, 180 cases).

## 5. Authentication and RBAC status
- **CONFIRMED:** JWT HS256 verification, expiry/revocation checks, DB-preferred user with claims fallback, active-account check. Static X-API-Key for system-to-system analysis.
- **CONFIRMED:** Server-side RBAC authoritative; viewer denied protected analysis/demo status/mutations as applicable; admin required for demo mutations.
- **PARTIALLY VERIFIED:** prototype token storage/revocation model; browser-auth E2E not verified.

## 6. Gate E safety properties (CONFIRMED)
Default OFF; loopback-only; synthetic-only; explicit confirmation `ENABLE_LOCAL_DEMO`; bounded requests/duration; temp SQLite under system temp; path escape guard; kill switch effective; disable disposes demo-owned state; no PostgreSQL/original DB; no external exposure; no real enforcement.

## 7. Demo prerequisites
- Existing `.venv`, Node/npm, repo deps already installed.
- Run on loopback only; use isolated temp SQLite for demo.
- Do not touch PostgreSQL/MW4-B preserved dirs.
- Use existing supported test identities/fixtures; no real credentials.

## 8. Known blockers
- **BLOCKED:** MW4-B PostgreSQL persistence/auth E2E (ambiguous liveval pgdata preserved; no PG actions).
- **NOT VERIFIED:** authenticated browser E2E; real-world detection accuracy; production latency/capacity; external pentest.

## 9. Recommendation
**CONDITIONAL GO** for controlled local demo/release-candidate review only. **NO-GO** for production deployment, real enforcement, public exposure, or claims of PG readiness/accuracy/capacity.