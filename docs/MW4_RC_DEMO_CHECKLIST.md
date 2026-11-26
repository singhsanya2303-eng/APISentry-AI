# MW4 Release Candidate Demo Checklist (Local, Safe)

## 0. Safety pre-checks (MANDATORY)
- [ ] Loopback only (`127.0.0.1`/`localhost`); no LAN/public exposure.
- [ ] No PostgreSQL start/stop/connect/restore/migration/repair/cleanup. No touch of MW4-B preserved pgdata.
- [ ] No real traffic, no production enforcement, no production policy activation.
- [ ] Gate E demo default OFF; explicit confirmation required.
- [ ] Use existing supported test identities/fixtures only; no real credentials/secrets.

## 1. Startup prerequisites
- [ ] Repo: `<PROJECT_ROOT>`, existing `.venv`, frontend deps present.
- [ ] Backend/frontend started only if needed and bound to loopback.
- [ ] Temp/demo SQLite paths under system temp.

## 2. Authentication / RBAC expectations
- [ ] Viewer: denied protected analysis/demo mutation flows as applicable; no privilege elevation.
- [ ] Analyst: can read analysis/runtime/demo status/history as permitted; cannot perform admin-only demo mutations.
- [ ] Admin: can perform Gate E enable/run/kill-switch/disable with explicit confirmation.
- [ ] Backend RBAC is authoritative (UI hiding is not security).

## 3. Runtime analysis flow (advisory)
- [ ] Call `GET /api/v1/security/mitigation/runtime-analyze` as analyst/admin.
- [ ] Confirm `advisory_only=true`, `enforcement_executed=false`.
- [ ] Confirm MW1 unified assessment shown (0-100, severity, coverage, uncertainty, signal statuses).
- [ ] Confirm MW2 advisory signals shown separately; no combined score.
- [ ] Confirm missing/error/uncertain states visible; no raw payload/credentials displayed.

## 4. Gate E synthetic demo
- [ ] Confirm status is OFF by default.
- [ ] Enable with explicit confirmation `ENABLE_LOCAL_DEMO` (admin only).
- [ ] Run bounded synthetic requests only.
- [ ] Observe decision/audit records in demo-owned temp SQLite.
- [ ] Activate kill switch; confirm enforcement disabled and further runs rejected as designed.
- [ ] Disable demo; confirm final state OFF/advisory-only and demo state disposed.

## 5. Evidence to capture
- [ ] API responses/screenshots/log excerpts (no secrets).
- [ ] Test command outputs (pytest/node/lint/build).
- [ ] Harness `harness_summary.json` and dataset SHA256.
- [ ] Git status/HASH integrity snapshot.

## 6. Shutdown
- [ ] Disable Gate E demo if enabled.
- [ ] Stop loopback dev processes.
- [ ] Do **not** delete/repair/touch any MW4-B PostgreSQL data dirs or backups.

## 7. Limitations to disclose during demo
- PostgreSQL persistence/auth E2E **BLOCKED/NOT VERIFIED** (MW4-B).
- Browser E2E may be **NOT VERIFIED** if not executed.
- Synthetic benchmark/evaluation only — no real-world accuracy or production performance claims.
- Local demo RC only; not production-ready, not externally exposed, no real enforcement.