# APISentry MW4-C P1 — API Reference (Verified Scope)

> Evidence-based reference for key mitigation/runtime/demo endpoints. Not exhaustive of all legacy analysis routes. Verify against `backend/app/api/v1/router.py` and route modules.

## Authentication
- **JWT Bearer**: `Authorization: Bearer <token>`; server verifies HS256 signature/exp/revocation; DB-preferred user with claims fallback.
- **API Key**: `X-API-Key: <configured key>` for system-to-system access on protected analysis routes.
- **RBAC roles**: `admin`, `analyst`, `viewer`. Backend enforcement is authoritative.

## Key endpoints

| Method | Path | Auth | Role | Purpose | Advisory/Enforcement |
|---|---|---|---|---|---|
| GET | `/api/v1/health` | None | - | API health | N/A |
| GET | `/api/v1/security/mitigation/analyze` | JWT or API key | analyst/admin/API key | Legacy Stage 1+Stage A mitigation analysis | Advisory only |
| GET | `/api/v1/security/mitigation/runtime-analyze` | JWT or API key | analyst/admin/API key | MW4-A runtime: bot detection + MW2 + MW1 + Stage A mitigation | Advisory only, no combined score |
| GET | `/api/v1/security/mitigation/policies` | JWT | analyst/admin | List policies | Read-only |
| POST | `/api/v1/security/mitigation/policies` | JWT | admin | Propose policy | Lifecycle admin |
| POST | `/api/v1/security/mitigation/policies/{version}/validate` | JWT | admin | Validate policy | Lifecycle admin |
| POST | `/api/v1/security/mitigation/policies/{version}/activate` | JWT | admin | Activate policy | Lifecycle admin (no production enforcement) |
| POST | `/api/v1/security/mitigation/policies/{version}/deactivate` | JWT | admin | Deactivate policy | Lifecycle admin |
| POST | `/api/v1/security/mitigation/policies/{version}/retire` | JWT | admin | Retire policy | Lifecycle admin |
| POST | `/api/v1/security/mitigation/dry-run` | JWT | analyst/admin | Advisory dry-run evaluation | Advisory only; no state mutation beyond read |
| GET | `/api/v1/security/mitigation/decisions` | JWT | analyst/admin | Decision history | Read-only |
| GET | `/api/v1/security/mitigation/audit-events` | JWT | analyst/admin | Audit history | Read-only |
| GET | `/api/v1/security/mitigation/demo/status` | JWT | analyst/admin | Gate E demo status | Demo-only state |
| POST | `/api/v1/security/mitigation/demo/enable` | JWT | admin | Enable Gate E demo (explicit confirmation required) | Demo-only, default OFF |
| POST | `/api/v1/security/mitigation/demo/run` | JWT | admin | Run bounded synthetic demo requests | Demo-only synthetic |
| POST | `/api/v1/security/mitigation/demo/kill-switch` | JWT | admin | Immediate demo kill switch | Demo-only safety |
| POST | `/api/v1/security/mitigation/demo/disable` | JWT | admin | Disable and dispose demo-owned state | Demo-only cleanup |

## Common error conditions
- `401 Unauthorized`: missing/invalid/expired/revoked JWT or missing/invalid API key.
- `403 Forbidden`: authenticated but insufficient role (e.g., viewer on analyst/admin route; analyst on admin mutation).
- `422 Unprocessable Content`: schema/validation error (e.g., missing demo confirmation, invalid synthetic payload).
- `409 Conflict`: invalid demo state (e.g., post-kill-switch run, wrong demo_id).
- `503 Service Unavailable`: auth not configured where required.

## Runtime-analyze response (high level)
- `detection`: BotDetectionResponse
- `runtime_results[]`: per-result MW2 `AdvancedDetectionEnvelope`, MW1 `UnifiedRiskAssessment` or `mw1_error`, `mw1_status`, `signal_normalization`, `advisory_only=true`
- `mitigation`: Stage A advisory integration result
- `uncertainty`, `timings_ms`, `advisory_only=true`, `enforcement_executed=false`

## Security notes
- No raw payloads, credentials, cookies, or sensitive headers in evidence/response contracts.
- Demo endpoints are loopback-only guarded at service layer; synthetic-only; bounded; temp SQLite; no production enforcement.
- PostgreSQL-backed persistence endpoints are present but PG verification is MW4-B BLOCKED; P1 did not run PG.