# APISentry MW4-C P1 — Security, Privacy, and Limitations

## Security model (local prototype)
- **Trust boundaries:** browser/UI -> FastAPI (loopback in demo) -> services -> app DB / demo temp SQLite. No external trust assumed.
- **Auth:** HS256 JWT with signature/exp/revocation checks; DB-preferred user; claims fallback for verified tokens; active-account check. Static X-API-Key for system-to-system analysis routes.
- **RBAC:** server-side `RequireRole` and `require_analyst_or_api_key`. Viewer denied protected analysis/demo mutations. Frontend hiding is not enforcement.
- **Privacy:** no raw payloads, credentials, cookies, or sensitive header values in MW1/MW2 evidence or demo audit surfaces. Opaque refs only.
- **Demo safety:** default OFF, loopback-only, synthetic-only, explicit confirmation, bounded requests/duration, kill switch, fail-closed guards, temp SQLite under system temp, path escape guard.

## Limitations (explicit)
- **MW4-B PostgreSQL verification BLOCKED.** No PG persistence/auth E2E readiness claim. Preserved ambiguous pgdata untouched.
- **No production accuracy claims.** Synthetic benchmark/evaluation only; no representative production-labeled dataset; no real-world P/R/F1/FPR/FNR/generalization.
- **No production performance/capacity claims.** In-process sequential bounded timings only.
- **Browser E2E:** may be NOT VERIFIED if no browser automation tooling/session executed; API/TestClient RBAC evidence is not browser proof.
- **Auth limitations:** token storage/revocation model is prototype-grade; in-memory revocation set and demo seed flows have local-dev constraints. No secret rotation/revocation infrastructure claim.
- **Demo not enforcement:** Gate E is isolated synthetic local demonstration only.

## Adversarial/input handling (bounded)
- Pydantic validation rejects malformed/invalid fields (422). Demo service rejects non-loopback, invalid confirmation, bad state (409), and bounded limits.
- Missing/error detector signals must be represented explicitly; no fabricated clean result.
- Fail-closed on evaluation/persistence errors in demo.

## Out of scope / not performed in P1
- PostgreSQL start/stop/connect/restore/migration/repair.
- External deployment, LAN/public exposure, real traffic, production enforcement.
- Unbounded load/stress/fuzzing or destructive pentest.
- Batch 7 model retraining/replacement.