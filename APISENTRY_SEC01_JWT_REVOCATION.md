# APISENTRY SEC-01 — JWT Revocation Hardening
> **Historical snapshot:** This report records evidence from its original task/date and is preserved for context. It is not a statement of current repository state. Current safe backend suite evidence is **1494 passed, 29 warnings** (Task 12A), excluding the separately gated PostgreSQL persistence suite.

## Status
**Implemented in isolated demo / codebase (CONDITIONAL)** — safe fix applied; durable cross-process PostgreSQL revocation requires separate explicit approval.

## Problem
Logout did not reliably invalidate JWTs for reuse. In-memory-only revocation was insufficient for restart/multi-worker consistency; no persistent revocation record existed.

## Fix Applied
- `backend/app/core/security.py`
  - Added hash-based revocation tracking (`SHA-256` of token) with in-memory expiry map and cleanup.
  - Added optional DB-backed revocation persistence/fallback via `RevokedToken` (`is_token_revoked`, `revoke_token`, cleanup).
  - `decode_access_token(..., db=None)` now checks revocation **after** signature/expiry validation. Revoked tokens raise `ValueError("Token has been revoked")`.
  - `require_jwt_auth` passes DB session to decode; revocation is enforced on authenticated requests.
  - No JWT contract/signature/expiry/role validation semantics changed except revocation rejection.
- `backend/app/api/v1/routes/auth.py`
  - Logout calls `revoke_token(credentials.credentials, db=db)` and returns success only after revocation path executes.
- `backend/app/models/revoked_token.py` (new)
  - Minimal revocation table: `id`, `token_hash` (unique/indexed), `expires_at` (indexed), `revoked_at`.
- `backend/app/models/__init__.py`, `backend/app/db/init_db.py`
  - Registered model/import for metadata/create_all compatibility.
- `backend/alembic/versions/0004_revoked_tokens.py` (new, additive)
  - Creates `revoked_tokens` table/indexes. **File only; not applied to existing PostgreSQL DBs.**

## Security Properties
- Logout invalidates token for reuse in the same process (in-memory) and in DB-backed mode when DB is available.
- Restart behavior: DB-backed revocation is checked when in-memory cache is empty/cold (validated by test simulating restart by clearing in-memory maps).
- Expired tokens are not treated as active revocations; cleanup removes expired in-memory entries.
- No secrets/tokens logged; only hash stored.

## Tests
- Added `backend/tests/test_sec01_jwt_revocation.py` — **5 passed**.
  - logout revokes token and rejects reuse
  - revoked token rejected by decode with DB
  - expired token not treated as active revocation
  - restart behavior uses DB revocation
  - expired in-memory cleanup
- Existing auth tests passed: `backend/tests/test_jwt_authentication.py` (included in full suite pass).

## Residual Risk / Blockers
- **True multi-worker revocation consistency** requires shared persistent store in all workers; in isolated demo SQLite works for single-process, but durable PostgreSQL deployment requires explicit approval to apply additive migration `0004_revoked_tokens` to approved target DB.
- Existing PostgreSQL DBs at 5432/55446/55447 were **not** touched/migrated.
- Revocation table growth needs periodic cleanup job in production (cleanup function exists; scheduling is deployment concern).
