# APISENTRY Known Limitations
> **Historical snapshot:** This report records evidence from its original task/date and is preserved for context. It is not a statement of current repository state. Current safe backend suite evidence is **1494 passed, 29 warnings** (Task 12A), excluding the separately gated PostgreSQL persistence suite.

## Verdict
**CONDITIONALLY COMPLETE** — functional isolated local SQLite demo with key flows verified. Not COMPLETE.

## Verification limits
- PostgreSQL compatibility/migrations on approved PG: **BLOCKED** (ports 5432/55446/55447 and existing DBs protected; separate explicit approval required).
- PG-gated test `backend/tests/test_mitigation_policy_lifecycle_persistence.py` not run.
- Full browser E2E across every panel/role/error/empty/loading/responsive state not exhaustive.
- Full concurrency/load/restart durability not validated.

## Runtime / architecture
- **JWT revocation in-memory:** revoked tokens lost on restart/multi-instance.
- **Mitigation lifecycle registry in-memory:** process-local singleton may diverge from persisted Gate B state after restart; reconciliation not verified.
- **SQLite demo only:** not a production-equivalent substitute for approved PostgreSQL.
- **Dev auto-create schema:** convenient for demo; production should use reviewed Alembic migrations.

## Security / product boundaries
- **Advisory only:** detection/mitigation outputs do not enforce real blocking/throttling/banning in production paths.
- **Gate E demo:** loopback-only, synthetic-only, explicit confirmation, bounded, kill-switch, isolated temp SQLite. Do not expose publicly.
- **Payload classifier Batch 7 frozen:** hash `2d694c932b9779d4971fa418aa35ecdf60cc266fe909b2ea40aa5392c5ae92dc`; margins are not probabilities/confidence; research-only limitations apply.

## Operational
- No package installs/upgrades performed; dependency/CVE audit not run.
- No `.env`/secrets changed or exposed.
- Pre-existing dirty/untracked worktree preserved.