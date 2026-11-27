# Disposable PostgreSQL Staging Checklist

**Status: NOT EXECUTED.** This is an executable checklist for a future,
owner-approved, disposable PostgreSQL instance. During Prompt 3 no database was
created, contacted, migrated, stamped, or modified; no DDL was run and no
migration was applied. Commands below are future steps only.

Use a distinct, disposable database and role. Never point these commands at a
protected or production database. Inject credentials through the owner's secret
manager; do not place DSNs or passwords in shell history, docs, or git.

## 0. Preconditions

- [ ] Owner has approved the instance, migration window, and rollback owner.
- [ ] Identity of host, port, database name, schema, and application role is recorded.
- [ ] Reviewed Alembic heads are the only schema source of truth:
      `0001_baseline_existing_schema` → `0002_mitigation_policy_models` →
      `0003_mitigation_decision_audit` → `0004_revoked_tokens`.
- [ ] `backend/alembic.ini` contains no embedded URL; `backend/alembic/env.py`
      reads `app.core.config.settings.get_database_url()`.
- [ ] Safe CI suite already passed with the PostgreSQL lifecycle test and SQLite
      baseline DDL test excluded; those exclusions remain in force locally.

## 1. Fresh database initialization

For a genuinely empty database only:

```powershell
# FUTURE ONLY — NOT EXECUTED. Secrets are injected by the host.
$env:PYTHONPATH = 'backend'
python -B -m alembic -c backend/alembic.ini upgrade head
```

Expected final revision: `0004_revoked_tokens`.

If the target is an existing populated schema, **do not run `upgrade` first**.

## 2. Existing schema detection

Read-only inspection only:

```powershell
# FUTURE ONLY — NOT EXECUTED.
$env:PYTHONPATH = 'backend'
python -B -m app.scripts.verify_baseline --mode pre-correction
python -B -m app.scripts.verify_exact_structure --mode pre-correction --expected-owner <approved_owner>
python -B -m app.scripts.verify_exact_structure --mode corrected-users --expected-owner <approved_owner>
```

Interpretation:

- `pre-correction` describes the original unversioned traffic-only baseline.
- `corrected-users` describes traffic plus the guarded users correction result.
- `after-migrations` describes the reviewed head schema including `alembic_version`.
- Any reported drift, unexpected object, or ownership mismatch stops the plan.
  Do not stamp a schema whose verifier reports index/definition drift.

## 3. Read-only baseline verification

- [ ] `verify_exact_structure` exits 0 for the selected mode.
- [ ] Output contains object names/reason codes only; no DSN, credential, traffic
      row, or identity data appears.
- [ ] If later mitigation/revocation tables already exist, do **not** stamp
      `0001`. Escalate for a separate owner-reviewed head-level baseline decision.
- [ ] Confirm that ad hoc `init_db()` DDL is not used as a migration substitute;
      it can diverge (for example, a non-unique `ix_users_email`).

## 4. Backup requirements

- [ ] Take a provider snapshot or verified logical backup before any schema operation.
- [ ] Record backup ID, timestamp, target revision, and restoration owner.
- [ ] Verify the backup can be restored onto a second disposable instance before
      proceeding; a backup that has never been restored is not evidence.
- [ ] Confirm the backup includes users, roles, policies, audits, traffic logs,
      and revocation rows if those are expected to survive the operation.

## 5. Correct migration path

Clean database:

```powershell
# FUTURE ONLY — NOT EXECUTED.
python -B -m alembic -c backend/alembic.ini upgrade head
```

Existing reviewed baseline:

```powershell
# FUTURE ONLY — NOT EXECUTED, and only after verification + backup + owner approval.
python -B -m alembic -c backend/alembic.ini stamp 0001_baseline_existing_schema
python -B -m alembic -c backend/alembic.ini upgrade head
```

Rules:

- `0001` is not idempotent; never run `upgrade head` directly on an existing
  populated baseline.
- `stamp 0001` is correct only when the verified schema matches the reviewed
  traffic/users baseline and has no later mitigation/revocation tables.
- Migrations use direct short-lived `NullPool` connections. Never run them through
  the request pool or the application lifespan.

## 6. Migration verification

```powershell
# FUTURE ONLY — NOT EXECUTED.
$env:PYTHONPATH = 'backend'
python -B -m alembic -c backend/alembic.ini current
python -B -m app.scripts.verify_exact_structure --mode after-migrations --expected-owner <approved_owner>
```

- [ ] `current` reports `0004_revoked_tokens` (head).
- [ ] Exact structure verifier exits 0.
- [ ] Expected tables, columns, indexes, constraints, and sequence ownership match.
- [ ] `alembic_version` contains only the approved head revision.

## 7. User and role persistence

Future owner-approved smoke sequence (no real credentials in this document):

- [ ] Start the app with the injected staging configuration and **one worker**.
- [ ] Provision the first admin only through `backend/scripts/provision_admin.py`
      with `APISENTRY_NEW_ADMIN_PASSWORD` or the interactive prompt and
      `--confirm-production` when `ENVIRONMENT=production`.
- [ ] Confirm login succeeds for admin and analyst fixtures; Viewer sees only
      permitted surfaces.
- [ ] Confirm public registration still returns HTTP 403.
- [ ] Query user rows and role values read-only after restart; compare with the
      pre-restart snapshot.

## 8. JWT revocation persistence

- [ ] Confirm migration `0004_revoked_tokens` exists before claiming durability.
- [ ] Log out with a valid JWT and confirm that reusing the same JWT is rejected.
- [ ] Read only the hash/expiry columns and verify the raw JWT is not stored.
- [ ] Confirm expired-row cleanup is bounded: 500 rows per pass, throttled to
      300 seconds on logout, and one best-effort pass at startup.
- [ ] Confirm cleanup failure is logged but does not block logout or liveness.
- [ ] Without `0004`, revocation is process-local only and must be reported as
      **not durable**.

## 9. Restart durability

- [ ] Record user/role, policy, audit, traffic-log, and revocation counts before restart.
- [ ] Restart the single worker using the approved command; do not use `--reload`.
- [ ] Re-run `/health` and `/ready`; `/ready` must return 200.
- [ ] Repeat one login, one analysis request, and one revoked-token rejection.
- [ ] Confirm the recorded counts and specific rows remain present.

## 10. Policy and audit persistence

- [ ] Create/validate/activate one test policy with an owner-approved fixture.
- [ ] Run one advisory mitigation analysis.
- [ ] Read back the active policy version, decision, and audit event.
- [ ] Confirm hash-chain fields and attribution hashes are stable across restart.
- [ ] Confirm no enforcement action was executed; responses remain advisory-only.

## 11. Traffic-log persistence

- [ ] Generate one bounded synthetic request through the local analysis path.
- [ ] Confirm a corresponding `api_traffic_logs` row persists after restart.
- [ ] Confirm the bounded analysis window limit (10,000 logs/window) returns HTTP
      413 when exceeded, instead of loading an unbounded dataset.
- [ ] Do not copy or load research datasets to populate traffic logs.

## 12. Rollback and recovery

- [ ] Preferred rollback: restore the verified backup onto a disposable instance.
- [ ] Alembic `downgrade` is available for reviewed revisions after `0001`, but
      must be rehearsed on disposable infrastructure before any production use.
- [ ] Revision `0001` is deliberately not downgradeable; restore from backup
      instead of dropping baseline tables.
- [ ] After rollback, re-run the exact-structure verifier and application smoke checks.
- [ ] If configuration is rolled back, keep `ENVIRONMENT=production`,
      `AUTO_CREATE_SCHEMA=false`, explicit HTTPS `CORS_ORIGINS`, and strong secrets.
- [ ] Dispose of the temporary instance only after evidence is captured and owner
      approval is recorded.

## Safe tests versus infrastructure-gated tests

Already run in the safe suite with in-memory SQLite fixtures:

- `backend/tests/test_persistent_auth.py`
- `backend/tests/test_sec01_jwt_revocation.py`
- `backend/tests/test_jwt_revocation_cleanup.py`
- `backend/tests/test_mitigation_policy_persistence_service.py`
- `backend/tests/test_mitigation_decision_persistence_service.py`
- `backend/tests/test_mitigation_audit_persistence_service.py`
- `backend/tests/test_alembic_source_safety.py`
- `backend/tests/test_verify_exact_structure.py`

Deferred until explicit infrastructure approval:

- `backend/tests/test_mitigation_policy_lifecycle_persistence.py` requires a
  dedicated PostgreSQL instance at `127.0.0.1:55444`.
- `backend/tests/test_alembic_baseline.py` performs SQLite DDL.

**NOT VERIFIED here:** real managed-PostgreSQL upgrade/downgrade/stamp timing,
lock behavior, concurrent request pooling under load, multi-worker revocation on
a shared database, and any provider-specific backup/restore mechanism.
