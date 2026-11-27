# APISENTRY Security Review
> **Historical snapshot:** This report records evidence from its original task/date and is preserved for context. It is not a statement of current repository state. Current safe backend suite evidence is **1494 passed, 29 warnings** (Task 12A), excluding the separately gated PostgreSQL persistence suite.

## Scope
Read-only code inspection, targeted runtime smoke, browser E2E smoke, and automated tests on an isolated local SQLite demo. No secrets read/exposed. No existing PostgreSQL/ports 5432/55446/55447 touched. Batch 7 frozen.

## Confirmed controls
| Area | Status | Evidence |
|---|---|---|
| Authentication | PASS | JWT login/register/me endpoints; 29 auth tests passed; browser login/register/logout worked. |
| Password hashing | PASS | bcrypt 12 rounds with PBKDF2 backward compatibility in `core/security.py`. |
| RBAC | PASS | Viewer 403 on admin endpoints; viewer UI hid analyst/admin modules; admin accessed mitigation/user admin. |
| Token invalidation | PARTIAL | Logout revokes token in in-memory set; post-logout `/me` 401 verified. Not durable across restart. |
| CORS | PASS | Restricted origins; dev-only 5174 added; no wildcard. |
| Input validation | PASS | Pydantic schemas; payload classifier returns generic 422 on invalid request; 134+ targeted tests pass. |
| Demo safety (Gate E) | PASS | Default OFF, loopback-only, synthetic-only, explicit `ENABLE_LOCAL_DEMO`, bounded requests/duration, kill switch, temp SQLite isolation. |
| Advisory-only posture | PASS | Bot/Mitigation/Payload UIs show advisory banners; no production enforcement middleware observed. |
| Frozen classifier | PASS | Metadata/predict report artifact hash `2d694c932b9779d4971fa418aa35ecdf60cc266fe909b2ea40aa5392c5ae92dc`. |
| Audit/decision integrity claims | PARTIAL | Audit UI states hashes are content digests, not tamper-evident chain. Good transparency. |

## Findings / risks
| ID | Severity | Status | Finding | Recommendation |
|---|---|---|---|---|
| SEC-01 | Medium | Open | JWT revocation is in-memory (`_REVOKED_TOKENS`); lost on restart/multi-instance. | Durable revocation/denylist or short-lived tokens + refresh; approved design change. |
| SEC-02 | Medium | Open | Mitigation lifecycle registry is process-local in-memory; can diverge from persisted DB after restart. | Hydrate/reconcile from Gate B persistence on startup; add regression test. |
| SEC-03 | Low | Open | SQLite demo validated; PostgreSQL production parity not validated. | Run approved isolated PostgreSQL validation before production claims. |
| SEC-04 | Low | Mitigated (dev) | CORS 5174 added in code for dev. | Keep production CORS env-driven. |
| SEC-05 | Info | Open | Demo status after disable may retain `kill_switch_active`/`active_demo_id` semantics that can confuse operators while mode/enforcement are off. | Clarify status semantics; ensure no enforcement possible regardless. |

## Not performed
- Full SAST/DAST, dependency CVE audit, penetration testing, secret-history scan.
- Full authz matrix across every endpoint/role.
- PostgreSQL production hardening review.