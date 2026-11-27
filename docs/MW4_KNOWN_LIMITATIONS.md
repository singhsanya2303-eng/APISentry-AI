# MW4 Known Limitations Register

| ID | Limitation | Status | Impact | Evidence | Blocks local demo? | Blocks RC? | Blocks production? | Safe next action |
|---|---|---|---|---|---:|---:|---:|---|
| L1 | MW4-B PostgreSQL persistence/auth E2E unverified; ambiguous liveval pgdata/process state preserved | BLOCKED | No PG-backed persistence/auth integration readiness can be claimed | `mw4b_liveval_20261122T183624Z_d91b2c` evidence; P1/P0 reports; no PG actions in MW4-D | No (SQLite/demo paths available) | Partially (PG readiness claim blocked) | Yes | Separate explicit disposition decision for preserved pgdata, then fresh disposable PG retry with strict gates |
| L2 | Authenticated browser E2E not executed | NOT VERIFIED | UI login/logout/role flows and Gate E browser interactions not browser-proven | No Playwright/Cypress/Selenium installed; no browser run; API/TestClient tests pass | No | Partially | Yes | Run approved browser E2E with existing/approved tooling; otherwise supervised manual evidence capture |
| L3 | No representative real-world labeled detection dataset/evaluation | NOT VERIFIED | Cannot claim operational precision/recall/F1/FPR/FNR/generalization | P1 harness is synthetic-rule agreement only; dataset synthetic | No | Partially | Yes | Build/obtain authorized representative labeled dataset; report separate from synthetic agreement |
| L4 | No production latency/throughput/capacity evidence | NOT VERIFIED | Cannot claim production SLO/capacity | P1 benchmark in-process sequential only; no load/stress | No | Partially | Yes | Separate approved bounded performance campaign with clear measurement boundaries |
| L5 | No external penetration test / unbounded adversarial testing | NOT RUN | Security assurance incomplete | Out of scope; static/TestClient checks only | No | Partially | Yes | Separate authorized security assessment in isolated environment |
| L6 | Prototype auth/session/token lifecycle | PARTIALLY VERIFIED | Token storage/revocation/secret management not production-hardened | In-memory revocation, frontend localStorage token, dev/demo auth flows | No | Partially | Yes | Dedicated auth hardening workstream with threat model and tests |
| L7 | Frontend build chunk-size warning | CONFIRMED (non-blocking) | Large JS chunk; performance/maintainability concern | `vite build` warning in P1/MW4-D | No | No | Partially | Code-splitting/optimization in separate approved change |
| L8 | Pre-existing Starlette/httpx test deprecation warnings | CONFIRMED (non-blocking) | Test/tooling noise; future compatibility risk | Pytest warnings in full non-PG suite | No | No | Partially | Separate dependency/tooling upgrade approval |

## Claim boundaries
- **May claim:** local demo RC with advisory MW1/MW2/MW4-A, Gate E isolated synthetic demo, reproducible synthetic harness, non-PG regression green.
- **Must not claim:** PG readiness, production readiness, real-world accuracy, production performance/capacity, external security certification.