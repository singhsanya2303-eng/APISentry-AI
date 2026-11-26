# APISENTRY Performance Report
> **Historical snapshot:** This report records evidence from its original task/date and is preserved for context. It is not a statement of current repository state. Current safe backend suite evidence is **1494 passed, 29 warnings** (Task 12A), excluding the separately gated PostgreSQL persistence suite.

## Verdict
- **Performance readiness: NO-GO** (limited local microbenchmarks only; no production/load/infrastructure validation)

## Test Conditions (Local Microbenchmark)
- Date: 2026-11-23 (local run)
- Host: Windows local dev machine (workspace environment)
- Backend: `uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000`
- DB: isolated SQLite demo DB (`<LOCAL_TEMP>\opencode\apisentry_local_demo_20261123\apisentry_demo.sqlite3`, preserved)
- Environment: `ENVIRONMENT=development`, `AUTO_CREATE_SCHEMA=true`
- Tool: Python `urllib.request` loop, loopback HTTP, single process, no concurrent load generator
- **Not production throughput. Not representative of multi-worker/PostgreSQL/network deployment.**

## Measured Results (Local Microbenchmark)
| Endpoint | Requests | Status | Avg ms | P95 ms | Max ms |
|---|---:|---:|---:|---:|---:|
| `GET /health` | 50 | 200 | 30.17 | 34.83 | 103.53 |
| `GET /ready` | 30 | 200 | 27.33 | 38.24 | 45.13 |

## Test Suite Performance (observed)
| Suite | Result | Duration |
|---|---|---|
| Backend safe suite | 1388 passed, 27 warnings, 0 failed | 128.98s |
| Frontend tests | 25 passed, 0 failed | ~0.30s |
| Frontend build | PASS | ~1.86s |

## Not Executed / Blocked
| Area | Status | Reason |
|---|---|---|
| Concurrent load/stress test | Not executed | Requires approved load tooling/environment; avoid false production claims |
| Multi-worker throughput | Not executed | No distributed deployment configured in this pass |
| PostgreSQL query performance | Not executed | PostgreSQL not touched per constraints |
| Memory/CPU profiling under load | Not executed | No profiling/load harness approved |
| Connection exhaustion/timeout recovery | Not executed | Requires controlled environment |
| Large payload streaming behavior | Partially covered | Content-Length size limit tested; chunked streaming cap not implemented |

## Findings
- New security middleware adds minimal overhead in local microbenchmark; no regression observed in test suite.
- Readiness endpoint performs a simple `SELECT 1`; acceptable for local demo, but production should consider health-check frequency and pool impact.
- RequestSizeLimit currently enforces Content-Length; chunked bodies without accurate/early enforcement remain a gap.

## Recommendations
1. Run approved load tests (k6/Locust/JMeter) in isolated staging with PostgreSQL and realistic worker count.
2. Add streaming request body byte counting for chunked requests.
3. Profile DB queries and add indexes where query plans show bottlenecks.
4. Establish SLOs: p95 latency, error rate, saturation thresholds; monitor in production.
5. Report all future benchmarks with exact tool, concurrency, dataset, env, and DB type.