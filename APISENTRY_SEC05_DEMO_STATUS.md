# APISENTRY SEC-05 — Demo Status Semantics Hardening
> **Historical snapshot:** This report records evidence from its original task/date and is preserved for context. It is not a statement of current repository state. Current safe backend suite evidence is **1494 passed, 29 warnings** (Task 12A), excluding the separately gated PostgreSQL persistence suite.

## Status
**Implemented** — backend/frontend status semantics aligned; regression tests added.

## Problem
Demo disable/kill-switch/readiness/partial-failure states could be ambiguous. Frontend and backend needed explicit, consistent status semantics.

## Fix Applied
- `backend/app/services/mitigation_demo_service.py`
  - `get_status()` now returns explicit `expired`, `status_reason`, and `real_enforcement=False`.
  - `status_reason` values: `disabled`, `kill_switch_active`, `expired`, `active_demo_enforcement`, `advisory_only`.
  - `disable_demo()` returns clean off/advisory state: `demo_mode=False`, `enforcement_enabled=False`, `kill_switch_active=False`, clears active demo metadata; keeps `real_enforcement=False`.
  - `kill_switch()` keeps demo context but forces advisory-only/non-enforcing state with explicit reason.
  - Expired demo is reported as advisory/non-enforcing with `expired=True`.
- `backend/app/schemas/mitigation_demo.py`
  - `DemoStatusResponse` extended additively with `expired`, `status_reason`, `real_enforcement`.
- `frontend/src/components/MitigationDemoPanel.jsx`
  - Displays explicit status badge/reason for disabled, kill-switch, expired, active demo, advisory-only.
  - Shows `real_enforcement` and `expired` fields. No real enforcement UI introduced.

## Tests
- Extended `backend/tests/test_mitigation_demo_enforcement.py` — **21 passed** total.
  - disable status clean/distinct
  - expired demo reported as advisory with explicit semantics
  - kill-switch status explicit

## Residual Risk
- UI "Loading mitigation administration..." was observed in browser E2E despite 200 API responses; this appears to be frontend state/render issue, not a SEC-05 backend semantic mismatch. Reported in E2E matrix/blockers.
