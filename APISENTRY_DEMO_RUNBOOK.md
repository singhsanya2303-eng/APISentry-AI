# APISENTRY Demo Runbook (Local, Isolated SQLite)
> **Historical snapshot:** This report records evidence from its original task/date and is preserved for context. It is not a statement of current repository state. Current safe backend suite evidence is **1494 passed, 29 warnings** (Task 12A), excluding the separately gated PostgreSQL persistence suite.

## Safety
- Uses disposable SQLite DB under `<LOCAL_TEMP>\opencode\apisentry_local_demo_20261123`.
- Does **not** modify existing PostgreSQL, `.env`, or ports 5432/55446/55447.
- Gate E demo is default OFF, loopback-only, synthetic-only, explicit confirmation required, bounded, and has kill switch.
- No real enforcement, no external/attack traffic.

## 1) Start backend (isolated demo DB)
```powershell
$dbDir = Join-Path $env:TEMP "opencode\apisentry_local_demo_20261123"
New-Item -ItemType Directory -Force -Path $dbDir | Out-Null
$env:DATABASE_URL = "sqlite:///" + ((Join-Path $dbDir "apisentry_demo.sqlite3").Replace('\','/'))
$env:ENVIRONMENT = "development"
$env:AUTO_CREATE_SCHEMA = "true"
$env:PYTHONPATH = "<PROJECT_ROOT>\backend;<PROJECT_ROOT>"
cd "<PROJECT_ROOT>"
.\.venv\Scripts\python.exe -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
```
Expected: `http://127.0.0.1:8000/health` returns 200.

## 2) Start frontend
```powershell
cd "<PROJECT_ROOT>\frontend"
npm run dev -- --host 127.0.0.1 --port 5174
```
Expected: `http://127.0.0.1:5174/`.

## 3) Demo users
- **Viewer:** register from UI (viewer-only public registration).
- **Admin (isolated demo DB only):** create through controlled script/app context targeting the same temp SQLite DB. Do not run against existing DBs.

## 4) Feature-by-feature demo flow
1. **Auth:** register viewer, login, confirm dashboard, sign out. Login as admin for admin flows.
2. **Overview/API Modules:** confirm API connected and module navigation.
3. **Bot Detection:** open Bot Detection, apply filters, review advisory scores/reasons.
4. **Bot Mitigation:** open Bot Mitigation; show advisory-only banner and filters.
5. **Payload Classifier:** open HTTP Payload Classifier; verify frozen hash/limitations; submit `1 OR 1=1` and `hello`; note margin is not probability.
6. **Mitigation Control > Policies:** inspect active policy, create/validate/activate only with explicit admin intent.
7. **Mitigation Control > Dry Run:** evaluate synthetic context; confirm advisory-only.
8. **Mitigation Control > Decisions/Audit:** review persisted records and integrity limitation note.
9. **Mitigation Control > Demo:** confirm default OFF; enable with `ENABLE_LOCAL_DEMO` + active policy + bounds; run synthetic requests; hit kill switch; disable.

## 5) Sample synthetic inputs
- **Payload benign:** `hello`, `page=1`
- **Payload suspicious (advisory):** `1 OR 1=1`, `<script>alert(1)</script>`
- **Dry-run context:** low-risk and high-risk synthetic `bot_risk_score` values; never real user traffic.

## 6) Known limitations
- Isolated SQLite demo; not approved PostgreSQL production validation.
- In-memory JWT revocation and lifecycle registry are process-local.
- Full browser E2E matrix not exhaustively completed.
- Batch 7 classifier frozen; advisory only.