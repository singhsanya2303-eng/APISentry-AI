# APISentry MW4-C P1 — Architecture and Integration (Verified Scope)

> Status: evidence-backed documentation for the local prototype. Not a production certification.

## 1. System purpose
APISentry is a local FastAPI + React prototype for API traffic analysis, advisory threat detection, unified risk assessment, mitigation policy lifecycle management, and a default-off synthetic local enforcement demonstration (Gate E).

## 2. High-level architecture

```mermaid
flowchart LR
  subgraph FE[Frontend - React/Vite]
    UI[Dashboard / Mitigation UI]
    APIJS[services/api.js]
  end
  subgraph BE[Backend - FastAPI]
    R[API Router / Auth deps]
    BOT[Bot Detection]
    MW2[MW2 Advanced Advisory Detection]
    MW1[MW1 Unified Risk Assessment]
    MW4[MW4-A Runtime Orchestration]
    MIT[Mitigation Integration / Gate C APIs]
    DEMO[Gate E Demo Service]
  end
  subgraph DATA[Persistence]
    SQL[(App DB: SQLite dev/test; PostgreSQL target - MW4-B BLOCKED)]
    DEMOSQL[(Gate E temp SQLite - isolated, demo-owned)]
  end

  UI --> APIJS --> R
  R --> BOT --> MW4
  MW4 --> MW2
  MW4 --> MW1
  MW4 --> MIT
  R --> MIT --> SQL
  R --> DEMO --> DEMOSQL
```

## 3. Runtime orchestration flow (MW4-A)

```mermaid
sequenceDiagram
  participant C as Client (Analyst/Admin/API key)
  participant R as /security/mitigation/runtime-analyze
  participant B as Bot Detection
  participant M2 as MW2 build_advisory_envelope
  participant M1 as MW1 assess_risk
  participant I as Stage A Mitigation Integration

  C->>R: GET (auth required)
  R->>B: analyze_bot_traffic()
  B-->>R: BotDetectionResponse
  loop per detection result
    R->>M2: snapshots from BotAnalysisResult
    M2-->>R: AdvancedDetectionEnvelope (advisory)
    R->>M1: unified risk input
    M1-->>R: UnifiedRiskAssessment (0-100, owner)
  end
  R->>I: advisory mitigation orchestration
  I-->>R: MitigationIntegrationResult
  R-->>C: detection + runtime_results + mitigation (advisory_only)
```

## 4. MW1/MW2 ownership boundaries
- **MW1** (`unified_risk_assessment_service.py`): sole owner of bounded 0–100 unified risk score and severity classification. Produces contributions, reasons, signal statuses, coverage, uncertainty, provenance, evidence refs. No fabricated confidence/probability; no raw payload echoes.
- **MW2** (`advanced_detection/advisory_orchestrator.py`): separate advisory envelope with 7 signal analyzers, bounded contributions, structured statuses, opaque evidence refs. No raw credentials/headers/cookies/payload exposure.
- **MW4-A** composes MW2 then MW1 per result; does not create a combined score.

## 5. Mitigation policy lifecycle (Gate A/B/C)

```mermaid
stateDiagram-v2
  [*] --> PROPOSED
  PROPOSED --> VALIDATED
  VALIDATED --> ACTIVE
  ACTIVE --> DEACTIVATED
  DEACTIVATED --> ACTIVE
  DEACTIVATED --> RETIRED
  ACTIVE --> RETIRED: admin protection rules apply
```

- Gate A: lifecycle service (propose/validate/activate/deactivate/retire/dry-run evaluate). Advisory-only decisions.
- Gate B: persistence service (SQLite-safe tests; PostgreSQL target BLOCKED).
- Gate C: authenticated read/admin APIs; RBAC server-side authoritative.

## 6. Gate E local demo lifecycle

```mermaid
stateDiagram-v2
  [*] --> OFF
  OFF --> ENABLED: Admin + explicit confirmation + loopback + synthetic-only
  ENABLED --> RUNNING: bounded synthetic run
  RUNNING --> ENABLED: results/audit persisted to demo temp SQLite
  ENABLED --> KILL_SWITCH: admin kill-switch
  RUNNING --> KILL_SWITCH: fail-closed/error path
  KILL_SWITCH --> OFF: disable/dispose demo-owned state
  ENABLED --> OFF: disable
```

Safety: default OFF, loopback-only, synthetic-only, explicit confirmation, temp SQLite demo-owned, kill switch effective, no PG/original DB, no external exposure, no real enforcement.

## 7. Auth/RBAC boundaries
- `require_api_key`: system-to-system static key.
- `require_jwt_auth` / `get_current_user`: verified JWT, DB-preferred identity, registry/claims fallback, active account check.
- `RequireRole`: server-side RBAC (`admin`, `analyst`, `viewer`).
- `require_analyst_or_api_key`: protects security analysis routes; viewer JWT rejected (403); missing auth rejected (401/503).
- Frontend role gating is display-only; backend is authoritative.

## 8. Persistence architecture
- App DB: SQLAlchemy models; dev/test SQLite; PostgreSQL intended but **MW4-B BLOCKED/NO-GO** (ambiguous liveval pgdata/process state preserved; no PG actions in P1).
- Gate E: isolated temporary SQLite under system temp (configurable `MITIGATION_DEMO_DB_DIR`, temp-contained guard). Demo-owned; disposed on disable/reset.

## 9. Advisory vs enforcement boundaries
- MW1/MW2/MW4-A/mitigation analyze/runtime-analyze: **advisory only**, no enforcement.
- Gate E: isolated local demo-only enforcement simulation on synthetic requests in demo-owned temp SQLite. Not production enforcement; default OFF; kill switch/dispose required.

## 10. Known gaps (honest)
- MW4-B PostgreSQL persistence/auth E2E: BLOCKED.
- Full authenticated browser E2E: NOT VERIFIED in this P1 run unless explicitly executed with evidence.
- Production accuracy/performance/capacity: NOT MEASURED/NOT CLAIMED.
- Benchmark/eval in P1 are synthetic and bounded.