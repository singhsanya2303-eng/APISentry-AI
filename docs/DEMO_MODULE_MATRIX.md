# Demo Module Selection Matrix

This matrix records the repository-side demo scope only. It does not enable a
module, change a threshold, create infrastructure, or publish an artifact.
Normal production routes remain advisory-only. Gate E/WP9 demo control-plane
routes remain default-disabled and cannot be mounted in production.

All analysis routes are mounted under `/api/v1` with
`require_analyst_or_api_key` (`backend/app/api/v1/router.py:69-88`).

Prompt 3 profiling used a clean isolated venv with unchanged dependency minima:
Python 3.13.7, `numpy 2.5.5`, `scikit-learn 1.9.1`, and `torch 2.15.0+cpu`.
Install, `pip check`, and imports all exited 0. All bounded operations stayed
below the 2,048 MB process ceiling and returned HTTP 200 with small synthetic
inputs. Full numbers are in `docs/DEPLOYMENT_CONFIGURATION.md`.

## Default demo candidates (recommended)

| Module | Artifact requirement | RAM / runtime cost | Runtime dependency | API availability | If unavailable | Recommendation |
|---|---|---|---|---|---|---|
| Deterministic risk scoring | No model artifact; weights are code-defined in `backend/app/detection/risk_scorer.py` | Prompt 3: startup RSS 178.4 MB; request 0.055 s, RSS 181.0 MB; four concurrent requests 0.097 s total, RSS 182.1 MB | FastAPI, SQLAlchemy DB session, Pydantic | `GET /api/v1/security/behavior/analyze` | Invalid time range → 422; DB/service failure → generic 500; DB not ready → `/ready` 503 | **Include**. Keep thresholds unchanged. |
| BOLA analysis | No artifact; deterministic detector | Base process only | SQLAlchemy DB | `GET /api/v1/security/bola/analyze` | Failure → generic 500; no fabricated verdict | **Include**. |
| Brute-force detection | No artifact; deterministic detector | Base process only | SQLAlchemy DB | `GET /api/v1/security/bruteforce/analyze` | Failure → generic 500 | **Include**. |
| Rate anomaly detection | No artifact; deterministic detector | Base process only | SQLAlchemy DB | `GET /api/v1/security/rate-anomaly/analyze` | Invalid `scope` → 422; failure → 500 | **Include**. |
| Bot detection | No artifact; deterministic composition of existing signals | Base process only | SQLAlchemy DB | `GET /api/v1/security/bot/analyze` | Invalid range → 422; missing evidence lowers confidence, not fabricated risk | **Include**. |
| Token usage classifier | Trusted checkpoint `backend/models/token_usage_classifier.joblib` (present, SHA-256 `a961152d18e905a135bd1d5cd6c64a9c8e4a44a40c114682fec0cc47e3ddc116`) | Prompt 3: request 0.132 s, RSS 182.0 MB; scikit-learn import cost shared | joblib + scikit-learn RandomForest | `GET /api/v1/security/token-classifier/features`; `POST /api/v1/security/token-classifier/predict` | Missing artifact → `/features available=false`, `/predict` 503; feature mismatch → 422; never substitute a score | **Include** if trusted artifact is present. |
| Clustering comparison | No artifact; 10+ supplied feature vectors | Prompt 3: `sklearn.ensemble` import 2.063 s / +85.4 MB; request 0.134 s, RSS 181.4 MB | NumPy + scikit-learn | `POST /api/v1/security/clustering/analyze` | Bad dimensions/non-finite values → 422; failure → 500 | **Include**. |
| Advisory mitigation composition | No artifact; composes existing services | Base process only | SQLAlchemy DB + internal services | `GET /api/v1/security/mitigation/analyze`; `GET /api/v1/security/mitigation/runtime-analyze` | Failure → generic 500; must remain `advisory_only=true`, `enforcement_executed=false` | **Recommended for narrative**, not a separate model requirement. |

## Optional modules (explicit opt-in only)

| Module | Artifact requirement | RAM / runtime cost | Runtime dependency | API availability | If unavailable | Recommendation |
|---|---|---|---|---|---|---|
| Stacked autoencoder traffic trends | No pre-trained artifact for the normal route; fits from at least 10 baseline windows | Prompt 3: `import torch` 2.590 s / +155.7 MB; bounded request 4.827 s, RSS 414.1 MB. torch import is deferred to the request path. | torch + NumPy + scikit-learn | `GET /api/v1/security/traffic-trends/analyze` | <10 baseline windows → 422; >10,000 logs/window → 413; unexpected failure → 500 | **Optional**. Do not include in minimum demo path; budget 1–2 GB headroom or use a separate process. |
| HTTP payload classifier | Frozen bundle `research/models/http_payload_classifier/v1/model_bundle.joblib`, SHA-256 verified before load (present and hash-verified in this workspace) | Prompt 3: request 0.352 s, RSS 200.2 MB / peak 213.0 MB (+22.4 MB); artifact hash verified | joblib + NumPy/scikit-learn | `POST /api/v1/security/payload-classifier/predict`; `GET /api/v1/security/payload-classifier/metadata` | Missing/mismatched artifact → generic 503; malformed input → generic 422; no fake model | **Optional**, research-only advisory output. |

## Research-only modules (do not include in demo)

| Module | Artifact / status | Why excluded | API availability |
|---|---|---|---|
| CSIC 2010 HTTP classifier | Artifact exists at `backend/models/csic_http_anomaly/v1/model.joblib`, but acceptance failed: session PR-AUC 0.303, FPR 0.910, keyword baseline PR-AUC 0.473 | Failed predeclared acceptance criteria; must remain a failed baseline | No production route |
| SR-BH 2020 model | No model artifact; training halted before fitting | Dataset audit only; no performance claim | No route |
| WAMM evaluation | No model trained; decision NO-GO due overlap/leakage and semantic relabeling | Unsuitable for shipped evaluation | No route |
| Offline training/capture/split helpers | CLI-only scripts in `backend/` and `research/` | Never mounted; require explicit operator opt-in and reviewed data | No route |

## Module behavior rules

- Do not silently disable a module or substitute a fallback score.
- Do not change thresholds or weights to improve a demo.
- Missing artifacts must return explicit `503`/`available=false`, not a fabricated result.
- Optional ML modules must be opted into separately in staging planning.
- Gate E/WP9 remain disabled; production enforcement remains advisory-only.
- Public registration is hidden in production builds and rejected again by the
  client handler; the backend remains fail-closed. Owner-provisioned accounts only.
- An account without Admin/Analyst rights sees only the read-only Viewer status
  surface (Overview and Service Status). No analysis, mitigation, policy, or
  user-administration navigation is shown, and backend authorization remains
  the authoritative boundary.
- Backend cold starts follow a bounded readiness model: 11 maximum attempts,
  80 seconds of cumulative backoff, a 90-second deadline, and a 4-second request
  timeout. States are `checking`, `waking`, `online`, `not_ready`, and `offline`;
  `not_ready` means the health endpoint responded but readiness reported an
  unavailable dependency. The frontend does not infer data beyond those responses.
