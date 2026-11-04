# APISentry AI Research Dataset Foundation

This package defines the versioned, privacy-preserving dataset boundary for
future APISentry AI experiments. It does not download data, train models, or
change the runtime backend.

For the current infrastructure decision, collection status, and continuation
plan, see [STAGE_7_HANDOFF.md](./STAGE_7_HANDOFF.md).

## Data flow

```text
source-specific record
        |
        v
safe HTTP/payload preprocessing
        |
        v
CanonicalEvent
        |
        v
leakage-safe grouped split
```

Raw requests and credentials are intentionally not part of the canonical
schema. Preprocessors retain only safe metadata and derived numeric features.
Principal identifiers are HMAC-SHA256 pseudonyms in the format
`principal_<64 lowercase hex characters>`. The HMAC key must be supplied by
the caller and contain at least 32 bytes; `generate_principal_secret()` creates
a cryptographically random 256-bit key. Canonical events accept only the
trusted value returned by the HMAC helper, not caller-provided identifier
strings. This is pseudonymization, not irreversible anonymization: holders of
the key can reproduce the identifier. Keep keys outside records, logs, and
manifests. Rotating a key changes all resulting pseudonyms, so key rotation
requires an explicit migration or versioned dataset boundary.

## Split and evaluation policy

The split helpers support:

- random group-aware baseline splits with an explicit seed;
- chronological grouping for time-based evaluation;
- principal-disjoint evaluation;
- campaign-disjoint evaluation.

Sessions and campaigns are treated as indivisible groups. Validation rejects
duplicate event IDs and any session or campaign appearing in more than one
split.
At least three independent groups are required. Time splits also require
strictly ordered train, validation, and test timestamps. For principal or
campaign splits, a session or campaign that spans incompatible groups is
rejected rather than silently discarded.

The evaluation strategies answer different questions:

| Strategy | Generalization question | Isolation | Primary result |
|---|---|---|---|
| `random` | Can a model generalize to held-out grouped traffic from the same collection? | session and campaign groups | Baseline only; use an explicit seed |
| `principal` | Can a model generalize to unseen principals? | principal, session, and campaign | Suitable when enough principals exist |
| `campaign` | Can a model generalize across collection campaigns? | session and campaign | Suitable for campaign robustness |
| `time` | Can a model generalize forward in time? | session and campaign, with strict chronology | Preferred primary result when collection history supports it |
| `held-out-category` | Can a model detect an attack category absent from training? | category-pure campaigns and their sessions | Secondary result only; requires at least three attack categories, normal campaigns, and one category per campaign |

`known-category` remains available for the earlier coverage-oriented protocol;
it is not category holdout because every split is required to contain every
category. A held-out-category result must not be described as ordinary
category coverage. The category-holdout protocol assigns known attack
categories to training and unseen categories to validation/test; it is not a
claim that every split has complete category coverage.

The strategies have different leakage risks. Random and campaign splits can
still share principals or collection time; principal-disjoint splits can
still share campaign semantics and time; chronological splits can repeat
principals and categories across time. The primary result should use the
strategy justified by the research question and available independent groups,
not the strategy with the most favorable coverage. Every strategy requires
three independent groups; principal and campaign strategies additionally
require three independent principals or campaigns, respectively, and time
requires strict timestamps. Missing labels and categories are recorded in
split metadata and are never filled with fabricated records.

Every CLI split writes `split_metadata.yaml` containing the strategy, seed,
generation timestamp, per-split counts and file checksums. Missing classes or
insufficient independent groups are rejected rather than filled with
fabricated data.

## Dataset manifest

`data_manifest.yaml` is a metadata template. No datasets are included or
downloaded by this foundation. Checksums and collection dates must be filled
only after a source is acquired and hashed locally.

Acquired canonical datasets can be verified without modifying them:

```powershell
python -m research.capture.cli verify-manifest `
  --manifest .research-local\normal-baseline\manifest.yaml `
  --dataset-root .research-local\normal-baseline
```

Verification checks the manifest version, referenced files, hashes, canonical
event validity, counts, distributions, duplicate IDs, split overlap, and
unexpected JSONL files. The principal secret is read from the environment and
is never printed or written. The `split_metadata.yaml` artifact produced by
the split command is also accepted by the verifier; its split files, hashes,
event counts, label distributions, and event-ID disjointness are checked.

## Controlled crAPI collection

The collection boundary is deliberately separate from backend runtime
middleware. Playwright is used for browser workflows and a Python HTTP client
is used for controlled attack procedures. Both clients emit only in-memory
metadata observations. Raw browser objects, credentials, cookies, query
strings, request bodies, and response bodies are never dataset inputs.

The collection flow is:

```text
scenario definition
  -> controlled execution
  -> in-memory sanitization
  -> canonical events
  -> dataset writer
  -> manifest
  -> evaluation splits
```

Every action has its own ID, label, campaign, principal, session, expected
outcome, and capture policy. A campaign label is never copied to unrelated
requests. Primary requests are retained by default; redirects, preflight, and
background requests require explicit policy. Requests without an unambiguous
action mapping are rejected or excluded as configured background traffic.

Targets must be explicitly configured HTTP(S) loopback origins. The validator
checks the scheme, hostname, port, resolved addresses, exact origin, and every
redirect destination. DNS resolution changes are rejected. Browser requests
outside the approved origin fail closed, and Python HTTP requests disable
automatic redirects.

The BOLA procedure requires at least two controlled accounts with tracked
resource ownership. Expected and actual access outcomes are recorded
separately. A 403 or 404 status by itself is not treated as authorization
ground truth.

Playwright is a research-only dependency declared in
`research/requirements.txt`; it is not added to backend runtime dependencies.
Generated captures, datasets, and secrets belong under `.research-local/` and
are excluded from Git.

## Versioned crAPI scenarios

The concrete scenario definitions are under `research/scenarios/` and target
only `http://127.0.0.1:8888`. They are grounded in the checked-in crAPI
OpenAPI document at `crAPI/openapi-spec/crapi-openapi-spec.json`:

- `normal_user_baseline_001.yaml`: signup, login, dashboard, vehicle listing,
  recent posts, and product listing.
- `bola_idor_001.yaml`: two runtime-generated accounts, victim vehicle-list
  setup, and one attacker cross-account vehicle-location request.
- `bruteforce_attack_001.yaml`: five invalid login attempts with a 100 ms
  delay.
- `rate_abuse_001.yaml`: ten bounded authenticated dashboard requests with a
  100 ms delay.
- `payload_attack_001.yaml`: one bounded malformed coupon-validation request.

Scenario YAML contains endpoint paths, methods, authentication state, required
field names, OpenAPI operation IDs, expected response semantics, and mapping
policies, but never runtime credentials or tokens. Account credentials and
JWTs are generated and held by the future orchestrator only.

The OpenAPI document does not establish vehicle ownership semantics. The BOLA
scenario therefore uses a runtime `victim_vehicle_id` placeholder and
requires independent in-memory ownership and response-semantic verification.
The scenario must be reported as unresolved rather than treated as a confirmed
vulnerability when ownership or actual access cannot be established.

## Collection CLI

Validation and dry-run do not construct an HTTP client:

```powershell
python -m research.capture.cli validate
python -m research.capture.cli dry-run --scenario normal_user_baseline_001
python -m research.capture.cli dry-run `
  --scenario bola_idor_001 `
  --scenario bruteforce_attack_001 `
  --scenario rate_abuse_001 `
  --scenario payload_attack_001
```

Network execution requires both explicit scenario selection and `--execute`.
The principal secret must be supplied through an environment variable and is
never printed:

```powershell
$env:APISENTRY_PRINCIPAL_SECRET = '<load-a-32-byte-secret-out-of-band>'
python -m research.capture.cli collect `
  --execute `
  --scenario normal_user_baseline_001 `
  --output-dir .research-local\normal-baseline
```

The CLI rejects non-default targets, requires bounded request counts, and does
not execute all scenarios implicitly. `run` executes selected scenarios
without writing the dataset; `collect` additionally writes `events.jsonl` and
`manifest.yaml`. Splitting an existing canonical JSONL requires the same
principal secret environment variable:

```powershell
python -m research.capture.cli split `
  --events .research-local\normal-baseline\events.jsonl `
  --strategy campaign `
  --output-dir .research-local\normal-baseline\splits
```

Use `--strategy random --seed <integer>` for a reproducible group-aware
baseline. Use `--strategy held-out-category` only when the dataset contains
at least three separately collected attack categories and the required
campaign isolation.

The BOLA runner stops before resolving `${victim_vehicle_id}` unless the
victim response explicitly identifies the resource owner. It marks the
cross-account response as `confirmed_access` only when the requested vehicle
ID and protected location data are both present; echoed IDs without protected
data remain inconclusive. This is an inconclusive safety gate, not a
vulnerability result.
