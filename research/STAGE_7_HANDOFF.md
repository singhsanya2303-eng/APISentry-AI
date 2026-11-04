# APISentry AI Stage 7 Handoff

## Project status

APISentry AI is an API security monitoring and threat-detection project. The
research package defines a privacy-preserving boundary for controlled API
traffic collection and later evaluation; it does not claim that collection or
model experiments have been completed.

The repository contains a FastAPI backend, a React frontend, and a separate
`research/` package. The research package provides:

- the canonical `CanonicalEvent` schema;
- safe preprocessing and HMAC-SHA256 principal pseudonymization;
- JSONL writing and read-only manifest verification;
- group-aware evaluation and split metadata;
- scenario definitions and controlled capture contracts.

The five versioned scenarios are:

| Scenario | Purpose |
|---|---|
| `normal_user_baseline_001` | Controlled normal workflow baseline |
| `bruteforce_attack_001` | Bounded invalid-login attempts |
| `rate_abuse_001` | Bounded repeated authenticated requests |
| `payload_attack_001` | Bounded malformed coupon-validation request |
| `bola_idor_001` | Cross-account vehicle access test with ownership and semantic gates |

The CLI commands are:

```powershell
python -m research.capture.cli validate
python -m research.capture.cli dry-run --scenario normal_user_baseline_001
python -m research.capture.cli run --execute --scenario <scenario-id>
python -m research.capture.cli collect --execute --scenario <scenario-id>
```

`run` and `collect` require explicit scenario selection, `--execute`, the
approved loopback target, and a principal secret. The variable name is
`APISENTRY_PRINCIPAL_SECRET`; its value must be supplied out of band and must
never be committed, logged, or placed in a manifest. `verify-manifest` and
`split` also require that variable. No other research environment variable is
required by the current CLI.

## Infrastructure findings

The audited crAPI checkout is pinned to commit
`b5fc307f3e5f875809b095b771108ef342a33724`. The existing environment must
remain untouched while an isolated research environment is prepared.

The Compose deployment has ten fixed container names and collision risks from
existing published ports, named database/ChromaDB volumes, the identity key
bind mount, and the project network. A different Compose project name alone is
not sufficient. Same-daemon isolation is technically possible but conditional:
fixed names must be removed, ports and volumes must be unique, the network
must be isolated, image digests must be pinned, and original keys and volumes
must not be reused.

A separate Docker engine or VM is preferred for the first backup/restore
rehearsal. It provides a stronger boundary against accidentally reusing the
original volumes or key directory. The VM/restore rehearsal has not been
performed.

The following are point-in-time observations, not permanent machine
specifications:

- Host RAM: 15.69 GB total, 2.21 GB available at measurement time.
- Aggregate Docker container memory: approximately 718 MiB.
- Host CPU utilization: 74% at measurement time.
- `C:` drive free space: approximately 243 GB.
- The current host is **NOT READY** for a second isolated environment under
  the measured conditions.

## Dataset collection status

No research traffic collection has been successfully completed. An earlier
collection attempt failed, and its failure has not been fully resolved. No
backup/restore rehearsal has been performed. No experimental detection
results or model performance claims are established.

Collection remains **NO-GO** until environment isolation, backup/restore, and
cleanup/reset procedures are proven and approved. Do not treat dry-run output,
temporary test data, or scenario validation as collected traffic or an
experimental result.

## Next team member instructions

1. Clone the GitHub repository:

   ```powershell
   git clone https://github.com/singhsanya2303-eng/APISentry-AI.git
   Set-Location .\APISentry-AI
   ```

2. Create and activate a Python virtual environment:

   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

3. Install dependencies from the repository's actual dependency files:

   ```powershell
   python -m pip install -r backend\requirements.txt
   python -m pip install -r research\requirements.txt
   ```

4. Run the research tests and CLI validation before making infrastructure
   changes.
5. Review [research/README.md](./README.md),
   [data_manifest.yaml](./data_manifest.yaml), the canonical schema, and all
   scenario definitions.
6. Establish a separate isolated crAPI host; do not reuse the existing
   Docker Desktop volumes, network, ports, or identity keys.
7. Perform and validate an isolated backup/restore rehearsal.
8. Verify the account cleanup and environment reset procedure.
9. Obtain explicit approval before executing any controlled collection.
10. Keep generated raw captures outside Git. Store only sanitized, reviewed
    artifacts when explicitly approved.

The research CLI's non-network checks are:

```powershell
python -m research.capture.cli validate
python -m research.capture.cli dry-run `
  --scenario normal_user_baseline_001 `
  --scenario bola_idor_001 `
  --scenario bruteforce_attack_001 `
  --scenario rate_abuse_001 `
  --scenario payload_attack_001
```

Do not run `run` or `collect` until the collection gate is approved.
