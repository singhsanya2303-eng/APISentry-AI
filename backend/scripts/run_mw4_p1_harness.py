"""CLI for MW4-C P1 synthetic benchmark/evaluation harness.

Safe: synthetic-only, bounded, sequential, no PostgreSQL, no network.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "backend"))
sys.path.insert(0, str(REPO))

from app.services.mw4_p1_evaluation import (  # noqa: E402
    generate_synthetic_dataset,
    run_benchmark,
    run_synthetic_evaluation,
    write_json,
)


def main() -> int:
    ap = argparse.ArgumentParser(description="MW4-C P1 synthetic benchmark/evaluation harness")
    ap.add_argument("--out", required=True, help="Output directory")
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--n-per-category", type=int, default=20)
    ap.add_argument("--iterations", type=int, default=2)
    ap.add_argument("--warmup", type=int, default=1)
    args = ap.parse_args()

    for name, val, lo, hi in [
        ("n-per-category", args.n_per_category, 1, 200),
        ("iterations", args.iterations, 1, 20),
        ("warmup", args.warmup, 0, 20),
    ]:
        if val < lo or val > hi:
            ap.error(f"--{name} must be between {lo} and {hi}")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    ds = generate_synthetic_dataset(seed=args.seed, n_per_category=args.n_per_category)
    write_json(out / "synthetic_dataset.json", ds)
    bench = run_benchmark(ds, iterations=args.iterations, warmup=args.warmup)
    write_json(out / "benchmark_results.json", bench)
    ev = run_synthetic_evaluation(ds)
    write_json(out / "evaluation_results.json", ev)
    summary = {
        "dataset_version": ds["dataset_version"],
        "dataset_sha256": ds["dataset_sha256"],
        "cases": ds["total_cases"],
        "benchmark_error_count": bench["error_count"],
        "evaluation_error_count": ev["error_count"],
        "end_to_end_median_ms": bench["timings"]["total_ms"].get("median_ms"),
        "mw1_agreement_rate": ev["mw1_severity_agreement"]["agreement_rate"],
        "limitations": ds["limitations"],
    }
    write_json(out / "harness_summary.json", summary)
    print(json.dumps(summary, indent=2))
    return 0 if bench["error_count"] == 0 and ev["error_count"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
