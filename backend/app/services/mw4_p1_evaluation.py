"""MW4-C P1 synthetic benchmark and evaluation harness.

Reproducible, bounded, synthetic-only. No PostgreSQL, no network, no real
traffic, no production claims. Metrics from synthetic labeled data are reported
as synthetic-rule agreement / synthetic benchmark measurements only.
"""
from __future__ import annotations

import json
import os
import platform
import random
import statistics
import sys
import time
import tracemalloc
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable

DATASET_VERSION = "mw4-p1-synth-v1"
HARNESS_VERSION = "1.0.0"


@dataclass
class LabeledCase:
    case_id: str
    category: str
    label: str  # benign|suspicious|malicious|ambiguous|error
    expected_mw1_severity: str | None
    expected_gate_e_outcome: str | None
    bot_result: dict[str, Any]
    detection: dict[str, Any]
    notes: str


def _iso(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).isoformat()


def generate_synthetic_dataset(seed: int = 1337, n_per_category: int = 20) -> dict[str, Any]:
    """Generate deterministic synthetic labeled dataset. No real user data."""
    rnd = random.Random(seed)
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    cases: list[LabeledCase] = []
    # Expected MW1 severities are intentionally conservative: only categories
    # with defensible synthetic-rule expectations are labeled; others are None
    # (ambiguous / not ground truth). Agreement is reported as synthetic-rule
    # agreement only, never real-world accuracy.
    cats = [
        ("benign", "LOW", "advisory_only"),
        ("high_frequency", None, "enforced_block"),
        ("repeated_requests", None, "enforced_allow"),
        ("suspicious_automation", None, "enforced_block"),
        ("invalid_payload_structure", None, "advisory_only"),
        ("attack_like", None, "enforced_block"),
        ("missing_signal", None, "advisory_only"),
        ("detector_error", None, "advisory_only"),
        ("ambiguous_borderline", None, "advisory_only"),
    ]
    for ci, (cat, exp_sev, exp_gate) in enumerate(cats):
        for i in range(n_per_category):
            idx = ci * n_per_category + i
            ts = base + timedelta(seconds=idx)
            req_count = {
                "benign": rnd.randint(1, 8),
                "high_frequency": rnd.randint(120, 400),
                "repeated_requests": rnd.randint(30, 80),
                "suspicious_automation": rnd.randint(20, 60),
                "invalid_payload_structure": rnd.randint(5, 20),
                "attack_like": rnd.randint(40, 120),
                "missing_signal": rnd.randint(1, 10),
                "detector_error": rnd.randint(1, 10),
                "ambiguous_borderline": rnd.randint(10, 25),
            }[cat]
            bot_score = {
                "benign": rnd.uniform(0, 15),
                "high_frequency": rnd.uniform(55, 85),
                "repeated_requests": rnd.uniform(35, 65),
                "suspicious_automation": rnd.uniform(65, 95),
                "invalid_payload_structure": rnd.uniform(25, 55),
                "attack_like": rnd.uniform(80, 99),
                "missing_signal": rnd.uniform(0, 30),
                "detector_error": rnd.uniform(0, 30),
                "ambiguous_borderline": rnd.uniform(18, 42),
            }[cat]
            classification = {
                "benign": "human_like",
                "high_frequency": "automation_suspicious",
                "repeated_requests": "automation_benign_candidate",
                "suspicious_automation": "automation_suspicious",
                "invalid_payload_structure": "unknown",
                "attack_like": "automation_suspicious",
                "missing_signal": "unknown",
                "detector_error": "unknown",
                "ambiguous_borderline": "automation_benign_candidate",
            }[cat]
            reasons = []
            if cat != "missing_signal":
                reasons.append({
                    "code": f"SYNTH_{cat.upper()}",
                    "category": "automation_characteristic",
                    "description": f"Synthetic {cat} indicator",
                    "severity": "high" if bot_score > 70 else "medium" if bot_score > 35 else "low",
                    "evidence_count": req_count,
                    "score_contribution": min(100.0, round(bot_score / 2, 2)),
                    "request_ids": [],
                    "details": {"synthetic": True, "category": cat},
                })
            bot_result = {
                "client_ip": "127.0.0.1",
                "actor_id": f"synth-{cat}-{i}",
                "bot_risk_score": round(bot_score, 2),
                "classification": classification,
                "reasons": reasons,
                "score_factors": [],
                "evidence_references": [],
                "request_count": req_count,
                "first_seen": _iso(ts),
                "last_seen": _iso(ts + timedelta(seconds=30)),
                "observation_window_seconds": 30.0,
                "summary": f"Synthetic {cat} case {i}",
                "behavioral_risk": None,
            }
            detection = {
                "results": [bot_result],
                "total_clients": 1,
                "total_events_analyzed": req_count,
                "analysis_window_start": _iso(ts),
                "analysis_window_end": _iso(ts + timedelta(seconds=30)),
                "requested_start_time": None,
                "requested_end_time": None,
                "limits": {
                    "requested_page": 1,
                    "requested_page_size": 50,
                    "max_records": 1000,
                    "records_analyzed": req_count,
                    "truncated": False,
                },
                "summary": {
                    "total_clients": 1,
                    "total_requests_analyzed": req_count,
                    "human_like_clients": 1 if classification == "human_like" else 0,
                    "benign_automation_candidates": 1 if classification == "automation_benign_candidate" else 0,
                    "suspicious_automation_candidates": 1 if classification == "automation_suspicious" else 0,
                    "unknown_clients": 1 if classification == "unknown" else 0,
                    "malformed_records_skipped": 0,
                    "brute_force_override_count": 0,
                    "summary": f"Synthetic {cat}",
                },
            }
            cases.append(LabeledCase(
                case_id=f"{cat}-{i:03d}",
                category=cat,
                label="benign" if cat == "benign" else "ambiguous" if cat in {"ambiguous_borderline", "missing_signal"} else "malicious",
                expected_mw1_severity=exp_sev,
                expected_gate_e_outcome=exp_gate,
                bot_result=bot_result,
                detection=detection,
                notes=f"Synthetic deterministic case; category={cat}; no real traffic.",
            ))
    payload = {
        "dataset_version": DATASET_VERSION,
        "harness_version": HARNESS_VERSION,
        "seed": seed,
        "n_per_category": n_per_category,
        "total_cases": len(cases),
        "categories": [c[0] for c in cats],
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "privacy": "Synthetic only; no real credentials, user info, or customer payloads.",
        "limitations": [
            "Synthetic labels do not represent real-world ground truth.",
            "Metrics computed from this dataset must be reported as synthetic-rule agreement only.",
            "No production precision/recall/FPR/FNR claims are supported.",
        ],
        "cases": [asdict(c) for c in cases],
    }
    payload["dataset_sha256"] = sha256(json.dumps(payload["cases"], sort_keys=True).encode("utf-8")).hexdigest()
    return payload


def _percentile(vals: list[float], p: float) -> float:
    if not vals:
        return 0.0
    s = sorted(vals)
    k = (len(s) - 1) * p / 100.0
    f = int(k)
    c = min(f + 1, len(s) - 1)
    return s[f] + (s[c] - s[f]) * (k - f)


def _stats(vals: list[float]) -> dict[str, Any]:
    if not vals:
        return {"count": 0}
    return {
        "count": len(vals),
        "min_ms": min(vals),
        "max_ms": max(vals),
        "mean_ms": statistics.mean(vals),
        "median_ms": statistics.median(vals),
        "p90_ms": _percentile(vals, 90),
        "p95_ms": _percentile(vals, 95),
    }


def run_benchmark(dataset: dict[str, Any], iterations: int = 1, warmup: int = 0) -> dict[str, Any]:
    """Bounded sequential in-process benchmark over MW4-A runtime orchestration."""
    from app.schemas.bot_detection import BotDetectionResponse
    from app.services.mw4_runtime_orchestration_service import orchestrate_mw4_runtime

    cases = dataset.get("cases", [])
    timings: dict[str, list[float]] = {"mw2_ms": [], "mw1_ms": [], "total_ms": []}
    errors: list[dict[str, Any]] = []
    tracemalloc.start()

    def _run(case: dict[str, Any], record: bool) -> None:
        try:
            det = BotDetectionResponse.model_validate(case["detection"])
            _, t = orchestrate_mw4_runtime(det)
            if record:
                timings["mw2_ms"].append(float(t.mw2_ms))
                timings["mw1_ms"].append(float(t.mw1_ms))
                timings["total_ms"].append(float(t.total_ms))
        except Exception as e:
            if record:
                errors.append({"case_id": case.get("case_id"), "error": type(e).__name__})

    for case in cases[: min(max(0, warmup), len(cases))]:
        _run(case, record=False)
    for _ in range(max(1, iterations)):
        for case in cases:
            _run(case, record=True)

    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    total_s = sum(timings["total_ms"]) / 1000.0 if timings["total_ms"] else 0.0
    throughput = (len(timings["total_ms"]) / total_s) if total_s > 0 else 0.0
    return {
        "harness_version": HARNESS_VERSION,
        "dataset_version": dataset.get("dataset_version"),
        "dataset_sha256": dataset.get("dataset_sha256"),
        "measurement_type": "in-process service timing (sequential, bounded, MW4-A orchestration)",
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "pid": os.getpid(),
        },
        "config": {"iterations": iterations, "warmup": warmup, "cases": len(cases)},
        "timings": {k: _stats(v) for k, v in timings.items()},
        "throughput_cases_per_sec": throughput,
        "memory_tracemalloc": {"current_bytes": current, "peak_bytes": peak},
        "errors": errors[:50],
        "error_count": len(errors),
        "limitations": [
            "In-process timing only; not API/browser/production latency.",
            "Sequential bounded run; no concurrency/load/stress testing.",
            "Tracemalloc measures Python allocations, not total process RSS.",
            "Synthetic dataset; results do not establish production capacity.",
        ],
    }


def run_synthetic_evaluation(dataset: dict[str, Any]) -> dict[str, Any]:
    """Labeled synthetic evaluation with explicit separation of layers."""
    from app.schemas.bot_detection import BotDetectionResponse
    from app.services.mw4_runtime_orchestration_service import orchestrate_mw4_runtime

    cases = dataset.get("cases", [])
    mw1_rows: list[dict[str, Any]] = []
    mw2_rows: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for case in cases:
        try:
            det = BotDetectionResponse.model_validate(case["detection"])
            runtime_results, _ = orchestrate_mw4_runtime(det)
            for rr in runtime_results:
                mw1 = rr.mw1_unified_assessment
                actual = None
                has_missing_or_error = False
                risk_score = None
                if mw1 is not None:
                    actual = mw1.severity.value if hasattr(mw1.severity, "value") else str(mw1.severity)
                    risk_score = mw1.risk_score
                    has_missing_or_error = any(
                        getattr(s.status, "value", str(s.status)) in {"missing", "error", "invalid"}
                        for s in getattr(mw1, "signal_statuses", []) or []
                    )
                mw1_rows.append({
                    "case_id": case["case_id"],
                    "category": case["category"],
                    "label": case["label"],
                    "expected": case.get("expected_mw1_severity"),
                    "actual": actual,
                    "risk_score": risk_score,
                    "mw1_status": rr.mw1_status,
                    "has_missing_or_error": has_missing_or_error,
                })
                mw2 = rr.mw2_advanced_detection
                mw2_rows.append({
                    "case_id": case["case_id"],
                    "category": case["category"],
                    "signal_count": len(getattr(mw2, "signals", []) or []),
                    "statuses": [getattr(s.status, "value", str(s.status)) for s in (getattr(mw2, "signals", []) or [])],
                })
        except Exception as e:
            errors.append({"case_id": case.get("case_id"), "error": type(e).__name__})

    evaluable = [r for r in mw1_rows if r["expected"] is not None and r["actual"] is not None]
    matches = [r for r in evaluable if r["expected"] == r["actual"]]
    by_cat: dict[str, list[dict[str, Any]]] = {}
    for r in mw1_rows:
        by_cat.setdefault(r["category"], []).append(r)
    cat_summary = {}
    for cat, rows in by_cat.items():
        ev = [r for r in rows if r["expected"] is not None and r["actual"] is not None]
        cat_summary[cat] = {
            "total": len(rows),
            "evaluable": len(ev),
            "matches": sum(1 for r in ev if r["expected"] == r["actual"]),
            "actual_severities": sorted({str(r["actual"]) for r in rows}),
        }

    missing_signal_cases = [r for r in mw1_rows if r["category"] == "missing_signal"]
    missing_not_silent = sum(
        1 for r in missing_signal_cases if r["has_missing_or_error"] or r["actual"] not in {None, "LOW"}
    )

    return {
        "harness_version": HARNESS_VERSION,
        "dataset_version": dataset.get("dataset_version"),
        "dataset_sha256": dataset.get("dataset_sha256"),
        "evaluation_type": "synthetic-rule agreement (NOT real-world accuracy)",
        "mw1_severity_agreement": {
            "evaluable_cases": len(evaluable),
            "matches": len(matches),
            "agreement_rate": (len(matches) / len(evaluable)) if evaluable else None,
            "by_category": cat_summary,
            "note": "Agreement with synthetic expected severities only; not production precision/recall/F1/FPR/FNR.",
        },
        "mw2_signal_coverage": {
            "cases": len(mw2_rows),
            "avg_signals": (sum(r["signal_count"] for r in mw2_rows) / len(mw2_rows)) if mw2_rows else 0,
        },
        "missing_uncertain_handling": {
            "missing_signal_cases": len(missing_signal_cases),
            "missing_not_silently_benign": missing_not_silent,
            "note": "Checks that missing-signal cases are not silently treated as clean benign without evidence.",
        },
        "errors": errors[:50],
        "error_count": len(errors),
        "limitations": [
            "Synthetic dataset only; no representative production-labeled data.",
            "No real-world precision/recall/F1/FPR/FNR/generalization claims.",
            "MW1 severity is not ground truth for underlying threats; this is synthetic-rule agreement.",
            "MW2/MW1 outputs are not independent ground truth for each other.",
        ],
    }


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, default=str), encoding="utf-8")
