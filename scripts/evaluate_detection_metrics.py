#!/usr/bin/env python3
"""Reproducible detection metric calculator for APISENTRY evaluation artifacts.

Usage:
  python scripts/evaluate_detection_metrics.py --input predictions.jsonl --dataset-kind labelled \
      --label-field label --pred-field predicted --positive-class malicious
  python scripts/evaluate_detection_metrics.py --input predictions.csv --dataset-kind synthetic-rule-agreement \
      --label-field expected --pred-field observed --category-field category

Accepted formats: .jsonl (one JSON object per line) or .csv.
This script does not download datasets, train models, or modify model artifacts.
Predictive metrics are emitted only for explicitly labelled datasets; synthetic
rule agreement is reported separately and never presented as accuracy.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


DATASET_KIND_NOTES = {
    "labelled": (
        "Authoritative labels were supplied by the caller; predictive metrics are "
        "valid only when the positive and negative classes are both represented."
    ),
    "synthetic-rule-agreement": (
        "Agreement with deterministic synthetic expectations only. This is not "
        "accuracy: it is not precision, recall, F1, FPR, FNR, or evidence of "
        "real-world generalization."
    ),
    "unknown": (
        "Dataset provenance was not declared. No predictive accuracy metric is claimed."
    ),
}


def load_rows(path: Path) -> list[dict[str, Any]]:
    if path.suffix.lower() == ".jsonl":
        rows = []
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            obj = json.loads(line)
            if not isinstance(obj, dict):
                raise ValueError(f"Line {i} is not a JSON object")
            rows.append(obj)
        return rows
    if path.suffix.lower() == ".csv":
        with path.open("r", encoding="utf-8", newline="") as f:
            return list(csv.DictReader(f))
    raise ValueError("Unsupported input format; use .jsonl or .csv")


def _value(row: dict[str, Any], field: str) -> str:
    value = row.get(field, "")
    return "" if value is None else str(value).strip()


def valid_rows(
    rows: list[dict[str, Any]], label: str, pred: str
) -> tuple[list[dict[str, Any]], int]:
    """Drop rows without both an authoritative label and a prediction."""
    valid = [r for r in rows if _value(r, label) and _value(r, pred)]
    return valid, len(rows) - len(valid)


def safe_div(n: float, d: float) -> float:
    return float(n / d) if d else 0.0


def binary_metrics(
    rows: list[dict[str, Any]], label: str, pred: str, positive: str
) -> dict[str, Any]:
    """Compute labelled binary metrics; mark them unsupported without class balance."""
    if not positive:
        raise ValueError("positive class is required for binary metrics")
    clean, skipped = valid_rows(rows, label, pred)
    tp = fp = tn = fn = 0
    for r in clean:
        y = _value(r, label)
        p = _value(r, pred)
        y_pos = y == positive
        p_pos = p == positive
        if p_pos and y_pos:
            tp += 1
        elif p_pos and not y_pos:
            fp += 1
        elif (not p_pos) and (not y_pos):
            tn += 1
        else:
            fn += 1
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    f1 = safe_div(2 * precision * recall, precision + recall) if (precision + recall) else 0.0
    fpr = safe_div(fp, fp + tn)
    fnr = safe_div(fn, fn + tp)
    positive_labelled = tp + fn
    negative_labelled = tn + fp
    return {
        "positive_class": positive,
        "valid_rows": len(clean),
        "skipped_invalid_rows": skipped,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
        "false_positive_rate": round(fpr, 6),
        "false_negative_rate": round(fnr, 6),
        "supported": positive_labelled > 0 and negative_labelled > 0,
        "support_note": (
            "Both positive and negative labelled examples are required before "
            "these values may be reported as predictive metrics."
        ),
    }


def confusion(rows: list[dict[str, Any]], label: str, pred: str) -> dict[str, Any]:
    clean, skipped = valid_rows(rows, label, pred)
    labels = sorted({_value(r, label) for r in clean} | {_value(r, pred) for r in clean})
    matrix = {a: {b: 0 for b in labels} for a in labels}
    for r in clean:
        matrix[_value(r, label)][_value(r, pred)] += 1
    return {"labels": labels, "matrix": matrix, "valid_rows": len(clean), "skipped_invalid_rows": skipped}


def per_category(
    rows: list[dict[str, Any]], label: str, pred: str, category: str
) -> dict[str, Any]:
    clean, _ = valid_rows(rows, label, pred)
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in clean:
        groups[_value(r, category) or "unknown"].append(r)
    out = {}
    for cat, items in sorted(groups.items()):
        cm = confusion(items, label, pred)
        labels = cm["labels"]
        cls = {}
        for cls_label in labels:
            tp = cm["matrix"].get(cls_label, {}).get(cls_label, 0)
            fp = sum(cm["matrix"].get(other, {}).get(cls_label, 0) for other in labels if other != cls_label)
            fn = sum(cm["matrix"].get(cls_label, {}).get(other, 0) for other in labels if other != cls_label)
            precision = safe_div(tp, tp + fp)
            recall = safe_div(tp, tp + fn)
            f1 = safe_div(2 * precision * recall, precision + recall) if (precision + recall) else 0.0
            cls[cls_label] = {
                "precision": round(precision, 6),
                "recall": round(recall, 6),
                "f1": round(f1, 6),
                "support": sum(cm["matrix"].get(cls_label, {}).values()),
            }
        out[cat] = {"count": len(items), "classes": cls}
    return out


def evaluate(
    rows: list[dict[str, Any]],
    *,
    label_field: str,
    pred_field: str,
    category_field: str | None = None,
    positive_class: str | None = None,
    dataset_kind: str = "unknown",
) -> dict[str, Any]:
    """Build a report that never conflates synthetic agreement with accuracy."""
    if dataset_kind not in DATASET_KIND_NOTES:
        raise ValueError(f"unsupported dataset kind: {dataset_kind}")
    clean, skipped = valid_rows(rows, label_field, pred_field)
    is_labelled = dataset_kind == "labelled"
    binary = None
    if is_labelled and positive_class:
        binary = binary_metrics(rows, label_field, pred_field, positive_class)

    report: dict[str, Any] = {
        "dataset_kind": dataset_kind,
        "evaluation_type": {
            "labelled": "labelled predictive metrics",
            "synthetic-rule-agreement": "synthetic-rule agreement (not predictive accuracy)",
            "unknown": "unclassified evaluation data (no predictive accuracy claim)",
        }[dataset_kind],
        "rows": len(rows),
        "valid_rows": len(clean),
        "skipped_invalid_rows": skipped,
        "label_field": label_field,
        "predicted_field": pred_field,
        "confusion_matrix": confusion(rows, label_field, pred_field),
        "predictive_accuracy_supported": bool(binary and binary["supported"]),
        "notes": [
            "Metrics computed from supplied local file only.",
            "Do not interpret decision margins as calibrated probabilities unless calibrated.",
            DATASET_KIND_NOTES[dataset_kind],
        ],
    }
    if binary is not None:
        report["binary_metrics"] = binary
    if is_labelled and not positive_class:
        report["notes"].append("--positive-class is required to compute labelled binary metrics.")
    if dataset_kind == "synthetic-rule-agreement":
        report["notes"].append("Binary precision/recall/F1/FPR/FNR are intentionally omitted.")
    if category_field:
        report["per_category"] = per_category(rows, label_field, pred_field, category_field)
    return report


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--label-field", default="label")
    ap.add_argument("--pred-field", default="predicted")
    ap.add_argument("--category-field", default=None)
    ap.add_argument("--positive-class", default=None)
    ap.add_argument(
        "--dataset-kind",
        choices=sorted(DATASET_KIND_NOTES),
        default="unknown",
        help="labelled data is the only kind eligible for predictive accuracy metrics",
    )
    ap.add_argument("--output", default=None)
    args = ap.parse_args()

    rows = load_rows(Path(args.input))
    if not rows:
        raise SystemExit("No rows loaded")
    report = evaluate(
        rows,
        label_field=args.label_field,
        pred_field=args.pred_field,
        category_field=args.category_field,
        positive_class=args.positive_class,
        dataset_kind=args.dataset_kind,
    )
    text = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
