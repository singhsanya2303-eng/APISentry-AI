"""Controlled research-only training/evaluation for binary HTTP payload classification.

Writes exclusively into a new isolated artifact directory. Existing artifacts are
never modified or overwritten: every output is opened in exclusive-create mode.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import math
import platform
import re
import sys
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import sklearn
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.svm import LinearSVC

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from research.scripts.predict_http_payload import (  # noqa: E402
    FORMAT_VERSION,
    LABELS,
    LengthThresholdClassifier,
)

ZIP_PATH = _ROOT / "research" / "datasets" / "raw" / "HttpParamsDataset-master.zip"
ARTIFACT_DIR = _ROOT / "research" / "models" / "http_payload_classifier" / "v1"
TRAIN_MEMBER = "HttpParamsDataset-master/payload_train.csv"
TEST_MEMBER = "HttpParamsDataset-master/payload_test.csv"

SEED = 42
VALIDATION_FRACTION = 0.2
THRESHOLD = 28
TFIDF_KWARGS: dict[str, Any] = {
    "analyzer": "char",
    "ngram_range": (2, 5),
    "min_df": 2,
    "max_features": 50000,
    "sublinear_tf": True,
    "lowercase": True,
    "dtype": np.float32,
}
LR_KWARGS: dict[str, Any] = {"C": 1.0, "max_iter": 2000, "random_state": SEED}
SVM_KWARGS: dict[str, Any] = {
    "C": 1.0,
    "max_iter": 5000,
    "dual": True,
    "random_state": SEED,
}
SPECS: list[dict[str, Any]] = [
    {"name": "length_threshold", "kind": "threshold", "feature_mode": "length_raw"},
    {"name": "length_logreg", "kind": "lr", "feature_mode": "length_scaled"},
    {"name": "tfidf_char_lr", "kind": "lr", "feature_mode": "text"},
    {"name": "tfidf_char_svm", "kind": "svm", "feature_mode": "text"},
    {"name": "tfidf_char_len_lr", "kind": "lr", "feature_mode": "text_length"},
    {"name": "tfidf_char_len_svm", "kind": "svm", "feature_mode": "text_length"},
]
CORRUPT_RE = re.compile(
    r",\s*\d+\s*,\s*(cmdi|sqli|xss|path-traversal|norm)\s*,\s*(anom|norm)"
)
OUTPUT_NAMES = [
    "model.joblib",
    "vectorizer.joblib",
    "scaler.joblib",
    "model_bundle.joblib",
    "metadata.json",
    "training_config.json",
    "data_quality.json",
    "evaluation.json",
    "evaluation.md",
    "model_card.md",
    "reproducibility.md",
    "examples.json",
]


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_rows(zf: zipfile.ZipFile, member: str) -> list[dict[str, Any]]:
    text = zf.read(member).decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(text, newline=""))
    expected = ["payload", "length", "attack_type", "label"]
    if reader.fieldnames != expected:
        raise ValueError(f"unexpected header in {member}: {reader.fieldnames}")
    rows: list[dict[str, Any]] = []
    for line, row in enumerate(reader, start=2):
        if len(row) != 4 or any(value is None for value in row.values()):
            raise ValueError(f"malformed row at {member}:{line}")
        row["_csv_line"] = line
        rows.append(row)
    return rows


def _make_estimator(kind: str) -> Any:
    if kind == "threshold":
        return LengthThresholdClassifier(threshold=THRESHOLD)
    if kind == "lr":
        return LogisticRegression(**LR_KWARGS)
    if kind == "svm":
        return LinearSVC(**SVM_KWARGS)
    raise ValueError(f"unknown model kind: {kind}")


def _lengths(payloads: list[str]) -> np.ndarray:
    return np.asarray([[float(len(value))] for value in payloads], dtype=np.float64)


def _build_matrices(
    vectorizer: TfidfVectorizer,
    scaler: StandardScaler,
    payload_sets: dict[str, list[str]],
) -> dict[str, dict[str, Any]]:
    mats: dict[str, dict[str, Any]] = {
        "length_raw": {},
        "length_scaled": {},
        "text": {},
        "text_length": {},
    }
    for key, values in payload_sets.items():
        raw = csr_matrix(_lengths(values).astype(np.float32))
        scaled = csr_matrix(scaler.transform(_lengths(values)).astype(np.float32))
        text = vectorizer.transform(values)
        mats["length_raw"][key] = raw
        mats["length_scaled"][key] = scaled
        mats["text"][key] = text
        mats["text_length"][key] = hstack([text, scaled], format="csr")
    return mats


def _metrics(y_true: np.ndarray, prediction: np.ndarray, score: np.ndarray) -> dict[str, Any]:
    tn, fp, fn, tp = (int(x) for x in confusion_matrix(y_true, prediction, labels=[0, 1]).ravel())
    return {
        "n_samples": int(len(y_true)),
        "positive_rate": float(np.mean(y_true)),
        "accuracy": float(accuracy_score(y_true, prediction)),
        "precision": float(precision_score(y_true, prediction, zero_division=0)),
        "recall": float(recall_score(y_true, prediction, zero_division=0)),
        "f1": float(f1_score(y_true, prediction, zero_division=0)),
        "pr_auc": float(average_precision_score(y_true, score)),
        "roc_auc": float(roc_auc_score(y_true, score)),
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "false_positive_rate": float(fp / (fp + tn)) if fp + tn else 0.0,
    }


def _latency(model: Any, X: Any) -> dict[str, float]:
    start = time.perf_counter()
    model.predict(X)
    total_ms = (time.perf_counter() - start) * 1000.0
    n = X.shape[0]
    return {
        "total_ms": float(total_ms),
        "mean_ms_per_sample": float(total_ms / n),
    }


def _score(model: Any, X: Any) -> np.ndarray:
    if isinstance(model, LengthThresholdClassifier):
        return np.asarray(model.decision_function(X)).ravel()
    if hasattr(model, "predict_proba"):
        return np.asarray(model.predict_proba(X)[:, 1]).ravel()
    if hasattr(model, "decision_function"):
        return np.asarray(model.decision_function(X)).ravel()
    return np.asarray(model.predict(X)).ravel().astype(float)


def _evaluate(model: Any, X: Any, y: np.ndarray) -> dict[str, Any]:
    prediction = np.asarray(model.predict(X)).ravel().astype(int)
    result = _metrics(y, prediction, _score(model, X))
    result["latency"] = _latency(model, X)
    return result


def _pick_examples(
    rows: list[dict[str, Any]], y: np.ndarray, per_class: int = 2
) -> list[dict[str, Any]]:
    chosen: list[dict[str, Any]] = []
    for cls in (0, 1):
        indices = np.flatnonzero(y == cls)
        lengths = np.asarray([len(rows[int(i)]["payload"]) for i in indices], dtype=float)
        median = float(np.median(lengths))
        order = sorted(
            (int(i) for i in indices),
            key=lambda i: (abs(len(rows[i]["payload"]) - median), rows[i]["payload"]),
        )
        for i in order[:per_class]:
            row = rows[i]
            chosen.append(
                {
                    "payload": row["payload"],
                    "label": LABELS[int(y[i])],
                    "attack_type": row["attack_type"],
                    "length": len(row["payload"]),
                    "source_file": "payload_test.csv",
                    "csv_line": row["_csv_line"],
                }
            )
    return chosen


def _write_json(path: Path, payload: Any) -> None:
    with path.open("x", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False, sort_keys=False)
        handle.write("\n")


def _write_text(path: Path, text: str) -> None:
    with path.open("x", encoding="utf-8") as handle:
        handle.write(text)


def _write_joblib(path: Path, obj: Any) -> None:
    with path.open("xb") as handle:
        joblib.dump(obj, handle)


def _markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
    out.extend("| " + " | ".join(str(cell) for cell in row) + " |" for row in rows)
    return "\n".join(out)


def _metric_rows(results: dict[str, dict[str, Any]]) -> list[list[str]]:
    rows: list[list[str]] = []
    for name, m in results.items():
        cm = m["confusion_matrix"]
        rows.append(
            [
                name,
                f"{m['accuracy']:.4f}",
                f"{m['precision']:.4f}",
                f"{m['recall']:.4f}",
                f"{m['f1']:.4f}",
                f"{m['pr_auc']:.4f}",
                f"{m['roc_auc']:.4f}",
                f"{m['false_positive_rate']:.4f}",
                f"{cm['tn']}/{cm['fp']}/{cm['fn']}/{cm['tp']}",
                f"{m['latency']['mean_ms_per_sample']:.5f}",
            ]
        )
    return rows


METRIC_HEADERS = [
    "model",
    "accuracy",
    "precision",
    "recall",
    "f1",
    "PR-AUC",
    "ROC-AUC",
    "FPR",
    "TN/FP/FN/TP",
    "ms/sample",
]


def main() -> int:
    if ARTIFACT_DIR.exists():
        raise SystemExit(f"REFUSING TO OVERWRITE existing artifact directory: {ARTIFACT_DIR}")
    for name in OUTPUT_NAMES:
        if (ARTIFACT_DIR / name).exists():
            raise SystemExit(f"REFUSING TO OVERWRITE existing artifact: {ARTIFACT_DIR / name}")
    if not ZIP_PATH.is_file():
        raise SystemExit(f"source archive not found: {ZIP_PATH}")

    with ZIP_PATH.open("rb") as handle:
        zip_sha = _sha256_bytes(handle.read())
    with zipfile.ZipFile(ZIP_PATH) as zf:
        member_sha = {
            "payload_train.csv": _sha256_bytes(zf.read(TRAIN_MEMBER)),
            "payload_test.csv": _sha256_bytes(zf.read(TEST_MEMBER)),
        }
        raw_train = _load_rows(zf, TRAIN_MEMBER)
        raw_test = _load_rows(zf, TEST_MEMBER)

    corrupt: list[dict[str, Any]] = []
    mismatches: list[dict[str, Any]] = []
    for source_name, rows in (("payload_train.csv", raw_train), ("payload_test.csv", raw_test)):
        for row in rows:
            if CORRUPT_RE.search(row["payload"]):
                corrupt.append(
                    {
                        "source_file": source_name,
                        "csv_line": row["_csv_line"],
                        "attack_type": row["attack_type"],
                        "label": row["label"],
                        "payload": row["payload"],
                        "action": "excluded from training and evaluation",
                        "reason": (
                            "payload text embeds a CSV fragment including the literal "
                            "attack_type/label, which would leak the target into text features"
                        ),
                    }
                )
            stored = row["length"]
            actual = len(row["payload"])
            if not stored.isdigit() or int(stored) != actual:
                mismatches.append(
                    {
                        "source_file": source_name,
                        "csv_line": row["_csv_line"],
                        "attack_type": row["attack_type"],
                        "stored_length": stored,
                        "actual_length": actual,
                        "action": "retained; stored length ignored; length recomputed from payload",
                        "reason": "payload text is intact; only the metadata length is inconsistent",
                    }
                )

    train_rows = [r for r in raw_train if not CORRUPT_RE.search(r["payload"])]
    test_rows = [r for r in raw_test if not CORRUPT_RE.search(r["payload"])]
    train_payloads = [r["payload"] for r in train_rows]
    test_payloads = [r["payload"] for r in test_rows]
    y_train = np.asarray([1 if r["label"] == "anom" else 0 for r in train_rows], dtype=int)
    y_test = np.asarray([1 if r["label"] == "anom" else 0 for r in test_rows], dtype=int)
    for name, labels in (("train", y_train), ("test", y_test)):
        if set(np.unique(labels)) != {0, 1}:
            raise ValueError(f"unexpected binary labels in {name}: {set(np.unique(labels))}")

    fit_idx, val_idx = train_test_split(
        np.arange(len(train_rows)),
        test_size=VALIDATION_FRACTION,
        random_state=SEED,
        stratify=y_train,
    )
    fit_idx = np.sort(fit_idx)
    val_idx = np.sort(val_idx)
    fit_payloads = [train_payloads[int(i)] for i in fit_idx]
    val_payloads = [train_payloads[int(i)] for i in val_idx]

    vectorizer = TfidfVectorizer(**TFIDF_KWARGS)
    vectorizer.fit(fit_payloads)
    scaler = StandardScaler()
    scaler.fit(_lengths(fit_payloads))
    candidate_mats = _build_matrices(
        vectorizer,
        scaler,
        {"fit": fit_payloads, "val": val_payloads, "test": test_payloads},
    )
    y_fit, y_val = y_train[fit_idx], y_train[val_idx]

    candidate_results: dict[str, dict[str, dict[str, Any]]] = {}
    candidate_models: dict[str, Any] = {}
    for spec in SPECS:
        name = spec["name"]
        model = _make_estimator(spec["kind"])
        mode = spec["feature_mode"]
        X_fit, X_val = candidate_mats[mode]["fit"], candidate_mats[mode]["val"]
        if not isinstance(model, LengthThresholdClassifier):
            model.fit(X_fit, y_fit)
        candidate_models[name] = model
        candidate_results[name] = {
            "train": _evaluate(model, X_fit, y_fit),
            "validation": _evaluate(model, X_val, y_val),
        }

    selection_key = lambda n: (
        -candidate_results[n]["validation"]["pr_auc"],
        candidate_results[n]["validation"]["false_positive_rate"],
        -candidate_results[n]["validation"]["f1"],
        n,
    )
    selected_name = min((s["name"] for s in SPECS), key=selection_key)
    selected_spec = next(s for s in SPECS if s["name"] == selected_name)

    # Refit every candidate on the whole supplied training partition for the
    # single final test evaluation. No test-derived information is used for
    # selection or preprocessing.
    final_vectorizer = TfidfVectorizer(**TFIDF_KWARGS)
    final_vectorizer.fit(train_payloads)
    final_scaler = StandardScaler()
    final_scaler.fit(_lengths(train_payloads))
    final_mats = _build_matrices(
        final_vectorizer,
        final_scaler,
        {"train": train_payloads, "test": test_payloads},
    )
    final_models: dict[str, Any] = {}
    test_results: dict[str, dict[str, Any]] = {}
    full_train_results: dict[str, dict[str, Any]] = {}
    for spec in SPECS:
        name, mode = spec["name"], spec["feature_mode"]
        model = _make_estimator(spec["kind"])
        X_train_full, X_test = final_mats[mode]["train"], final_mats[mode]["test"]
        if not isinstance(model, LengthThresholdClassifier):
            model.fit(X_train_full, y_train)
        final_models[name] = model
        full_train_results[name] = _evaluate(model, X_train_full, y_train)
        test_results[name] = _evaluate(model, X_test, y_test)

    selected_model = final_models[selected_name]
    selected_mode = selected_spec["feature_mode"]
    decision_threshold = (
        THRESHOLD
        if isinstance(selected_model, LengthThresholdClassifier)
        else (0.5 if hasattr(selected_model, "predict_proba") else 0.0)
    )
    examples = _pick_examples(test_rows, y_test, per_class=2)

    bundle = {
        "format_version": FORMAT_VERSION,
        "model": selected_model,
        "vectorizer": final_vectorizer,
        "scaler": final_scaler,
        "feature_mode": selected_mode,
        "selected_model_name": selected_name,
        "decision_threshold": decision_threshold,
        "labels": LABELS,
        "seed": SEED,
        "dataset_sha256": zip_sha,
    }

    overfitting = {
        name: {
            "validation_minus_train_pr_auc": float(
                r["validation"]["pr_auc"] - r["train"]["pr_auc"]
            ),
            "validation_minus_train_f1": float(r["validation"]["f1"] - r["train"]["f1"]),
            "train_pr_auc": r["train"]["pr_auc"],
            "validation_pr_auc": r["validation"]["pr_auc"],
        }
        for name, r in candidate_results.items()
    }
    class_distribution = {
        "raw_train": {"norm": 12870, "anom": 7842, "total": 20712},
        "raw_test": {"norm": 6434, "anom": 3921, "total": 10355},
        "used_train": {
            "norm": int(np.sum(y_train == 0)),
            "anom": int(np.sum(y_train == 1)),
            "total": int(len(y_train)),
        },
        "used_test": {
            "norm": int(np.sum(y_test == 0)),
            "anom": int(np.sum(y_test == 1)),
            "total": int(len(y_test)),
        },
        "fit_subset": {
            "norm": int(np.sum(y_fit == 0)),
            "anom": int(np.sum(y_fit == 1)),
            "total": int(len(y_fit)),
        },
        "validation_subset": {
            "norm": int(np.sum(y_val == 0)),
            "anom": int(np.sum(y_val == 1)),
            "total": int(len(y_val)),
        },
    }
    metadata = {
        "format_version": FORMAT_VERSION,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "project": "APISentry AI research-only HTTP payload classifier",
        "task": "binary payload classification (norm=0 benign, anom=1 anomalous)",
        "selected_model_name": selected_name,
        "feature_mode": selected_mode,
        "decision_threshold": decision_threshold,
        "seed": SEED,
        "validation_fraction": VALIDATION_FRACTION,
        "length_rule_threshold": THRESHOLD,
        "labels": LABELS,
        "dataset_archive": str(ZIP_PATH.relative_to(_ROOT)),
        "dataset_sha256": zip_sha,
        "member_sha256": member_sha,
        "split_counts": {
            "raw_train": 20712,
            "raw_test": 10355,
            "used_train": int(len(train_rows)),
            "used_test": int(len(test_rows)),
            "fit_subset": int(len(fit_idx)),
            "validation_subset": int(len(val_idx)),
        },
        "selection_rule": (
            "maximum validation PR-AUC; tie-breaks: lower validation FPR, higher validation F1, "
            "then model name. Final test evaluated once after selection and final refit."
        ),
        "versions": {
            "python": platform.python_version(),
            "numpy": np.__version__,
            "scikit_learn": sklearn.__version__,
            "joblib": joblib.__version__,
        },
        "research_only": True,
    }
    training_config = {
        "seed": SEED,
        "validation_fraction": VALIDATION_FRACTION,
        "length_threshold": THRESHOLD,
        "tfidf": {**TFIDF_KWARGS, "dtype": "np.float32"},
        "logistic_regression": LR_KWARGS,
        "linear_svm": SVM_KWARGS,
        "specs": SPECS,
        "data_quality_policy": {
            "corrupt_records": "excluded from training and evaluation (in-memory filter only)",
            "length_mismatches": (
                "retained; stored length column ignored; length recomputed from payload text"
            ),
            "source_archive": "read-only, never modified or overwritten",
            "attack_type": "never used as a feature",
            "final_test": "evaluated once after validation-only model selection",
        },
    }
    data_quality = {
        "corrupt_records": corrupt,
        "length_mismatches": mismatches,
        "counts": {
            "corrupt_train": sum(r["source_file"] == "payload_train.csv" for r in corrupt),
            "corrupt_test": sum(r["source_file"] == "payload_test.csv" for r in corrupt),
            "mismatch_train": sum(r["source_file"] == "payload_train.csv" for r in mismatches),
            "mismatch_test": sum(r["source_file"] == "payload_test.csv" for r in mismatches),
        },
        "source_integrity": {
            "archive_sha256_before_training": zip_sha,
            "member_sha256": member_sha,
            "source_files_modified": False,
        },
    }
    evaluation = {
        "class_distribution": class_distribution,
        "candidate_validation": candidate_results,
        "final_full_train": full_train_results,
        "final_test": test_results,
        "overfitting_analysis": overfitting,
        "selection": {
            "selected_model": selected_name,
            "rule": metadata["selection_rule"],
            "validation_pr_auc": candidate_results[selected_name]["validation"]["pr_auc"],
        },
        "length_shortcut": {
            "deterministic_rule": "> 28 characters => anomalous",
            "validation_pr_auc": candidate_results["length_threshold"]["validation"]["pr_auc"],
            "test_pr_auc": test_results["length_threshold"]["pr_auc"],
            "test_f1": test_results["length_threshold"]["f1"],
            "test_fpr": test_results["length_threshold"]["false_positive_rate"],
            "selected_test_pr_auc": test_results[selected_name]["pr_auc"],
            "selected_test_f1": test_results[selected_name]["f1"],
        },
        "notes": [
            "Metrics are research-benchmark results on generated scanner payloads versus "
            "CSIC-derived benign values; they do not establish real-world API detection accuracy.",
            "Latency was measured on this machine with batch predict; no hardware normalization.",
        ],
    }

    ARTIFACT_DIR.mkdir(parents=True, exist_ok=False)
    _write_joblib(ARTIFACT_DIR / "model.joblib", selected_model)
    _write_joblib(ARTIFACT_DIR / "vectorizer.joblib", final_vectorizer)
    _write_joblib(ARTIFACT_DIR / "scaler.joblib", final_scaler)
    _write_joblib(ARTIFACT_DIR / "model_bundle.joblib", bundle)
    _write_json(ARTIFACT_DIR / "metadata.json", metadata)
    _write_json(ARTIFACT_DIR / "training_config.json", training_config)
    _write_json(ARTIFACT_DIR / "data_quality.json", data_quality)
    _write_json(ARTIFACT_DIR / "evaluation.json", evaluation)
    _write_json(ARTIFACT_DIR / "examples.json", examples)

    eval_md = "\n".join(
        [
            "# HTTP Payload Classifier — Research Evaluation",
            "",
            "**Research-only artifact. Not integrated with runtime detection or enforcement.**",
            "",
            f"- Dataset archive SHA-256: `{zip_sha}`",
            f"- Seed: {SEED}; validation fraction: {VALIDATION_FRACTION}",
            f"- Selected on validation PR-AUC: **{selected_name}** ({selected_mode})",
            "",
            "## Class distribution",
            "",
            _markdown_table(
                ["partition", "norm", "anom", "total"],
                [
                    [k, str(v["norm"]), str(v["anom"]), str(v["total"])]
                    for k, v in class_distribution.items()
                ],
            ),
            "",
            "## Validation results (selection basis; fitted on train subset only)",
            "",
            _markdown_table(METRIC_HEADERS, _metric_rows(
                {name: r["validation"] for name, r in candidate_results.items()}
            )),
            "",
            "## Final held-out test results (single evaluation after selection)",
            "",
            _markdown_table(METRIC_HEADERS, _metric_rows(test_results)),
            "",
            "## Length-shortcut analysis",
            "",
            f"- Deterministic length rule (> {THRESHOLD} chars) validation PR-AUC: "
            f"{candidate_results['length_threshold']['validation']['pr_auc']:.4f}",
            f"- Deterministic length rule test PR-AUC / F1 / FPR: "
            f"{test_results['length_threshold']['pr_auc']:.4f} / "
            f"{test_results['length_threshold']['f1']:.4f} / "
            f"{test_results['length_threshold']['false_positive_rate']:.4f}",
            f"- Selected model test PR-AUC / F1: {test_results[selected_name]['pr_auc']:.4f} / "
            f"{test_results[selected_name]['f1']:.4f}",
            f"- Text-only vs text+length (validation PR-AUC): "
            f"{candidate_results['tfidf_char_lr']['validation']['pr_auc']:.4f} (LR text) / "
            f"{candidate_results['tfidf_char_len_lr']['validation']['pr_auc']:.4f} (LR text+length) / "
            f"{candidate_results['tfidf_char_svm']['validation']['pr_auc']:.4f} (SVM text) / "
            f"{candidate_results['tfidf_char_len_svm']['validation']['pr_auc']:.4f} (SVM text+length)",
            "",
            "## Overfitting and class bias",
            "",
            _markdown_table(
                ["model", "train PR-AUC", "validation PR-AUC", "val - train PR-AUC", "val - train F1"],
                [
                    [
                        name,
                        f"{v['train_pr_auc']:.4f}",
                        f"{v['validation_pr_auc']:.4f}",
                        f"{v['validation_minus_train_pr_auc']:+.4f}",
                        f"{v['validation_minus_train_f1']:+.4f}",
                    ]
                    for name, v in overfitting.items()
                ],
            ),
            "",
            "## Data quality",
            "",
            f"- Excluded corrupted records: {len(corrupt)} (3 train, 1 test); see `data_quality.json`.",
            f"- Retained length-mismatch records: {len(mismatches)} (7 train, 8 test); "
            "stored length ignored, length recomputed from payload.",
            "- Source ZIP and member files were not modified.",
            "",
            "## Limitations",
            "",
            "- Parameter-value level, not request/session level; no timestamps, hosts or sessions.",
            "- Benign values share CSIC origin; attacks are scanner-generated, not real traffic.",
            "- Do not merge with CSIC, SR-BH or WAMM experiments.",
            "- These results do not establish production or real-world API detection accuracy.",
            "",
        ]
    )
    _write_text(ARTIFACT_DIR / "evaluation.md", eval_md)

    model_card = "\n".join(
        [
            "# Model Card — HTTP Payload Classifier v1",
            "",
            "**Status:** research-only; not integrated into APISentry runtime. No enforcement use.",
            "",
            "## Intended use",
            "",
            "Binary lexical classification of individual HTTP parameter-value strings as "
            "`norm` (benign) or `anom` (anomalous) for research benchmarking and demonstration.",
            "",
            "## Out-of-scope uses",
            "",
            "- Request-level, session-level, or production API attack detection.",
            "- Automated blocking, throttling, banning, or any enforcement action.",
            "- Merging with CSIC, SR-BH, WAMM, bot-detection, or mitigation experiments.",
            "",
            "## Training data",
            "",
            f"- Archive: `{metadata['dataset_archive']}` (SHA-256 `{zip_sha}`).",
            "- Only `payload_train.csv` was used for fitting; `payload_test.csv` was held out.",
            "- `attack_type` was never used as a feature; `payload_full.csv` and "
            "`payload_test_lexical.csv` were not used.",
            "- Benign values originate from CSIC 2010; attacks from sqlmap, XSSYA, Vega and FuzzDB.",
            "",
            "## Model and features",
            "",
            f"- Selected estimator: `{selected_name}`; feature mode: `{selected_mode}`.",
            "- Character n-gram TF-IDF (2-5), fitted on the training partition only.",
            "- Length is recomputed from payload text; the stored `length` column is ignored.",
            "",
            "## Performance summary",
            "",
            f"- Validation PR-AUC: {candidate_results[selected_name]['validation']['pr_auc']:.4f}.",
            f"- Test PR-AUC: {test_results[selected_name]['pr_auc']:.4f}; "
            f"F1: {test_results[selected_name]['f1']:.4f}; "
            f"FPR: {test_results[selected_name]['false_positive_rate']:.4f}.",
            "- See `evaluation.md` and `evaluation.json` for full metrics.",
            "",
            "## Ethical and technical limitations",
            "",
            "- Generator-specific lexical signatures can be memorized; high scores do not imply "
            "real-world detection capability.",
            "- Length is a strong shortcut; length-only and length-ablation results are reported.",
            "- Four label-fragment-corrupted records were excluded; fifteen length-metadata "
            "mismatches were retained with recomputed length.",
            "- Class distribution is imbalanced and the benign class is short CSIC-derived values.",
            "",
        ]
    )
    _write_text(ARTIFACT_DIR / "model_card.md", model_card)

    reproducibility = "\n".join(
        [
            "# Reproducibility — HTTP Payload Classifier v1",
            "",
            "Artifacts are created only once; all writes use exclusive-create guards.",
            "",
            "## Environment",
            "",
            f"- Python {platform.python_version()}, NumPy {np.__version__}, "
            f"scikit-learn {sklearn.__version__}, joblib {joblib.__version__}.",
            "- No packages were installed for this experiment.",
            "",
            "## Train (creates a new isolated artifact directory)",
            "",
            "```powershell",
            "python -B research/scripts/train_http_payload_classifier.py",
            "```",
            "",
            "If `research/models/http_payload_classifier/v1/` already exists, the script refuses "
            "to run rather than overwrite it. Use a new version directory for a new experiment.",
            "",
            "## Prediction demo",
            "",
            "```powershell",
            'python -B research/scripts/predict_http_payload.py "id=1 or 1=1"',
            "python -B research/scripts/predict_http_payload.py --examples",
            "python -B research/scripts/predict_http_payload.py --json \"admin\"",
            "```",
            "",
            "## Tests",
            "",
            "```powershell",
            ".venv\\Scripts\\python.exe -B -m pytest -p no:cacheprovider -q research/tests",
            "```",
            "",
            "## Data handling",
            "",
            "- Source archive is read directly from the ZIP and never modified.",
            "- Only `payload_train.csv` and `payload_test.csv` are used.",
            "- Seed 42; stratified validation fraction 0.2 from the training partition only.",
            "",
        ]
    )
    _write_text(ARTIFACT_DIR / "reproducibility.md", reproducibility)

    print(f"SELECTED: {selected_name} ({selected_mode})")
    print(f"VAL PR-AUC: {candidate_results[selected_name]['validation']['pr_auc']:.6f}")
    print(f"TEST PR-AUC: {test_results[selected_name]['pr_auc']:.6f}")
    print(f"TEST F1: {test_results[selected_name]['f1']:.6f}")
    print(f"ARTIFACTS: {ARTIFACT_DIR}")
    print(f"FILES WRITTEN: {len(OUTPUT_NAMES)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
