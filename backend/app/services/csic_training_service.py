"""Research-only training, evaluation, and artifact handling for CSIC 2010.

This module has no runtime consumers. It is imported only by the dedicated
training script and by tests. No result from this module may be wired into
detection, mitigation, or any enforcement path.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping, Sequence

import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.metrics import (
    average_precision_score,
    balanced_accuracy_score,
    confusion_matrix,
    precision_recall_fscore_support,
)
from app.services.csic_http_feature_adapter import (
    LABEL_ANOMALOUS,
    LABEL_NORMAL,
    normalize_payload,
)


ARTIFACT_VERSION = 1

# Fixed before the held-out test partition is evaluated.
ACCEPTANCE_CRITERIA: dict[str, Any] = {
    "definition": (
        "Research benchmark criteria agreed before final test evaluation. "
        "Failure is reported honestly; it does not alter the model or data."
    ),
    "minimum_session_pr_auc": 0.70,
    "minimum_session_recall": 0.60,
    "maximum_session_false_positive_rate": 0.20,
    "must_beat_keyword_baseline_on_session_pr_auc": True,
    "require_zero_session_overlap_across_splits": True,
    "scope_warning": (
        "Meeting these criteria supports only a research benchmark result. It "
        "does not establish real-world API attack detection accuracy."
    ),
}

_KEYWORD_MARKERS = (
    "<script",
    "alert(",
    "--",
    "waitfor delay",
    "drop table",
    "insert into",
    "1=1",
    "#exec",
    "sleep(",
)


def build_models(seed: int) -> dict[str, dict[str, Any]]:
    """Return reproducible baseline specifications for validation selection.

    The linear SVM uses stochastic gradient descent (hinge loss) because the
    liblinear dual/primal solvers do not converge within a practical runtime on
    the 156k-row sparse matrix. It is still a linear SVM decision function;
    ranking metrics use its margin rather than calibrated probabilities.
    """
    return {
        "tfidf_logistic_regression": {
            "estimator": LogisticRegression(
                class_weight="balanced",
                max_iter=100,
                solver="liblinear",
                random_state=seed,
            ),
            "feature_view": "combined",
            "score_kind": "probability",
            "threshold": 0.5,
        },
        "tfidf_linear_svm": {
            "estimator": SGDClassifier(
                loss="hinge",
                class_weight="balanced",
                max_iter=20,
                random_state=seed,
                n_jobs=-1,
            ),
            "feature_view": "combined",
            "score_kind": "margin",
            "threshold": 0.0,
        },
        "structured_logistic_regression": {
            "estimator": LogisticRegression(
                class_weight="balanced",
                max_iter=100,
                solver="liblinear",
                random_state=seed,
            ),
            "feature_view": "structured",
            "score_kind": "probability",
            "threshold": 0.5,
        },
    }


def _scores(spec: Mapping[str, Any], estimator: Any, matrix: Any) -> np.ndarray:
    if spec["score_kind"] == "probability":
        return np.asarray(estimator.predict_proba(matrix)[:, 1], dtype=float)
    if spec["score_kind"] == "margin":
        return np.asarray(estimator.decision_function(matrix), dtype=float)
    raise ValueError(f"unsupported score kind: {spec['score_kind']}")


def fit_models(
    specs: Mapping[str, Mapping[str, Any]],
    features: Mapping[str, Any],
) -> dict[str, Any]:
    fitted: dict[str, Any] = {}
    for name, spec in specs.items():
        view = spec["feature_view"]
        estimator = spec["estimator"]
        estimator.fit(getattr(features, view), features.labels)
        fitted[name] = {
            "spec": dict(spec),
            "estimator": estimator,
        }
    return fitted


def keyword_baseline_scores(records: Sequence[Any]) -> np.ndarray:
    """Deterministic comparison rule; never used as a model feature or target."""
    scores = []
    for record in records:
        decoded = normalize_payload(record.payload).lower()
        scores.append(1.0 if any(marker in decoded for marker in _KEYWORD_MARKERS) else 0.0)
    return np.asarray(scores, dtype=float)


def aggregate_session_scores(
    sessions: Sequence[str],
    scores: Sequence[float],
    labels: Sequence[str],
) -> tuple[np.ndarray, np.ndarray]:
    """Reduce request scores to one score per session using max pooling."""
    if not (len(sessions) == len(scores) == len(labels)):
        raise ValueError("sessions, scores, and labels must have equal length")
    best: dict[str, tuple[float, str]] = {}
    for session, score, label in zip(sessions, scores, labels):
        value = float(score)
        if session not in best or value > best[session][0]:
            best[session] = (value, str(label))
    session_scores = np.asarray([value[0] for value in best.values()], dtype=float)
    session_labels = np.asarray([value[1] for value in best.values()])
    return session_scores, session_labels


def compute_metrics(
    labels: Sequence[str],
    scores: Sequence[float],
    *,
    threshold: float,
) -> dict[str, Any]:
    """Compute binary and per-class metrics for the positive ``anom`` class."""
    y_true = np.asarray([1 if label == LABEL_ANOMALOUS else 0 for label in labels])
    score_array = np.asarray(scores, dtype=float)
    if y_true.shape != score_array.shape or y_true.size == 0:
        raise ValueError("labels and scores must be non-empty and equal in length")
    y_pred = (score_array >= threshold).astype(int)

    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average="binary", pos_label=1, zero_division=0
    )
    class_precision, class_recall, class_f1, support = precision_recall_fscore_support(
        y_true, y_pred, labels=[0, 1], zero_division=0
    )
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    false_positive_rate = float(fp / (fp + tn)) if (fp + tn) else 0.0

    return {
        "sample_count": int(y_true.size),
        "positive_count": int(y_true.sum()),
        "threshold": float(threshold),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "pr_auc": float(average_precision_score(y_true, score_array)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "confusion_matrix": {
            "true_negative": int(tn),
            "false_positive": int(fp),
            "false_negative": int(fn),
            "true_positive": int(tp),
        },
        "false_positive_rate": false_positive_rate,
        "per_class": {
            LABEL_NORMAL: {
                "precision": float(class_precision[0]),
                "recall": float(class_recall[0]),
                "f1": float(class_f1[0]),
                "support": int(support[0]),
            },
            LABEL_ANOMALOUS: {
                "precision": float(class_precision[1]),
                "recall": float(class_recall[1]),
                "f1": float(class_f1[1]),
                "support": int(support[1]),
            },
        },
    }


def evaluate_predictions(
    labels: Sequence[str],
    scores: Sequence[float],
    sessions: Sequence[str],
    *,
    threshold: float,
) -> dict[str, Any]:
    """Evaluate both request-level and session-level behaviour."""
    session_scores, session_labels = aggregate_session_scores(sessions, scores, labels)
    return {
        "request_level": compute_metrics(labels, scores, threshold=threshold),
        "session_level": compute_metrics(session_labels, session_scores, threshold=threshold),
    }


def evaluate_all_models(
    fitted: Mapping[str, Mapping[str, Any]],
    features: Mapping[str, Any],
    records: Sequence[Any],
) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    for name, item in fitted.items():
        spec = item["spec"]
        scores = _scores(spec, item["estimator"], getattr(features, spec["feature_view"]))
        results[name] = evaluate_predictions(
            features.labels,
            scores,
            features.sessions,
            threshold=spec["threshold"],
        )
    scores = keyword_baseline_scores(records)
    results["deterministic_keyword_baseline"] = evaluate_predictions(
        [record.label for record in records],
        scores,
        [record.session for record in records],
        threshold=0.5,
    )
    return results


def select_model(validation_results: Mapping[str, Mapping[str, Any]]) -> str:
    """Choose by validation session PR-AUC; exclude the rule baseline."""
    candidates = {
        name: result["session_level"]["pr_auc"]
        for name, result in validation_results.items()
        if name != "deterministic_keyword_baseline"
    }
    if not candidates:
        raise ValueError("no trained model available for selection")
    return max(candidates, key=lambda name: (candidates[name], name))


def check_acceptance(
    selected_test: Mapping[str, Any],
    baseline_test: Mapping[str, Any],
    session_overlap_conflicts: int,
) -> dict[str, Any]:
    """Evaluate pre-declared criteria against measured test metrics."""
    session = selected_test["session_level"]
    baseline_pr_auc = baseline_test["session_level"]["pr_auc"]
    checks = {
        "minimum_session_pr_auc": session["pr_auc"] >= ACCEPTANCE_CRITERIA["minimum_session_pr_auc"],
        "minimum_session_recall": session["recall"] >= ACCEPTANCE_CRITERIA["minimum_session_recall"],
        "maximum_session_false_positive_rate": (
            session["false_positive_rate"]
            <= ACCEPTANCE_CRITERIA["maximum_session_false_positive_rate"]
        ),
        "must_beat_keyword_baseline_on_session_pr_auc": (
            session["pr_auc"] > baseline_pr_auc
        ),
        "require_zero_session_overlap_across_splits": session_overlap_conflicts == 0,
    }
    return {
        "criteria": dict(ACCEPTANCE_CRITERIA),
        "checks": checks,
        "passed": all(checks.values()),
        "measured_session_pr_auc": session["pr_auc"],
        "baseline_session_pr_auc": baseline_pr_auc,
    }


def save_artifact(path: str | Path, artifact: Mapping[str, Any]) -> Path:
    """Persist a research artifact with an explicit no-overwrite guard."""
    destination = Path(path)
    if destination.exists():
        raise FileExistsError(f"refusing to overwrite existing artifact: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(dict(artifact), destination)
    return destination


def load_artifact(path: str | Path) -> dict[str, Any]:
    """Load and validate a trusted CSIC research artifact."""
    source = Path(path)
    if not source.is_file():
        raise FileNotFoundError(f"CSIC research artifact not found: {source}")
    artifact = joblib.load(source)
    required = {
        "artifact_version",
        "model_name",
        "model",
        "adapter",
        "feature_view",
        "score_kind",
        "threshold",
        "feature_schema",
        "dataset_sha256",
        "split_summary",
        "evaluation",
        "research_only",
    }
    if not isinstance(artifact, dict) or not required <= set(artifact):
        raise ValueError("invalid CSIC research artifact structure")
    if artifact["artifact_version"] != ARTIFACT_VERSION:
        raise ValueError("unsupported CSIC research artifact version")
    if artifact["research_only"] is not True:
        raise ValueError("CSIC research artifact must be marked research_only")
    if not getattr(artifact["adapter"], "is_fitted", False):
        raise ValueError("CSIC research artifact adapter is not fitted")
    if not hasattr(artifact["model"], "predict"):
        raise ValueError("CSIC research artifact model is invalid")
    return artifact


def predict_with_artifact(artifact: Mapping[str, Any], records: Sequence[Any]) -> list[dict[str, Any]]:
    """Return advisory predictions only; never used by production routes."""
    features = artifact["adapter"].transform(records)
    matrix = getattr(features, artifact["feature_view"])
    scores = _scores(artifact, artifact["model"], matrix)
    predictions = []
    for record, score in zip(records, scores):
        label = (
            LABEL_ANOMALOUS
            if score >= float(artifact["threshold"])
            else LABEL_NORMAL
        )
        predictions.append(
            {
                "predicted_label": label,
                "score": float(score),
                "research_only": True,
            }
        )
    return predictions


def write_json_guard(path: str | Path, payload: Mapping[str, Any]) -> Path:
    """Write a JSON file only when it does not already exist."""
    destination = Path(path)
    if destination.exists():
        raise FileExistsError(f"refusing to overwrite existing file: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return destination


def render_report(report: Mapping[str, Any]) -> str:
    """Render a human-readable research evaluation report."""
    lines = [
        "# CSIC 2010 HTTP Anomaly Classifier — Research Evaluation",
        "",
        "**Research-only artifact. Not integrated with any security decision.**",
        "",
        f"- Dataset SHA-256: `{report['provenance']['archive_sha256']}`",
        f"- Rows: {report['provenance']['row_count']}; sessions: {report['provenance']['session_count']}",
        f"- Selected model: `{report['selected_model']}`",
        f"- Split seed: {report['split']['seed']}",
        "",
        "## Split sizes",
        "",
    ]
    for name, summary in report["split"]["splits"].items():
        lines.append(
            f"- {name}: {summary['row_count']} rows, {summary['session_count']} sessions, "
            f"labels {summary['label_counts']}"
        )
    lines.extend(["", "## Validation results", ""])
    for name, result in report["validation_results"].items():
        session = result["session_level"]
        lines.append(
            f"- {name}: session PR-AUC {session['pr_auc']:.4f}, "
            f"recall {session['recall']:.4f}, F1 {session['f1']:.4f}, "
            f"FPR {session['false_positive_rate']:.4f}"
        )
    lines.extend(["", "## Final held-out test results", ""])
    for name, result in report["test_results"].items():
        session = result["session_level"]
        request = result["request_level"]
        lines.append(
            f"- {name}: session PR-AUC {session['pr_auc']:.4f}, "
            f"recall {session['recall']:.4f}, precision {session['precision']:.4f}, "
            f"F1 {session['f1']:.4f}, balanced accuracy {session['balanced_accuracy']:.4f}, "
            f"FPR {session['false_positive_rate']:.4f}; "
            f"request PR-AUC {request['pr_auc']:.4f}"
        )
    selected = report["test_results"][report["selected_model"]]
    lines.extend(
        [
            "",
            "Confusion matrix (selected model, session level): "
            f"{selected['session_level']['confusion_matrix']}",
            "",
            "## Acceptance criteria",
            "",
            f"- Passed: {report['acceptance']['passed']}",
        ]
    )
    for name, passed in report["acceptance"]["checks"].items():
        lines.append(f"- {name}: {'PASS' if passed else 'FAIL'}")
    lines.extend(["", "## Limitations", ""])
    for limitation in report["provenance"]["limitations"]:
        lines.append(f"- {limitation}")
    lines.append("")
    return "\n".join(lines)
