"""Standalone, research-only live prediction demo for the HTTP payload classifier.

The payload is treated strictly as text. It is never evaluated, executed, or sent
anywhere. All outputs are advisory research outputs, not security decisions.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

import joblib
import numpy as np
from scipy.sparse import csr_matrix, hstack

# Allow direct invocation from any working directory so bundled custom classes
# can be unpickled by their fully qualified module path.
_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

ARTIFACT_DIR = Path(__file__).resolve().parents[1] / "models" / "http_payload_classifier" / "v1"
BUNDLE_NAME = "model_bundle.joblib"
EXAMPLES_NAME = "examples.json"
FORMAT_VERSION = 1
MAX_PAYLOAD_CHARS = 10000
LABELS = {0: "benign", 1: "anomalous"}


class LengthThresholdClassifier:
    """Picklable deterministic length-rule baseline used by the experiment."""

    def __init__(self, threshold: int = 28) -> None:
        self.threshold = int(threshold)

    def predict(self, X: Any) -> np.ndarray:
        lengths = X.toarray().ravel() if hasattr(X, "toarray") else np.asarray(X).ravel()
        return (lengths > self.threshold).astype(int)

    def decision_function(self, X: Any) -> np.ndarray:
        lengths = X.toarray().ravel() if hasattr(X, "toarray") else np.asarray(X).ravel()
        return lengths.astype(float)


def validate_payload(payload: Any) -> str:
    """Validate CLI/text input without modifying or executing it."""
    if payload is None:
        raise ValueError("payload must be a string, not None")
    if not isinstance(payload, str):
        raise ValueError("payload must be a string")
    if payload.strip() == "":
        raise ValueError("payload must not be empty or whitespace-only")
    if len(payload) > MAX_PAYLOAD_CHARS:
        raise ValueError(
            f"payload is too long ({len(payload)} chars); limit is {MAX_PAYLOAD_CHARS}"
        )
    return payload


def load_bundle(artifact_dir: str | Path | None = None) -> dict[str, Any]:
    """Load and validate the saved research artifact bundle."""
    directory = Path(artifact_dir) if artifact_dir is not None else ARTIFACT_DIR
    bundle_path = directory / BUNDLE_NAME
    if not bundle_path.is_file():
        raise FileNotFoundError(f"model bundle not found: {bundle_path}")
    bundle = joblib.load(bundle_path)
    if not isinstance(bundle, dict):
        raise ValueError("model bundle must be a dictionary")
    required = {
        "format_version",
        "model",
        "vectorizer",
        "scaler",
        "feature_mode",
        "selected_model_name",
        "decision_threshold",
        "labels",
        "seed",
        "dataset_sha256",
    }
    missing = sorted(required - set(bundle))
    if missing:
        raise ValueError(f"model bundle is missing keys: {missing}")
    if bundle["format_version"] != FORMAT_VERSION:
        raise ValueError(
            f"unsupported artifact format_version {bundle['format_version']!r}; "
            f"expected {FORMAT_VERSION}"
        )
    if bundle["feature_mode"] not in {"length_raw", "length_scaled", "text", "text_length"}:
        raise ValueError(f"unknown feature_mode: {bundle['feature_mode']!r}")
    if bundle["labels"] != LABELS:
        raise ValueError(f"unsupported label mapping: {bundle['labels']!r}")
    return bundle


def transform_payloads(payloads: Sequence[str], bundle: dict[str, Any]) -> Any:
    """Apply exactly the fitted preprocessing stored with the model."""
    if not payloads:
        raise ValueError("at least one payload is required")
    for value in payloads:
        validate_payload(value)
    mode = bundle["feature_mode"]
    if mode == "text":
        return bundle["vectorizer"].transform(list(payloads))
    lengths = np.asarray([[len(value)] for value in payloads], dtype=np.float64)
    if mode == "length_raw":
        return csr_matrix(lengths.astype(np.float32))
    scaled = csr_matrix(bundle["scaler"].transform(lengths).astype(np.float32))
    if mode == "length_scaled":
        return scaled
    text = bundle["vectorizer"].transform(list(payloads))
    return hstack([text, scaled], format="csr")


def predict_payload(payload: str, bundle: dict[str, Any]) -> dict[str, Any]:
    """Return an advisory binary prediction with a clearly interpreted score."""
    value = validate_payload(payload)
    X = transform_payloads([value], bundle)
    model = bundle["model"]
    result: dict[str, Any] = {
        "model_name": bundle["selected_model_name"],
        "feature_mode": bundle["feature_mode"],
        "payload_length": len(value),
        "payload": value,
    }
    if hasattr(model, "predict_proba"):
        score = float(np.asarray(model.predict_proba(X)[:, 1]).ravel()[0])
        label_int = int(score >= 0.5)
        score_type = "probability"
        interpretation = (
            f"P(anomalous) = {score:.4f}; threshold 0.50 -> {LABELS[label_int]}."
        )
    elif hasattr(model, "decision_function"):
        score = float(np.asarray(model.decision_function(X)).ravel()[0])
        label_int = int(score >= 0.0)
        score_type = "decision_score"
        interpretation = (
            f"Decision score = {score:+.4f}; positive favors anomalous "
            f"(threshold 0.00) -> {LABELS[label_int]}."
        )
    else:
        label_int = int(np.asarray(model.predict(X)).ravel()[0])
        score = None
        score_type = "none"
        interpretation = f"Hard class label only -> {LABELS[label_int]}."
    result.update(
        {
            "label": LABELS[label_int],
            "label_int": label_int,
            "score_type": score_type,
            "score": score,
            "decision_threshold": bundle["decision_threshold"],
            "interpretation": interpretation
            + " Advisory research output only; not an enforcement decision.",
        }
    )
    return result


def _format_result(result: dict[str, Any]) -> str:
    score = result["score"]
    score_text = "n/a" if score is None else f"{score:+.4f}"
    return "\n".join(
        [
            f"Model: {result['model_name']} (features: {result['feature_mode']})",
            f"Payload length: {result['payload_length']} characters",
            f"Prediction: {result['label']}",
            f"Score type: {result['score_type']}",
            f"Score: {score_text}",
            f"Interpretation: {result['interpretation']}",
        ]
    )


def _show_examples(bundle: dict[str, Any], artifact_dir: Path) -> None:
    examples_path = artifact_dir / EXAMPLES_NAME
    if not examples_path.is_file():
        raise FileNotFoundError(f"examples file not found: {examples_path}")
    examples = json.loads(examples_path.read_text(encoding="utf-8"))
    print(f"Representative held-out test examples (n={len(examples)}):")
    for i, example in enumerate(examples, 1):
        payload = example["payload"]
        prediction = predict_payload(payload, bundle)
        shown = payload if len(payload) <= 120 else payload[:117] + "..."
        print(
            f"[{i}] true={example['label']} predicted={prediction['label']} "
            f"score={prediction['score']!r} payload={shown!r}"
        )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Research-only binary HTTP payload prediction (text is never executed)."
    )
    parser.add_argument("payload", nargs="?", help="payload string to classify")
    parser.add_argument(
        "--examples", action="store_true", help="show held-out test examples and predictions"
    )
    parser.add_argument("--artifact-dir", default=None, help="override artifact directory")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args(argv)
    if args.payload is None and not args.examples:
        parser.error("provide a payload string or --examples")

    artifact_dir = Path(args.artifact_dir) if args.artifact_dir else ARTIFACT_DIR
    try:
        bundle = load_bundle(artifact_dir)
        if args.examples:
            _show_examples(bundle, artifact_dir)
            return 0
        result = predict_payload(args.payload, bundle)
    except (ValueError, FileNotFoundError) as exc:
        print(f"INPUT/ARTIFACT ERROR: {exc}", file=sys.stderr)
        return 2 if args.payload is not None else 3

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(_format_result(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
