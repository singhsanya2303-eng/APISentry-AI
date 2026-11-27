"""Offline, leakage-safe training workflow for verified tabular datasets."""

from collections import Counter
import math
from pathlib import Path
from typing import Any, Mapping, Sequence

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from app.services.token_usage_classifier_service import ALLOWED_LABELS


PIPELINE_VERSION = 1


def _matrix(
    feature_rows: Sequence[Mapping[str, Any]],
    feature_names: Sequence[str],
) -> np.ndarray:
    names = list(feature_names)
    if not names or len(set(names)) != len(names):
        raise ValueError("feature_names must be non-empty and unique")
    if not feature_rows:
        raise ValueError("At least one feature row is required")

    values = []
    for row in feature_rows:
        if set(row) != set(names):
            raise ValueError("Every feature row must match feature_names exactly")
        values.append([row[name] for name in names])

    try:
        matrix = np.asarray(values, dtype=np.float64)
    except (TypeError, ValueError) as exc:
        raise ValueError("Feature values must be numeric") from exc

    if matrix.ndim != 2 or not np.isfinite(matrix).all():
        raise ValueError("Feature values must be a finite numeric matrix")
    return matrix


def _labels(labels: Sequence[str], expected_count: int) -> list[str]:
    values = list(labels)
    if len(values) != expected_count:
        raise ValueError("Number of labels must match feature rows")
    if not set(values).issubset(ALLOWED_LABELS):
        raise ValueError("Labels contain unsupported token-usage classes")
    if set(values) != ALLOWED_LABELS:
        raise ValueError("Training data must contain all token-usage classes")
    return values


def _metrics(model, scaler, rows, labels) -> dict[str, Any]:
    predictions = model.predict(scaler.transform(rows))
    return {
        "sample_count": len(labels),
        "accuracy": float(accuracy_score(labels, predictions)),
        "classification_report": classification_report(
            labels,
            predictions,
            output_dict=True,
            zero_division=0,
        ),
    }


def _minimum_samples_per_class(validation_size: float, test_size: float) -> int:
    """Minimum samples per class required by the two-stage stratified split.

    Stage 1 sends ``validation_size + test_size`` of every class into the
    held-out set, and stage 2 splits that held-out set again. scikit-learn's
    stratified split requires at least two members of every class in any set
    that is itself split, and at least one member in each resulting partition.
    Computing this from the configured fractions (rather than assuming a fixed
    number) keeps the check honest if the split configuration changes, and
    rejects undersized input before either ``train_test_split`` call is made.
    """
    held_out_fraction = validation_size + test_size
    requirements = (
        2,
        math.ceil(2 / held_out_fraction),
        math.ceil(1 / (1 - held_out_fraction)),
        math.ceil(1 / validation_size),
        math.ceil(1 / test_size),
    )
    return max(requirements)


def train_token_classifier_pipeline(
    feature_rows: Sequence[Mapping[str, Any]],
    labels: Sequence[str],
    feature_names: Sequence[str],
    artifact_path: str | Path,
    *,
    validation_size: float = 0.2,
    test_size: float = 0.2,
    random_state: int = 42,
) -> dict[str, Any]:
    """Train and persist a validated model using train-only preprocessing.

    This function performs no data acquisition. Metrics are returned only for
    the caller-supplied held-out partitions.
    """
    if not 0 < validation_size < 1 or not 0 < test_size < 1:
        raise ValueError("validation_size and test_size must be between 0 and 1")
    if validation_size + test_size >= 1:
        raise ValueError("validation_size and test_size must leave training data")

    matrix = _matrix(feature_rows, feature_names)
    label_values = _labels(labels, len(matrix))
    minimum_per_class = _minimum_samples_per_class(validation_size, test_size)
    class_counts = Counter(label_values)
    least_populated = min(class_counts.values())
    if least_populated < minimum_per_class:
        raise ValueError(
            f"At least {minimum_per_class} samples per class are required for the "
            f"two-stage stratified split (validation_size={validation_size}, "
            f"test_size={test_size}); the least-represented class has "
            f"{least_populated} sample(s)."
        )

    train_rows, held_out_rows, train_labels, held_out_labels = train_test_split(
        matrix,
        label_values,
        test_size=validation_size + test_size,
        random_state=random_state,
        stratify=label_values,
    )
    relative_test_size = test_size / (validation_size + test_size)
    validation_rows, test_rows, validation_labels, test_labels = train_test_split(
        held_out_rows,
        held_out_labels,
        test_size=relative_test_size,
        random_state=random_state,
        stratify=held_out_labels,
    )

    expected_classes = set(label_values)
    if any(set(partition) != expected_classes for partition in (
        train_labels,
        validation_labels,
        test_labels,
    )):
        raise ValueError("Every split must contain every class")

    scaler = StandardScaler()
    scaled_train = scaler.fit_transform(train_rows)
    model = RandomForestClassifier(
        n_estimators=200,
        class_weight="balanced",
        random_state=random_state,
    )
    model.fit(scaled_train, train_labels)

    artifact = {
        "version": PIPELINE_VERSION,
        "n_estimators": model.n_estimators,
        "random_state": random_state,
        "feature_names": list(feature_names),
        "class_labels": sorted(expected_classes),
        "scaler": scaler,
        "model": model,
    }
    path = Path(artifact_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, path)

    return {
        "version": PIPELINE_VERSION,
        "feature_names": list(feature_names),
        "train": _metrics(model, scaler, train_rows, train_labels),
        "validation": _metrics(model, scaler, validation_rows, validation_labels),
        "test": _metrics(model, scaler, test_rows, test_labels),
        "artifact_path": str(path),
    }


def load_token_classifier_pipeline(
    artifact_path: str | Path,
) -> dict[str, Any]:
    """Load and validate an offline pipeline artifact from a trusted path."""
    path = Path(artifact_path)
    if not path.is_file():
        raise FileNotFoundError(f"Training artifact not found: {path}")

    artifact = joblib.load(path)
    if not isinstance(artifact, dict) or artifact.get("version") != PIPELINE_VERSION:
        raise ValueError("Unsupported or invalid training artifact")

    feature_names = artifact.get("feature_names")
    scaler = artifact.get("scaler")
    model = artifact.get("model")
    if (
        not isinstance(feature_names, list)
        or not feature_names
        or len(set(feature_names)) != len(feature_names)
        or not hasattr(scaler, "transform")
        or not hasattr(model, "predict")
        or getattr(scaler, "n_features_in_", None) != len(feature_names)
        or getattr(model, "n_features_in_", None) != len(feature_names)
    ):
        raise ValueError("Training artifact feature metadata is incompatible")

    return artifact
