
"""Random Forest classifier for API token-usage behavior."""

from pathlib import Path
from typing import Any, Dict, List, Sequence

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix


NORMAL = "Normal"
TOKEN_HIJACKING = "Token Hijacking"
ABNORMAL_TOKEN_USAGE = "Abnormal Token Usage"

ALLOWED_LABELS = {
    NORMAL,
    TOKEN_HIJACKING,
    ABNORMAL_TOKEN_USAGE,
}


class TokenUsageRandomForestClassifier:
    """Classify API behavior using labeled numeric features.

    Only load model files created by a trusted training process.
    """

    CHECKPOINT_VERSION = 1

    def __init__(
        self,
        n_estimators: int = 200,
        random_state: int = 42,
    ) -> None:
        if (
            not isinstance(n_estimators, int)
            or isinstance(n_estimators, bool)
            or n_estimators < 1
        ):
            raise ValueError("n_estimators must be a positive integer")

        self.n_estimators = n_estimators
        self.random_state = random_state
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            class_weight="balanced",
            random_state=random_state,
        )
        self.feature_names: List[str] = []
        self.is_fitted = False

    @staticmethod
    def _validate_features(
        feature_vectors: Any,
        feature_names: Sequence[str] | None = None,
    ) -> np.ndarray:
        try:
            matrix = np.asarray(feature_vectors, dtype=np.float64)
        except (TypeError, ValueError) as exc:
            raise ValueError("Features must be a numeric 2D matrix") from exc

        if matrix.ndim != 2:
            raise ValueError("Features must be a 2D matrix")

        if matrix.shape[0] < 1:
            raise ValueError("At least one feature row is required")

        if matrix.shape[1] < 1:
            raise ValueError("At least one feature column is required")

        if not np.isfinite(matrix).all():
            raise ValueError("Features must contain only finite values")

        if feature_names is not None:
            names = list(feature_names)

            if len(names) != matrix.shape[1]:
                raise ValueError(
                    "The number of feature names must match feature columns"
                )

            if (
                any(not isinstance(name, str) or not name.strip() for name in names)
                or len(set(names)) != len(names)
            ):
                raise ValueError(
                    "Feature names must be non-empty, unique strings"
                )

        return matrix

    @staticmethod
    def _validate_labels(
        labels: Sequence[str],
        expected_count: int,
    ) -> List[str]:
        if isinstance(labels, (str, bytes)):
            raise ValueError("labels must be a sequence of class labels")

        try:
            values = list(labels)
        except TypeError as exc:
            raise ValueError("labels must be a sequence of class labels") from exc

        if len(values) != expected_count:
            raise ValueError("Number of labels must match number of feature rows")

        invalid = sorted(
            {
                repr(label)
                for label in values
                if not isinstance(label, str) or label not in ALLOWED_LABELS
            }
        )

        if invalid:
            raise ValueError(
                "Unknown label(s): "
                + ", ".join(invalid)
                + ". Allowed labels are: "
                + ", ".join(sorted(ALLOWED_LABELS))
            )

        return values

    def fit(
        self,
        feature_vectors: Any,
        labels: Sequence[str],
        feature_names: Sequence[str] | None = None,
    ) -> "TokenUsageRandomForestClassifier":
        """Train using labeled examples from all three classes."""
        matrix = self._validate_features(feature_vectors, feature_names)
        label_values = self._validate_labels(labels, len(matrix))

        missing = ALLOWED_LABELS - set(label_values)
        if missing:
            raise ValueError(
                "Training data must contain all three classes; missing: "
                + ", ".join(sorted(missing))
            )

        names = (
            list(feature_names)
            if feature_names is not None
            else [f"feature_{index}" for index in range(matrix.shape[1])]
        )

        self.model.fit(matrix, label_values)
        self.feature_names = names
        self.is_fitted = True
        return self

    def predict(self, feature_vectors: Any) -> List[Dict[str, Any]]:
        """Return predicted labels and estimated class probabilities."""
        if not self.is_fitted:
            raise RuntimeError("Classifier must be fitted before prediction")

        matrix = self._validate_features(feature_vectors)

        if matrix.shape[1] != len(self.feature_names):
            raise ValueError(
                f"Expected {len(self.feature_names)} feature columns, "
                f"received {matrix.shape[1]}"
            )

        labels = self.model.predict(matrix)
        probabilities = self.model.predict_proba(matrix)
        class_names = list(self.model.classes_)

        results = []
        for label, row_probabilities in zip(labels, probabilities):
            probability_map = {
                str(class_name): float(probability)
                for class_name, probability in zip(
                    class_names, row_probabilities
                )
            }
            results.append(
                {
                    "predicted_label": str(label),
                    "confidence": float(np.max(row_probabilities)),
                    "class_probabilities": probability_map,
                }
            )

        return results

    def evaluate(
        self,
        feature_vectors: Any,
        true_labels: Sequence[str],
    ) -> Dict[str, Any]:
        """Evaluate on labeled data; use held-out examples for honest metrics."""
        if not self.is_fitted:
            raise RuntimeError("Classifier must be fitted before evaluation")

        matrix = self._validate_features(feature_vectors)
        if matrix.shape[1] != len(self.feature_names):
            raise ValueError(
                f"Expected {len(self.feature_names)} feature columns, "
                f"received {matrix.shape[1]}"
            )

        labels = self._validate_labels(true_labels, len(matrix))
        predictions = self.model.predict(matrix)
        ordered_labels = sorted(ALLOWED_LABELS)

        return {
            "sample_count": int(len(matrix)),
            "accuracy": float(accuracy_score(labels, predictions)),
            "labels": ordered_labels,
            "confusion_matrix": confusion_matrix(
                labels, predictions, labels=ordered_labels
            ).tolist(),
            "classification_report": classification_report(
                labels,
                predictions,
                labels=ordered_labels,
                output_dict=True,
                zero_division=0,
            ),
        }

    def save(self, file_path: str) -> None:
        """Save the fitted model and its feature metadata."""
        if not self.is_fitted:
            raise RuntimeError("Cannot save an unfitted classifier")

        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        checkpoint = {
            "version": self.CHECKPOINT_VERSION,
            "n_estimators": self.n_estimators,
            "random_state": self.random_state,
            "feature_names": self.feature_names,
            "model": self.model,
        }
        joblib.dump(checkpoint, path)

    @classmethod
    def load(cls, file_path: str) -> "TokenUsageRandomForestClassifier":
        """Load a classifier saved by this service.

        SECURITY: joblib files can execute code while loading. Only load
        checkpoints from a trusted location created by your own application.
        """
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Classifier checkpoint not found: {path}")

        checkpoint = joblib.load(path)

        if not isinstance(checkpoint, dict):
            raise ValueError("Invalid classifier checkpoint")

        if checkpoint.get("version") != cls.CHECKPOINT_VERSION:
            raise ValueError("Unsupported or invalid checkpoint version")

        model = checkpoint.get("model")
        feature_names = checkpoint.get("feature_names")
        n_estimators = checkpoint.get("n_estimators")
        random_state = checkpoint.get("random_state")

        if not isinstance(model, RandomForestClassifier):
            raise ValueError("Checkpoint does not contain a Random Forest model")

        if not isinstance(feature_names, list) or not feature_names:
            raise ValueError("Invalid checkpoint feature names")

        if (
            any(not isinstance(name, str) or not name.strip() for name in feature_names)
            or len(set(feature_names)) != len(feature_names)
        ):
            raise ValueError("Invalid checkpoint feature names")

        if not hasattr(model, "n_features_in_"):
            raise ValueError("Checkpoint model has not been fitted")

        if model.n_features_in_ != len(feature_names):
            raise ValueError("Checkpoint feature count does not match model")

        model_classes = set(model.classes_.tolist())
        if model_classes != ALLOWED_LABELS:
            raise ValueError("Checkpoint is missing one or more required classes")

        classifier = cls(
            n_estimators=n_estimators,
            random_state=random_state,
        )
        classifier.model = model
        classifier.feature_names = list(feature_names)
        classifier.is_fitted = True
        return classifier
