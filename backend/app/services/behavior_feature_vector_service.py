
"""Convert per-client behavioral profiles into ML-ready numeric vectors."""

from typing import Any, Dict, List, Optional, Sequence

import numpy as np
from sklearn.preprocessing import StandardScaler


DEFAULT_METHODS = ["DELETE", "GET", "PATCH", "POST", "PUT"]


class BehaviorFeatureVectorizer:
    """Create consistent numeric vectors from behavioral profiles."""

    def __init__(
        self,
        methods: Optional[Sequence[str]] = None,
    ) -> None:
        normalized_methods = {
            str(method).strip().upper()
            for method in (methods or DEFAULT_METHODS)
            if str(method).strip()
        }
        self.methods = sorted(normalized_methods)
        self.feature_names: List[str] = []
        self.scaler = StandardScaler()
        self.is_fitted = False

    def _build_matrix(
        self,
        profiles: List[Dict[str, Any]],
    ) -> np.ndarray:
        if not profiles:
            raise ValueError("At least one behavioral profile is required")

        rows = []
        feature_names = [
            "total_requests",
            "unique_http_methods",
            "unique_endpoints",
            *[f"method_count_{method}" for method in self.methods],
        ]

        for profile in profiles:
            values = []

            for key in (
                "total_requests",
                "unique_http_methods",
                "unique_endpoints",
            ):
                value = profile.get(key, 0)

                if (
                    isinstance(value, bool)
                    or not isinstance(value, (int, float, np.number))
                    or not np.isfinite(value)
                    or value < 0
                ):
                    raise ValueError(
                        f"'{key}' must be a finite non-negative number"
                    )

                values.append(float(value))

            method_counts = profile.get("http_method_counts", {})
            if not isinstance(method_counts, dict):
                raise ValueError("'http_method_counts' must be a dictionary")

            normalized_counts = {}
            for method, count in method_counts.items():
                method_name = str(method).strip().upper()

                if (
                    isinstance(count, bool)
                    or not isinstance(count, (int, float, np.number))
                    or not np.isfinite(count)
                    or count < 0
                ):
                    raise ValueError(
                        "HTTP method counts must be finite non-negative numbers"
                    )

                normalized_counts[method_name] = float(count)

            # Methods not known during initialization are intentionally ignored.
            # Supply the same method vocabulary during training and inference.
            values.extend(
                normalized_counts.get(method, 0.0)
                for method in self.methods
            )
            rows.append(values)

        self.feature_names = feature_names
        return np.asarray(rows, dtype=np.float64)

    def fit(
        self,
        profiles: List[Dict[str, Any]],
    ) -> "BehaviorFeatureVectorizer":
        """Fit feature scaling using training profiles only."""
        matrix = self._build_matrix(profiles)
        self.scaler.fit(matrix)
        self.is_fitted = True
        return self

    def transform(
        self,
        profiles: List[Dict[str, Any]],
    ) -> np.ndarray:
        """Transform profiles using the fitted feature schema and scaler."""
        if not self.is_fitted:
            raise RuntimeError("Vectorizer must be fitted before transform")

        matrix = self._build_matrix(profiles)
        return self.scaler.transform(matrix)

    def fit_transform(
        self,
        profiles: List[Dict[str, Any]],
    ) -> np.ndarray:
        """Fit and transform training profiles."""
        self.fit(profiles)
        return self.transform(profiles)

    def get_feature_names(self) -> List[str]:
        """Return feature names in vector column order."""
        return list(self.feature_names)
