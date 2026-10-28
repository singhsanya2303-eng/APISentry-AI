
"""Stacked Autoencoder service with model persistence."""

from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import torch
from torch import nn
from sklearn.preprocessing import StandardScaler


DEFAULT_FEATURES = [
    "request_count",
    "unique_client_count",
    "http_2xx_count",
    "http_3xx_count",
    "http_4xx_count",
    "http_5xx_count",
    "mean_response_time_ms",
    "max_response_time_ms",
]


class _Autoencoder(nn.Module):
    """Neural network used by the anomaly detector."""

    def __init__(self, input_dim: int, hidden_dims: List[int]) -> None:
        super().__init__()

        first_hidden, bottleneck, decoder_hidden = hidden_dims

        self.network = nn.Sequential(
            nn.Linear(input_dim, first_hidden),
            nn.ReLU(),
            nn.Linear(first_hidden, bottleneck),
            nn.ReLU(),
            nn.Linear(bottleneck, decoder_hidden),
            nn.ReLU(),
            nn.Linear(decoder_hidden, input_dim),
        )

    def forward(self, values: torch.Tensor) -> torch.Tensor:
        return self.network(values)


class StackedAutoencoderDetector:
    """Train, save, load and use an SAE traffic anomaly detector."""

    CHECKPOINT_VERSION = 1

    def __init__(
        self,
        hidden_dims: Optional[List[int]] = None,
        threshold_percentile: float = 95.0,
        random_state: int = 42,
    ) -> None:
        if not 0 < threshold_percentile <= 100:
            raise ValueError("threshold_percentile must be in (0, 100]")

        self.hidden_dims = list(hidden_dims or [6, 3, 6])

        if (
            len(self.hidden_dims) != 3
            or any(
                not isinstance(size, int)
                or isinstance(size, bool)
                or size <= 0
                for size in self.hidden_dims
            )
        ):
            raise ValueError("hidden_dims must contain three positive integers")

        self.threshold_percentile = float(threshold_percentile)
        self.random_state = int(random_state)
        self.scaler = StandardScaler()
        self.model: Optional[_Autoencoder] = None
        self.threshold: Optional[float] = None
        self.feature_names: List[str] = []
        self.is_fitted = False

    @staticmethod
    def _validate_matrix(
        rows: List[Dict[str, Any]],
        feature_names: List[str],
    ) -> np.ndarray:
        if not rows:
            raise ValueError("At least one traffic window is required")

        matrix = []

        for row in rows:
            values = []

            for name in feature_names:
                value = row.get(name, 0.0)

                if (
                    isinstance(value, bool)
                    or not isinstance(value, (int, float, np.number))
                    or not np.isfinite(value)
                ):
                    raise ValueError(
                        f"Feature '{name}' must be a finite numeric value"
                    )

                values.append(float(value))

            matrix.append(values)

        return np.asarray(matrix, dtype=np.float64)

    def fit(
        self,
        baseline_windows: List[Dict[str, Any]],
        feature_names: Optional[List[str]] = None,
    ) -> "StackedAutoencoderDetector":
        """Train on windows expected to represent normal traffic."""
        names = list(feature_names or DEFAULT_FEATURES)

        if not names or len(set(names)) != len(names):
            raise ValueError("feature_names must be non-empty and unique")

        matrix = self._validate_matrix(baseline_windows, names)

        if len(matrix) < 10:
            raise ValueError(
                "At least 10 baseline windows are required for training"
            )

        self.feature_names = names
        scaled = self.scaler.fit_transform(matrix)

        torch.manual_seed(self.random_state)
        torch.use_deterministic_algorithms(True, warn_only=True)

        self.model = _Autoencoder(len(names), self.hidden_dims)
        optimizer = torch.optim.Adam(self.model.parameters(), lr=0.01)
        loss_function = nn.MSELoss()
        training_data = torch.tensor(scaled, dtype=torch.float32)

        self.model.train()

        for _ in range(200):
            optimizer.zero_grad()
            reconstructed = self.model(training_data)
            loss = loss_function(reconstructed, training_data)
            loss.backward()
            optimizer.step()

        self.model.eval()

        with torch.no_grad():
            reconstructed = self.model(training_data).cpu().numpy()

        errors = np.mean((scaled - reconstructed) ** 2, axis=1)

        self.threshold = float(
            np.percentile(errors, self.threshold_percentile)
        )
        self.is_fitted = True

        return self

    def predict(
        self,
        windows: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Return reconstruction errors and anomaly flags."""
        if not self.is_fitted or self.model is None or self.threshold is None:
            raise RuntimeError("Detector must be fitted before prediction")

        matrix = self._validate_matrix(windows, self.feature_names)
        scaled = self.scaler.transform(matrix)

        self.model.eval()

        with torch.no_grad():
            reconstructed = self.model(
                torch.tensor(scaled, dtype=torch.float32)
            ).cpu().numpy()

        errors = np.mean((scaled - reconstructed) ** 2, axis=1)

        return [
            {
                "window_start": window.get("window_start"),
                "reconstruction_error": float(error),
                "threshold": self.threshold,
                "is_anomaly": bool(error > self.threshold),
            }
            for window, error in zip(windows, errors)
        ]

    def save(self, file_path: str) -> None:
        """Save model weights, scaler state and threshold to a checkpoint."""
        if not self.is_fitted or self.model is None or self.threshold is None:
            raise RuntimeError("Cannot save an unfitted detector")

        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        checkpoint = {
            "version": self.CHECKPOINT_VERSION,
            "hidden_dims": self.hidden_dims,
            "threshold_percentile": self.threshold_percentile,
            "random_state": self.random_state,
            "threshold": self.threshold,
            "feature_names": self.feature_names,
            "model_state_dict": self.model.state_dict(),
            "scaler_mean": torch.tensor(
                self.scaler.mean_.tolist(), dtype=torch.float64
            ),
            "scaler_scale": torch.tensor(
                self.scaler.scale_.tolist(), dtype=torch.float64
            ),
            "scaler_var": torch.tensor(
                self.scaler.var_.tolist(), dtype=torch.float64
            ),
            "scaler_n_samples_seen": torch.tensor(
                np.asarray(self.scaler.n_samples_seen_).tolist(),
                dtype=torch.int64,
            ),
        }

        torch.save(checkpoint, path)

    @classmethod
    def load(cls, file_path: str) -> "StackedAutoencoderDetector":
        """Load a checkpoint without retraining the model."""
        path = Path(file_path)

        if not path.is_file():
            raise FileNotFoundError(f"Checkpoint not found: {path}")

        checkpoint = torch.load(
            path,
            map_location="cpu",
            weights_only=True,
        )

        if checkpoint.get("version") != cls.CHECKPOINT_VERSION:
            raise ValueError("Unsupported or invalid checkpoint version")

        detector = cls(
            hidden_dims=checkpoint["hidden_dims"],
            threshold_percentile=checkpoint["threshold_percentile"],
            random_state=checkpoint["random_state"],
        )

        detector.feature_names = list(checkpoint["feature_names"])
        detector.model = _Autoencoder(
            len(detector.feature_names),
            detector.hidden_dims,
        )
        detector.model.load_state_dict(checkpoint["model_state_dict"])
        detector.model.eval()

        detector.scaler = StandardScaler()
        detector.scaler.mean_ = checkpoint["scaler_mean"].cpu().numpy()
        detector.scaler.scale_ = checkpoint["scaler_scale"].cpu().numpy()
        detector.scaler.var_ = checkpoint["scaler_var"].cpu().numpy()
        detector.scaler.n_features_in_ = len(detector.feature_names)
        detector.scaler.n_samples_seen_ = (
            checkpoint["scaler_n_samples_seen"].cpu().numpy()
        )

        if detector.scaler.n_samples_seen_.ndim == 0:
            detector.scaler.n_samples_seen_ = int(
                detector.scaler.n_samples_seen_.item()
            )

        threshold = checkpoint["threshold"]

        if not isinstance(threshold, (int, float)) or not np.isfinite(threshold):
            raise ValueError("Invalid checkpoint threshold")

        detector.threshold = float(threshold)
        detector.is_fitted = True

        return detector
