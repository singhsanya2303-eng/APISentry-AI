
"""Train a DEMO token-usage classifier on synthetic data.

Important: Synthetic data is for integration testing only.
It does not establish real-world security detection accuracy.
"""

from pathlib import Path

import numpy as np

from app.services.token_usage_classifier_service import (
    TokenUsageRandomForestClassifier,
)

RANDOM_STATE = 42
SAMPLES_PER_CLASS = 300

FEATURE_NAMES = [
    "requests_per_minute",
    "unique_ips",
    "failed_requests_ratio",
    "token_reuse_count",
    "geo_distance_km",
]

LABELS = [
    "Normal",
    "Token Hijacking",
    "Abnormal Token Usage",
]


def generate_demo_data():
    rng = np.random.default_rng(RANDOM_STATE)

    # Synthetic normal traffic
    normal = np.column_stack([
        rng.uniform(1, 30, SAMPLES_PER_CLASS),
        rng.integers(1, 3, SAMPLES_PER_CLASS),
        rng.uniform(0, 0.08, SAMPLES_PER_CLASS),
        rng.integers(0, 4, SAMPLES_PER_CLASS),
        rng.uniform(0, 50, SAMPLES_PER_CLASS),
    ])

    # Synthetic token-hijacking-like patterns
    hijacking = np.column_stack([
        rng.uniform(10, 100, SAMPLES_PER_CLASS),
        rng.integers(2, 12, SAMPLES_PER_CLASS),
        rng.uniform(0, 0.35, SAMPLES_PER_CLASS),
        rng.integers(5, 40, SAMPLES_PER_CLASS),
        rng.uniform(300, 5000, SAMPLES_PER_CLASS),
    ])

    # Synthetic abnormal usage patterns
    abnormal = np.column_stack([
        rng.uniform(60, 250, SAMPLES_PER_CLASS),
        rng.integers(1, 5, SAMPLES_PER_CLASS),
        rng.uniform(0.15, 1.0, SAMPLES_PER_CLASS),
        rng.integers(10, 100, SAMPLES_PER_CLASS),
        rng.uniform(0, 500, SAMPLES_PER_CLASS),
    ])

    features = np.vstack([normal, hijacking, abnormal])
    labels = (
        ["Normal"] * SAMPLES_PER_CLASS
        + ["Token Hijacking"] * SAMPLES_PER_CLASS
        + ["Abnormal Token Usage"] * SAMPLES_PER_CLASS
    )

    # Shuffle features and labels together
    order = rng.permutation(len(labels))
    return features[order], [labels[i] for i in order]


def main():
    features, labels = generate_demo_data()

    classifier = TokenUsageRandomForestClassifier(
        n_estimators=200,
        random_state=RANDOM_STATE,
    )

    classifier.fit(
        feature_vectors=features,
        labels=labels,
        feature_names=FEATURE_NAMES,
    )

    output_path = (
        Path(__file__).resolve().parent
        / "models"
        / "token_usage_classifier.joblib"
    )

    classifier.save(str(output_path))

    print("Demo token classifier trained successfully.")
    print(f"Training samples: {len(labels)}")
    print(f"Feature names: {FEATURE_NAMES}")
    print(f"Classes: {LABELS}")
    print(f"Saved model: {output_path}")


if __name__ == "__main__":
    main()
