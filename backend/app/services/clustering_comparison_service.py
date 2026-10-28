
"""Compare K-Means distance and LOF for behavioral anomaly detection."""

from typing import Any, Dict, List

import numpy as np
from sklearn.cluster import KMeans
from sklearn.neighbors import LocalOutlierFactor


def compare_clustering_detectors(
    feature_vectors: np.ndarray,
    contamination: float = 0.1,
    random_state: int = 42,
) -> Dict[str, Any]:
    """Run K-Means distance scoring and LOF on the same feature matrix.

    Both methods return anomaly flags where True means an outlier.
    K-Means flags points with large distances to their assigned cluster
    centers. LOF uses its local-density outlier prediction.

    This is an unsupervised comparison, not an accuracy evaluation.
    """
    if not 0 < contamination < 0.5:
        raise ValueError("contamination must be greater than 0 and less than 0.5")

    matrix = np.asarray(feature_vectors, dtype=np.float64)

    if matrix.ndim != 2:
        raise ValueError("feature_vectors must be a 2D matrix")

    if matrix.shape[0] < 3:
        raise ValueError("At least 3 samples are required")

    if matrix.shape[1] < 1:
        raise ValueError("At least one feature is required")

    if not np.isfinite(matrix).all():
        raise ValueError("feature_vectors must contain only finite values")

    sample_count = matrix.shape[0]
    cluster_count = min(
        max(2, int(round(np.sqrt(sample_count / 2)))),
        sample_count - 1,
    )

    kmeans = KMeans(
        n_clusters=cluster_count,
        random_state=random_state,
        n_init=10,
    )
    cluster_labels = kmeans.fit_predict(matrix)
    distances = kmeans.transform(matrix)
    assigned_distances = distances[np.arange(sample_count), cluster_labels]

    kmeans_threshold = float(
        np.quantile(assigned_distances, 1.0 - contamination)
    )
    kmeans_flags = assigned_distances > kmeans_threshold

    lof_neighbors = min(20, sample_count - 1)
    lof = LocalOutlierFactor(
        n_neighbors=lof_neighbors,
        contamination=contamination,
    )
    lof_labels = lof.fit_predict(matrix)
    lof_scores = -lof.negative_outlier_factor_
    lof_flags = lof_labels == -1

    return {
        "sample_count": int(sample_count),
        "feature_count": int(matrix.shape[1]),
        "contamination": float(contamination),
        "kmeans": {
            "cluster_count": int(cluster_count),
            "threshold": kmeans_threshold,
            "anomaly_count": int(np.sum(kmeans_flags)),
            "anomaly_flags": kmeans_flags.tolist(),
            "anomaly_scores": assigned_distances.tolist(),
            "cluster_labels": cluster_labels.tolist(),
        },
        "lof": {
            "neighbors": int(lof_neighbors),
            "anomaly_count": int(np.sum(lof_flags)),
            "anomaly_flags": lof_flags.tolist(),
            "anomaly_scores": lof_scores.tolist(),
        },
    }
