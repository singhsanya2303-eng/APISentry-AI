
"""Integrate 10-second traffic aggregation with SAE anomaly detection.

Train the detector on baseline traffic windows and score separate target
traffic windows. Existing behavior-risk scoring remains unchanged.
"""

import logging
from typing import Any, Dict, List

from app.services.traffic_aggregation_service import aggregate_traffic_logs
from app.services.stacked_autoencoder_service import (
    StackedAutoencoderDetector,
)

logger = logging.getLogger("apisentry.analysis.traffic_trends")


def analyze_traffic_trends(
    baseline_logs: List[Any],
    target_logs: List[Any],
    threshold_percentile: float = 95.0,
) -> Dict[str, Any]:
    """Train on baseline traffic and detect anomalies in target traffic.

    Args:
        baseline_logs: Historical logs expected to represent normal traffic.
        target_logs: Separate logs to evaluate for anomalies.
        threshold_percentile: Percentile of baseline reconstruction errors
            used to establish the anomaly threshold.

    Returns:
        A dictionary containing aggregation counts, the learned threshold,
        and anomaly predictions for each target window.

    Raises:
        ValueError: If insufficient baseline windows are available or
            input parameters are invalid.
    """
    if not baseline_logs:
        raise ValueError("baseline_logs must not be empty")

    if not target_logs:
        return {
            "baseline_window_count": 0,
            "target_window_count": 0,
            "anomaly_count": 0,
            "threshold": None,
            "predictions": [],
            "summary": "No target traffic logs provided.",
        }

    baseline_windows = aggregate_traffic_logs(baseline_logs)
    target_windows = aggregate_traffic_logs(target_logs)

    if len(baseline_windows) < 10:
        raise ValueError(
            "At least 10 baseline windows are required; "
            f"received {len(baseline_windows)}. "
            "Collect more baseline traffic before training."
        )

    if not target_windows:
        return {
            "baseline_window_count": len(baseline_windows),
            "target_window_count": 0,
            "anomaly_count": 0,
            "threshold": None,
            "predictions": [],
            "summary": "No valid target traffic windows were found.",
        }

    detector = StackedAutoencoderDetector(
        threshold_percentile=threshold_percentile
    )
    detector.fit(baseline_windows)

    predictions = detector.predict(target_windows)
    anomaly_count = sum(
        1 for prediction in predictions if prediction["is_anomaly"]
    )

    logger.info(
        "Traffic trend analysis completed: baseline_windows=%d, "
        "target_windows=%d, anomalies=%d",
        len(baseline_windows),
        len(target_windows),
        anomaly_count,
    )

    return {
        "baseline_window_count": len(baseline_windows),
        "target_window_count": len(target_windows),
        "anomaly_count": anomaly_count,
        "threshold": detector.threshold,
        "predictions": predictions,
        "summary": (
            f"Analyzed {len(target_windows)} target traffic window(s); "
            f"{anomaly_count} flagged as anomalous."
        ),
    }
