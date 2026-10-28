
import numpy as np
import pytest

from app.services.stacked_autoencoder_service import (
    StackedAutoencoderDetector,
)


def make_window(index, *, unusual=False):
    """Create synthetic traffic for reliability testing."""
    if unusual:
        return {
            "window_start": f"target-{index}",
            "request_count": 100,
            "unique_client_count": 50,
            "http_2xx_count": 10,
            "http_3xx_count": 0,
            "http_4xx_count": 10,
            "http_5xx_count": 80,
            "mean_response_time_ms": 5000.0,
            "max_response_time_ms": 10000.0,
        }

    return {
        "window_start": f"baseline-{index}",
        "request_count": 10,
        "unique_client_count": 2,
        "http_2xx_count": 9,
        "http_3xx_count": 1,
        "http_4xx_count": 0,
        "http_5xx_count": 0,
        "mean_response_time_ms": 100.0,
        "max_response_time_ms": 150.0,
    }


def test_detector_reports_reconstruction_errors():
    baseline = [make_window(i) for i in range(30)]
    targets = [
        make_window(1),
        make_window(2, unusual=True),
    ]

    detector = StackedAutoencoderDetector(
        threshold_percentile=95.0,
        random_state=42,
    )
    detector.fit(baseline)
    predictions = detector.predict(targets)

    assert len(predictions) == 2
    assert all(
        np.isfinite(p["reconstruction_error"])
        and p["reconstruction_error"] >= 0
        for p in predictions
    )
    assert all(
        p["threshold"] == detector.threshold
        for p in predictions
    )

    assert predictions[0]["is_anomaly"] is False
    assert predictions[1]["is_anomaly"] is True


def test_saved_and_loaded_detector_preserves_predictions(tmp_path):
    baseline = [make_window(i) for i in range(30)]
    targets = [
        make_window(100),
        make_window(101, unusual=True),
    ]

    detector = StackedAutoencoderDetector(
        threshold_percentile=95.0,
        random_state=42,
    )
    detector.fit(baseline)

    original_predictions = detector.predict(targets)

    checkpoint = tmp_path / "sae_checkpoint.pt"
    detector.save(str(checkpoint))

    assert checkpoint.exists()

    loaded_detector = StackedAutoencoderDetector.load(
        str(checkpoint)
    )
    loaded_predictions = loaded_detector.predict(targets)

    assert loaded_detector.is_fitted is True
    assert loaded_detector.threshold == detector.threshold
    assert len(loaded_predictions) == len(original_predictions)

    for original, loaded in zip(
        original_predictions, loaded_predictions
    ):
        assert loaded["reconstruction_error"] == pytest.approx(
            original["reconstruction_error"],
            rel=1e-5,
            abs=1e-7,
        )
        assert loaded["is_anomaly"] == original["is_anomaly"]

def test_detector_handles_variable_normal_traffic():
    """Check predictions on normal traffic with modest variation."""
    baseline = []

    for i in range(40):
        window = make_window(i)

        # Introduce small, realistic variation in normal traffic.
        window["request_count"] = 10 + (i % 4)
        window["unique_client_count"] = 2 + (i % 2)
        window["http_2xx_count"] = window["request_count"] - 1
        window["http_3xx_count"] = 1
        window["mean_response_time_ms"] = 95.0 + (i % 6) * 5
        window["max_response_time_ms"] = (
            window["mean_response_time_ms"] + 30.0
        )

        baseline.append(window)

    detector = StackedAutoencoderDetector(
        threshold_percentile=95.0,
        random_state=42,
    )
    detector.fit(baseline)

    predictions = detector.predict(baseline)

    assert len(predictions) == len(baseline)
    assert all(
        np.isfinite(p["reconstruction_error"])
        for p in predictions
    )
    assert all(
        p["threshold"] == detector.threshold
        for p in predictions
    )

    anomaly_count = sum(
        p["is_anomaly"] for p in predictions
    )
    print(f"Variable-normal windows flagged: {anomaly_count}/40")

    # At least one window must be classified as normal.
    assert anomaly_count < len(predictions)
