
from datetime import datetime, timezone

import pytest

from app.services.stacked_autoencoder_service import (
    DEFAULT_FEATURES,
    StackedAutoencoderDetector,
)


def make_baseline(count=30):
    """Create repeatable synthetic baseline traffic windows."""
    rows = []

    for i in range(count):
        rows.append(
            {
                "window_start": datetime.fromtimestamp(
                    1767225600 + i * 10,
                    tz=timezone.utc,
                ),
                "request_count": 20 + (i % 3),
                "unique_client_count": 3 + (i % 2),
                "http_2xx_count": 17 + (i % 3),
                "http_3xx_count": 1,
                "http_4xx_count": 1,
                "http_5xx_count": 1,
                "mean_response_time_ms": 100 + (i % 5) * 2,
                "max_response_time_ms": 150 + (i % 5) * 3,
            }
        )

    return rows


def test_detector_trains_on_baseline():
    detector = StackedAutoencoderDetector()
    detector.fit(make_baseline())

    assert detector.is_fitted is True
    assert detector.threshold is not None
    assert detector.threshold >= 0
    assert detector.feature_names == DEFAULT_FEATURES


def test_prediction_returns_expected_fields():
    detector = StackedAutoencoderDetector()
    baseline = make_baseline()
    detector.fit(baseline)

    results = detector.predict(baseline[:3])

    assert len(results) == 3

    for result in results:
        assert "reconstruction_error" in result
        assert "threshold" in result
        assert "is_anomaly" in result
        assert isinstance(result["is_anomaly"], bool)


def test_extreme_traffic_window_has_anomaly_score():
    detector = StackedAutoencoderDetector()
    detector.fit(make_baseline())

    unusual_window = {
        "request_count": 10000,
        "unique_client_count": 500,
        "http_2xx_count": 100,
        "http_3xx_count": 10,
        "http_4xx_count": 7000,
        "http_5xx_count": 2000,
        "mean_response_time_ms": 5000,
        "max_response_time_ms": 30000,
    }

    result = detector.predict([unusual_window])[0]

    assert result["reconstruction_error"] > 0
    assert result["is_anomaly"] is True


def test_predict_before_fit_raises_error():
    detector = StackedAutoencoderDetector()

    with pytest.raises(RuntimeError, match="fitted"):
        detector.predict(make_baseline(1))


def test_fit_rejects_too_few_windows():
    detector = StackedAutoencoderDetector()

    with pytest.raises(ValueError, match="At least 10"):
        detector.fit(make_baseline(9))


def test_fit_rejects_invalid_threshold():
    with pytest.raises(ValueError):
        StackedAutoencoderDetector(threshold_percentile=0)


def test_fit_rejects_invalid_feature_value():
    detector = StackedAutoencoderDetector()
    baseline = make_baseline()
    baseline[0]["request_count"] = float("nan")

    with pytest.raises(ValueError, match="finite numeric"):
        detector.fit(baseline)


def test_save_and_load_preserves_predictions(tmp_path):
    baseline = make_baseline()
    detector = StackedAutoencoderDetector()
    detector.fit(baseline)

    expected = detector.predict(baseline[:5])
    checkpoint = tmp_path / "sae_checkpoint.pt"

    detector.save(str(checkpoint))

    assert checkpoint.is_file()

    loaded = StackedAutoencoderDetector.load(str(checkpoint))
    actual = loaded.predict(baseline[:5])

    assert loaded.is_fitted is True
    assert loaded.feature_names == detector.feature_names
    assert loaded.threshold == detector.threshold
    assert [p["is_anomaly"] for p in actual] == [
        p["is_anomaly"] for p in expected
    ]

    for before, after in zip(expected, actual):
        assert after["reconstruction_error"] == pytest.approx(
            before["reconstruction_error"], abs=1e-6
        )


def test_save_rejects_unfitted_detector(tmp_path):
    detector = StackedAutoencoderDetector()

    with pytest.raises(RuntimeError, match="unfitted"):
        detector.save(str(tmp_path / "not_trained.pt"))


def test_load_rejects_missing_checkpoint(tmp_path):
    missing_path = tmp_path / "missing.pt"

    with pytest.raises(FileNotFoundError):
        StackedAutoencoderDetector.load(str(missing_path))
