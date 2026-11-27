
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from app.services.traffic_trend_analysis_service import (
    analyze_traffic_trends,
)


def make_logs(count, start_time, unusual=False):
    """Create synthetic logs in separate 10-second windows."""
    logs = []

    for i in range(count):
        timestamp = start_time + timedelta(seconds=10 * i)

        if unusual:
            request_count = 1000
            status_code = 500
            response_time = 5000.0
        else:
            request_count = 1
            status_code = 200
            response_time = 100.0

        for _ in range(request_count):
            logs.append(
                SimpleNamespace(
                    timestamp=timestamp,
                    request_id=f"req-{i}-{_}",
                    status_code=status_code,
                    response_time_ms=response_time,
                    client_ip="192.0.2.10",
                    method="GET",
                )
            )

    return logs


def test_trend_analysis_trains_and_returns_predictions():
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    baseline = make_logs(12, start)
    target = make_logs(2, start + timedelta(hours=1))

    result = analyze_traffic_trends(baseline, target)

    assert result["baseline_window_count"] == 12
    assert result["target_window_count"] == 2
    assert len(result["predictions"]) == 2
    assert result["threshold"] is not None
    assert result["anomaly_count"] >= 0
    assert result["anomaly_count"] <= 2

    for prediction in result["predictions"]:
        assert "reconstruction_error" in prediction
        assert "threshold" in prediction
        assert isinstance(prediction["is_anomaly"], bool)


def test_trend_analysis_rejects_insufficient_baseline():
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    baseline = make_logs(9, start)
    target = make_logs(1, start + timedelta(hours=1))

    with pytest.raises(ValueError, match="At least 10 baseline windows"):
        analyze_traffic_trends(baseline, target)


def test_trend_analysis_handles_empty_target():
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    baseline = make_logs(12, start)

    result = analyze_traffic_trends(baseline, [])

    assert result["target_window_count"] == 0
    assert result["anomaly_count"] == 0
    assert result["predictions"] == []
    assert result["threshold"] is None


def test_trend_analysis_rejects_empty_baseline():
    target = make_logs(
        1,
        datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    with pytest.raises(ValueError, match="baseline_logs must not be empty"):
        analyze_traffic_trends([], target)


def test_app_import_succeeds_without_torch(tmp_path):
    """Torch must not be imported during app startup; SAE loads on demand."""
    backend_dir = Path(__file__).resolve().parents[1]
    env = dict(os.environ)
    env["PYTHONPATH"] = str(backend_dir)
    script = """
import sys
class BlockTorch:
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "torch" or fullname.startswith("torch."):
            raise ImportError("torch blocked for test")
sys.meta_path.insert(0, BlockTorch())
import app.main
assert "torch" not in sys.modules
assert "app.services.stacked_autoencoder_service" not in sys.modules
assert any(
    "traffic-trends/analyze" in path
    for path in app.main.app.openapi()["paths"]
)
print("APP_IMPORT_OK")
"""

    completed = subprocess.run(
        [sys.executable, "-B", "-c", script],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert "APP_IMPORT_OK" in completed.stdout
