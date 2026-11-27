"""WP14 reproducible evaluation checks.

The script is imported from the repository scripts directory so the same code
that operators run is what the tests exercise. No dataset or model artifact is
downloaded, trained or modified.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "evaluate_detection_metrics.py"


@pytest.fixture(scope="module")
def metrics_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("apisentry_evaluate_detection_metrics", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _balanced_rows() -> list[dict[str, str]]:
    rows = (
        [{"label": "malicious", "predicted": "malicious", "category": "credential_stuffing"}] * 3
        + [{"label": "malicious", "predicted": "benign"}]
        + [{"label": "benign", "predicted": "malicious"}]
        + [{"label": "benign", "predicted": "benign", "category": "normal"}] * 5
    )
    rows.extend(
        [
            {"label": "", "predicted": "malicious"},
            {"label": "benign", "predicted": None},
        ]
    )
    return rows


def test_labelled_metrics_are_computed_with_class_support(metrics_module: ModuleType) -> None:
    report = metrics_module.evaluate(
        _balanced_rows(),
        label_field="label",
        pred_field="predicted",
        positive_class="malicious",
        dataset_kind="labelled",
    )
    assert report["evaluation_type"] == "labelled predictive metrics"
    assert report["rows"] == 12
    assert report["valid_rows"] == 10
    assert report["skipped_invalid_rows"] == 2
    assert report["predictive_accuracy_supported"] is True
    binary = report["binary_metrics"]
    assert (binary["tp"], binary["fp"], binary["tn"], binary["fn"]) == (3, 1, 5, 1)
    assert binary["precision"] == 0.75
    assert binary["recall"] == 0.75
    assert binary["f1"] == 0.75
    assert binary["false_positive_rate"] == pytest.approx(0.166667)
    assert binary["false_negative_rate"] == 0.25
    assert binary["supported"] is True


def test_synthetic_agreement_never_emits_predictive_accuracy(metrics_module: ModuleType) -> None:
    report = metrics_module.evaluate(
        _balanced_rows(),
        label_field="label",
        pred_field="predicted",
        positive_class="malicious",
        dataset_kind="synthetic-rule-agreement",
    )
    assert report["evaluation_type"].startswith("synthetic-rule agreement")
    assert report["predictive_accuracy_supported"] is False
    assert "binary_metrics" not in report
    assert any("not accuracy" in note for note in report["notes"])


def test_unknown_or_single_class_data_is_not_reported_as_accuracy(metrics_module: ModuleType) -> None:
    unknown = metrics_module.evaluate(
        _balanced_rows(),
        label_field="label",
        pred_field="predicted",
        positive_class="malicious",
        dataset_kind="unknown",
    )
    assert "binary_metrics" not in unknown
    assert unknown["predictive_accuracy_supported"] is False

    single_class = metrics_module.evaluate(
        [{"label": "benign", "predicted": "benign"}, {"label": "benign", "predicted": "benign"}],
        label_field="label",
        pred_field="predicted",
        positive_class="malicious",
        dataset_kind="labelled",
    )
    assert single_class["binary_metrics"]["supported"] is False
    assert single_class["predictive_accuracy_supported"] is False


def test_cli_output_is_deterministic_and_reproducible(
    metrics_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    dataset = tmp_path / "predictions.jsonl"
    dataset.write_text(
        "\n".join(json.dumps(row) for row in _balanced_rows()) + "\n",
        encoding="utf-8",
    )
    output = tmp_path / "report.json"
    argv = [
        "evaluate_detection_metrics.py",
        "--input", str(dataset),
        "--dataset-kind", "labelled",
        "--label-field", "label",
        "--pred-field", "predicted",
        "--positive-class", "malicious",
        "--output", str(output),
    ]
    monkeypatch.setattr(sys, "argv", argv)
    assert metrics_module.main() == 0
    first = capsys.readouterr().out
    assert output.exists()

    monkeypatch.setattr(sys, "argv", argv)
    assert metrics_module.main() == 0
    second = capsys.readouterr().out
    assert first == second
    assert json.loads(output.read_text(encoding="utf-8")) == json.loads(first)
