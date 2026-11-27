"""Phase 3 hardening tests for the frozen HTTP payload classifier artifacts.

These tests only read the saved artifacts. They must never retrain or overwrite them.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path
from urllib.parse import quote

import pytest

from research.scripts.predict_http_payload import load_bundle, predict_payload, validate_payload

_ROOT = Path(__file__).resolve().parents[2]
_ARTIFACTS = _ROOT / "research" / "models" / "http_payload_classifier" / "v1"

# Hashes recorded at the start of Phase 3; any change means an artifact was overwritten.
_EXPECTED_HASHES = {
    "model.joblib": "5e2bd9e4c24cca91b4eb4ac8979100e04a8e45b71c719b1e4e26784dbcbbcdaa",
    "vectorizer.joblib": "b236fcf062d1a9363d750296fc5ff55e6a9f93b3993fdf0d0f7bb96c88d6884d",
    "scaler.joblib": "90b20ce5dfed6268055a8a88a81d853df00bf7d5fdcb4716dc3a87326a5a4678",
    "model_bundle.joblib": "2d694c932b9779d4971fa418aa35ecdf60cc266fe909b2ea40aa5392c5ae92dc",
    "metadata.json": "bc4843693a3222098f9dc69602a79256cb6f14fc5c673bcbc36104cd571a1aa0",
    "evaluation.json": "b2cdb7d8704c498594592e90204bdbc105ad4bb47c59078a9da1b00ec7276089",
}


@pytest.fixture(scope="module")
def bundle():
    if not _ARTIFACTS.is_dir():
        pytest.skip("research artifact directory not present")
    return load_bundle()


def test_fresh_process_loading_and_determinism():
    code = f"""
import sys
sys.path.insert(0, {str(_ROOT)!r})
from research.scripts.predict_http_payload import load_bundle, predict_payload
b = load_bundle()
r1 = predict_payload('admin', b)
r2 = predict_payload('admin', b)
assert r1 == r2
assert b['selected_model_name'] == 'tfidf_char_svm'
assert b['feature_mode'] == 'text'
print('FRESH_LOAD_OK')
print('DETERMINISTIC_OK')
"""
    result = subprocess.run(
        [sys.executable, "-B", "-c", code],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "FRESH_LOAD_OK" in result.stdout
    assert "DETERMINISTIC_OK" in result.stdout


def test_decision_scores_are_not_probabilities(bundle):
    result = predict_payload("1' OR '1'='1", bundle)
    assert result["score_type"] == "decision_score"
    assert isinstance(result["score"], float)
    assert "probability" not in result["interpretation"].lower()
    assert "positive favors anomalous" in result["interpretation"]


def test_robustness_variants_return_valid_predictions(bundle):
    variants = [
        "  admin  ",
        "\tadmin\n",
        "ADMIN",
        "1'  OR  '1'='1",
        "<SCRIPT>ALERT(1)</SCRIPT>",
        ";cat /etc/passwd",
        "..//..//etc//passwd",
        quote("1' OR '1'='1", safe=""),
        quote("<script>alert(1)</script>", safe=""),
        "a" * 28,
        "a" * 29,
        "a" * 1000,
    ]
    for value in variants:
        result = predict_payload(value, bundle)
        assert result["label"] in {"benign", "anomalous"}
        assert result["label_int"] in {0, 1}
        assert isinstance(result["score"], float)


def test_url_encoding_degrades_detection_documented(bundle):
    raw = predict_payload("1' OR '1'='1", bundle)
    encoded = predict_payload(quote("1' OR '1'='1", safe=""), bundle)
    assert raw["label"] == "anomalous"
    # Documents an observed Phase 3 weakness; this is not desired behaviour.
    assert encoded["label"] == "benign"
    assert encoded["score"] < raw["score"]


def test_phase3_invalid_inputs(bundle):
    for value in (None, "", "  ", "\t\n", 99, "x" * 10001):
        with pytest.raises(ValueError):
            validate_payload(value)
        with pytest.raises(ValueError):
            predict_payload(value, bundle)


def test_artifacts_unchanged_during_phase3():
    for name, expected in _EXPECTED_HASHES.items():
        actual = hashlib.sha256((_ARTIFACTS / name).read_bytes()).hexdigest()
        assert actual == expected, f"artifact changed during Phase 3: {name}"
