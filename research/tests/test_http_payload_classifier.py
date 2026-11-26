"""Focused tests for the research-only HTTP payload classifier artifacts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import joblib
import numpy as np
import pytest

from research.scripts.predict_http_payload import (
    ARTIFACT_DIR,
    EXAMPLES_NAME,
    FORMAT_VERSION,
    LABELS,
    MAX_PAYLOAD_CHARS,
    load_bundle,
    main,
    predict_payload,
    transform_payloads,
    validate_payload,
)

_ROOT = Path(__file__).resolve().parents[2]
_ZIP = _ROOT / "research" / "datasets" / "raw" / "HttpParamsDataset-master.zip"


@pytest.fixture(scope="module")
def bundle():
    if not ARTIFACT_DIR.is_dir():
        pytest.skip("research artifact directory not present")
    return load_bundle()


def test_artifact_loading(bundle):
    assert isinstance(bundle, dict)
    assert bundle["format_version"] == FORMAT_VERSION
    assert bundle["selected_model_name"]
    assert bundle["feature_mode"] in {"length_raw", "length_scaled", "text", "text_length"}
    for name in ("model.joblib", "vectorizer.joblib", "scaler.joblib"):
        assert (ARTIFACT_DIR / name).is_file()
    assert joblib.load(ARTIFACT_DIR / "model.joblib") is not None


def test_preprocessing_consistency(bundle):
    payloads = ["admin", "id=1 or 1=1"]
    first = transform_payloads(payloads, bundle)
    second = transform_payloads(payloads, bundle)
    assert first.shape[0] == len(payloads)
    assert np.allclose(first.toarray(), second.toarray())
    if bundle["feature_mode"] == "text":
        assert first.shape[1] == len(bundle["vectorizer"].vocabulary_)
        direct = bundle["vectorizer"].transform(payloads)
        assert np.allclose(first.toarray(), direct.toarray())
    else:
        expected = len(bundle["vectorizer"].vocabulary_) + 1
        assert first.shape[1] in (1, expected)


def test_valid_binary_predictions(bundle):
    examples_path = ARTIFACT_DIR / EXAMPLES_NAME
    examples = json.loads(examples_path.read_text(encoding="utf-8"))
    assert len(examples) >= 4
    for example in examples:
        result = predict_payload(example["payload"], bundle)
        assert result["label"] in set(LABELS.values())
        assert result["label_int"] in (0, 1)
        assert result["score_type"] in {"probability", "decision_score", "none"}
        assert "Advisory research output only" in result["interpretation"]
        assert result["payload_length"] == len(example["payload"])


def test_invalid_and_empty_inputs(bundle):
    for value in (None, "", "   ", "\t\n", 123, "x" * (MAX_PAYLOAD_CHARS + 1)):
        with pytest.raises(ValueError):
            validate_payload(value)
        with pytest.raises(ValueError):
            predict_payload(value, bundle)
    assert main([""]) == 2


def test_deterministic_predictions(bundle):
    payload = "1' or '1'='1"
    first = predict_payload(payload, bundle)
    second = predict_payload(payload, bundle)
    assert first == second
    batch = transform_payloads([payload, "ordinary-value"], bundle).toarray()
    single = transform_payloads([payload], bundle).toarray()
    assert np.allclose(batch[0], single[0])


def test_model_metadata_compatibility(bundle):
    metadata = json.loads((ARTIFACT_DIR / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["format_version"] == bundle["format_version"] == FORMAT_VERSION
    assert metadata["selected_model_name"] == bundle["selected_model_name"]
    assert metadata["feature_mode"] == bundle["feature_mode"]
    assert bundle["labels"] == LABELS
    assert metadata["labels"] == {str(key): value for key, value in LABELS.items()}
    assert metadata["seed"] == bundle["seed"] == 42
    with _ZIP.open("rb") as handle:
        assert metadata["dataset_sha256"] == hashlib.sha256(handle.read()).hexdigest()
    assert metadata["research_only"] is True
