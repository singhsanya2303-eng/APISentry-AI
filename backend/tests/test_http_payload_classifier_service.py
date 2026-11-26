"""Focused unit tests for the isolated HTTP payload classifier service.

These tests only read the frozen research artifact. They never retrain,
overwrite, or otherwise modify it, and they use installed dependencies only.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import joblib
import numpy as np
import pytest
from pydantic import ValidationError

from app.schemas.http_payload_classifier import (
    HttpPayloadClassifierRequest,
    HttpPayloadClassifierResult,
)
from app.services import http_payload_classifier_service as service
from classifier_artifact_policy import CLASSIFIER_ARTIFACT_SKIP_REASON

_ROOT = Path(__file__).resolve().parents[2]
_ARTIFACT = (
    _ROOT / "research" / "models" / "http_payload_classifier" / "v1" / "model_bundle.joblib"
)

# These tests exercise the supported artifact-backed behaviour. The
# missing-artifact contract is covered independently by
# test_task11_classifier_artifact_regression.py, which never assumes the
# excluded research artifact is present in a contribution.
pytestmark = pytest.mark.skipif(
    not _ARTIFACT.is_file(),
    reason=CLASSIFIER_ARTIFACT_SKIP_REASON,
)

_FORBIDDEN_FIELDS = {
    "confidence",
    "probability",
    "risk_score",
    "bot_risk_score",
    "severity",
}
_SECRET = "api_key=SUPER_SECRET_VALUE_12345"


@pytest.fixture(autouse=True)
def _isolated_model_cache():
    """Prevent cached artifact state (or test hooks) leaking between tests."""
    service._reset_cache()
    yield
    service._reset_cache()


@pytest.fixture(scope="module")
def reference_bundle():
    """Independently loaded artifact used as the research-semantics oracle."""
    if not _ARTIFACT.is_file():
        pytest.skip("frozen model bundle is not present")
    return joblib.load(_ARTIFACT)


def _expected_score(payload: str, bundle) -> float:
    features = bundle["vectorizer"].transform([payload])
    return float(bundle["model"].decision_function(features).ravel()[0])


# ---------------------------------------------------------------------------
# Model loading and caching
# ---------------------------------------------------------------------------


def test_model_loads_lazily_from_verified_artifact(reference_bundle):
    assert service._cached_bundle is None

    response = service.predict_payloads(["admin"])

    assert service._cached_bundle is not None
    assert response.model_name == "tfidf_char_svm"
    assert response.feature_mode == "text"
    assert response.artifact_sha256 == service.ARTIFACT_SHA256
    assert response.advisory_only is True
    assert len(response.results) == 1


def test_bundle_is_cached_after_first_load(monkeypatch):
    service.predict_payloads(["admin"])

    def _must_not_reload():
        pytest.fail("verified bundle was reloaded instead of using the cache")

    monkeypatch.setattr(service, "_load_bundle_verified", _must_not_reload)
    second = service.predict_payloads(["falset"])
    assert len(second.results) == 1


def test_thread_safe_caching_loads_only_once(monkeypatch):
    call_count = []
    count_lock = threading.Lock()
    marker = {"marker": object()}
    start = threading.Event()

    def _slow_load():
        with count_lock:
            call_count.append(1)
        time.sleep(0.01)
        return marker

    monkeypatch.setattr(service, "_load_bundle_verified", _slow_load)

    results = []
    errors = []
    threads = []

    def _worker():
        start.wait(timeout=10)
        try:
            results.append(service._get_cached_bundle())
        except BaseException as exc:  # pragma: no cover - failure reporting only
            errors.append(exc)

    for _ in range(8):
        thread = threading.Thread(target=_worker)
        thread.start()
        threads.append(thread)
    start.set()
    for thread in threads:
        thread.join(timeout=10)

    assert not errors
    assert len(call_count) == 1
    assert len(results) == 8
    assert all(result is marker for result in results)


# ---------------------------------------------------------------------------
# SHA-256 validation and safe artifact failures
# ---------------------------------------------------------------------------


def test_sha256_mismatch_is_rejected_before_loading(monkeypatch, tmp_path, reference_bundle):
    tampered = _ARTIFACT.read_bytes() + b"\n# tampered"
    (tmp_path / service._ARTIFACT_FILENAME).write_bytes(tampered)
    monkeypatch.setattr(service, "_ARTIFACT_DIR", tmp_path)

    def _must_not_load(*args, **kwargs):
        pytest.fail("unverified bytes were passed to joblib.load")

    monkeypatch.setattr(service.joblib, "load", _must_not_load)

    with pytest.raises(service.HttpPayloadClassifierUnavailableError) as exc_info:
        service.predict_payloads(["admin"])

    assert str(exc_info.value) == "Payload classifier model is not available."
    assert str(tmp_path) not in str(exc_info.value)


def test_missing_artifact_is_reported_safely(monkeypatch, tmp_path):
    monkeypatch.setattr(service, "_ARTIFACT_DIR", tmp_path / "does-not-exist")

    with pytest.raises(service.HttpPayloadClassifierUnavailableError) as exc_info:
        service.predict_payloads(["admin"])

    assert str(exc_info.value) == "Payload classifier model is not available."
    assert "does-not-exist" not in str(exc_info.value)


def test_corrupt_artifact_is_reported_safely(monkeypatch, tmp_path):
    garbage = b"this is not a joblib bundle"
    (tmp_path / service._ARTIFACT_FILENAME).write_bytes(garbage)
    monkeypatch.setattr(service, "_ARTIFACT_DIR", tmp_path)
    monkeypatch.setattr(service, "ARTIFACT_SHA256", hashlib.sha256(garbage).hexdigest())

    with pytest.raises(service.HttpPayloadClassifierUnavailableError) as exc_info:
        service.predict_payloads(["admin"])

    assert str(exc_info.value) == "Payload classifier model is not available."


# ---------------------------------------------------------------------------
# Single and batch prediction semantics
# ---------------------------------------------------------------------------


def test_single_prediction_returns_one_result(reference_bundle):
    payload = "1' OR '1'='1"
    response = service.predict_payloads([payload])

    assert len(response.results) == 1
    result = response.results[0]
    assert result.index == 0
    assert result.payload_length == len(payload)
    assert result.decision_score == pytest.approx(_expected_score(payload, reference_bundle))


def test_batch_results_are_independent_of_siblings(reference_bundle):
    payloads = ["admin", "falset", "union select password", "1' OR '1'='1"]

    batch = service.predict_payloads(payloads)

    assert [result.index for result in batch.results] == list(range(len(payloads)))
    for index, payload in enumerate(payloads):
        single = service.predict_payloads([payload]).results[0]
        # Position in the batch is the only expected difference between a
        # standalone prediction and the same value inside a batch.
        batch_fields = batch.results[index].model_dump(exclude={"index"})
        single_fields = single.model_dump(exclude={"index"})
        assert batch_fields == single_fields
        assert batch.results[index].decision_score == pytest.approx(
            _expected_score(payload, reference_bundle)
        )


def test_batch_size_boundaries_are_supported(reference_bundle):
    for count in (1, service.MAX_BATCH_SIZE):
        payloads = ["admin"] * count
        response = service.predict_payloads(payloads)
        assert len(response.results) == count


def test_decision_score_is_uncalibrated_margin_not_probability(
    reference_bundle,
):
    payload = "1' OR '1'='1"
    result = service.predict_payloads([payload]).results[0]
    expected_score = _expected_score(payload, reference_bundle)

    assert result.score_type == "decision_score"
    assert isinstance(result.decision_score, float)
    assert result.decision_score == pytest.approx(expected_score)
    assert result.decision_threshold == 0.0
    assert result.label_int == int(expected_score >= 0.0)
    assert result.label == ("anomalous" if expected_score >= 0.0 else "benign")

    assert _FORBIDDEN_FIELDS.isdisjoint(result.model_dump())
    assert _FORBIDDEN_FIELDS.isdisjoint(service.predict_payloads([payload]).model_dump())


def test_low_margin_flag_matches_abs_score_threshold(reference_bundle):
    low = service.predict_payloads(["falset"]).results[0]
    high = service.predict_payloads(["1' OR '1'='1"]).results[0]

    assert abs(low.decision_score) < 1.0
    assert low.low_margin is True
    assert low.label == "anomalous"  # the flag never changes the label

    assert abs(high.decision_score) >= 1.0
    assert high.low_margin is False

    mixed = service.predict_payloads(["falset", "admin", "union select password"])
    for result in mixed.results:
        assert result.low_margin is (abs(result.decision_score) < 1.0)
        expected_score = _expected_score(
            ["falset", "admin", "union select password"][result.index], reference_bundle
        )
        assert result.decision_score == pytest.approx(expected_score)


# ---------------------------------------------------------------------------
# Validation: whole batch rejected before prediction
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("invalid", [None, 123, b"abc", "", "   ", "\t\n", "x" * 10001])
def test_invalid_payload_values_raise_safe_value_error(invalid):
    with pytest.raises(service.HttpPayloadClassifierInputError) as exc_info:
        service.predict_payloads([invalid])

    message = str(exc_info.value)
    if isinstance(invalid, str) and invalid:
        assert invalid not in message


def test_invalid_batch_shapes_and_totals_raise_value_error():
    with pytest.raises(service.HttpPayloadClassifierInputError):
        service.predict_payloads("admin")
    with pytest.raises(ValueError):
        service.predict_payloads([])
    with pytest.raises(ValueError):
        service.predict_payloads(["a"] * (service.MAX_BATCH_SIZE + 1))
    with pytest.raises(ValueError):
        service.predict_payloads(["x" * service.MAX_PAYLOAD_CHARS] * 11)
    with pytest.raises(ValueError):
        service.predict_payloads(["admin"], include_payload_echo=1)


def test_whole_batch_is_rejected_before_any_prediction(monkeypatch):
    def _must_not_predict():
        pytest.fail("model was used despite an invalid batch item")

    monkeypatch.setattr(service, "_get_cached_bundle", _must_not_predict)

    with pytest.raises(service.HttpPayloadClassifierInputError):
        service.predict_payloads(["admin", "valid", 123])


# ---------------------------------------------------------------------------
# Privacy: no echo or logging by default
# ---------------------------------------------------------------------------


def test_no_raw_payload_echo_or_logging_by_default(caplog):
    with caplog.at_level(logging.DEBUG):
        response = service.predict_payloads([_SECRET])

    assert all(result.payload_echo is None for result in response.results)
    assert _SECRET not in response.model_dump_json()
    assert _SECRET not in caplog.text

    opted_in = service.predict_payloads([_SECRET], include_payload_echo=True)
    assert opted_in.results[0].payload_echo == _SECRET


# ---------------------------------------------------------------------------
# Safe model failures
# ---------------------------------------------------------------------------


def test_loading_failure_is_wrapped_without_leaking_details(monkeypatch):
    def _broken_loader():
        raise RuntimeError(f"C:\\internal\\path\\model.joblib payload={_SECRET}")

    monkeypatch.setattr(service, "_load_bundle_verified", _broken_loader)

    with pytest.raises(service.HttpPayloadClassifierUnavailableError) as exc_info:
        service.predict_payloads([_SECRET])

    message = str(exc_info.value)
    assert message == "Payload classifier model is not available."
    assert "internal" not in message
    assert _SECRET not in message


def test_prediction_failure_is_wrapped_without_leaking_details(monkeypatch):
    class _FailingModel:
        def decision_function(self, features):
            raise RuntimeError(f"C:\\internal\\path failed for {_SECRET}")

    fake_bundle = {
        "vectorizer": SimpleNamespace(transform=lambda values: values),
        "model": _FailingModel(),
    }
    monkeypatch.setattr(service, "_get_cached_bundle", lambda: fake_bundle)

    with pytest.raises(service.HttpPayloadClassifierUnavailableError) as exc_info:
        service.predict_payloads([_SECRET])

    assert str(exc_info.value) == "Payload classifier model is not available."
    assert _SECRET not in str(exc_info.value)


def test_non_finite_decision_score_is_rejected(monkeypatch):
    fake_bundle = {
        "vectorizer": SimpleNamespace(transform=lambda values: values),
        "model": SimpleNamespace(decision_function=lambda features: np.array([float("nan")])),
    }
    monkeypatch.setattr(service, "_get_cached_bundle", lambda: fake_bundle)

    with pytest.raises(service.HttpPayloadClassifierUnavailableError):
        service.predict_payloads(["admin"])


# ---------------------------------------------------------------------------
# Frozen schemas and forbidden fields
# ---------------------------------------------------------------------------


def test_schemas_are_frozen_and_forbid_confidence_style_fields():
    request = HttpPayloadClassifierRequest(payloads=["admin"])
    assert request.include_payload_echo is False
    assert request.parameter_name is None
    with pytest.raises(ValidationError):
        request.payloads = ["other"]

    result = service.predict_payloads(["admin"]).results[0]
    with pytest.raises(ValidationError):
        result.decision_score = 0.5

    for forbidden in _FORBIDDEN_FIELDS:
        with pytest.raises(ValidationError):
            HttpPayloadClassifierResult(**{**result.model_dump(), forbidden: 0.9})


def test_request_schema_accepts_only_strict_booleans_for_echo():
    defaulted = HttpPayloadClassifierRequest.model_validate({"payloads": ["admin"]})
    assert defaulted.include_payload_echo is False

    assert (
        HttpPayloadClassifierRequest.model_validate(
            {"payloads": ["admin"], "include_payload_echo": True}
        ).include_payload_echo
        is True
    )
    assert (
        HttpPayloadClassifierRequest.model_validate(
            {"payloads": ["admin"], "include_payload_echo": False}
        ).include_payload_echo
        is False
    )

    for invalid in ("yes", "true", "false", "True", "False", 1, 0):
        with pytest.raises(ValidationError):
            HttpPayloadClassifierRequest.model_validate(
                {"payloads": ["admin"], "include_payload_echo": invalid}
            )
