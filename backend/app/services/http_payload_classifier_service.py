"""Isolated, advisory-only HTTP payload classification service.

This service is intentionally separate from bot detection, mitigation policy,
mitigation orchestration, audit persistence, and request enforcement. It reads
one frozen research artifact, verifies its SHA-256 before loading, and returns
one independent advisory prediction per supplied HTTP parameter value.

SAFETY CONTRACT
---------------
- The artifact path is a server-side constant. Callers can never supply a path.
- The artifact bytes are hashed and verified before being handed to joblib;
  joblib unpickling can execute code, so an unverified file is never loaded.
- Loading is lazy, cached, and protected by a thread lock (double-checked).
- Input is plain text only: string, non-empty, <= 10,000 characters each,
  1-50 items per batch, <= 100,000 characters in total. The whole batch is
  validated before any prediction is attempted.
- TF-IDF transformation and scoring mirror the research script exactly for
  ``feature_mode="text"``: ``vectorizer.transform`` then
  ``LinearSVC.decision_function``, with label = ``int(score >= 0.0)``.
- No aggregation, request verdict, probability, confidence, risk score, or
  severity is produced. Results are advisory research output only.
- Raw payload values are never logged and are echoed only when a caller
  explicitly requests it. Errors never expose paths, payloads, or tracebacks.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import logging
import math
import threading
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from app.schemas.http_payload_classifier import (
    FEATURE_MODE_TEXT,
    LABEL_ANOMALOUS,
    LABEL_BENIGN,
    SCORE_TYPE_DECISION,
    HttpPayloadClassifierResponse,
    HttpPayloadClassifierResult,
)

logger = logging.getLogger("apisentry.services.http_payload_classifier")

# The frozen artifact and its recorded digest. Both are server-side constants:
# no API input can influence either one.
ARTIFACT_SHA256 = "2d694c932b9779d4971fa418aa35ecdf60cc266fe909b2ea40aa5392c5ae92dc"
_ARTIFACT_DIR = (
    Path(__file__).resolve().parents[3]
    / "research"
    / "models"
    / "http_payload_classifier"
    / "v1"
)
_ARTIFACT_FILENAME = "model_bundle.joblib"

MAX_PAYLOAD_CHARS = 10_000
MAX_BATCH_SIZE = 50
MAX_TOTAL_PAYLOAD_CHARS = 100_000
LOW_MARGIN_ABS_THRESHOLD = 1.0
FORMAT_VERSION = 1
DECISION_BOUNDARY = 0.0

_LABELS = {0: LABEL_BENIGN, 1: LABEL_ANOMALOUS}
_REQUIRED_BUNDLE_KEYS = frozenset(
    {
        "format_version",
        "model",
        "vectorizer",
        "scaler",
        "feature_mode",
        "selected_model_name",
        "decision_threshold",
        "labels",
        "seed",
        "dataset_sha256",
    }
)

INTERPRETATION = (
    "Decision score is an uncalibrated, signed LinearSVC margin (threshold 0.00); "
    "positive favours anomalous. It is not a probability, risk score, or severity. "
    "Advisory research output only; not an enforcement decision."
)
LIMITATIONS = (
    "Trained on individual HTTP parameter values, not complete requests, sessions, or actors.",
    "The SVM decision score is uncalibrated and is not a probability.",
    "About 21.43% of held-out samples had an absolute decision score below 1.0.",
    "URL-encoded attacks can evade classification and repeated benign characters can be false positives.",
    "Several command and path variations were misclassified in Phase 3 hardening tests.",
    "Advisory research evidence only: no blocking, throttling, banning, or other enforcement is performed.",
)

_UNAVAILABLE_MESSAGE = "Payload classifier model is not available."


class HttpPayloadClassifierUnavailableError(RuntimeError):
    """Safe failure for a missing, corrupt, mismatched, or unusable artifact.

    The message is fixed and contains no file path, payload value, or internal
    exception text.
    """

    def __init__(self) -> None:
        super().__init__(_UNAVAILABLE_MESSAGE)


class HttpPayloadClassifierInputError(ValueError):
    """Safe validation failure whose message never contains a payload value."""


def _unavailable(reason: str) -> HttpPayloadClassifierUnavailableError:
    """Log a static server-side reason and return a caller-safe exception."""
    logger.warning("HTTP payload classifier unavailable: %s", reason)
    return HttpPayloadClassifierUnavailableError()


def _validate_batch(payloads: Any) -> list[str]:
    """Validate the entire batch before any model work; return copied strings.

    Error messages identify positions and limits only, never payload contents.
    """
    if isinstance(payloads, (str, bytes, bytearray)) or not isinstance(payloads, Sequence):
        raise HttpPayloadClassifierInputError("payloads must be a list of strings")

    count = len(payloads)
    if count < 1 or count > MAX_BATCH_SIZE:
        raise HttpPayloadClassifierInputError(
            f"payloads must contain between 1 and {MAX_BATCH_SIZE} items"
        )

    validated: list[str] = []
    total_chars = 0
    for index, value in enumerate(payloads):
        if not isinstance(value, str):
            raise HttpPayloadClassifierInputError(f"payloads[{index}] must be a string")
        if not value.strip():
            raise HttpPayloadClassifierInputError(
                f"payloads[{index}] must not be empty or whitespace-only"
            )
        if len(value) > MAX_PAYLOAD_CHARS:
            raise HttpPayloadClassifierInputError(
                f"payloads[{index}] exceeds the {MAX_PAYLOAD_CHARS} character limit"
            )
        total_chars += len(value)
        if total_chars > MAX_TOTAL_PAYLOAD_CHARS:
            raise HttpPayloadClassifierInputError(
                f"total payload length exceeds the {MAX_TOTAL_PAYLOAD_CHARS} character limit"
            )
        validated.append(value)
    return validated


def _validate_bundle(bundle: Any) -> dict[str, Any]:
    """Validate that the verified artifact supports text-only margin scoring."""
    if not isinstance(bundle, dict):
        raise _unavailable("invalid artifact structure")

    missing = sorted(_REQUIRED_BUNDLE_KEYS - set(bundle))
    if missing:
        raise _unavailable("artifact is missing required keys")

    if bundle["format_version"] != FORMAT_VERSION:
        raise _unavailable("unsupported artifact format version")
    if bundle["feature_mode"] != FEATURE_MODE_TEXT:
        raise _unavailable("unsupported feature mode")
    if bundle["labels"] != _LABELS:
        raise _unavailable("unsupported label mapping")
    if float(bundle["decision_threshold"]) != DECISION_BOUNDARY:
        raise _unavailable("unsupported decision threshold")

    model = bundle["model"]
    if not hasattr(model, "decision_function") or hasattr(model, "predict_proba"):
        raise _unavailable("artifact model does not provide decision scores")
    if not hasattr(bundle["vectorizer"], "transform"):
        raise _unavailable("artifact vectorizer is invalid")

    return bundle


def _read_verified_artifact() -> bytes:
    """Read and hash the fixed artifact path before any unpickling occurs."""
    path = _ARTIFACT_DIR / _ARTIFACT_FILENAME
    try:
        data = path.read_bytes()
    except OSError:
        raise _unavailable("artifact could not be read") from None

    actual_sha256 = hashlib.sha256(data).hexdigest()
    if not hmac.compare_digest(actual_sha256, ARTIFACT_SHA256):
        raise _unavailable("artifact hash mismatch")
    return data


def _load_bundle_verified() -> dict[str, Any]:
    """Verify the artifact digest, then load exactly those verified bytes."""
    data = _read_verified_artifact()
    try:
        bundle = joblib.load(io.BytesIO(data))
    except Exception:
        raise _unavailable("artifact could not be loaded") from None
    return _validate_bundle(bundle)


_cached_bundle: dict[str, Any] | None = None
_cache_lock = threading.Lock()


def _get_cached_bundle() -> dict[str, Any]:
    """Lazily load the verified bundle once, safely across threads."""
    global _cached_bundle

    bundle = _cached_bundle
    if bundle is None:
        with _cache_lock:
            bundle = _cached_bundle
            if bundle is None:
                bundle = _load_bundle_verified()
                _cached_bundle = bundle
    return bundle


def _reset_cache() -> None:
    """Internal test hook only; it is not reachable from any API input."""
    global _cached_bundle
    with _cache_lock:
        _cached_bundle = None


def predict_payloads(
    payloads: Sequence[str],
    *,
    include_payload_echo: bool = False,
) -> HttpPayloadClassifierResponse:
    """Classify each supplied parameter value independently and advisorially.

    Args:
        payloads: 1-50 plain-text parameter values.
        include_payload_echo: opt-in echo of raw values; off by default.

    Raises:
        HttpPayloadClassifierInputError: invalid batch, before any prediction.
        HttpPayloadClassifierUnavailableError: artifact or prediction failure.
    """
    validated = _validate_batch(payloads)
    if not isinstance(include_payload_echo, bool):
        raise HttpPayloadClassifierInputError("include_payload_echo must be a boolean")

    try:
        bundle = _get_cached_bundle()
    except HttpPayloadClassifierUnavailableError:
        raise
    except Exception:
        raise _unavailable("model initialization failed") from None

    try:
        # Text-only preprocessing: exactly the fitted vectorizer transform used
        # by the research script for feature_mode="text" (no decoding or scaling).
        features = bundle["vectorizer"].transform(list(validated))
        raw_scores = np.asarray(bundle["model"].decision_function(features)).ravel()
    except HttpPayloadClassifierUnavailableError:
        raise
    except Exception:
        raise _unavailable("prediction failed") from None

    if raw_scores.size != len(validated):
        raise _unavailable("unexpected number of decision scores")

    results: list[HttpPayloadClassifierResult] = []
    for index, (value, raw_score) in enumerate(zip(validated, raw_scores)):
        score = float(raw_score)
        if not math.isfinite(score):
            raise _unavailable("non-finite decision score")

        # Mirrors research predict_payload(): int(score >= 0.0).
        label_int = int(score >= DECISION_BOUNDARY)
        results.append(
            HttpPayloadClassifierResult(
                index=index,
                label=_LABELS[label_int],
                label_int=label_int,
                decision_score=score,
                decision_threshold=float(bundle["decision_threshold"]),
                score_type=SCORE_TYPE_DECISION,
                payload_length=len(value),
                low_margin=abs(score) < LOW_MARGIN_ABS_THRESHOLD,
                payload_echo=value if include_payload_echo else None,
            )
        )

    return HttpPayloadClassifierResponse(
        model_name=str(bundle["selected_model_name"]),
        feature_mode=FEATURE_MODE_TEXT,
        artifact_sha256=ARTIFACT_SHA256,
        advisory_only=True,
        interpretation=INTERPRETATION,
        limitations=list(LIMITATIONS),
        results=results,
    )


__all__ = [
    "ARTIFACT_SHA256",
    "LOW_MARGIN_ABS_THRESHOLD",
    "MAX_BATCH_SIZE",
    "MAX_PAYLOAD_CHARS",
    "MAX_TOTAL_PAYLOAD_CHARS",
    "HttpPayloadClassifierInputError",
    "HttpPayloadClassifierUnavailableError",
    "predict_payloads",
]
