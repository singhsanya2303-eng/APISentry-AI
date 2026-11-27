"""Shared test policy for the excluded frozen HTTP payload classifier bundle."""

from __future__ import annotations

from pathlib import Path

CLASSIFIER_ARTIFACT_PATH = (
    Path(__file__).resolve().parents[2]
    / "research"
    / "models"
    / "http_payload_classifier"
    / "v1"
    / "model_bundle.joblib"
)
CLASSIFIER_ARTIFACT_REQUIRED_OPTION = "--require-classifier-artifact"
CLASSIFIER_ARTIFACT_REQUIRED_DEST = "require_classifier_artifact"
CLASSIFIER_ARTIFACT_SKIP_REASON = (
    "frozen HTTP payload classifier bundle is not present; real-artifact tests "
    "are intentionally skipped. Use --require-classifier-artifact to fail CI "
    "when the bundle is required."
)


class ClassifierArtifactRequiredError(RuntimeError):
    """Raised when required mode is enabled but the frozen bundle is absent."""


def classifier_artifact_is_available() -> bool:
    """Return whether the frozen research bundle is present for this checkout."""
    return CLASSIFIER_ARTIFACT_PATH.is_file()


def validate_required_classifier_artifact(required: bool) -> None:
    """Fail explicitly when artifact-backed coverage is required but unavailable."""
    if required and not classifier_artifact_is_available():
        raise ClassifierArtifactRequiredError(
            f"{CLASSIFIER_ARTIFACT_REQUIRED_OPTION} was supplied but the frozen "
            f"classifier bundle is missing: {CLASSIFIER_ARTIFACT_PATH}"
        )
