"""Frozen Pydantic schemas for the isolated HTTP payload classifier.

CONTRACT
--------
- A payload is one HTTP parameter *value* (plain text), not a request, session,
  actor, or complete URL. Every payload is classified independently.
- The score is an uncalibrated, signed LinearSVC ``decision_function`` margin.
  Positive favours ``anomalous``; the margin is NOT a probability, risk score,
  or severity. No forbidden field name is part of any response model.
- ``low_margin`` (``abs(decision_score) < 1.0``) is a descriptive review flag
  derived from a Phase 3 observation. It is not a calibrated risk category and
  it never changes the label.
- Outputs are advisory research evidence only. No enforcement decision is
  represented anywhere in this module.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool

LABEL_BENIGN = "benign"
LABEL_ANOMALOUS = "anomalous"
SCORE_TYPE_DECISION = "decision_score"
FEATURE_MODE_TEXT = "text"


class HttpPayloadClassifierRequest(BaseModel):
    """Input contract for advisory classification of parameter values.

    ``parameter_name`` is display-only caller metadata. It is never a model
    feature and is not part of the response. ``include_payload_echo`` is off
    by default because parameter values may contain secrets or PII.

    Bounds (1-50 items, 10,000 characters each, 100,000 characters in total)
    are enforced by the service, which raises generic validation errors that
    never include payload contents.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    payloads: list[str] = Field(
        ...,
        description="Individual HTTP parameter-value strings to classify independently.",
    )
    parameter_name: str | None = Field(
        default=None,
        description="Optional display label; never used as a model feature.",
    )
    include_payload_echo: StrictBool = Field(
        default=False,
        description="Echo raw payload values back only when explicitly requested.",
    )


class HttpPayloadClassifierResult(BaseModel):
    """Advisory per-payload result. There is no aggregate or request verdict."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    index: int = Field(
        ge=0,
        description="Zero-based index of this value in the submitted batch.",
    )
    label: Literal["benign", "anomalous"] = Field(
        description="Advisory binary label derived from the decision score sign."
    )
    label_int: Literal[0, 1] = Field(description="Numeric form of label: 0 benign, 1 anomalous.")
    decision_score: float = Field(
        description="Uncalibrated signed LinearSVC margin; NOT a probability."
    )
    decision_threshold: float = Field(
        description="Decision boundary used for the label (0.0 in the frozen artifact)."
    )
    score_type: Literal["decision_score"] = Field(
        description="Always 'decision_score'; never 'probability' or 'confidence'."
    )
    payload_length: int = Field(ge=1, description="Character count of the input value.")
    low_margin: bool = Field(
        description=(
            "abs(decision_score) < 1.0: descriptive review flag, "
            "not a calibrated risk category."
        )
    )
    payload_echo: str | None = Field(
        default=None,
        description="Raw input value; populated only when explicitly requested.",
    )


class HttpPayloadClassifierResponse(BaseModel):
    """Envelope for one independent classification per submitted payload."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    model_name: str = Field(description="Name of the frozen selected model.")
    feature_mode: Literal["text"] = Field(
        description="Only text-only TF-IDF features are supported."
    )
    artifact_sha256: str = Field(
        description="SHA-256 of the verified model bundle that produced the results."
    )
    advisory_only: Literal[True] = Field(
        default=True,
        description="Always true; these results never enforce any action.",
    )
    interpretation: str = Field(description="Plain-language decision-score semantics.")
    limitations: list[str] = Field(description="Known model limitations and caveats.")
    results: list[HttpPayloadClassifierResult] = Field(
        description="One result per input payload, in input order."
    )


__all__ = [
    "HttpPayloadClassifierRequest",
    "HttpPayloadClassifierResponse",
    "HttpPayloadClassifierResult",
]
