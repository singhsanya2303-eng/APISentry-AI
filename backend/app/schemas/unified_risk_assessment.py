"""
Advisory Unified Risk Assessment Contracts — Master Workstream 1.

These schemas define an internal, source-level contract that consumes existing
detector outputs. They deliberately add no HTTP endpoint, no database model and
no enforcement representation.

SECURITY CONTRACT:
  - No credentials, tokens, headers, cookies, API keys, passwords, raw request
    IDs or payload echoes are accepted or emitted.
  - The frozen payload classifier decision margin is not part of this contract.
  - No overall confidence, probability or calibrated certainty is emitted.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.schemas.bot_detection import BotClassification, OpaqueRequestId
from app.schemas.mitigation import MitigationDecisionType
from app.schemas.rate_anomaly import RateAnomalyVerdict
from app.schemas.behavior import RiskLevel


class SignalName(str, Enum):
    """Signals consumed by the unified assessment."""

    BOT_DETECTION = "bot_detection"
    BEHAVIOR_RISK = "behavior_risk"
    TRAFFIC_ANOMALY = "traffic_anomaly"
    PAYLOAD_CLASSIFIER = "payload_classifier"
    REQUEST_PATTERN = "request_pattern"
    MITIGATION_CONTEXT = "mitigation_context"


class ThreatCategory(str, Enum):
    """Explainable threat categories used by contributions and reasons."""

    BOT_AUTOMATION = "bot_automation"
    BEHAVIORAL = "behavioral"
    TRAFFIC_ANOMALY = "traffic_anomaly"
    PAYLOAD = "payload"
    REQUEST_PATTERN = "request_pattern"
    MITIGATION_CONTEXT = "mitigation_context"
    DATA_QUALITY = "data_quality"


class SignalStatus(str, Enum):
    """Per-signal availability. Missing is never equivalent to clean."""

    AVAILABLE = "available"
    MISSING = "missing"
    UNAVAILABLE = "unavailable"
    ERROR = "error"
    INVALID = "invalid"


class SignalErrorCode(str, Enum):
    """Fixed, non-sensitive detector failure codes."""

    DETECTOR_TIMEOUT = "detector_timeout"
    DETECTOR_EXCEPTION = "detector_exception"
    DEPENDENCY_UNAVAILABLE = "dependency_unavailable"
    INVALID_OUTPUT = "invalid_output"
    CONFLICTING_OUTPUT = "conflicting_output"


class SignalInputBase(BaseModel):
    """Common per-signal status fields."""

    model_config = ConfigDict(extra="forbid")

    status: SignalStatus = SignalStatus.MISSING
    error_code: SignalErrorCode | None = None


class BotDetectionSignalInput(SignalInputBase):
    """Normalized view of an existing bot-detection result."""

    bot_risk_score: float | None = Field(default=None, ge=0.0, le=100.0)
    classification: BotClassification | None = None
    suspicious_automation_candidates: int | None = Field(default=None, ge=0)
    evidence_references: list[OpaqueRequestId] | None = Field(
        default=None, max_length=25
    )
    limits_truncated: bool | None = None

    @model_validator(mode="after")
    def _require_available_fields(self) -> "BotDetectionSignalInput":
        if self.status == SignalStatus.AVAILABLE and self.bot_risk_score is None:
            self.status = SignalStatus.INVALID
            self.error_code = SignalErrorCode.INVALID_OUTPUT
        return self


class BehaviorRiskSignalInput(SignalInputBase):
    """Normalized view of an existing RiskScoreResult."""

    risk_score: float | None = Field(default=None, ge=0.0, le=100.0)
    risk_level: RiskLevel | None = None
    factor_names: list[str] | None = Field(default=None, max_length=25)

    @model_validator(mode="after")
    def _require_available_fields(self) -> "BehaviorRiskSignalInput":
        if self.status == SignalStatus.AVAILABLE and self.risk_score is None:
            self.status = SignalStatus.INVALID
            self.error_code = SignalErrorCode.INVALID_OUTPUT
        return self


class TrafficAnomalySignalInput(SignalInputBase):
    """Normalized view of an existing rate-anomaly result."""

    verdict: RateAnomalyVerdict | None = None
    anomalous_request_count: int | None = Field(default=None, ge=0)
    source_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    window_seconds: float | None = Field(default=None, gt=0.0)
    truncated: bool | None = None

    @model_validator(mode="after")
    def _require_available_fields(self) -> "TrafficAnomalySignalInput":
        if self.status == SignalStatus.AVAILABLE and self.verdict is None:
            self.status = SignalStatus.INVALID
            self.error_code = SignalErrorCode.INVALID_OUTPUT
        return self


class PayloadLabelSignal(BaseModel):
    """Categorical payload label only; the decision margin is excluded."""

    model_config = ConfigDict(extra="forbid")

    index: int = Field(..., ge=0)
    label: Literal["benign", "anomalous"]
    low_margin: bool = False


class PayloadClassifierSignalInput(SignalInputBase):
    """Normalized view of a frozen classifier response without score leakage."""

    results: list[PayloadLabelSignal] | None = Field(default=None, max_length=50)
    artifact_sha256: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )

    @model_validator(mode="after")
    def _require_available_fields(self) -> "PayloadClassifierSignalInput":
        if self.status == SignalStatus.AVAILABLE and self.results is None:
            self.status = SignalStatus.INVALID
            self.error_code = SignalErrorCode.INVALID_OUTPUT
        return self


class RequestPatternSignalInput(SignalInputBase):
    """Review-only novelty flags from existing behavioural analyzers."""

    flags: list[str] | None = Field(default=None, max_length=25)

    @model_validator(mode="after")
    def _require_available_fields(self) -> "RequestPatternSignalInput":
        if self.status == SignalStatus.AVAILABLE and self.flags is None:
            self.status = SignalStatus.INVALID
            self.error_code = SignalErrorCode.INVALID_OUTPUT
        return self


class MitigationContextSignalInput(SignalInputBase):
    """Pure advisory policy context. Never contributes points."""

    decision: MitigationDecisionType | None = None
    policy_version: str | None = Field(default=None, max_length=64)
    advisory_only: Literal[True] = True

    @model_validator(mode="after")
    def _require_available_fields(self) -> "MitigationContextSignalInput":
        if self.status == SignalStatus.AVAILABLE and self.decision is None:
            self.status = SignalStatus.INVALID
            self.error_code = SignalErrorCode.INVALID_OUTPUT
        return self


class UnifiedRiskInput(BaseModel):
    """Top-level snapshot of existing detector outputs."""

    model_config = ConfigDict(extra="forbid")

    subject_ref: str | None = Field(
        default=None,
        max_length=128,
        description="Optional opaque caller reference; never a token or credential.",
    )
    bot_detection: dict[str, Any] | None = None
    behavior_risk: dict[str, Any] | None = None
    traffic_anomaly: dict[str, Any] | None = None
    payload_classifier: dict[str, Any] | None = None
    request_pattern: dict[str, Any] | None = None
    mitigation_context: dict[str, Any] | None = None


class SignalStatusRecord(BaseModel):
    """Availability and provenance record for one signal."""

    signal: SignalName
    status: SignalStatus
    error_code: SignalErrorCode | None = None
    source_module: str
    source_function: str
    note: str


class RiskContribution(BaseModel):
    """One explainable score contribution."""

    signal: SignalName
    category: ThreatCategory
    source_module: str
    source_function: str
    points: float = Field(..., ge=0.0, le=100.0)
    status: SignalStatus
    rationale: str
    evidence_refs: list[OpaqueRequestId] = Field(default_factory=list)
    source_confidence: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description=(
            "Detector-provided evidence weight preserved as provenance only; "
            "this is not a probability or calibrated confidence."
        ),
    )


class RiskReason(BaseModel):
    """Stable, neutral explanation attached to the assessment."""

    code: str = Field(..., min_length=1, max_length=64)
    message: str = Field(..., min_length=1, max_length=300)
    category: ThreatCategory
    signal: SignalName


class CoverageSummary(BaseModel):
    """Signal completeness. This measures availability, not confidence."""

    signals_expected: int = Field(..., ge=0)
    signals_available: int = Field(..., ge=0)
    signals_missing: int = Field(..., ge=0)
    signals_unavailable: int = Field(..., ge=0)
    signals_error: int = Field(..., ge=0)
    signals_invalid: int = Field(..., ge=0)
    coverage_ratio: float = Field(..., ge=0.0, le=1.0)


class UnifiedRiskAssessment(BaseModel):
    """Advisory unified risk assessment with full signal attribution."""

    schema_version: Literal["mw1-unified-risk/v1"] = "mw1-unified-risk/v1"
    advisory_only: Literal[True] = True
    risk_score: float = Field(..., ge=0.0, le=100.0)
    severity: RiskLevel
    raw_contribution_total: float = Field(..., ge=0.0)
    clamp_applied: bool
    categories: list[ThreatCategory] = Field(default_factory=list)
    contributions: list[RiskContribution] = Field(default_factory=list)
    reasons: list[RiskReason] = Field(default_factory=list)
    signal_statuses: list[SignalStatusRecord] = Field(default_factory=list)
    coverage: CoverageSummary
    uncertainty_notes: list[str] = Field(default_factory=list)
    limits: list[str] = Field(default_factory=list)
    confidence_policy: str = (
        "No overall confidence or probability is emitted. Coverage measures signal "
        "availability only. Missing signals are not treated as clean signals."
    )
    advisory_notice: str = (
        "This assessment is an advisory review signal. It does not block, throttle, "
        "mitigate, persist a policy or execute any enforcement action."
    )


__all__ = [
    "BehaviorRiskSignalInput",
    "BotDetectionSignalInput",
    "CoverageSummary",
    "MitigationContextSignalInput",
    "PayloadClassifierSignalInput",
    "PayloadLabelSignal",
    "RequestPatternSignalInput",
    "RiskContribution",
    "RiskReason",
    "SignalErrorCode",
    "SignalName",
    "SignalStatus",
    "SignalStatusRecord",
    "ThreatCategory",
    "TrafficAnomalySignalInput",
    "UnifiedRiskAssessment",
    "UnifiedRiskInput",
]
