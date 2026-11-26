"""
Advisory Advanced Detection Signal Schemas — Master Workstream 2.

Internal-only contracts for the MW2 advanced detection envelope. These schemas:

  - do not modify or extend MW1 schemas;
  - do not represent a combined score or a second unified risk score;
  - do not accept credentials, headers, cookies, raw request IDs, payload text,
    classifier decision margins or low-margin flags;
  - emit opaque UUID5 correlation references only;
  - are snapshot-driven and deterministic (no wall-clock defaults).

The envelope lives ALONGSIDE an unchanged MW1 assessment. MW1 remains the sole
owner of the unified 0-100 score, its caps and its severity thresholds.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.schemas.behavior import RiskLevel
from app.schemas.bot_detection import OpaqueRequestId
from app.schemas.unified_risk_assessment import (
    SignalErrorCode,
    SignalStatus,
    ThreatCategory,
)


class AdvancedSignalName(str, Enum):
    """Stable identities for MW2 advisory signals."""

    COORDINATED_BEHAVIOR = "coordinated_behavior"
    CREDENTIAL_ABUSE = "credential_abuse"
    API_ABUSE = "api_abuse"
    ENUMERATION_REVIEW = "enumeration_review"
    PAYLOAD_CONTEXT = "payload_context"
    ATTRIBUTION_QUALITY = "attribution_quality"
    TREND_CONTEXT = "trend_context"


class SignalLimits(BaseModel):
    """Explicit completeness state for one snapshot or result."""

    model_config = ConfigDict(extra="forbid")

    truncated: bool = False
    reason: str | None = Field(default=None, max_length=200)


class DetectionWindow(BaseModel):
    """
    Caller-supplied observation window. No value is generated from the clock,
    which preserves determinism for identical inputs.
    """

    model_config = ConfigDict(extra="forbid")

    start: datetime | None = None
    end: datetime | None = None
    duration_seconds: float | None = Field(default=None, ge=0.0)
    scope: str | None = Field(default=None, max_length=64)


class SnapshotBase(BaseModel):
    """Common, safety-checked fields for every controlled input snapshot."""

    model_config = ConfigDict(extra="forbid")

    status: SignalStatus = SignalStatus.MISSING
    error_code: SignalErrorCode | None = None
    window: DetectionWindow | None = None
    subject_ref: str | None = Field(default=None, max_length=128)
    source_module: str = Field(default="", max_length=200)
    source_function: str = Field(default="", max_length=200)
    limits: SignalLimits = Field(default_factory=SignalLimits)
    evidence_refs: list[OpaqueRequestId] = Field(
        default_factory=list, max_length=25
    )

    @model_validator(mode="after")
    def _normalise_error_code(self) -> "SnapshotBase":
        if self.status == SignalStatus.ERROR and self.error_code is None:
            self.error_code = SignalErrorCode.DETECTOR_EXCEPTION
        elif self.status == SignalStatus.INVALID and self.error_code is None:
            self.error_code = SignalErrorCode.INVALID_OUTPUT
        return self


class BehaviorSnapshot(SnapshotBase):
    """
    Aggregated, sanitized behavioural indicators. These values are supplied by
    a caller from existing detector output; no raw traffic is read here.
    """

    request_count: int = Field(default=0, ge=0)
    auth_failure_count: int = Field(default=0, ge=0)
    rate_anomaly_request_count: int = Field(default=0, ge=0)
    distinct_path_count: int = Field(default=0, ge=0)
    distinct_method_count: int = Field(default=0, ge=0)
    dominant_path_share: float = Field(default=0.0, ge=0.0, le=1.0)
    stable_user_agent: bool = False
    classification: str | None = Field(default=None, max_length=64)
    bot_risk_score: float | None = Field(default=None, ge=0.0, le=100.0)
    burst_count: int = Field(default=0, ge=0)
    inter_arrival_cv: float | None = Field(default=None, ge=0.0, le=100.0)
    sequence_repeat_count: int = Field(default=0, ge=0)
    behavior_change_flags: list[str] = Field(default_factory=list, max_length=25)
    client_count: int = Field(default=0, ge=0)
    coordinated_group_count: int = Field(default=0, ge=0)
    shared_ua_client_count: int = Field(default=0, ge=0)
    aligned_burst_client_count: int = Field(default=0, ge=0)


class CredentialSnapshot(SnapshotBase):
    """Aggregated authentication-failure counts. No account values are accepted."""

    failure_count: int = Field(default=0, ge=0)
    success_count: int = Field(default=0, ge=0)
    distinct_account_keys: int = Field(default=0, ge=0)
    distinct_client_count: int = Field(default=0, ge=0)
    auth_endpoint_count: int = Field(default=0, ge=0)
    success_after_failure_count: int = Field(default=0, ge=0)
    shared_ip_failure_groups: int = Field(default=0, ge=0)


class ApiAbuseSnapshot(SnapshotBase):
    """Aggregated API-abuse indicators derived from sanitized traffic summaries."""

    request_count: int = Field(default=0, ge=0)
    distinct_path_count: int = Field(default=0, ge=0)
    distinct_method_count: int = Field(default=0, ge=0)
    error_4xx_count: int = Field(default=0, ge=0)
    error_5xx_count: int = Field(default=0, ge=0)
    burst_count: int = Field(default=0, ge=0)
    peak_requests_per_window: int = Field(default=0, ge=0)
    window_request_threshold: int = Field(default=50, ge=1)
    enumeration_path_count: int = Field(default=0, ge=0)
    sequential_object_count: int = Field(default=0, ge=0)
    rare_method_count: int = Field(default=0, ge=0)
    scraping_path_repeat_count: int = Field(default=0, ge=0)


class PayloadLabelSnapshot(SnapshotBase):
    """
    Categorical classifier labels only. Any decision margin, low-margin flag,
    payload echo or classifier internal is rejected by ``extra='forbid'``.
    """

    labels: list[Literal["benign", "anomalous"]] = Field(
        default_factory=list, max_length=50
    )
    artifact_sha256: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )


class AttributionSnapshot(SnapshotBase):
    """Attribution-quality guardrail inputs; contributes zero points."""

    shared_ip: bool = False
    actor_inferred: bool = False
    actor_missing: bool = False
    client_missing: bool = False
    distinct_actor_count: int = Field(default=0, ge=0)
    distinct_client_count: int = Field(default=0, ge=0)


class TrendSnapshot(SnapshotBase):
    """Supplied baseline/target window summary for the existing SAE trend service."""

    baseline_window_count: int = Field(default=0, ge=0)
    target_window_count: int = Field(default=0, ge=0)
    anomalous_window_count: int = Field(default=0, ge=0)
    minimum_baseline_windows: int = Field(default=10, ge=1)
    threshold_percentile: float = Field(default=95.0, gt=0.0, le=100.0)


class AdvancedSnapshots(BaseModel):
    """Complete controlled input container for the advisory orchestrator."""

    model_config = ConfigDict(extra="forbid")

    subject_ref: str | None = Field(default=None, max_length=128)
    behavior: BehaviorSnapshot | None = None
    credential: CredentialSnapshot | None = None
    api_abuse: ApiAbuseSnapshot | None = None
    payload: PayloadLabelSnapshot | None = None
    attribution: AttributionSnapshot | None = None
    trend: TrendSnapshot | None = None


class AdvancedReason(BaseModel):
    """Neutral, explainable per-signal reason."""

    model_config = ConfigDict(extra="forbid")

    code: str = Field(..., min_length=1, max_length=64)
    message: str = Field(..., min_length=1, max_length=300)
    evidence_count: int = Field(default=0, ge=0)
    score_contribution: float = Field(default=0.0, ge=0.0, le=100.0)


class AdvancedSignalResult(BaseModel):
    """
    The MW2 advisory envelope for one advanced detection signal.

    ``points`` is a bounded review contribution inside this envelope only. It is
    NEVER added to the MW1 0-100 score and never becomes a probability.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["mw2-advanced-signal/v1"] = "mw2-advanced-signal/v1"
    signal: AdvancedSignalName
    detection_name: str = Field(..., min_length=1, max_length=128)
    threat_category: ThreatCategory
    severity: RiskLevel
    observed_indicator: str = Field(..., min_length=1, max_length=300)
    explanation: str = Field(..., min_length=1, max_length=500)
    evidence_refs: list[OpaqueRequestId] = Field(
        default_factory=list, max_length=25
    )
    source_module: str = Field(..., min_length=1, max_length=200)
    source_function: str = Field(..., min_length=1, max_length=200)
    window: DetectionWindow | None = None
    timestamp: datetime | None = None
    status: SignalStatus
    error_code: SignalErrorCode | None = None
    points: float = Field(..., ge=0.0, le=100.0)
    cap: float = Field(..., ge=0.0, le=100.0)
    reasons: list[AdvancedReason] = Field(default_factory=list, max_length=25)
    source_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    coverage_note: str | None = Field(default=None, max_length=300)
    subject_ref: str | None = Field(default=None, max_length=128)
    dedupe_key: str | None = Field(default=None, max_length=200)
    limits: SignalLimits = Field(default_factory=SignalLimits)
    advisory_only: Literal[True] = True

    @model_validator(mode="after")
    def _validate_bounds(self) -> "AdvancedSignalResult":
        if self.points > self.cap:
            raise ValueError("points must not exceed the signal cap")
        if self.status != SignalStatus.AVAILABLE and self.points != 0.0:
            raise ValueError("inactive signals must contribute zero points")
        return self


class AdvancedDetectionEnvelope(BaseModel):
    """Separate advisory envelope; independent of MW1 scoring."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["mw2-advanced-signals/v1"] = "mw2-advanced-signals/v1"
    subject_ref: str | None = Field(default=None, max_length=128)
    signals: list[AdvancedSignalResult] = Field(default_factory=list)
    advisory_only: Literal[True] = True
    confidence_policy: str = (
        "No probability, calibrated confidence or overall score is emitted. "
        "Per-signal severity reuses the existing 25/50/75 thresholds on bounded "
        "advisory points only. Coverage describes availability, not certainty."
    )
    advisory_notice: str = (
        "This envelope is advisory review evidence. It does not block, throttle, "
        "mitigate, persist a policy, execute a detector, read live traffic or "
        "activate enforcement."
    )


class AdvisoryOrchestrationResult(BaseModel):
    """
    Container that holds an UNCHANGED MW1 assessment alongside the MW2 envelope.

    ``unified_assessment`` is passed through by reference; MW1 scoring is never
    called, rewritten or combined with advanced points here.
    """

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    schema_version: Literal["mw2-advisory-orchestration/v1"] = (
        "mw2-advisory-orchestration/v1"
    )
    unified_assessment: Any | None = None
    advanced_envelope: AdvancedDetectionEnvelope
    advisory_only: Literal[True] = True
    advisory_notice: str = (
        "MW1 and MW2 outputs are separate advisory layers. No combined score is "
        "calculated and no enforcement action is represented."
    )


__all__ = [
    "AdvancedDetectionEnvelope",
    "AdvancedReason",
    "AdvancedSignalName",
    "AdvancedSignalResult",
    "AdvancedSnapshots",
    "AdvisoryOrchestrationResult",
    "ApiAbuseSnapshot",
    "AttributionSnapshot",
    "BehaviorSnapshot",
    "CredentialSnapshot",
    "DetectionWindow",
    "PayloadLabelSnapshot",
    "SignalLimits",
    "SnapshotBase",
    "TrendSnapshot",
]
