"""
Bot Detection Schemas — Stage 1.

Schemas for the deterministic, evidence-based bot classification engine.

SECURITY CONTRACT:
  - Only sanitized traffic metadata is exposed.
  - No Authorization headers, Bearer tokens, cookies, API keys, passwords,
    query-parameter secrets, or request bodies are ever included in responses.
  - Request IDs are emitted only as deterministic opaque UUID references;
    client-supplied original values are never included in responses.
  - Bot risk is always distinct from the existing behavioural risk score.
"""

from datetime import datetime
from enum import Enum
from typing import Annotated, Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

# Correlation references are opaque UUID5 values produced by the bot service.
# The schema rejects any client-shaped identifier as defence in depth; no raw
# request ID can satisfy this contract.
OPAQUE_REQUEST_ID_PATTERN = (
    r"^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
OpaqueRequestId = Annotated[
    str,
    Field(
        min_length=36,
        max_length=36,
        pattern=OPAQUE_REQUEST_ID_PATTERN,
        description="Deterministic opaque UUID5 request correlation reference",
    ),
]


class BotClassification(str, Enum):
    """Evidence-based bot classification labels."""

    HUMAN_LIKE = "human_like"
    AUTOMATION_BENIGN_CANDIDATE = "automation_benign_candidate"
    AUTOMATION_SUSPICIOUS = "automation_suspicious"
    UNKNOWN = "unknown"


class BotReasonSeverity(str, Enum):
    """Neutral signal severity; not a mitigation or enforcement decision."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class BotReasonCategory(str, Enum):
    """Machine-readable category for a bot detection reason."""

    RATE_ANOMALY = "rate_anomaly"
    AUTHENTICATION = "authentication"
    REQUEST_PATTERN = "request_pattern"
    USER_AGENT = "user_agent"
    HISTORICAL_PATTERN = "historical_pattern"
    ENDPOINT_DIVERSITY = "endpoint_diversity"
    RESOURCE_DIVERSITY = "resource_diversity"
    AUTOMATION_CHARACTERISTIC = "automation_characteristic"
    EVIDENCE_QUALITY = "evidence_quality"


class BotReason(BaseModel):
    """Structured, explainable reason contributing to a bot assessment."""

    code: str = Field(..., min_length=1, description="Stable machine-readable reason code")
    category: BotReasonCategory = Field(..., description="Signal category")
    description: str = Field(
        ..., min_length=1, description="Neutral human-readable explanation"
    )
    severity: BotReasonSeverity = Field(..., description="Signal severity, not enforcement")
    evidence_count: int = Field(
        default=0, ge=0, description="Number of supporting traffic observations"
    )
    score_contribution: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
        description="Points added to the independent bot risk score",
    )
    request_ids: List[OpaqueRequestId] = Field(
        default_factory=list,
        description="Bounded list of opaque request correlation references supporting this reason",
    )
    details: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional non-sensitive numeric or boolean signal details",
    )

    model_config = ConfigDict(from_attributes=True)


class BotEvidenceReference(BaseModel):
    """A request-level opaque reference deterministically derived from a traffic log."""

    request_id: OpaqueRequestId = Field(
        ..., description="Opaque correlation reference for a traffic-log request"
    )
    source: str = Field(
        ..., min_length=1, description="Detection signal that produced this reference"
    )
    observed_at: Optional[datetime] = Field(
        default=None, description="UTC timestamp of the referenced request when available"
    )

    model_config = ConfigDict(from_attributes=True)


class BotScoreFactor(BaseModel):
    """Explainable contribution to the independent bot risk score."""

    factor_name: str = Field(..., min_length=1, description="Stable factor identifier")
    contribution: float = Field(
        ..., ge=0.0, le=100.0, description="Bounded score contribution in points"
    )
    evidence_count: int = Field(
        default=0, ge=0, description="Number of observations supporting this factor"
    )
    description: str = Field(..., min_length=1, description="Factor explanation")

    model_config = ConfigDict(from_attributes=True)


class BehavioralRiskContext(BaseModel):
    """Separately labelled context from the existing behavioural risk engine."""

    label: str = Field(
        default="behavioral_risk_score",
        description="Explicit label distinguishing this from bot_risk_score",
    )
    risk_score: float = Field(
        ..., ge=0.0, le=100.0, description="Existing behavioural risk score"
    )
    risk_level: str = Field(..., description="Existing behavioural risk level")
    explanation: str = Field(..., description="Existing behavioural explanation")
    source: str = Field(
        default="behavior_analysis_service",
        description="Service that produced the behavioural score",
    )
    note: str = Field(
        default=(
            "Separate from bot_risk_score; not used to calculate bot_risk_score. "
            "This context is computed from the requested traffic page only and may "
            "cover a narrower window than page 1 multi-page bot analysis."
        ),
        description="Explicit separation and window-scope statement",
    )

    model_config = ConfigDict(from_attributes=True)


class BotAnalysisResult(BaseModel):
    """Per-client bot detection assessment."""

    client_ip: Optional[str] = Field(
        default=None, description="Attributed client IP; None when not available"
    )
    actor_id: Optional[str] = Field(
        default=None,
        description=(
            "Non-sensitive actor context for this group. A shared IP may produce "
            "multiple groups; an IP alone is never treated as an individual identity."
        ),
    )
    bot_risk_score: float = Field(
        ..., ge=0.0, le=100.0, description="Independent deterministic bot risk score"
    )
    classification: BotClassification = Field(..., description="Evidence-based label")
    reasons: List[BotReason] = Field(default_factory=list, description="Structured reasons")
    score_factors: List[BotScoreFactor] = Field(
        default_factory=list, description="Explainable score factor contributions"
    )
    evidence_references: List[BotEvidenceReference] = Field(
        default_factory=list, description="Bounded request-level evidence references"
    )
    request_count: int = Field(default=0, ge=0, description="Attributed requests analyzed")
    first_seen: Optional[datetime] = Field(default=None, description="First observed UTC time")
    last_seen: Optional[datetime] = Field(default=None, description="Last observed UTC time")
    observation_window_seconds: float = Field(
        default=0.0, ge=0.0, description="Observation span in seconds"
    )
    summary: str = Field(..., min_length=1, description="Neutral human-readable summary")
    behavioral_risk: Optional[BehavioralRiskContext] = Field(
        default=None, description="Optional, separately labelled behavioural risk context"
    )

    model_config = ConfigDict(from_attributes=True)


class BotAnalysisSummary(BaseModel):
    """Aggregate classification counts and neutral analysis summary."""

    total_clients: int = Field(default=0, ge=0)
    total_requests_analyzed: int = Field(default=0, ge=0)
    human_like_clients: int = Field(default=0, ge=0)
    benign_automation_candidates: int = Field(default=0, ge=0)
    suspicious_automation_candidates: int = Field(default=0, ge=0)
    unknown_clients: int = Field(default=0, ge=0)
    malformed_records_skipped: int = Field(default=0, ge=0)
    brute_force_override_count: int = Field(
        default=0,
        ge=0,
        description="Clients classified suspicious by the explicit brute-force override rule",
    )
    summary: str = Field(..., min_length=1)

    model_config = ConfigDict(from_attributes=True)


class BotAnalysisLimits(BaseModel):
    """Documented limits affecting detection completeness."""

    requested_page: int = Field(..., ge=1)
    requested_page_size: int = Field(..., ge=1)
    max_records: int = Field(..., ge=1)
    records_analyzed: int = Field(default=0, ge=0)
    truncated: bool = Field(
        default=False,
        description="True when matching records beyond max_records were not analyzed",
    )
    note: str = Field(
        default=(
            "max_records bounds only page 1, which may be read across multiple "
            "database pages using a fixed page size. page > 1 analyzes only that "
            "requested page and ignores max_records; records_analyzed is the exact "
            "number of traffic records used. truncated is true only when matching "
            "records beyond max_records were not analyzed. Optional behavioural "
            "context is page-scoped and may cover a narrower window than page 1 "
            "multi-page bot analysis. Results are detections, not mitigation decisions."
        )
    )

    model_config = ConfigDict(from_attributes=True)


class BotDetectionResponse(BaseModel):
    """Top-level response for GET /api/v1/security/bot/analyze."""

    results: List[BotAnalysisResult] = Field(default_factory=list)
    total_clients: int = Field(default=0, ge=0)
    total_events_analyzed: int = Field(default=0, ge=0)
    analysis_window_start: Optional[datetime] = Field(
        default=None, description="Earliest observed request timestamp in UTC"
    )
    analysis_window_end: Optional[datetime] = Field(
        default=None, description="Latest observed request timestamp in UTC"
    )
    requested_start_time: Optional[datetime] = Field(default=None)
    requested_end_time: Optional[datetime] = Field(default=None)
    limits: BotAnalysisLimits
    summary: BotAnalysisSummary

    model_config = ConfigDict(from_attributes=True)
