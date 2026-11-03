"""
Brute-Force Detection Schemas — Module 5, Step 1.

All schemas are derived exclusively from fields actually present in APITrafficLog
and safe external context (e.g. non-sensitive X-User-ID headers).

SECURITY CONTRACT:
  - Authorization headers, Bearer tokens, cookies, API keys, passwords,
    and any credential-bearing data are NEVER stored, logged, or exposed.
  - actor_id is OPTIONAL supporting context; client_ip is the primary
    attribution signal.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field, ConfigDict


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------

class BruteForceVerdict(str, Enum):
    """Top-level verdict for a brute-force detection analysis run."""

    NO_BRUTEFORCE_DETECTED = "no_bruteforce_detected"
    """Analyzed events do not meet any detection threshold."""

    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    """Events were present but lacked sufficient attribution (e.g. missing client_ip) to conclude."""

    SUSPICIOUS_BRUTEFORCE_CANDIDATE = "suspicious_bruteforce_candidate"
    """At or above the failure threshold; warrants further review. NOT a confirmed attack."""


# ---------------------------------------------------------------------------
# Per-Event Input
# ---------------------------------------------------------------------------

class BruteForceEvent(BaseModel):
    """
    A single API traffic event submitted for brute-force analysis.

    Fields map 1-to-1 to APITrafficLog columns plus optional safe context.
    Credential-bearing fields (Authorization, tokens, cookies) are excluded.
    """

    request_id: str = Field(..., description="Unique correlation ID for request tracing")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC-aware timestamp of the API request"
    )
    method: str = Field(..., description="HTTP method (e.g. POST)")
    path: str = Field(..., description="Request URI path (e.g. /api/v1/auth/login)")

    # Primary attribution signal — optional to allow safe handling of missing IPs
    client_ip: Optional[str] = Field(
        default=None,
        description="Client IP address. Primary attribution signal for brute-force detection."
    )

    # Optional supporting context — never derived from credentials
    actor_id: Optional[str] = Field(
        default=None,
        description=(
            "Non-sensitive actor/user identity when safely available "
            "(e.g. from X-User-ID header). "
            "NEVER populated from Authorization, Bearer tokens, cookies, or API keys."
        )
    )

    status_code: int = Field(..., description="HTTP response status code")

    # Computed flag for convenience — set by caller based on status_code and path
    authentication_failure: bool = Field(
        default=False,
        description=(
            "True when status_code == 401 AND path matches a recognised "
            "authentication endpoint. Caller is responsible for setting this "
            "correctly; the detector uses it as a pre-computed hint."
        )
    )

    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Optional per-event confidence weight (default 1.0)"
    )

    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------------------
# Per-Group Evidence
# ---------------------------------------------------------------------------

class BruteForceEvidence(BaseModel):
    """
    Structured evidence for a single suspicious brute-force candidate pattern.
    Grouped by (client_ip, auth_endpoint).
    """

    client_ip: str = Field(..., description="Client IP address that generated the suspect attempts")
    actor_id: Optional[str] = Field(
        default=None,
        description="Non-sensitive actor identity observed in this group, if available"
    )
    auth_endpoint: str = Field(..., description="Authentication endpoint path that was targeted")

    failed_attempt_count: int = Field(
        ...,
        ge=0,
        description="Number of 401 responses from the authentication endpoint within the time window"
    )
    successful_attempt_count: int = Field(
        default=0,
        ge=0,
        description="Number of 2xx responses from the authentication endpoint"
    )
    forbidden_count: int = Field(
        default=0,
        ge=0,
        description="Number of 403 responses (NOT counted as authentication failures)"
    )

    timestamps: List[datetime] = Field(
        default_factory=list,
        description="Ordered UTC timestamps of contributing requests"
    )
    request_ids: List[str] = Field(
        default_factory=list,
        description="Request correlation IDs for all contributing events"
    )
    status_codes: List[int] = Field(
        default_factory=list,
        description="Status codes for all contributing events, in timestamp order"
    )

    confidence_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Evidence confidence score (0.0 – 1.0)"
    )
    explanation: str = Field(
        ...,
        description=(
            "Deterministic, human-readable explanation. "
            "Never contains credential values."
        )
    )

    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------------------
# Overall Detection Result
# ---------------------------------------------------------------------------

class BruteForceDetectionResult(BaseModel):
    """Overall output of a single brute-force analysis run."""

    verdict: BruteForceVerdict = Field(..., description="Top-level detection verdict")

    analyzed_event_count: int = Field(
        ...,
        ge=0,
        description="Total number of BruteForceEvent records submitted for analysis"
    )
    failed_attempt_count: int = Field(
        default=0,
        ge=0,
        description="Total authentication failures (401s on auth endpoints) across all groups"
    )
    distinct_client_count: int = Field(
        default=0,
        ge=0,
        description="Number of distinct client IPs observed in candidate groups"
    )
    distinct_actor_count: int = Field(
        default=0,
        ge=0,
        description=(
            "Number of distinct actor_ids observed where available. "
            "Zero when actor_id is absent from all events."
        )
    )

    evidences: List[BruteForceEvidence] = Field(
        default_factory=list,
        description="One evidence record per suspicious (client_ip, auth_endpoint) group"
    )
    summary: str = Field(
        ...,
        description="Human-readable summary of the overall analysis result"
    )

    model_config = ConfigDict(from_attributes=True)
