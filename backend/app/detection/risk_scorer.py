"""
Deterministic Risk Scoring Engine — Module 7, Step 2.

Translates aggregated BehaviorFeatures into a normalized, explainable 0–100 risk score
and categorical RiskLevel (LOW, MEDIUM, HIGH, CRITICAL).

DESIGN PRINCIPLES:
  - 100% deterministic rule-based evaluation (no ML, no heuristics, no randomness).
  - Configurable weights via RiskScoringConfig without hardcoded magic numbers.
  - Avoids double-counting (e.g. separates 401 auth failures from non-auth HTTP 4xx/5xx).
  - Every score point is traceable to an explicit RiskFactor with verifiable evidence.
  - Explanations describe observed patterns without implying definitive malice or attack certainty.
  - Bounded output: score is strictly clamped to [0.0, 100.0].

SECURITY CONTRACT:
  - Never inspects, stores, logs, or reflects passwords, Authorization headers,
    Bearer tokens, cookies, API keys, or request bodies.
"""

from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, Field

from app.schemas.behavior import (
    BehaviorFeatures,
    RiskFactor,
    RiskLevel,
    RiskScoreResult,
)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

class RiskScoringConfig(BaseModel):
    """
    Configurable weights for behavioral risk factor evaluation.
    """

    bola_weight: float = Field(
        default=30.0,
        ge=0.0,
        le=100.0,
        description="Score contribution weight for BOLA / IDOR candidate patterns"
    )
    brute_force_weight: float = Field(
        default=35.0,
        ge=0.0,
        le=100.0,
        description="Score contribution weight for brute-force candidate patterns"
    )
    rate_anomaly_weight: float = Field(
        default=25.0,
        ge=0.0,
        le=100.0,
        description="Score contribution weight for request rate anomaly signals"
    )
    authentication_failure_weight: float = Field(
        default=15.0,
        ge=0.0,
        le=100.0,
        description="Score contribution weight for raw HTTP 401 authentication failures"
    )
    failed_request_weight: float = Field(
        default=10.0,
        ge=0.0,
        le=100.0,
        description="Score contribution weight for non-auth HTTP error responses (status >= 400)"
    )
    endpoint_diversity_weight: float = Field(
        default=10.0,
        ge=0.0,
        le=100.0,
        description="Score contribution weight for elevated endpoint exploration"
    )
    resource_diversity_weight: float = Field(
        default=10.0,
        ge=0.0,
        le=100.0,
        description="Score contribution weight for horizontal object ID enumeration"
    )
    high_request_volume_weight: float = Field(
        default=10.0,
        ge=0.0,
        le=100.0,
        description="Score contribution weight for elevated request volume"
    )


# ---------------------------------------------------------------------------
# Risk Level Converter
# ---------------------------------------------------------------------------

def get_risk_level(score: float) -> RiskLevel:
    """
    Deterministic conversion of numeric risk score (0–100) to categorical RiskLevel.

    Thresholds:
      0.0 – 24.9   -> LOW
      25.0 – 49.9  -> MEDIUM
      50.0 – 74.9  -> HIGH
      75.0 – 100.0 -> CRITICAL
    """
    if score >= 75.0:
        return RiskLevel.CRITICAL
    if score >= 50.0:
        return RiskLevel.HIGH
    if score >= 25.0:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


# ---------------------------------------------------------------------------
# Risk Scorer Engine
# ---------------------------------------------------------------------------

class RiskScorer:
    """
    Deterministic Behavioral Risk Scorer.

    Evaluates BehaviorFeatures against configurable factor weights to produce
    a bounded 0–100 risk score, categorical level, and explainable factor breakdown.
    """

    def __init__(self, config: Optional[RiskScoringConfig] = None) -> None:
        self.config = config or RiskScoringConfig()

    def score_features(self, features: Optional[BehaviorFeatures]) -> RiskScoreResult:
        """
        Evaluate behavioral features and return a comprehensive RiskScoreResult.
        """
        if features is None or features.total_requests == 0:
            return RiskScoreResult(
                client_ip=features.client_ip if features else None,
                actor_id=features.actor_id if features else None,
                risk_score=0.0,
                risk_level=RiskLevel.LOW,
                factors=[],
                explanation="Normal baseline API behavior observed with no significant risk indicators."
            )

        client_ip = features.client_ip if features.client_ip else None
        client_display = client_ip or "unattributed client"
        actor_id = features.actor_id if features.actor_id else None

        factors: List[RiskFactor] = []

        # 1. BOLA / IDOR Signal
        if features.bola_candidate_count > 0 and self.config.bola_weight > 0:
            ratio = min(features.bola_candidate_count / 3.0, 1.0)
            contrib = round(min(self.config.bola_weight, self.config.bola_weight * (0.6 + 0.4 * ratio)), 1)
            factors.append(
                RiskFactor(
                    factor_name="bola_activity",
                    contribution=contrib,
                    evidence=f"{features.bola_candidate_count} BOLA / IDOR candidate access pattern(s) observed for client {client_display}."
                )
            )

        # 2. Brute-Force Activity Signal
        if features.brute_force_candidate_count > 0 and self.config.brute_force_weight > 0:
            ratio = min(features.brute_force_candidate_count / 3.0, 1.0)
            contrib = round(min(self.config.brute_force_weight, self.config.brute_force_weight * (0.6 + 0.4 * ratio)), 1)
            factors.append(
                RiskFactor(
                    factor_name="brute_force_activity",
                    contribution=contrib,
                    evidence=f"{features.brute_force_candidate_count} brute-force candidate pattern(s) observed for client {client_display}."
                )
            )

        # 3. Rate Anomaly Activity Signal
        if features.rate_anomaly_count > 0 and self.config.rate_anomaly_weight > 0:
            ratio = min(features.rate_anomaly_count / 3.0, 1.0)
            contrib = round(min(self.config.rate_anomaly_weight, self.config.rate_anomaly_weight * (0.6 + 0.4 * ratio)), 1)
            factors.append(
                RiskFactor(
                    factor_name="rate_anomaly_activity",
                    contribution=contrib,
                    evidence=f"{features.rate_anomaly_count} request rate anomaly signal(s) observed for client {client_display}."
                )
            )

        # 4. Authentication Failures (HTTP 401)
        if features.authentication_failure_count > 0 and self.config.authentication_failure_weight > 0:
            ratio = min(features.authentication_failure_count / 5.0, 1.0)
            contrib = round(self.config.authentication_failure_weight * ratio, 1)
            factors.append(
                RiskFactor(
                    factor_name="authentication_failures",
                    contribution=contrib,
                    evidence=f"{features.authentication_failure_count} authentication failure(s) (HTTP 401) observed for client {client_display}."
                )
            )

        # 5. Non-Auth Failed Requests (status >= 400 excluding 401 to avoid double-counting)
        non_auth_failures = max(0, features.failed_request_count - features.authentication_failure_count)
        if non_auth_failures >= 3 and self.config.failed_request_weight > 0:
            ratio = min(non_auth_failures / 10.0, 1.0)
            contrib = round(self.config.failed_request_weight * ratio, 1)
            factors.append(
                RiskFactor(
                    factor_name="failed_requests",
                    contribution=contrib,
                    evidence=f"{non_auth_failures} non-authentication HTTP error response(s) (status >= 400) observed for client {client_display}."
                )
            )

        # 6. Endpoint Diversity (elevated surface exploration)
        if features.unique_endpoints >= 5 and self.config.endpoint_diversity_weight > 0:
            ratio = min((features.unique_endpoints - 1) / 10.0, 1.0)
            contrib = round(self.config.endpoint_diversity_weight * ratio, 1)
            factors.append(
                RiskFactor(
                    factor_name="endpoint_diversity",
                    contribution=contrib,
                    evidence=f"Access across {features.unique_endpoints} distinct normalized endpoints observed for client {client_display}."
                )
            )

        # 7. Resource Diversity (object ID enumeration)
        if features.unique_resource_ids >= 5 and self.config.resource_diversity_weight > 0:
            ratio = min((features.unique_resource_ids - 1) / 10.0, 1.0)
            contrib = round(self.config.resource_diversity_weight * ratio, 1)
            factors.append(
                RiskFactor(
                    factor_name="resource_diversity",
                    contribution=contrib,
                    evidence=f"Access to {features.unique_resource_ids} distinct resource IDs across {features.unique_resource_types} resource type(s) observed for client {client_display}."
                )
            )

        # 8. High Request Volume
        duration = max(1.0, features.observation_window_seconds)
        rps = features.total_requests / duration
        if features.total_requests >= 50 and self.config.high_request_volume_weight > 0:
            ratio = min(features.total_requests / 200.0, 1.0)
            contrib = round(self.config.high_request_volume_weight * ratio, 1)
            factors.append(
                RiskFactor(
                    factor_name="high_request_volume",
                    contribution=contrib,
                    evidence=f"High traffic volume of {features.total_requests} requests observed over {features.observation_window_seconds:.1f}s ({rps:.2f} req/sec) for client {client_display}."
                )
            )

        # Aggregate raw score and clamp to [0.0, 100.0]
        raw_score = sum(f.contribution for f in factors)
        final_score = round(min(100.0, max(0.0, raw_score)), 1)
        risk_level = get_risk_level(final_score)

        # Build explainability description
        if not factors:
            explanation = "Normal baseline API behavior observed with no significant risk indicators."
        else:
            factor_descriptions = [f.factor_name.replace("_", " ") for f in factors]
            explanation = (
                f"Risk score is {final_score:.1f} ({risk_level.value}) based on observed behavioral indicators: "
                f"{', '.join(factor_descriptions)}."
            )

        return RiskScoreResult(
            client_ip=client_ip,
            actor_id=actor_id,
            risk_score=final_score,
            risk_level=risk_level,
            factors=factors,
            explanation=explanation,
        )
