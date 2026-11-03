"""
Tests for RiskScorer — Module 7, Step 2.

Comprehensive test suite verifying the deterministic, explainable risk scoring engine:
  1. zero-risk empty features
  2. normal low-risk behavior
  3. BOLA contribution
  4. brute-force contribution
  5. rate anomaly contribution
  6. authentication failure contribution
  7. failed request contribution
  8. endpoint diversity contribution
  9. resource diversity contribution
  10. request volume contribution
  11. mixed suspicious signals
  12. score capped at 100
  13. score never negative
  14. LOW boundary (0.0 - 24.9)
  15. MEDIUM boundary (25.0 - 49.9)
  16. HIGH boundary (50.0 - 74.9)
  17. CRITICAL boundary (75.0 - 100.0)
  18. deterministic output
  19. configurable weights
  20. missing actor
  21. missing client IP
  22. explanation generation
  23. factor evidence correctness
  24. no credential leakage
  25. no attacker-confirmation wording
  26. zero observation window handling
  27. very large request volume
  28. very large resource diversity
  29. no suspicious signals
  30. repeated identical features
  31. malformed/invalid config bounds handling
"""

from datetime import datetime, timezone
import pytest

from app.schemas.behavior import (
    BehaviorFeatures,
    RiskLevel,
    RiskScoreResult,
)
from app.detection.risk_scorer import (
    RiskScorer,
    RiskScoringConfig,
    get_risk_level,
)


def make_features(
    client_ip: str = "192.168.1.100",
    actor_id: str = "user_101",
    total_requests: int = 10,
    unique_endpoints: int = 2,
    unique_resource_types: int = 1,
    unique_resource_ids: int = 2,
    failed_request_count: int = 0,
    successful_request_count: int = 10,
    authentication_failure_count: int = 0,
    rate_anomaly_count: int = 0,
    bola_candidate_count: int = 0,
    brute_force_candidate_count: int = 0,
    observation_window_seconds: float = 60.0,
) -> BehaviorFeatures:
    """Helper to construct BehaviorFeatures instances for testing."""
    now = datetime.now(timezone.utc)
    return BehaviorFeatures(
        client_ip=client_ip,
        actor_id=actor_id,
        total_requests=total_requests,
        unique_endpoints=unique_endpoints,
        unique_resource_types=unique_resource_types,
        unique_resource_ids=unique_resource_ids,
        failed_request_count=failed_request_count,
        successful_request_count=successful_request_count,
        authentication_failure_count=authentication_failure_count,
        rate_anomaly_count=rate_anomaly_count,
        bola_candidate_count=bola_candidate_count,
        brute_force_candidate_count=brute_force_candidate_count,
        first_seen=now,
        last_seen=now,
        observation_window_seconds=observation_window_seconds,
    )


# ---------------------------------------------------------------------------
# 1. Zero-Risk Empty Features
# ---------------------------------------------------------------------------

def test_scenario_1_zero_risk_empty_features():
    scorer = RiskScorer()
    res = scorer.score_features(None)
    assert res.risk_score == 0.0
    assert res.risk_level == RiskLevel.LOW
    assert len(res.factors) == 0

    empty_feat = make_features(total_requests=0)
    res_empty = scorer.score_features(empty_feat)
    assert res_empty.risk_score == 0.0
    assert res_empty.risk_level == RiskLevel.LOW
    assert len(res_empty.factors) == 0


# ---------------------------------------------------------------------------
# 2. Normal Low-Risk Behavior
# ---------------------------------------------------------------------------

def test_scenario_2_normal_low_risk_behavior():
    scorer = RiskScorer()
    feat = make_features(
        total_requests=5,
        unique_endpoints=2,
        unique_resource_ids=2,
        successful_request_count=5,
        failed_request_count=0
    )
    res = scorer.score_features(feat)
    assert res.risk_score == 0.0
    assert res.risk_level == RiskLevel.LOW
    assert len(res.factors) == 0
    assert "Normal baseline" in res.explanation


# ---------------------------------------------------------------------------
# 3. BOLA Contribution
# ---------------------------------------------------------------------------

def test_scenario_3_bola_contribution():
    scorer = RiskScorer()
    feat = make_features(bola_candidate_count=2)
    res = scorer.score_features(feat)

    assert res.risk_score > 0.0
    assert any(f.factor_name == "bola_activity" for f in res.factors)
    bola_factor = next(f for f in res.factors if f.factor_name == "bola_activity")
    assert bola_factor.contribution > 0.0
    assert "BOLA / IDOR" in bola_factor.evidence


# ---------------------------------------------------------------------------
# 4. Brute-Force Contribution
# ---------------------------------------------------------------------------

def test_scenario_4_brute_force_contribution():
    scorer = RiskScorer()
    feat = make_features(brute_force_candidate_count=1)
    res = scorer.score_features(feat)

    assert res.risk_score > 0.0
    assert any(f.factor_name == "brute_force_activity" for f in res.factors)
    bf_factor = next(f for f in res.factors if f.factor_name == "brute_force_activity")
    assert bf_factor.contribution > 0.0
    assert "brute-force candidate" in bf_factor.evidence


# ---------------------------------------------------------------------------
# 5. Rate Anomaly Contribution
# ---------------------------------------------------------------------------

def test_scenario_5_rate_anomaly_contribution():
    scorer = RiskScorer()
    feat = make_features(rate_anomaly_count=1)
    res = scorer.score_features(feat)

    assert res.risk_score > 0.0
    assert any(f.factor_name == "rate_anomaly_activity" for f in res.factors)
    ra_factor = next(f for f in res.factors if f.factor_name == "rate_anomaly_activity")
    assert ra_factor.contribution > 0.0
    assert "rate anomaly" in ra_factor.evidence


# ---------------------------------------------------------------------------
# 6. Authentication Failure Contribution
# ---------------------------------------------------------------------------

def test_scenario_6_authentication_failure_contribution():
    scorer = RiskScorer()
    feat = make_features(authentication_failure_count=4, failed_request_count=4)
    res = scorer.score_features(feat)

    assert any(f.factor_name == "authentication_failures" for f in res.factors)
    auth_factor = next(f for f in res.factors if f.factor_name == "authentication_failures")
    assert auth_factor.contribution > 0.0
    assert "authentication failure" in auth_factor.evidence


# ---------------------------------------------------------------------------
# 7. Failed Request Contribution (Non-Auth Errors)
# ---------------------------------------------------------------------------

def test_scenario_7_failed_request_contribution():
    scorer = RiskScorer()
    # 5 failed requests that are NOT 401s (e.g. 500s or 404s)
    feat = make_features(failed_request_count=5, authentication_failure_count=0)
    res = scorer.score_features(feat)

    assert any(f.factor_name == "failed_requests" for f in res.factors)
    fail_factor = next(f for f in res.factors if f.factor_name == "failed_requests")
    assert fail_factor.contribution > 0.0
    assert "non-authentication HTTP error" in fail_factor.evidence


# ---------------------------------------------------------------------------
# 8. Endpoint Diversity Contribution
# ---------------------------------------------------------------------------

def test_scenario_8_endpoint_diversity_contribution():
    scorer = RiskScorer()
    feat = make_features(unique_endpoints=8)
    res = scorer.score_features(feat)

    assert any(f.factor_name == "endpoint_diversity" for f in res.factors)
    ep_factor = next(f for f in res.factors if f.factor_name == "endpoint_diversity")
    assert ep_factor.contribution > 0.0
    assert "8 distinct normalized endpoints" in ep_factor.evidence


# ---------------------------------------------------------------------------
# 9. Resource Diversity Contribution
# ---------------------------------------------------------------------------

def test_scenario_9_resource_diversity_contribution():
    scorer = RiskScorer()
    feat = make_features(unique_resource_ids=12, unique_resource_types=2)
    res = scorer.score_features(feat)

    assert any(f.factor_name == "resource_diversity" for f in res.factors)
    res_factor = next(f for f in res.factors if f.factor_name == "resource_diversity")
    assert res_factor.contribution > 0.0
    assert "12 distinct resource IDs" in res_factor.evidence


# ---------------------------------------------------------------------------
# 10. Request Volume Contribution
# ---------------------------------------------------------------------------

def test_scenario_10_request_volume_contribution():
    scorer = RiskScorer()
    feat = make_features(total_requests=100, observation_window_seconds=10.0)
    res = scorer.score_features(feat)

    assert any(f.factor_name == "high_request_volume" for f in res.factors)
    vol_factor = next(f for f in res.factors if f.factor_name == "high_request_volume")
    assert vol_factor.contribution > 0.0
    assert "100 requests" in vol_factor.evidence


# ---------------------------------------------------------------------------
# 11. Mixed Suspicious Signals
# ---------------------------------------------------------------------------

def test_scenario_11_mixed_suspicious_signals():
    scorer = RiskScorer()
    feat = make_features(
        bola_candidate_count=2,
        brute_force_candidate_count=1,
        rate_anomaly_count=1,
        authentication_failure_count=5,
        total_requests=80,
        observation_window_seconds=20.0
    )
    res = scorer.score_features(feat)
    assert res.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    assert len(res.factors) >= 4


# ---------------------------------------------------------------------------
# 12. Score Capped at 100
# ---------------------------------------------------------------------------

def test_scenario_12_score_capped_at_100():
    scorer = RiskScorer()
    # High signals across all factors that would sum over 100
    feat = make_features(
        bola_candidate_count=10,
        brute_force_candidate_count=10,
        rate_anomaly_count=10,
        authentication_failure_count=50,
        failed_request_count=100,
        unique_endpoints=20,
        unique_resource_ids=50,
        total_requests=500,
        observation_window_seconds=10.0
    )
    res = scorer.score_features(feat)
    assert res.risk_score == 100.0
    assert res.risk_level == RiskLevel.CRITICAL


# ---------------------------------------------------------------------------
# 13. Score Never Negative
# ---------------------------------------------------------------------------

def test_scenario_13_score_never_negative():
    scorer = RiskScorer()
    feat = make_features(total_requests=0)
    res = scorer.score_features(feat)
    assert res.risk_score >= 0.0


# ---------------------------------------------------------------------------
# 14–17. Risk Level Boundaries
# ---------------------------------------------------------------------------

def test_scenario_14_to_17_risk_level_boundaries():
    # LOW: 0.0 - 24.9
    assert get_risk_level(0.0) == RiskLevel.LOW
    assert get_risk_level(12.5) == RiskLevel.LOW
    assert get_risk_level(24.9) == RiskLevel.LOW

    # MEDIUM: 25.0 - 49.9
    assert get_risk_level(25.0) == RiskLevel.MEDIUM
    assert get_risk_level(35.0) == RiskLevel.MEDIUM
    assert get_risk_level(49.9) == RiskLevel.MEDIUM

    # HIGH: 50.0 - 74.9
    assert get_risk_level(50.0) == RiskLevel.HIGH
    assert get_risk_level(60.0) == RiskLevel.HIGH
    assert get_risk_level(74.9) == RiskLevel.HIGH

    # CRITICAL: 75.0 - 100.0
    assert get_risk_level(75.0) == RiskLevel.CRITICAL
    assert get_risk_level(85.0) == RiskLevel.CRITICAL
    assert get_risk_level(100.0) == RiskLevel.CRITICAL


# ---------------------------------------------------------------------------
# 18. Deterministic Output
# ---------------------------------------------------------------------------

def test_scenario_18_deterministic_output():
    scorer = RiskScorer()
    feat = make_features(
        bola_candidate_count=1,
        rate_anomaly_count=1,
        authentication_failure_count=3,
        total_requests=30
    )
    res1 = scorer.score_features(feat)
    res2 = scorer.score_features(feat)

    assert res1.risk_score == res2.risk_score
    assert res1.risk_level == res2.risk_level
    assert len(res1.factors) == len(res2.factors)
    assert res1.explanation == res2.explanation


# ---------------------------------------------------------------------------
# 19. Configurable Weights
# ---------------------------------------------------------------------------

def test_scenario_19_configurable_weights():
    config_default = RiskScoringConfig()
    config_custom = RiskScoringConfig(bola_weight=50.0, brute_force_weight=50.0)

    scorer_default = RiskScorer(config_default)
    scorer_custom = RiskScorer(config_custom)

    feat = make_features(bola_candidate_count=2)

    res_default = scorer_default.score_features(feat)
    res_custom = scorer_custom.score_features(feat)

    assert res_custom.risk_score > res_default.risk_score


# ---------------------------------------------------------------------------
# 20. Missing Actor
# ---------------------------------------------------------------------------

def test_scenario_20_missing_actor():
    scorer = RiskScorer()
    feat = make_features(actor_id=None, bola_candidate_count=1)
    res = scorer.score_features(feat)
    assert res.actor_id is None
    assert res.client_ip == "192.168.1.100"
    assert res.risk_score > 0.0


# ---------------------------------------------------------------------------
# 21. Missing Client IP
# ---------------------------------------------------------------------------

def test_scenario_21_missing_client_ip():
    scorer = RiskScorer()
    feat = make_features(client_ip="", bola_candidate_count=1)
    res = scorer.score_features(feat)
    assert res.client_ip is None
    assert res.risk_score > 0.0


# ---------------------------------------------------------------------------
# 22. Explanation Generation
# ---------------------------------------------------------------------------

def test_scenario_22_explanation_generation():
    scorer = RiskScorer()
    feat = make_features(brute_force_candidate_count=1, authentication_failure_count=5)
    res = scorer.score_features(feat)
    assert "brute force activity" in res.explanation
    assert "authentication failures" in res.explanation
    assert str(res.risk_score) in res.explanation


# ---------------------------------------------------------------------------
# 23. Factor Evidence Correctness
# ---------------------------------------------------------------------------

def test_scenario_23_factor_evidence_correctness():
    scorer = RiskScorer()
    feat = make_features(client_ip="10.20.30.40", authentication_failure_count=7)
    res = scorer.score_features(feat)
    auth_factor = next(f for f in res.factors if f.factor_name == "authentication_failures")
    assert "7 authentication failure(s)" in auth_factor.evidence
    assert "10.20.30.40" in auth_factor.evidence


# ---------------------------------------------------------------------------
# 24. No Credential Leakage
# ---------------------------------------------------------------------------

def test_scenario_24_no_credential_leakage():
    scorer = RiskScorer()
    feat = make_features(bola_candidate_count=2, brute_force_candidate_count=1)
    res = scorer.score_features(feat)

    res_json = res.model_dump_json()
    forbidden_tokens = ["Bearer", "Authorization", "Cookie", "X-API-Key", "password", "secret"]
    for token in forbidden_tokens:
        assert token not in res_json


# ---------------------------------------------------------------------------
# 25. No Attacker-Confirmation Wording
# ---------------------------------------------------------------------------

def test_scenario_25_no_attacker_confirmation_wording():
    scorer = RiskScorer()
    feat = make_features(
        bola_candidate_count=5,
        brute_force_candidate_count=5,
        rate_anomaly_count=5
    )
    res = scorer.score_features(feat)

    # Explanations must describe observed indicators without claiming certainty
    res_text = res.explanation.lower()
    assert "attacker detected" not in res_text
    assert "user is malicious" not in res_text
    assert "confirmed attack" not in res_text


# ---------------------------------------------------------------------------
# 26. Zero Observation Window Handling
# ---------------------------------------------------------------------------

def test_scenario_26_zero_observation_window_handling():
    scorer = RiskScorer()
    # High requests in 0.0 seconds (e.g. burst in sub-second precision)
    feat = make_features(total_requests=60, observation_window_seconds=0.0)
    res = scorer.score_features(feat)
    assert res.risk_score >= 0.0
    vol_factor = next(f for f in res.factors if f.factor_name == "high_request_volume")
    assert vol_factor.contribution > 0.0


# ---------------------------------------------------------------------------
# 27. Very Large Request Volume
# ---------------------------------------------------------------------------

def test_scenario_27_very_large_request_volume():
    scorer = RiskScorer()
    feat = make_features(total_requests=10000, observation_window_seconds=100.0)
    res = scorer.score_features(feat)
    vol_factor = next(f for f in res.factors if f.factor_name == "high_request_volume")
    assert vol_factor.contribution == scorer.config.high_request_volume_weight


# ---------------------------------------------------------------------------
# 28. Very Large Resource Diversity
# ---------------------------------------------------------------------------

def test_scenario_28_very_large_resource_diversity():
    scorer = RiskScorer()
    feat = make_features(unique_resource_ids=500, unique_resource_types=10)
    res = scorer.score_features(feat)
    res_factor = next(f for f in res.factors if f.factor_name == "resource_diversity")
    assert res_factor.contribution == scorer.config.resource_diversity_weight


# ---------------------------------------------------------------------------
# 29. No Suspicious Signals
# ---------------------------------------------------------------------------

def test_scenario_29_no_suspicious_signals():
    scorer = RiskScorer()
    feat = make_features(
        total_requests=1,
        unique_endpoints=1,
        unique_resource_types=1,
        unique_resource_ids=1,
        successful_request_count=1
    )
    res = scorer.score_features(feat)
    assert res.risk_score == 0.0
    assert res.risk_level == RiskLevel.LOW
    assert len(res.factors) == 0


# ---------------------------------------------------------------------------
# 30. Repeated Identical Features
# ---------------------------------------------------------------------------

def test_scenario_30_repeated_identical_features():
    scorer = RiskScorer()
    feat = make_features(bola_candidate_count=2, failed_request_count=5)
    res1 = scorer.score_features(feat)
    res2 = scorer.score_features(feat)
    assert res1.model_dump() == res2.model_dump()


# ---------------------------------------------------------------------------
# 31. Invalid / Extreme Config Bounds
# ---------------------------------------------------------------------------

def test_scenario_31_invalid_config_bounds():
    # Pydantic validation on RiskScoringConfig
    with pytest.raises(Exception):
        RiskScoringConfig(bola_weight=-5.0)

    with pytest.raises(Exception):
        RiskScoringConfig(brute_force_weight=150.0)
