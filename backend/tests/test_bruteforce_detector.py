"""
Tests for BruteForceDetector — Module 5, Step 1.

Coverage:
  1.  Single failed login → no detection
  2.  Multiple failed login attempts from same IP → candidate
  3.  Attempts below threshold → no detection
  4.  Attempts exactly at threshold → candidate
  5.  Attempts outside time window → not grouped
  6.  HTTP 401 login failures → counted
  7.  HTTP 403 responses → NOT counted as authentication failures
  8.  HTTP 200 login → not counted as failure
  9.  Non-auth endpoint returning 401 → ignored
  10. Multiple client IPs → independently analysed
  11. Safe actor_id preserved when available
  12. Missing actor_id but valid client_ip → detector still works
  13. Missing client_ip → safely handled
  14. Credential/token values never appear in result
  15. Configurable threshold works
  16. Empty input
  17. Mixed success/failure responses
  18. Multiple authentication endpoints analysed separately
"""

from datetime import datetime, timedelta, timezone
from typing import List, Optional

import pytest

from app.detection.bruteforce_detector import (
    BruteForceDetector,
    BruteForceDetectorConfig,
    _is_auth_endpoint,
    _is_auth_failure,
    _is_forbidden,
    _is_successful_auth,
    _normalise_path,
    _DEFAULT_AUTH_PATH_PATTERNS,
)
from app.schemas.bruteforce import (
    BruteForceEvent,
    BruteForceVerdict,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)


def make_event(
    request_id: str,
    path: str = "/api/v1/auth/login",
    status_code: int = 401,
    client_ip: Optional[str] = "192.0.2.1",
    actor_id: Optional[str] = None,
    method: str = "POST",
    ts_offset_minutes: float = 0.0,
    base_time: Optional[datetime] = None,
) -> BruteForceEvent:
    """
    Factory helper — produces a BruteForceEvent with sane defaults.

    ts_offset_minutes: minutes relative to base_time (negative = in the past).
    """
    base = base_time or _now()
    ts = base + timedelta(minutes=ts_offset_minutes)
    return BruteForceEvent(
        request_id=request_id,
        timestamp=ts,
        method=method,
        path=path,
        client_ip=client_ip,
        actor_id=actor_id,
        status_code=status_code,
        authentication_failure=(status_code == 401),
    )


def default_detector() -> BruteForceDetector:
    """Detector with default config (threshold=5, window=15min)."""
    return BruteForceDetector()


def detector_with(threshold: int = 5, window: int = 15) -> BruteForceDetector:
    return BruteForceDetector(
        BruteForceDetectorConfig(
            failure_threshold=threshold,
            time_window_minutes=window,
        )
    )


# ---------------------------------------------------------------------------
# Internal helper unit tests
# ---------------------------------------------------------------------------

class TestInternalHelpers:

    def test_normalise_path_lowercases(self):
        assert _normalise_path("/API/V1/Auth/Login") == "/api/v1/auth/login"

    def test_normalise_path_strips_trailing_slash(self):
        assert _normalise_path("/login/") == "/login"

    def test_is_auth_endpoint_exact_match(self):
        assert _is_auth_endpoint("/api/v1/auth/login", _DEFAULT_AUTH_PATH_PATTERNS)
        assert _is_auth_endpoint("/login", _DEFAULT_AUTH_PATH_PATTERNS)
        assert _is_auth_endpoint("/signin", _DEFAULT_AUTH_PATH_PATTERNS)
        assert _is_auth_endpoint("/auth/login", _DEFAULT_AUTH_PATH_PATTERNS)

    def test_is_auth_endpoint_case_insensitive(self):
        assert _is_auth_endpoint("/API/V1/AUTH/LOGIN", _DEFAULT_AUTH_PATH_PATTERNS)

    def test_is_auth_endpoint_non_auth_paths(self):
        assert not _is_auth_endpoint("/api/v1/users/auth-status", _DEFAULT_AUTH_PATH_PATTERNS)
        assert not _is_auth_endpoint("/auth", _DEFAULT_AUTH_PATH_PATTERNS)
        assert not _is_auth_endpoint("/api/v1/users", _DEFAULT_AUTH_PATH_PATTERNS)
        assert not _is_auth_endpoint("/health", _DEFAULT_AUTH_PATH_PATTERNS)
        # "/auth" alone (without /login) should NOT match
        assert not _is_auth_endpoint("/auth", _DEFAULT_AUTH_PATH_PATTERNS)

    def test_is_auth_failure_only_401(self):
        assert _is_auth_failure(401) is True
        assert _is_auth_failure(403) is False
        assert _is_auth_failure(200) is False
        assert _is_auth_failure(500) is False

    def test_is_forbidden(self):
        assert _is_forbidden(403) is True
        assert _is_forbidden(401) is False
        assert _is_forbidden(200) is False

    def test_is_successful_auth(self):
        assert _is_successful_auth(200) is True
        assert _is_successful_auth(201) is True
        assert _is_successful_auth(299) is True
        assert _is_successful_auth(300) is False
        assert _is_successful_auth(401) is False


# ---------------------------------------------------------------------------
# Scenario 1 — Single failed login → NO detection
# ---------------------------------------------------------------------------

class TestScenario1_SingleFailure:

    def test_single_failed_login_no_detection(self):
        detector = default_detector()
        events = [make_event("req-1", status_code=401)]
        result = detector.analyze_events(events)
        assert result.verdict == BruteForceVerdict.NO_BRUTEFORCE_DETECTED
        assert len(result.evidences) == 0
        assert result.analyzed_event_count == 1


# ---------------------------------------------------------------------------
# Scenario 2 — Multiple failures from same IP → candidate
# ---------------------------------------------------------------------------

class TestScenario2_MultipleSameIP:

    def test_multiple_failed_logins_from_same_ip(self):
        detector = default_detector()  # threshold = 5
        events = [
            make_event(f"req-{i}", status_code=401) for i in range(1, 7)
        ]
        result = detector.analyze_events(events)
        assert result.verdict == BruteForceVerdict.SUSPICIOUS_BRUTEFORCE_CANDIDATE
        assert len(result.evidences) == 1
        ev = result.evidences[0]
        assert ev.client_ip == "192.0.2.1"
        assert ev.failed_attempt_count == 6
        assert ev.auth_endpoint == "/api/v1/auth/login"

    def test_candidate_includes_confidence_score(self):
        detector = default_detector()
        events = [make_event(f"req-{i}", status_code=401) for i in range(1, 7)]
        result = detector.analyze_events(events)
        assert result.evidences[0].confidence_score >= 0.70


# ---------------------------------------------------------------------------
# Scenario 3 — Below threshold → NO detection
# ---------------------------------------------------------------------------

class TestScenario3_BelowThreshold:

    def test_four_failures_below_default_threshold(self):
        """4 failures < threshold 5 → no detection."""
        detector = default_detector()
        events = [make_event(f"req-{i}", status_code=401) for i in range(1, 5)]
        result = detector.analyze_events(events)
        assert result.verdict == BruteForceVerdict.NO_BRUTEFORCE_DETECTED
        assert len(result.evidences) == 0

    def test_zero_failures(self):
        """All 200 responses from auth endpoint → no detection."""
        detector = default_detector()
        events = [make_event(f"req-{i}", status_code=200) for i in range(1, 8)]
        result = detector.analyze_events(events)
        assert result.verdict == BruteForceVerdict.NO_BRUTEFORCE_DETECTED
        assert len(result.evidences) == 0


# ---------------------------------------------------------------------------
# Scenario 4 — Exactly at threshold → candidate
# ---------------------------------------------------------------------------

class TestScenario4_ExactlyAtThreshold:

    def test_exactly_at_threshold_is_candidate(self):
        """Exactly 5 failures = threshold → SUSPICIOUS_BRUTEFORCE_CANDIDATE."""
        detector = default_detector()
        events = [make_event(f"req-{i}", status_code=401) for i in range(1, 6)]
        result = detector.analyze_events(events)
        assert result.verdict == BruteForceVerdict.SUSPICIOUS_BRUTEFORCE_CANDIDATE
        assert result.evidences[0].failed_attempt_count == 5

    def test_one_below_threshold_not_candidate(self):
        """4 failures (one below default 5) → no detection."""
        detector = default_detector()
        events = [make_event(f"req-{i}", status_code=401) for i in range(1, 5)]
        result = detector.analyze_events(events)
        assert result.verdict == BruteForceVerdict.NO_BRUTEFORCE_DETECTED


# ---------------------------------------------------------------------------
# Scenario 5 — Outside time window → not grouped
# ---------------------------------------------------------------------------

class TestScenario5_TimeWindow:

    def test_failures_outside_window_not_grouped(self):
        """5 failures but 4 are outside the 15-minute window → below threshold."""
        detector = default_detector()  # window = 15 min
        now = _now()
        # 4 old failures (20 min ago) + 1 recent failure
        events = [
            make_event(f"old-{i}", status_code=401, ts_offset_minutes=-20, base_time=now)
            for i in range(1, 5)
        ] + [
            make_event("recent-1", status_code=401, ts_offset_minutes=0, base_time=now)
        ]
        result = detector.analyze_events(events)
        # Only 1 failure within the window → below threshold of 5
        assert result.verdict == BruteForceVerdict.NO_BRUTEFORCE_DETECTED

    def test_all_failures_within_window_detected(self):
        """5 failures all within the 15-minute window → candidate."""
        detector = default_detector()
        now = _now()
        events = [
            make_event(f"req-{i}", status_code=401, ts_offset_minutes=-i, base_time=now)
            for i in range(1, 6)  # -1 to -5 minutes → all within window
        ]
        result = detector.analyze_events(events)
        assert result.verdict == BruteForceVerdict.SUSPICIOUS_BRUTEFORCE_CANDIDATE

    def test_window_boundary_is_inclusive(self):
        """Failure exactly at window_start should be included."""
        detector = detector_with(threshold=5, window=15)
        now = _now()
        # 4 recent failures + 1 exactly at window boundary (-15 min)
        events = [
            make_event(f"req-{i}", status_code=401, ts_offset_minutes=-i, base_time=now)
            for i in range(0, 4)
        ] + [
            make_event("boundary", status_code=401, ts_offset_minutes=-15, base_time=now)
        ]
        result = detector.analyze_events(events)
        assert result.verdict == BruteForceVerdict.SUSPICIOUS_BRUTEFORCE_CANDIDATE


# ---------------------------------------------------------------------------
# Scenario 6 — 401 login failures → counted
# ---------------------------------------------------------------------------

class TestScenario6_401Counted:

    def test_401_failures_counted(self):
        detector = default_detector()
        events = [make_event(f"req-{i}", status_code=401) for i in range(1, 6)]
        result = detector.analyze_events(events)
        assert result.failed_attempt_count == 5
        assert result.evidences[0].failed_attempt_count == 5


# ---------------------------------------------------------------------------
# Scenario 7 — 403 NOT counted as auth failure
# ---------------------------------------------------------------------------

class TestScenario7_403NotCounted:

    def test_403_responses_not_counted_as_failures(self):
        """10 HTTP 403 responses should not trigger detection."""
        detector = default_detector()
        events = [
            make_event(f"req-{i}", status_code=403) for i in range(1, 11)
        ]
        result = detector.analyze_events(events)
        assert result.verdict == BruteForceVerdict.NO_BRUTEFORCE_DETECTED
        assert result.failed_attempt_count == 0

    def test_403_tracked_separately_in_evidence(self):
        """5× 401 + 3× 403 → candidate with 403 tracked in forbidden_count."""
        detector = default_detector()
        events = (
            [make_event(f"fail-{i}", status_code=401) for i in range(1, 6)]
            + [make_event(f"forb-{i}", status_code=403) for i in range(1, 4)]
        )
        result = detector.analyze_events(events)
        assert result.verdict == BruteForceVerdict.SUSPICIOUS_BRUTEFORCE_CANDIDATE
        ev = result.evidences[0]
        assert ev.failed_attempt_count == 5
        assert ev.forbidden_count == 3

    def test_explanation_mentions_forbidden_as_non_failure(self):
        detector = default_detector()
        events = (
            [make_event(f"fail-{i}", status_code=401) for i in range(1, 6)]
            + [make_event("forb-1", status_code=403)]
        )
        result = detector.analyze_events(events)
        explanation = result.evidences[0].explanation
        assert "not counted as authentication failure" in explanation.lower()


# ---------------------------------------------------------------------------
# Scenario 8 — HTTP 200 on login → not counted as failure
# ---------------------------------------------------------------------------

class TestScenario8_200NotFailure:

    def test_200_login_not_counted_as_failure(self):
        """Successful 200 login responses do not contribute to failure count."""
        detector = default_detector()
        events = [make_event(f"req-{i}", status_code=200) for i in range(1, 8)]
        result = detector.analyze_events(events)
        assert result.verdict == BruteForceVerdict.NO_BRUTEFORCE_DETECTED
        assert result.failed_attempt_count == 0

    def test_200_tracked_as_success_in_evidence(self):
        """Mix of 5× 401 and 2× 200 → candidate with success count tracked."""
        detector = default_detector()
        events = (
            [make_event(f"fail-{i}", status_code=401) for i in range(1, 6)]
            + [make_event(f"ok-{i}", status_code=200) for i in range(1, 3)]
        )
        result = detector.analyze_events(events)
        assert result.verdict == BruteForceVerdict.SUSPICIOUS_BRUTEFORCE_CANDIDATE
        ev = result.evidences[0]
        assert ev.successful_attempt_count == 2
        assert ev.failed_attempt_count == 5


# ---------------------------------------------------------------------------
# Scenario 9 — Non-auth endpoint 401 → ignored
# ---------------------------------------------------------------------------

class TestScenario9_NonAuthEndpoint:

    def test_401_on_non_auth_endpoint_ignored(self):
        """HTTP 401 from /api/v1/users is not a brute-force signal."""
        detector = default_detector()
        events = [
            make_event(
                f"req-{i}",
                path="/api/v1/users",
                status_code=401,
            )
            for i in range(1, 10)
        ]
        result = detector.analyze_events(events)
        assert result.verdict == BruteForceVerdict.NO_BRUTEFORCE_DETECTED
        assert result.failed_attempt_count == 0

    def test_401_on_orders_endpoint_ignored(self):
        detector = default_detector()
        events = [
            make_event(f"req-{i}", path="/api/v1/orders/1", status_code=401)
            for i in range(1, 8)
        ]
        result = detector.analyze_events(events)
        assert result.verdict == BruteForceVerdict.NO_BRUTEFORCE_DETECTED

    def test_broad_auth_path_not_matched(self):
        """A path that merely contains 'auth' but is not a login endpoint."""
        detector = default_detector()
        events = [
            make_event(
                f"req-{i}",
                path="/api/v1/users/auth-status",
                status_code=401,
            )
            for i in range(1, 10)
        ]
        result = detector.analyze_events(events)
        assert result.verdict == BruteForceVerdict.NO_BRUTEFORCE_DETECTED


# ---------------------------------------------------------------------------
# Scenario 10 — Multiple client IPs → independently analysed
# ---------------------------------------------------------------------------

class TestScenario10_MultipleIPs:

    def test_two_ips_each_at_threshold(self):
        """Two IPs each hitting 5 failures → 2 evidence records."""
        detector = default_detector()
        events = (
            [make_event(f"ip1-{i}", client_ip="10.0.0.1", status_code=401) for i in range(1, 6)]
            + [make_event(f"ip2-{i}", client_ip="10.0.0.2", status_code=401) for i in range(1, 6)]
        )
        result = detector.analyze_events(events)
        assert result.verdict == BruteForceVerdict.SUSPICIOUS_BRUTEFORCE_CANDIDATE
        assert len(result.evidences) == 2
        assert result.distinct_client_count == 2

    def test_one_ip_above_threshold_one_below(self):
        """IP-A at 5 failures → candidate; IP-B at 3 failures → below threshold."""
        detector = default_detector()
        events = (
            [make_event(f"ipA-{i}", client_ip="10.0.0.1", status_code=401) for i in range(1, 6)]
            + [make_event(f"ipB-{i}", client_ip="10.0.0.2", status_code=401) for i in range(1, 4)]
        )
        result = detector.analyze_events(events)
        assert result.verdict == BruteForceVerdict.SUSPICIOUS_BRUTEFORCE_CANDIDATE
        assert len(result.evidences) == 1
        assert result.evidences[0].client_ip == "10.0.0.1"

    def test_different_ips_independently_analysed(self):
        """Each IP's failure count is not pooled with others."""
        detector = default_detector()
        events = [
            make_event(f"ip{i}-req", client_ip=f"10.0.0.{i}", status_code=401)
            for i in range(1, 6)
        ]
        # 5 different IPs, each with 1 failure → no single IP reaches threshold
        result = detector.analyze_events(events)
        assert result.verdict == BruteForceVerdict.NO_BRUTEFORCE_DETECTED


# ---------------------------------------------------------------------------
# Scenario 11 — Safe actor_id preserved when available
# ---------------------------------------------------------------------------

class TestScenario11_ActorIdPreserved:

    def test_actor_id_preserved_in_evidence(self):
        """actor_id from safe header context is preserved in evidence."""
        detector = default_detector()
        events = [
            make_event(f"req-{i}", status_code=401, actor_id="user_42")
            for i in range(1, 6)
        ]
        result = detector.analyze_events(events)
        assert result.verdict == BruteForceVerdict.SUSPICIOUS_BRUTEFORCE_CANDIDATE
        ev = result.evidences[0]
        assert ev.actor_id == "user_42"

    def test_distinct_actor_count_populated(self):
        detector = default_detector()
        events = [
            make_event(f"req-{i}", status_code=401, actor_id="user_42")
            for i in range(1, 6)
        ]
        result = detector.analyze_events(events)
        assert result.distinct_actor_count == 1


# ---------------------------------------------------------------------------
# Scenario 12 — Missing actor_id, valid client_ip → detector still works
# ---------------------------------------------------------------------------

class TestScenario12_MissingActorId:

    def test_no_actor_id_still_detected(self):
        """Brute-force detection works without actor_id."""
        detector = default_detector()
        events = [
            make_event(f"req-{i}", status_code=401, actor_id=None)
            for i in range(1, 6)
        ]
        result = detector.analyze_events(events)
        assert result.verdict == BruteForceVerdict.SUSPICIOUS_BRUTEFORCE_CANDIDATE
        ev = result.evidences[0]
        assert ev.actor_id is None
        assert ev.client_ip == "192.0.2.1"

    def test_actor_id_none_does_not_affect_count(self):
        detector = default_detector()
        events = [
            make_event(f"req-{i}", status_code=401, actor_id=None)
            for i in range(1, 6)
        ]
        result = detector.analyze_events(events)
        # actor count is 0 when no actor_ids are present
        assert result.distinct_actor_count == 0


# ---------------------------------------------------------------------------
# Scenario 13 — Missing client_ip → safely handled
# ---------------------------------------------------------------------------

class TestScenario13_MissingClientIP:

    def test_missing_client_ip_events_safely_excluded(self):
        """Events with client_ip=None are excluded from detection, not error."""
        detector = default_detector()
        events = [
            make_event(f"req-{i}", status_code=401, client_ip=None)
            for i in range(1, 10)
        ]
        result = detector.analyze_events(events)
        # Should not crash; should return insufficient evidence or no detection
        assert result.verdict in (
            BruteForceVerdict.INSUFFICIENT_EVIDENCE,
            BruteForceVerdict.NO_BRUTEFORCE_DETECTED,
        )
        assert len(result.evidences) == 0

    def test_mixed_missing_and_valid_ips(self):
        """Events with valid IPs are analysed; events without IPs are excluded."""
        detector = default_detector()
        events = (
            [make_event(f"nip-{i}", status_code=401, client_ip=None) for i in range(1, 5)]
            + [make_event(f"ok-{i}", status_code=401, client_ip="10.0.0.1") for i in range(1, 6)]
        )
        result = detector.analyze_events(events)
        # IP 10.0.0.1 has 5 failures → candidate
        assert result.verdict == BruteForceVerdict.SUSPICIOUS_BRUTEFORCE_CANDIDATE
        assert result.evidences[0].client_ip == "10.0.0.1"

    def test_all_missing_ip_returns_insufficient_or_no_detection(self):
        detector = default_detector()
        events = [
            make_event(f"req-{i}", status_code=401, client_ip=None)
            for i in range(1, 3)
        ]
        result = detector.analyze_events(events)
        # Must not crash; verdict either insufficient or no-detection
        assert result.verdict in (
            BruteForceVerdict.INSUFFICIENT_EVIDENCE,
            BruteForceVerdict.NO_BRUTEFORCE_DETECTED,
        )


# ---------------------------------------------------------------------------
# Scenario 14 — Credential/token values never appear in result
# ---------------------------------------------------------------------------

class TestScenario14_NoCrendentialsInResult:

    # Simulate events whose actor_id was passed a "safe" value but whose
    # description also includes a "leaked" credential string to ensure
    # the detector never echoes it.
    _CREDENTIAL_STRINGS = [
        "Bearer eyJhbGciOiJIUzI1NiJ9.secret",
        "password=s3cr3t",
        "api_key=abc123xyz",
        "Authorization: Basic dXNlcjpwYXNz",
        "Cookie: session=abc",
    ]

    def test_no_credential_in_evidence_explanation(self):
        """Credential strings must never appear in the result explanation."""
        detector = default_detector()
        for cred in self._CREDENTIAL_STRINGS:
            # Even if someone mistakenly sets actor_id to a cred string
            events = [
                make_event(f"req-{i}", status_code=401, actor_id=cred)
                for i in range(1, 6)
            ]
            result = detector.analyze_events(events)
            # The explanation must not contain the raw credential string
            for ev in result.evidences:
                assert cred not in ev.explanation, (
                    f"Credential string leaked into explanation: {cred!r}"
                )

    def test_no_credential_in_summary(self):
        detector = default_detector()
        for cred in self._CREDENTIAL_STRINGS:
            events = [
                make_event(f"req-{i}", status_code=401, actor_id=cred)
                for i in range(1, 6)
            ]
            result = detector.analyze_events(events)
            assert cred not in result.summary

    def test_explanation_contains_no_token_words(self):
        """Spot-check that known sensitive header names don't appear in output."""
        detector = default_detector()
        events = [make_event(f"req-{i}", status_code=401) for i in range(1, 6)]
        result = detector.analyze_events(events)
        for ev in result.evidences:
            lower = ev.explanation.lower()
            for bad_word in ("authorization", "bearer", "cookie", "api_key", "password", "secret"):
                assert bad_word not in lower, (
                    f"Sensitive word '{bad_word}' found in explanation"
                )


# ---------------------------------------------------------------------------
# Scenario 15 — Configurable threshold
# ---------------------------------------------------------------------------

class TestScenario15_ConfigurableThreshold:

    def test_lower_threshold_triggers_earlier(self):
        """With threshold=3, three failures are enough."""
        detector = detector_with(threshold=3)
        events = [make_event(f"req-{i}", status_code=401) for i in range(1, 4)]
        result = detector.analyze_events(events)
        assert result.verdict == BruteForceVerdict.SUSPICIOUS_BRUTEFORCE_CANDIDATE

    def test_lower_threshold_two_below_still_no_detection(self):
        """With threshold=3, two failures are not enough."""
        detector = detector_with(threshold=3)
        events = [make_event(f"req-{i}", status_code=401) for i in range(1, 3)]
        result = detector.analyze_events(events)
        assert result.verdict == BruteForceVerdict.NO_BRUTEFORCE_DETECTED

    def test_higher_threshold(self):
        """With threshold=10, five failures are not enough."""
        detector = detector_with(threshold=10)
        events = [make_event(f"req-{i}", status_code=401) for i in range(1, 6)]
        result = detector.analyze_events(events)
        assert result.verdict == BruteForceVerdict.NO_BRUTEFORCE_DETECTED

    def test_higher_threshold_exactly_met(self):
        """With threshold=10, exactly 10 failures trigger detection."""
        detector = detector_with(threshold=10)
        events = [make_event(f"req-{i}", status_code=401) for i in range(1, 11)]
        result = detector.analyze_events(events)
        assert result.verdict == BruteForceVerdict.SUSPICIOUS_BRUTEFORCE_CANDIDATE


# ---------------------------------------------------------------------------
# Scenario 16 — Empty input
# ---------------------------------------------------------------------------

class TestScenario16_EmptyInput:

    def test_empty_event_list_no_crash(self):
        detector = default_detector()
        result = detector.analyze_events([])
        assert result.verdict == BruteForceVerdict.NO_BRUTEFORCE_DETECTED
        assert result.analyzed_event_count == 0
        assert len(result.evidences) == 0
        assert result.failed_attempt_count == 0
        assert result.distinct_client_count == 0


# ---------------------------------------------------------------------------
# Scenario 17 — Mixed success/failure responses
# ---------------------------------------------------------------------------

class TestScenario17_MixedResponses:

    def test_mixed_401_and_200_only_failures_counted(self):
        """Sequence: 5× 401 then 2× 200 — detector sees 5 failures (candidate)."""
        detector = default_detector()
        events = (
            [make_event(f"fail-{i}", status_code=401) for i in range(1, 6)]
            + [make_event(f"ok-{i}", status_code=200) for i in range(1, 3)]
        )
        result = detector.analyze_events(events)
        assert result.verdict == BruteForceVerdict.SUSPICIOUS_BRUTEFORCE_CANDIDATE
        ev = result.evidences[0]
        assert ev.failed_attempt_count == 5
        assert ev.successful_attempt_count == 2

    def test_single_success_surrounded_by_failures(self):
        detector = default_detector()
        events = (
            [make_event(f"f{i}", status_code=401) for i in range(1, 4)]
            + [make_event("s1", status_code=200)]
            + [make_event(f"f{i}", status_code=401) for i in range(4, 7)]
        )
        result = detector.analyze_events(events)
        assert result.verdict == BruteForceVerdict.SUSPICIOUS_BRUTEFORCE_CANDIDATE
        ev = result.evidences[0]
        assert ev.failed_attempt_count == 6
        assert ev.successful_attempt_count == 1

    def test_mixed_does_not_auto_classify_as_bruteforce_without_threshold(self):
        """Only 2 failures + 3 successes → below threshold → no detection."""
        detector = default_detector()
        events = (
            [make_event(f"f{i}", status_code=401) for i in range(1, 3)]
            + [make_event(f"s{i}", status_code=200) for i in range(1, 4)]
        )
        result = detector.analyze_events(events)
        assert result.verdict == BruteForceVerdict.NO_BRUTEFORCE_DETECTED


# ---------------------------------------------------------------------------
# Scenario 18 — Multiple auth endpoints analysed separately
# ---------------------------------------------------------------------------

class TestScenario18_MultipleAuthEndpoints:

    def test_two_endpoints_analysed_separately(self):
        """Failures against /login and /api/v1/auth/login are in separate groups."""
        detector = default_detector()
        events = (
            [make_event(f"e1-{i}", path="/login", status_code=401) for i in range(1, 6)]
            + [make_event(f"e2-{i}", path="/api/v1/auth/login", status_code=401) for i in range(1, 6)]
        )
        result = detector.analyze_events(events)
        assert result.verdict == BruteForceVerdict.SUSPICIOUS_BRUTEFORCE_CANDIDATE
        assert len(result.evidences) == 2
        endpoints = {ev.auth_endpoint for ev in result.evidences}
        assert "/login" in endpoints
        assert "/api/v1/auth/login" in endpoints

    def test_one_endpoint_above_threshold_other_below(self):
        """/login has 5 failures; /auth/token has 2 → only /login is evidence."""
        detector = default_detector()
        events = (
            [make_event(f"login-{i}", path="/login", status_code=401) for i in range(1, 6)]
            + [make_event(f"token-{i}", path="/auth/token", status_code=401) for i in range(1, 3)]
        )
        result = detector.analyze_events(events)
        assert result.verdict == BruteForceVerdict.SUSPICIOUS_BRUTEFORCE_CANDIDATE
        assert len(result.evidences) == 1
        assert result.evidences[0].auth_endpoint == "/login"

    def test_failures_not_pooled_across_endpoints(self):
        """3 failures on /login + 3 on /api/v1/auth/login → neither hits threshold=5."""
        detector = default_detector()
        events = (
            [make_event(f"a-{i}", path="/login", status_code=401) for i in range(1, 4)]
            + [make_event(f"b-{i}", path="/api/v1/auth/login", status_code=401) for i in range(1, 4)]
        )
        result = detector.analyze_events(events)
        assert result.verdict == BruteForceVerdict.NO_BRUTEFORCE_DETECTED


# ---------------------------------------------------------------------------
# Additional edge-case tests
# ---------------------------------------------------------------------------

class TestEdgeCases:

    def test_analyze_event_count_accurate(self):
        detector = default_detector()
        events = [make_event(f"req-{i}", status_code=401) for i in range(1, 4)]
        result = detector.analyze_events(events)
        assert result.analyzed_event_count == 3

    def test_result_summary_not_empty(self):
        detector = default_detector()
        result = detector.analyze_events([])
        assert result.summary

    def test_explanation_contains_client_ip(self):
        """Deterministic explanation format includes the client IP."""
        detector = default_detector()
        events = [
            make_event(f"req-{i}", status_code=401, client_ip="192.0.2.10")
            for i in range(1, 6)
        ]
        result = detector.analyze_events(events)
        assert "192.0.2.10" in result.evidences[0].explanation

    def test_explanation_contains_failure_count(self):
        detector = default_detector()
        events = [
            make_event(f"req-{i}", status_code=401) for i in range(1, 8)
        ]
        result = detector.analyze_events(events)
        assert "7" in result.evidences[0].explanation

    def test_explanation_contains_auth_endpoint(self):
        detector = default_detector()
        events = [make_event(f"req-{i}", status_code=401) for i in range(1, 6)]
        result = detector.analyze_events(events)
        assert "/api/v1/auth/login" in result.evidences[0].explanation

    def test_status_codes_list_populated(self):
        """Evidence status_codes list contains all events in the group."""
        detector = default_detector()
        events = (
            [make_event(f"f{i}", status_code=401) for i in range(1, 6)]
            + [make_event("ok1", status_code=200)]
        )
        result = detector.analyze_events(events)
        ev = result.evidences[0]
        assert 401 in ev.status_codes
        assert 200 in ev.status_codes

    def test_request_ids_preserved(self):
        detector = default_detector()
        events = [make_event(f"unique-req-{i}", status_code=401) for i in range(1, 6)]
        result = detector.analyze_events(events)
        ev = result.evidences[0]
        for i in range(1, 6):
            assert f"unique-req-{i}" in ev.request_ids

    def test_timestamps_are_utc_aware(self):
        """All timestamps in evidence should be timezone-aware."""
        detector = default_detector()
        events = [make_event(f"req-{i}", status_code=401) for i in range(1, 6)]
        result = detector.analyze_events(events)
        for ts in result.evidences[0].timestamps:
            assert ts.tzinfo is not None

    def test_signin_endpoint_recognised(self):
        """/signin is a recognised authentication endpoint."""
        detector = default_detector()
        events = [make_event(f"req-{i}", path="/signin", status_code=401) for i in range(1, 6)]
        result = detector.analyze_events(events)
        assert result.verdict == BruteForceVerdict.SUSPICIOUS_BRUTEFORCE_CANDIDATE

    def test_oauth_token_endpoint_recognised(self):
        detector = default_detector()
        events = [make_event(f"req-{i}", path="/oauth/token", status_code=401) for i in range(1, 6)]
        result = detector.analyze_events(events)
        assert result.verdict == BruteForceVerdict.SUSPICIOUS_BRUTEFORCE_CANDIDATE

    def test_five_hundred_errors_not_counted(self):
        """HTTP 500 from auth endpoint does not contribute to failure count."""
        detector = default_detector()
        events = [make_event(f"req-{i}", status_code=500) for i in range(1, 10)]
        result = detector.analyze_events(events)
        assert result.verdict == BruteForceVerdict.NO_BRUTEFORCE_DETECTED
        assert result.failed_attempt_count == 0


# ---------------------------------------------------------------------------
# Verification: Auth Endpoint Pattern Set (Hardening Pass)
# ---------------------------------------------------------------------------

class TestAuthEndpointPatternHardening:
    """
    Focused verification that the auth endpoint pattern set contains NO wildcard
    entries and that matching is strictly exact-set-membership (after normalisation).

    The implementation report mentioned '/api/v2/auth/*' in prose — this class
    confirms the actual frozenset contains only explicit strings and that the
    matching function behaves correctly for all v2 paths.
    """

    def test_no_wildcard_characters_in_default_pattern_set(self):
        """The frozenset must contain only concrete path strings — no '*' or '?' chars."""
        for pattern in _DEFAULT_AUTH_PATH_PATTERNS:
            assert "*" not in pattern, (
                f"Wildcard '*' found in auth pattern: {pattern!r}. "
                "All patterns must be explicit path strings."
            )
            assert "?" not in pattern, (
                f"Wildcard '?' found in auth pattern: {pattern!r}."
            )

    def test_api_v2_auth_login_matches(self):
        """/api/v2/auth/login is an explicit member and must match."""
        assert _is_auth_endpoint("/api/v2/auth/login", _DEFAULT_AUTH_PATH_PATTERNS)

    def test_api_v2_auth_signin_matches(self):
        """/api/v2/auth/signin is an explicit member and must match."""
        assert _is_auth_endpoint("/api/v2/auth/signin", _DEFAULT_AUTH_PATH_PATTERNS)

    def test_api_v2_auth_anything_does_not_match(self):
        """
        /api/v2/auth/anything is NOT in the pattern set.
        Exact matching must NOT fall through to any wildcard for 'anything'.
        """
        assert not _is_auth_endpoint("/api/v2/auth/anything", _DEFAULT_AUTH_PATH_PATTERNS)
        assert not _is_auth_endpoint("/api/v2/auth/reset-password", _DEFAULT_AUTH_PATH_PATTERNS)
        assert not _is_auth_endpoint("/api/v2/auth/verify", _DEFAULT_AUTH_PATH_PATTERNS)
        assert not _is_auth_endpoint("/api/v2/auth/refresh", _DEFAULT_AUTH_PATH_PATTERNS)

    def test_api_v2_users_auth_status_does_not_match(self):
        """
        /api/v2/users/auth-status must NOT match merely because it contains 'auth'.
        Substring/contains matching is explicitly forbidden.
        """
        assert not _is_auth_endpoint("/api/v2/users/auth-status", _DEFAULT_AUTH_PATH_PATTERNS)
        assert not _is_auth_endpoint("/api/v2/auth-service/ping", _DEFAULT_AUTH_PATH_PATTERNS)
        assert not _is_auth_endpoint("/internal/auth-check", _DEFAULT_AUTH_PATH_PATTERNS)

    def test_v2_login_detection_end_to_end(self):
        """Integration: 5x 401 against /api/v2/auth/login → candidate."""
        detector = default_detector()
        events = [
            make_event(f"req-{i}", path="/api/v2/auth/login", status_code=401)
            for i in range(1, 6)
        ]
        result = detector.analyze_events(events)
        assert result.verdict == BruteForceVerdict.SUSPICIOUS_BRUTEFORCE_CANDIDATE
        assert result.evidences[0].auth_endpoint == "/api/v2/auth/login"

    def test_v2_signin_detection_end_to_end(self):
        """Integration: 5x 401 against /api/v2/auth/signin → candidate."""
        detector = default_detector()
        events = [
            make_event(f"req-{i}", path="/api/v2/auth/signin", status_code=401)
            for i in range(1, 6)
        ]
        result = detector.analyze_events(events)
        assert result.verdict == BruteForceVerdict.SUSPICIOUS_BRUTEFORCE_CANDIDATE
        assert result.evidences[0].auth_endpoint == "/api/v2/auth/signin"

    def test_v2_auth_anything_not_detected(self):
        """Integration: 10x 401 against /api/v2/auth/anything → no detection."""
        detector = default_detector()
        events = [
            make_event(f"req-{i}", path="/api/v2/auth/anything", status_code=401)
            for i in range(1, 11)
        ]
        result = detector.analyze_events(events)
        assert result.verdict == BruteForceVerdict.NO_BRUTEFORCE_DETECTED
        assert len(result.evidences) == 0

    def test_v2_users_auth_status_not_detected(self):
        """Integration: 10x 401 against /api/v2/users/auth-status → no detection."""
        detector = default_detector()
        events = [
            make_event(f"req-{i}", path="/api/v2/users/auth-status", status_code=401)
            for i in range(1, 11)
        ]
        result = detector.analyze_events(events)
        assert result.verdict == BruteForceVerdict.NO_BRUTEFORCE_DETECTED
        assert len(result.evidences) == 0

    def test_pattern_set_is_frozen(self):
        """Default pattern set must be a frozenset (immutable — no accidental mutation)."""
        assert isinstance(_DEFAULT_AUTH_PATH_PATTERNS, frozenset)

    def test_case_insensitive_v2_login_matches(self):
        """Normalisation allows case-insensitive matching for v2 paths."""
        assert _is_auth_endpoint("/API/V2/AUTH/LOGIN", _DEFAULT_AUTH_PATH_PATTERNS)
        assert _is_auth_endpoint("/Api/V2/Auth/Login", _DEFAULT_AUTH_PATH_PATTERNS)


# ---------------------------------------------------------------------------
# Verification: actor_id Safety (Hardening Pass)
# ---------------------------------------------------------------------------

class TestActorIdSafetyHardening:
    """
    Focused verification that actor_id:
      - is NEVER interpolated into ev.explanation
      - is preserved only in the dedicated ev.actor_id field
      - never causes credential material to surface in any text output field
    """

    _SENSITIVE_ACTOR_VALUES = [
        "Bearer eyJhbGciOiJSUzI1NiJ9.payload.sig",
        "Basic dXNlcjpwYXNzd29yZA==",
        "api_key_12345_secret",
        "password=hunter2",
        "session_token=abc123xyz",
        "Authorization: Bearer secret",
    ]

    def test_actor_id_not_in_explanation(self):
        """
        actor_id must NEVER appear in ev.explanation.
        The explanation template uses only client_ip, fail_count, endpoint, window.
        """
        detector = default_detector()
        for sensitive_val in self._SENSITIVE_ACTOR_VALUES:
            events = [
                make_event(f"req-{i}", status_code=401, actor_id=sensitive_val)
                for i in range(1, 6)
            ]
            result = detector.analyze_events(events)
            for ev in result.evidences:
                assert sensitive_val not in ev.explanation, (
                    f"actor_id value leaked into explanation: {sensitive_val!r}"
                )

    def test_actor_id_not_in_summary(self):
        """actor_id must NEVER appear in the overall result summary."""
        detector = default_detector()
        for sensitive_val in self._SENSITIVE_ACTOR_VALUES:
            events = [
                make_event(f"req-{i}", status_code=401, actor_id=sensitive_val)
                for i in range(1, 6)
            ]
            result = detector.analyze_events(events)
            assert sensitive_val not in result.summary, (
                f"actor_id value leaked into summary: {sensitive_val!r}"
            )

    def test_actor_id_stored_only_in_dedicated_field(self):
        """
        A safe actor_id is present in ev.actor_id ONLY —
        not replicated into explanation, request_ids, status_codes, or timestamps.
        """
        detector = default_detector()
        events = [
            make_event(f"req-{i}", status_code=401, actor_id="user_safe_42")
            for i in range(1, 6)
        ]
        result = detector.analyze_events(events)
        assert result.verdict == BruteForceVerdict.SUSPICIOUS_BRUTEFORCE_CANDIDATE
        ev = result.evidences[0]
        # Correct dedicated field: present
        assert ev.actor_id == "user_safe_42"
        # Must NOT appear in explanation text
        assert "user_safe_42" not in ev.explanation

    def test_explanation_template_uses_only_safe_fields(self):
        """
        Explanation contains client_ip and endpoint (expected) — not actor_id.
        """
        detector = default_detector()
        events = [
            make_event(f"req-{i}", status_code=401,
                       client_ip="198.51.100.7", actor_id="actor_xyz_99")
            for i in range(1, 6)
        ]
        result = detector.analyze_events(events)
        ev = result.evidences[0]
        # client_ip IS in explanation (correct)
        assert "198.51.100.7" in ev.explanation
        # actor_id is NOT in explanation
        assert "actor_xyz_99" not in ev.explanation

    def test_none_actor_id_produces_none_in_evidence(self):
        """Absence of actor_id must produce ev.actor_id = None, not empty string."""
        detector = default_detector()
        events = [
            make_event(f"req-{i}", status_code=401, actor_id=None)
            for i in range(1, 6)
        ]
        result = detector.analyze_events(events)
        ev = result.evidences[0]
        assert ev.actor_id is None

    def test_mixed_actor_ids_representative_not_in_explanation(self):
        """
        With mixed actor_ids, the majority representative is stored in ev.actor_id
        but never echoed into ev.explanation.
        """
        detector = default_detector()
        events = (
            [make_event(f"a-{i}", status_code=401, actor_id="user_dominant") for i in range(1, 5)]
            + [make_event("b-1", status_code=401, actor_id="user_minority")]
        )
        result = detector.analyze_events(events)
        ev = result.evidences[0]
        assert ev.actor_id == "user_dominant"
        assert "user_dominant" not in ev.explanation
        assert "user_minority" not in ev.explanation
