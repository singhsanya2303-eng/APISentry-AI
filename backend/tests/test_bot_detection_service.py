"""Focused regression tests for the Stage 1 bot detection service."""

import re
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from app.models.traffic import APITrafficLog
from app.schemas.bot_detection import BotClassification
from app.services import bot_detection_service as bot_module
from app.services.behavior_analysis_service import analyze_traffic_for_behavior_risk
from app.services.bot_detection_service import (
    BotScoringConfig,
    analyze_traffic_for_bot_detection,
)

FIXED_NOW = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)

OPAQUE_REQUEST_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


def _log(
    request_id,
    client_ip,
    *,
    seconds_ago=0,
    method="GET",
    path="/api/v1/users",
    status_code=200,
    user_agent="Browser/1.0",
    actor_id=None,
):
    return APITrafficLog(
        request_id=request_id,
        timestamp=FIXED_NOW - timedelta(seconds=seconds_ago),
        method=method,
        path=path,
        query_params={},
        client_ip=client_ip,
        user_agent=user_agent,
        status_code=status_code,
        response_time_ms=10.0,
        actor_id=actor_id,
    )


def _seed(session_factory, logs):
    session = session_factory()
    try:
        session.add_all(logs)
        session.commit()
    finally:
        session.close()


def _reason_codes(result):
    return {reason.code for reason in result.reasons}


def test_low_volume_traffic_produces_low_bot_score(testing_session_factory):
    _seed(
        testing_session_factory,
        [
            _log("low-1", "192.0.2.10", seconds_ago=120, path="/api/v1/users/1"),
            _log("low-2", "192.0.2.10", seconds_ago=90, path="/api/v1/orders/2"),
            _log("low-3", "192.0.2.10", seconds_ago=60, path="/api/v1/reports/3"),
            _log("low-4", "192.0.2.10", seconds_ago=30, path="/api/v1/users/4"),
            _log("low-5", "192.0.2.10", seconds_ago=10, path="/api/v1/orders/5"),
        ],
    )

    session = testing_session_factory()
    try:
        response = analyze_traffic_for_bot_detection(db=session)
    finally:
        session.close()

    assert response.total_clients == 1
    result = response.results[0]
    assert result.client_ip == "192.0.2.10"
    assert result.bot_risk_score <= 10
    assert result.classification == BotClassification.HUMAN_LIKE
    assert "HIGH_REQUEST_VELOCITY" not in _reason_codes(result)
    assert response.summary.human_like_clients == 1


def test_repeated_high_volume_increases_score_without_implying_malice(
    testing_session_factory,
):
    low = [
        _log("low-a", "192.0.2.10", seconds_ago=60, path="/api/v1/users/1"),
        _log("low-b", "192.0.2.10", seconds_ago=30, path="/api/v1/users/2"),
        _log("low-c", "192.0.2.10", seconds_ago=10, path="/api/v1/users/3"),
    ]
    high = [
        _log(f"high-{index}", "192.0.2.20", seconds_ago=59 - index, path="/api/v1/orders")
        for index in range(60)
    ]
    _seed(testing_session_factory, [*low, *high])

    session = testing_session_factory()
    try:
        response = analyze_traffic_for_bot_detection(db=session)
    finally:
        session.close()

    by_ip = {result.client_ip: result for result in response.results}
    low_result = by_ip["192.0.2.10"]
    high_result = by_ip["192.0.2.20"]

    assert high_result.bot_risk_score > low_result.bot_risk_score
    assert "HIGH_REQUEST_VELOCITY" in _reason_codes(high_result)
    assert high_result.classification == BotClassification.AUTOMATION_BENIGN_CANDIDATE
    assert high_result.classification != BotClassification.AUTOMATION_SUSPICIOUS
    assert any(
        factor.factor_name == "rate_anomaly" for factor in high_result.score_factors
    )


def test_repeated_authentication_failures_are_reported_with_evidence(
    testing_session_factory,
):
    logs = [
        _log(
            f"auth-{index}",
            "192.0.2.30",
            seconds_ago=300 - (index * 30),
            method="POST",
            path="/api/v1/auth/login",
            status_code=401,
        )
        for index in range(6)
    ]
    _seed(testing_session_factory, logs)

    session = testing_session_factory()
    try:
        response = analyze_traffic_for_bot_detection(db=session)
    finally:
        session.close()

    result = response.results[0]
    reason = next(
        reason for reason in result.reasons
        if reason.code == "REPEATED_AUTHENTICATION_FAILURES"
    )
    assert reason.category.value == "authentication"
    assert reason.severity.value == "high"
    assert reason.score_contribution > 0
    assert len(reason.request_ids) >= 2
    assert all(OPAQUE_REQUEST_ID_RE.fullmatch(value) for value in reason.request_ids)
    assert "auth-0" not in reason.request_ids
    assert "auth-1" not in reason.request_ids
    assert any(
        reference.source == "REPEATED_AUTHENTICATION_FAILURES"
        for reference in result.evidence_references
    )
    assert result.classification == BotClassification.AUTOMATION_SUSPICIOUS


def test_user_agent_novelty_is_supporting_not_proof_of_maliciousness(
    testing_session_factory,
):
    logs = [
        _log(
            f"ua-{index}",
            "192.0.2.40",
            seconds_ago=10 - index,
            user_agent="BaselineClient/1.0" if index < 4 else "NovelClient/2.0",
        )
        for index in range(5)
    ]
    _seed(testing_session_factory, logs)

    session = testing_session_factory()
    try:
        response = analyze_traffic_for_bot_detection(db=session)
    finally:
        session.close()

    result = response.results[0]
    reason = next(
        reason for reason in result.reasons if reason.code == "USER_AGENT_NOVELTY"
    )
    assert reason.severity.value == "low"
    assert reason.score_contribution <= 6
    assert len(reason.request_ids) == 1
    assert OPAQUE_REQUEST_ID_RE.fullmatch(reason.request_ids[0])
    assert "ua-4" not in reason.request_ids
    assert result.bot_risk_score <= 10
    assert result.classification != BotClassification.AUTOMATION_SUSPICIOUS
    assert "HIGH_REQUEST_VELOCITY" not in _reason_codes(result)


def test_stable_legitimate_looking_automation_is_not_malicious(
    testing_session_factory,
):
    logs = [
        _log(
            f"stable-{index}",
            "192.0.2.50",
            seconds_ago=11 - index,
            path="/api/v1/health",
            user_agent="ScheduledMonitor/1.0",
        )
        for index in range(12)
    ]
    _seed(testing_session_factory, logs)

    session = testing_session_factory()
    try:
        response = analyze_traffic_for_bot_detection(db=session)
    finally:
        session.close()

    result = response.results[0]
    assert "STABLE_REPEATED_REQUEST_PATTERN" in _reason_codes(result)
    assert "STABLE_USER_AGENT" in _reason_codes(result)
    assert result.classification == BotClassification.AUTOMATION_BENIGN_CANDIDATE
    assert result.bot_risk_score <= 15
    assert "HIGH_REQUEST_VELOCITY" not in _reason_codes(result)
    assert "REPEATED_AUTHENTICATION_FAILURES" not in _reason_codes(result)


def test_missing_or_incomplete_evidence_does_not_create_false_high_risk(
    testing_session_factory,
):
    _seed(
        testing_session_factory,
        [
            _log("short-1", "192.0.2.60", seconds_ago=10),
            _log("short-2", "192.0.2.60", seconds_ago=5),
            _log("missing-ip-1", "", seconds_ago=10),
            _log("missing-ip-2", "", seconds_ago=5),
        ],
    )

    session = testing_session_factory()
    try:
        response = analyze_traffic_for_bot_detection(db=session)
    finally:
        session.close()

    by_ip = {result.client_ip: result for result in response.results}
    short = by_ip["192.0.2.60"]
    missing = by_ip[None]

    assert "INSUFFICIENT_EVIDENCE" in _reason_codes(short)
    assert short.bot_risk_score == 0.0
    assert short.classification == BotClassification.UNKNOWN

    assert "MISSING_CLIENT_ATTRIBUTION" in _reason_codes(missing)
    assert missing.bot_risk_score == 0.0
    assert missing.classification == BotClassification.UNKNOWN


def test_identical_input_produces_identical_output(testing_session_factory):
    _seed(
        testing_session_factory,
        [
            _log("det-1", "192.0.2.70", seconds_ago=60),
            _log("det-2", "192.0.2.70", seconds_ago=30),
            _log("det-3", "192.0.2.70", seconds_ago=10),
        ],
    )

    session = testing_session_factory()
    try:
        first = analyze_traffic_for_bot_detection(db=session)
        second = analyze_traffic_for_bot_detection(db=session)
    finally:
        session.close()

    assert first.model_dump() == second.model_dump()


def test_score_is_always_bounded_and_limits_are_reported(testing_session_factory):
    logs = [
        _log(
            f"mixed-{index}",
            "192.0.2.80",
            seconds_ago=59 - index % 60,
            path=f"/api/v1/resource/{index % 30}",
            status_code=401 if index < 20 else 200,
        )
        for index in range(120)
    ]
    _seed(testing_session_factory, logs)

    session = testing_session_factory()
    try:
        full = analyze_traffic_for_bot_detection(db=session)
        bounded = analyze_traffic_for_bot_detection(db=session, max_records=25)
    finally:
        session.close()

    assert full.results
    assert all(0.0 <= item.bot_risk_score <= 100.0 for item in full.results)
    assert all(0.0 <= factor.contribution <= 100.0 for result in full.results for factor in result.score_factors)
    assert bounded.limits.records_analyzed == 25
    assert bounded.limits.truncated is True
    assert all(0.0 <= item.bot_risk_score <= 100.0 for item in bounded.results)


def test_behavioral_risk_scoring_remains_independent(testing_session_factory):
    _seed(
        testing_session_factory,
        [
            _log("ind-1", "192.0.2.90", seconds_ago=60, path="/api/v1/users/1"),
            _log("ind-2", "192.0.2.90", seconds_ago=30, path="/api/v1/users/2"),
            _log("ind-3", "192.0.2.90", seconds_ago=10, path="/api/v1/users/3"),
        ],
    )

    session = testing_session_factory()
    try:
        with patch.object(
            bot_module,
            "analyze_traffic_for_behavior_risk",
            side_effect=AssertionError(
                "Behavioural risk scoring must not run for the independent bot score"
            ),
        ) as behavior_mock:
            bot_response = analyze_traffic_for_bot_detection(db=session)
        assert behavior_mock.call_count == 0

        behavior_response = analyze_traffic_for_behavior_risk(db=session)

        with_context = analyze_traffic_for_bot_detection(
            db=session, include_behavioral_risk=True
        )
    finally:
        session.close()

    assert bot_response.results[0].behavioral_risk is None
    assert behavior_response.results[0].risk_score is not None
    assert with_context.results[0].behavioral_risk is not None
    assert with_context.results[0].behavioral_risk.label == "behavioral_risk_score"
    assert with_context.results[0].behavioral_risk.risk_level is not None


def test_pagination_uses_fixed_page_size_and_analyzes_distinct_records(
    testing_session_factory,
):
    _seed(
        testing_session_factory,
        [
            _log(f"page-{index}", "192.0.2.100", seconds_ago=300 - index)
            for index in range(300)
        ],
    )

    real_get_traffic_logs = bot_module.get_traffic_logs
    fetched_ids = []

    def _tracking_get_traffic_logs(**kwargs):
        batch = real_get_traffic_logs(**kwargs)
        fetched_ids.extend(record.request_id for record in batch)
        return batch

    session = testing_session_factory()
    try:
        with patch.object(
            bot_module, "get_traffic_logs", side_effect=_tracking_get_traffic_logs
        ):
            response = analyze_traffic_for_bot_detection(
                db=session, page_size=200, max_records=250
            )
    finally:
        session.close()

    expected_ids = {f"page-{index}" for index in range(50, 300)}
    assert response.limits.records_analyzed == 250
    assert response.total_events_analyzed == 250
    assert response.limits.truncated is True
    assert len(fetched_ids) == len(set(fetched_ids))
    assert expected_ids.issubset(set(fetched_ids))
    assert {"page-250", "page-275", "page-299"}.issubset(set(fetched_ids))


def test_page_greater_than_one_analyzes_only_requested_page(testing_session_factory):
    _seed(
        testing_session_factory,
        [
            _log(f"later-{index}", "192.0.2.101", seconds_ago=30 - index)
            for index in range(30)
        ],
    )

    real_get_traffic_logs = bot_module.get_traffic_logs
    fetched_ids = []

    def _tracking_get_traffic_logs(**kwargs):
        batch = real_get_traffic_logs(**kwargs)
        fetched_ids.extend(record.request_id for record in batch)
        return batch

    session = testing_session_factory()
    try:
        with patch.object(
            bot_module, "get_traffic_logs", side_effect=_tracking_get_traffic_logs
        ):
            response = analyze_traffic_for_bot_detection(
                db=session, page=2, page_size=10, max_records=25
            )
    finally:
        session.close()

    assert response.limits.requested_page == 2
    assert response.limits.max_records == 25
    assert response.limits.records_analyzed == 10
    assert response.limits.truncated is False
    assert set(fetched_ids) == {f"later-{index}" for index in range(10, 20)}


def test_behavioral_context_is_page_scoped_and_documented(testing_session_factory):
    _seed(
        testing_session_factory,
        [
            _log(f"ctx-page-{index}", "192.0.2.102", seconds_ago=60 - index)
            for index in range(60)
        ],
    )

    session = testing_session_factory()
    try:
        response = analyze_traffic_for_bot_detection(
            db=session,
            page_size=10,
            max_records=50,
            include_behavioral_risk=True,
        )
    finally:
        session.close()

    assert response.limits.records_analyzed == 50
    assert response.limits.truncated is True
    assert len(response.results) == 1
    context = response.results[0].behavioral_risk
    assert context is not None
    assert "requested traffic page only" in context.note
    assert "narrower window" in context.note
    assert "not used to calculate bot_risk_score" in context.note


def test_brute_force_evidence_does_not_contaminate_other_actors_on_shared_ip(
    testing_session_factory,
):
    shared_ip = "192.0.2.103"
    logs = [
        _log(
            f"shared-auth-{index}",
            shared_ip,
            seconds_ago=300 - index * 30,
            method="POST",
            path="/api/v1/auth/login",
            status_code=401,
            actor_id="actor-a",
        )
        for index in range(6)
    ]
    logs.extend(
        _log(
            f"shared-normal-{index}",
            shared_ip,
            seconds_ago=290 - index * 30,
            path=f"/api/v1/orders/{index}",
            actor_id="actor-b",
        )
        for index in range(6)
    )
    _seed(testing_session_factory, logs)

    session = testing_session_factory()
    try:
        response = analyze_traffic_for_bot_detection(db=session)
    finally:
        session.close()

    by_actor = {
        result.actor_id: result
        for result in response.results
        if result.client_ip == shared_ip
    }
    assert set(by_actor) == {"actor-a", "actor-b"}

    attacker = by_actor["actor-a"]
    other = by_actor["actor-b"]
    assert "REPEATED_AUTHENTICATION_FAILURES" in _reason_codes(attacker)
    assert attacker.classification == BotClassification.AUTOMATION_SUSPICIOUS
    assert "REPEATED_AUTHENTICATION_FAILURES" not in _reason_codes(other)
    assert other.classification != BotClassification.AUTOMATION_SUSPICIOUS
    assert "SHARED_IP_ATTRIBUTION_AMBIGUOUS" in _reason_codes(attacker)
    assert "SHARED_IP_ATTRIBUTION_AMBIGUOUS" in _reason_codes(other)
    assert all(result.client_ip == shared_ip for result in response.results)


def test_shared_ip_with_missing_actor_is_explicitly_ambiguous(testing_session_factory):
    shared_ip = "192.0.2.104"
    logs = [
        _log(
            f"missing-actor-auth-{index}",
            shared_ip,
            seconds_ago=300 - index * 30,
            method="POST",
            path="/api/v1/auth/login",
            status_code=401,
            actor_id="actor-a",
        )
        for index in range(6)
    ]
    logs.extend(
        _log(
            f"missing-actor-normal-{index}",
            shared_ip,
            seconds_ago=290 - index * 30,
            path=f"/api/v1/reports/{index}",
        )
        for index in range(6)
    )
    _seed(testing_session_factory, logs)

    session = testing_session_factory()
    try:
        response = analyze_traffic_for_bot_detection(db=session)
    finally:
        session.close()

    by_actor = {result.actor_id: result for result in response.results}
    assert set(by_actor) == {"actor-a", None}
    assert by_actor["actor-a"].classification == BotClassification.AUTOMATION_SUSPICIOUS
    assert by_actor[None].classification != BotClassification.AUTOMATION_SUSPICIOUS
    assert "SHARED_IP_ATTRIBUTION_AMBIGUOUS" in _reason_codes(by_actor[None])
    assert "REPEATED_AUTHENTICATION_FAILURES" not in _reason_codes(by_actor[None])


def test_weak_signals_alone_do_not_produce_suspicious_classification(
    testing_session_factory,
):
    logs = []
    for index in range(60):
        logs.append(
            _log(
                f"weak-{index}",
                "192.0.2.105",
                seconds_ago=59 - index,
                path="/api/v1/orders" if index % 10 else f"/api/v1/orders/{index}",
                method="POST" if index % 10 == 0 else "GET",
                user_agent=f"Client/{index % 3}",
            )
        )
    _seed(testing_session_factory, logs)

    session = testing_session_factory()
    try:
        response = analyze_traffic_for_bot_detection(
            db=session,
            scoring_config=BotScoringConfig(suspicious_score_threshold=10.0),
        )
    finally:
        session.close()

    result = response.results[0]
    assert result.bot_risk_score >= 10.0
    assert result.classification != BotClassification.AUTOMATION_SUSPICIOUS
    assert "REPEATED_AUTHENTICATION_FAILURES" not in _reason_codes(result)
    assert "BRUTE_FORCE_OVERRIDE" not in _reason_codes(result)
    assert "No strong suspicious evidence" in result.summary


def test_brute_force_override_enabled_below_threshold(testing_session_factory):
    _seed(
        testing_session_factory,
        [
            _log(
                f"override-on-{index}",
                "192.0.2.106",
                seconds_ago=300 - index * 30,
                method="POST",
                path="/api/v1/auth/login",
                status_code=401,
            )
            for index in range(6)
        ],
    )

    session = testing_session_factory()
    try:
        response = analyze_traffic_for_bot_detection(db=session)
    finally:
        session.close()

    result = response.results[0]
    assert result.bot_risk_score < 50.0
    assert result.classification == BotClassification.AUTOMATION_SUSPICIOUS
    assert "BRUTE_FORCE_OVERRIDE" in _reason_codes(result)
    assert "BRUTE_FORCE_OVERRIDE" in result.summary
    assert response.summary.brute_force_override_count == 1


def test_brute_force_override_disabled_below_threshold(testing_session_factory):
    _seed(
        testing_session_factory,
        [
            _log(
                f"override-off-{index}",
                "192.0.2.107",
                seconds_ago=300 - index * 30,
                method="POST",
                path="/api/v1/auth/login",
                status_code=401,
            )
            for index in range(6)
        ],
    )

    session = testing_session_factory()
    try:
        response = analyze_traffic_for_bot_detection(
            db=session,
            scoring_config=BotScoringConfig(brute_force_override_enabled=False),
        )
    finally:
        session.close()

    result = response.results[0]
    assert result.bot_risk_score < 50.0
    assert result.classification != BotClassification.AUTOMATION_SUSPICIOUS
    assert "BRUTE_FORCE_OVERRIDE" not in _reason_codes(result)
    assert "override is disabled" in result.summary
    assert response.summary.brute_force_override_count == 0


def test_score_threshold_with_strong_evidence_when_override_disabled(
    testing_session_factory,
):
    _seed(
        testing_session_factory,
        [
            _log(
                f"strong-threshold-{index}",
                "192.0.2.108",
                seconds_ago=59 - index,
                method="POST",
                path="/api/v1/auth/login",
                status_code=401,
            )
            for index in range(60)
        ],
    )

    session = testing_session_factory()
    try:
        response = analyze_traffic_for_bot_detection(
            db=session,
            scoring_config=BotScoringConfig(brute_force_override_enabled=False),
        )
    finally:
        session.close()

    result = response.results[0]
    assert result.bot_risk_score >= 50.0
    assert result.classification == BotClassification.AUTOMATION_SUSPICIOUS
    assert "SCORE_THRESHOLD_WITH_STRONG_EVIDENCE" in _reason_codes(result)
    assert "BRUTE_FORCE_OVERRIDE" not in _reason_codes(result)
    assert "SCORE_THRESHOLD_WITH_STRONG_EVIDENCE" in result.summary
    assert "override disabled" in result.summary
    assert "BRUTE_FORCE_OVERRIDE" not in result.summary


def test_original_request_ids_are_never_emitted_and_opaque_refs_are_stable(
    testing_session_factory,
):
    originals = [
        "api_key:secret",
        "Bearer abc123",
        "password.secret",
        "123e4567-e89b-12d3-a456-426614174000",
    ]
    _seed(
        testing_session_factory,
        [
            _log(
                original,
                "192.0.2.200",
                seconds_ago=300 - index * 30,
                method="POST",
                path="/api/v1/auth/login",
                status_code=401,
            )
            for index, original in enumerate(originals)
        ],
    )

    config = BotScoringConfig(authentication_failure_threshold=1)
    session = testing_session_factory()
    try:
        first = analyze_traffic_for_bot_detection(db=session, scoring_config=config)
        second = analyze_traffic_for_bot_detection(db=session, scoring_config=config)
    finally:
        session.close()

    first_body = first.model_dump_json()
    for original in originals:
        assert original not in first_body
        assert original.lower() not in first_body.lower()

    def _emitted(response):
        return [
            request_id
            for result in response.results
            for reason in result.reasons
            if reason.code == "AUTHENTICATION_FAILURE_VOLUME"
            for request_id in reason.request_ids
        ]

    emitted = _emitted(first)
    assert len(emitted) == len(originals)
    assert len(set(emitted)) == len(originals)
    assert all(OPAQUE_REQUEST_ID_RE.fullmatch(value) for value in emitted)
    assert _emitted(second) == emitted


def test_behavioral_context_does_not_change_bot_score(testing_session_factory):
    _seed(
        testing_session_factory,
        [
            _log(
                f"independent-{index}",
                "192.0.2.201",
                seconds_ago=59 - index,
                path="/api/v1/orders" if index % 5 else f"/api/v1/orders/{index}",
                method="POST" if index % 10 == 0 else "GET",
                user_agent=f"Client/{index % 3}",
            )
            for index in range(60)
        ],
    )

    session = testing_session_factory()
    try:
        without_context = analyze_traffic_for_bot_detection(db=session)
        with_context = analyze_traffic_for_bot_detection(
            db=session, include_behavioral_risk=True
        )
    finally:
        session.close()

    plain = without_context.results[0]
    contextual = with_context.results[0]

    assert plain.behavioral_risk is None
    assert contextual.behavioral_risk is not None
    assert contextual.behavioral_risk.risk_score is not None
    assert without_context.total_events_analyzed == with_context.total_events_analyzed
    assert plain.bot_risk_score == contextual.bot_risk_score
    assert plain.classification == contextual.classification
    assert [factor.model_dump() for factor in plain.score_factors] == [
        factor.model_dump() for factor in contextual.score_factors
    ]
    assert _reason_codes(plain) == _reason_codes(contextual)


# --- F01 regression: grouped brute-force evidence must never be human_like ----
# BEFORE: with brute_force_override_enabled=False and a score below the
# suspicious threshold, the classification ladder fell through to
# AUTOMATION_BENIGN_CANDIDATE / HUMAN_LIKE. The confirmed case produced
# HUMAN_LIKE with reason code REPEATED_AUTHENTICATION_FAILURES; mitigation then
# reported ALLOW + HUMAN_LIKE_NO_ACTION + NO_SUSPICIOUS_EVIDENCE.
# AFTER: grouped brute-force evidence is never human_like. When it is not strong
# enough for automation_suspicious (override disabled and score below threshold)
# it is conservatively classified as UNKNOWN. The override keeps its original
# meaning: enabled still yields automation_suspicious; disabled still yields no
# BRUTE_FORCE_OVERRIDE reason and no override count. No blocking, banning,
# throttling, or enforcement is activated by this evidence-only change.


def test_f01_strong_brute_force_override_disabled_never_human_like(
    testing_session_factory,
):
    _seed(
        testing_session_factory,
        [
            _log(
                f"f01-off-{index}",
                "192.0.2.210",
                seconds_ago=300 - index * 30,
                method="POST",
                path="/api/v1/auth/login",
                status_code=401,
            )
            for index in range(6)
        ],
    )

    session = testing_session_factory()
    try:
        response = analyze_traffic_for_bot_detection(
            db=session,
            scoring_config=BotScoringConfig(brute_force_override_enabled=False),
        )
    finally:
        session.close()

    result = response.results[0]
    assert result.bot_risk_score < 50.0
    assert "REPEATED_AUTHENTICATION_FAILURES" in _reason_codes(result)
    assert result.classification == BotClassification.UNKNOWN
    assert result.classification != BotClassification.HUMAN_LIKE
    assert result.classification != BotClassification.AUTOMATION_SUSPICIOUS
    assert "BRUTE_FORCE_OVERRIDE" not in _reason_codes(result)
    assert "rather than human_like" in result.summary
    assert "override is disabled" in result.summary
    assert response.summary.brute_force_override_count == 0


@pytest.mark.parametrize(
    ("failure_count", "expected_classification"),
    [
        (6, BotClassification.UNKNOWN),
        (60, BotClassification.AUTOMATION_SUSPICIOUS),
    ],
)
def test_f01_strong_brute_force_evidence_is_never_human_like_across_scores(
    testing_session_factory, failure_count, expected_classification
):
    _seed(
        testing_session_factory,
        [
            _log(
                f"f01-band-{failure_count}-{index}",
                "192.0.2.211",
                seconds_ago=max(1, failure_count - index),
                method="POST",
                path="/api/v1/auth/login",
                status_code=401,
            )
            for index in range(failure_count)
        ],
    )

    session = testing_session_factory()
    try:
        response = analyze_traffic_for_bot_detection(
            db=session,
            scoring_config=BotScoringConfig(brute_force_override_enabled=False),
        )
    finally:
        session.close()

    result = response.results[0]
    assert "REPEATED_AUTHENTICATION_FAILURES" in _reason_codes(result)
    assert result.classification == expected_classification
    assert result.classification != BotClassification.HUMAN_LIKE
    assert "BRUTE_FORCE_OVERRIDE" not in _reason_codes(result)
    assert response.summary.brute_force_override_count == 0


def test_f01_weak_only_signals_keep_existing_safeguards(testing_session_factory):
    _seed(
        testing_session_factory,
        [
            _log(
                f"f01-weak-{index}",
                "192.0.2.212",
                seconds_ago=59 - index,
                path="/api/v1/orders" if index % 10 else f"/api/v1/orders/{index}",
                method="POST" if index % 10 == 0 else "GET",
                user_agent=f"Client/{index % 3}",
            )
            for index in range(60)
        ],
    )

    session = testing_session_factory()
    try:
        response = analyze_traffic_for_bot_detection(
            db=session,
            scoring_config=BotScoringConfig(suspicious_score_threshold=10.0),
        )
    finally:
        session.close()

    result = response.results[0]
    assert result.bot_risk_score >= 10.0
    # No grouped brute-force evidence: the conservative UNKNOWN branch must not
    # capture ordinary weak-signal traffic.
    assert result.classification == BotClassification.AUTOMATION_BENIGN_CANDIDATE
    assert result.classification != BotClassification.AUTOMATION_SUSPICIOUS
    assert "REPEATED_AUTHENTICATION_FAILURES" not in _reason_codes(result)
    assert "BRUTE_FORCE_OVERRIDE" not in _reason_codes(result)
    assert "No strong suspicious evidence" in result.summary
