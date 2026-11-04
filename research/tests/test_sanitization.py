from datetime import datetime, timezone

import pytest

from research.capture.models import CaptureKind, EventLabel, ExperimentAction
from research.capture.runners import RequestObservation
from research.capture.sanitize import sanitize_observation, to_canonical_event


def make_observation(**overrides):
    action = ExperimentAction(
        action_id="bola",
        campaign_id="campaign-1",
        principal_id="victim-account",
        session_id="session-1",
        label=EventLabel.ATTACK,
        attack_category="bola_idor",
        expected_outcome="access denied",
    )
    values = {
        "action": action,
        "capture_kind": CaptureKind.PRIMARY,
        "event_id": "event-1",
        "timestamp": datetime(2026, 1, 1, tzinfo=timezone.utc),
        "method": "GET",
        "url": "http://127.0.0.1:8888/items/42?token=secret&limit=10",
        "status_code": 403,
        "latency_ms": 4.5,
        "request_headers": {
            "Authorization": "Bearer secret",
            "Content-Length": "17",
            "Cookie": "session=secret",
        },
        "response_headers": {"Content-Length": "3", "Set-Cookie": "secret"},
        "request_body": None,
        "response_body": None,
    }
    values.update(overrides)
    return RequestObservation(**values)


def test_sanitization_removes_sensitive_url_and_headers():
    capture = sanitize_observation(make_observation(), actual_outcome="denied")
    assert capture.url == "/items/42"
    assert "secret" not in repr(capture)
    assert capture.safe_query_parameter_categories == ["pagination"]
    assert capture.request_size_bytes == 17
    assert capture.response_size_bytes == 3


def test_raw_bodies_are_rejected_before_persistence():
    with pytest.raises(ValueError, match="raw bodies"):
        sanitize_observation(make_observation(request_body=b"password"), actual_outcome="denied")


def test_canonical_conversion_preserves_action_label_and_pseudonymizes():
    capture = sanitize_observation(make_observation(), actual_outcome="denied")
    event = to_canonical_event(
        capture,
        source_dataset="custom_crapi",
        principal_secret=bytes(range(32)),
    )
    assert event.label == "attack"
    assert event.attack_category == "bola_idor"
    assert str(event.principal_id).startswith("principal_")
