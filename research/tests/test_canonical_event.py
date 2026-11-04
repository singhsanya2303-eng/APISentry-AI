from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from research.preprocessing.api_traffic import anonymize_principal
from research.schemas.canonical_event import CanonicalEvent


def make_event(**overrides):
    data = {
        "event_id": "event-1",
        "timestamp": datetime(2026, 1, 1, tzinfo=timezone.utc),
        "principal_id": anonymize_principal("user", secret=bytes(range(32))),
        "session_id": "session-1",
        "campaign_id": "campaign-1",
        "method": "get",
        "endpoint_template": "/api/items/{id}",
        "status_code": 200,
        "latency_ms": 12.5,
        "request_size_bytes": 10,
        "response_size_bytes": 20,
        "label": "normal",
        "source_dataset": "test",
    }
    data.update(overrides)
    return CanonicalEvent(**data)


def test_valid_event_normalizes_safe_fields():
    event = make_event()
    assert event.method == "GET"
    assert event.timestamp.tzinfo is not None


@pytest.mark.parametrize(
    "overrides",
    [
        {"event_id": ""},
        {"principal_id": "   "},
        {"session_id": "   "},
        {"campaign_id": "   "},
        {"source_dataset": "   "},
        {"timestamp": "not-a-timestamp"},
        {"timestamp": datetime(2026, 1, 1)},
        {"label": "unknown"},
        {"status_code": 700},
        {"endpoint_template": "items"},
    ],
)
def test_invalid_event_is_rejected(overrides):
    with pytest.raises(ValidationError):
        make_event(**overrides)


def test_extra_sensitive_fields_are_rejected():
    with pytest.raises(ValidationError):
        make_event(authorization="secret")


@pytest.mark.parametrize("field", ["event_id", "session_id", "campaign_id"])
def test_null_identifiers_are_rejected(field):
    with pytest.raises(ValidationError):
        make_event(**{field: None})


def test_non_anonymized_principal_is_rejected():
    with pytest.raises(ValidationError, match="TrustedPrincipalId"):
        make_event(principal_id="real-user-id")


def test_fake_principal_format_is_rejected():
    with pytest.raises(ValidationError):
        make_event(principal_id="principal_fake")


def test_label_and_attack_category_must_be_consistent():
    with pytest.raises(ValidationError):
        make_event(label="normal", attack_category="bola_idor")
    with pytest.raises(ValidationError):
        make_event(label="attack", attack_category=None)
