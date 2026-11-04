from research.capture.action_mapping import (
    RequestClassification,
    classify_request,
    correlate_request,
)
from research.capture.models import EventLabel, ExperimentAction


def make_action():
    return ExperimentAction(
        action_id="browse",
        campaign_id="campaign",
        principal_id="principal",
        session_id="session",
        label=EventLabel.NORMAL,
        expected_outcome="success",
    )


def test_multiple_primary_requests_can_correlate_to_same_action():
    action = make_action()
    for event_id in ("e1", "e2"):
        mapped, diagnostic = correlate_request(
            event_id=event_id,
            classification=RequestClassification.PRIMARY_API,
            action=action,
        )
        assert mapped is not None
        assert mapped.action.action_id == "browse"
        assert diagnostic is None


def test_unrelated_and_ambiguous_requests_are_excluded_with_diagnostics():
    action = make_action()
    for classification in (
        RequestClassification.UNRELATED,
        RequestClassification.AMBIGUOUS,
    ):
        mapped, diagnostic = correlate_request(
            event_id="excluded",
            classification=classification,
            action=action,
        )
        assert mapped is None
        assert diagnostic is not None
        assert diagnostic.classification is classification


def test_request_classification_does_not_infer_labels():
    assert classify_request(
        method="GET",
        url="http://127.0.0.1:8888/assets/app.js",
        resource_type="script",
        approved_api_prefixes=("/api/",),
    ) is RequestClassification.STATIC_ASSET
    assert classify_request(
        method="OPTIONS",
        url="http://127.0.0.1:8888/api/items",
    ) is RequestClassification.PREFLIGHT
    assert classify_request(
        method="GET",
        url="http://127.0.0.1:8888/api/items",
        resource_type="fetch",
    ) is RequestClassification.AMBIGUOUS
