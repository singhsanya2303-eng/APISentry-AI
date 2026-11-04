from datetime import datetime, timezone

import pytest

from research.capture.models import EventLabel, ExperimentAction
from research.capture.runners import (
    execute_http_request,
    event_id_for_action,
    execute_playwright_navigation,
)
from research.capture.target_validation import validate_target_origin


class FakeRequest:
    extensions = {}
    headers = {"Content-Length": "12"}


class FakeResponse:
    status_code = 403
    headers = {"Content-Length": "4"}
    request = FakeRequest()


class FakeClient:
    def __init__(self, response):
        self.response = response
        self.kwargs = None

    def request(self, method, url, **kwargs):
        self.kwargs = kwargs
        return self.response


def test_http_runner_disables_redirects_and_returns_metadata(monkeypatch):
    monkeypatch.setattr(
        "research.capture.target_validation._resolve",
        lambda hostname: frozenset({"127.0.0.1"}),
    )
    origin = validate_target_origin("http://127.0.0.1:8888")
    action = ExperimentAction(
        action_id="attack",
        campaign_id="c",
        principal_id="attacker",
        session_id="s",
        label=EventLabel.ATTACK,
        attack_category="bola_idor",
        expected_outcome="access denied",
        execution_timestamp=datetime.now(timezone.utc),
    )
    client = FakeClient(FakeResponse())
    observation = execute_http_request(
        client=client,
        origin=origin,
        action=action,
        event_id="e1",
        method="GET",
        path="/vehicles/1",
    )
    assert client.kwargs["follow_redirects"] is False
    assert observation.status_code == 403
    assert observation.request_body is None
    assert observation.response_body is None


def test_http_runner_rejects_external_redirect(monkeypatch):
    monkeypatch.setattr(
        "research.capture.target_validation._resolve",
        lambda hostname: frozenset({"127.0.0.1"}),
    )
    origin = validate_target_origin("http://127.0.0.1:8888")
    response = FakeResponse()
    response.headers = {"Location": "https://example.com/out"}
    client = FakeClient(response)
    action = ExperimentAction(
        action_id="a",
        campaign_id="c",
        principal_id="p",
        session_id="s",
        label=EventLabel.NORMAL,
        expected_outcome="done",
    )
    with pytest.raises(ValueError, match="approved"):
        execute_http_request(
            client=client,
            origin=origin,
            action=action,
            event_id="e",
            method="GET",
            path="/",
        )


def test_action_event_ids_are_stable():
    assert event_id_for_action("login", 0) == event_id_for_action("login", 0)
    assert event_id_for_action("login", 0) != event_id_for_action("login", 1)


class FakePlaywrightRequest:
    def all_headers(self):
        return {"Content-Length": "2"}


class FakePlaywrightResponse:
    status = 200
    request = FakePlaywrightRequest()

    def header_value(self, name):
        return None

    def all_headers(self):
        return {"Content-Length": "3"}


class FakePage:
    def __init__(self):
        self.handlers = []

    def on(self, name, handler):
        self.handlers.append((name, handler))

    def goto(self, url, wait_until, timeout):
        assert wait_until == "domcontentloaded"
        return FakePlaywrightResponse()


def test_playwright_navigation_has_aware_timestamp_and_no_body(monkeypatch):
    monkeypatch.setattr(
        "research.capture.target_validation._resolve",
        lambda hostname: frozenset({"127.0.0.1"}),
    )
    origin = validate_target_origin("http://127.0.0.1:8888")
    current = ExperimentAction(
        action_id="browse",
        campaign_id="c",
        principal_id="p",
        session_id="s",
        label=EventLabel.NORMAL,
        expected_outcome="page loads",
    )
    observation = execute_playwright_navigation(
        page=FakePage(),
        origin=origin,
        action=current,
        event_id="e",
        path="/",
    )
    assert observation.timestamp.tzinfo is not None
    assert observation.request_body is None
    assert observation.response_body is None
