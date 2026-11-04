from pathlib import Path
from datetime import datetime, timezone

import pytest

from research.capture import cli
from research.capture import runners
from research.capture.models import CaptureKind
from research.capture.runners import RequestObservation
from research.capture.sanitize import sanitize_observation
from research.capture.target_validation import ApprovedOrigin
from research.datasets.writer import write_events


def test_dry_run_does_not_construct_http_client(monkeypatch, capsys):
    def fail_if_constructed(*args, **kwargs):
        raise AssertionError("dry-run constructed an HTTP client")

    monkeypatch.setattr(cli.httpx, "Client", fail_if_constructed)
    result = cli.main(
        [
            "dry-run",
            "--scenario-dir",
            str(Path(__file__).parents[1] / "scenarios"),
            "--scenario",
            "normal_user_baseline_001",
        ]
    )
    assert result == 0
    output = capsys.readouterr().out
    assert "baseline_register" in output
    assert "baseline_cleanup" in output


def test_dry_run_matches_exact_execution_plan_and_cli_output(capsys):
    scenario = cli.load_scenario(
        Path(__file__).parents[1] / "scenarios" / "normal_user_baseline_001.yaml"
    )
    expected_plan = [
        "setup: baseline_register POST /identity/api/auth/signup x1 label=normal",
        "setup: baseline_login POST /identity/api/auth/login x1 label=normal",
        "execution: baseline_dashboard GET /identity/api/v2/user/dashboard x1 label=normal",
        "execution: baseline_vehicles GET /identity/api/v2/vehicle/vehicles x1 label=normal",
        "execution: baseline_recent_posts GET /community/api/v2/community/posts/recent x1 label=normal",
        "execution: baseline_products GET /workshop/api/shop/products x1 label=normal",
        "cleanup: baseline_cleanup (operator cleanup)",
    ]
    assert cli.build_execution_plan(scenario) == expected_plan

    assert cli.main(["dry-run", "--scenario", scenario.scenario_id]) == 0
    output = capsys.readouterr().out
    assert output == (
        "normal_user_baseline_001: valid\n"
        + "\n".join(expected_plan)
        + "\n"
    )


def test_runtime_credentials_and_login_token_are_in_memory():
    scenario = cli.load_scenario(
        Path(__file__).parents[1] / "scenarios" / "normal_user_baseline_001.yaml"
    )
    accounts = cli._runtime_accounts(scenario)
    account = accounts["baseline_user"]
    assert account["email"].endswith("@example.invalid")
    assert account["password"]
    tokens = {}
    cli._token_inspector(tokens, "baseline_user")(b'{"token":"jwt-in-memory"}')
    assert tokens == {"baseline_user": "jwt-in-memory"}
    assert "jwt-in-memory" not in repr(cli.ExecutionDiagnostics())
    accounts.clear()
    tokens.clear()


def _baseline_observation(action, status_code=200, request_headers=None):
    return RequestObservation(
        action=action,
        capture_kind=CaptureKind.PRIMARY,
        event_id=cli.event_id_for_action(action.action_id, 0),
        timestamp=datetime.now(timezone.utc),
        method=str(action.execution["method"]),
        url="http://127.0.0.1:8888" + str(action.execution["path"]),
        status_code=status_code,
        latency_ms=1,
        request_headers=request_headers or {},
        response_headers={"content-length": "2"},
        request_body=None,
        response_body=None,
    )


def test_normal_baseline_registration_login_and_authenticated_requests(
    monkeypatch,
):
    scenario = cli.load_scenario(
        Path(__file__).parents[1] / "scenarios" / "normal_user_baseline_001.yaml"
    )
    requests = []
    observations = []

    class ClosedClient:
        def __init__(self, **kwargs):
            pass

        def close(self):
            pass

    def fake_request(**kwargs):
        action = kwargs["action"]
        requests.append((action.action_id, kwargs["headers"].copy()))
        inspector = kwargs["response_inspector"]
        if inspector is not None:
            inspector(b'{"token":"validated-jwt"}' if action.action_id == "baseline_login" else b"{}")
        observation = _baseline_observation(
            action,
            request_headers=kwargs["headers"],
        )
        observations.append(observation)
        return observation

    monkeypatch.setattr(cli.httpx, "Client", ClosedClient)
    monkeypatch.setattr(cli, "execute_http_request", fake_request)
    diagnostics = cli.execute_scenario(
        scenario,
        origin=ApprovedOrigin("http", "127.0.0.1", 8888, frozenset({"127.0.0.1"})),
        principal_secret="x" * 31 + "y",
        max_requests=20,
    )

    assert len(diagnostics.events) == 6
    assert [item[0] for item in requests] == [
        "baseline_register",
        "baseline_login",
        "baseline_dashboard",
        "baseline_vehicles",
        "baseline_recent_posts",
        "baseline_products",
    ]
    assert all(
        headers["Authorization"] == "Bearer validated-jwt"
        for _, headers in requests[2:]
    )
    sanitized = sanitize_observation(
        observations[2],
        actual_outcome="observed_status_200",
    )
    assert "Authorization" not in repr(sanitized)
    assert "validated-jwt" not in repr(sanitized)
    for event in diagnostics.events:
        serialized_event = repr(event.model_dump())
        assert "Authorization" not in serialized_event
        assert "validated-jwt" not in serialized_event
    output = Path(__file__).parent / "test-output-events.jsonl"
    try:
        write_events(diagnostics.events, output)
        serialized = output.read_text(encoding="utf-8")
        assert "Authorization" not in serialized
        assert "validated-jwt" not in serialized
    finally:
        if output.exists():
            output.unlink()


def test_registration_failure_stops_before_login(monkeypatch):
    scenario = cli.load_scenario(
        Path(__file__).parents[1] / "scenarios" / "normal_user_baseline_001.yaml"
    )
    calls = []

    class ClosedClient:
        def __init__(self, **kwargs):
            pass

        def close(self):
            pass

    def fake_request(**kwargs):
        calls.append(kwargs["action"].action_id)
        return _baseline_observation(kwargs["action"], status_code=403)

    monkeypatch.setattr(cli.httpx, "Client", ClosedClient)
    monkeypatch.setattr(cli, "execute_http_request", fake_request)
    diagnostics = cli.ExecutionDiagnostics()
    with pytest.raises(RuntimeError, match="scenario execution failed"):
        cli.execute_scenario(
            scenario,
            origin=ApprovedOrigin("http", "127.0.0.1", 8888, frozenset({"127.0.0.1"})),
            principal_secret="x" * 31 + "y",
            max_requests=20,
            diagnostics=diagnostics,
        )
    assert calls == ["baseline_register"]
    assert diagnostics.events == []
    assert diagnostics.cleanup_pending == ["baseline_cleanup"]


@pytest.mark.parametrize(
    "token_payload",
    [
        "{}",
        '{"token":null}',
        '{"token":""}',
        '{"token":"   "}',
        '{"token":123}',
        "not-json",
    ],
)
def test_invalid_login_token_stops_before_authenticated_requests(
    monkeypatch, token_payload
):
    scenario = cli.load_scenario(
        Path(__file__).parents[1] / "scenarios" / "normal_user_baseline_001.yaml"
    )
    calls = []

    class ClosedClient:
        def __init__(self, **kwargs):
            pass

        def close(self):
            pass

    def fake_request(**kwargs):
        action = kwargs["action"]
        calls.append((action.action_id, kwargs["headers"]))
        inspector = kwargs["response_inspector"]
        if action.action_id == "baseline_login":
            inspector(token_payload.encode())
        return _baseline_observation(action)

    monkeypatch.setattr(cli.httpx, "Client", ClosedClient)
    monkeypatch.setattr(cli, "execute_http_request", fake_request)
    diagnostics = cli.ExecutionDiagnostics()
    with pytest.raises(RuntimeError, match="scenario execution failed"):
        cli.execute_scenario(
            scenario,
            origin=ApprovedOrigin("http", "127.0.0.1", 8888, frozenset({"127.0.0.1"})),
            principal_secret="x" * 31 + "y",
            max_requests=20,
            diagnostics=diagnostics,
        )
    assert [item[0] for item in calls] == ["baseline_register", "baseline_login"]
    assert len(diagnostics.events) == 1
    assert all("validated-jwt" not in repr(item) for item in diagnostics.__dict__.values())


def test_action_request_count_enforces_per_action_bound():
    scenario = cli.load_scenario(
        Path(__file__).parents[1] / "scenarios" / "normal_user_baseline_001.yaml"
    )
    api_actions = [
        action
        for action in cli.ordered_actions(scenario)
        if action.execution.get("method") != "NONE"
    ]
    assert sum(cli.action_request_count(action) for action in api_actions) == 6
    with pytest.raises(ValueError, match="exceeds request bound"):
        cli.action_request_count(
            scenario.actions[0].model_copy(
                update={"execution": {"request_count": 21}}
            )
        )


def test_execution_requires_explicit_flag():
    try:
        cli.main(["run", "--scenario", "normal_user_baseline_001"])
    except SystemExit as exc:
        assert "--execute" in str(exc)
    else:
        raise AssertionError("run unexpectedly proceeded without --execute")


def test_validate_and_dry_run_all_scenarios_are_side_effect_free(
    monkeypatch, capsys, tmp_path: Path
):
    scenario_dir = Path(__file__).parents[1] / "scenarios"
    scenario_ids = {
        scenario.scenario_id for scenario in cli.load_scenarios(scenario_dir)
    }

    def fail_if_network(*args, **kwargs):
        raise AssertionError("validation or dry-run performed network activity")

    monkeypatch.setattr(cli.httpx, "Client", fail_if_network)
    monkeypatch.setattr(
        runners,
        "execute_playwright_navigation",
        fail_if_network,
    )
    monkeypatch.setattr(
        cli,
        "_runtime_accounts",
        lambda scenario: (_ for _ in ()).throw(
            AssertionError("dry-run generated credentials")
        ),
    )

    for command in ("validate", "dry-run"):
        assert cli.main([command, "--scenario-dir", str(scenario_dir)]) == 0

    output = capsys.readouterr().out
    assert scenario_ids == {
        line.split(":", 1)[0]
        for line in output.splitlines()
        if line.endswith(": valid")
    }
    assert not list(tmp_path.iterdir())


def test_bola_echoed_resource_id_without_protected_data_is_inconclusive():
    outcome = {"value": "unset"}
    cli._bola_outcome_inspector(outcome, "vehicle-1")(
        b'{"vehicleId":"vehicle-1"}'
    )
    assert outcome["value"] == "inconclusive"


def test_bola_matching_resource_with_protected_data_is_confirmed():
    outcome = {"value": "unset"}
    cli._bola_outcome_inspector(outcome, "vehicle-1")(
        b'{"vehicleId":"vehicle-1","latitude":12.3,"longitude":45.6}'
    )
    assert outcome["value"] == "confirmed_access"


def test_bola_resource_discovery_requires_explicit_owner_evidence():
    discovered = {}
    cli._vehicle_inspector(discovered, "bola_victim")(
        b'{"vehicles":[{"vehicleId":"vehicle-1"}]}'
    )
    assert discovered == {}


def test_failed_execution_reports_cleanup_accounts_without_secrets(monkeypatch):
    scenario = cli.load_scenario(
        Path(__file__).parents[1] / "scenarios" / "bola_idor_001.yaml"
    )
    diagnostics = cli.ExecutionDiagnostics()

    class ClosedClient:
        def __init__(self, **kwargs):
            pass

        def close(self):
            pass

    monkeypatch.setattr(cli.httpx, "Client", ClosedClient)
    monkeypatch.setattr(
        cli,
        "execute_http_request",
        lambda **kwargs: (_ for _ in ()).throw(RuntimeError("controlled failure")),
    )
    origin = ApprovedOrigin("http", "127.0.0.1", 8888, frozenset({"127.0.0.1"}))

    with pytest.raises(RuntimeError, match="scenario execution failed"):
        cli.execute_scenario(
            scenario,
            origin=origin,
            principal_secret="x" * 31 + "y",
            max_requests=20,
            diagnostics=diagnostics,
        )

    assert {item["account_id"] for item in diagnostics.cleanup_accounts} == {
        "bola_attacker",
        "bola_victim",
    }
    assert all("password" not in item and "token" not in item for item in diagnostics.cleanup_accounts)
    assert diagnostics.cleanup_pending == ["bola_cleanup"]
    assert diagnostics.failures == [
        "bola_idor_001: action=bola_register_attacker "
        "failure=RuntimeError root_cause=RuntimeError"
    ]
