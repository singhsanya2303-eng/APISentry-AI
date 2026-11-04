import re
from pathlib import Path

import pytest

from research.capture.models import ActionPhase, EventLabel
from research.scenarios.loader import load_scenario, load_scenarios


SCENARIOS = Path(__file__).parents[1] / "scenarios"
EXPECTED = {
    "normal_user_baseline_001.yaml",
    "bola_idor_001.yaml",
    "bruteforce_attack_001.yaml",
    "rate_abuse_001.yaml",
    "payload_attack_001.yaml",
}


def test_all_scenario_yaml_files_load_against_contracts():
    assert {path.name for path in SCENARIOS.glob("*.yaml")} == EXPECTED
    scenarios = load_scenarios(SCENARIOS)
    assert len(scenarios) == len(EXPECTED)
    assert all(item.target_origin == "http://127.0.0.1:8888" for item in scenarios)


def test_scenario_and_action_ids_are_unique():
    scenarios = load_scenarios(SCENARIOS)
    assert len({scenario.scenario_id for scenario in scenarios}) == len(scenarios)
    for scenario in scenarios:
        actions = [
            *scenario.setup_actions,
            *scenario.actions,
            *scenario.cleanup_actions,
        ]
        assert len({action.action_id for action in actions}) == len(actions)
        assert all(action.campaign_id == scenario.campaign_id for action in actions)


def test_setup_and_cleanup_actions_have_normal_labels():
    for scenario in load_scenarios(SCENARIOS):
        assert all(
            action.label is EventLabel.NORMAL
            for action in [*scenario.setup_actions, *scenario.cleanup_actions]
        )
        assert all(
            action.phase is ActionPhase.SETUP for action in scenario.setup_actions
        )
        assert all(
            action.phase is ActionPhase.CLEANUP for action in scenario.cleanup_actions
        )


def test_yaml_has_no_credentials_or_secret_values():
    forbidden_value_patterns = (
        re.compile(r"bearer\s+[A-Za-z0-9._-]{12,}", re.IGNORECASE),
        re.compile(r"AKIA[0-9A-Z]{16}"),
        re.compile(r"password\s*:\s*[^$\n]+", re.IGNORECASE),
    )
    for path in SCENARIOS.glob("*.yaml"):
        text = path.read_text(encoding="utf-8")
        for pattern in forbidden_value_patterns:
            assert not pattern.search(text), path.name
        assert "credential_source: runtime_generated" in text


def test_bola_has_two_accounts_and_explicit_other_owner():
    scenario = load_scenario(SCENARIOS / "bola_idor_001.yaml")
    assert len(scenario.controlled_accounts) >= 2
    account_ids = {account.account_id for account in scenario.controlled_accounts}
    assert all(
        resource.owner_account_id in account_ids
        for resource in scenario.resource_ownership
    )
    attack = next(
        action for action in scenario.actions if action.label is EventLabel.ATTACK
    )
    assert attack.attack_category == "bola_idor"
    assert attack.execution["verification"]["status_only_insufficient"] is True


@pytest.mark.parametrize(
    "filename,category,max_count",
    [
        ("bruteforce_attack_001.yaml", "brute_force", 20),
        ("rate_abuse_001.yaml", "rate_abuse", 20),
    ],
)
def test_bounded_attack_parameters(filename, category, max_count):
    scenario = load_scenario(SCENARIOS / filename)
    action = next(item for item in scenario.actions if item.attack_category == category)
    assert 1 <= action.execution["request_count"] <= max_count
    assert action.execution["delay_ms"] >= 0


def test_each_http_action_has_verified_method_path_and_mapping_policy():
    for scenario in load_scenarios(SCENARIOS):
        actions = [*scenario.setup_actions, *scenario.actions]
        for action in actions:
            execution = action.execution
            assert execution["method"] in {"GET", "POST", "PUT", "DELETE"}
            assert str(execution["path"]).startswith("/")
            assert action.mapping_policy.retained_kinds


def test_cleanup_actions_are_explicit_operator_cleanup_steps():
    for scenario in load_scenarios(SCENARIOS):
        for action in scenario.cleanup_actions:
            assert action.execution["operation"] == "controlled_environment_cleanup"
            assert action.execution["authentication"] == "operator"
            assert action.execution["path"] is None
