from datetime import datetime, timezone

import pytest

from research.capture.action_mapping import ActionMappingError, map_request_to_action
from research.capture.models import (
    ActionPhase,
    CaptureKind,
    ControlledAccountDefinition,
    CapturePolicy,
    EventLabel,
    ExperimentAction,
    ExperimentScenario,
    RequestMappingPolicy,
    ResourceOwnershipDeclaration,
)
from research.capture.target_validation import (
    TargetValidationError,
    validate_request_url,
    validate_target_origin,
)


def action(**overrides):
    values = {
        "action_id": "login",
        "campaign_id": "c1",
        "principal_id": "account-a",
        "session_id": "session-1",
        "label": EventLabel.NORMAL,
        "expected_outcome": "login succeeds",
        "execution_timestamp": datetime.now(timezone.utc),
    }
    values.update(overrides)
    return ExperimentAction(**values)


def test_action_labels_are_explicit():
    assert action().label is EventLabel.NORMAL
    with pytest.raises(ValueError, match="require an attack category"):
        action(label=EventLabel.ATTACK)


def test_campaign_does_not_override_action_label():
    attack = action(
        action_id="bola",
        label=EventLabel.ATTACK,
        attack_category="bola_idor",
    )
    assert attack.label.value == "attack"
    assert action().label.value == "normal"


def test_capture_policy_drops_unselected_request_kinds():
    current = action(capture_policy=CapturePolicy(retain_redirects=False))
    assert map_request_to_action(
        action=current, capture_kind=CaptureKind.REDIRECT
    ) is None


def test_unmapped_non_background_request_is_rejected():
    with pytest.raises(ActionMappingError, match="unambiguous"):
        map_request_to_action(action=None, capture_kind=CaptureKind.PRIMARY)


def test_loopback_origin_and_exact_request_are_allowed(monkeypatch):
    monkeypatch.setattr(
        "research.capture.target_validation._resolve",
        lambda hostname: frozenset({"127.0.0.1"}),
    )
    origin = validate_target_origin("http://127.0.0.1:8888")
    validate_request_url("http://127.0.0.1:8888/api", origin)


def test_non_loopback_resolution_is_rejected(monkeypatch):
    monkeypatch.setattr(
        "research.capture.target_validation._resolve",
        lambda hostname: frozenset({"203.0.113.10"}),
    )
    with pytest.raises(TargetValidationError, match="loopback"):
        validate_target_origin("http://example.test:8888")


def test_origin_mismatch_is_rejected(monkeypatch):
    monkeypatch.setattr(
        "research.capture.target_validation._resolve",
        lambda hostname: frozenset({"127.0.0.1"}),
    )
    origin = validate_target_origin("http://127.0.0.1:8888")
    with pytest.raises(TargetValidationError, match="approved origin"):
        validate_request_url("http://127.0.0.1:8889/api", origin)


def test_scenario_rejects_mixed_campaign_actions():
    with pytest.raises(ValueError, match="scenario campaign"):
        ExperimentScenario(
            scenario_id="s",
            campaign_id="c1",
            source_dataset="custom_crapi",
            target_origin="http://127.0.0.1:8888",
            crapi_commit="commit",
            capture_tool="test",
            capture_tool_version="1",
            actions=[action(campaign_id="c2")],
        )


def test_versioned_scenario_requires_valid_setup_and_cleanup_phases():
    setup_action = action(
        action_id="register",
        phase=ActionPhase.SETUP,
    )
    cleanup_action = action(
        action_id="logout",
        phase=ActionPhase.CLEANUP,
    )
    scenario = ExperimentScenario(
        scenario_id="scenario-1",
        scenario_version="1.0",
        campaign_id="c1",
        source_dataset="custom_crapi",
        target_origin="http://127.0.0.1:8888",
        crapi_commit="commit",
        capture_tool="test",
        capture_tool_version="1",
        controlled_accounts=[
            ControlledAccountDefinition(
                account_id="account-a",
                principal_id="principal-a",
                role="user",
            )
        ],
        resource_ownership=[
            ResourceOwnershipDeclaration(
                resource_id="vehicle-a",
                owner_account_id="account-a",
                resource_type="vehicle",
            )
        ],
        setup_actions=[setup_action],
        actions=[action()],
        cleanup_actions=[cleanup_action],
        success_conditions=["all expected outcomes observed"],
        failure_conditions=["target leaves local origin"],
    )
    assert scenario.scenario_version == "1.0"


def test_attack_campaign_setup_remains_normal():
    setup_action = action(
        action_id="authenticate",
        phase=ActionPhase.SETUP,
        label=EventLabel.NORMAL,
    )
    attack_action = action(
        action_id="attack",
        label=EventLabel.ATTACK,
        attack_category="bola_idor",
    )
    scenario = ExperimentScenario(
        scenario_id="bola",
        campaign_id="c1",
        source_dataset="custom_crapi",
        target_origin="http://127.0.0.1:8888",
        crapi_commit="commit",
        capture_tool="test",
        capture_tool_version="1",
        setup_actions=[setup_action],
        actions=[attack_action],
    )
    assert scenario.setup_actions[0].label is EventLabel.NORMAL
    assert scenario.actions[0].label is EventLabel.ATTACK


def test_invalid_resource_owner_is_rejected():
    with pytest.raises(ValueError, match="controlled account"):
        ExperimentScenario(
            scenario_id="s",
            campaign_id="c1",
            source_dataset="custom_crapi",
            target_origin="http://127.0.0.1:8888",
            crapi_commit="commit",
            capture_tool="test",
            capture_tool_version="1",
            controlled_accounts=[],
            resource_ownership=[
                ResourceOwnershipDeclaration(
                    resource_id="r",
                    owner_account_id="missing",
                    resource_type="vehicle",
                )
            ],
            actions=[action(mapping_policy=RequestMappingPolicy())],
        )
