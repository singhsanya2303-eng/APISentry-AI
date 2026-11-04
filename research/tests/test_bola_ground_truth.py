import pytest

from research.capture.bola import (
    AccessOutcome,
    BolaAccessCheck,
    BolaGroundTruth,
    ControlledAccount,
    ResourceOwnership,
    verify_bola_access,
)


def setup():
    return BolaGroundTruth(
        accounts=[
            ControlledAccount(account_id="attacker", principal_id="p-a"),
            ControlledAccount(account_id="victim", principal_id="p-v"),
        ],
        resources=[ResourceOwnership(resource_id="vehicle-1", owner_account_id="victim")],
    )


def test_bola_setup_tracks_two_accounts_and_resource_owner():
    ground_truth = setup()
    assert len(ground_truth.accounts) == 2
    assert ground_truth.resources[0].owner_account_id == "victim"


def test_status_code_alone_is_not_ground_truth():
    with pytest.raises(ValueError, match="status alone"):
        BolaAccessCheck(
            attacker_account_id="attacker",
            resource_id="vehicle-1",
            expected_outcome=AccessOutcome.DENIED,
            actual_outcome=AccessOutcome.DENIED,
            verification_method="status_code",
            status_code=403,
        )


def test_unknown_bola_outcome_is_rejected():
    with pytest.raises(ValueError, match="verified"):
        BolaAccessCheck(
            attacker_account_id="attacker",
            resource_id="vehicle-1",
            expected_outcome=AccessOutcome.DENIED,
            actual_outcome=AccessOutcome.UNKNOWN,
            verification_method="independent_resource_comparison",
            status_code=404,
        )


def test_bola_verification_requires_other_owner_and_returns_safe_result():
    result = verify_bola_access(
        ground_truth=setup(),
        attacker_account_id="attacker",
        resource_id="vehicle-1",
        status_code=403,
        response_body=b'{"private":"not persisted"}',
        semantic_verifier=lambda body: AccessOutcome.DENIED,
    )
    assert result.actual_outcome is AccessOutcome.DENIED
    assert result.verification_method == "in_memory_response_semantics"
    assert "private" not in repr(result)


def test_bola_verification_rejects_attacker_owned_resource():
    ground_truth = BolaGroundTruth(
        accounts=[
            ControlledAccount(account_id="attacker", principal_id="p-a"),
            ControlledAccount(account_id="victim", principal_id="p-v"),
        ],
        resources=[ResourceOwnership(resource_id="vehicle-1", owner_account_id="attacker")],
    )
    with pytest.raises(ValueError, match="another account"):
        verify_bola_access(
            ground_truth=ground_truth,
            attacker_account_id="attacker",
            resource_id="vehicle-1",
            status_code=200,
            response_body=b"{}",
            semantic_verifier=lambda body: AccessOutcome.ALLOWED,
        )
