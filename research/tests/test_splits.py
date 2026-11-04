from datetime import datetime, timedelta, timezone

import pytest

from research.schemas.canonical_event import CanonicalEvent
from research.preprocessing.api_traffic import anonymize_principal
from research.splits.create_splits import create_splits, validate_split_leakage


def event(index, *, session=None, campaign=None, principal=None):
    return CanonicalEvent(
        event_id=f"e-{index}",
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(days=index),
        principal_id=principal or anonymize_principal(
            f"user-{index}",
            secret=bytes(range(32)),
        ),
        session_id=session or f"s-{index}",
        campaign_id=campaign or f"c-{index}",
        method="GET",
        endpoint_template="/items",
        status_code=200,
        latency_ms=1,
        request_size_bytes=0,
        response_size_bytes=0,
        label="normal",
        source_dataset="test",
    )


def test_time_split_keeps_sessions_and_campaigns_together():
    splits = create_splits(
        [event(0, session="s-a", campaign="c-a"), event(1, session="s-a", campaign="c-a")]
        + [event(index) for index in range(2, 8)],
        strategy="time",
    )
    validate_split_leakage(splits)


def test_duplicate_event_ids_are_rejected():
    first = event(1)
    with pytest.raises(ValueError, match="duplicate event_id"):
        validate_split_leakage({"train": [first], "test": [first]})


def test_session_leakage_is_rejected():
    first = event(1, session="shared")
    second = event(2, session="shared")
    with pytest.raises(ValueError, match="session_id leakage"):
        validate_split_leakage({"train": [first], "test": [second]})


def test_campaign_disjoint_strategy():
    splits = create_splits(
        [event(index, campaign=f"campaign-{index // 2}") for index in range(8)],
        strategy="campaign",
    )
    validate_split_leakage(splits)


@pytest.mark.parametrize("count", [1, 2])
def test_insufficient_groups_are_rejected(count):
    with pytest.raises(ValueError, match="three independent groups"):
        create_splits([event(index) for index in range(count)], strategy="time")


def test_principal_leakage_is_rejected():
    shared_principal = anonymize_principal("shared", secret=bytes(range(32)))
    first = event(1, principal=shared_principal, session="s-1", campaign="c-1")
    second = event(2, principal=shared_principal, session="s-2", campaign="c-2")
    with pytest.raises(
        ValueError,
        match="principal_id leakage|session_id leakage|campaign_id leakage",
    ):
        validate_split_leakage(
            {"train": [first], "validation": [second], "test": [event(3)]},
            isolated_fields=("principal_id",),
        )


def test_principal_split_is_deterministic_and_disjoint():
    splits = create_splits(
        [
            event(index, principal=anonymize_principal(
                f"shared-{index // 2}",
                secret=bytes(range(32)),
            ))
            for index in range(6)
        ],
        strategy="principal",
    )
    assert set(splits) == {"train", "validation", "test"}
    principals = [
        {str(item.principal_id) for item in split_events}
        for split_events in splits.values()
    ]
    assert principals[0].isdisjoint(principals[1])
    assert principals[0].isdisjoint(principals[2])
    assert principals[1].isdisjoint(principals[2])


def test_random_group_split_is_reproducible_with_seed():
    events = [event(index) for index in range(9)]
    first = create_splits(events, strategy="random", seed=7)
    second = create_splits(events, strategy="random", seed=7)
    assert {
        name: [item.event_id for item in values]
        for name, values in first.items()
    } == {
        name: [item.event_id for item in values]
        for name, values in second.items()
    }


def test_transitive_session_campaign_grouping():
    events = [
        event(0, session="s-a", campaign="c-a"),
        event(1, session="s-b", campaign="c-a"),
        event(2, session="s-b", campaign="c-b"),
        event(3, session="s-c", campaign="c-c"),
        event(4, session="s-d", campaign="c-d"),
        event(5, session="s-e", campaign="c-e"),
    ]
    splits = create_splits(events, strategy="time")
    validate_split_leakage(splits)


def test_time_partitions_are_chronological():
    splits = create_splits([event(index) for index in range(6)], strategy="time")
    assert max(item.timestamp for item in splits["train"]) < min(
        item.timestamp for item in splits["validation"]
    )
    assert max(item.timestamp for item in splits["validation"]) < min(
        item.timestamp for item in splits["test"]
    )


def test_validation_data_cannot_extend_beyond_test_start():
    splits = {
        "train": [event(0)],
        "validation": [event(1), event(3)],
        "test": [event(2)],
    }
    with pytest.raises(ValueError, match="time partitions"):
        validate_split_leakage(splits, check_chronology=True)
