"""Create and validate time-, principal-, and campaign-disjoint splits."""

from collections import defaultdict
import random
from typing import Dict, Iterable, List, Literal, Sequence

from research.schemas.canonical_event import CanonicalEvent

SplitName = Literal["time", "principal", "campaign", "random"]


def _group_key(event: CanonicalEvent, strategy: SplitName) -> str:
    if strategy == "principal":
        return str(event.principal_id)
    if strategy == "campaign":
        return event.campaign_id
    return event.session_id


def _connected_groups(events: Sequence[CanonicalEvent]) -> list[list[CanonicalEvent]]:
    """Keep sessions and campaigns together when constructing time groups."""
    by_key: dict[str, list[int]] = defaultdict(list)
    for index, event in enumerate(events):
        by_key[event.session_id].append(index)
        by_key[event.campaign_id].append(index)

    visited: set[int] = set()
    groups: list[list[CanonicalEvent]] = []
    for start in range(len(events)):
        if start in visited:
            continue
        pending = [start]
        component: set[int] = set()
        while pending:
            index = pending.pop()
            if index in component:
                continue
            component.add(index)
            event = events[index]
            pending.extend(by_key[event.session_id])
            pending.extend(by_key[event.campaign_id])
        visited.update(component)
        groups.append([events[index] for index in sorted(component)])
    return groups


def _validate_unique_event_ids(events: Iterable[CanonicalEvent]) -> None:
    event_ids = [event.event_id for event in events]
    if len(event_ids) != len(set(event_ids)):
        raise ValueError("duplicate event_id detected")


def validate_split_leakage(
    splits: Dict[str, Sequence[CanonicalEvent]],
    *,
    isolated_fields: Sequence[str] = ("session_id", "campaign_id"),
    check_chronology: bool = False,
) -> None:
    """Reject duplicate IDs and session/campaign overlap across split boundaries."""
    all_events = [event for split in splits.values() for event in split]
    _validate_unique_event_ids(all_events)

    for field_name in isolated_fields:
        seen: dict[str, str] = {}
        for split_name, events in splits.items():
            for event in events:
                value = getattr(event, field_name)
                previous = seen.setdefault(value, split_name)
                if previous != split_name:
                    raise ValueError(f"{field_name} leakage across splits: {value}")

    if not check_chronology or not all(
        name in splits for name in ("train", "validation", "test")
    ):
        return

    ordered = [splits[name] for name in ("train", "validation", "test")]
    if any(not events for events in ordered):
        raise ValueError("each split must contain at least one event")
    if any(event.timestamp is None for events in ordered for event in events):
        raise ValueError("chronology validation requires timestamps")
    train_end = max(event.timestamp for event in ordered[0])
    validation_start = min(event.timestamp for event in ordered[1])
    validation_end = max(event.timestamp for event in ordered[1])
    test_start = min(event.timestamp for event in ordered[2])
    if not train_end < validation_start or not validation_end < test_start:
        raise ValueError(
            "time partitions must be ordered as train < validation < test"
        )


def create_splits(
    events: Sequence[CanonicalEvent],
    *,
    strategy: SplitName = "time",
    train_ratio: float = 0.7,
    validation_ratio: float = 0.15,
    seed: int | None = None,
) -> Dict[str, List[CanonicalEvent]]:
    """Split complete groups; random uses a reproducible seed."""
    if strategy not in {"time", "principal", "campaign", "random"}:
        raise ValueError("strategy must be time, principal, campaign, or random")
    if not 0 < train_ratio < 1 or not 0 < validation_ratio < 1:
        raise ValueError("split ratios must be between 0 and 1")
    if train_ratio + validation_ratio >= 1:
        raise ValueError("train and validation ratios must leave test data")
    if not events:
        raise ValueError("at least one event is required")

    _validate_unique_event_ids(events)
    groups = (
        _connected_groups(events)
        if strategy in {"time", "random"}
        else list(
            grouped
            for grouped in _group_events(events, strategy).values()
        )
    )
    if strategy == "time":
        groups.sort(key=lambda group: min(event.timestamp for event in group))
    elif strategy == "random":
        if seed is None:
            raise ValueError("random strategy requires an explicit seed")
        random.Random(seed).shuffle(groups)
    else:
        groups.sort(key=lambda group: _group_key(group[0], strategy))

    if len(groups) < 3:
        raise ValueError(
            "at least three independent groups are required for train, validation, and test"
        )

    train_end = max(1, int(len(groups) * train_ratio))
    validation_end = max(train_end + 1, int(len(groups) * (train_ratio + validation_ratio)))
    validation_end = min(validation_end, len(groups) - 1) if len(groups) > 2 else len(groups)

    splits = {
        "train": [event for group in groups[:train_end] for event in group],
        "validation": [event for group in groups[train_end:validation_end] for event in group],
        "test": [event for group in groups[validation_end:] for event in group],
    }
    isolated_fields = (
        ("principal_id", "session_id", "campaign_id")
        if strategy == "principal"
        else ("session_id", "campaign_id")
    )
    validate_split_leakage(
        splits,
        isolated_fields=isolated_fields,
        check_chronology=strategy == "time",
    )
    return splits


def _group_events(
    events: Sequence[CanonicalEvent],
    strategy: SplitName,
) -> dict[str, list[CanonicalEvent]]:
    grouped: dict[str, list[CanonicalEvent]] = defaultdict(list)
    for event in events:
        grouped[_group_key(event, strategy)].append(event)
    return grouped
