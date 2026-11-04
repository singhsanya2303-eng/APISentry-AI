"""Leakage-aware evaluation configurations and coverage checks."""

from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from research.schemas.canonical_event import CanonicalEvent
from research.datasets.writer import sha256_file
from research.splits.create_splits import create_splits, validate_split_leakage

EVALUATION_PROTOCOLS = {
    "random": {
        "question": "Can a model generalize to held-out grouped events sampled from the same population?",
        "isolated": "session and campaign groups",
        "risks": "principal overlap and temporal drift may remain",
        "minimum": "three independent session/campaign groups and both labels per split",
        "primary": False,
    },
    "principal": {
        "question": "Can a model generalize to principals not seen during training?",
        "isolated": "principal, session, and campaign",
        "risks": "campaign semantics and time may still be shared",
        "minimum": "three independent principals with both labels in each split",
        "primary": True,
    },
    "time": {
        "question": "Can a model generalize forward in time?",
        "isolated": "session and campaign, with ordered time partitions",
        "risks": "principals and attack categories may recur across time",
        "minimum": "three chronologically ordered groups and timestamps",
        "primary": True,
    },
    "campaign": {
        "question": "Can a model generalize to unseen campaigns?",
        "isolated": "campaign, session",
        "risks": "principal overlap and temporal leakage may remain",
        "minimum": "three independent campaigns and both labels per split",
        "primary": False,
    },
    "held-out-category": {
        "question": "Can a model generalize to an attack category absent from training?",
        "isolated": "campaigns grouped by one attack category",
        "risks": "category holdout is not a substitute for population or time generalization",
        "minimum": "three attack categories, one category per campaign, and normal campaigns",
        "primary": False,
    },
}


def _coverage(
    splits: dict[str, Sequence[CanonicalEvent]],
    *,
    require_all_categories: bool = True,
) -> None:
    required_labels = {"normal", "attack"}
    all_categories = {
        event.attack_category
        for events in splits.values()
        for event in events
        if event.attack_category is not None
    }
    for name, events in splits.items():
        labels = {event.label for event in events}
        categories = {
            event.attack_category
            for event in events
            if event.attack_category is not None
        }
        if require_all_categories and labels != required_labels:
            raise ValueError(f"{name} lacks normal and attack class coverage")
        if require_all_categories and categories != all_categories:
            raise ValueError(f"{name} lacks attack-category coverage")


def _coverage_report(
    splits: dict[str, Sequence[CanonicalEvent]],
) -> dict[str, object]:
    categories = sorted(
        {
            event.attack_category
            for events in splits.values()
            for event in events
            if event.attack_category is not None
        }
    )
    return {
        name: {
            "labels": dict(Counter(event.label for event in events)),
            "attack_categories": dict(
                Counter(
                    event.attack_category
                    for event in events
                    if event.attack_category is not None
                )
            ),
            "missing_labels": sorted(
                {"normal", "attack"}
                - {event.label for event in events}
            ),
            "missing_attack_categories": [
                category
                for category in categories
                if category
                not in {
                    event.attack_category
                    for event in events
                    if event.attack_category is not None
                }
            ],
        }
        for name, events in splits.items()
    }


def create_evaluation_splits(
    events: Sequence[CanonicalEvent],
    *,
    strategy: str,
    seed: int | None = None,
) -> dict[str, list[CanonicalEvent]]:
    """Create an explicitly named split from the documented protocol.

    ``random`` is the grouped baseline; ``principal``, ``time``, and
    ``campaign`` isolate their named entities. ``held-out-category`` is the
    only category-holdout protocol and requires category-pure campaigns.
    ``known-category`` is retained as a compatibility strategy for the
    existing grouped, category-covered evaluation.
    """
    if strategy == "held-out-category":
        campaign_groups: dict[str, list[CanonicalEvent]] = defaultdict(list)
        for event in events:
            campaign_groups[event.campaign_id].append(event)
        category_groups: dict[str, list[list[CanonicalEvent]]] = defaultdict(list)
        for group in campaign_groups.values():
            categories = {event.attack_category or "normal" for event in group}
            if len(categories) != 1:
                raise ValueError("held-out-category requires one category per campaign")
            category_groups[next(iter(categories))].append(group)
        attack_categories = sorted(category for category in category_groups if category != "normal")
        if len(attack_categories) < 3:
            raise ValueError("held-out-category requires three attack categories")
        if not category_groups.get("normal"):
            raise ValueError("held-out-category requires normal campaigns")
        splits = {"train": [], "validation": [], "test": []}
        for category in attack_categories:
            target = "train"
            if category == attack_categories[-2]:
                target = "validation"
            elif category == attack_categories[-1]:
                target = "test"
            for group in category_groups[category]:
                splits[target].extend(group)
        for group in category_groups["normal"]:
            splits["train"].extend(group)
        validate_split_leakage(splits)
        _coverage(splits, require_all_categories=False)
        return splits
    if strategy == "known-category":
        campaign_groups: dict[str, list[CanonicalEvent]] = defaultdict(list)
        for event in events:
            campaign_groups[event.campaign_id].append(event)
        if len(campaign_groups) < 3:
            raise ValueError("known-category evaluation requires three campaigns")
        ordered_groups = sorted(
            campaign_groups.values(),
            key=lambda group: (
                tuple(sorted({event.attack_category or "normal" for event in group})),
                min(event.timestamp for event in group),
                group[0].campaign_id,
            ),
        )
        splits = {"train": [], "validation": [], "test": []}
        split_names = tuple(splits)
        for index, group in enumerate(ordered_groups):
            splits[split_names[index % len(split_names)]].extend(group)
        validate_split_leakage(splits, isolated_fields=("session_id", "campaign_id"))
        _coverage(splits)
        return splits
    if strategy == "random":
        splits = create_splits(events, strategy="random", seed=seed)
        validate_split_leakage(splits)
    elif strategy == "campaign":
        splits = create_splits(
            events,
            strategy="campaign",
        )
        validate_split_leakage(splits)
    elif strategy == "principal":
        splits = create_splits(
            events,
            strategy="principal",
        )
        validate_split_leakage(
            splits,
            isolated_fields=("principal_id", "session_id", "campaign_id"),
        )
    elif strategy == "time":
        splits = create_splits(events, strategy="time")
        validate_split_leakage(splits, check_chronology=True)
    else:
        raise ValueError("unknown evaluation strategy")
    _coverage(splits)
    return splits


def build_split_metadata(
    splits: dict[str, Sequence[CanonicalEvent]],
    *,
    strategy: str,
    seed: int | None = None,
    files: dict[str, Path] | None = None,
    generated_at: datetime | None = None,
) -> dict[str, object]:
    """Build reproducibility metadata without claiming experimental results."""
    validate_split_leakage(splits)
    label_distributions = {
        name: dict(Counter(event.label for event in events))
        for name, events in splits.items()
    }
    class_imbalance: dict[str, dict[str, object]] = {}
    for name, distribution in label_distributions.items():
        normal_count = distribution.get("normal", 0)
        attack_count = distribution.get("attack", 0)
        non_zero = [count for count in (normal_count, attack_count) if count]
        class_imbalance[name] = {
            "normal": normal_count,
            "attack": attack_count,
            "missing_labels": sorted(
                {"normal", "attack"} - set(distribution)
            ),
            "majority_to_minority_ratio": (
                max(non_zero) / min(non_zero) if len(non_zero) == 2 else None
            ),
        }
    return {
        "strategy": strategy,
        "seed": seed,
        "generated_at": (generated_at or datetime.now(timezone.utc)).isoformat(),
        "event_counts": {name: len(events) for name, events in splits.items()},
        "label_distributions": label_distributions,
        "class_imbalance": class_imbalance,
        "coverage": _coverage_report(splits),
        "files": {
            name: {"path": str(path), "sha256": sha256_file(path)}
            for name, path in (files or {}).items()
        },
    }
