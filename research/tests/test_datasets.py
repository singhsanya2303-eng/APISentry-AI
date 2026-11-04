from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from research.capture.sanitize import to_canonical_event
from research.datasets.evaluation import create_evaluation_splits
from research.datasets.manifest import build_manifest, write_manifest
from research.datasets.manifest import ManifestVerificationError, verify_manifest
from research.datasets.reader import read_events
from research.datasets.writer import sha256_file, write_events
from research.preprocessing.api_traffic import anonymize_principal
from research.schemas.canonical_event import CanonicalEvent


def event(index: int, label: str, category: str | None = None):
    return CanonicalEvent(
        event_id=f"e-{index}",
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc)
        + timedelta(days=index),
        principal_id=anonymize_principal(f"p-{index}", secret=bytes(range(32))),
        session_id=f"s-{index}",
        campaign_id=f"c-{index}",
        method="GET",
        endpoint_template="/items",
        status_code=200 if label == "normal" else 403,
        latency_ms=1,
        request_size_bytes=0,
        response_size_bytes=0,
        label=label,
        attack_category=category,
        source_dataset="custom_crapi",
    )


def test_writer_and_manifest_exclude_sensitive_fields(tmp_path: Path):
    path = tmp_path / "events.jsonl"
    checksum = write_events([event(0, "normal")], path)
    assert len(checksum) == 64
    text = path.read_text(encoding="utf-8")
    assert "password" not in text.lower()
    manifest = build_manifest(
        [event(0, "normal")],
        dataset_name="test",
        dataset_version="1",
        crapi_commit="commit",
        collection_run_id="run",
        files=[path],
    )
    output = tmp_path / "manifest.yaml"
    write_manifest(manifest, output)
    assert output.exists()
    assert manifest["event_count"] == len(read_events(path, principal_secret=bytes(range(32))))
    assert manifest["files"][0]["sha256"] == sha256_file(path)


def test_evaluation_fails_without_class_coverage():
    with pytest.raises(ValueError, match="class coverage"):
        create_evaluation_splits(
            [event(index, "normal") for index in range(6)],
            strategy="campaign",
        )


def test_known_category_evaluation_groups_whole_campaigns_and_checks_coverage():
    events = []
    for index in range(3):
        events.append(event(index, "normal"))
    for index, category in enumerate(("bola_idor", "brute_force", "rate_abuse"), start=3):
        for offset in range(3):
            events.append(event(index + offset * 3, "attack", category))
    splits = create_evaluation_splits(events, strategy="known-category")
    for split_events in splits.values():
        assert {item.label for item in split_events} == {"normal", "attack"}
        assert {
            item.attack_category
            for item in split_events
            if item.attack_category
        } == {"bola_idor", "brute_force", "rate_abuse"}
    assert {
        item.campaign_id for item in splits["train"]
    }.isdisjoint({item.campaign_id for item in splits["test"]})


def test_duplicate_events_are_rejected(tmp_path: Path):
    with pytest.raises(ValueError, match="duplicate"):
        write_events([event(0, "normal"), event(0, "normal")], tmp_path / "e.jsonl")


def _write_valid_manifest(tmp_path: Path):
    events_path = tmp_path / "events.jsonl"
    events = [event(0, "normal"), event(1, "attack", "bola_idor")]
    write_events(events, events_path)
    manifest = build_manifest(
        events,
        dataset_name="test",
        dataset_version="1",
        crapi_commit="commit",
        collection_run_id="run",
        files=[events_path],
    )
    manifest_path = tmp_path / "manifest.yaml"
    write_manifest(manifest, manifest_path)
    return manifest_path, events_path


def test_manifest_verifier_accepts_valid_dataset(tmp_path: Path):
    manifest_path, _ = _write_valid_manifest(tmp_path)
    result = verify_manifest(
        manifest_path,
        principal_secret=bytes(range(32)),
        dataset_root=tmp_path,
    )
    assert result["event_count"] == 2
    assert result["label_distribution"] == {"normal": 1, "attack": 1}


@pytest.mark.parametrize(
    "mutation",
    ["checksum", "missing", "count", "labels", "version"],
)
def test_manifest_verifier_rejects_manifest_inconsistency(
    tmp_path: Path, mutation: str
):
    manifest_path, events_path = _write_valid_manifest(tmp_path)
    import yaml

    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    if mutation == "checksum":
        manifest["files"][0]["sha256"] = "0" * 64
    elif mutation == "missing":
        events_path.unlink()
    elif mutation == "count":
        manifest["event_count"] = 99
    elif mutation == "labels":
        manifest["label_distribution"] = {"normal": 2}
    else:
        manifest["schema_version"] = "9.0"
    manifest_path.write_text(yaml.safe_dump(manifest), encoding="utf-8")
    with pytest.raises(ManifestVerificationError):
        verify_manifest(
            manifest_path,
            principal_secret=bytes(range(32)),
            dataset_root=tmp_path,
        )


def test_manifest_verifier_rejects_unexpected_and_duplicate_split_files(
    tmp_path: Path,
):
    manifest_path, events_path = _write_valid_manifest(tmp_path)
    extra = tmp_path / "extra.jsonl"
    write_events([event(2, "normal")], extra)
    with pytest.raises(ManifestVerificationError, match="unexpected"):
        verify_manifest(
            manifest_path,
            principal_secret=bytes(range(32)),
            dataset_root=tmp_path,
        )
    extra.unlink()
    split_a = tmp_path / "train.jsonl"
    split_b = tmp_path / "test.jsonl"
    write_events([event(0, "normal")], split_a)
    write_events([event(0, "normal")], split_b)
    import yaml

    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    manifest["split_files"] = [
        {"name": "train", "path": str(split_a), "sha256": sha256_file(split_a)},
        {"name": "test", "path": str(split_b), "sha256": sha256_file(split_b)},
    ]
    manifest_path.write_text(yaml.safe_dump(manifest), encoding="utf-8")
    with pytest.raises(ManifestVerificationError, match="overlapping"):
        verify_manifest(
            manifest_path,
            principal_secret=bytes(range(32)),
            dataset_root=tmp_path,
        )


def test_manifest_verifier_accepts_a_complete_non_overlapping_split_partition(
    tmp_path: Path,
):
    manifest_path, events_path = _write_valid_manifest(tmp_path)
    train_path = tmp_path / "train.jsonl"
    test_path = tmp_path / "test.jsonl"
    train_events = [event(0, "normal")]
    test_events = [event(1, "attack", "bola_idor")]
    write_events(train_events, train_path)
    write_events(test_events, test_path)
    import yaml

    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    manifest["split_files"] = [
        {"name": "train", "path": str(train_path), "sha256": sha256_file(train_path)},
        {"name": "test", "path": str(test_path), "sha256": sha256_file(test_path)},
    ]
    manifest_path.write_text(yaml.safe_dump(manifest), encoding="utf-8")
    result = verify_manifest(
        manifest_path,
        principal_secret=bytes(range(32)),
        dataset_root=tmp_path,
    )
    assert result["split_counts"] == {"train": 1, "test": 1}
    assert events_path.exists()


def test_manifest_verifier_accepts_cli_split_metadata(tmp_path: Path):
    events = [
        event(0, "normal"),
        event(1, "normal"),
        event(2, "attack", "bola_idor"),
    ]
    split_paths = []
    for name, split_events in (
        ("train", events[:1]),
        ("validation", events[1:2]),
        ("test", events[2:]),
    ):
        path = tmp_path / f"{name}.jsonl"
        write_events(split_events, path)
        split_paths.append((name, path, split_events))
    import yaml

    metadata = {
        "strategy": "random",
        "seed": 7,
        "event_counts": {
            name: len(split_events) for name, _, split_events in split_paths
        },
        "label_distributions": {
            name: dict(Counter(item.label for item in split_events))
            for name, _, split_events in split_paths
        },
        "files": {
            name: {"path": str(path), "sha256": sha256_file(path)}
            for name, path, _ in split_paths
        },
    }
    manifest_path = tmp_path / "split_metadata.yaml"
    write_manifest(
        {"schema_version": "1.0", "split_metadata": metadata},
        manifest_path,
    )
    result = verify_manifest(
        manifest_path,
        principal_secret=bytes(range(32)),
        dataset_root=tmp_path,
    )
    assert result["event_count"] == 3
    assert result["split_counts"] == {"train": 1, "validation": 1, "test": 1}


def test_held_out_category_is_not_category_coverage(tmp_path: Path):
    events = [
        event(0, "normal"),
        event(1, "normal"),
        event(2, "normal"),
        event(3, "attack", "bola_idor"),
        event(4, "attack", "brute_force"),
        event(5, "attack", "rate_abuse"),
    ]
    splits = create_evaluation_splits(events, strategy="held-out-category")
    assert {
        item.attack_category
        for item in splits["train"]
        if item.attack_category
    } == {"bola_idor"}
    assert {
        item.attack_category
        for item in splits["validation"]
        if item.attack_category
    } == {"brute_force"}
    assert {
        item.attack_category
        for item in splits["test"]
        if item.attack_category
    } == {"rate_abuse"}
