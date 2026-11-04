"""Manifest construction and read-only verification without raw traffic."""

from collections import Counter
import os
from pathlib import Path
import re
from typing import Any

import yaml

from research.datasets.writer import sha256_file
from research.datasets.reader import read_events
from research.schemas.canonical_event import CanonicalEvent

MANIFEST_SCHEMA_VERSION = "1.0"


class ManifestVerificationError(ValueError):
    """Raised when a dataset manifest or referenced file is inconsistent."""


def _distribution(events: list[CanonicalEvent]) -> tuple[dict[str, int], dict[str, int]]:
    labels = Counter(event.label for event in events)
    categories = Counter(
        event.attack_category
        for event in events
        if event.attack_category is not None
    )
    return dict(labels), dict(categories)


def _safe_manifest_path(root: Path, value: object) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise ManifestVerificationError("manifest file path must be non-blank")
    relative = Path(value)
    root_resolved = root.resolve()
    if relative.is_absolute():
        resolved = relative.resolve()
        if root_resolved not in resolved.parents and resolved != root_resolved:
            raise ManifestVerificationError(
                "manifest file path must stay within dataset root"
            )
        return resolved
    if ".." in relative.parts:
        raise ManifestVerificationError("manifest file path must stay within dataset root")
    resolved = (root / relative).resolve()
    if root_resolved not in resolved.parents and resolved != root_resolved:
        raise ManifestVerificationError(
            "manifest file path must stay within dataset root"
        )
    return resolved


def _file_entries(manifest: dict[str, Any], key: str) -> list[dict[str, Any]]:
    entries = manifest.get(key, [])
    if not isinstance(entries, list):
        raise ManifestVerificationError(f"manifest {key} must be a list")
    if any(not isinstance(entry, dict) for entry in entries):
        raise ManifestVerificationError(f"manifest {key} contains an invalid entry")
    return entries


def _validate_distribution(value: object, field_name: str) -> dict[str, int]:
    if not isinstance(value, dict):
        raise ManifestVerificationError(f"manifest {field_name} must be a mapping")
    if any(
        not isinstance(key, str) or type(count) is not int or count < 0
        for key, count in value.items()
    ):
        raise ManifestVerificationError(
            f"manifest {field_name} contains an invalid count"
        )
    return value


def _validate_file_entry(entry: dict[str, Any]) -> None:
    if not isinstance(entry.get("path"), str) or not entry["path"].strip():
        raise ManifestVerificationError("manifest file path must be non-blank")
    checksum = entry.get("sha256")
    if not isinstance(checksum, str) or not re.fullmatch(r"[0-9a-f]{64}", checksum):
        raise ManifestVerificationError("manifest contains an invalid file checksum")
    if "event_count" in entry and (
        type(entry["event_count"]) is not int or entry["event_count"] < 0
    ):
        raise ManifestVerificationError(
            f"manifest event_count for {entry['path']} must be non-negative"
        )


def _same_file(left: Path, right: Path) -> bool:
    try:
        return os.path.samefile(left, right)
    except OSError:
        return left.resolve() == right.resolve()


def _unexpected_jsonl_files(root: Path, referenced: list[Path]) -> bool:
    return any(
        not any(_same_file(path, expected) for expected in referenced)
        for path in root.rglob("*.jsonl")
        if path.is_file()
    )


def _verify_split_metadata(
    manifest: dict[str, Any],
    *,
    root: Path,
    principal_secret: str | bytes,
) -> dict[str, Any]:
    metadata = manifest["split_metadata"]
    if not isinstance(metadata, dict):
        raise ManifestVerificationError("manifest split_metadata must be a mapping")
    files = metadata.get("files")
    if not isinstance(files, dict) or not files:
        raise ManifestVerificationError("split metadata must reference files")
    entries: list[tuple[str, dict[str, Any], Path]] = []
    referenced: list[Path] = []
    for name, value in files.items():
        if not isinstance(name, str) or not isinstance(value, dict):
            raise ManifestVerificationError("split metadata contains an invalid file entry")
        _validate_file_entry(value)
        path = _safe_manifest_path(root, value["path"])
        if any(_same_file(path, existing) for existing in referenced):
            raise ManifestVerificationError("split metadata references a file more than once")
        if not path.is_file():
            raise ManifestVerificationError(
                f"referenced dataset file is missing: {value['path']}"
            )
        if sha256_file(path) != value["sha256"]:
            raise ManifestVerificationError(f"checksum mismatch for {value['path']}")
        referenced.append(path)
        entries.append((name, value, path))
    if _unexpected_jsonl_files(root, referenced):
        raise ManifestVerificationError("unexpected dataset files are present")

    all_events: list[CanonicalEvent] = []
    split_counts: dict[str, int] = {}
    label_distributions: dict[str, dict[str, int]] = {}
    event_ids: set[str] = set()
    for name, entry, path in entries:
        try:
            events = read_events(path, principal_secret=principal_secret)
        except (OSError, ValueError) as exc:
            raise ManifestVerificationError(
                f"invalid canonical events in split {entry['path']}"
            ) from exc
        ids = [event.event_id for event in events]
        if len(ids) != len(set(ids)) or event_ids.intersection(ids):
            raise ManifestVerificationError("split files contain overlapping event IDs")
        event_ids.update(ids)
        split_counts[name] = len(events)
        label_distributions[name] = dict(Counter(event.label for event in events))
        if entry.get("event_count") is not None and entry["event_count"] != len(events):
            raise ManifestVerificationError(f"split event count mismatch for {entry['path']}")
        all_events.extend(events)

    declared_counts = metadata.get("event_counts")
    if declared_counts != split_counts:
        raise ManifestVerificationError("split metadata event counts do not match files")
    if metadata.get("label_distributions") != label_distributions:
        raise ManifestVerificationError(
            "split metadata label distributions do not match files"
        )
    return {
        "event_count": len(all_events),
        "label_distribution": dict(Counter(event.label for event in all_events)),
        "attack_category_distribution": dict(
            Counter(
                event.attack_category
                for event in all_events
                if event.attack_category is not None
            )
        ),
        "split_counts": split_counts,
        "verified_files": [str(path) for path in referenced],
    }

def build_manifest(
    events: list[CanonicalEvent],
    *,
    dataset_name: str,
    dataset_version: str,
    crapi_commit: str,
    collection_run_id: str,
    schema_version: str = "1.0",
    sanitization_version: str = "1.0",
    split_strategy: str = "not-created",
    files: list[Path] | None = None,
    split_files: list[dict[str, Any]] | None = None,
    split_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build provenance and distribution metadata from canonical events."""
    labels = Counter(event.label for event in events)
    categories = Counter(
        event.attack_category
        for event in events
        if event.attack_category is not None
    )
    manifest = {
        "dataset_name": dataset_name,
        "dataset_version": dataset_version,
        "source": "OWASP crAPI",
        "crapi_commit": crapi_commit,
        "collection_run_ids": [collection_run_id],
        "schema_version": schema_version,
        "sanitization_version": sanitization_version,
        "event_count": len(events),
        "label_distribution": dict(labels),
        "attack_category_distribution": dict(categories),
        "split_strategy": split_strategy,
        "files": [
            {"path": str(path), "sha256": sha256_file(path)}
            for path in (files or [])
        ],
        "known_limitations": [
            "Controlled localhost crAPI traffic is not production traffic.",
            "Labels describe the controlled procedure, not model accuracy.",
        ],
    }
    if split_files is not None:
        manifest["split_files"] = split_files
    if split_metadata is not None:
        manifest["split_metadata"] = split_metadata
    return manifest


def verify_manifest(
    manifest_path: Path,
    *,
    principal_secret: str | bytes,
    dataset_root: Path | None = None,
) -> dict[str, Any]:
    """Verify a manifest and all referenced canonical JSONL files read-only."""
    try:
        manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ManifestVerificationError("unable to read dataset manifest") from exc
    if not isinstance(manifest, dict):
        raise ManifestVerificationError("manifest must contain a mapping")
    if manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise ManifestVerificationError("unsupported manifest schema version")
    if "files" not in manifest and "split_metadata" in manifest:
        root = dataset_root or manifest_path.parent
        return _verify_split_metadata(
            manifest,
            root=root,
            principal_secret=principal_secret,
        )
    for key in ("dataset_name", "dataset_version", "event_count", "files"):
        if key not in manifest:
            raise ManifestVerificationError(f"manifest missing {key}")
    for key in ("dataset_name", "dataset_version"):
        if not isinstance(manifest[key], str) or not manifest[key].strip():
            raise ManifestVerificationError(f"manifest {key} must be non-blank text")
    if type(manifest["event_count"]) is not int or manifest["event_count"] < 0:
        raise ManifestVerificationError("manifest event_count must be a non-negative integer")
    declared_labels = _validate_distribution(
        manifest.get("label_distribution"), "label_distribution"
    )
    declared_categories = _validate_distribution(
        manifest.get("attack_category_distribution"),
        "attack_category_distribution",
    )

    root = dataset_root or manifest_path.parent
    data_entries = _file_entries(manifest, "files")
    split_entries = _file_entries(manifest, "split_files")
    for entry in data_entries + split_entries:
        _validate_file_entry(entry)
    all_entries = data_entries + split_entries
    if not all_entries:
        raise ManifestVerificationError("manifest references no dataset files")

    paths: list[Path] = []
    for entry in all_entries:
        path = _safe_manifest_path(root, entry.get("path"))
        if path in paths:
            raise ManifestVerificationError("manifest references a file more than once")
        if not path.is_file():
            raise ManifestVerificationError(f"referenced dataset file is missing: {entry.get('path')}")
        expected_hash = entry["sha256"]
        try:
            actual_hash = sha256_file(path)
        except OSError as exc:
            raise ManifestVerificationError(
                f"unable to read referenced dataset file {entry['path']}"
            ) from exc
        if actual_hash != expected_hash:
            raise ManifestVerificationError(f"checksum mismatch for {entry['path']}")
        paths.append(path)

    if _unexpected_jsonl_files(root, paths):
        raise ManifestVerificationError("unexpected dataset files are present")

    data_events: list[CanonicalEvent] = []
    for entry, path in zip(data_entries, paths[: len(data_entries)]):
        try:
            events = read_events(path, principal_secret=principal_secret)
        except (OSError, ValueError) as exc:
            raise ManifestVerificationError(
                f"invalid canonical events in {entry.get('path')}"
            ) from exc
        declared_count = entry.get("event_count")
        if declared_count is not None and declared_count != len(events):
            raise ManifestVerificationError(
                f"event count mismatch for {entry.get('path')}"
            )
        data_events.extend(events)

    event_ids = [event.event_id for event in data_events]
    if len(event_ids) != len(set(event_ids)):
        raise ManifestVerificationError("duplicate event_id detected")
    if len(data_events) != manifest["event_count"]:
        raise ManifestVerificationError("manifest event count does not match dataset")
    labels, categories = _distribution(data_events)
    if declared_labels != labels:
        raise ManifestVerificationError("manifest label distribution does not match dataset")
    if declared_categories != categories:
        raise ManifestVerificationError(
            "manifest attack-category distribution does not match dataset"
        )

    data_ids = {event.event_id for event in data_events}
    split_ids: set[str] = set()
    split_names: set[str] = set()
    split_counts: dict[str, int] = {}
    for entry, path in zip(split_entries, paths[len(data_entries):]):
        try:
            events = read_events(path, principal_secret=principal_secret)
        except (OSError, ValueError) as exc:
            raise ManifestVerificationError(
                f"invalid canonical events in split {entry.get('path')}"
            ) from exc
        ids = [event.event_id for event in events]
        split_name = str(entry.get("name", entry["path"]))
        if split_name in split_names:
            raise ManifestVerificationError("split files contain duplicate names")
        split_names.add(split_name)
        if len(ids) != len(set(ids)) or split_ids.intersection(ids):
            raise ManifestVerificationError("split files contain overlapping event IDs")
        split_ids.update(ids)
        if not set(ids).issubset(data_ids):
            raise ManifestVerificationError(
                f"split file {entry['path']} contains events outside the dataset"
            )
        split_counts[split_name] = len(events)
        if entry.get("event_count") is not None and entry["event_count"] != len(events):
            raise ManifestVerificationError(
                f"split event count mismatch for {entry.get('path')}"
            )
    if split_entries and split_ids != data_ids:
        raise ManifestVerificationError(
            "split files do not partition the referenced dataset events"
        )

    return {
        "event_count": len(data_events),
        "label_distribution": labels,
        "attack_category_distribution": categories,
        "split_counts": split_counts,
        "verified_files": [str(path) for path in paths],
    }


def write_manifest(manifest: dict[str, Any], path: Path) -> None:
    """Write a YAML manifest without accepting secret fields."""
    forbidden = {"secret", "password", "token", "authorization", "cookie", "body"}
    serialized = yaml.safe_dump(manifest, sort_keys=True)
    lowered = serialized.lower()
    if any(word in lowered for word in forbidden):
        raise ValueError("manifest contains a forbidden sensitive field")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(serialized, encoding="utf-8")
