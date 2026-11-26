"""Research-only CSIC 2010 HTTP anomaly dataset preparation.

This module is deliberately isolated from the production detection, mitigation,
and inference stack. No application router, middleware, or runtime service
imports it. It exists solely for the separate CSIC research experiment.

Security/label contract:
    - ``cookie`` is a session grouping key only and is never a predictive input.
    - ``index`` and ``host`` are excluded as non-generalising identifiers.
    - ``label`` is the target. Attack-marker heuristics are NOT targets or inputs.
    - Raw payloads and session identifiers are never persisted by this module.
"""

from __future__ import annotations

import csv
import hashlib
import io
import random
import re
import zipfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, NamedTuple, Sequence
from urllib.parse import unquote, urlsplit

import numpy as np
from scipy import sparse
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import OneHotEncoder, StandardScaler


FEATURE_ADAPTER_VERSION = 1

LABEL_NORMAL = "norm"
LABEL_ANOMALOUS = "anom"
LABELS = (LABEL_NORMAL, LABEL_ANOMALOUS)

EXPECTED_COLUMNS = (
    "index",
    "method",
    "url",
    "protocol",
    "userAgent",
    "pragma",
    "cacheControl",
    "accept",
    "acceptEncoding",
    "acceptCharset",
    "acceptLanguage",
    "host",
    "connection",
    "contentLength",
    "contentType",
    "cookie",
    "payload",
    "label",
)

EXCLUDED_COLUMNS = frozenset(
    {
        "index",
        "cookie",
        "host",
        "label",
        "protocol",
        "userAgent",
        "pragma",
        "cacheControl",
        "accept",
        "acceptEncoding",
        "acceptCharset",
        "acceptLanguage",
        "connection",
        "contentType",
    }
)

NUMERIC_FEATURES = (
    "payload_length",
    "parameter_count",
    "percent_encoding_ratio",
    "content_length",
    "content_length_missing",
)

_SESSION_TOKEN_RE = re.compile(r"JSESSIONID=[0-9A-Fa-f]{1,64}")
_HEX_SEGMENT_RE = re.compile(r"/[0-9a-fA-F]{8,}")
_ID_SEGMENT_RE = re.compile(r"/\d+")
_PERCENT_ESCAPE_RE = re.compile(r"%[0-9A-Fa-f]{2}")
_WHITESPACE_RE = re.compile(r"\s+")


class CsicRecord(NamedTuple):
    """Minimal, non-sensitive row view used by the research pipeline."""

    session: str
    label: str
    method: str
    url: str
    payload: str
    content_length: str


@dataclass(frozen=True)
class GroupSplit:
    """Group-aware split with explicit session isolation evidence."""

    indices: dict[str, list[int]]
    session_assignments: dict[str, str]
    summary: dict[str, Any]

    def records_for(
        self,
        records: Sequence[CsicRecord],
        split_name: str,
    ) -> list[CsicRecord]:
        return [records[index] for index in self.indices[split_name]]


@dataclass(frozen=True)
class FeatureBundle:
    """Separate matrices allow text and structured baselines to be compared."""

    text: Any
    structured: Any
    combined: Any
    labels: np.ndarray
    sessions: list[str]


def verify_dataset_hash(archive_path: str | Path, expected_sha256: str) -> str:
    """Stream the archive and reject a hash mismatch before any processing."""
    path = Path(archive_path)
    if not path.is_file():
        raise FileNotFoundError(f"CSIC archive not found: {path}")
    if not isinstance(expected_sha256, str) or len(expected_sha256.strip()) != 64:
        raise ValueError("expected_sha256 must be a 64-character hexadecimal string")

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    actual = digest.hexdigest()
    if actual.lower() != expected_sha256.strip().lower():
        raise ValueError(
            f"CSIC archive SHA-256 mismatch: expected {expected_sha256}, got {actual}"
        )
    return actual


def load_records_from_zip(archive_path: str | Path) -> list[CsicRecord]:
    """Read the single CSV member directly from the ZIP without extraction."""
    path = Path(archive_path)
    with zipfile.ZipFile(path) as archive:
        members = [
            info
            for info in archive.infolist()
            if not info.is_dir() and info.filename.lower().endswith(".csv")
        ]
        if len(members) != 1:
            raise ValueError(
                f"expected exactly one CSV member in {path}, found {len(members)}"
            )
        with archive.open(members[0]) as raw:
            text = io.TextIOWrapper(raw, encoding="utf-8", errors="replace", newline="")
            reader = csv.DictReader(text)
            if tuple(reader.fieldnames or ()) != EXPECTED_COLUMNS:
                raise ValueError(
                    "unexpected CSV header: "
                    f"expected {EXPECTED_COLUMNS}, got {tuple(reader.fieldnames or ())}"
                )
            records: list[CsicRecord] = []
            for row in reader:
                if None in row or any(value is None for value in row.values()):
                    raise ValueError("malformed CSV row with inconsistent field count")
                label = row["label"]
                if label not in LABELS:
                    raise ValueError(f"unexpected CSIC label: {label!r}")
                session = row["cookie"]
                if not session:
                    raise ValueError("empty session grouping key")
                records.append(
                    CsicRecord(
                        session=session,
                        label=label,
                        method=row["method"],
                        url=row["url"],
                        payload=row["payload"],
                        content_length=row["contentLength"],
                    )
                )
    if not records:
        raise ValueError("CSIC archive contains no data rows")
    return records


def decode_percent_encoding(value: str) -> str:
    """Decode CSIC percent escapes using Latin-1 to preserve Spanish bytes."""
    try:
        return unquote(value, encoding="latin-1", errors="replace")
    except Exception:
        return value


def normalize_url(url: str) -> str:
    """Strip host/scheme and replace opaque identifier segments."""
    path = urlsplit(url).path or "/"
    path = _HEX_SEGMENT_RE.sub("/:hex", path)
    path = _ID_SEGMENT_RE.sub("/:id", path)
    return _WHITESPACE_RE.sub(" ", path).strip()


def normalize_payload(payload: str) -> str:
    """Decode once, redact session tokens, and collapse whitespace."""
    if not payload:
        return "<no_payload>"
    decoded = decode_percent_encoding(payload)
    decoded = _SESSION_TOKEN_RE.sub("<session>", decoded)
    return _WHITESPACE_RE.sub(" ", decoded).strip()


def _numeric_vector(record: CsicRecord) -> list[float]:
    decoded = decode_percent_encoding(record.payload)
    raw = record.payload
    content_missing = record.content_length.strip().lower() in {"", "null", "nan"}
    content_length = float("nan") if content_missing else float(record.content_length)
    return [
        float(len(decoded)),
        float(decoded.count("&") + 1 if decoded else 0),
        float(len(_PERCENT_ESCAPE_RE.findall(raw))) / max(len(raw), 1),
        content_length,
        float(content_missing),
    ]


class CsicHttpFeatureAdapter:
    """Fit-on-train-only adapter for CSIC HTTP request records.

    The transformer produces three views: TF-IDF text features, structured
    numeric/method features, and their sparse concatenation. All fitted state
    (vocabularies, imputer statistics, scaler, method categories) comes from
    the training partition supplied to :meth:`fit_transform`.
    """

    def __init__(
        self,
        *,
        seed: int = 42,
        url_max_features: int = 3000,
        payload_max_features: int = 10000,
        char_ngram_range: tuple[int, int] = (3, 5),
    ) -> None:
        self.seed = seed
        self.url_max_features = url_max_features
        self.payload_max_features = payload_max_features
        self.char_ngram_range = char_ngram_range
        self.is_fitted = False

    def _raw_views(
        self, records: Sequence[CsicRecord]
    ) -> tuple[list[str], list[str], list[list[str]], np.ndarray]:
        urls = [normalize_url(record.url) for record in records]
        payloads = [normalize_payload(record.payload) for record in records]
        methods = [[record.method] for record in records]
        numeric = np.asarray([_numeric_vector(record) for record in records], dtype=float)
        return urls, payloads, methods, numeric

    def fit_transform(self, records: Sequence[CsicRecord]) -> FeatureBundle:
        if not records:
            raise ValueError("at least one record is required to fit the adapter")
        urls, payloads, methods, numeric = self._raw_views(records)
        labels = np.asarray([record.label for record in records])
        sessions = [record.session for record in records]

        self.url_vectorizer_ = TfidfVectorizer(
            analyzer="char",
            ngram_range=self.char_ngram_range,
            min_df=2,
            max_features=self.url_max_features,
            sublinear_tf=True,
            dtype=np.float32,
        )
        self.payload_vectorizer_ = TfidfVectorizer(
            analyzer="char",
            ngram_range=self.char_ngram_range,
            min_df=2,
            max_features=self.payload_max_features,
            sublinear_tf=True,
            dtype=np.float32,
        )
        self.method_encoder_ = OneHotEncoder(handle_unknown="ignore", sparse_output=True)
        self.imputer_ = SimpleImputer(strategy="median")
        self.scaler_ = StandardScaler()

        url_features = self.url_vectorizer_.fit_transform(urls)
        payload_features = self.payload_vectorizer_.fit_transform(payloads)
        method_features = self.method_encoder_.fit_transform(methods)
        numeric_imputed = self.imputer_.fit_transform(numeric)
        numeric_features = self.scaler_.fit_transform(numeric_imputed)

        text = sparse.hstack([url_features, payload_features], format="csr", dtype=np.float32)
        structured = sparse.hstack(
            [method_features, sparse.csr_matrix(numeric_features)],
            format="csr",
            dtype=np.float32,
        )
        combined = sparse.hstack([text, structured], format="csr", dtype=np.float32)
        self.is_fitted = True
        self.feature_schema_ = self._build_schema()
        return FeatureBundle(
            text=text,
            structured=structured,
            combined=combined,
            labels=labels,
            sessions=sessions,
        )

    def transform(self, records: Sequence[CsicRecord]) -> FeatureBundle:
        if not self.is_fitted:
            raise RuntimeError("adapter must be fitted before transform")
        urls, payloads, methods, numeric = self._raw_views(records)
        labels = np.asarray([record.label for record in records])
        sessions = [record.session for record in records]

        url_features = self.url_vectorizer_.transform(urls)
        payload_features = self.payload_vectorizer_.transform(payloads)
        method_features = self.method_encoder_.transform(methods)
        numeric_imputed = self.imputer_.transform(numeric)
        numeric_features = self.scaler_.transform(numeric_imputed)

        text = sparse.hstack([url_features, payload_features], format="csr", dtype=np.float32)
        structured = sparse.hstack(
            [method_features, sparse.csr_matrix(numeric_features)],
            format="csr",
            dtype=np.float32,
        )
        combined = sparse.hstack([text, structured], format="csr", dtype=np.float32)
        return FeatureBundle(
            text=text,
            structured=structured,
            combined=combined,
            labels=labels,
            sessions=sessions,
        )

    def _build_schema(self) -> dict[str, Any]:
        return {
            "version": FEATURE_ADAPTER_VERSION,
            "seed": self.seed,
            "excluded_columns": sorted(EXCLUDED_COLUMNS),
            "excluded_from_features": [
                "index",
                "cookie",
                "host",
                "label",
                "attack_marker_heuristics",
            ],
            "feature_blocks": [
                "url_char_ngrams",
                "payload_char_ngrams",
                "method_onehot",
                "numeric",
            ],
            "url_char_ngram_count": len(self.url_vectorizer_.vocabulary_),
            "payload_char_ngram_count": len(self.payload_vectorizer_.vocabulary_),
            "method_categories": [str(value) for value in self.method_encoder_.categories_[0]],
            "numeric_features": list(NUMERIC_FEATURES),
            "char_ngram_range": list(self.char_ngram_range),
            "missing_value_policy": {
                "contentLength": "literal 'null' -> median imputation + indicator",
                "payload": "empty -> <no_payload> token; percent escapes decoded as Latin-1",
            },
        }


def create_group_split(
    records: Sequence[CsicRecord],
    *,
    seed: int,
    train_ratio: float = 0.7,
    validation_ratio: float = 0.15,
) -> GroupSplit:
    """Split whole sessions, stratified by the session-level binary label."""
    if not 0 < train_ratio < 1 or not 0 < validation_ratio < 1:
        raise ValueError("split ratios must be between 0 and 1")
    if train_ratio + validation_ratio >= 1:
        raise ValueError("train and validation ratios must leave room for test")

    sessions_by_label: dict[str, list[str]] = {label: [] for label in LABELS}
    label_by_session: dict[str, str] = {}
    rows_by_session: dict[str, int] = {}
    for record in records:
        previous = label_by_session.setdefault(record.session, record.label)
        if previous != record.label:
            raise ValueError(
                "session has conflicting labels; supervised group split is unreliable"
            )
        rows_by_session[record.session] = rows_by_session.get(record.session, 0) + 1

    for session, label in label_by_session.items():
        sessions_by_label[label].append(session)

    for label, sessions in sessions_by_label.items():
        if len(sessions) < 3:
            raise ValueError(
                f"at least three independent {label} sessions are required"
            )

    rng = random.Random(seed)
    assignments: dict[str, str] = {}
    for label in LABELS:
        sessions = list(sessions_by_label[label])
        rng.shuffle(sessions)
        total = len(sessions)
        train_end = max(1, int(total * train_ratio))
        validation_end = min(
            max(train_end + 1, int(total * (train_ratio + validation_ratio))),
            total - 1,
        )
        for position, session in enumerate(sessions):
            if position < train_end:
                split = "train"
            elif position < validation_end:
                split = "validation"
            else:
                split = "test"
            assignments[session] = split

    indices: dict[str, list[int]] = {name: [] for name in ("train", "validation", "test")}
    for index, record in enumerate(records):
        indices[assignments[record.session]].append(index)

    summary: dict[str, Any] = {
        "seed": seed,
        "train_ratio": train_ratio,
        "validation_ratio": validation_ratio,
        "splits": {},
    }
    for split_name, row_indices in indices.items():
        split_sessions = {records[index].session for index in row_indices}
        labels = Counter(records[index].label for index in row_indices)
        if not split_sessions or not all(count > 0 for count in labels.values()):
            raise ValueError(f"split {split_name} is empty or missing a class")
        split_labels = {records[index].label for index in row_indices}
        if len(split_labels) != len(LABELS):
            raise ValueError(f"split {split_name} does not contain both labels")
        summary["splits"][split_name] = {
            "row_count": len(row_indices),
            "session_count": len(split_sessions),
            "label_counts": {label: labels[label] for label in LABELS},
        }

    all_assigned = set(assignments)
    if len(all_assigned) != len(label_by_session):
        raise ValueError("session assignment is incomplete")
    return GroupSplit(indices=indices, session_assignments=assignments, summary=summary)


def analyze_split_overlap(
    records: Sequence[CsicRecord],
    split: GroupSplit,
) -> dict[str, Any]:
    """Measure non-session feature overlap and conflicting labels across splits.

    Feature keys deliberately use only model-visible fields (method, normalized
    URL, normalized payload) so the result describes what the model can see.
    """
    index_to_split: dict[int, str] = {}
    for name, row_indices in split.indices.items():
        for index in row_indices:
            index_to_split[index] = name
    if len(index_to_split) != len(records):
        raise ValueError("split must assign every record exactly once")

    keys: dict[tuple[str, str, str], list[tuple[str, str]]] = defaultdict(list)
    session_splits: dict[str, set[str]] = defaultdict(set)
    for index, record in enumerate(records):
        key = (record.method, normalize_url(record.url), normalize_payload(record.payload))
        keys[key].append((index_to_split[index], record.label))
        session_splits[record.session].add(index_to_split[index])

    pair_names = (("train", "validation"), ("train", "test"), ("validation", "test"))
    pairs: dict[str, Any] = {}
    for left, right in pair_names:
        shared = [entries for entries in keys.values() if {left, right} <= {s for s, _ in entries}]
        conflicting = [
            entries
            for entries in shared
            if len({label for _, label in entries}) > 1
        ]
        pairs[f"{left}_vs_{right}"] = {
            "shared_feature_vectors": len(shared),
            "conflicting_label_vectors": len(conflicting),
        }

    conflicting_overall = [
        entries for entries in keys.values() if len({label for _, label in entries}) > 1
    ]
    return {
        "sessions_in_multiple_splits": sum(
            1 for names in session_splits.values() if len(names) > 1
        ),
        "distinct_feature_vectors": len(keys),
        "conflicting_label_vectors_overall": len(conflicting_overall),
        "rows_at_conflicting_vectors": sum(len(entries) for entries in conflicting_overall),
        "pairwise": pairs,
        "interpretation": (
            "Non-zero overlap is expected: identical ordinary requests recur across "
            "independent sessions. Session grouping prevents the same session from "
            "appearing in more than one partition; conflicts are reported, not hidden."
        ),
    }


def dataset_provenance(
    archive_path: str | Path,
    dataset_hash: str,
    records: Sequence[CsicRecord],
) -> dict[str, Any]:
    """Record provenance and limitations without persisting raw records."""
    return {
        "archive_path": str(Path(archive_path).resolve()),
        "archive_sha256": dataset_hash,
        "row_count": len(records),
        "session_count": len({record.session for record in records}),
        "label_counts": {
            label: sum(1 for record in records if record.label == label) for label in LABELS
        },
        "original_block_membership": {
            "first_anom_row": 1,
            "last_anom_row": 119585,
            "first_norm_row": 119586,
            "last_norm_row": len(records),
            "used_as_supervised_split": False,
            "note": (
                "Original contiguous blocks are provenance metadata only. The normal "
                "block contains no anomalous examples, so it cannot serve as a "
                "supervised training partition."
            ),
        },
        "limitations": [
            "Labels are session-level; most anom-block requests are ordinary traffic.",
            "No attack-category ground truth exists; categories are not inferred.",
            "Attack-marker heuristics are used only by the comparison baseline.",
            "Benchmark results do not establish real-world API security accuracy.",
            "The source is a controlled academic web application, not APISentry traffic.",
        ],
    }
