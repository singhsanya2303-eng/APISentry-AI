"""Research-only CSIC pipeline tests.

These tests intentionally use tiny in-memory records. They never load the full
archive, contact a database, or import a production detection/mitigation route.
"""

from __future__ import annotations

import hashlib
import json
import zipfile

import joblib
import numpy as np
import pytest

from app.services.csic_http_feature_adapter import (
    EXPECTED_COLUMNS,
    CsicHttpFeatureAdapter,
    CsicRecord,
    _numeric_vector,
    analyze_split_overlap,
    create_group_split,
    decode_percent_encoding,
    normalize_payload,
    normalize_url,
    verify_dataset_hash,
)
from app.services.csic_training_service import (
    ACCEPTANCE_CRITERIA,
    build_models,
    check_acceptance,
    compute_metrics,
    evaluate_predictions,
    fit_models,
    load_artifact,
    render_report,
    save_artifact,
    select_model,
)


def make_records(sessions: int = 12, rows_per_session: int = 4) -> list[CsicRecord]:
    records: list[CsicRecord] = []
    for session_index in range(sessions):
        label = "anom" if session_index % 2 == 0 else "norm"
        session = f"session-{session_index:03d}"
        for row_index in range(rows_per_session):
            is_attack = label == "anom" and row_index == rows_per_session - 1
            payload = (
                "login=bob%40%3CSCRipt%3Ealert%28Paros%29%3C%2FscrIPT%3E"
                if is_attack
                else "id=2&nombre=Jam%F3n+Ib%E9rico"
            )
            records.append(
                CsicRecord(
                    session=session,
                    label=label,
                    method="POST" if row_index % 2 else "GET",
                    url="http://localhost:8080/tienda1/publico/anadir.jsp?id=12",
                    payload=payload,
                    content_length="null" if row_index % 2 == 0 else "42",
                )
            )
    return records


def test_verify_dataset_hash_accepts_expected_archive(tmp_path):
    archive = tmp_path / "csic_sample.zip"
    with zipfile.ZipFile(archive, "w") as zip_handle:
        zip_handle.writestr(
            "sample.csv",
            "id,url,payload\n1,/tienda1/publico/anadir.jsp,id=2\n",
        )

    expected_hash = hashlib.sha256(archive.read_bytes()).hexdigest()

    digest = verify_dataset_hash(archive, expected_hash)
    assert digest == expected_hash


def test_verify_dataset_hash_rejects_mismatch(tmp_path):
    archive = tmp_path / "sample.bin"
    archive.write_bytes(b"csic research fixture")
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        verify_dataset_hash(archive, "0" * 64)


def test_verify_dataset_hash_rejects_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        verify_dataset_hash(tmp_path / "absent.zip", "0" * 64)


def test_normalization_helpers_are_deterministic_and_redact_sessions():
    assert normalize_url("http://localhost:8080/tienda1/publico/anadir.jsp?id=12") == (
        "/tienda1/publico/anadir.jsp"
    )
    assert decode_percent_encoding("nombre=Jam%F3n") == "nombre=Jamón"
    redacted = normalize_payload("JSESSIONID=ABCDEF0123456789&id=2")
    assert "JSESSIONID" not in redacted
    assert "<session>" in redacted
    assert normalize_payload("") == "<no_payload>"


def test_feature_extraction_excludes_leakage_columns():
    records = make_records()
    adapter = CsicHttpFeatureAdapter()
    features = adapter.fit_transform(records)
    schema = adapter.feature_schema_

    assert set(schema["excluded_columns"]) >= {"index", "cookie", "host", "label"}
    assert "attack_marker_heuristics" in schema["excluded_from_features"]
    assert schema["numeric_features"] == [
        "payload_length",
        "parameter_count",
        "percent_encoding_ratio",
        "content_length",
        "content_length_missing",
    ]
    assert features.combined.shape[0] == len(records)
    assert features.text.shape[1] > 0
    assert features.structured.shape[1] > 0
    assert set(np.unique(features.labels)) == {"norm", "anom"}
    serialized = json.dumps(schema)
    for session in {record.session for record in records}:
        assert session not in serialized


def test_label_does_not_change_features_for_identical_requests():
    shared = dict(
        method="GET",
        url="http://localhost:8080/tienda1/publico/anadir.jsp?id=3",
        payload="id=3&nombre=Vino",
        content_length="10",
    )
    normal = CsicRecord(session="a", label="norm", **shared)
    anomalous = CsicRecord(session="b", label="anom", **shared)
    adapter = CsicHttpFeatureAdapter()
    bundle = adapter.fit_transform([normal, anomalous])
    difference = (bundle.combined[0] - bundle.combined[1]).nnz
    assert difference == 0


def test_missing_value_handling_uses_indicator_and_no_payload_token():
    missing = CsicRecord("s1", "norm", "GET", "http://x/a.jsp", "", "null")
    present = CsicRecord("s2", "anom", "POST", "http://x/a.jsp", "id=1", "25")
    missing_vector = _numeric_vector(missing)
    present_vector = _numeric_vector(present)

    assert np.isnan(missing_vector[3])
    assert missing_vector[4] == 1.0
    assert present_vector[3] == 25.0
    assert present_vector[4] == 0.0
    assert normalize_payload(missing.payload) == "<no_payload>"

    adapter = CsicHttpFeatureAdapter()
    adapter.fit_transform([missing, present, present])
    transformed = adapter.transform([missing])
    assert transformed.combined.shape[0] == 1


def test_session_grouping_isolation_and_coverage():
    records = make_records()
    split = create_group_split(records, seed=42)
    session_splits: dict[str, set[str]] = {}
    for name in ("train", "validation", "test"):
        for record in split.records_for(records, name):
            session_splits.setdefault(record.session, set()).add(name)

    assert session_splits
    assert all(len(names) == 1 for names in session_splits.values())
    assert len(split.session_assignments) == len(session_splits)
    for name in ("train", "validation", "test"):
        rows = split.records_for(records, name)
        assert {record.label for record in rows} == {"norm", "anom"}
    assert sum(len(split.indices[name]) for name in split.indices) == len(records)


def test_group_split_is_reproducible_for_a_fixed_seed():
    records = make_records(sessions=18)
    first = create_group_split(records, seed=7)
    second = create_group_split(records, seed=7)
    assert first.session_assignments == second.session_assignments


def test_group_split_rejects_mixed_label_session():
    records = make_records()
    records[1] = records[1]._replace(label="norm")
    with pytest.raises(ValueError, match="conflicting labels"):
        create_group_split(records, seed=42)


def test_feature_overlap_diagnostics_do_not_hide_conflicts():
    records = make_records()
    split = create_group_split(records, seed=42)
    overlap = analyze_split_overlap(records, split)
    assert "train_vs_test" in overlap["pairwise"]
    assert overlap["sessions_in_multiple_splits"] == 0
    assert overlap["conflicting_label_vectors_overall"] >= 0
    assert overlap["distinct_feature_vectors"] > 0


def test_acceptance_criteria_are_predeclared():
    assert ACCEPTANCE_CRITERIA["minimum_session_pr_auc"] == 0.70
    assert ACCEPTANCE_CRITERIA["minimum_session_recall"] == 0.60
    assert ACCEPTANCE_CRITERIA["maximum_session_false_positive_rate"] == 0.20


def test_compute_metrics_matches_known_result():
    labels = ["norm"] * 5 + ["anom"] * 5
    scores = [0.1] * 5 + [0.9] * 5
    metrics = compute_metrics(labels, scores, threshold=0.5)
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["f1"] == 1.0
    assert metrics["pr_auc"] == 1.0
    assert metrics["balanced_accuracy"] == 1.0
    assert metrics["confusion_matrix"] == {
        "true_negative": 5,
        "false_positive": 0,
        "false_negative": 0,
        "true_positive": 5,
    }
    assert metrics["false_positive_rate"] == 0.0
    assert metrics["per_class"]["anom"]["support"] == 5


def test_session_aggregation_uses_max_score():
    sessions = ["a", "a", "b", "b"]
    scores = [0.1, 0.4, 0.6, 0.7]
    labels = ["norm", "norm", "anom", "anom"]
    metrics = evaluate_predictions(labels, scores, sessions, threshold=0.5)[
        "session_level"
    ]
    assert metrics["sample_count"] == 2
    assert metrics["confusion_matrix"]["true_positive"] == 1
    assert metrics["confusion_matrix"]["true_negative"] == 1


def test_acceptance_check_reports_failure_honestly():
    passing = {
        "session_level": {
            "pr_auc": 0.9,
            "recall": 0.8,
            "false_positive_rate": 0.1,
        }
    }
    baseline = {"session_level": {"pr_auc": 0.5}}
    assert check_acceptance(passing, baseline, 0)["passed"] is True
    failing = {
        "session_level": {
            "pr_auc": 0.4,
            "recall": 0.2,
            "false_positive_rate": 0.6,
        }
    }
    result = check_acceptance(failing, baseline, 1)
    assert result["passed"] is False
    assert any(not value for value in result["checks"].values())


def test_artifact_no_overwrite_guard(tmp_path):
    path = tmp_path / "model.joblib"
    save_artifact(path, {"artifact_version": 1})
    with pytest.raises(FileExistsError):
        save_artifact(path, {"artifact_version": 1})


def test_artifact_roundtrip_and_research_only_prediction(tmp_path):
    records = make_records()
    adapter = CsicHttpFeatureAdapter()
    features = adapter.fit_transform(records)
    specs = build_models(seed=42)
    fitted = fit_models(specs, features)
    name = select_model(
        {
            key: {"session_level": {"pr_auc": 0.5}}
            for key in fitted
        }
    )
    spec = fitted[name]["spec"]
    path = tmp_path / "artifact.joblib"
    save_artifact(
        path,
        {
            "artifact_version": 1,
            "research_only": True,
            "model_name": name,
            "model": fitted[name]["estimator"],
            "adapter": adapter,
            "feature_view": spec["feature_view"],
            "score_kind": spec["score_kind"],
            "threshold": spec["threshold"],
            "feature_schema": adapter.feature_schema_,
            "dataset_sha256": "0" * 64,
            "split_summary": {},
            "evaluation": {},
        },
    )
    artifact = load_artifact(path)
    from app.services.csic_training_service import predict_with_artifact

    predictions = predict_with_artifact(artifact, records[:2])
    assert len(predictions) == 2
    assert all(prediction["research_only"] is True for prediction in predictions)
    assert all(
        prediction["predicted_label"] in {"norm", "anom"} for prediction in predictions
    )


def test_load_artifact_rejects_invalid_structure(tmp_path):
    path = tmp_path / "bad.joblib"
    joblib.dump({"artifact_version": 1}, path)
    with pytest.raises(ValueError):
        load_artifact(path)


def test_report_contains_required_sections():
    report = {
        "provenance": {
            "archive_sha256": "a" * 64,
            "row_count": 10,
            "session_count": 4,
            "limitations": ["research-only benchmark"],
        },
        "selected_model": "tfidf_logistic_regression",
        "split": {
            "seed": 42,
            "splits": {
                "train": {
                    "row_count": 6,
                    "session_count": 2,
                    "label_counts": {"norm": 3, "anom": 3},
                }
            },
        },
        "validation_results": {
            "tfidf_logistic_regression": {
                "session_level": {
                    "pr_auc": 0.8,
                    "recall": 0.7,
                    "f1": 0.7,
                    "false_positive_rate": 0.1,
                }
            }
        },
        "test_results": {
            "tfidf_logistic_regression": {
                "session_level": {
                    "pr_auc": 0.8,
                    "recall": 0.7,
                    "precision": 0.7,
                    "f1": 0.7,
                    "balanced_accuracy": 0.7,
                    "false_positive_rate": 0.1,
                    "confusion_matrix": {},
                },
                "request_level": {"pr_auc": 0.6},
            }
        },
        "acceptance": {"passed": True, "checks": {"minimum_session_pr_auc": True}},
    }
    text = render_report(report)
    assert "Research-only" in text
    assert "tfidf_logistic_regression" in text
    assert "Final held-out test results" in text
    assert "a" * 64 in text
    assert EXPECTED_COLUMNS[0] == "index"
