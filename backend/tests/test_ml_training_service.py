import numpy as np
import pytest

from app.services.ml_training_service import (
    load_token_classifier_pipeline,
    train_token_classifier_pipeline,
)
from app.services.token_usage_classifier_service import (
    ABNORMAL_TOKEN_USAGE,
    NORMAL,
    TOKEN_HIJACKING,
    TokenUsageRandomForestClassifier,
)


def training_rows():
    return training_rows_with_counts(
        {NORMAL: 6, TOKEN_HIJACKING: 6, ABNORMAL_TOKEN_USAGE: 6}
    )


def training_rows_with_counts(counts):
    bases = {NORMAL: 1, TOKEN_HIJACKING: 10, ABNORMAL_TOKEN_USAGE: 20}
    rows = []
    labels = []
    for label, count in counts.items():
        for offset in range(count):
            rows.append(
                {
                    "requests": bases[label] + offset,
                    "failures": bases[label] + offset / 10,
                }
            )
            labels.append(label)
    return rows, labels


def test_training_pipeline_persists_compatible_artifact(tmp_path):
    rows, labels = training_rows()
    result = train_token_classifier_pipeline(
        rows,
        labels,
        ["requests", "failures"],
        tmp_path / "pipeline.joblib",
    )

    assert result["test"]["sample_count"] > 0
    artifact = load_token_classifier_pipeline(tmp_path / "pipeline.joblib")
    predictions = artifact["model"].predict(
        artifact["scaler"].transform(np.asarray([[2, 1.0]]))
    )
    assert predictions[0] in {NORMAL, TOKEN_HIJACKING, ABNORMAL_TOKEN_USAGE}


def test_token_usage_classifier_loads_pipeline_artifact_and_scales_features(tmp_path):
    rows, labels = training_rows()
    path = tmp_path / "pipeline.joblib"
    train_token_classifier_pipeline(
        rows,
        labels,
        ["requests", "failures"],
        path,
    )

    classifier = TokenUsageRandomForestClassifier.load(str(path))
    assert classifier.feature_names == ["requests", "failures"]
    assert classifier.scaler is not None
    assert classifier.is_fitted is True

    predictions = classifier.predict([[2.0, 1.0]])
    assert len(predictions) == 1
    assert predictions[0]["predicted_label"] in {NORMAL, TOKEN_HIJACKING, ABNORMAL_TOKEN_USAGE}
    assert 0.0 <= predictions[0]["confidence"] <= 1.0
    assert set(predictions[0]["class_probabilities"].keys()) == {NORMAL, TOKEN_HIJACKING, ABNORMAL_TOKEN_USAGE}


def test_training_pipeline_rejects_non_finite_values(tmp_path):
    rows, labels = training_rows()
    rows[0]["requests"] = float("nan")

    with pytest.raises(ValueError, match="finite"):
        train_token_classifier_pipeline(
            rows,
            labels,
            ["requests", "failures"],
            tmp_path / "pipeline.joblib",
        )


def test_training_pipeline_rejects_incompatible_artifact(tmp_path):
    rows, labels = training_rows()
    path = tmp_path / "pipeline.joblib"
    train_token_classifier_pipeline(rows, labels, ["requests", "failures"], path)
    import joblib

    artifact = joblib.load(path)
    artifact["feature_names"] = ["requests"]
    joblib.dump(artifact, path)

    with pytest.raises(ValueError, match="incompatible"):
        load_token_classifier_pipeline(path)


# --- F02 regression: the minimum is set by the two-stage stratified split -----
# With the default 0.2 validation / 0.2 test configuration, stage 1 sends 40% of
# every class to the held-out set and stage 2 splits that set again. scikit-learn
# needs at least two samples of every class in the held-out set, so the minimum
# is 5 per class (not 3). 3 and 4 samples previously passed validation and then
# failed inside the second train_test_split. The check now runs before either
# split, keeps train-only scaler fitting, and does not change split boundaries.


@pytest.mark.parametrize("per_class", [3, 4])
def test_training_pipeline_rejects_samples_below_split_minimum(tmp_path, per_class):
    rows, labels = training_rows_with_counts(
        {NORMAL: per_class, TOKEN_HIJACKING: per_class, ABNORMAL_TOKEN_USAGE: per_class}
    )
    artifact = tmp_path / "pipeline.joblib"

    with pytest.raises(ValueError, match=r"At least 5 samples per class") as exc:
        train_token_classifier_pipeline(
            rows, labels, ["requests", "failures"], artifact
        )

    message = str(exc.value)
    assert "two-stage stratified split" in message
    assert f"least-represented class has {per_class} sample(s)" in message
    # Rejected before either split or any artifact persistence.
    assert not artifact.exists()


@pytest.mark.parametrize("per_class", [5, 6, 12])
def test_training_pipeline_accepts_samples_at_or_above_split_minimum(
    tmp_path, per_class
):
    rows, labels = training_rows_with_counts(
        {NORMAL: per_class, TOKEN_HIJACKING: per_class, ABNORMAL_TOKEN_USAGE: per_class}
    )
    result = train_token_classifier_pipeline(
        rows, labels, ["requests", "failures"], tmp_path / "pipeline.joblib"
    )

    for partition in ("train", "validation", "test"):
        assert result[partition]["sample_count"] > 0
        report = result[partition]["classification_report"]
        assert {NORMAL, TOKEN_HIJACKING, ABNORMAL_TOKEN_USAGE}.issubset(report)


def test_training_pipeline_minimum_tracks_split_configuration(tmp_path):
    rows, labels = training_rows_with_counts(
        {NORMAL: 5, TOKEN_HIJACKING: 5, ABNORMAL_TOKEN_USAGE: 5}
    )

    # Five is enough for 0.2/0.2 but not for a 0.1/0.1 split (held-out is 20%,
    # so one sample per class would reach the second split).
    with pytest.raises(ValueError, match=r"At least 10 samples per class"):
        train_token_classifier_pipeline(
            rows,
            labels,
            ["requests", "failures"],
            tmp_path / "pipeline.joblib",
            validation_size=0.1,
            test_size=0.1,
        )


def test_training_pipeline_rejects_missing_class(tmp_path):
    rows, labels = training_rows_with_counts({NORMAL: 10, TOKEN_HIJACKING: 10})

    with pytest.raises(ValueError, match="all token-usage classes"):
        train_token_classifier_pipeline(
            rows, labels, ["requests", "failures"], tmp_path / "pipeline.joblib"
        )


def test_training_pipeline_rejects_imbalanced_class_below_minimum(tmp_path):
    # Total (63) would satisfy the old aggregate check; one class at 3 must be
    # rejected by the per-class, pre-split validation.
    rows, labels = training_rows_with_counts(
        {NORMAL: 30, TOKEN_HIJACKING: 30, ABNORMAL_TOKEN_USAGE: 3}
    )

    with pytest.raises(ValueError, match="least-represented class has 3 sample"):
        train_token_classifier_pipeline(
            rows, labels, ["requests", "failures"], tmp_path / "pipeline.joblib"
        )
