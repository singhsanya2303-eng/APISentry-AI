
import numpy as np
import pytest

from app.services.token_usage_classifier_service import (
    ABNORMAL_TOKEN_USAGE,
    NORMAL,
    TOKEN_HIJACKING,
    TokenUsageRandomForestClassifier,
)


def training_data():
    features = np.array(
        [
            [1, 1, 0],
            [2, 1, 0],
            [1, 2, 0],
            [2, 2, 0],
            [1, 1, 1],
            [2, 1, 1],
            [8, 5, 4],
            [9, 6, 4],
            [8, 6, 5],
            [9, 5, 5],
            [4, 8, 2],
            [5, 9, 2],
            [4, 9, 3],
            [5, 8, 3],
            [3, 3, 1],
        ],
        dtype=float,
    )
    labels = [
        NORMAL, NORMAL, NORMAL, NORMAL, NORMAL,
        NORMAL, TOKEN_HIJACKING, TOKEN_HIJACKING,
        TOKEN_HIJACKING, TOKEN_HIJACKING,
        ABNORMAL_TOKEN_USAGE, ABNORMAL_TOKEN_USAGE,
        ABNORMAL_TOKEN_USAGE, ABNORMAL_TOKEN_USAGE, NORMAL,
    ]
    names = ["request_count", "unique_paths", "unusual_events"]
    return features, labels, names


def test_save_and_load_preserves_predictions(tmp_path):
    features, labels, names = training_data()
    classifier = TokenUsageRandomForestClassifier(
        n_estimators=30, random_state=42
    ).fit(features, labels, feature_names=names)

    before = classifier.predict(features[:5])
    checkpoint = tmp_path / "models" / "token_classifier.joblib"
    classifier.save(str(checkpoint))

    loaded = TokenUsageRandomForestClassifier.load(str(checkpoint))
    after = loaded.predict(features[:5])

    assert loaded.is_fitted
    assert loaded.feature_names == names
    assert after == before


def test_save_rejects_unfitted_classifier(tmp_path):
    classifier = TokenUsageRandomForestClassifier()

    with pytest.raises(RuntimeError, match="unfitted"):
        classifier.save(str(tmp_path / "model.joblib"))


def test_load_rejects_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError, match="not found"):
        TokenUsageRandomForestClassifier.load(str(tmp_path / "missing.joblib"))


def test_loaded_model_rejects_wrong_feature_count(tmp_path):
    features, labels, names = training_data()
    classifier = TokenUsageRandomForestClassifier(
        n_estimators=10
    ).fit(features, labels, feature_names=names)

    checkpoint = tmp_path / "model.joblib"
    classifier.save(str(checkpoint))
    loaded = TokenUsageRandomForestClassifier.load(str(checkpoint))

    with pytest.raises(ValueError, match="Expected 3 feature columns"):
        loaded.predict([[1, 2]])


def test_save_creates_parent_directory(tmp_path):
    features, labels, names = training_data()
    classifier = TokenUsageRandomForestClassifier(
        n_estimators=10
    ).fit(features, labels, feature_names=names)

    checkpoint = tmp_path / "nested" / "models" / "classifier.joblib"
    classifier.save(str(checkpoint))

    assert checkpoint.is_file()
