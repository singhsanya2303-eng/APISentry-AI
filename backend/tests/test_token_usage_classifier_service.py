
import numpy as np
import pytest

from app.services.token_usage_classifier_service import (
    ABNORMAL_TOKEN_USAGE,
    NORMAL,
    TOKEN_HIJACKING,
    TokenUsageRandomForestClassifier,
)


def make_training_data():
    """Small deterministic example data for unit tests only."""
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
        NORMAL,
        NORMAL,
        NORMAL,
        NORMAL,
        NORMAL,
        NORMAL,
        TOKEN_HIJACKING,
        TOKEN_HIJACKING,
        TOKEN_HIJACKING,
        TOKEN_HIJACKING,
        ABNORMAL_TOKEN_USAGE,
        ABNORMAL_TOKEN_USAGE,
        ABNORMAL_TOKEN_USAGE,
        ABNORMAL_TOKEN_USAGE,
        NORMAL,
    ]

    return features, labels


def make_classifier():
    features, labels = make_training_data()
    classifier = TokenUsageRandomForestClassifier(
        n_estimators=30,
        random_state=42,
    )
    classifier.fit(
        features,
        labels,
        feature_names=["request_count", "unique_paths", "unusual_events"],
    )
    return classifier, features, labels


def test_fit_returns_classifier():
    features, labels = make_training_data()
    classifier = TokenUsageRandomForestClassifier(n_estimators=10)

    result = classifier.fit(features, labels)

    assert result is classifier
    assert classifier.is_fitted is True
    assert len(classifier.feature_names) == 3


def test_predict_returns_valid_class_and_probabilities():
    classifier, features, _ = make_classifier()

    results = classifier.predict(features[:3])

    assert len(results) == 3

    for result in results:
        assert result["predicted_label"] in {
            NORMAL,
            TOKEN_HIJACKING,
            ABNORMAL_TOKEN_USAGE,
        }
        assert 0.0 <= result["confidence"] <= 1.0
        assert set(result["class_probabilities"]) == {
            NORMAL,
            TOKEN_HIJACKING,
            ABNORMAL_TOKEN_USAGE,
        }
        assert sum(result["class_probabilities"].values()) == pytest.approx(1.0)


def test_predict_before_fit_raises_error():
    classifier = TokenUsageRandomForestClassifier()

    with pytest.raises(RuntimeError, match="fitted"):
        classifier.predict([[1, 2, 3]])


def test_fit_rejects_missing_class():
    features, labels = make_training_data()
    normal_only_labels = [NORMAL] * len(labels)
    classifier = TokenUsageRandomForestClassifier(n_estimators=10)

    with pytest.raises(ValueError, match="all three classes"):
        classifier.fit(features, normal_only_labels)


def test_fit_rejects_unknown_label():
    features, labels = make_training_data()
    labels[0] = "Suspicious"
    classifier = TokenUsageRandomForestClassifier(n_estimators=10)

    with pytest.raises(ValueError, match="Unknown label"):
        classifier.fit(features, labels)


def test_fit_rejects_mismatched_label_count():
    features, labels = make_training_data()
    classifier = TokenUsageRandomForestClassifier(n_estimators=10)

    with pytest.raises(ValueError, match="match number of feature rows"):
        classifier.fit(features, labels[:-1])


def test_fit_rejects_non_finite_features():
    features, labels = make_training_data()
    features[0, 0] = np.nan
    classifier = TokenUsageRandomForestClassifier(n_estimators=10)

    with pytest.raises(ValueError, match="finite"):
        classifier.fit(features, labels)


def test_fit_rejects_duplicate_feature_names():
    features, labels = make_training_data()
    classifier = TokenUsageRandomForestClassifier(n_estimators=10)

    with pytest.raises(ValueError, match="unique"):
        classifier.fit(features, labels, feature_names=["count", "count", "other"])


def test_fit_rejects_feature_name_count_mismatch():
    features, labels = make_training_data()
    classifier = TokenUsageRandomForestClassifier(n_estimators=10)

    with pytest.raises(ValueError, match="match feature columns"):
        classifier.fit(features, labels, feature_names=["only_one"])


def test_predict_rejects_wrong_feature_count():
    classifier, _, _ = make_classifier()

    with pytest.raises(ValueError, match="Expected 3 feature columns"):
        classifier.predict([[1, 2]])


def test_evaluate_returns_metrics():
    classifier, features, labels = make_classifier()

    result = classifier.evaluate(features, labels)

    assert result["sample_count"] == len(features)
    assert 0.0 <= result["accuracy"] <= 1.0
    assert len(result["confusion_matrix"]) == 3
    assert len(result["confusion_matrix"][0]) == 3
    assert set(result["labels"]) == {
        NORMAL,
        TOKEN_HIJACKING,
        ABNORMAL_TOKEN_USAGE,
    }


def test_evaluate_before_fit_raises_error():
    classifier = TokenUsageRandomForestClassifier()

    with pytest.raises(RuntimeError, match="fitted"):
        classifier.evaluate([[1, 2, 3]], [NORMAL])


def test_rejects_invalid_estimator_count():
    with pytest.raises(ValueError, match="n_estimators"):
        TokenUsageRandomForestClassifier(n_estimators=0)
