
import numpy as np
import pytest

from app.services.behavior_feature_vector_service import (
    BehaviorFeatureVectorizer,
)


def make_profiles():
    return [
        {
            "client_ip": "192.0.2.10",
            "total_requests": 10,
            "unique_http_methods": 2,
            "unique_endpoints": 3,
            "http_method_counts": {"GET": 8, "POST": 2},
        },
        {
            "client_ip": "192.0.2.11",
            "total_requests": 20,
            "unique_http_methods": 3,
            "unique_endpoints": 5,
            "http_method_counts": {"GET": 10, "POST": 5, "DELETE": 5},
        },
        {
            "client_ip": "192.0.2.12",
            "total_requests": 5,
            "unique_http_methods": 1,
            "unique_endpoints": 2,
            "http_method_counts": {"GET": 5},
        },
    ]


def test_fit_transform_returns_numeric_matrix():
    vectorizer = BehaviorFeatureVectorizer()
    matrix = vectorizer.fit_transform(make_profiles())

    assert matrix.shape == (3, 8)
    assert np.isfinite(matrix).all()


def test_feature_names_are_consistent():
    vectorizer = BehaviorFeatureVectorizer()
    vectorizer.fit(make_profiles())

    assert vectorizer.get_feature_names() == [
        "total_requests",
        "unique_http_methods",
        "unique_endpoints",
        "method_count_DELETE",
        "method_count_GET",
        "method_count_PATCH",
        "method_count_POST",
        "method_count_PUT",
    ]


def test_transform_requires_fit():
    vectorizer = BehaviorFeatureVectorizer()

    with pytest.raises(RuntimeError, match="fitted"):
        vectorizer.transform(make_profiles())


def test_transform_uses_training_scaler():
    profiles = make_profiles()
    vectorizer = BehaviorFeatureVectorizer()
    training_matrix = vectorizer.fit_transform(profiles)
    transformed_again = vectorizer.transform(profiles)

    np.testing.assert_allclose(training_matrix, transformed_again)


def test_rejects_negative_request_count():
    profiles = make_profiles()
    profiles[0]["total_requests"] = -1

    vectorizer = BehaviorFeatureVectorizer()

    with pytest.raises(ValueError, match="non-negative"):
        vectorizer.fit(profiles)


def test_rejects_invalid_method_counts():
    profiles = make_profiles()
    profiles[0]["http_method_counts"]["GET"] = float("nan")

    vectorizer = BehaviorFeatureVectorizer()

    with pytest.raises(ValueError, match="HTTP method counts"):
        vectorizer.fit(profiles)


def test_client_ip_is_not_used_as_feature():
    vectorizer = BehaviorFeatureVectorizer()
    vectorizer.fit(make_profiles())

    assert "client_ip" not in vectorizer.get_feature_names()
