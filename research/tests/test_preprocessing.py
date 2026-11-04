import math

import pytest

from research.preprocessing.api_traffic import (
    anonymize_principal,
    canonicalize_api_record,
    generate_principal_secret,
)
from research.preprocessing.http_requests import parse_http_request
from research.preprocessing.payload_features import payload_lexical_features


def test_http_parser_removes_sensitive_headers_and_raw_payload():
    parsed = parse_http_request(
        "POST /api/items/123 HTTP/1.1\r\n"
        "Authorization: Bearer secret\r\n"
        "Cookie: session=secret\r\n"
        "Content-Type: application/json\r\n\r\n"
        '{"password":"not-stored"}'
    )
    assert "authorization" not in parsed["safe_headers"]
    assert "cookie" not in parsed["safe_headers"]
    assert "password" not in parsed
    assert parsed["endpoint_template"] == "/api/items/{id}"


def test_payload_features_are_numeric_and_do_not_return_payload():
    features = payload_lexical_features("SELECT 1")
    assert features["payload_length"] == 8
    assert all(isinstance(value, float) for value in features.values())
    assert "payload" not in features


def test_canonicalization_anonymizes_and_filters_sensitive_features():
    event = canonicalize_api_record(
        {
            "event_id": "e1",
            "timestamp": "2026-01-01T00:00:00Z",
            "session_id": "s1",
            "campaign_id": "c1",
            "path": "/users/42",
            "method": "get",
            "status_code": 200,
            "latency_ms": 1,
            "client_features": {"asn": 10, "api_key": 99},
            "label": "normal",
        },
        source_dataset="test",
        principal_value="user@example.invalid",
        principal_secret=bytes(range(32)),
    )
    assert event.principal_id == anonymize_principal(
        "user@example.invalid",
        secret=bytes(range(32)),
    )
    assert event.endpoint_template == "/users/{id}"
    assert "api_key" not in event.client_features


@pytest.mark.parametrize("field", ["event_id", "session_id", "campaign_id"])
def test_canonicalization_rejects_null_identifiers(field):
    record = {
        "event_id": "e1",
        "timestamp": "2026-01-01T00:00:00Z",
        "session_id": "s1",
        "campaign_id": "c1",
        "path": "/items",
        "method": "GET",
        "status_code": 200,
        "label": "normal",
    }
    record[field] = None
    with pytest.raises((ValueError, TypeError)):
        canonicalize_api_record(
            record,
            source_dataset="test",
            principal_value="user",
            principal_secret=bytes(range(32)),
        )


def test_hmac_principal_is_deterministic_and_keyed():
    first = anonymize_principal("user@example.invalid", secret=bytes(range(32)))
    same = anonymize_principal("user@example.invalid", secret=bytes(range(32)))
    different = anonymize_principal("user@example.invalid", secret=bytes(range(1, 33)))
    assert first == same
    assert first != different
    assert len(first) == len("principal_") + 64
    assert len(generate_principal_secret()) == 32


def test_fabricated_principal_cannot_cross_construction_boundary():
    from research.schemas.canonical_event import CanonicalEvent

    with pytest.raises((TypeError, ValueError)):
        CanonicalEvent(
            event_id="e1",
            timestamp="2026-01-01T00:00:00Z",
            principal_id="principal_" + "a" * 64,
            session_id="s1",
            campaign_id="c1",
            method="GET",
            endpoint_template="/items",
            status_code=200,
            latency_ms=1,
            request_size_bytes=0,
            response_size_bytes=0,
            label="normal",
            source_dataset="test",
        )


@pytest.mark.parametrize("secret", ["", "short", b"x" * 31, b"x" * 32])
def test_hmac_principal_rejects_weak_secret(secret):
    with pytest.raises(ValueError, match="32 bytes"):
        anonymize_principal("user@example.invalid", secret=secret)


@pytest.mark.parametrize(
    "headers",
    [
        "Authorization: bearer secret",
        "Cookie: session=secret",
        "Set-Cookie: session=secret",
        "X-API-Key: secret",
        "X-Access-Token: secret",
        "X-Auth-Token: secret",
        "X-CSRF-Token: secret",
        "Password: secret",
    ],
)
def test_credential_like_headers_are_not_returned(headers):
    parsed = parse_http_request(
        "GET /items HTTP/1.1\r\n"
        + headers
        + "\r\n\r\n"
    )
    assert parsed["safe_headers"] == {}


def test_credential_like_user_agent_is_not_returned():
    parsed = parse_http_request(
        "GET /items HTTP/1.1\r\n"
        "User-Agent: bearer secret-token\r\n\r\n"
    )
    assert parsed["safe_headers"] == {}


@pytest.mark.parametrize(
    "target",
    [
        "/items?token=secret&limit=10",
        "/items?ACCESS_TOKEN=secret&sort=name",
        "/items?api%5Fkey=secret&filter=active",
        "/items?password%3D=secret&offset=2",
        "/items?EMAIL=person@example.invalid&format=json",
        "/items?user_id=123&include=details",
        "/items?phone=5551234&fields=name",
    ],
)
def test_sensitive_query_values_are_not_returned(target):
    parsed = parse_http_request(f"GET {target} HTTP/1.1\r\n\r\n")
    assert "secret" not in repr(parsed)
    assert parsed["query_parameter_count"] == 1.0
    assert parsed["safe_query_parameter_categories"] in (
        ["pagination"],
        ["ordering"],
        ["filtering"],
        ["representation"],
    )


def test_benign_query_parameter_names_are_retained_without_values():
    parsed = parse_http_request("GET /items?limit=10&sort=name HTTP/1.1\r\n\r\n")
    assert parsed["path"] == "/items"
    assert parsed["safe_query_parameter_categories"] == ["pagination", "ordering"]
    assert parsed["query_parameter_count"] == 2.0


@pytest.mark.parametrize(
    "name",
    [
        "token",
        "access_token",
        "api_key",
        "key",
        "password",
        "secret",
        "authorization",
        "session",
        "credential",
        "email",
        "user",
        "phone",
        "account_id",
        "ip_address",
    ],
)
def test_sensitive_and_identifying_query_names_are_not_retained(name):
    parsed = parse_http_request(
        f"GET /items?{name}=private-value HTTP/1.1\r\n\r\n"
    )
    assert parsed["query_parameter_count"] == 0.0
    assert parsed["safe_query_parameter_categories"] == []


def test_encoded_and_mixed_case_sensitive_names_are_not_retained():
    parsed = parse_http_request(
        "GET /items?%41%43%43%45%53%53_%54%4f%4b%45%4e=secret"
        "&UsErNaMe=private HTTP/1.1\r\n\r\n"
    )
    assert parsed["query_parameter_count"] == 0.0
    assert parsed["safe_query_parameter_categories"] == []


def test_sql_keyword_counts_and_encoded_traversal():
    features = payload_lexical_features("SeLeCt x UNION y select")
    assert features["sql_keyword_count"] == 3.0
    assert payload_lexical_features("selective reunion")["sql_keyword_count"] == 0.0
    assert payload_lexical_features("%2e%2e%2fetc%2fpasswd")[
        "path_traversal_marker_count"
    ] == 1.0


@pytest.mark.parametrize("features", [[], {"latency": math.nan}, {"latency": math.inf}])
def test_invalid_numeric_features_are_rejected(features):
    with pytest.raises(ValueError):
        canonicalize_api_record(
            {
                "event_id": "e1",
                "timestamp": "2026-01-01T00:00:00Z",
                "session_id": "s1",
                "campaign_id": "c1",
                "path": "/items",
                "method": "GET",
                "status_code": 200,
                "label": "normal",
                "client_features": features,
            },
            source_dataset="test",
            principal_value="user",
            principal_secret=bytes(range(32)),
        )
