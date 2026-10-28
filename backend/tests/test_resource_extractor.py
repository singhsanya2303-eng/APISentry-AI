from datetime import datetime, timezone
import pytest
from app.services.resource_extractor import (
    extract_resource_access_event,
    extract_candidate_resources,
    extract_safe_actor_id
)
from app.models.traffic import APITrafficLog
from app.services.resource_extractor import extract_from_traffic_log


def test_single_user_path_extraction():
    now = datetime.now(timezone.utc)
    event = extract_resource_access_event(
        request_id="req-user-123",
        timestamp=now,
        method="GET",
        path="/users/123",
        client_ip="192.168.1.1",
        status_code=200
    )

    assert event.has_object_reference is True
    assert len(event.extracted_resources) == 1
    assert event.normalized_endpoint == "/users/{user_id}"

    res = event.primary_resource
    assert res is not None
    assert res.resource_type == "users"
    assert res.resource_id == "123"
    assert res.is_numeric is True
    assert res.is_uuid is False
    assert res.confidence == 0.90
    assert event.parent_resource is None


def test_single_order_path_extraction():
    now = datetime.now(timezone.utc)
    event = extract_resource_access_event(
        request_id="req-order-5001",
        timestamp=now,
        method="GET",
        path="/orders/5001",
        client_ip="10.0.0.1",
        status_code=200
    )

    assert event.has_object_reference is True
    assert event.normalized_endpoint == "/orders/{order_id}"
    assert event.primary_resource.resource_type == "orders"
    assert event.primary_resource.resource_id == "5001"


def test_nested_resource_path_extraction():
    now = datetime.now(timezone.utc)
    event = extract_resource_access_event(
        request_id="req-nested-42-91",
        timestamp=now,
        method="GET",
        path="/api/v1/accounts/42/orders/91",
        client_ip="172.16.0.10",
        status_code=200
    )

    assert event.has_object_reference is True
    assert len(event.extracted_resources) == 2
    assert event.normalized_endpoint == "/api/v1/accounts/{account_id}/orders/{order_id}"

    parent = event.parent_resource
    primary = event.primary_resource

    assert parent is not None
    assert parent.resource_type == "accounts"
    assert parent.resource_id == "42"

    assert primary is not None
    assert primary.resource_type == "orders"
    assert primary.resource_id == "91"


def test_uuid_resource_extraction():
    now = datetime.now(timezone.utc)
    uuid_str = "550e8400-e29b-41d4-a716-446655440000"
    event = extract_resource_access_event(
        request_id="req-uuid-doc",
        timestamp=now,
        method="GET",
        path=f"/documents/{uuid_str}",
        client_ip="192.168.1.5",
        status_code=200
    )

    assert event.has_object_reference is True
    assert len(event.extracted_resources) == 1
    assert event.normalized_endpoint == "/documents/{document_id}"

    res = event.primary_resource
    assert res.resource_type == "documents"
    assert res.resource_id == uuid_str
    assert res.is_uuid is True
    assert res.is_numeric is False
    assert res.confidence == 0.95


def test_alphanumeric_identifier_extraction():
    now = datetime.now(timezone.utc)
    event = extract_resource_access_event(
        request_id="req-alpha-item",
        timestamp=now,
        method="GET",
        path="/items/usr_abc123",
        client_ip="10.0.0.2",
        status_code=200
    )

    assert event.has_object_reference is True
    assert len(event.extracted_resources) == 1
    assert event.normalized_endpoint == "/items/{item_id}"
    assert event.primary_resource.resource_id == "usr_abc123"
    assert event.primary_resource.is_numeric is False
    assert event.primary_resource.is_uuid is False
    assert event.primary_resource.confidence == 0.85


def test_static_health_path_extraction():
    now = datetime.now(timezone.utc)
    event = extract_resource_access_event(
        request_id="req-health",
        timestamp=now,
        method="GET",
        path="/health",
        client_ip="127.0.0.1",
        status_code=200
    )

    assert event.has_object_reference is False
    assert len(event.extracted_resources) == 0
    assert event.normalized_endpoint == "/health"
    assert event.primary_resource is None
    assert event.parent_resource is None


def test_static_user_profile_path_extraction():
    now = datetime.now(timezone.utc)
    event = extract_resource_access_event(
        request_id="req-profile",
        timestamp=now,
        method="GET",
        path="/users/profile",
        client_ip="127.0.0.1",
        status_code=200
    )

    assert event.has_object_reference is False
    assert len(event.extracted_resources) == 0
    assert event.normalized_endpoint == "/users/profile"
    assert event.primary_resource is None


def test_malformed_path_extraction():
    now = datetime.now(timezone.utc)
    event = extract_resource_access_event(
        request_id="req-malformed",
        timestamp=now,
        method="GET",
        path="///",
        client_ip="127.0.0.1",
        status_code=400
    )

    assert event.has_object_reference is False
    assert event.normalized_endpoint == "/"
    assert len(event.extracted_resources) == 0


def test_ambiguous_path_extraction():
    now = datetime.now(timezone.utc)
    event = extract_resource_access_event(
        request_id="req-ambiguous",
        timestamp=now,
        method="GET",
        path="/123/456",
        client_ip="127.0.0.1",
        status_code=200
    )

    assert event.has_object_reference is True
    assert len(event.extracted_resources) == 2
    assert event.normalized_endpoint == "/{id}/{id}"

    # Ambiguous paths are marked with lower confidence score (< 0.5)
    for res in event.extracted_resources:
        assert res.confidence < 0.50


def test_multiple_candidate_resources_in_path():
    now = datetime.now(timezone.utc)
    event = extract_resource_access_event(
        request_id="req-multi-res",
        timestamp=now,
        method="GET",
        path="/orgs/10/projects/20/tasks/30",
        client_ip="10.0.0.1",
        status_code=200
    )

    assert event.has_object_reference is True
    assert len(event.extracted_resources) == 3
    assert event.normalized_endpoint == "/orgs/{org_id}/projects/{project_id}/tasks/{task_id}"

    types = [r.resource_type for r in event.extracted_resources]
    ids = [r.resource_id for r in event.extracted_resources]

    assert types == ["orgs", "projects", "tasks"]
    assert ids == ["10", "20", "30"]
    assert event.parent_resource.resource_id == "20"
    assert event.primary_resource.resource_id == "30"


def test_credential_exclusion_and_safe_actor_id():
    now = datetime.now(timezone.utc)
    headers = {
        "Authorization": "Bearer secret_jwt_token_12345",
        "Cookie": "session_id=super_secret_session_99",
        "X-API-Key": "my_secret_api_key",
        "X-User-ID": "user_actor_888"
    }
    query_params = {
        "password": "***MASKED***",
        "user_id": "user_actor_888"
    }

    event = extract_resource_access_event(
        request_id="req-safe-actor",
        timestamp=now,
        method="POST",
        path="/api/v1/accounts/55",
        client_ip="192.168.1.20",
        status_code=200,
        headers=headers,
        query_params=query_params
    )

    # Verify actor_id is extracted safely from X-User-ID / user_id
    assert event.actor_id == "user_actor_888"

    # Verify sensitive token values are NOT stored in any schema attribute
    event_dict = event.model_dump_json()
    assert "secret_jwt_token_12345" not in event_dict
    assert "super_secret_session_99" not in event_dict
    assert "my_secret_api_key" not in event_dict


def test_extract_from_traffic_log_orm():
    now = datetime.now(timezone.utc)
    log = APITrafficLog(
        request_id="req-orm-test-99",
        timestamp=now,
        method="GET",
        path="/users/44",
        query_params={},
        client_ip="127.0.0.1",
        user_agent="TestAgent",
        status_code=200,
        response_time_ms=10.0
    )

    event = extract_from_traffic_log(log, headers={"X-Actor-ID": "actor_44"})
    assert event.request_id == "req-orm-test-99"
    assert event.actor_id == "actor_44"
    assert event.primary_resource.resource_id == "44"
    assert event.normalized_endpoint == "/users/{user_id}"
