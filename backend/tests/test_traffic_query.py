from datetime import datetime, timedelta, timezone
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.db.base import Base
from app.models.traffic import APITrafficLog
from app.services.traffic_service import (
    save_traffic_log,
    get_traffic_log_by_id,
    get_traffic_log_by_request_id,
    get_traffic_logs,
    count_traffic_logs,
    get_traffic_in_window,
    get_recent_traffic_logs,
)


@pytest.fixture
def db_session():
    """Fixture to create an in-memory SQLite database session for unit testing."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()

    # Seed test data
    now = datetime.now(timezone.utc)
    test_logs = [
        APITrafficLog(
            request_id="req-query-001",
            timestamp=now - timedelta(minutes=30),
            method="GET",
            path="/api/v1/users",
            query_params={"page": "1"},
            client_ip="192.168.1.10",
            user_agent="TestAgent/1.0",
            status_code=200,
            response_time_ms=10.5
        ),
        APITrafficLog(
            request_id="req-query-002",
            timestamp=now - timedelta(minutes=20),
            method="POST",
            path="/api/v1/users",
            query_params={},
            client_ip="192.168.1.10",
            user_agent="TestAgent/1.0",
            status_code=201,
            response_time_ms=25.0
        ),
        APITrafficLog(
            request_id="req-query-003",
            timestamp=now - timedelta(minutes=10),
            method="GET",
            path="/api/v1/orders",
            query_params={"status": "pending"},
            client_ip="10.0.0.5",
            user_agent="OtherAgent/2.0",
            status_code=404,
            response_time_ms=5.2
        ),
        APITrafficLog(
            request_id="req-query-004",
            timestamp=now - timedelta(minutes=5),
            method="POST",
            path="/api/v1/auth/login",
            query_params={"password": "***MASKED***"},
            client_ip="10.0.0.5",
            user_agent="OtherAgent/2.0",
            status_code=500,
            response_time_ms=100.0
        ),
        APITrafficLog(
            request_id="req-query-005",
            timestamp=now,
            method="DELETE",
            path="/api/v1/orders/99",
            query_params={},
            client_ip="172.16.0.1",
            user_agent="AdminTool/1.0",
            status_code=204,
            response_time_ms=12.0
        ),
    ]
    for log in test_logs:
        session.add(log)
    session.commit()

    yield session
    session.close()


def test_get_traffic_log_by_id(db_session):
    record = get_traffic_log_by_request_id("req-query-001", db=db_session)
    assert record is not None
    fetched_by_id = get_traffic_log_by_id(record.id, db=db_session)
    assert fetched_by_id is not None
    assert fetched_by_id.request_id == "req-query-001"
    assert fetched_by_id.path == "/api/v1/users"


def test_get_traffic_log_by_request_id(db_session):
    record = get_traffic_log_by_request_id("req-query-003", db=db_session)
    assert record is not None
    assert record.method == "GET"
    assert record.path == "/api/v1/orders"
    assert record.status_code == 404
    assert record.client_ip == "10.0.0.5"


def test_get_recent_traffic_logs(db_session):
    recent = get_recent_traffic_logs(limit=3, db=db_session)
    assert len(recent) == 3
    # Ordered descending by timestamp
    assert recent[0].request_id == "req-query-005"
    assert recent[1].request_id == "req-query-004"
    assert recent[2].request_id == "req-query-003"


def test_filter_by_path(db_session):
    exact_match = get_traffic_logs(path="/api/v1/users", db=db_session)
    assert len(exact_match) == 2
    assert {r.request_id for r in exact_match} == {"req-query-001", "req-query-002"}

    wildcard_match = get_traffic_logs(path="/api/v1/orders*", db=db_session)
    assert len(wildcard_match) == 2
    assert {r.request_id for r in wildcard_match} == {"req-query-003", "req-query-005"}


def test_filter_by_method(db_session):
    post_logs = get_traffic_logs(method="POST", db=db_session)
    assert len(post_logs) == 2
    assert {r.request_id for r in post_logs} == {"req-query-002", "req-query-004"}


def test_filter_by_status_code(db_session):
    error_logs = get_traffic_logs(status_code=500, db=db_session)
    assert len(error_logs) == 1
    assert error_logs[0].request_id == "req-query-004"


def test_filter_by_client_ip(db_session):
    ip_logs = get_traffic_logs(client_ip="10.0.0.5", db=db_session)
    assert len(ip_logs) == 2
    assert {r.request_id for r in ip_logs} == {"req-query-003", "req-query-004"}


def test_time_range_filtering(db_session):
    now = datetime.now(timezone.utc)
    start_t = now - timedelta(minutes=25)
    end_t = now - timedelta(minutes=8)

    ranged = get_traffic_logs(start_time=start_t, end_time=end_t, db=db_session)
    assert len(ranged) == 2
    assert {r.request_id for r in ranged} == {"req-query-002", "req-query-003"}

    window_logs = get_traffic_in_window(duration_minutes=15, end_time=now, db=db_session)
    assert len(window_logs) == 3
    assert {r.request_id for r in window_logs} == {"req-query-003", "req-query-004", "req-query-005"}


def test_pagination(db_session):
    page_1 = get_traffic_logs(page=1, page_size=2, db=db_session)
    page_2 = get_traffic_logs(page=2, page_size=2, db=db_session)
    page_3 = get_traffic_logs(page=3, page_size=2, db=db_session)

    assert len(page_1) == 2
    assert len(page_2) == 2
    assert len(page_3) == 1

    ids_1 = [r.request_id for r in page_1]
    ids_2 = [r.request_id for r in page_2]
    ids_3 = [r.request_id for r in page_3]

    # Page 1: req-query-005, req-query-004
    # Page 2: req-query-003, req-query-002
    # Page 3: req-query-001
    assert set(ids_1).isdisjoint(set(ids_2))
    assert set(ids_2).isdisjoint(set(ids_3))


def test_count_functionality(db_session):
    total_count = count_traffic_logs(db=db_session)
    assert total_count == 5

    post_count = count_traffic_logs(method="POST", db=db_session)
    assert post_count == 2

    ip_count = count_traffic_logs(client_ip="192.168.1.10", db=db_session)
    assert ip_count == 2


def test_empty_results(db_session):
    empty_logs = get_traffic_logs(path="/nonexistent/path", db=db_session)
    assert empty_logs == []

    empty_count = count_traffic_logs(client_ip="99.99.99.99", db=db_session)
    assert empty_count == 0

    nonexistent_id = get_traffic_log_by_id(999999, db=db_session)
    assert nonexistent_id is None


def test_combined_filters(db_session):
    filtered = get_traffic_logs(
        method="POST",
        client_ip="10.0.0.5",
        status_code=500,
        db=db_session
    )
    assert len(filtered) == 1
    assert filtered[0].request_id == "req-query-004"
    assert filtered[0].query_params == {"password": "***MASKED***"}
