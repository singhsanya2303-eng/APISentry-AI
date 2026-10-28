"""
Tests for Behavioral Analysis & Risk Scoring FastAPI Endpoint — Module 7, Step 3.

Endpoint:
    GET /api/v1/security/behavior/analyze

Scenarios covered:
  1. Endpoint exists (HTTP 200)
  2. Empty traffic returns valid empty results
  3. Normal traffic returns LOW risk score
  4. Single client attribution
  5. Multiple clients analyzed independently
  6. Client aggregation integrity
  7. Risk score returned in range [0, 100]
  8. Categorical risk level returned (LOW, MEDIUM, HIGH, CRITICAL)
  9. Risk factors and evidence list returned
  10. Neutral, factual explanation returned
  11. BOLA signal reaches risk scoring
  12. Brute-force signal reaches risk scoring
  13. Rate anomaly signal reaches risk scoring
  14. Mixed suspicious signals compounded
  15. start_time filter
  16. end_time filter
  17. method filter
  18. path filter
  19. status_code filter
  20. client_ip filter
  21. Pagination validation (page < 1, page_size < 1, page_size > 500)
  22. Invalid date range (start_time > end_time) returns HTTP 422
  23. Invalid risk weight overrides (< 0.0 or > 100.0) return HTTP 422
  24. Missing client IP handled safely (not fabricated)
  25. Missing actor handled safely
  26. Empty result does not fabricate client entries
  27. Deterministic response ordering by client_ip
  28. No sensitive credential leakage in response
  29. Neutral explanation wording without attacker confirmation
  30. Malformed traffic handled defensively
  31. Configurable risk weight overrides via query params
  32. Existing security endpoints (BOLA, Brute-Force, Rate Anomaly, Health) remain operational
"""

from datetime import datetime, timedelta, timezone
from urllib.parse import quote
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.db.base import Base
from app.db.session import get_db
from app.models.traffic import APITrafficLog
from app.services.behavior_analysis_service import analyze_traffic_for_behavior_risk

client = TestClient(app)


@pytest.fixture
def override_db():
    """Fixture overriding get_db dependency with isolated in-memory SQLite database."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    def _get_test_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _get_test_db
    yield TestingSessionLocal
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# 1. Endpoint Exists
# ---------------------------------------------------------------------------

def test_scenario_1_endpoint_exists(override_db):
    response = client.get("/api/v1/security/behavior/analyze")
    assert response.status_code == 200
    data = response.json()
    assert "results" in data
    assert "total_clients" in data
    assert "total_events_analyzed" in data
    assert "summary" in data


# ---------------------------------------------------------------------------
# 2. Empty Traffic Result
# ---------------------------------------------------------------------------

def test_scenario_2_empty_traffic(override_db):
    response = client.get("/api/v1/security/behavior/analyze")
    assert response.status_code == 200
    data = response.json()
    assert data["results"] == []
    assert data["total_clients"] == 0
    assert data["total_events_analyzed"] == 0
    assert data["observation_start"] is None
    assert data["observation_end"] is None
    assert "No traffic events" in data["summary"]


# ---------------------------------------------------------------------------
# 3. Normal Traffic
# ---------------------------------------------------------------------------

def test_scenario_3_normal_traffic(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(
            request_id=f"norm-{i}",
            timestamp=now - timedelta(seconds=i * 5),
            method="GET",
            path=f"/api/v1/users/{i}",
            query_params={},
            client_ip="192.168.1.10",
            user_agent="Browser",
            status_code=200,
            response_time_ms=12.0
        )
        for i in range(1, 4)
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    response = client.get("/api/v1/security/behavior/analyze")
    assert response.status_code == 200
    data = response.json()
    assert data["total_clients"] == 1
    assert data["total_events_analyzed"] == 3
    assert len(data["results"]) == 1

    res = data["results"][0]
    assert res["client_ip"] == "192.168.1.10"
    assert res["risk_score"] == 0.0
    assert res["risk_level"] == "LOW"
    assert len(res["factors"]) == 0
    assert "Normal baseline API behavior" in res["explanation"]


# ---------------------------------------------------------------------------
# 4. Single Client Attribution
# ---------------------------------------------------------------------------

def test_scenario_4_single_client(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(
            request_id=f"sc-{i}",
            timestamp=now - timedelta(seconds=i),
            method="GET",
            path="/api/v1/products",
            query_params={},
            client_ip="10.0.0.50",
            user_agent="Agent",
            status_code=200,
            response_time_ms=10.0
        )
        for i in range(1, 5)
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    response = client.get("/api/v1/security/behavior/analyze")
    assert response.status_code == 200
    data = response.json()
    assert data["total_clients"] == 1
    assert data["results"][0]["client_ip"] == "10.0.0.50"


# ---------------------------------------------------------------------------
# 5. Multiple Clients
# ---------------------------------------------------------------------------

def test_scenario_5_multiple_clients(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(
            request_id=f"mc-a-{i}",
            timestamp=now - timedelta(seconds=i * 2),
            method="GET",
            path="/api/v1/items",
            query_params={},
            client_ip="10.0.0.1",
            user_agent="A",
            status_code=200,
            response_time_ms=8.0
        )
        for i in range(1, 3)
    ] + [
        APITrafficLog(
            request_id=f"mc-b-{i}",
            timestamp=now - timedelta(seconds=i * 2),
            method="GET",
            path="/api/v1/items",
            query_params={},
            client_ip="10.0.0.2",
            user_agent="B",
            status_code=200,
            response_time_ms=8.0
        )
        for i in range(1, 4)
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    response = client.get("/api/v1/security/behavior/analyze")
    assert response.status_code == 200
    data = response.json()
    assert data["total_clients"] == 2
    assert data["total_events_analyzed"] == 5

    ips = [r["client_ip"] for r in data["results"]]
    assert ips == ["10.0.0.1", "10.0.0.2"]


# ---------------------------------------------------------------------------
# 6. Client Aggregation (Separate Scores)
# ---------------------------------------------------------------------------

def test_scenario_6_client_aggregation(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    # Client A: 5 auth failures (high risk)
    # Client B: 2 successful requests (low risk)
    logs = [
        APITrafficLog(
            request_id=f"ca-a-{i}",
            timestamp=now - timedelta(seconds=i),
            method="POST",
            path="/api/v1/auth/login",
            query_params={},
            client_ip="192.168.1.100",
            user_agent="Bot",
            status_code=401,
            response_time_ms=15.0
        )
        for i in range(1, 6)
    ] + [
        APITrafficLog(
            request_id=f"ca-b-{i}",
            timestamp=now - timedelta(seconds=i * 10),
            method="GET",
            path="/api/v1/dashboard",
            query_params={},
            client_ip="192.168.1.200",
            user_agent="User",
            status_code=200,
            response_time_ms=25.0
        )
        for i in range(1, 3)
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    response = client.get("/api/v1/security/behavior/analyze")
    assert response.status_code == 200
    data = response.json()
    assert len(data["results"]) == 2

    res_a = next(r for r in data["results"] if r["client_ip"] == "192.168.1.100")
    res_b = next(r for r in data["results"] if r["client_ip"] == "192.168.1.200")

    assert res_a["risk_score"] > 0.0
    assert res_b["risk_score"] == 0.0


# ---------------------------------------------------------------------------
# 7. Risk Score Returned
# ---------------------------------------------------------------------------

def test_scenario_7_risk_score_returned(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(
            request_id=f"rs-{i}",
            timestamp=now - timedelta(seconds=i),
            method="POST",
            path="/api/v1/auth/login",
            query_params={},
            client_ip="10.10.10.10",
            user_agent="Attacker",
            status_code=401,
            response_time_ms=10.0
        )
        for i in range(1, 6)
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    response = client.get("/api/v1/security/behavior/analyze")
    assert response.status_code == 200
    data = response.json()
    res = data["results"][0]
    assert 0.0 <= res["risk_score"] <= 100.0
    # 5 auth failures (HTTP 401) on /api/v1/auth/login score 15.0 from authentication_failures.
    # The brute-force detector also fires (5 failures >= threshold=5 within window),
    # adding brute_force_activity (35.0). Total: 15.0 + 35.0 = 50.0.
    assert res["risk_score"] == 50.0


# ---------------------------------------------------------------------------
# 8. Risk Level Returned
# ---------------------------------------------------------------------------

def test_scenario_8_risk_level_returned(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(
            request_id=f"rl-{i}",
            timestamp=now - timedelta(seconds=i),
            method="GET",
            path="/api/v1/data",
            query_params={},
            client_ip="10.20.30.40",
            user_agent="Agent",
            status_code=200,
            response_time_ms=5.0
        )
        for i in range(1, 3)
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    response = client.get("/api/v1/security/behavior/analyze")
    assert response.status_code == 200
    data = response.json()
    assert data["results"][0]["risk_level"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert data["results"][0]["risk_level"] == "LOW"


# ---------------------------------------------------------------------------
# 9. Risk Factors Returned
# ---------------------------------------------------------------------------

def test_scenario_9_risk_factors_returned(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(
            request_id=f"rf-{i}",
            timestamp=now - timedelta(seconds=i),
            method="POST",
            path="/api/v1/login",
            query_params={},
            client_ip="172.16.0.5",
            user_agent="Bot",
            status_code=401,
            response_time_ms=10.0
        )
        for i in range(1, 6)
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    response = client.get("/api/v1/security/behavior/analyze")
    assert response.status_code == 200
    data = response.json()
    factors = data["results"][0]["factors"]
    assert len(factors) >= 1
    assert factors[0]["factor_name"] == "authentication_failures"
    assert factors[0]["contribution"] == 15.0
    assert factors[0]["triggered"] is True
    assert "authentication failure" in factors[0]["evidence"]


# ---------------------------------------------------------------------------
# 10. Explanation Returned
# ---------------------------------------------------------------------------

def test_scenario_10_explanation_returned(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(
            request_id=f"exp-{i}",
            timestamp=now - timedelta(seconds=i),
            method="POST",
            path="/api/v1/auth",
            query_params={},
            client_ip="172.16.0.10",
            user_agent="Bot",
            status_code=401,
            response_time_ms=10.0
        )
        for i in range(1, 4)
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    response = client.get("/api/v1/security/behavior/analyze")
    assert response.status_code == 200
    data = response.json()
    exp = data["results"][0]["explanation"]
    assert "Risk score is" in exp
    assert "authentication failures" in exp


# ---------------------------------------------------------------------------
# 11. BOLA Signal Reaches Risk Scoring
# ---------------------------------------------------------------------------

def test_scenario_11_bola_signal_reaches_risk_scoring(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    log = APITrafficLog(
        request_id="bola-1",
        timestamp=now,
        method="GET",
        path="/api/v1/users/123",
        query_params={},
        client_ip="192.168.1.50",
        user_agent="Tester",
        status_code=200,
        response_time_ms=10.0
    )
    session.add(log)
    session.commit()

    # Pass signals_map directly to verify BOLA integration
    res = analyze_traffic_for_behavior_risk(
        signals_map={"bola-1": {"detection_source": "bola", "detection_verdict": "suspicious_bola_candidate"}},
        db=session
    )
    session.close()

    assert res.total_clients == 1
    assert res.results[0].risk_score >= 22.0
    factor_names = [f.factor_name for f in res.results[0].factors]
    assert "bola_activity" in factor_names


# ---------------------------------------------------------------------------
# 12. Brute-Force Signal Reaches Risk Scoring
# ---------------------------------------------------------------------------

def test_scenario_12_bruteforce_signal_reaches_risk_scoring(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    log = APITrafficLog(
        request_id="bf-1",
        timestamp=now,
        method="POST",
        path="/api/v1/auth/login",
        query_params={},
        client_ip="192.168.1.60",
        user_agent="Tester",
        status_code=401,
        response_time_ms=10.0
    )
    session.add(log)
    session.commit()

    res = analyze_traffic_for_behavior_risk(
        signals_map={"bf-1": {"detection_source": "bruteforce", "detection_verdict": "suspicious_bruteforce_candidate"}},
        db=session
    )
    session.close()

    assert res.total_clients == 1
    factor_names = [f.factor_name for f in res.results[0].factors]
    assert "brute_force_activity" in factor_names


# ---------------------------------------------------------------------------
# 13. Rate Anomaly Signal Reaches Risk Scoring
# ---------------------------------------------------------------------------

def test_scenario_13_rate_anomaly_signal_reaches_risk_scoring(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    log = APITrafficLog(
        request_id="ra-1",
        timestamp=now,
        method="GET",
        path="/api/v1/orders",
        query_params={},
        client_ip="192.168.1.70",
        user_agent="Tester",
        status_code=200,
        response_time_ms=5.0
    )
    session.add(log)
    session.commit()

    res = analyze_traffic_for_behavior_risk(
        signals_map={"ra-1": {"detection_source": "rate_anomaly", "detection_verdict": "suspicious_rate_anomaly"}},
        db=session
    )
    session.close()

    assert res.total_clients == 1
    factor_names = [f.factor_name for f in res.results[0].factors]
    assert "rate_anomaly_activity" in factor_names


# ---------------------------------------------------------------------------
# 14. Mixed Signals Compounded
# ---------------------------------------------------------------------------

def test_scenario_14_mixed_signals_compounded(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(
            request_id=f"mix-{i}",
            timestamp=now - timedelta(seconds=i),
            method="POST",
            path=f"/api/v1/orders/{i}",
            query_params={},
            client_ip="10.0.0.99",
            user_agent="Bot",
            status_code=401,
            response_time_ms=10.0
        )
        for i in range(1, 6)
    ]
    session.add_all(logs)
    session.commit()

    signals = {
        "mix-1": {"detection_source": "bola", "detection_verdict": "suspicious_bola_candidate"},
        "mix-2": {"detection_source": "bruteforce", "detection_verdict": "suspicious_bruteforce_candidate"},
        "mix-3": {"detection_source": "rate_anomaly", "detection_verdict": "suspicious_rate_anomaly"},
    }
    res = analyze_traffic_for_behavior_risk(signals_map=signals, db=session)
    session.close()

    assert res.total_clients == 1
    r = res.results[0]
    assert r.risk_score >= 75.0
    assert r.risk_level.value == "CRITICAL"
    assert len(r.factors) >= 4


# ---------------------------------------------------------------------------
# 15. start_time Filter
# ---------------------------------------------------------------------------

def test_scenario_15_start_time_filter(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(
            request_id="old-1",
            timestamp=now - timedelta(minutes=30),
            method="GET",
            path="/api/v1/search",
            query_params={},
            client_ip="10.0.0.1",
            user_agent="C",
            status_code=200,
            response_time_ms=5.0
        ),
        APITrafficLog(
            request_id="new-1",
            timestamp=now - timedelta(minutes=5),
            method="GET",
            path="/api/v1/search",
            query_params={},
            client_ip="10.0.0.1",
            user_agent="C",
            status_code=200,
            response_time_ms=5.0
        )
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    start_iso = (now - timedelta(minutes=10)).isoformat()
    response = client.get(f"/api/v1/security/behavior/analyze?start_time={quote(start_iso)}")
    assert response.status_code == 200
    data = response.json()
    assert data["total_events_analyzed"] == 1


# ---------------------------------------------------------------------------
# 16. end_time Filter
# ---------------------------------------------------------------------------

def test_scenario_16_end_time_filter(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(
            request_id="early-1",
            timestamp=now - timedelta(minutes=20),
            method="GET",
            path="/api/v1/search",
            query_params={},
            client_ip="10.0.0.1",
            user_agent="C",
            status_code=200,
            response_time_ms=5.0
        ),
        APITrafficLog(
            request_id="late-1",
            timestamp=now - timedelta(minutes=2),
            method="GET",
            path="/api/v1/search",
            query_params={},
            client_ip="10.0.0.1",
            user_agent="C",
            status_code=200,
            response_time_ms=5.0
        )
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    end_iso = (now - timedelta(minutes=10)).isoformat()
    response = client.get(f"/api/v1/security/behavior/analyze?end_time={quote(end_iso)}")
    assert response.status_code == 200
    data = response.json()
    assert data["total_events_analyzed"] == 1


# ---------------------------------------------------------------------------
# 17. method Filter
# ---------------------------------------------------------------------------

def test_scenario_17_method_filter(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(
            request_id="get-1",
            timestamp=now - timedelta(seconds=10),
            method="GET",
            path="/api/v1/search",
            query_params={},
            client_ip="10.0.0.1",
            user_agent="C",
            status_code=200,
            response_time_ms=5.0
        ),
        APITrafficLog(
            request_id="post-1",
            timestamp=now - timedelta(seconds=5),
            method="POST",
            path="/api/v1/auth/login",
            query_params={},
            client_ip="10.0.0.1",
            user_agent="C",
            status_code=401,
            response_time_ms=5.0
        )
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    response = client.get("/api/v1/security/behavior/analyze?method=POST")
    assert response.status_code == 200
    data = response.json()
    assert data["total_events_analyzed"] == 1


# ---------------------------------------------------------------------------
# 18. path Filter
# ---------------------------------------------------------------------------

def test_scenario_18_path_filter(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(
            request_id="path-1",
            timestamp=now - timedelta(seconds=10),
            method="GET",
            path="/api/v1/orders",
            query_params={},
            client_ip="10.0.0.1",
            user_agent="C",
            status_code=200,
            response_time_ms=5.0
        ),
        APITrafficLog(
            request_id="path-2",
            timestamp=now - timedelta(seconds=5),
            method="GET",
            path="/api/v1/users",
            query_params={},
            client_ip="10.0.0.1",
            user_agent="C",
            status_code=200,
            response_time_ms=5.0
        )
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    response = client.get("/api/v1/security/behavior/analyze?path=/api/v1/orders")
    assert response.status_code == 200
    data = response.json()
    assert data["total_events_analyzed"] == 1


# ---------------------------------------------------------------------------
# 19. status_code Filter
# ---------------------------------------------------------------------------

def test_scenario_19_status_code_filter(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(
            request_id="status-200",
            timestamp=now - timedelta(seconds=10),
            method="GET",
            path="/api/v1/search",
            query_params={},
            client_ip="10.0.0.1",
            user_agent="C",
            status_code=200,
            response_time_ms=5.0
        ),
        APITrafficLog(
            request_id="status-401",
            timestamp=now - timedelta(seconds=5),
            method="POST",
            path="/api/v1/login",
            query_params={},
            client_ip="10.0.0.1",
            user_agent="C",
            status_code=401,
            response_time_ms=5.0
        )
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    response = client.get("/api/v1/security/behavior/analyze?status_code=401")
    assert response.status_code == 200
    data = response.json()
    assert data["total_events_analyzed"] == 1


# ---------------------------------------------------------------------------
# 20. client_ip Filter
# ---------------------------------------------------------------------------

def test_scenario_20_client_ip_filter(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(
            request_id="ip-a",
            timestamp=now - timedelta(seconds=10),
            method="GET",
            path="/api/v1/search",
            query_params={},
            client_ip="192.168.1.10",
            user_agent="C",
            status_code=200,
            response_time_ms=5.0
        ),
        APITrafficLog(
            request_id="ip-b",
            timestamp=now - timedelta(seconds=5),
            method="GET",
            path="/api/v1/search",
            query_params={},
            client_ip="192.168.1.20",
            user_agent="C",
            status_code=200,
            response_time_ms=5.0
        )
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    response = client.get("/api/v1/security/behavior/analyze?client_ip=192.168.1.10")
    assert response.status_code == 200
    data = response.json()
    assert data["total_clients"] == 1
    assert data["results"][0]["client_ip"] == "192.168.1.10"


# ---------------------------------------------------------------------------
# 21. Pagination Validation (422)
# ---------------------------------------------------------------------------

def test_scenario_21_pagination_validation(override_db):
    resp_page = client.get("/api/v1/security/behavior/analyze?page=0")
    assert resp_page.status_code == 422

    resp_size = client.get("/api/v1/security/behavior/analyze?page_size=0")
    assert resp_size.status_code == 422

    resp_oversize = client.get("/api/v1/security/behavior/analyze?page_size=1000")
    assert resp_oversize.status_code == 422


# ---------------------------------------------------------------------------
# 22. Invalid Date Range Returns 422
# ---------------------------------------------------------------------------

def test_scenario_22_invalid_date_range_returns_422(override_db):
    now = datetime.now(timezone.utc)
    start_iso = now.isoformat()
    end_iso = (now - timedelta(hours=1)).isoformat()

    response = client.get(
        f"/api/v1/security/behavior/analyze?start_time={quote(start_iso)}&end_time={quote(end_iso)}"
    )
    assert response.status_code == 422
    data = response.json()
    assert "start_time must be earlier than or equal to end_time" in str(data)


# ---------------------------------------------------------------------------
# 23. Invalid Risk Weight Returns 422
# ---------------------------------------------------------------------------

def test_scenario_23_invalid_risk_weight_returns_422(override_db):
    resp_neg = client.get("/api/v1/security/behavior/analyze?bola_weight=-5.0")
    assert resp_neg.status_code == 422

    resp_over = client.get("/api/v1/security/behavior/analyze?brute_force_weight=150.0")
    assert resp_over.status_code == 422


# ---------------------------------------------------------------------------
# 24. Missing Client IP Handled Safely
# ---------------------------------------------------------------------------

def test_scenario_24_missing_client_ip_handled_safely(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(
            request_id="no-ip-1",
            timestamp=now - timedelta(seconds=1),
            method="GET",
            path="/api/v1/search",
            query_params={},
            client_ip="",
            user_agent="C",
            status_code=200,
            response_time_ms=5.0
        )
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    response = client.get("/api/v1/security/behavior/analyze")
    assert response.status_code == 200
    data = response.json()
    assert data["total_clients"] == 0
    assert data["results"] == []
    assert data["total_events_analyzed"] == 1


# ---------------------------------------------------------------------------
# 25. Missing Actor Handled Safely
# ---------------------------------------------------------------------------

def test_scenario_25_missing_actor_handled_safely(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(
            request_id="no-actor-1",
            timestamp=now - timedelta(seconds=1),
            method="GET",
            path="/api/v1/search",
            query_params={},
            client_ip="10.0.0.1",
            user_agent="C",
            status_code=200,
            response_time_ms=5.0
        )
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    response = client.get("/api/v1/security/behavior/analyze")
    assert response.status_code == 200
    data = response.json()
    assert data["results"][0]["actor_id"] is None


# ---------------------------------------------------------------------------
# 26. Empty Result Does Not Fabricate Client
# ---------------------------------------------------------------------------

def test_scenario_26_empty_result_does_not_fabricate_client(override_db):
    response = client.get("/api/v1/security/behavior/analyze?client_ip=192.168.99.99")
    assert response.status_code == 200
    data = response.json()
    assert data["total_clients"] == 0
    assert data["results"] == []


# ---------------------------------------------------------------------------
# 27. Deterministic Response Ordering
# ---------------------------------------------------------------------------

def test_scenario_27_deterministic_response(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(
            request_id=f"det-{ip}-{i}",
            timestamp=now - timedelta(seconds=i),
            method="GET",
            path="/api/v1/data",
            query_params={},
            client_ip=ip,
            user_agent="Bot",
            status_code=200,
            response_time_ms=5.0
        )
        for ip in ["10.0.0.3", "10.0.0.1", "10.0.0.2"]
        for i in range(1, 3)
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    resp1 = client.get("/api/v1/security/behavior/analyze")
    resp2 = client.get("/api/v1/security/behavior/analyze")
    assert resp1.status_code == 200
    assert resp2.status_code == 200

    data1 = resp1.json()
    data2 = resp2.json()

    assert [r["client_ip"] for r in data1["results"]] == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    assert data1 == data2


# ---------------------------------------------------------------------------
# 28. No Credential Leakage
# ---------------------------------------------------------------------------

def test_scenario_28_no_credential_leakage(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(
            request_id="sec-1",
            timestamp=now,
            method="POST",
            path="/api/v1/login",
            query_params={"token": "secret_token_value", "password": "super_secret_pwd"},
            client_ip="10.0.0.1",
            user_agent="Tester",
            status_code=401,
            response_time_ms=10.0
        )
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    response = client.get("/api/v1/security/behavior/analyze")
    assert response.status_code == 200
    text_content = response.text.lower()
    assert "secret_token_value" not in text_content
    assert "super_secret_pwd" not in text_content
    assert "authorization" not in text_content
    assert "bearer" not in text_content


# ---------------------------------------------------------------------------
# 29. Neutral Explanation Wording
# ---------------------------------------------------------------------------

def test_scenario_29_neutral_explanation_wording(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(
            request_id=f"word-{i}",
            timestamp=now - timedelta(seconds=i),
            method="POST",
            path="/api/v1/login",
            query_params={},
            client_ip="10.0.0.1",
            user_agent="Bot",
            status_code=401,
            response_time_ms=5.0
        )
        for i in range(1, 6)
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    response = client.get("/api/v1/security/behavior/analyze")
    assert response.status_code == 200
    data = response.json()
    for res in data["results"]:
        exp = res["explanation"].lower()
        assert "attacker detected" not in exp
        assert "malicious user confirmed" not in exp
        assert "confirmed breach" not in exp


# ---------------------------------------------------------------------------
# 30. Malformed Traffic Handled Safely
# ---------------------------------------------------------------------------

def test_scenario_30_malformed_traffic_handled_safely(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(
            request_id="valid-1",
            timestamp=now,
            method="GET",
            path="/api/v1/search",
            query_params={},
            client_ip="10.0.0.1",
            user_agent="C",
            status_code=200,
            response_time_ms=5.0
        ),
        APITrafficLog(
            request_id="malformed-1",
            timestamp=now,
            method="",
            path="",
            query_params={},
            client_ip="10.0.0.1",
            user_agent="C",
            status_code=200,
            response_time_ms=5.0
        )
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    response = client.get("/api/v1/security/behavior/analyze")
    assert response.status_code == 200
    data = response.json()
    assert data["total_clients"] == 1


# ---------------------------------------------------------------------------
# 31. Configurable Risk Weight Overrides
# ---------------------------------------------------------------------------

def test_scenario_31_detector_weight_overrides(override_db):
    session = override_db()
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(
            request_id=f"wt-{i}",
            timestamp=now - timedelta(seconds=i),
            method="POST",
            path="/api/v1/auth/login",
            query_params={},
            client_ip="10.0.0.1",
            user_agent="Bot",
            status_code=401,
            response_time_ms=5.0
        )
        for i in range(1, 6)
    ]
    session.add_all(logs)
    session.commit()
    session.close()

    # With detector integration active, 5 auth failures on /api/v1/auth/login trigger both:
    #   - authentication_failures factor (weight=15.0): contribution = 15.0
    #   - brute_force_activity factor (weight=35.0): contribution = 35.0
    # Default total: 15.0 + 35.0 = 50.0
    resp_default = client.get("/api/v1/security/behavior/analyze")
    assert resp_default.status_code == 200
    assert resp_default.json()["results"][0]["risk_score"] == 50.0

    # Override authentication_failure_weight to 50.0 (brute_force_weight stays at 35.0):
    # authentication_failures = 50.0 + brute_force_activity = 35.0 → total = 85.0
    resp_override = client.get("/api/v1/security/behavior/analyze?authentication_failure_weight=50.0")
    assert resp_override.status_code == 200
    assert resp_override.json()["results"][0]["risk_score"] == 85.0


# ---------------------------------------------------------------------------
# 32. Existing Security & Health APIs Remain Operational
# ---------------------------------------------------------------------------

def test_scenario_32_existing_security_apis_remain_operational(override_db):
    resp_bola = client.get("/api/v1/security/bola/analyze")
    assert resp_bola.status_code == 200

    resp_bf = client.get("/api/v1/security/bruteforce/analyze")
    assert resp_bf.status_code == 200

    resp_ra = client.get("/api/v1/security/rate-anomaly/analyze")
    assert resp_ra.status_code == 200

    resp_health = client.get("/api/v1/health")
    assert resp_health.status_code == 200
    assert resp_health.json()["status"] == "healthy"

def test_historical_review_does_not_change_risk_score_or_signals_map(
    override_db, monkeypatch
):
    """Historical review findings must not affect risk scoring or signals."""
    from app.services import behavior_analysis_service as behavior_service

    session = override_db()
    now = datetime.now(timezone.utc)

    session.add(
        APITrafficLog(
            request_id="historical-review-current",
            timestamp=now,
            method="GET",
            path="/api/v1/items",
            query_params={},
            client_ip="192.0.2.25",
            user_agent="TestAgent",
            status_code=200,
            response_time_ms=10.0,
        )
    )
    session.commit()

    # Capture the original historical-review function and force a review flag.
    original_analyzer = behavior_service.analyze_historical_request_patterns

    def flagged_review(*args, **kwargs):
        return [
            {
                "client_ip": "192.0.2.25",
                "http_method": "PATCH",
                "current_request_count": 1,
                "historical_request_count": 20,
                "baseline_http_method": "GET",
                "is_anomaly": True,
                "reason": "unseen_historical_method",
            }
        ]

    monkeypatch.setattr(
        behavior_service,
        "analyze_historical_request_patterns",
        flagged_review,
    )
    monkeypatch.setattr(
        behavior_service,
        "get_historical_traffic_logs",
        lambda **kwargs: [],
    )

    try:
        response = client.get("/api/v1/security/behavior/analyze")
        assert response.status_code == 200

        data = response.json()
        result = next(
            item for item in data["results"]
            if item["client_ip"] == "192.0.2.25"
        )

        assert result["risk_score"] == 0.0
        assert result["risk_level"] == "LOW"
        assert "Historical HTTP-method/request-path baseline flagged 1 client(s)" in data["summary"]
    finally:
        session.close()

def test_historical_review_does_not_mutate_signals_map(override_db, monkeypatch):
    """Historical review must not mutate the caller-provided signals map."""
    from copy import deepcopy
    from app.services import behavior_analysis_service as behavior_service

    session = override_db()
    now = datetime.now(timezone.utc)

    session.add(
        APITrafficLog(
            request_id="signals-map-history-test",
            timestamp=now,
            method="GET",
            path="/api/v1/items",
            query_params={},
            client_ip="192.0.2.26",
            user_agent="TestAgent",
            status_code=200,
            response_time_ms=10.0,
        )
    )
    session.commit()

    signals = {
        "signals-map-history-test": {
            "detection_source": "bola",
            "detection_verdict": "suspicious_bola_candidate",
        }
    }
    original_signals = deepcopy(signals)

    monkeypatch.setattr(
        behavior_service,
        "get_historical_traffic_logs",
        lambda **kwargs: [],
    )
    monkeypatch.setattr(
        behavior_service,
        "analyze_historical_request_patterns",
        lambda *args, **kwargs: [
            {
                "client_ip": "192.0.2.26",
                "http_method": "PATCH",
                "current_request_count": 1,
                "historical_request_count": 20,
                "baseline_http_method": "GET",
                "is_anomaly": True,
                "reason": "unseen_historical_method",
            }
        ],
    )

    try:
        behavior_service.analyze_traffic_for_behavior_risk(
            signals_map=signals,
            db=session,
        )
        assert signals == original_signals
    finally:
        session.close()

def test_historical_database_failure_does_not_break_behavior_analysis(
    override_db, monkeypatch
):
    """Historical lookup failure must not break the main risk assessment."""
    from app.services import behavior_analysis_service as behavior_service

    session = override_db()
    now = datetime.now(timezone.utc)

    session.add(
        APITrafficLog(
            request_id="history-db-failure-test",
            timestamp=now,
            method="GET",
            path="/api/v1/items",
            query_params={},
            client_ip="192.0.2.27",
            user_agent="TestAgent",
            status_code=200,
            response_time_ms=10.0,
        )
    )
    session.commit()

    def fail_historical_lookup(**kwargs):
        raise RuntimeError("Simulated historical database failure")

    monkeypatch.setattr(
        behavior_service,
        "get_historical_traffic_logs",
        fail_historical_lookup,
    )

    try:
        response = client.get("/api/v1/security/behavior/analyze")

        assert response.status_code == 200

        data = response.json()
        result = next(
            item for item in data["results"]
            if item["client_ip"] == "192.0.2.27"
        )

        assert result["risk_score"] == 0.0
        assert result["risk_level"] == "LOW"
        assert data["total_events_analyzed"] == 1
    finally:
        session.close()
