from datetime import datetime, timedelta, timezone
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.models.traffic import APITrafficLog
from app.schemas.bola import DetectionVerdict
from app.schemas.bruteforce import BruteForceEvent, BruteForceVerdict
from app.schemas.rate_anomaly import RateAnomalyEvent, RateAnomalyVerdict
from app.detection.bruteforce_detector import BruteForceDetector, BruteForceDetectorConfig
from app.detection.rate_anomaly_detector import RateAnomalyDetector, RateAnomalyDetectorConfig
from app.services.bola_analysis_service import analyze_traffic_for_bola


@pytest.fixture
def in_memory_db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSession()
    yield session
    session.close()


def test_bola_detects_candidate_with_verified_persisted_actor(in_memory_db):
    """Verify that multiple objects accessed by a verified persisted actor_id triggers SUSPICIOUS_BOLA_CANDIDATE."""
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(
            request_id="r1",
            timestamp=now - timedelta(minutes=3),
            method="GET",
            path="/users/101",
            query_params={},
            client_ip="10.0.0.1",
            status_code=200,
            response_time_ms=5.0,
            actor_id="verified_audited_actor"
        ),
        APITrafficLog(
            request_id="r2",
            timestamp=now - timedelta(minutes=2),
            method="GET",
            path="/users/102",
            query_params={},
            client_ip="10.0.0.1",
            status_code=200,
            response_time_ms=5.0,
            actor_id="verified_audited_actor"
        ),
        APITrafficLog(
            request_id="r3",
            timestamp=now - timedelta(minutes=1),
            method="GET",
            path="/users/103",
            query_params={},
            client_ip="10.0.0.1",
            status_code=200,
            response_time_ms=5.0,
            actor_id="verified_audited_actor"
        ),
    ]
    in_memory_db.add_all(logs)
    in_memory_db.commit()

    result = analyze_traffic_for_bola(db=in_memory_db)
    assert result.verdict == DetectionVerdict.SUSPICIOUS_BOLA_CANDIDATE
    assert len(result.evidences) == 1
    assert result.evidences[0].actor_id == "verified_audited_actor"
    assert result.evidences[0].distinct_object_count == 3


def test_bola_returns_insufficient_evidence_when_actor_id_missing(in_memory_db):
    """Verify that multiple objects accessed with NO verified actor_id yields INSUFFICIENT_EVIDENCE."""
    now = datetime.now(timezone.utc)
    logs = [
        APITrafficLog(
            request_id="r1",
            timestamp=now - timedelta(minutes=3),
            method="GET",
            path="/users/101",
            query_params={},
            client_ip="10.0.0.1",
            status_code=200,
            response_time_ms=5.0,
            actor_id=None
        ),
        APITrafficLog(
            request_id="r2",
            timestamp=now - timedelta(minutes=2),
            method="GET",
            path="/users/102",
            query_params={},
            client_ip="10.0.0.1",
            status_code=200,
            response_time_ms=5.0,
            actor_id=None
        ),
        APITrafficLog(
            request_id="r3",
            timestamp=now - timedelta(minutes=1),
            method="GET",
            path="/users/103",
            query_params={},
            client_ip="10.0.0.1",
            status_code=200,
            response_time_ms=5.0,
            actor_id=None
        ),
    ]
    in_memory_db.add_all(logs)
    in_memory_db.commit()

    result = analyze_traffic_for_bola(db=in_memory_db)
    assert result.verdict == DetectionVerdict.INSUFFICIENT_EVIDENCE
    assert "lacked non-sensitive actor identity" in result.explanation


def test_bruteforce_detector_path_normalization_and_root_handling():
    """Verify that root path '/' is normalized safely without raising exceptions or breaking."""
    now = datetime.now(timezone.utc)
    events = [
        BruteForceEvent(
            request_id="bf-1",
            timestamp=now,
            method="POST",
            path="/",
            client_ip="192.168.1.1",
            status_code=401,
            authentication_failure=True,
        )
    ]
    detector = BruteForceDetector()
    result = detector.analyze_events(events)
    assert result.verdict == BruteForceVerdict.NO_BRUTEFORCE_DETECTED
    assert result.failed_attempt_count == 0
    assert "No events targeting recognised authentication endpoints" in result.summary


def test_rate_anomaly_detector_client_wide_scope():
    """Verify RateAnomalyDetector client_wide scope groups across different paths."""
    now = datetime.now(timezone.utc)
    events = [
        RateAnomalyEvent(
            request_id=f"ra-{i}",
            timestamp=now - timedelta(seconds=i),
            method="GET",
            path=f"/resource/{i}",
            client_ip="10.20.30.40",
            status_code=200,
        )
        for i in range(10)
    ]
    config = RateAnomalyDetectorConfig(
        request_threshold=10,
        time_window_seconds=60,
        scope="client_wide"
    )
    detector = RateAnomalyDetector(config=config)
    result = detector.analyze_events(events)
    assert result.verdict == RateAnomalyVerdict.SUSPICIOUS_RATE_ANOMALY
    assert result.anomalous_request_count == 10
    assert result.distinct_client_count == 1
