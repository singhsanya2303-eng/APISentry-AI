import logging
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from app.db.session import SessionLocal
from app.models.traffic import APITrafficLog

logger = logging.getLogger("apisentry.persistence")


def save_traffic_log(
    request_id: str,
    method: str,
    path: str,
    query_params: Dict[str, Any],
    client_ip: str,
    user_agent: str,
    status_code: int,
    response_time_ms: float,
    timestamp: Optional[datetime] = None
) -> bool:
    """
    Safely persist a captured API traffic log entry into PostgreSQL.
    
    Guarantees:
    - Session is always closed in a finally block.
    - Transaction is rolled back if database error occurs.
    - Exceptions are caught and logged, returning False without raising error.
    """
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)

    db = SessionLocal()
    try:
        log_entry = APITrafficLog(
            request_id=request_id,
            timestamp=timestamp,
            method=method,
            path=path,
            query_params=query_params,
            client_ip=client_ip,
            user_agent=user_agent or "",
            status_code=status_code,
            response_time_ms=response_time_ms
        )
        db.add(log_entry)
        db.commit()
        return True
    except Exception as exc:
        try:
            db.rollback()
        except Exception as rollback_exc:
            logger.error("Database rollback failed: %s", rollback_exc)
        logger.error("Failed to persist API traffic log (request_id=%s): %s", request_id, exc)
        return False
    finally:
        db.close()


@contextmanager
def _get_db_session(db: Optional[Session] = None):
    """Internal helper to manage DB session lifecycle safely."""
    if db is not None:
        yield db
    else:
        session = SessionLocal()
        try:
            yield session
        finally:
            session.close()


def get_traffic_log_by_id(log_id: int, db: Optional[Session] = None) -> Optional[APITrafficLog]:
    """Retrieve a single API traffic log record by database primary key ID."""
    with _get_db_session(db) as session:
        return session.query(APITrafficLog).filter(APITrafficLog.id == log_id).first()


def get_traffic_log_by_request_id(request_id: str, db: Optional[Session] = None) -> Optional[APITrafficLog]:
    """Retrieve a single API traffic log record by unique correlation request_id."""
    with _get_db_session(db) as session:
        return session.query(APITrafficLog).filter(APITrafficLog.request_id == request_id).first()


def _build_traffic_query(
    session: Session,
    method: Optional[str] = None,
    path: Optional[str] = None,
    status_code: Optional[int] = None,
    client_ip: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None
):
    """Helper to build filtered SQLAlchemy query on APITrafficLog."""
    query = session.query(APITrafficLog)
    if method:
        query = query.filter(APITrafficLog.method == method.upper())
    if path:
        if "%" in path or "*" in path:
            pattern = path.replace("*", "%")
            query = query.filter(APITrafficLog.path.like(pattern))
        else:
            query = query.filter(APITrafficLog.path == path)
    if status_code is not None:
        query = query.filter(APITrafficLog.status_code == status_code)
    if client_ip:
        query = query.filter(APITrafficLog.client_ip == client_ip)
    if start_time:
        query = query.filter(APITrafficLog.timestamp >= start_time)
    if end_time:
        query = query.filter(APITrafficLog.timestamp <= end_time)
    return query


def get_traffic_logs(
    method: Optional[str] = None,
    path: Optional[str] = None,
    status_code: Optional[int] = None,
    client_ip: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    page: int = 1,
    page_size: int = 50,
    db: Optional[Session] = None
) -> List[APITrafficLog]:
    """
    Retrieve paginated list of API traffic logs with optional multi-field filtering.
    Results are ordered by timestamp descending, then id descending.
    """
    safe_page = max(1, page)
    safe_page_size = min(max(1, page_size), 500)
    offset = (safe_page - 1) * safe_page_size

    with _get_db_session(db) as session:
        query = _build_traffic_query(
            session=session,
            method=method,
            path=path,
            status_code=status_code,
            client_ip=client_ip,
            start_time=start_time,
            end_time=end_time
        )
        return (
            query.order_by(APITrafficLog.timestamp.desc(), APITrafficLog.id.desc())
            .offset(offset)
            .limit(safe_page_size)
            .all()
        )


def count_traffic_logs(
    method: Optional[str] = None,
    path: Optional[str] = None,
    status_code: Optional[int] = None,
    client_ip: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    db: Optional[Session] = None
) -> int:
    """Count matching API traffic log entries for given filters."""
    with _get_db_session(db) as session:
        query = _build_traffic_query(
            session=session,
            method=method,
            path=path,
            status_code=status_code,
            client_ip=client_ip,
            start_time=start_time,
            end_time=end_time
        )
        return query.count()


def get_traffic_in_window(
    duration_minutes: int = 60,
    end_time: Optional[datetime] = None,
    page: int = 1,
    page_size: int = 50,
    db: Optional[Session] = None
) -> List[APITrafficLog]:
    """Retrieve traffic logs within a configurable time window ending at end_time (or UTC now)."""
    if end_time is None:
        end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(minutes=duration_minutes)

    return get_traffic_logs(
        start_time=start_time,
        end_time=end_time,
        page=page,
        page_size=page_size,
        db=db
    )


def get_recent_traffic_logs(
    limit: int = 50,
    db: Optional[Session] = None
) -> List[APITrafficLog]:
    """Retrieve the most recent API traffic log records."""
    return get_traffic_logs(page=1, page_size=limit, db=db)

def get_historical_traffic_logs(
    client_ips: List[str],
    start_time: datetime,
    end_time: datetime,
    db: Optional[Session] = None,
) -> List[APITrafficLog]:
    """Fetch historical traffic for multiple clients in one query.

    Results are restricted to the requested time window and client IPs.
    Current-window filtering by method, path, or status is intentionally
    not applied, so the baseline is not biased by the current request.
    """
    from sqlalchemy import and_

    safe_client_ips = sorted({
        ip.strip()
        for ip in client_ips
        if isinstance(ip, str) and ip.strip()
    })

    if not safe_client_ips or start_time >= end_time:
        return []

    with _get_db_session(db) as session:
        return (
            session.query(APITrafficLog)
            .filter(
                APITrafficLog.client_ip.in_(safe_client_ips),
                APITrafficLog.timestamp >= start_time,
                APITrafficLog.timestamp < end_time,
            )
            .order_by(
                APITrafficLog.timestamp.asc(),
                APITrafficLog.id.asc(),
            )
            .all()
        )
