
"""Generate isolated synthetic traffic for API-Sentry testing."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy.orm import Session

from app.db.session import SessionLocal
from app.models.traffic import APITrafficLog


def create_log(
    session: Session,
    timestamp: datetime,
    index: int,
    *,
    unusual: bool = False,
) -> None:
    """Insert one synthetic request without changing existing records."""
    session.add(
        APITrafficLog(
            request_id=f"synthetic-{uuid4()}",
            timestamp=timestamp,
            method="POST" if unusual else "GET",
            path="/synthetic/test",
            query_params={},
            client_ip=(
                f"198.51.100.{(index % 200) + 1}"
                if unusual
                else f"192.0.2.{(index % 20) + 1}"
            ),
            user_agent="APISentry-Synthetic-Test",
            status_code=500 if unusual else 200,
            response_time_ms=5000.0 if unusual else 100.0,
        )
    )


def main() -> None:
    # Round to the start of the current minute in UTC.
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)

    # Keep the synthetic test data separate from historical traffic.
    baseline_start = now - timedelta(minutes=15)
    target_start = now - timedelta(minutes=5)

    session = SessionLocal()

    try:
        # Baseline: 12 distinct 10-second windows, with similar normal traffic.
        for window_index in range(12):
            window_time = baseline_start + timedelta(
                seconds=window_index * 10
            )

            for request_index in range(3):
                create_log(
                    session,
                    window_time + timedelta(seconds=request_index),
                    window_index * 3 + request_index,
                )

        # Target: 3 normal windows, followed by 3 unusual windows.
        for window_index in range(6):
            window_time = target_start + timedelta(
                seconds=window_index * 10
            )
            unusual = window_index >= 3

            for request_index in range(3):
                create_log(
                    session,
                    window_time + timedelta(seconds=request_index),
                    100 + window_index * 3 + request_index,
                    unusual=unusual,
                )

        session.commit()

        baseline_end = baseline_start + timedelta(seconds=120)
        target_end = target_start + timedelta(seconds=60)

        print("\nSynthetic traffic inserted successfully.")
        print("Use these UTC timestamps in Swagger:")
        print(f"baseline_start = {baseline_start.isoformat()}")
        print(f"baseline_end   = {baseline_end.isoformat()}")
        print(f"target_start   = {target_start.isoformat()}")
        print(f"target_end     = {target_end.isoformat()}")
        print("\nKeep these exact values for the API request.")

    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


if __name__ == "__main__":
    main()
