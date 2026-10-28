from datetime import datetime, timezone
from sqlalchemy import String, Integer, Float, DateTime, JSON
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base


class APITrafficLog(Base):
    """SQLAlchemy model representing a captured API traffic event."""
    __tablename__ = "api_traffic_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)
    request_id: Mapped[str] = mapped_column(String(100), index=True, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
        nullable=False
    )
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    path: Mapped[str] = mapped_column(String(500), index=True, nullable=False)
    query_params: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    client_ip: Mapped[str] = mapped_column(String(45), index=True, nullable=False)
    user_agent: Mapped[str] = mapped_column(String(500), nullable=True, default="")
    status_code: Mapped[int] = mapped_column(Integer, index=True, nullable=False)
    response_time_ms: Mapped[float] = mapped_column(Float, nullable=False)

    def __repr__(self) -> str:
        return f"<APITrafficLog(request_id='{self.request_id}', method='{self.method}', path='{self.path}', status_code={self.status_code})>"
