"""
Persistent User SQLAlchemy model for authentication and role-based access control.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class UserRole(str, Enum):
    """Allowed user authorization roles."""
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


ALLOWED_ROLES = {role.value for role in UserRole}


class User(Base):
    """Persistent PostgreSQL User entity."""
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    username: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), index=True, nullable=False, default=UserRole.VIEWER.value)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    @property
    def actor_id(self) -> str:
        """Attributable actor identifier correlating with traffic logging and security analytics."""
        return f"user_{self.id}" if self.id is not None else f"user_{self.username}"

    @property
    def is_authenticated(self) -> bool:
        """Compatibility property for middleware actor identity resolution."""
        return bool(self.is_active)

    @property
    def identity(self) -> str:
        """Attributable identity string for security middleware."""
        return self.actor_id

    def __repr__(self) -> str:
        return f"<User(id={self.id}, username='{self.username}', email='{self.email}', role='{self.role}', is_active={self.is_active})>"
