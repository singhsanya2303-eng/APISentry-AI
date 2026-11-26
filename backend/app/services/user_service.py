"""
Persistent User Service — Database CRUD, credential verification, and role management.
"""

import logging
import re
from typing import List, Optional
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.user import User, UserRole, ALLOWED_ROLES

logger = logging.getLogger("apisentry.services.user")

_EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def normalize_email(email: str) -> str:
    """Normalize and validate email address format."""
    if not email or not isinstance(email, str):
        raise ValueError("Email cannot be empty")
    cleaned = email.strip().lower()
    if not _EMAIL_REGEX.match(cleaned):
        raise ValueError(f"Invalid email address format: '{email}'")
    return cleaned


def normalize_username(username: str) -> str:
    """Normalize username identifier."""
    if not username or not isinstance(username, str):
        raise ValueError("Username cannot be empty")
    cleaned = username.strip().lower()
    if len(cleaned) < 3 or len(cleaned) > 50:
        raise ValueError("Username must be between 3 and 50 characters")
    if not re.match(r"^[a-zA-Z0-9_\-\.]+$", cleaned):
        raise ValueError("Username contains invalid characters")
    return cleaned


def get_user_by_id(db: Session, user_id: int) -> Optional[User]:
    """Retrieve user by primary key ID."""
    return db.query(User).filter(User.id == user_id).first()


def get_user_by_email(db: Session, email: str) -> Optional[User]:
    """Retrieve user by normalized unique email."""
    try:
        norm_email = normalize_email(email)
    except ValueError:
        return None
    return db.query(User).filter(User.email == norm_email).first()


def get_user_by_username(db: Session, username: str) -> Optional[User]:
    """Retrieve user by normalized unique username."""
    try:
        norm_username = normalize_username(username)
    except ValueError:
        return None
    return db.query(User).filter(User.username == norm_username).first()


def get_user_by_identifier(db: Session, identifier: str) -> Optional[User]:
    """Retrieve user by either email or username."""
    if not identifier or not isinstance(identifier, str):
        return None
    cleaned = identifier.strip().lower()
    if "@" in cleaned:
        user = get_user_by_email(db, cleaned)
        if user:
            return user
    return get_user_by_username(db, cleaned)


def create_user(
    db: Session,
    email: str,
    username: str,
    password_hash: str,
    role: str = UserRole.VIEWER.value,
    is_active: bool = True,
) -> User:
    """
    Create and persist a new user in PostgreSQL.
    Raises ValueError on duplicate email or username.
    """
    norm_email = normalize_email(email)
    norm_username = normalize_username(username)

    if role not in ALLOWED_ROLES:
        raise ValueError(f"Invalid role '{role}'. Allowed roles: {', '.join(sorted(ALLOWED_ROLES))}")

    if get_user_by_email(db, norm_email):
        raise ValueError(f"An account with email '{norm_email}' already exists")

    if get_user_by_username(db, norm_username):
        raise ValueError(f"An account with username '{norm_username}' already exists")

    user = User(
        email=norm_email,
        username=norm_username,
        hashed_password=password_hash,
        role=role,
        is_active=is_active,
    )
    db.add(user)
    try:
        db.commit()
        db.refresh(user)
    except IntegrityError as exc:
        # Handle the unique-constraint race between the checks above and commit.
        db.rollback()
        raise ValueError("An account with that email or username already exists") from exc
    logger.info("Created user id=%d username=%s role=%s", user.id, user.username, user.role)
    return user


def list_users(db: Session, skip: int = 0, limit: int = 100) -> List[User]:
    """List users ordered by ID."""
    return db.query(User).order_by(User.id.asc()).offset(skip).limit(limit).all()


def update_user(
    db: Session,
    user: User,
    role: Optional[str] = None,
    is_active: Optional[bool] = None,
    password_hash: Optional[str] = None,
) -> User:
    """Update user role, active status, or password hash."""
    if role is not None:
        if role not in ALLOWED_ROLES:
            raise ValueError(f"Invalid role '{role}'. Allowed roles: {', '.join(sorted(ALLOWED_ROLES))}")
        user.role = role

    if is_active is not None:
        user.is_active = is_active

    if password_hash is not None:
        user.hashed_password = password_hash

    db.commit()
    db.refresh(user)
    logger.info("Updated user id=%d role=%s is_active=%s", user.id, user.role, user.is_active)
    return user
