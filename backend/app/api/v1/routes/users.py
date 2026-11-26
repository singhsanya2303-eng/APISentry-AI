"""
User Administration API Routes — Role-based access control and user management (Admin only).
"""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.security import (
    get_current_active_user,
    hash_password,
    require_admin,
)
from app.db.session import get_db
from app.schemas.auth import UserResponse, UserUpdateRequest
from app.services.user_service import (
    get_user_by_id,
    list_users,
    update_user,
)

router = APIRouter(prefix="/users", tags=["User Administration"])


@router.get(
    "",
    response_model=List[UserResponse],
    summary="List all users (Admin only)",
    responses={
        401: {"description": "Missing or invalid token"},
        403: {"description": "Admin role required"},
    },
)
def get_all_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    admin_user=Depends(require_admin),
) -> List[UserResponse]:
    """
    List all persistent registered users. Enforces admin-only access.
    """
    users = list_users(db, skip=skip, limit=limit)
    return [
        UserResponse(
            id=u.id,
            email=u.email,
            username=u.username,
            role=u.role,
            is_active=u.is_active,
            created_at=u.created_at,
            actor_id=u.actor_id,
        )
        for u in users
    ]


@router.get(
    "/{user_id}",
    response_model=UserResponse,
    summary="Get user details by ID (Admin or Self)",
    responses={
        401: {"description": "Missing or invalid token"},
        403: {"description": "Access denied"},
        404: {"description": "User not found"},
    },
)
def get_user_details(
    user_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_active_user),
) -> UserResponse:
    """
    Retrieve user record by ID. Allowed if caller is admin or viewing own record.
    """
    if current_user.role != "admin" and current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: you may only view your own user account",
        )

    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found",
        )

    return UserResponse(
        id=user.id,
        email=user.email,
        username=user.username,
        role=user.role,
        is_active=user.is_active,
        created_at=user.created_at,
        actor_id=user.actor_id,
    )


@router.patch(
    "/{user_id}",
    response_model=UserResponse,
    summary="Update user role or active status (Admin only)",
    responses={
        401: {"description": "Missing or invalid token"},
        403: {"description": "Admin role required"},
        404: {"description": "User not found"},
    },
)
def update_user_attributes(
    user_id: int,
    payload: UserUpdateRequest,
    db: Session = Depends(get_db),
    admin_user=Depends(require_admin),
) -> UserResponse:
    """
    Update a user's role, active status, or password. Enforces admin-only access.
    """
    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found",
        )

    password_hash = hash_password(payload.password) if payload.password else None
    role_val = payload.role.value if payload.role else None

    try:
        updated = update_user(
            db=db,
            user=user,
            role=role_val,
            is_active=payload.is_active,
            password_hash=password_hash,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    return UserResponse(
        id=updated.id,
        email=updated.email,
        username=updated.username,
        role=updated.role,
        is_active=updated.is_active,
        created_at=updated.created_at,
        actor_id=updated.actor_id,
    )
